/**
 * Deterministic Blueprint Runtime — Hot Loop  (#457)
 * Blueprint Control Loop — scheduler + tick-telemetry integration  (#458)
 *
 * This file hosts two complementary pieces of the blueprint control plane:
 *
 *   1. {@link BlueprintRuntime} (#457) — the *deterministic* execution core: a
 *      bounded-allocation, fully-synchronous hot loop that executes one scan of
 *      a compiled blueprint per `tick()`/`tickFast()` call.
 *   2. {@link BlueprintControlLoop} (#458) — the control-loop *lifecycle*: it
 *      pins the control thread to real-time scheduling at startup (or falls
 *      back), drives a fixed-period tick, and measures jitter / duration /
 *      deadline misses, mirroring them onto the Prometheus metrics in
 *      `server/metrics/blueprint.ts`.
 *
 * The two compose: a {@link BlueprintControlLoop} drives any {@link TickFn}, and
 * a {@link BlueprintRuntime}'s `tickFast()` is exactly such a `TickFn`. So the
 * scheduler/telemetry loop wraps the deterministic tick without either side
 * taking a hard structural dependency on the other.
 *
 * ── #457 DESIGN INVARIANTS (the whole point of BlueprintRuntime) ──
 *   1. ALL memory is allocated at `load()` time. `tick()` allocates NOTHING —
 *      no closures, no arrays, no objects, no string concat, no Map access.
 *   2. NO `await` / Promise / microtask in the critical path. `tick()` is fully
 *      synchronous so it cannot be preempted by the event loop mid-scan.
 *   3. Tag access in the loop is by integer index into a single `Float64Array`,
 *      never by name. Name resolution happened in the compiler.
 *   4. Dispatch is a single `switch` on a `Uint8Array` opcode — V8 lowers a
 *      dense switch to a jump table.
 *
 * The runtime owns three pre-allocated buffers:
 *   - tagBuffer   : Float64Array(tagCount)   — current value of every tag
 *   - stateBuffer : Float64Array(stateCount) — feedback/timer state across ticks
 *   - (operand decode uses the program's typed arrays directly; no scratch buffer
 *      is needed because every op reads <= OPERAND_STRIDE operands into locals.)
 *
 * @module server/blueprint/runtime
 */

import {
  type CompiledBlueprint,
  type TagDescriptor,
  OpCode,
  OPERAND_STRIDE,
} from "./types.js";
import {
  TickScheduler,
  configFromEnv,
  type SchedulerConfig,
  type SchedulerStatus,
  type SchedulingMode,
  type HostProbe,
} from "./scheduler.js";
import {
  TickAccountant,
  publishTickStats,
  type TickStats,
} from "../metrics/blueprint.js";
import { logInfo, logError } from "../logger.js";

/** Result of a single tick: timing only (values are read via getters to avoid allocation). */
export interface TickResult {
  /** Wall-clock duration of the tick in milliseconds (fractional). */
  durationMs: number;
  /** Monotonic tick counter since load. */
  tickNumber: number;
}

export class BlueprintRuntime {
  private readonly program: CompiledBlueprint;

  // ── Pre-allocated buffers (allocated once, in the constructor) ──
  private readonly tagBuffer: Float64Array;
  private readonly stateBuffer: Float64Array;

  // ── Pre-hoisted references to the program's typed arrays ──
  // Hoisting to instance fields lets the JIT treat them as monomorphic and
  // avoids a property chain (`this.program.opcodes`) on every instruction.
  private readonly opcodes: Uint8Array;
  private readonly destIndices: Int32Array;
  private readonly immediates: Float64Array;
  private readonly operandTagIndices: Int32Array;
  private readonly operandConsts: Float64Array;
  private readonly stateIndices: Int32Array;
  private readonly instructionCount: number;
  private readonly scanPeriodSeconds: number;

  private tickNumber = 0;

  /**
   * Load a compiled blueprint and pre-allocate all runtime buffers.
   * This is the ONLY place allocation happens (plus get/set helpers below).
   */
  constructor(program: CompiledBlueprint) {
    this.program = program;
    this.tagBuffer = new Float64Array(program.tagCount);
    this.tagBuffer.set(program.initialValues);
    this.stateBuffer = new Float64Array(program.stateCount);

    this.opcodes = program.opcodes;
    this.destIndices = program.destIndices;
    this.immediates = program.immediates;
    this.operandTagIndices = program.operandTagIndices;
    this.operandConsts = program.operandConsts;
    this.stateIndices = program.stateIndices;
    this.instructionCount = program.instructionCount;
    this.scanPeriodSeconds = program.scanPeriodMs / 1000;
  }

  // ─── Hot loop ───────────────────────────────────────────────────────────────

  /**
   * Execute one scan over the entire instruction stream.
   *
   * ZERO allocations in this method body. The only objects created are the
   * returned `TickResult` literal — callers that run at very high rates and do
   * not need timing should use {@link tickFast} which returns nothing.
   */
  tick(): TickResult {
    const start = performance.now();
    this.tickFast();
    const durationMs = performance.now() - start;
    return { durationMs, tickNumber: this.tickNumber };
  }

  /**
   * The genuinely allocation-free scan. Returns nothing so the steady-state hot
   * path can avoid even the result-object literal.
   */
  tickFast(): void {
    // Hoist everything into locals so the loop touches no `this` after entry.
    const tags = this.tagBuffer;
    const state = this.stateBuffer;
    const opcodes = this.opcodes;
    const dest = this.destIndices;
    const imm = this.immediates;
    const opTag = this.operandTagIndices;
    const opConst = this.operandConsts;
    const stateIdx = this.stateIndices;
    const n = this.instructionCount;
    const dt = this.scanPeriodSeconds;

    for (let i = 0; i < n; i++) {
      const base = i * OPERAND_STRIDE;

      // Decode up to OPERAND_STRIDE operands. `index === -1` means "immediate".
      const i0 = opTag[base];
      const a = i0 >= 0 ? tags[i0] : opConst[base];
      const i1 = opTag[base + 1];
      const b = i1 >= 0 ? tags[i1] : opConst[base + 1];
      const i2 = opTag[base + 2];
      const c = i2 >= 0 ? tags[i2] : opConst[base + 2];

      const d = dest[i];
      let out: number;

      switch (opcodes[i]) {
        // ── Boolean (treat any non-zero as true; emit 0.0/1.0) ──
        case OpCode.AND:
          out = a !== 0 && b !== 0 ? 1 : 0;
          break;
        case OpCode.OR:
          out = a !== 0 || b !== 0 ? 1 : 0;
          break;
        case OpCode.NOT:
          out = a !== 0 ? 0 : 1;
          break;
        case OpCode.XOR:
          out = (a !== 0) !== (b !== 0) ? 1 : 0;
          break;
        // ── Comparison ──
        case OpCode.GT:
          out = a > b ? 1 : 0;
          break;
        case OpCode.GTE:
          out = a >= b ? 1 : 0;
          break;
        case OpCode.LT:
          out = a < b ? 1 : 0;
          break;
        case OpCode.LTE:
          out = a <= b ? 1 : 0;
          break;
        case OpCode.EQ:
          out = a === b ? 1 : 0;
          break;
        case OpCode.NEQ:
          out = a !== b ? 1 : 0;
          break;
        // ── Arithmetic ──
        case OpCode.ADD:
          out = a + b;
          break;
        case OpCode.SUB:
          out = a - b;
          break;
        case OpCode.MUL:
          out = a * b;
          break;
        case OpCode.DIV:
          out = b !== 0 ? a / b : 0; // deterministic: div-by-zero -> 0, never NaN/Inf
          break;
        case OpCode.MIN:
          out = a < b ? a : b;
          break;
        case OpCode.MAX:
          out = a > b ? a : b;
          break;
        // ── Selection / movement ──
        case OpCode.SELECT:
          out = a !== 0 ? b : c;
          break;
        case OpCode.MOVE:
          out = a;
          break;
        case OpCode.CONST:
          out = imm[i];
          break;
        // ── Stateful ──
        case OpCode.LATCH: {
          // SR latch with set-dominant behaviour. State holds the latched value.
          const s = stateIdx[i];
          let q = state[s];
          if (b !== 0) q = 0; // reset
          if (a !== 0) q = 1; // set dominates
          state[s] = q;
          out = q;
          break;
        }
        case OpCode.TON: {
          // On-delay timer. `a` = enable, `imm[i]` = preset seconds.
          // State holds elapsed seconds. Output is the "done" bit (0/1).
          const s = stateIdx[i];
          let elapsed = state[s];
          if (a !== 0) {
            elapsed += dt;
            const preset = imm[i];
            if (elapsed >= preset) {
              elapsed = preset;
              out = 1;
            } else {
              out = 0;
            }
          } else {
            elapsed = 0;
            out = 0;
          }
          state[s] = elapsed;
          break;
        }
        default:
          // Unreachable for a validly-compiled program; keep deterministic.
          out = 0;
          break;
      }

      tags[d] = out;
    }

    this.tickNumber++;
  }

  // ─── IO marshalling (called OUTSIDE the tick) ─────────────────────────────────

  /**
   * Bulk-write input tags from a same-length Float64Array of input values, in
   * the order of `program.inputSlots`. Allocation-free.
   */
  writeInputs(values: Float64Array): void {
    const slots = this.program.inputSlots;
    const n = slots.length;
    if (values.length !== n) {
      throw new RangeError(`expected ${n} input values, got ${values.length}`);
    }
    const tags = this.tagBuffer;
    for (let i = 0; i < n; i++) tags[slots[i]] = values[i];
  }

  /**
   * Bulk-read output tags into the provided same-length Float64Array, in the
   * order of `program.outputSlots`. Allocation-free (caller supplies the buffer).
   */
  readOutputs(out: Float64Array): void {
    const slots = this.program.outputSlots;
    const n = slots.length;
    if (out.length !== n) {
      throw new RangeError(`expected ${n} output slots, got ${out.length}`);
    }
    const tags = this.tagBuffer;
    for (let i = 0; i < n; i++) out[i] = tags[slots[i]];
  }

  // ─── Single-tag accessors (diagnostics / tests; NOT for the hot path) ──────────

  /** Read a tag by name. Uses the Map — do not call inside the tick. */
  get(name: string): number {
    const slot = this.program.tagIndex.get(name);
    if (slot === undefined) throw new RangeError(`unknown tag "${name}"`);
    return this.tagBuffer[slot];
  }

  /** Write a tag by name. Uses the Map — do not call inside the tick. */
  set(name: string, value: number): void {
    const slot = this.program.tagIndex.get(name);
    if (slot === undefined) throw new RangeError(`unknown tag "${name}"`);
    this.tagBuffer[slot] = value;
  }

  /** Reset tag + state buffers to load-time initial values. */
  reset(): void {
    this.tagBuffer.set(this.program.initialValues);
    this.stateBuffer.fill(0);
    this.tickNumber = 0;
  }

  // ─── Introspection ────────────────────────────────────────────────────────────

  get tagCount(): number {
    return this.program.tagCount;
  }
  get inputCount(): number {
    return this.program.inputSlots.length;
  }
  get outputCount(): number {
    return this.program.outputSlots.length;
  }
  get ticks(): number {
    return this.tickNumber;
  }
  get tagMeta(): readonly TagDescriptor[] {
    return this.program.tagMeta;
  }
}

// ============================================================================
// CONTROL LOOP LIFECYCLE (#458) — scheduler + tick telemetry
// ============================================================================

/**
 * One tick of blueprint control logic. Synchronous by contract: a real-time
 * control tick MUST NOT await — Promise micro-tasks defeat the determinism the
 * scheduler is trying to protect. (#457's {@link BlueprintRuntime.tickFast} is
 * exactly such a `TickFn`; pass `() => runtime.tickFast()` to drive it.)
 */
export type TickFn = (tickIndex: number) => void;

export interface RuntimeOptions {
  /** Stable id for the blueprint, used as the metric label. */
  blueprintId: string;
  /** Target tick period in milliseconds (the control-loop budget). */
  periodMs: number;
  /**
   * Deadline budget in milliseconds. A tick whose body runs longer counts as a
   * missed deadline. Defaults to `periodMs` (a tick must finish within its own
   * period).
   */
  deadlineMs?: number;
  /** Rolling window (tick count) over which WCET is computed. Default 1000. */
  wcetWindow?: number;
  /** Scheduler configuration overrides. Defaults derive from env. */
  scheduler?: Partial<SchedulerConfig>;
  /** Inject a host probe (tests / non-Linux). */
  hostProbe?: HostProbe;
  /**
   * Injectable monotonic clock returning nanoseconds. Defaults to
   * `process.hrtime.bigint()`. Lets tests drive deterministic timing.
   */
  nowNs?: () => bigint;
}

export interface RuntimeHealth {
  blueprintId: string;
  running: boolean;
  schedulingMode: SchedulingMode;
  scheduler: ReturnType<TickScheduler['healthSummary']>;
  tick: TickStats;
  targetPeriodMs: number;
}

const MS_TO_NS = 1_000_000;

/**
 * Control-loop lifecycle (#458): pins the control thread to real-time
 * scheduling at startup (or falls back), drives a fixed-period tick, and
 * measures jitter / duration / deadline misses per tick, mirroring them onto
 * the Prometheus metrics from `server/metrics/blueprint.ts`.
 *
 * The per-tick body is any {@link TickFn} — register a {@link BlueprintRuntime}'s
 * `tickFast()` via {@link setTickFn} so this loop drives the deterministic tick.
 */
export class BlueprintControlLoop {
  private readonly opts: Required<Omit<RuntimeOptions, 'scheduler' | 'hostProbe'>> & {
    scheduler?: Partial<SchedulerConfig>;
  };
  private readonly scheduler: TickScheduler;
  private readonly accountant: TickAccountant;
  private readonly nowNs: () => bigint;

  private timer: ReturnType<typeof setInterval> | null = null;
  private tickFn: TickFn | null = null;
  private tickIndex = 0;
  private lastTickStartNs: bigint | null = null;
  private running = false;
  private lastStats: TickStats;

  constructor(options: RuntimeOptions) {
    if (!options.blueprintId) throw new Error('blueprintId is required');
    if (!(options.periodMs > 0)) throw new Error('periodMs must be > 0');

    const periodMs = options.periodMs;
    const deadlineMs = options.deadlineMs ?? periodMs;

    this.opts = {
      blueprintId: options.blueprintId,
      periodMs,
      deadlineMs,
      wcetWindow: options.wcetWindow ?? 1000,
      nowNs: options.nowNs ?? (() => process.hrtime.bigint()),
      scheduler: options.scheduler,
    };
    this.nowNs = this.opts.nowNs;

    this.scheduler = new TickScheduler(
      options.scheduler ?? configFromEnv(),
      options.hostProbe,
    );
    this.accountant = new TickAccountant({
      targetPeriodNs: periodMs * MS_TO_NS,
      deadlineNs: deadlineMs * MS_TO_NS,
      windowSize: this.opts.wcetWindow,
    });
    this.lastStats = this.accountant.stats();
  }

  /** Register the per-tick control body. Must be called before {@link start}. */
  setTickFn(fn: TickFn): void {
    this.tickFn = fn;
  }

  /**
   * Resolve scheduler posture and begin ticking. This in-process timer never
   * supplies a dedicated control-process PID, so the scheduler must remain in
   * fallback mode and cannot elevate the Express process. A production RT
   * composition requires a separate control-process driver.
   */
  start(): SchedulerStatus {
    if (this.running) return this.scheduler.status();
    if (!this.tickFn) throw new Error('setTickFn() must be called before start()');

    const status = this.scheduler.apply();
    logInfo(
      `[runtime] blueprint '${this.opts.blueprintId}' starting in ${status.mode} mode ` +
        `(period ${this.opts.periodMs}ms, deadline ${this.opts.deadlineMs}ms)`,
    );

    this.running = true;
    this.timer = setInterval(() => this.runOneTick(), this.opts.periodMs);
    // Don't keep the process alive solely for the control loop in dev/test.
    if (typeof this.timer === 'object' && this.timer && 'unref' in this.timer) {
      (this.timer as { unref: () => void }).unref();
    }
    return status;
  }

  /** Stop the control loop. Idempotent. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.running = false;
  }

  /**
   * Execute exactly one tick: measure period jitter and execution duration,
   * run the registered control body, and publish telemetry. Exposed (not just
   * the interval callback) so a deterministic driver or test can step the loop.
   */
  runOneTick(): TickStats {
    const fn = this.tickFn;
    if (!fn) throw new Error('no tick function registered');

    const startNs = this.nowNs();
    const periodNs =
      this.lastTickStartNs === null ? undefined : Number(startNs - this.lastTickStartNs);
    this.lastTickStartNs = startNs;

    try {
      fn(this.tickIndex);
    } catch (err) {
      // A throwing control body must not crash the loop; surface and continue.
      logError(err, `[runtime] tick ${this.tickIndex} of '${this.opts.blueprintId}' threw`);
    }

    const durationNs = Number(this.nowNs() - startNs);
    this.tickIndex += 1;

    this.lastStats = publishTickStats(
      this.accountant,
      { durationNs, periodNs },
      { blueprint: this.opts.blueprintId },
    );
    return this.lastStats;
  }

  /** Current scheduling mode (mirrors the scheduler). */
  get schedulingMode(): SchedulingMode {
    return this.scheduler.mode;
  }

  /** Health snapshot for embedding in the `/health` endpoint payload. */
  health(): RuntimeHealth {
    return {
      blueprintId: this.opts.blueprintId,
      running: this.running,
      schedulingMode: this.scheduler.mode,
      scheduler: this.scheduler.healthSummary(),
      tick: this.lastStats,
      targetPeriodMs: this.opts.periodMs,
    };
  }
}
