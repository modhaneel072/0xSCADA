/**
 * Blueprint control-plane module — public surface.
 *
 * Issue #457: [wave:2b] Deterministic Blueprint Runtime (compiler + hot loop).
 * Issue #458: Tick-aware scheduler + tick telemetry that drive/wrap the
 *             deterministic tick.
 * Issue #459: Watchdog + safe-state fallback (tick-budget monitor → halt →
 *             declared safe state, anchored & audited).
 *
 * This barrel is the single import point for the rest of the server (and for the
 * 2b watchdog, #3, which gates on this module). Consumers should import from
 * `server/blueprint` rather than reaching into individual files, so the internal
 * SoA layout and the scheduling glue can evolve without churning call sites.
 *
 * @module server/blueprint
 */

import { TickScheduler, configFromEnv } from './scheduler.js';
import type { HealthCheck, ServiceCheckResult } from '../health/health-manager.js';

// #459 watchdog/safe-state imports. Note: `safe-state.ts` declares its own
// MINIMAL runtime seam interface (also named `BlueprintRuntime`) distinct from
// #457's deterministic `BlueprintRuntime` class. We alias it here as
// `SafeStateRuntime` so both can coexist on this barrel without an export clash.
import type { SafeStateConfig } from "@shared/schema";
import { Watchdog } from "./watchdog";
import type {
  AnchorBackend,
  BlueprintRuntime as SafeStateRuntime,
  SafeStateAuditSink,
  SafeStateStatus,
} from "./safe-state";

// ── #457: deterministic compiler + runtime types ──
export {
  type TagDirection,
  type TagDescriptor,
  type BlueprintOp,
  type BlueprintNode,
  type BlueprintOperand,
  type BlueprintDefinition,
  type CompiledBlueprint,
  OpCode,
  OP_TO_OPCODE,
  OPERAND_STRIDE,
  isTagOperand,
} from "./types.js";

export { compileBlueprint, BlueprintCompileError } from "./compiler.js";

export { makeControlFarmBlueprint, makeInputVector } from "./fixtures.js";

// ── #457: deterministic runtime + #458: control-loop lifecycle ──
// `BlueprintRuntime` is the deterministic hot-loop executor; `BlueprintControlLoop`
// is the scheduler/telemetry-driven loop that wraps any TickFn (e.g. the
// runtime's `tickFast`).
export {
  BlueprintRuntime,
  type TickResult,
  BlueprintControlLoop,
  type TickFn,
  type RuntimeOptions,
  type RuntimeHealth,
} from "./runtime.js";

// ── #458: tick-aware scheduler public surface ──
export {
  TickScheduler,
  detectRtCapability,
  normalizeConfig,
  configFromEnv,
  createDefaultHostProbe,
  chrtSyscall,
  DEFAULT_PRIORITY,
  DEFAULT_SCHEDULER_CONFIG,
  type SchedulingMode,
  type SchedPolicy,
  type SchedulerConfig,
  type SchedulerStatus,
  type DedicatedSchedulerTarget,
  type RtCapability,
  type HostProbe,
  type RtSyscall,
} from './scheduler.js';

// ── #458: tick telemetry ──
export {
  exposeBlueprintMetrics,
  resetBlueprintMetrics,
  TickAccountant,
  publishTickStats,
} from '../metrics/blueprint.js';

/**
 * Process-wide scheduler singleton. Constructed lazily from environment config
 * so importing this module is side-effect-light (no syscall until `apply()`).
 * The control runtime and the `/health` check share this instance so the
 * reported mode is consistent.
 */
let sharedScheduler: TickScheduler | null = null;

export function getScheduler(): TickScheduler {
  if (!sharedScheduler) {
    sharedScheduler = new TickScheduler(configFromEnv());
  }
  return sharedScheduler;
}

/**
 * Explicitly apply real-time scheduling to a dedicated control process.
 * Requiring the target prevents health imports or Express startup from
 * accidentally elevating the main server process.
 */
export function applyScheduler(
  target: import("./scheduler.js").DedicatedSchedulerTarget,
): ReturnType<TickScheduler['apply']> {
  return getScheduler().apply(target);
}

/**
 * Health check reporting the scheduling mode. Registered with the HealthManager
 * so `schedulingMode` appears in the `/health` payload (acceptance criterion).
 *
 * Always reports `healthy` and non-required: running in fallback mode is a
 * degraded real-time posture, NOT a service outage — surfacing it honestly is
 * the whole point, but it must not flip readiness to "not ready" on a dev box.
 */
export function createSchedulerCheck(): HealthCheck {
  return {
    name: 'scheduler',
    required: false,
    check: async (): Promise<ServiceCheckResult> => {
      const summary = getScheduler().healthSummary();
      return {
        name: 'scheduler',
        status: 'healthy',
        lastCheck: new Date(),
        message: summary.reason,
        details: {
          schedulingMode: summary.schedulingMode,
          policy: summary.policy,
          priority: summary.priority,
          realtimeKernel: summary.realtimeKernel,
        },
      };
    },
  };
}

// ============================================================================
// #459 — Watchdog & safe-state fallback public surface
// ============================================================================
//
// - Watchdog            : per-blueprint tick-budget monitor + trip logic.
// - SafeStateController : applies / clears the declared safe state, anchors
//                         CRITICAL transitions, audits them.
// - WatchdogRegistry    : tracks one watchdog per running blueprint and exposes
//                         status for the operator UI.
//
// Production adapters (anchor backend + Drizzle audit sink) live in
// ./safe-state-adapters to keep the core dependency-free and unit-testable.

// Re-export the safe-state surface EXCEPT its local `BlueprintRuntime` seam
// interface, which would clash with #457's `BlueprintRuntime` class exported
// above. Consumers that need the seam type import it from "./safe-state"
// directly (or use the `SafeStateRuntime` alias surfaced here).
export {
  type AnchorSeverity,
  type AnchorEvent,
  type AnchorReceipt,
  type AnchorBackend,
  type SafeStateAuditSink,
  type SafeStateAuditEntry,
  type BlueprintRunState,
  type SafeStateStatus,
  describeSafeState,
  computeAnchorHash,
  SafeStateController,
} from "./safe-state";
export type { BlueprintRuntime as SafeStateRuntime } from "./safe-state";
export * from "./watchdog";
export {
  BridgeAnchorBackend,
  DrizzleSafeStateAuditSink,
} from "./safe-state-adapters";
export {
  BLUEPRINT_PRODUCTION_HOLD_CODE,
  BLUEPRINT_PRODUCTION_HOLD_REASON,
  createBlueprintProductionHoldMiddleware,
  getBlueprintProductionSafetyStatus,
  type BlueprintProductionSafetyStatus,
} from "./production-safety";

/**
 * Registry of active blueprint watchdogs. One {@link Watchdog} is created per
 * running blueprint; the registry is the single place the runtime feeds tick
 * observations and the API/UI reads safe-state status.
 */
export class WatchdogRegistry {
  private readonly watchdogs = new Map<string, Watchdog>();

  constructor(
    private readonly anchor: AnchorBackend,
    private readonly audit: SafeStateAuditSink,
  ) {}

  /**
   * Register (or replace) the watchdog for a blueprint. Returns the watchdog so
   * the caller can feed it tick observations.
   */
  register(runtime: SafeStateRuntime, config: SafeStateConfig): Watchdog {
    const watchdog = new Watchdog(runtime, config, this.anchor, this.audit);
    this.watchdogs.set(runtime.blueprintId, watchdog);
    return watchdog;
  }

  /** Remove a blueprint's watchdog (e.g. on blueprint stop / undeploy). */
  unregister(blueprintId: string): void {
    this.watchdogs.delete(blueprintId);
  }

  /** Get the watchdog for a blueprint, if registered. */
  get(blueprintId: string): Watchdog | undefined {
    return this.watchdogs.get(blueprintId);
  }

  /** Safe-state status for every registered blueprint (for the operator UI). */
  getAllStatuses(): SafeStateStatus[] {
    return [...this.watchdogs.values()].map((w) => w.getStatus());
  }

  /** Blueprints in safe-state handling, including degraded recovery states. */
  getSafeStateStatuses(): SafeStateStatus[] {
    return this.getAllStatuses().filter((s) => s.runState !== "RUNNING");
  }
}
