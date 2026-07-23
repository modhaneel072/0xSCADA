import { readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import {
  BLUEPRINT_PRODUCTION_HOLD_CODE,
  createBlueprintProductionHoldMiddleware,
  getBlueprintProductionSafetyStatus,
} from "../production-safety";

describe("production blueprint safety hold", () => {
  it("reports every unbound production capability explicitly", () => {
    expect(getBlueprintProductionSafetyStatus()).toMatchObject({
      state: "HELD",
      code: BLUEPRINT_PRODUCTION_HOLD_CODE,
      latencyProbe: {
        state: "HELD",
        running: false,
      },
      capabilities: {
        deterministicRuntimeBound: false,
        dedicatedControlProcessBound: false,
        watchdogRegistered: false,
        outputActuatorBound: false,
        latencyProbeRunning: false,
        realtimeSchedulerApplied: false,
      },
    });
  });

  it("fails the production API closed with a machine-visible 503", () => {
    const json = vi.fn();
    const status = vi.fn().mockReturnValue({ json });
    const next = vi.fn();
    const middleware = createBlueprintProductionHoldMiddleware();

    middleware({} as never, { status } as never, next);

    expect(status).toHaveBeenCalledWith(503);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: BLUEPRINT_PRODUCTION_HOLD_CODE,
        safetyRuntime: expect.objectContaining({ state: "HELD" }),
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });
});

describe("safe-state audit migration alignment", () => {
  it("creates every column and index declared by the Drizzle table", () => {
    const sql = readFileSync(
      new URL("../../../migrations/0005_blueprint_safe_state_log.sql", import.meta.url),
      "utf8",
    );

    for (const column of [
      "blueprint_id",
      "site_id",
      "transition",
      "safe_state",
      "tick_budget_ms",
      "consecutive_misses",
      "operator",
      "reason",
      "anchor_hash",
      "anchor_tx_hash",
      "metadata",
      "created_at",
    ]) {
      expect(sql).toMatch(new RegExp(`\\b${column}\\b`));
    }
    expect(sql).toContain("idx_safe_state_log_blueprint_id");
    expect(sql).toContain("idx_safe_state_log_transition");
    expect(sql).toContain("idx_safe_state_log_created_at");
  });

  it("registers migrations 0003 through 0006 in the Drizzle journal", () => {
    const journal = JSON.parse(
      readFileSync(
        new URL("../../../migrations/meta/_journal.json", import.meta.url),
        "utf8",
      ),
    ) as { entries: Array<{ idx: number; tag: string }> };

    expect(journal.entries.map(({ idx, tag }) => ({ idx, tag }))).toEqual([
      { idx: 0, tag: "0001_initial_schema" },
      { idx: 1, tag: "0002_seed_rbac_defaults" },
      { idx: 2, tag: "0003_blueprint_persistence" },
      { idx: 3, tag: "0004_validator_registry" },
      { idx: 4, tag: "0005_blueprint_safe_state_log" },
      { idx: 5, tag: "0006_blueprint_instance_identity" },
    ]);
  });
});

describe("production latency-probe alert alignment", () => {
  it("requires the live SLO gauge to remain breached for five minutes", () => {
    const rules = readFileSync(
      new URL("../../../ops/alertmanager/control-loop-rules.yml", import.meta.url),
      "utf8",
    );
    const stageRule = rules.match(
      /- alert:\s*ControlLoopStageBudgetBreached[\s\S]*?(?=\n\s+- alert:)/,
    )?.[0];

    expect(stageRule).toBeDefined();
    expect(stageRule).toContain("expr: scada_control_loop_stage_slo_ok == 0");
    expect(stageRule).toMatch(/\n\s+for:\s*5m/);
    expect(stageRule).not.toContain("min_over_time");
    expect(stageRule).not.toContain("max_over_time");
  });

  it("alerts from the explicit probe-up gauge rather than an absent histogram", () => {
    const rules = readFileSync(
      new URL("../../../ops/alertmanager/control-loop-rules.yml", import.meta.url),
      "utf8",
    );

    expect(rules).toContain("scada_control_loop_probe_up");
    expect(rules).toMatch(
      /alert:\s*ControlLoopProbeStalled[\s\S]*expr:\s*scada_control_loop_probe_up == 0/,
    );
    expect(rules).not.toMatch(
      /ControlLoopProbeStalled[\s\S]*rate\(scada_control_loop_roundtrip_latency_seconds_count/,
    );
  });
});
