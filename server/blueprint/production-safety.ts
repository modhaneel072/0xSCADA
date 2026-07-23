/**
 * Production hold for the Wave 2 blueprint safety surfaces (#457-#460).
 *
 * The deterministic runtime, watchdog, and latency probe are useful libraries,
 * but this repository does not yet contain a composition root that binds them
 * to a deployed blueprint, a dedicated control process, and a field-I/O output
 * adapter. Exposing an empty "healthy" safe-state API in that condition would
 * imply an actuation guarantee that does not exist.
 *
 * Keep the production surface fail-closed until a future integration supplies
 * and verifies all of those bindings. This is intentionally not controlled by
 * an environment flag: configuration alone cannot prove physical actuation.
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";
import {
  PRODUCTION_LATENCY_PROBE_STATUS,
  publishProductionLatencyProbeStatus,
} from "../integrity/latency-probe";

export const BLUEPRINT_PRODUCTION_HOLD_CODE =
  "BLUEPRINT_CONTROL_PATH_UNBOUND" as const;

export const BLUEPRINT_PRODUCTION_HOLD_REASON =
  "Blueprint safety runtime is held: no verified deployed-blueprint, dedicated-control-process, and field-I/O actuator binding is registered." as const;

export interface BlueprintProductionSafetyStatus {
  state: "HELD";
  code: typeof BLUEPRINT_PRODUCTION_HOLD_CODE;
  reason: typeof BLUEPRINT_PRODUCTION_HOLD_REASON;
  latencyProbe: typeof PRODUCTION_LATENCY_PROBE_STATUS;
  capabilities: {
    deterministicRuntimeBound: false;
    dedicatedControlProcessBound: false;
    watchdogRegistered: false;
    outputActuatorBound: false;
    latencyProbeRunning: false;
    realtimeSchedulerApplied: false;
  };
}

const HELD_STATUS: BlueprintProductionSafetyStatus = Object.freeze({
  state: "HELD",
  code: BLUEPRINT_PRODUCTION_HOLD_CODE,
  reason: BLUEPRINT_PRODUCTION_HOLD_REASON,
  latencyProbe: PRODUCTION_LATENCY_PROBE_STATUS,
  capabilities: Object.freeze({
    deterministicRuntimeBound: false,
    dedicatedControlProcessBound: false,
    watchdogRegistered: false,
    outputActuatorBound: false,
    latencyProbeRunning: false,
    realtimeSchedulerApplied: false,
  }),
});

/**
 * Current production capability statement. A real composition root should
 * replace this hold with an active runtime rather than mutating this object.
 */
export function getBlueprintProductionSafetyStatus(): BlueprintProductionSafetyStatus {
  // Reassert on health evaluation so a metrics-registry reset or hot reload
  // cannot leave the held/down series absent.
  publishProductionLatencyProbeStatus();
  return HELD_STATUS;
}

/**
 * Fail-closed middleware mounted before the legacy safe-state router. Keeping
 * the response at 503 makes the product boundary machine-visible to operators,
 * monitors, and API clients instead of returning `{ statuses: [] }`.
 */
export function createBlueprintProductionHoldMiddleware(): RequestHandler {
  return (_req: Request, res: Response, _next: NextFunction): void => {
    res.status(503).json({
      error: BLUEPRINT_PRODUCTION_HOLD_CODE,
      message: BLUEPRINT_PRODUCTION_HOLD_REASON,
      safetyRuntime: HELD_STATUS,
    });
  };
}
