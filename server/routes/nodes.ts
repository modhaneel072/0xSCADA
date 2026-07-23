/**
 * Node / Validator Routes — combined surface (#454 + #456)
 *
 * This router backs two complementary, read-only operator features mounted under
 * `/api/nodes`:
 *
 *   #454 Cross-Node State Query
 *     GET /:id/state/:key
 *       Proxy a `state_get` to a *specific* validator's oxscada RPC endpoint and
 *       VERIFY the validator's signature against its registered public key
 *       before returning anything. Useful for divergence investigations.
 *
 *       Distinct error status codes (acceptance criteria):
 *         - validator-unreachable → 502
 *         - validator-timeout     → 504
 *         - signature-invalid     → 502 (distinct `code`)
 *         - key-not-found         → 404
 *         - unknown-validator     → 404
 *
 *       Rate-limited per-operator via the sliding-window limiter
 *       (`server/middleware/api-gateway.ts`), keyed by operator id.
 *       INTEGRATION (#447): swap for the Redis limiter keyed the same way;
 *       `operatorKeyExtractor` is the unchanged seam.
 *
 *   #456 Slashing & Liveness Visualizer history
 *     GET /                      → list known validators (id + label + stake)
 *     GET /history?window=…      → per-validator attestation participation
 *                                  history (hit / miss / late) over a window,
 *                                  consumed by the client-side pure simulator.
 *
 *       Read-only / no mutations. The attestation data is synthesised
 *       DETERMINISTICALLY from a seed until the canonical Validator Dashboard
 *       data layer lands (isolated in `generateValidatorHistory`).
 */

import { Router, type Request, type Response } from "express";
import { z } from "zod";
import pino from "pino";
import { rateLimitMiddleware } from "../middleware/api-gateway";
import {
  NodeRpcClient,
  NodeUnreachableError,
  NodeTimeoutError,
  StateKeyNotFoundError,
  NodeRpcError,
  UnknownValidatorError,
} from "../blockchain/node-client";
import { verifySignedStateResponse, type SignedStateResponse } from "../blockchain/state-signature";
import {
  getValidatorNode,
  getActiveValidatorPubkey,
  type ValidatorNodeRecord,
  type ValidatorPubkeyRecord,
} from "../storage";
import type {
  AttestationRecord,
  AttestationStatus,
  TimelineWindow,
  ValidatorHistory,
} from "@shared/types/slashing";
import { WINDOW_MS } from "@shared/types/slashing";

const logger = pino({ name: "node-state-routes" });

// ─── Registry abstraction (injectable for tests) ───────────────────────────────

/**
 * Resolves validator metadata + the public key the server uses to verify a
 * validator's signed responses. Backed by the DB via `server/storage.ts` in
 * production; an in-memory implementation is injected in tests.
 */
export interface ValidatorRegistry {
  getNode(id: string): Promise<ValidatorNodeRecord | null>;
  getActivePubkey(nodeId: string): Promise<ValidatorPubkeyRecord | null>;
}

const defaultRegistry: ValidatorRegistry = {
  getNode: getValidatorNode,
  getActivePubkey: getActiveValidatorPubkey,
};

// ─── Validation ────────────────────────────────────────────────────────────────

// Validator ids and keys are URL path params. Keep them conservative: the id
// matches the registry id format; the key is any non-empty, reasonably-sized
// string (the value namespace of the validator is opaque to us).
const ParamsSchema = z.object({
  id: z.string().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/, "invalid validator id"),
  key: z.string().min(1).max(512),
});

const HistoryQuerySchema = z.object({
  /** Timeline window to return. */
  window: z.enum(["1h", "24h", "7d"]).default("24h"),
  /** Optional validator filter; when omitted, all known validators returned. */
  validatorId: z.string().min(1).optional(),
  /** Optional deterministic seed override (testing / reproducibility). */
  seed: z.coerce.number().int().optional(),
});

// ─── Per-operator rate limiting ─────────────────────────────────────────────────

/**
 * Extract the rate-limit bucket. Prefer an explicit operator identity (API key
 * record / header) and fall back to the request IP. This is the seam that a
 * Redis-backed limiter (#447) will reuse verbatim.
 */
export function operatorKeyExtractor(req: Request): string {
  const apiKeyName = (req as { apiKeyName?: string }).apiKeyName;
  if (apiKeyName) return `operator:${apiKeyName}`;
  const headerOperator = req.header("x-operator-id");
  if (headerOperator) return `operator:${headerOperator}`;
  return `ip:${req.ip || "unknown"}`;
}

const stateQueryRateLimit = rateLimitMiddleware({
  windowMs: 60_000,
  maxRequests: 60,
  keyExtractor: operatorKeyExtractor,
});

// ─── #456: Deterministic synthetic attestation history (INTEGRATION seam) ───────

/**
 * Tiny deterministic PRNG (mulberry32). Pure given its seed; used so the
 * synthesised history is stable across requests and unit-testable.
 */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Slot cadence per window: how far apart attestation duties are spaced. */
const SLOT_STEP_MS: Record<TimelineWindow, number> = {
  "1h": 60 * 1000, // 1-minute slots over 1h -> 60 records
  "24h": 30 * 60 * 1000, // 30-minute slots over 24h -> 48 records
  "7d": 6 * 60 * 60 * 1000, // 6-hour slots over 7d -> 28 records
};

interface ValidatorProfile {
  validatorId: string;
  label: string;
  stake: number;
  /** Base miss probability for this validator. */
  missRate: number;
  /** Probability a non-miss is `late` rather than `hit`. */
  lateRate: number;
  /** Inject a deterministic consecutive-miss outage of this many slots. */
  outageLength: number;
}

const VALIDATOR_PROFILES: ValidatorProfile[] = [
  { validatorId: "val-aurora", label: "Aurora", stake: 32000, missRate: 0.04, lateRate: 0.03, outageLength: 0 },
  { validatorId: "val-borealis", label: "Borealis", stake: 32000, missRate: 0.08, lateRate: 0.05, outageLength: 5 },
  { validatorId: "val-cygnus", label: "Cygnus", stake: 64000, missRate: 0.02, lateRate: 0.02, outageLength: 0 },
  { validatorId: "val-draco", label: "Draco", stake: 16000, missRate: 0.15, lateRate: 0.04, outageLength: 8 },
];

/**
 * Deterministically generate one validator's attestation history over a window.
 *
 * Pure: depends only on its arguments (profile, window, anchor, seed). Records
 * are returned in ascending slot/time order. An optional consecutive-miss
 * "outage" is injected near the end so liveness-fault detection has something
 * to highlight in the demo data.
 */
export function generateValidatorHistory(
  profile: ValidatorProfile,
  window: TimelineWindow,
  anchorMs: number,
  seed: number,
): ValidatorHistory {
  const span = WINDOW_MS[window];
  const step = SLOT_STEP_MS[window];
  const count = Math.max(1, Math.floor(span / step));
  const start = anchorMs - span;

  // Seed combines the global seed with a per-validator salt for variety.
  let salt = 0;
  for (let i = 0; i < profile.validatorId.length; i += 1) {
    salt = (salt * 31 + profile.validatorId.charCodeAt(i)) | 0;
  }
  const rand = mulberry32((seed ^ salt) >>> 0);

  const outageStart =
    profile.outageLength > 0 ? Math.max(0, count - profile.outageLength - 1) : -1;
  const outageEnd = outageStart === -1 ? -1 : outageStart + profile.outageLength;

  const records: AttestationRecord[] = [];
  for (let i = 0; i < count; i += 1) {
    let status: AttestationStatus;
    if (outageStart !== -1 && i >= outageStart && i < outageEnd) {
      status = "miss"; // deterministic injected outage
    } else {
      const r = rand();
      if (r < profile.missRate) status = "miss";
      else if (r < profile.missRate + profile.lateRate) status = "late";
      else status = "hit";
    }
    records.push({ slot: i, timestamp: start + i * step, status });
  }

  return {
    validatorId: profile.validatorId,
    label: profile.label,
    stake: profile.stake,
    records,
  };
}

const DEFAULT_SEED = 0x5cada;

// ─── Router factory ──────────────────────────────────────────────────────────

export interface NodeRoutesDeps {
  registry?: ValidatorRegistry;
  client?: NodeRpcClient;
}

/**
 * Build the combined node/validator router. Dependencies are injectable so the
 * #454 cross-node state route can be integration-tested against a local fake
 * node + in-memory registry; the #456 history routes are dependency-free.
 */
export function createNodeRoutes(deps: NodeRoutesDeps = {}): Router {
  const router = Router();
  const registry = deps.registry ?? defaultRegistry;
  const client = deps.client ?? new NodeRpcClient();

  // ── #456: read-only attestation history ──
  // Registered before the rate-limited proxy route so the read-only visualizer
  // endpoints are not gated by the per-operator proxy budget. `/` and `/history`
  // are single-segment paths and never collide with `/:id/state/:key`.

  /** List known validators (id + label + stake), no history. */
  router.get("/", (_req: Request, res: Response) => {
    res.json({
      validators: VALIDATOR_PROFILES.map((p) => ({
        validatorId: p.validatorId,
        label: p.label,
        stake: p.stake,
      })),
    });
  });

  /**
   * GET /api/nodes/history?window=24h[&validatorId=...][&seed=...]
   *
   * Returns deterministic per-validator attestation history for the requested
   * window. Read-only.
   */
  router.get("/history", (req: Request, res: Response) => {
    const parsed = HistoryQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid history query", details: parsed.error.flatten() });
    }
    const { window, validatorId, seed } = parsed.data;
    const anchorMs = Date.now();
    const effectiveSeed = seed ?? DEFAULT_SEED;

    const profiles = validatorId
      ? VALIDATOR_PROFILES.filter((p) => p.validatorId === validatorId)
      : VALIDATOR_PROFILES;

    if (validatorId && profiles.length === 0) {
      return res.status(404).json({ error: `Unknown validator: ${validatorId}` });
    }

    const histories = profiles.map((p) =>
      generateValidatorHistory(p, window, anchorMs, effectiveSeed),
    );

    return res.json({
      window,
      anchorMs,
      seed: effectiveSeed,
      validators: histories,
    });
  });

  // ── #454: per-operator rate-limited cross-node state proxy ──
  // The rate limiter is applied only to the proxy route below so the read-only
  // history endpoints above remain ungated.

  /**
   * GET /:id/state/:key
   * Proxy a state query to validator `:id` and return its signed response after
   * verifying the signature.
   */
  router.get("/:id/state/:key", stateQueryRateLimit, async (req: Request, res: Response) => {
    const parsed = ParamsSchema.safeParse(req.params);
    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid request parameters",
        code: "invalid-params",
        details: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
      });
    }
    const { id, key } = parsed.data;

    // 1. Resolve validator + its registered verification key.
    let node: ValidatorNodeRecord | null;
    let pubkey: ValidatorPubkeyRecord | null;
    try {
      node = await registry.getNode(id);
      pubkey = node ? await registry.getActivePubkey(id) : null;
    } catch (err) {
      logger.error({ err: (err as Error).message, nodeId: id }, "validator registry lookup failed");
      return res.status(500).json({ error: "Failed to resolve validator", code: "registry-error" });
    }

    if (!node || node.enabled === false) {
      const unknown = new UnknownValidatorError(id);
      return res.status(404).json({ error: unknown.message, code: unknown.code, nodeId: id });
    }

    if (!pubkey) {
      // We refuse to proxy a response we cannot verify.
      return res.status(409).json({
        error: `No active public key registered for validator ${id}`,
        code: "no-registered-pubkey",
        nodeId: id,
      });
    }

    // 2. Proxy the state query to the validator's RPC.
    let signed: SignedStateResponse;
    try {
      signed = await client.getState(id, node.rpcUrl, key);
    } catch (err) {
      return handleClientError(err, res, id, key);
    }

    // 3. VERIFY the signature BEFORE returning to the client.
    const verdict = verifySignedStateResponse(signed, pubkey.publicKeyPem);
    if (!verdict.valid) {
      logger.warn(
        { nodeId: id, key, reason: verdict.reason },
        "validator state response failed signature verification",
      );
      // Proxied successfully but the payload is not trustworthy. 502 Bad Gateway
      // with a distinct code so clients can distinguish from a transport error.
      return res.status(502).json({
        error: "Validator response failed signature verification",
        code: "signature-invalid",
        reason: verdict.reason,
        nodeId: id,
        key,
      });
    }

    // 4. Return the verified value + signature.
    return res.status(200).json({
      nodeId: id,
      key: signed.key,
      value: signed.value,
      blockHeight: signed.blockHeight,
      signature: signed.signature,
      keyId: signed.keyId ?? pubkey.keyId ?? null,
      verified: true,
    });
  });

  return router;
}

/** Map node-client errors onto distinct HTTP status codes + stable `code`s. */
function handleClientError(err: unknown, res: Response, nodeId: string, key: string): Response {
  if (err instanceof StateKeyNotFoundError) {
    return res.status(404).json({ error: err.message, code: "key-not-found", nodeId, key });
  }
  if (err instanceof NodeTimeoutError) {
    return res.status(504).json({ error: err.message, code: "validator-timeout", nodeId });
  }
  if (err instanceof NodeUnreachableError) {
    return res.status(502).json({ error: err.message, code: "validator-unreachable", nodeId });
  }
  if (err instanceof NodeRpcError) {
    return res.status(502).json({ error: err.message, code: "validator-rpc-error", nodeId, httpStatus: err.httpStatus });
  }
  logger.error({ err: (err as Error).message, nodeId, key }, "unexpected error proxying state query");
  return res.status(502).json({ error: "Failed to query validator state", code: "validator-error", nodeId });
}

/**
 * Default combined router instance for mounting in `server/routes.ts`.
 * Exported under both names the two source branches used so existing imports
 * (`nodeRoutes` from #454, `nodesRoutes` from #456) both resolve to the single
 * combined router.
 */
export const nodeRoutes = createNodeRoutes();
export { nodeRoutes as nodesRoutes };

export default nodeRoutes;
