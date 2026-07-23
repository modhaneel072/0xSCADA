import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import express, { type Router } from "express";
import { createServer, type Server } from "node:http";

import { adminAnchorRoutes, getSwitchHistory } from "../routes/admin-anchor";
import { alarmRoutes } from "../routes/alarms";
import { alarmCorrelationRoutes } from "../routes/alarm-correlation";
import {
  blueprintSafeStateRoutes,
  safeStateRegistry,
} from "../routes/blueprint-safe-state";
import { blueprintRoutes } from "../routes/blueprints";
import { marketplaceRoutes } from "../routes/marketplace";
import { predictiveRoutes } from "../routes/predictive";
import { tuningRoutes } from "../routes/tuning";
import { twinRoutes } from "../routes/twin";
import {
  _resetControlPlaneAuthCache,
} from "../middleware/control-plane-auth";
import {
  _resetAnchorBackendState,
  getAnchorBackend,
  getAnchorBackendSnapshot,
  setAnchorBackend,
} from "../bridge/anchor-backend";
import { natsPublisher } from "../services/nats";

interface TestServer {
  server: Server;
  baseUrl: string;
}

function startServer(mounts: Array<[string, Router]>): Promise<TestServer> {
  const app = express();
  app.use(express.json());
  for (const [path, router] of mounts) app.use(path, router);

  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

describe("control-plane mutation authentication", () => {
  let testServer: TestServer;
  const originalApiKeys = process.env.API_KEYS;
  const originalAnchorBackend = process.env.ANCHOR_BACKEND;
  const originalReplicaCount = process.env.OXSCADA_REPLICA_COUNT;

  beforeAll(async () => {
    process.env.ANCHOR_BACKEND = "node";
    process.env.OXSCADA_REPLICA_COUNT = "1";
    process.env.API_KEYS = [
      "read-key:read-only:operator",
      "anchor-key:anchor-alice:operator+anchor.admin",
      "alarm-key:alarm-alice:operator+alarms.write",
      "safety-key:safety-alice:operator+safety.resume",
      "marketplace-key:market-alice:operator+marketplace.write",
      "predictive-key:predictive-alice:operator+predictive.write",
      "tuning-write-key:tuning-writer:operator+tuning.write",
      "tuning-approve-key:tuning-approver:operator+tuning.approve",
      "twin-key:twin-alice:operator+twin.write",
    ].join(",");
    _resetControlPlaneAuthCache();
    _resetAnchorBackendState();
    vi.spyOn(natsPublisher, "isConnected").mockReturnValue(true);
    vi.spyOn(natsPublisher, "publish").mockReturnValue(true);

    testServer = await startServer([
      ["/api/admin/anchor-backend", adminAnchorRoutes],
      ["/api/alarms", alarmRoutes],
      ["/api/alarm-correlation", alarmCorrelationRoutes],
      ["/api/blueprint-safe-state", blueprintSafeStateRoutes],
      ["/api/blueprints", blueprintRoutes],
      ["/api/marketplace", marketplaceRoutes],
      ["/api/predictive", predictiveRoutes],
      ["/api/tuning", tuningRoutes],
      ["/api/twin", twinRoutes],
    ]);
  });

  afterAll(async () => {
    await closeServer(testServer.server);
    if (originalApiKeys === undefined) delete process.env.API_KEYS;
    else process.env.API_KEYS = originalApiKeys;
    if (originalAnchorBackend === undefined) delete process.env.ANCHOR_BACKEND;
    else process.env.ANCHOR_BACKEND = originalAnchorBackend;
    if (originalReplicaCount === undefined) delete process.env.OXSCADA_REPLICA_COUNT;
    else process.env.OXSCADA_REPLICA_COUNT = originalReplicaCount;
    _resetControlPlaneAuthCache();
    _resetAnchorBackendState();
    vi.restoreAllMocks();
  });

  const anonymousMutations: Array<{
    name: string;
    path: string;
    method: "POST" | "PUT" | "DELETE";
    body?: unknown;
  }> = [
    {
      name: "anchor backend commit",
      path: "/api/admin/anchor-backend",
      method: "POST",
      body: {
        backend: "both",
        dryRun: false,
        confirm: true,
        confirmToken: "confirm-switch-both",
        operator: "spoofed-admin",
      },
    },
    {
      name: "phi alarm injection",
      path: "/api/alarms/phi/check",
      method: "POST",
    },
    {
      name: "alarm injection",
      path: "/api/alarm-correlation/alarms",
      method: "POST",
      body: { alarms: [{ id: "anonymous-alarm", timestamp: Date.now() }] },
    },
    {
      name: "safe-state resume",
      path: "/api/blueprint-safe-state/not-registered/resume",
      method: "POST",
      body: { operator: "spoofed-operator", reason: "resume it" },
    },
    {
      name: "blueprint import",
      path: "/api/blueprints/import",
      method: "POST",
      body: { cmTypePackage: [] },
    },
    {
      name: "marketplace publication",
      path: "/api/marketplace/plugins",
      method: "POST",
      body: {
        id: "anonymous-plugin",
        name: "Anonymous plugin",
        version: "1.0.0",
        category: "custom",
      },
    },
    {
      name: "predictive data injection",
      path: "/api/predictive/ingest",
      method: "POST",
      body: {
        tagId: "anonymous-tag",
        points: [{ timestamp: Date.now(), value: 12 }],
      },
    },
    {
      name: "PID loop registration",
      path: "/api/tuning/loops",
      method: "POST",
      body: {
        id: "anonymous-loop",
        name: "Anonymous loop",
        gains: { kp: 1, ki: 0.1, kd: 0 },
        setpoint: 10,
        outputMin: 0,
        outputMax: 100,
      },
    },
    {
      name: "digital-twin registration",
      path: "/api/twin/models",
      method: "POST",
      body: {
        id: "anonymous-model",
        name: "Anonymous model",
        components: [
          {
            id: "tank",
            type: "tank",
            name: "Tank",
            config: {},
            initialState: {},
            connections: [],
          },
        ],
        timeStepMs: 1000,
      },
    },
  ];

  for (const mutation of anonymousMutations) {
    it(`rejects anonymous ${mutation.name} before mutation`, async () => {
      const response = await fetch(`${testServer.baseUrl}${mutation.path}`, {
        method: mutation.method,
        headers: { "content-type": "application/json", "x-operator-id": "spoofed-operator" },
        body: mutation.body === undefined ? undefined : JSON.stringify(mutation.body),
      });

      expect(response.status).toBe(401);
    });

    it(`rejects operator ${mutation.name} without its required scope`, async () => {
      const response = await fetch(`${testServer.baseUrl}${mutation.path}`, {
        method: mutation.method,
        headers: {
          "content-type": "application/json",
          "x-api-key": "read-key",
          "x-operator-id": "spoofed-operator",
        },
        body: mutation.body === undefined ? undefined : JSON.stringify(mutation.body),
      });

      expect(response.status).toBe(403);
    });
  }

  it("enforces a mutation scope before every control-plane mutating handler", async () => {
    const endpoints: Array<[method: string, path: string]> = [
      ["POST", "/api/admin/anchor-backend"],
      ["POST", "/api/alarm-correlation/alarms"],
      ["POST", "/api/alarm-correlation/alarms/a/clear"],
      ["POST", "/api/alarm-correlation/alarms/a/acknowledge"],
      ["PUT", "/api/alarm-correlation/rules/r"],
      ["DELETE", "/api/alarm-correlation/rules/r"],
      ["POST", "/api/alarm-correlation/rules/r/enable"],
      ["POST", "/api/alarm-correlation/rules/r/disable"],
      ["PUT", "/api/alarm-correlation/topology"],
      ["DELETE", "/api/alarm-correlation/topology/e"],
      ["PUT", "/api/alarm-correlation/suppression-policy"],
      ["POST", "/api/blueprint-safe-state/b/resume"],
      ["POST", "/api/blueprints/cm-types"],
      ["POST", "/api/blueprints/unit-types"],
      ["POST", "/api/blueprints/phase-types"],
      ["POST", "/api/blueprints/import"],
      ["POST", "/api/blueprints/seed"],
      ["POST", "/api/predictive/ingest"],
      ["PUT", "/api/predictive/thresholds/t"],
      ["POST", "/api/predictive/alerts/a/acknowledge"],
      ["POST", "/api/tuning/loops"],
      ["PUT", "/api/tuning/loops/l/envelope"],
      ["POST", "/api/tuning/loops/l/tune/relay"],
      ["POST", "/api/tuning/loops/l/tune/cohen-coon"],
      ["POST", "/api/tuning/loops/l/tune/rl"],
      ["POST", "/api/tuning/proposals/p/approve"],
      ["POST", "/api/tuning/proposals/p/reject"],
      ["POST", "/api/twin/models"],
      ["DELETE", "/api/twin/models/m"],
      ["POST", "/api/twin/models/m/start"],
      ["POST", "/api/twin/models/m/stop"],
      ["POST", "/api/twin/models/m/reset"],
      ["POST", "/api/twin/models/m/step"],
      ["POST", "/api/twin/models/m/sync"],
      ["POST", "/api/twin/scenarios"],
      ["POST", "/api/twin/models/m/rollback-simulation"],
      ["POST", "/api/marketplace/plugins"],
      ["POST", "/api/marketplace/plugins/p/install"],
      ["POST", "/api/marketplace/plugins/p/update"],
      ["PUT", "/api/marketplace/plugins/p/config"],
      ["POST", "/api/marketplace/plugins/p/start"],
      ["POST", "/api/marketplace/plugins/p/stop"],
      ["POST", "/api/marketplace/plugins/p/enable"],
      ["POST", "/api/marketplace/plugins/p/disable"],
      ["DELETE", "/api/marketplace/plugins/p"],
      ["POST", "/api/marketplace/plugins/p/invoke"],
    ];

    for (const [method, path] of endpoints) {
      const response = await fetch(`${testServer.baseUrl}${path}`, {
        method,
        headers: {
          "content-type": "application/json",
          "x-api-key": "read-key",
        },
        body: method === "DELETE" ? undefined : "{}",
      });
      await response.body?.cancel();
      expect(response.status, `${method} ${path}`).toBe(403);
    }
  });

  it("does not disclose a confirmation token and rejects the former public-token commit", async () => {
    _resetAnchorBackendState();

    const dryRun = await fetch(`${testServer.baseUrl}/api/admin/anchor-backend`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "anchor-key",
      },
      body: JSON.stringify({ backend: "l2", dryRun: true }),
    });
    expect(dryRun.status).toBe(200);
    const preview = await dryRun.json() as Record<string, unknown>;
    expect(preview).not.toHaveProperty("confirmToken");
    expect(preview.runtimeReady).toBe(false);
    expect(preview.runtimePreparationSupported).toBe(true);
    expect(preview).toMatchObject({
      currentBackend: "node",
      backendRevision: 0,
    });

    const formerPublicToken = await fetch(
      `${testServer.baseUrl}/api/admin/anchor-backend`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "anchor-key",
        },
        body: JSON.stringify({
          backend: "l2",
          dryRun: false,
          confirmToken: "confirm-switch-l2",
        }),
      },
    );
    expect(formerPublicToken.status).toBe(400);
    const error = await formerPublicToken.json() as Record<string, unknown>;
    expect(error).not.toHaveProperty("expected");
    expect(JSON.stringify(error)).not.toContain("confirm-switch-l2");
    expect(getAnchorBackend()).toBe("node");
  });

  it("rejects an authorized switch when the target runtime is not initialized", async () => {
    _resetAnchorBackendState();
    expect(getAnchorBackend()).toBe("node");
    const preview = getAnchorBackendSnapshot();
    const historyLength = getSwitchHistory().length;

    const response = await fetch(`${testServer.baseUrl}/api/admin/anchor-backend`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "anchor-key",
        "x-operator-id": "spoofed-header",
      },
      body: JSON.stringify({
        backend: "l2",
        dryRun: false,
        confirm: true,
        expectedCurrentBackend: preview.backend,
        expectedBackendRevision: preview.revision,
        confirmToken: "confirm-switch-l2",
        operator: "spoofed-body",
      }),
    });

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      code: "anchor-backend-unavailable",
      backend: "l2",
    });
    expect(getAnchorBackend()).toBe("node");
    expect(getSwitchHistory()).toHaveLength(historyLength);
  });

  it("rejects a commit when the backend changed after the operator's dry-run", async () => {
    _resetAnchorBackendState();
    const preview = getAnchorBackendSnapshot();
    const historyLength = getSwitchHistory().length;
    const publishCalls = vi.mocked(natsPublisher.publish).mock.calls.length;

    // Simulate another operator changing node -> both after this preview.
    setAnchorBackend("both");

    const response = await fetch(`${testServer.baseUrl}/api/admin/anchor-backend`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "anchor-key",
      },
      body: JSON.stringify({
        backend: "node",
        dryRun: false,
        confirm: true,
        expectedCurrentBackend: preview.backend,
        expectedBackendRevision: preview.revision,
      }),
    });

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      code: "anchor-backend-preview-stale",
      committed: false,
      expectedBackend: "node",
      expectedBackendRevision: 0,
      currentBackend: "both",
      currentBackendRevision: 1,
    });
    expect(getAnchorBackend()).toBe("both");
    expect(getSwitchHistory()).toHaveLength(historyLength);
    expect(vi.mocked(natsPublisher.publish)).toHaveBeenCalledTimes(publishCalls);
  });

  it("commits an authorized switch when its runtime is available and binds audit identity", async () => {
    _resetAnchorBackendState();
    setAnchorBackend("both");
    const preview = getAnchorBackendSnapshot();

    const response = await fetch(`${testServer.baseUrl}/api/admin/anchor-backend`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "anchor-key",
        "x-operator-id": "spoofed-header",
      },
      body: JSON.stringify({
        backend: "node",
        dryRun: false,
        confirm: true,
        expectedCurrentBackend: preview.backend,
        expectedBackendRevision: preview.revision,
        operator: "spoofed-body",
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      committed: true,
      currentBackend: "node",
      backendRevision: preview.revision + 1,
      auditStatus: "queued",
      auditQueueId: expect.stringMatching(/^anchor-switch-/),
    });
    expect(getAnchorBackend()).toBe("node");
    expect(getSwitchHistory()[0]).toMatchObject({
      previous: "both",
      current: "node",
      operator: "anchor-alice",
      auditStatus: "queued",
      auditQueueId: expect.stringMatching(/^anchor-switch-/),
    });
  });

  it("leaves routing untouched when the target audit queue rejects the intent", async () => {
    _resetAnchorBackendState();
    setAnchorBackend("both");
    const preview = getAnchorBackendSnapshot();
    const historyLength = getSwitchHistory().length;
    vi.mocked(natsPublisher.publish).mockReturnValueOnce(false);

    const response = await fetch(`${testServer.baseUrl}/api/admin/anchor-backend`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "anchor-key",
      },
      body: JSON.stringify({
        backend: "node",
        dryRun: false,
        confirm: true,
        expectedCurrentBackend: preview.backend,
        expectedBackendRevision: preview.revision,
      }),
    });

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toMatchObject({
      code: "anchor-audit-delivery-failed",
      committed: false,
      currentBackend: "both",
    });
    expect(getAnchorBackend()).toBe("both");
    expect(getSwitchHistory()).toHaveLength(historyLength);
  });

  it("allows an authorized alarm source to ingest an alarm", async () => {
    const response = await fetch(`${testServer.baseUrl}/api/alarm-correlation/alarms`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "alarm-key",
      },
      body: JSON.stringify({
        alarms: [{ id: "authorized-alarm", timestamp: Date.now(), severity: "high" }],
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ingested: 1 });
  });

  it("allows an authorized alarm operator to run the phi alarm check", async () => {
    const response = await fetch(`${testServer.baseUrl}/api/alarms/phi/check`, {
      method: "POST",
      headers: { "x-api-key": "alarm-key" },
    });

    expect(response.status).toBe(200);
  });

  it("binds safe-state resume audit identity to the authenticated principal", async () => {
    const resume = vi.fn().mockResolvedValue({
      blueprintId: "bp-auth",
      runState: "RUNNING",
      safeState: "hold-last",
    });
    const getSpy = vi.spyOn(safeStateRegistry, "get").mockReturnValue({ resume } as never);

    try {
      const response = await fetch(
        `${testServer.baseUrl}/api/blueprint-safe-state/bp-auth/resume`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-api-key": "safety-key",
            "x-operator-id": "spoofed-header",
          },
          body: JSON.stringify({
            operator: "spoofed-body",
            reason: "verified plant state",
          }),
        },
      );

      expect(response.status).toBe(200);
      expect(resume).toHaveBeenCalledWith("safety-alice", "verified plant state");
    } finally {
      getSpy.mockRestore();
    }
  });

  it("allows an authorized predictive source to ingest telemetry", async () => {
    const response = await fetch(`${testServer.baseUrl}/api/predictive/ingest`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "predictive-key",
      },
      body: JSON.stringify({
        tagId: "authorized-tag",
        points: [{ timestamp: Date.now(), value: 12 }],
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ingested: 1 });
  });

  it("uses the authenticated approver for a PID tuning decision", async () => {
    const loopId = "authorized-loop";
    const register = await fetch(`${testServer.baseUrl}/api/tuning/loops`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "tuning-write-key",
      },
      body: JSON.stringify({
        id: loopId,
        name: "Authorized loop",
        gains: { kp: 1, ki: 0.1, kd: 0 },
        setpoint: 10,
        outputMin: 0,
        outputMax: 100,
      }),
    });
    expect(register.status).toBe(201);

    const tune = await fetch(
      `${testServer.baseUrl}/api/tuning/loops/${loopId}/tune/cohen-coon`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "tuning-write-key",
        },
        body: JSON.stringify({
          model: { gain: 1, timeConstantS: 10, deadTimeS: 1 },
        }),
      },
    );
    expect(tune.status).toBe(201);
    const proposal = await tune.json() as { id: string };

    const approve = await fetch(
      `${testServer.baseUrl}/api/tuning/proposals/${proposal.id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": "tuning-approve-key",
          "x-operator-id": "spoofed-header",
        },
        body: JSON.stringify({
          approver: "spoofed-body",
          comment: "reviewed",
        }),
      },
    );

    expect(approve.status).toBe(200);
    await expect(approve.json()).resolves.toMatchObject({
      status: "applied",
      decidedBy: "tuning-approver",
    });
  });

  it("allows an authorized operator to register a digital twin", async () => {
    const response = await fetch(`${testServer.baseUrl}/api/twin/models`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "twin-key",
      },
      body: JSON.stringify({
        id: "authorized-model",
        name: "Authorized model",
        components: [
          {
            id: "tank",
            type: "tank",
            name: "Tank",
            config: {},
            initialState: {},
            connections: [],
          },
        ],
        timeStepMs: 1000,
      }),
    });

    expect(response.status).toBe(201);
  });

  it("allows an authorized publisher to add a marketplace plugin", async () => {
    const response = await fetch(`${testServer.baseUrl}/api/marketplace/plugins`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "marketplace-key",
      },
      body: JSON.stringify({
        id: "authorized-plugin",
        name: "Authorized plugin",
        version: "1.0.0",
        category: "custom",
      }),
    });

    expect(response.status).toBe(201);
  });
});
