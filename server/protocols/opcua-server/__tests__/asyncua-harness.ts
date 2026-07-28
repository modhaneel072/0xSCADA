/**
 * Local harness for the opcua-asyncio conformance smoke test (#461).
 *
 * `opcua_asyncio_smoke.py` needs a running UA server. Starting the real product
 * requires PostgreSQL (`runtime.ts` refuses the SQLite fallback), which is a
 * heavy prerequisite for what is fundamentally a protocol-conformance check, so
 * this harness starts the same {@link OxScadaOpcuaServer} over an in-memory
 * {@link TagDataSource} fixture instead. What it proves is the UA surface —
 * address space, security profile, sessions, subscriptions — **not** the Drizzle
 * queries in `runtime.ts`, which still need a database.
 *
 * It is not a vitest file (vitest collects only `*.test.ts` / `*.spec.ts`), and
 * nothing imports it; it only ever runs when a human invokes it:
 *
 *     npx tsx server/protocols/opcua-server/__tests__/asyncua-harness.ts None <dir>
 *     npx tsx server/protocols/opcua-server/__tests__/asyncua-harness.ts Basic256Sha256 <dir>
 *
 * SAFETY: the bind is hardcoded to `127.0.0.1` on an ephemeral port — the host
 * is not configurable here at all, so this can never be pointed at a routable
 * interface — the configuration still goes through `loadOpcuaServerConfig`, and
 * the process self-terminates after {@link MAX_LIFETIME_MS} so a forgotten
 * harness cannot linger. The credentials below are a fixture, not a seeded
 * account: they exist only inside this process's in-memory user lookup.
 *
 * It prints `ENDPOINT`, `CLIENT_CERT`, `CLIENT_KEY`, `NAMESPACE_INDEX` and then
 * `READY`, which is what the runner script greps for.
 */

import fs from "node:fs";
import path from "node:path";
import { scryptSync } from "node:crypto";
import { loadOpcuaServerConfig } from "../config";
import { OxScadaOpcuaServer, type TagDataSource } from "../index";
import type { SourceSite, SourceTag, TagSample } from "../types";
import type { AuthUserRecord, UserLookup } from "../user-auth";

/** Hard cap on how long the harness may stay up. */
const MAX_LIFETIME_MS = 180_000;

/** How often the fixture publishes a new value, to drive subscriptions. */
const UPDATE_INTERVAL_MS = 150;

const SITE: SourceSite = { id: "SITE-01", name: "Refinery" };
const TAGS: SourceTag[] = [
  { tagId: "PT-101.PV", siteId: "SITE-01", dataType: "number", units: "bar" },
  { tagId: "RUN", siteId: "SITE-01", dataType: "boolean" },
];

class FixtureDataSource implements TagDataSource {
  private readonly latest = new Map<string, TagSample>();
  private readonly listeners = new Set<(sample: TagSample) => void>();

  async loadSites(): Promise<SourceSite[]> {
    return [SITE];
  }

  async loadTags(): Promise<SourceTag[]> {
    return TAGS;
  }

  async readTag(tagId: string): Promise<TagSample | undefined> {
    return this.latest.get(tagId);
  }

  subscribe(onChange: (sample: TagSample) => void): () => void {
    this.listeners.add(onChange);
    return () => {
      this.listeners.delete(onChange);
    };
  }

  push(sample: TagSample): void {
    this.latest.set(sample.tagId, sample);
    for (const listener of this.listeners) listener(sample);
  }
}

const SALT = "0011223344556677";
const PASSWORD = "hunter2-correct-horse";
const OPERATOR: AuthUserRecord = {
  id: "harness-user-1",
  username: "ua-operator",
  passwordHash: `scrypt$${SALT}$${scryptSync(PASSWORD, Buffer.from(SALT, "hex"), 32).toString("hex")}`,
  isActive: true,
};
const userLookup: UserLookup = async (username) =>
  username === OPERATOR.username ? OPERATOR : null;

async function main(): Promise<void> {
  const policyArg = process.argv[2] ?? "None";
  if (policyArg !== "None" && policyArg !== "Basic256Sha256") {
    throw new Error(
      `Unknown security policy "${policyArg}"; use None or Basic256Sha256.`,
    );
  }
  const pkiFolder = process.argv[3];
  if (!pkiFolder) {
    throw new Error("Usage: asyncua-harness.ts <None|Basic256Sha256> <pkiDir>");
  }
  fs.mkdirSync(pkiFolder, { recursive: true });

  const opcua = await import("node-opcua");

  // Provision the client certificate the Python client will present, and put it
  // in the server's trust list *before* the server starts. node-opcua reads the
  // trust list at initialize() time, and the server keeps
  // `trustUnknownClientCertificates: false`, so this is the real PKI path.
  const clientRoot = path.join(pkiFolder, "client");
  fs.mkdirSync(clientRoot, { recursive: true });
  const clientCerts = new opcua.OPCUACertificateManager({
    rootFolder: clientRoot,
    automaticallyAcceptUnknownCertificate: false,
  });
  await clientCerts.initialize();
  const clientCertFile = path.join(
    clientCerts.ownCertFolder,
    "asyncua_client_cert.pem",
  );
  await clientCerts.createSelfSignedCertificate({
    applicationUri: "urn:0xscada:asyncua-smoke",
    dns: ["localhost"],
    subject: "/CN=0xSCADA asyncua smoke client",
    startDate: new Date(),
    validity: 30,
    outputFile: clientCertFile,
  });
  const trustedCerts = path.join(pkiFolder, "trusted", "certs");
  fs.mkdirSync(trustedCerts, { recursive: true });
  fs.copyFileSync(clientCertFile, path.join(trustedCerts, "asyncua_client.pem"));

  const config = loadOpcuaServerConfig({
    enabled: true,
    // SecurityPolicy None is refused in hardened environments; the
    // Basic256Sha256 run is the one that mirrors the production posture.
    env: policyArg === "None" ? "test" : "production",
    host: "127.0.0.1",
    port: 0,
    pkiFolder,
    securityPolicy: policyArg,
    disableCertificateFileWatchers: true,
    minSamplingIntervalMs: 10,
  });

  const dataSource = new FixtureDataSource();
  const now = (): string => new Date().toISOString();
  dataSource.push({
    tagId: "PT-101.PV",
    value: 12.5,
    dataType: "number",
    quality: "good",
    timestamp: now(),
  });
  dataSource.push({
    tagId: "RUN",
    value: true,
    dataType: "boolean",
    quality: "good",
    timestamp: now(),
  });

  const server = new OxScadaOpcuaServer({ config, dataSource, userLookup });
  await server.start();

  let tick = 0;
  const timer = setInterval(() => {
    tick += 1;
    dataSource.push({
      tagId: "PT-101.PV",
      value: 100 + tick,
      dataType: "number",
      quality: "good",
      timestamp: now(),
    });
  }, UPDATE_INTERVAL_MS);

  let stopping = false;
  const shutdown = async (): Promise<void> => {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    await server.stop().catch(() => undefined);
    await clientCerts.dispose().catch(() => undefined);
    process.exit(0);
  };

  const lifetime = setTimeout(() => void shutdown(), MAX_LIFETIME_MS);
  lifetime.unref();
  process.on("SIGTERM", () => void shutdown());
  process.on("SIGINT", () => void shutdown());

  console.log(`ENDPOINT ${server.endpoint}`);
  console.log(`CLIENT_CERT ${clientCertFile}`);
  console.log(`CLIENT_KEY ${clientCerts.privateKey}`);
  console.log(`USERNAME ${OPERATOR.username}`);
  console.log(`PASSWORD ${PASSWORD}`);
  console.log(`NAMESPACE_INDEX ${server.addressSpacePlan?.namespaceIndex}`);
  console.log("READY");
}

main().catch((err: unknown) => {
  console.error("HARNESS FAILED", err);
  process.exit(1);
});
