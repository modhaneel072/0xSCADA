/**
 * LIVE binding test for OPC-UA Server Mode (#461).
 *
 * The maintainer's review of the first cut was that "the whole node-opcua
 * binding layer [is] unexercised". This test exercises it for real: it starts
 * {@link OxScadaOpcuaServer} on an ephemeral loopback port, drives a genuine
 * node-opcua client session against it (browse the site folder, read a tag
 * value, subscribe and receive a DataChangeNotification for a pushed update),
 * and then shuts everything down.
 *
 * It also proves the security fix end-to-end on the wire: a second server
 * instance built with the shipped `allowAnonymous: false` refuses an anonymous
 * session, accepts a valid username/password from the injected user store, and
 * refuses a bad password.
 *
 * A third suite covers the profile operators actually deploy — the shipped
 * Basic256Sha256 Sign&Encrypt default, with the client certificate trusted
 * through the real PKI trust list — and asserts the loopback bind is not
 * reachable from a routable interface. The first two suites both run with
 * `securityPolicy: "None"`, so without it the default endpoint had no wire
 * coverage at all.
 *
 * Nothing here is mocked on the node-opcua side. If the package cannot be
 * loaded the whole suite is skipped with a printed reason rather than asserting
 * against a stand-in — see `isNodeOpcuaAvailable()`.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { scryptSync } from "node:crypto";
import { loadOpcuaServerConfig } from "../config";
import { isNodeOpcuaAvailable } from "../node-opcua-api";
import { resolveCertificatePaths } from "../security";
import { OxScadaOpcuaServer, type TagDataSource } from "../index";
import type { SourceSite, SourceTag, TagSample } from "../types";
import type { AuthUserRecord, UserLookup } from "../user-auth";

// ─── node-opcua client surface (loaded at runtime, like the server does) ─────

interface UaDataValue {
  value: { value: unknown };
  statusCode: { name: string };
}

interface UaMonitoredItem {
  on(event: "changed", handler: (dataValue: UaDataValue) => void): void;
}

interface UaSubscription {
  monitor(
    itemToMonitor: { nodeId: string; attributeId: number },
    parameters: {
      samplingInterval: number;
      discardOldest: boolean;
      queueSize: number;
    },
    timestampsToReturn: number,
  ): Promise<UaMonitoredItem>;
  terminate(): Promise<void>;
}

interface UaBrowseResult {
  references: { browseName: { name: string }; nodeId: { toString(): string } }[] | null;
}

interface UaSession {
  browse(nodeToBrowse: string): Promise<UaBrowseResult>;
  readVariableValue(nodeId: string): Promise<UaDataValue>;
  createSubscription2(options: Record<string, unknown>): Promise<UaSubscription>;
  close(): Promise<void>;
}

/** Subset of a UA EndpointDescription this test asserts on. */
interface UaEndpointDescription {
  endpointUrl: string;
  securityPolicyUri: string;
  securityMode: number;
  userIdentityTokens: { tokenType: number; policyId: string }[] | null;
}

interface UaClient {
  connect(endpointUrl: string): Promise<void>;
  createSession(userIdentity?: Record<string, unknown>): Promise<UaSession>;
  getEndpoints(): Promise<UaEndpointDescription[]>;
  disconnect(): Promise<void>;
  getCertificate(): Buffer;
}

/** Parameters node-opcua's PKI layer accepts for self-signed generation. */
interface SelfSignedCertificateParams {
  applicationUri: string;
  dns: string[];
  subject: string;
  startDate: Date;
  validity: number;
  outputFile: string;
}

interface UaCertificateManagerLike {
  initialize(): Promise<void>;
  dispose(): Promise<void>;
  createSelfSignedCertificate(
    params: SelfSignedCertificateParams,
  ): Promise<void>;
  readonly privateKey: string;
  readonly ownCertFolder: string;
}

interface UaClientApi {
  OPCUAClient: { create(options: Record<string, unknown>): UaClient };
  OPCUACertificateManager: new (options: {
    rootFolder: string;
    automaticallyAcceptUnknownCertificate: boolean;
    disableFileWatchers?: boolean;
  }) => UaCertificateManagerLike;
  AttributeIds: Record<string, number>;
  TimestampsToReturn: Record<string, number>;
  UserTokenType: Record<string, number>;
  MessageSecurityMode: Record<string, number>;
  SecurityPolicy: Record<string, string>;
}

async function loadClientApi(): Promise<UaClientApi> {
  const specifier: string = "node-opcua";
  const loaded = (await import(/* @vite-ignore */ specifier)) as Record<
    string,
    unknown
  >;
  const namespace =
    typeof loaded.OPCUAClient === "function"
      ? loaded
      : (loaded.default as Record<string, unknown>);
  return namespace as unknown as UaClientApi;
}

// ─── Test fixtures ───────────────────────────────────────────────────────────

const SITE: SourceSite = { id: "SITE-01", name: "Refinery" };
const TAGS: SourceTag[] = [
  { tagId: "PT-101.PV", siteId: "SITE-01", dataType: "number", units: "bar" },
  { tagId: "RUN", siteId: "SITE-01", dataType: "boolean" },
];

/** In-memory {@link TagDataSource}: the 0xSCADA side is not what is under test. */
class InMemoryTagDataSource implements TagDataSource {
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

function scryptHash(plaintext: string): string {
  const derived = scryptSync(plaintext, Buffer.from(SALT, "hex"), 32);
  return `scrypt$${SALT}$${derived.toString("hex")}`;
}

const OPERATOR: AuthUserRecord = {
  id: "user-1",
  username: "ua-operator",
  passwordHash: scryptHash(PASSWORD),
  isActive: true,
};

const userLookup: UserLookup = async (username) =>
  username === OPERATOR.username ? OPERATOR : null;

const nodeOpcuaAvailable = await isNodeOpcuaAvailable();
if (!nodeOpcuaAvailable) {
  // Truthful skip reason — never assert against a mock and call it verified.
  console.warn(
    "[#461] Skipping the OPC-UA live binding test: the `node-opcua` package could not be " +
      "loaded from this working tree. It is a declared dependency in package.json/package-lock.json, " +
      "so `npm ci` (as CI runs) makes this suite execute.",
  );
}

const TAG_NODE_ID_SUFFIX = "s=Tags/SITE-01/PT-101.PV";

function makeServer(
  dataSource: TagDataSource,
  pkiFolder: string,
  overrides: Record<string, unknown>,
): OxScadaOpcuaServer {
  return new OxScadaOpcuaServer({
    config: loadOpcuaServerConfig({
      enabled: true,
      env: "test",
      host: "127.0.0.1",
      port: 0,
      pkiFolder,
      disableCertificateFileWatchers: true,
      minSamplingIntervalMs: 10,
      ...overrides,
    }),
    dataSource,
    userLookup,
  });
}

describe.skipIf(!nodeOpcuaAvailable)(
  "OPC-UA server — live node-opcua binding",
  () => {
    let pkiFolder: string;
    let server: OxScadaOpcuaServer;
    let dataSource: InMemoryTagDataSource;
    let api: UaClientApi;

    beforeAll(async () => {
      api = await loadClientApi();
      pkiFolder = fs.mkdtempSync(path.join(os.tmpdir(), "oxscada-opcua-live-"));
      dataSource = new InMemoryTagDataSource();
      dataSource.push({
        tagId: "PT-101.PV",
        value: 12.5,
        dataType: "number",
        quality: "good",
        timestamp: new Date().toISOString(),
      });
      // SecurityPolicy None + anonymous is permitted here only because the bind
      // is loopback and env is "test"; the config layer refuses both otherwise.
      server = makeServer(dataSource, pkiFolder, {
        securityPolicy: "None",
        allowAnonymous: true,
        trustUnknownClientCertificates: true,
      });
      await server.start();
    }, 180_000);

    afterAll(async () => {
      await server?.stop();
      if (pkiFolder) fs.rmSync(pkiFolder, { recursive: true, force: true });
    }, 60_000);

    test("binds an ephemeral loopback port", () => {
      expect(server.isRunning).toBe(true);
      expect(server.boundPort).toBeGreaterThan(0);
      expect(server.endpoint).toBe(
        `opc.tcp://127.0.0.1:${server.boundPort}/0xscada`,
      );
    });

    test("a real client browses the address space, reads and subscribes", async () => {
      const client = api.OPCUAClient.create({
        endpointMustExist: false,
        connectionStrategy: { maxRetry: 0 },
      });
      await client.connect(server.endpoint);
      const session = await client.createSession();

      try {
        const plan = server.addressSpacePlan;
        expect(plan).not.toBeNull();
        const namespaceIndex = plan!.namespaceIndex;
        const sitesRoot = `ns=${namespaceIndex};s=Sites`;
        const siteFolder = `ns=${namespaceIndex};s=Sites/SITE-01`;
        const tagNodeId = `ns=${namespaceIndex};${TAG_NODE_ID_SUFFIX}`;

        // 1. Browse: Objects -> Sites -> SITE-01 -> tag variables.
        const sites = await session.browse(sitesRoot);
        expect(
          (sites.references ?? []).map((ref) => ref.browseName.name),
        ).toContain("Refinery");

        const tags = await session.browse(siteFolder);
        const tagNames = (tags.references ?? []).map(
          (ref) => ref.browseName.name,
        );
        expect(tagNames).toEqual(expect.arrayContaining(["PT-101.PV", "RUN"]));

        // 2. Read the seeded value back through the UA read service.
        const read = await session.readVariableValue(tagNodeId);
        expect(read.statusCode.name).toBe("Good");
        expect(read.value.value).toBeCloseTo(12.5, 6);

        // 3. Subscribe and receive a DataChangeNotification for a pushed update.
        const subscription = await session.createSubscription2({
          requestedPublishingInterval: 50,
          requestedLifetimeCount: 600,
          requestedMaxKeepAliveCount: 20,
          maxNotificationsPerPublish: 100,
          publishingEnabled: true,
          priority: 1,
        });

        const received: number[] = [];
        const monitored = await subscription.monitor(
          { nodeId: tagNodeId, attributeId: api.AttributeIds.Value },
          { samplingInterval: 20, discardOldest: true, queueSize: 10 },
          api.TimestampsToReturn.Both,
        );
        monitored.on("changed", (dataValue) => {
          if (typeof dataValue.value.value === "number") {
            received.push(dataValue.value.value);
          }
        });

        const updated = await new Promise<boolean>((resolve) => {
          const deadline = Date.now() + 20_000;
          const timer = setInterval(() => {
            if (received.includes(42.25)) {
              clearInterval(timer);
              resolve(true);
            } else if (Date.now() > deadline) {
              clearInterval(timer);
              resolve(false);
            } else {
              dataSource.push({
                tagId: "PT-101.PV",
                value: 42.25,
                dataType: "number",
                quality: "good",
                timestamp: new Date().toISOString(),
              });
            }
          }, 100);
        });

        expect(received.length).toBeGreaterThan(0);
        expect(updated).toBe(true);

        await subscription.terminate();
      } finally {
        await session.close();
        await client.disconnect();
      }
    }, 120_000);
  },
);

describe.skipIf(!nodeOpcuaAvailable)(
  "OPC-UA server — authentication against the existing user store",
  () => {
    let pkiFolder: string;
    let server: OxScadaOpcuaServer;
    let api: UaClientApi;

    beforeAll(async () => {
      api = await loadClientApi();
      pkiFolder = fs.mkdtempSync(path.join(os.tmpdir(), "oxscada-opcua-auth-"));
      // The shipped default: anonymous access OFF.
      server = makeServer(new InMemoryTagDataSource(), pkiFolder, {
        securityPolicy: "None",
        allowAnonymous: false,
        trustUnknownClientCertificates: true,
      });
      await server.start();
    }, 180_000);

    afterAll(async () => {
      await server?.stop();
      if (pkiFolder) fs.rmSync(pkiFolder, { recursive: true, force: true });
    }, 60_000);

    async function withClient<T>(
      run: (client: UaClient) => Promise<T>,
    ): Promise<T> {
      const client = api.OPCUAClient.create({
        endpointMustExist: false,
        connectionStrategy: { maxRetry: 0 },
      });
      await client.connect(server.endpoint);
      try {
        return await run(client);
      } finally {
        await client.disconnect();
      }
    }

    test("does not even advertise an anonymous token policy", async () => {
      // The rejection has to come from the missing Anonymous user-token policy,
      // not from an unrelated connection failure — assert on the reason.
      await expect(
        withClient((client) => client.createSession()),
      ).rejects.toThrow(/ANONYMOUS user token policy/i);
    }, 60_000);

    test("accepts a valid username/password from the user store", async () => {
      const closed = await withClient(async (client) => {
        const session = await client.createSession({
          type: api.UserTokenType.UserName,
          userName: OPERATOR.username,
          password: PASSWORD,
        });
        await session.close();
        return true;
      });
      expect(closed).toBe(true);
    }, 60_000);

    test("refuses a bad password", async () => {
      await expect(
        withClient((client) =>
          client.createSession({
            type: api.UserTokenType.UserName,
            userName: OPERATOR.username,
            password: "not-the-password",
          }),
        ),
      ).rejects.toThrow(/BadUserAccessDenied/);
    }, 60_000);

    test("refuses a self-signed X509 identity token", async () => {
      // node-opcua advertises a Certificate user-token policy alongside
      // UserName, and falls back to a process-wide default user-PKI manager
      // built with `automaticallyAcceptUnknownCertificate: true` when the server
      // does not supply one. That would let any client mint a throwaway
      // certificate and obtain a session without ever touching the `users`
      // table — anonymous access under a different token type. The server must
      // supply its own user certificate manager and reject the token.
      const clientPki = fs.mkdtempSync(
        path.join(os.tmpdir(), "oxscada-opcua-userpki-"),
      );
      const clientCerts = new api.OPCUACertificateManager({
        rootFolder: clientPki,
        automaticallyAcceptUnknownCertificate: true,
      });
      await clientCerts.initialize();
      const client = api.OPCUAClient.create({
        endpointMustExist: false,
        connectionStrategy: { maxRetry: 0 },
        clientCertificateManager: clientCerts,
      });
      await client.connect(server.endpoint);
      try {
        await expect(
          client.createSession({
            type: api.UserTokenType.Certificate,
            certificateData: client.getCertificate(),
            privateKey: fs.readFileSync(clientCerts.privateKey, "utf8"),
          }),
        ).rejects.toThrow(/BadIdentityTokenRejected/);
      } finally {
        await client.disconnect();
        await clientCerts.dispose();
        fs.rmSync(clientPki, { recursive: true, force: true });
      }
    }, 60_000);

    test("refuses an unknown user", async () => {
      await expect(
        withClient((client) =>
          client.createSession({
            type: api.UserTokenType.UserName,
            userName: "nobody",
            password: PASSWORD,
          }),
        ),
      ).rejects.toThrow(/BadUserAccessDenied/);
    }, 60_000);
  },
);

// ─── The shipped production profile, on the wire ─────────────────────────────

/** First non-internal IPv4 address on this host, if there is one. */
function routableIPv4(): string | null {
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && !address.internal) return address.address;
    }
  }
  return null;
}

/** Raw TCP reachability probe; resolves to a short outcome string. */
function probeTcp(
  host: string,
  port: number,
  timeoutMs = 4_000,
): Promise<string> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const finish = (outcome: string): void => {
      socket.destroy();
      resolve(outcome);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish("connected"));
    socket.once("timeout", () => finish("timeout"));
    socket.once("error", (err: NodeJS.ErrnoException) =>
      finish(`error:${err.code ?? err.message}`),
    );
    socket.connect(port, host);
  });
}

/**
 * Everything above drives the server with `securityPolicy: "None"`, which is
 * loopback/dev-only. The *shipped* profile — Basic256Sha256 Sign&Encrypt with a
 * managed PKI trust list and no anonymous access — had no wire coverage at all,
 * so the endpoint operators actually deploy was the one nothing exercised.
 *
 * This suite starts the server with the shipped defaults (no securityPolicy,
 * allowAnonymous or trustUnknownClientCertificates override) under
 * `env: "production"`, and connects a real client whose certificate was placed
 * in `<pkiFolder>/trusted/certs` *before* start — i.e. through the real trust
 * list, not the loopback auto-accept shortcut.
 */
describe.skipIf(!nodeOpcuaAvailable)(
  "OPC-UA server — shipped Basic256Sha256 profile over the PKI trust list",
  () => {
    let pkiFolder: string;
    let clientPki: string;
    let clientCerts: UaCertificateManagerLike;
    let clientCertFile: string;
    let server: OxScadaOpcuaServer;
    let dataSource: InMemoryTagDataSource;
    let api: UaClientApi;

    beforeAll(async () => {
      api = await loadClientApi();
      pkiFolder = fs.mkdtempSync(path.join(os.tmpdir(), "oxscada-opcua-tls-"));
      clientPki = fs.mkdtempSync(path.join(os.tmpdir(), "oxscada-opcua-tlsc-"));

      // Provision the client certificate and trust it BEFORE the server starts:
      // node-opcua reads the trust list at initialize() time.
      // Auto-accept here is the *client's* trust decision about the server's
      // self-signed certificate; it says nothing about the server posture under
      // test, which keeps `trustUnknownClientCertificates: false`.
      clientCerts = new api.OPCUACertificateManager({
        rootFolder: clientPki,
        automaticallyAcceptUnknownCertificate: true,
        disableFileWatchers: true,
      });
      await clientCerts.initialize();
      clientCertFile = path.join(clientCerts.ownCertFolder, "client_cert.pem");
      await clientCerts.createSelfSignedCertificate({
        applicationUri: "urn:0xscada:live-test-client",
        dns: ["localhost"],
        subject: "/CN=0xSCADA live test client",
        startDate: new Date(),
        validity: 30,
        outputFile: clientCertFile,
      });
      const trustedCerts = path.join(pkiFolder, "trusted", "certs");
      fs.mkdirSync(trustedCerts, { recursive: true });
      fs.copyFileSync(clientCertFile, path.join(trustedCerts, "client.pem"));

      dataSource = new InMemoryTagDataSource();
      dataSource.push({
        tagId: "PT-101.PV",
        value: 12.5,
        dataType: "number",
        quality: "good",
        timestamp: new Date().toISOString(),
      });

      // No security overrides: this is exactly what an operator gets from
      // `OPCUA_SERVER_ENABLED=true` with nothing else set.
      server = makeServer(dataSource, pkiFolder, { env: "production" });
      await server.start();
    }, 180_000);

    afterAll(async () => {
      await server?.stop();
      await clientCerts?.dispose();
      if (pkiFolder) fs.rmSync(pkiFolder, { recursive: true, force: true });
      if (clientPki) fs.rmSync(clientPki, { recursive: true, force: true });
    }, 60_000);

    function secureClient(): UaClient {
      return api.OPCUAClient.create({
        endpointMustExist: false,
        connectionStrategy: { maxRetry: 0 },
        securityMode: api.MessageSecurityMode.SignAndEncrypt,
        securityPolicy: api.SecurityPolicy.Basic256Sha256,
        clientCertificateManager: clientCerts,
        certificateFile: clientCertFile,
        privateKeyFile: clientCerts.privateKey,
      });
    }

    test("the shipped defaults really are the secure ones", () => {
      expect(server.configuration.securityPolicy).toBe("Basic256Sha256");
      expect(server.configuration.allowAnonymous).toBe(false);
      expect(server.configuration.trustUnknownClientCertificates).toBe(false);
      expect(server.configuration.host).toBe("127.0.0.1");
    });

    test("generates server key material whose SAN URI matches the ApplicationUri", async () => {
      // A UA client validates that the server certificate's subjectAltName URI
      // equals the ApplicationUri in the EndpointDescription; a mismatch is
      // BadCertificateUriInvalid on any conformant stack.
      const { certificateFile, privateKeyFile } =
        resolveCertificatePaths(pkiFolder);
      expect(fs.existsSync(certificateFile)).toBe(true);
      expect(fs.existsSync(privateKeyFile)).toBe(true);

      const { X509Certificate } = await import("node:crypto");
      const certificate = new X509Certificate(fs.readFileSync(certificateFile));
      expect(
        certificate.publicKey.asymmetricKeyDetails?.modulusLength ?? 0,
      ).toBeGreaterThanOrEqual(2048);
      expect(certificate.subjectAltName ?? "").toContain(
        `URI:${server.configuration.applicationUri}`,
      );
    }, 30_000);

    test("advertises only Basic256Sha256/SignAndEncrypt and no anonymous token", async () => {
      const client = secureClient();
      await client.connect(server.endpoint);
      try {
        const endpoints = await client.getEndpoints();
        expect(endpoints.length).toBeGreaterThan(0);
        for (const endpoint of endpoints) {
          expect(endpoint.securityPolicyUri).toBe(
            api.SecurityPolicy.Basic256Sha256,
          );
          expect(endpoint.securityMode).toBe(
            api.MessageSecurityMode.SignAndEncrypt,
          );
        }
        const tokenTypes = endpoints.flatMap((endpoint) =>
          (endpoint.userIdentityTokens ?? []).map((token) => token.tokenType),
        );
        expect(tokenTypes).not.toContain(api.UserTokenType.Anonymous);
        expect(tokenTypes).toContain(api.UserTokenType.UserName);
      } finally {
        await client.disconnect();
      }
    }, 60_000);

    test("a trusted client reads a tag over Sign&Encrypt with a UserName token", async () => {
      const client = secureClient();
      await client.connect(server.endpoint);
      try {
        const session = await client.createSession({
          type: api.UserTokenType.UserName,
          userName: OPERATOR.username,
          password: PASSWORD,
        });
        const namespaceIndex = server.addressSpacePlan!.namespaceIndex;
        const read = await session.readVariableValue(
          `ns=${namespaceIndex};${TAG_NODE_ID_SUFFIX}`,
        );
        expect(read.statusCode.name).toBe("Good");
        expect(read.value.value).toBeCloseTo(12.5, 6);
        await session.close();
      } finally {
        await client.disconnect();
      }
    }, 60_000);

    test("refuses an anonymous session on the secure endpoint", async () => {
      const client = secureClient();
      await client.connect(server.endpoint);
      try {
        await expect(client.createSession()).rejects.toThrow(
          /ANONYMOUS user token policy/i,
        );
      } finally {
        await client.disconnect();
      }
    }, 60_000);

    test("refuses a client certificate that is not in the trust list", async () => {
      const strangerPki = fs.mkdtempSync(
        path.join(os.tmpdir(), "oxscada-opcua-stranger-"),
      );
      const strangerCerts = new api.OPCUACertificateManager({
        rootFolder: strangerPki,
        automaticallyAcceptUnknownCertificate: true,
        disableFileWatchers: true,
      });
      await strangerCerts.initialize();
      const client = api.OPCUAClient.create({
        endpointMustExist: false,
        connectionStrategy: { maxRetry: 0 },
        securityMode: api.MessageSecurityMode.SignAndEncrypt,
        securityPolicy: api.SecurityPolicy.Basic256Sha256,
        clientCertificateManager: strangerCerts,
      });
      try {
        await expect(client.connect(server.endpoint)).rejects.toThrow();
      } finally {
        await client.disconnect().catch(() => undefined);
        await strangerCerts.dispose();
        fs.rmSync(strangerPki, { recursive: true, force: true });
      }
    }, 60_000);

    test("the loopback bind is not reachable from a routable interface", async () => {
      const port = server.boundPort!;
      expect(await probeTcp("127.0.0.1", port)).toBe("connected");

      const routable = routableIPv4();
      if (routable === null) {
        // Truthful skip: with no non-internal IPv4 address there is nothing to
        // prove the negative against. Never assert a pass we did not observe.
        console.warn(
          "[#461] no non-internal IPv4 interface on this host; " +
            "skipping the routable-interface reachability probe",
        );
        return;
      }
      expect(await probeTcp(routable, port)).not.toBe("connected");
    }, 30_000);
  },
);
