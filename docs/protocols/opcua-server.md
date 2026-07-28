# OPC-UA Server Mode

> Status: **implemented and wired** (#461). The server is started from
> `server/index.ts` when `OPCUA_SERVER_ENABLED=true`, and the `node-opcua`
> binding layer is exercised by a live test that starts a real server on an
> ephemeral loopback port and drives a real client session through it
> (`server/protocols/opcua-server/__tests__/live-binding.test.ts`).
>
> It is **off by default**, binds **loopback only** by default, and refuses
> anonymous access in every environment unless explicitly opted in.

## Overview

0xSCADA already speaks OPC-UA as a **client** (reading from PLCs). *Server mode*
turns that around: it exposes 0xSCADA's own site/tag model as a standard UA
**address space** so external SCADA systems and historians can browse, read and
subscribe to 0xSCADA data.

Source: `server/protocols/opcua-server/`

| File | Responsibility |
|------|----------------|
| `config.ts` | Zod-validated, fail-closed configuration + env loader |
| `security.ts` | Endpoint/security-policy selection + PKI paths (pure) |
| `address-space.ts` | Map sites/tags → UA folders/variables (pure) |
| `user-auth.ts` | UA UserName token → existing `users` table (lookup injected) |
| `storage-data-source.ts` | Latest-value cache + change fan-out (pure) |
| `node-opcua-api.ts` | The single typed `node-opcua` dependency boundary |
| `index.ts` | `OxScadaOpcuaServer` — the node-opcua server lifecycle |
| `runtime.ts` | The opt-in production startup path (storage + tag stream) |

## Enabling it

`OPCUA_SERVER_ENABLED=true` is the **single flag** that turns the subsystem on.
`server/index.ts` calls `startOpcuaServer()` after the HTTP listener is up; with
the flag unset it logs that the subsystem is disabled and returns.

If the subsystem is enabled but cannot be started safely — invalid
configuration, `node-opcua` missing, or the SQLite development fallback in use
(it has no `sites` / `users` / `historian_data` tables) — startup **throws** and
the error is logged. No OPC-UA listener comes up. There is no degraded mode.

```bash
DATABASE_URL=postgres://…  OPCUA_SERVER_ENABLED=true  npm run start
# → opc.tcp://127.0.0.1:4840/0xscada, Basic256Sha256 Sign&Encrypt, no anonymous
```

## Configuration

Every setting is validated by `OpcuaServerConfigSchema`. Unknown keys are
rejected, so a typo'd security flag fails the boot rather than silently
defaulting to something permissive.

| Env var | Config field | Default | Notes |
|---------|--------------|---------|-------|
| `OPCUA_SERVER_ENABLED` | `enabled` | `false` | The single enable flag. |
| `OPCUA_SERVER_HOST` | `host` | `127.0.0.1` | Literal address. Loopback unless `allowRemoteBind`. |
| `OPCUA_SERVER_ALLOW_REMOTE_BIND` | `allowRemoteBind` | `false` | Required for **any** non-loopback bind, wildcard included. |
| `OPCUA_SERVER_PORT` | `port` | `4840` | `0` (ephemeral) is loopback-only. |
| `OPCUA_SERVER_RESOURCE_PATH` | `resourcePath` | `/0xscada` | |
| `OPCUA_SERVER_APPLICATION_URI` | `applicationUri` | `urn:0xscada:server` | |
| `OPCUA_SERVER_NAME` | `serverName` | `0xSCADA OPC-UA Server` | |
| `OPCUA_SERVER_SECURITY_POLICY` | `securityPolicy` | `Basic256Sha256` | `None` is loopback-only and never in staging/production. |
| `OPCUA_SERVER_ALLOW_ANONYMOUS` | `allowAnonymous` | `false` | Off in **every** environment, development included. |
| `OPCUA_SERVER_TRUST_UNKNOWN_CLIENT_CERTS` | `trustUnknownClientCertificates` | `false` | Loopback-only. |
| `OPCUA_SERVER_PKI_FOLDER` | `pkiFolder` | `./pki/opcua-server` | |
| `OPCUA_SERVER_MIN_SAMPLING_MS` | `minSamplingIntervalMs` | `100` | |
| `OPCUA_SERVER_MAX_SESSIONS` | `maxSessions` | `100` | Per endpoint. |
| `NODE_ENV` | `env` | `production` | Unrecognised values fall back to the hardened default. |

Boolean variables are parsed strictly: `true/1/yes/on` and `false/0/no/off`
only. Anything else (`OPCUA_SERVER_ALLOW_ANONYMOUS=maybe`) is an error — an
ambiguous value must never be read as truthy, nor silently as `false`.

### Safety rules (enforced, not merely documented)

These are refused at configuration time *and* again when the security profile is
built, so a caller that hand-builds a config object still cannot get a
permissive server:

1. Any non-loopback `host` — including the `0.0.0.0` / `::` wildcards — requires
   `allowRemoteBind=true`. Exposing the server is a deliberate act.
2. `securityPolicy=None` is permitted only on a loopback bind, and never when
   `env` is `staging` or `production`.
3. `allowAnonymous=true` is refused outright when the policy is `None` on a
   non-loopback bind, and refused in `staging`/`production`.
4. `trustUnknownClientCertificates=true` is permitted only on a loopback bind.
5. An ephemeral port (`0`) is permitted only on a loopback bind.

Note that a *hostname* is never treated as loopback — only literal addresses
(`127.0.0.0/8`, `::1`). Name resolution is not under this process's control, so
a `hosts`/DNS entry must not be able to turn a "loopback-only" deployment into a
routable one. Use `127.0.0.1`.

## Security

| `securityPolicy` | Advertised endpoints | UserName | Anonymous |
|------------------|----------------------|----------|-----------|
| `Basic256Sha256` (default) | `Basic256Sha256` / `SignAndEncrypt` | ✅ | only if `allowAnonymous` |
| `None` (loopback only) | `None`/`None` **and** `Basic256Sha256`/`SignAndEncrypt` | ✅ | only if `allowAnonymous` |

The secure endpoint is always kept, even when `None` is selected. That is
deliberate: node-opcua only advertises an RSA-protected UserName token policy
when a secure policy is present in the endpoint's policy list, so dropping it
would leave anonymous as the only usable identity on the unencrypted endpoint.

Server key material lives under `pkiFolder`
(`own/certs/certificate.pem`, `own/private/private_key.pem`). node-opcua's
`OPCUACertificateManager` provisions self-signed material on first start when
those files are absent. **For production, install CA-issued material at those
paths and populate the `trusted/` list** rather than relying on the self-signed
certificate.

## Authentication

- **UserName / Password** — validated against the existing `users` table.
  `runtime.ts` supplies a Drizzle-backed `UserLookup`; `user-auth.ts` checks the
  record is active and compares the password hash in constant time. There is no
  parallel credential store.
  Supported stored formats: `scrypt$<saltHex>$<hashHex>` and
  `sha256$<saltHex>$<hashHex>`. Any other format (bcrypt, argon2, …) is
  **refused** — never a false accept. See `INTEGRATION(user-store)` in
  `user-auth.ts`: when a shared password verifier lands in the repo, that one
  function is the only thing to replace.
- **Anonymous** — off by default everywhere; explicit opt-in only, and refused
  entirely in staging/production.
- **X509 user identity token** — advertised by node-opcua but **always
  refused** (`BadIdentityTokenRejected`). node-opcua defaults the *user* trust
  store to a process-wide manager built with
  `automaticallyAcceptUnknownCertificate: true`, which would let any client mint
  a throwaway certificate and obtain a session without ever consulting the
  `users` table — anonymous access under a different token type. The server
  therefore supplies its own user certificate manager rooted at
  `<pkiFolder>/userPKI` with auto-accept hardcoded **off**, deliberately not
  tied to `trustUnknownClientCertificates` (that flag is a channel-level
  convenience; accepting an unknown certificate as an *identity* is an
  authentication decision). There is no UA user-certificate enrolment path in
  0xSCADA, so UserName is the supported identity. Pinned by
  `live-binding.test.ts` → "refuses a self-signed X509 identity token".

## Address space

```
Objects/                       (UA NS0, i=85)
└── Sites/                      ns=<i>;s=Sites
    ├── Refinery/               ns=<i>;s=Sites/SITE-01      (one folder per site)
    │   ├── PT-101.PV           ns=<i>;s=Tags/SITE-01/PT-101.PV  (one variable per tag)
    │   └── RUN                 ns=<i>;s=Tags/SITE-01/RUN
    └── SITE-02/
        └── BATCH-ID            ns=<i>;s=Tags/SITE-02/BATCH-ID
```

- **One folder per site**, one **variable per tag**.
- NodeIds are **string** identifiers in the application namespace, built
  deterministically from `siteId` / `tagId` (slashes/percents are escaped).
  `<i>` is the index the address space actually assigns to the application
  namespace, which is why the NodeIds are built after `registerNamespace()`
  rather than against a hardcoded number. **Always read it from
  `server.addressSpacePlan.namespaceIndex`** (UA clients should resolve it by
  URI — `get_namespace_index("urn:0xscada:server")`). Measured value on the
  installed node-opcua 2.175.2 (the dependency is declared `^2.130.0`): `1`.
- Data-type mapping: `boolean → Boolean`, `number → Double`, `string → String`,
  `object`/`array` → JSON-encoded String (`TODO(#461)`: synthesise proper UA
  structured/array types).
- Variables are exposed **read-only**. 0xSCADA has no audited UA write path yet,
  so the server must not advertise one; `accessLevel`/`userAccessLevel` are set
  explicitly rather than inherited from node-opcua's defaults.

### Where the data comes from

- **Sites** — `SELECT id, name FROM sites`.
- **Tag catalogue** — there is no dedicated tag table; the tag id space is what
  the historian has recorded, so `runtime.ts` groups `historian_data` by
  `(tag_id, site_id)` and derives the UA type from whether a `string_value` was
  ever stored.
- **Live values** — `tagStreamServer.onTagUpdate(...)`, the same stream the
  gateway scan loop and the field simulator already publish to. Each update is
  pushed into `StorageTagDataSource`, which sets the value on the matching UA
  variable; node-opcua turns that into a `DataChangeNotification` for every
  subscribed client.

## Tests

Unit tests (`npx vitest run server/protocols/opcua-server`):

- `config.test.ts` — fail-closed defaults, bind/security rules, strict env parsing.
- `security.test.ts` — profile selection and every refusal, independent of the schema.
- `address-space.test.ts` — mapping, NodeId scheme, ordering, dedup, orphans.
- `user-auth.test.ts` — password verification, auth flow, node-opcua's
  *callback-style* `isValidUserAsync` contract.
- `storage-data-source.test.ts` — type inference, caching, subscribe fan-out.
- `runtime.test.ts` — the startup gate: off unless enabled, throws instead of
  relaxing on invalid config, refuses the SQLite fallback.
- `live-binding.test.ts` — **the real thing**: starts the server on
  `127.0.0.1:0`, connects a genuine node-opcua client, browses the site folder,
  reads a tag through the UA read service, subscribes and receives a
  `DataChangeNotification` for a pushed update, then shuts down. A second suite
  starts a server with the shipped `allowAnonymous: false` and asserts that an
  anonymous session is refused (no Anonymous token policy is advertised), a
  valid username/password from the user store is accepted, and a bad password or
  unknown user gets `BadUserAccessDenied`.

  A third suite in the same file covers the **shipped** profile, which the two
  above do not: it starts the server with no security overrides at all
  (`Basic256Sha256` / Sign&Encrypt, `allowAnonymous: false`,
  `trustUnknownClientCertificates: false`) under `env: "production"`, places the
  client certificate in `<pkiFolder>/trusted/certs` *before* start so the
  handshake goes through the real trust list, and asserts: the generated server
  certificate is RSA ≥2048 with a subjectAltName URI equal to the
  ApplicationUri; only a `Basic256Sha256`/`SignAndEncrypt` endpoint is
  advertised and it carries no Anonymous token; a trusted client reads a tag
  over Sign&Encrypt with a UserName token; an anonymous session is refused; an
  untrusted client certificate is refused; and the loopback bind is **not**
  reachable over this host's routable IPv4 address (skipped with a printed
  reason if the host has none).

  If `node-opcua` cannot be loaded the live suite **skips with a printed
  reason** rather than asserting against a stand-in.

## Conformance smoke test with opcua-asyncio

The vitest suite above drives node-opcua on *both* ends, which cannot
demonstrate interoperability with an independent stack. The third-party check is
a real, runnable client script:

    server/protocols/opcua-server/__tests__/opcua_asyncio_smoke.py

It is deliberately **not** wired into `npx vitest run`: CI has no Python
toolchain, so it would either skip silently or break the build on machines
without `asyncua`. Run it explicitly:

```bash
pip install asyncua
DATABASE_URL=…  OPCUA_SERVER_ENABLED=true npm run start
# then, against the endpoint the server logged:
python server/protocols/opcua-server/__tests__/opcua_asyncio_smoke.py \
  --endpoint opc.tcp://127.0.0.1:4840/0xscada \
  --user ua-operator --password '…' \
  --security 'Basic256Sha256,SignAndEncrypt,client_cert.pem,client_key.pem'
```

The client certificate must be in `<pkiFolder>/trusted/certs/` — the server does
not auto-accept unknown client certificates. Drop `--security` only against a
loopback `OPCUA_SERVER_SECURITY_POLICY=None` deployment. A second mode,
`--expect-anonymous-refused`, asserts the shipped no-anonymous posture and
deliberately scores a transport-level failure as *inconclusive* rather than as a
pass.

It checks: UserName session; namespace resolved **by URI**; `Objects/Sites` with
one folder per site and one variable per tag; every variable reads with a good
StatusCode and a source timestamp; a subscription delivers a
DataChangeNotification within `--max-latency-ms` (default 200 ms, the issue's
bound); and writes are refused.

### Recorded run

Executed 2026-07-28 via `asyncua-harness.ts` on `127.0.0.1:0`, asyncua 2.0.1 /
CPython 3.13.14, Windows 11, with the fixture publishing a new value every
150 ms. **Caveat:** the address space came from an in-memory `TagDataSource`
fixture, not a live `sites` / `historian_data` database — this exercises the UA
surface, not the Drizzle queries in `runtime.ts`.

Functional results, both on `None`/`None` and on
`Basic256Sha256`/`SignAndEncrypt` (client certificate trusted through the PKI
trust list), were identical and passed every time:

- UserName session established; namespace resolved by URI to index `1`;
  `Objects/Sites` → one `Refinery` folder → two variables;
- both variables read `Good` with a source timestamp;
- 16–38 `DataChangeNotification`s per run;
- writes refused with `BadNotWritable`;
- anonymous refused with `BadIdentityTokenInvalid`.

**The 200 ms latency bound in the issue is met at the median but not at the
tail.** Worst-case source-timestamp → client-arrival latency across 10 runs:

| Requested publishing interval | Runs | Worst-case latencies (ms) |
|---|---|---|
| 50 ms | 8 | 125.5, 145.1, 173.4, 188.6, 191.5, 232.9, 237.7, 398.1 |
| 20 ms | 2 | 174.7, 214.8 |

4 of 10 runs exceeded 200 ms. Dropping the publishing interval from 50 ms to
20 ms did not remove the tail, so it is not simply publish-cycle quantisation;
the residual jitter is in the sampling/publish path (each UA variable carries an
async `refreshFunc`, so monitored items are polled rather than driven purely by
`setValueFromSource`) plus host scheduling. Treat 200 ms as a typical figure on
a developer workstation, not a guarantee — see "Known gaps".

## Known gaps

- **No latency guarantee.** The 200 ms update bound from #461 is met at the
  median but not at the tail: 4 of 10 measured opcua-asyncio runs exceeded it
  (worst 398 ms), and lowering the publishing interval did not remove the tail.
  Nothing in the server bounds, measures or reports notification latency, so
  there is currently no way to detect a regression here. Characterising and
  bounding it is unfinished work.
- **Reads are served from the live cache only, with no historian backfill.**
  `StorageTagDataSource.readTag()` answers from an in-memory latest-value map
  that is populated *exclusively* by `tagStreamServer.onTagUpdate(...)`. Between
  server start and the first update for a given tag, a UA read of that variable
  returns `StatusCodes.Bad` with a zero/empty value — even though the tag exists
  in the address space precisely because `historian_data` has rows for it. A
  restart therefore blanks every variable until its next scan. Seeding the cache
  with the newest `historian_data` row per tag at startup would close this.
- **No certificate-generation helper of our own.** `resolveCertificatePaths()`
  only *locates* the files; the material itself is provisioned by node-opcua's
  `OPCUACertificateManager` on first start. Verified as RSA-2048, ~10-year
  validity, subjectAltName URI equal to the ApplicationUri (so UA clients accept
  it) — but the subject DN carries node-opcua's vendor default
  (`C=FR L=Orleans O=Sterfive CN=<serverName>@<host>`), and there is no CSR path
  for getting CA-issued material.
- **No UA writes.** All variables are read-only. Wiring writes means routing
  them through the same authorisation the other actuating routes use
  (`requireControlPlaneAccess`) plus an audit trail — `TODO(#461)`.
- **Structured types.** `object` / `array` tags are exposed as JSON strings
  rather than UA ExtensionObjects / arrays.
- **Self-signed certificates.** Fine for a loopback bind; production deployments
  should install CA-issued material and manage the trust list.
