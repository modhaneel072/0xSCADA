# Dependency security review — 2026-07-23

This review accompanies issue #496 and records the result of the coordinated
major-version upgrade.

## Resolved

- `drizzle-orm` was upgraded from `0.29.x` to `0.45.2`, which contains the SQL
  identifier escaping fix. `drizzle-zod` was upgraded to `0.8.3` to keep schema
  generation compatible with the new ORM.
- `hardhat` was pinned to `3.11.1`. Its vulnerable transitive `adm-zip` range is
  overridden to `0.6.0`.
- `sparkplug-payload` is retained for Sparkplug B compatibility, with its
  vulnerable `protobufjs` dependency overridden to `8.7.1`.
- The legacy Azure IoT dependency chain is constrained to `uuid` `11.1.1`.
- `esbuild` is constrained to `0.28.1`, covering both Vite and Drizzle Kit's
  loader chain.
- `zod-validation-error` was upgraded to `5.x`; imports explicitly select its
  Zod 3 or Zod 4 adapter so both hand-written and Drizzle-generated schemas
  remain type-safe.

After these changes, both `npm audit` and `npm audit --omit=dev` report zero
known vulnerabilities.
