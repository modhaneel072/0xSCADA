# Control-Plane API Keys

0xSCADA reads API key records from the `API_KEYS` environment variable. A
record has the following format, and multiple records are comma-separated:

```text
key:name:scope+scope
```

Do not commit real key material to a values file, Compose file, or `.env`
template. Generate each key with a cryptographically secure secret generator
and inject the complete `API_KEYS` value at deployment time.

## Required grants

Every key that accesses an operator-only control-plane route needs the
`operator` grant. A mutation also needs its route-specific scope:

| Scope | Intended operation |
|---|---|
| `anchor.admin` | Switch the event-anchoring backend |
| `alarms.write` | Mutate alarms and alarm-correlation rules |
| `blueprints.write` | Create, update, or delete blueprints |
| `safety.resume` | Resume a blueprint from safe state |
| `predictive.write` | Mutate predictive-maintenance configuration |
| `tuning.write` | Create or update tuning work |
| `tuning.approve` | Approve or reject tuning decisions |
| `twin.write` | Mutate digital-twin models and scenarios |
| `marketplace.write` | Mutate marketplace registrations |
| `marketplace.invoke` | Invoke a marketplace agent |

For example, an interactive operator key that manages blueprints and resumes
safe-state execution needs:

```text
<generated-operator-key>:operations-console:operator+blueprints.write+safety.resume
```

A service principal should receive only its required capability. An alarm
automation service, for example, needs both the operator role and the narrow
write scope:

```text
<generated-service-key>:alarm-automation:operator+alarms.write
```

`admin` and `*` bypass the role and scope checks. Reserve them for exceptional
break-glass workflows rather than routine operator or service keys. Keep
`tuning.write` and `tuning.approve` on different principals when separation of
duties is required.

Clients send a key only in the `X-API-Key` request header:

```bash
curl -H "X-API-Key: ${OPERATOR_KEY}" \
  https://oxscada.example.com/api/blueprints/summary
```

## Docker Compose

The root `docker-compose.yml` takes `API_KEYS` and `ENABLE_API_KEYS` from the
host environment (or a local `.env` file). It contains no default credential.
Control-plane routes use `API_KEYS` even when global gateway authentication is
disabled.

```bash
OPERATOR_KEY="$(openssl rand -hex 32)"
SERVICE_KEY="$(openssl rand -hex 32)"
export API_KEYS="${OPERATOR_KEY}:operations-console:operator+blueprints.write+safety.resume,${SERVICE_KEY}:alarm-automation:operator+alarms.write"

# Optional: require a valid API key on all non-public API routes.
export ENABLE_API_KEYS=true
docker compose up -d
```

Treat `.env` as a local secret file if it is used for persistence, and do not
commit it.

## Helm

Both `helm/oxscada` and `helm/oxscada-full` read `API_KEYS` from an existing
Kubernetes Secret. Create the Secret out of band, then select it with
`server.apiKeys.existingSecret`. The chart does not render the credential into
a Helm-managed Secret or ConfigMap.

```bash
OPERATOR_KEY="$(openssl rand -hex 32)"
SERVICE_KEY="$(openssl rand -hex 32)"
API_KEYS_VALUE="${OPERATOR_KEY}:operations-console:operator+blueprints.write+safety.resume,${SERVICE_KEY}:alarm-automation:operator+alarms.write"

kubectl create namespace oxscada --dry-run=client -o yaml | kubectl apply -f -
kubectl -n oxscada create secret generic oxscada-api-keys \
  --from-literal=API_KEYS="${API_KEYS_VALUE}"

helm upgrade --install oxscada ./helm/oxscada \
  --namespace oxscada --create-namespace \
  --set-string server.apiKeys.existingSecret=oxscada-api-keys
```

Use `./helm/oxscada-full` in the same command for the full-stack chart. Set
`server.apiKeys.secretKey` if the existing Secret uses a key other than
`API_KEYS`. Set `server.apiKeys.enableGlobalAuth=true` only when every
non-public API client is prepared to send a configured key.

Rotate keys by updating the Secret and restarting the server Deployment so the
pod receives the new environment value:

```bash
kubectl -n oxscada rollout restart deployment/oxscada-server
```
