# optimusIssuer

Credential issuance for the OptimusDB swarm.

OptimusDB agents authenticate callers by verifying W3C Verifiable Credentials locally — no authority is contacted at request time. Something, however, has to *sign* those credentials. This is that something: a small Go service with a React interface, holding one Ed25519 key and a set of policies about what it will grant.

It is deliberately the only component in the system that touches issuer private key material, and deliberately the only one that is not required for an agent to verify anything.

---

## Contents

- [What it does](#what-it-does)
- [What it deliberately does not do](#what-it-deliberately-does-not-do)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [The two-tier key model](#the-two-tier-key-model)
- [API](#api)
- [The interface](#the-interface)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Security notes](#security-notes)
- [Development](#development)
- [Related projects](#related-projects)

---

## What it does

| | |
|---|---|
| **Accepts requests** | Any party may submit a credential request. It contains a public DID and a statement of what is wanted. Nothing is granted by submitting one. |
| **Presents them for approval** | An operator signs in with Keycloak, reviews the request, narrows the capabilities if necessary, and approves. |
| **Signs credentials** | Ed25519 over the JCS-canonicalised credential, then immediately verifies its own output with the same code an agent runs. |
| **Records issuance** | Into the `kbissuance` OptimusDB store, which replicates and is covered by the existing export. |
| **Revokes** | Writes a revocation record into `kbtrust`. Takes effect as it replicates — not instantly. |
| **Manages the trust list** | Adding a partner's issuer DID, or deactivating one. The most consequential action available here. |

## What it deliberately does not do

**It does not issue automatically.** Every credential passes through a human. The decision to trust a party is not one a program should make on its own, and an automatic issuer with a network-reachable key is a considerably larger target.

**It is not on the request path.** Agents verify credentials without contacting this service. It can be down, redeployed or unreachable and every existing credential keeps working. Only *new* onboarding is blocked.

**It keeps no database.** Requests, issued-credential records, trusted issuers and revocations all live in OptimusDB stores. The service is stateless and can be rescheduled without losing anything.

---

## Architecture

```
  applicant                operator (browser)
      │                            │
      │ POST /requests             │ Keycloak OIDC
      │ (public DID only)          │
      ▼                            ▼
┌─────────────────────────────────────────────┐
│  optimusIssuer                              │
│    React SPA  ── embedded in the binary     │
│    chi router ── public / operator / admin  │
│    signer     ── the only key holder        │
└───────────────┬─────────────────────────────┘
                │ command API
                ▼
      OptimusDB agent ──► kbtrust, kbissuance, whoiswho
                                  │ replication
                                  ▼
                        every other agent
```

The frontend is built by Vite and embedded into the Go binary with `go:embed`, so the runtime image is a single static executable — no node runtime, no web server, nothing else to keep patched.

---

## Quick start

### Development, without Kubernetes

```bash
make keygen                 # creates ./dev.key, prints its DID
make dev                    # runs with operator auth disabled
```

In a second terminal:

```bash
make dev-ui                 # Vite on :5173, proxying /api to :8090
```

Operator authentication is off in this mode and every caller is treated as a local admin. The service logs a warning saying so. Do not run it this way anywhere that matters.

### Issue a credential from the command line

`issuerctl` never touches a network. It is the tool for the key ceremony and for emergency signing when the service is unavailable.

```bash
# the applicant, on their own machine
go run ./cmd/issuerctl keygen --out app.key --label "Attica Solar Ingest"
# did:key:z6MkfMyApp9kWq2fT7nB4pL8sYdX1aH6uJ0eC5rNmQvT

# you, offline
go run ./cmd/issuerctl issue \
    --key issuer.key \
    --subject did:key:z6MkfMyApp9kWq2... \
    --name "Attica Solar Ingest" \
    --capability crudput:kbmetadata \
    --capability crudget:kbmetadata \
    --days 90 \
    --out myapp.vc.json

# anyone, with no network
go run ./cmd/issuerctl verify --credential myapp.vc.json
```

---

## The two-tier key model

Putting a signing key in a container means a cluster compromise becomes the ability to mint arbitrary credentials. That is exactly what an offline key protects against, so the design uses two keys rather than one.

| | Where it lives | Signs | Used |
|---|---|---|---|
| **Root issuer** | Offline, outside the cluster | Only the trust-list entry authorising the service key | Once, plus emergencies |
| **Service issuer** | Kubernetes Secret, mounted read-only | Day-to-day application credentials | Constantly |

Both DIDs go in the genesis list:

```bash
issuerctl genesis \
  --key root.key    --name "ICCS Root Issuer (offline)" \
  --key service.key --name "optimusIssuer service" \
  --out issuers.json
```

If the service key is compromised, the root key signs one record marking it inactive. Every credential it ever issued stops verifying, across the whole swarm, without redeploying anything.

**Without the root tier**, recovering from a compromise means editing the genesis ConfigMap and restarting all three agents, because no one is left with authority to revoke. A single issuer is not a single point of failure for verification, but it is one for *recovery*.

---

## API

Base path `/api/v1/issuer`. Three tiers.

### Public

| | | |
|---|---|---|
| `GET` | `/health` | Service and agent reachability |
| `GET` | `/info` | Issuer DID and policy limits |
| `POST` | `/requests` | Submit a credential request |

```bash
curl -s -X POST https://.../issuer/api/v1/issuer/requests \
  -H 'Content-Type: application/json' \
  -d '{
    "subject_did": "did:key:z6MkfMyApp9kWq2...",
    "name": "Attica Solar Ingest",
    "organisation": "ICCS",
    "contact": "ops@iccs.example",
    "justification": "Publishes dataset descriptors nightly",
    "requested_capabilities": [
      { "action": "crudput", "store": "kbmetadata" },
      { "action": "crudget", "store": "kbmetadata" }
    ],
    "requested_validity_days": 90
  }'
```

```json
{ "request_id": "req-4f2b9c1e",
  "status": "pending_approval",
  "message": "An operator must approve this request before a credential is signed. Nothing has been granted." }
```

This endpoint is unauthenticated on purpose: the payload carries no secret, and refusing anonymous requests would mean every applicant needed a credential to ask for a credential.

### Operator — requires `issuer:operator`

| | | |
|---|---|---|
| `GET` | `/requests?status=pending` | The approval queue |
| `POST` | `/requests/{id}/approve` | Approve and sign |
| `POST` | `/requests/{id}/reject` | Reject with a reason |
| `POST` | `/credentials` | Issue directly, outside the queue |
| `GET` | `/credentials` | Everything issued |
| `POST` | `/credentials/{id}/revoke` | Revoke |
| `GET` | `/trust` | Read the trust list |
| `GET` | `/audit` | Recent actions |

### Admin — requires `issuer:admin`

| | | |
|---|---|---|
| `POST` | `/trust` | Add or deactivate a trusted issuer |

---

## The interface

Five views, in the order an operator uses them.

**Requests** — the approval queue. Each entry shows the subject DID, what was asked for, who asked and why. Approving opens a capability editor pre-filled with the request, which the operator narrows before signing. The signed credential is offered as a download.

**Issue** — direct issuance for cases that did not come through the queue, such as reissuing after an expiry.

**Credentials** — everything issued, with expiry highlighted inside two weeks and a revoke action.

**Trust list** — the issuers this swarm accepts. Adding one is behind a confirmation that spells out what it means, because it delegates the ability to grant capabilities.

**Audit** — what operators did in this process.

Wildcard capabilities are highlighted wherever they appear, and with `-require-second-approval` a credential containing one cannot be issued by a single operator.

---

## Configuration

| Flag | Default | Purpose |
|---|---|---|
| `-addr` | `:8090` | Listen address |
| `-key` | `/etc/issuer/key/issuer.key` | Issuer key file. Must be mode 0600 |
| `-agent` | `http://optimusdb1:8089` | OptimusDB agent base URL |
| `-agent-context` | `swarmkb` | Agent API context |
| `-oidc-issuer` | *(empty)* | Keycloak realm URL. **Empty disables operator auth** |
| `-oidc-audience` | `optimusissuer` | Expected audience claim |
| `-max-validity-days` | `365` | Longest credential this issuer will sign |
| `-default-validity-days` | `90` | Applied when none is named |
| `-require-second-approval` | `true` | Two operators for any wildcard capability |
| `-allowed-actions` | *(empty)* | Allow-list bounding what may be granted |
| `-cors-origins` | *(empty)* | For a separately hosted frontend |

---

## Deployment

```bash
kubectl apply -f deploy/01-namespace.yaml

# produce the Secret where the key is, apply it, then destroy the local copy
kubectl -n optimusissuer create secret generic issuer-key \
    --from-file=issuer.key=./service.key \
    --dry-run=client -o yaml > secret.yaml
kubectl apply -f secret.yaml && shred -u secret.yaml

kubectl apply -f deploy/03-deployment.yaml
kubectl apply -f deploy/04-ingressroute.yaml
kubectl apply -f deploy/05-networkpolicy.yaml

# into the agents' namespace, not this one
kubectl apply -f deploy/06-genesis-configmap.yaml
```

One replica, deliberately: a second would mean a second copy of the key in memory for no availability gain, since the service is not on the request path.

---

## Security notes

**The key is mounted as a file, never an environment variable.** Environment variables appear in `kubectl describe pod`, in crash dumps and in child process environments.

**The container refuses to start on a loose key file.** Mode 0600 or it exits. An issuer key readable by other accounts is equivalent to a published key, and the failure is otherwise silent.

**Egress is restricted** by NetworkPolicy to the agents and Keycloak. A compromised container cannot post the key to an arbitrary host.

**Root filesystem is read-only**, the container runs as UID 10001, and all capabilities are dropped.

**Every credential is verified immediately after signing**, with the same code an agent runs. A canonicalisation defect fails at issuance rather than in the field, where it would look like a forged signature.

**Wildcards are visible.** They are highlighted in the interface, recorded distinctly in the audit trail, and can require a second operator.

**Revocation is not immediate** and the interface says so where it matters. Short credential lifetimes are the primary control; the revocation list is for emergencies.

---

## Development

```bash
make build      # both binaries
make test       # Go tests, no network required
make vet
make image
```

The tests cover the round trip that matters — sign, serialise, verify — plus tampering, expiry, issuer mismatch, DID encoding and canonicalisation stability. A failure in the canonicalisation tests almost certainly means credentials issued here will not verify in the agents.

### Keeping canonicalisation in step

`internal/did` and `internal/canonical` must produce byte-identical output to the verifier inside the OptimusDB agent. If the two ever diverge, every credential fails to verify and the failure presents as a bad signature, which sends people looking in the wrong place.

The safest arrangement is for the agent to vendor these two packages rather than reimplement them. If they must be separate, the test vectors in `roundtrip_test.go` should be run against both.

---

## Related projects

| | |
|---|---|
| **OptimusDB** | The agent swarm that verifies these credentials |
| **OptimusDDC** | Catalog front end; keeps its Keycloak browser session |
| **optimusPy** | Client library, holds a credential and presents it |

## License

MIT
