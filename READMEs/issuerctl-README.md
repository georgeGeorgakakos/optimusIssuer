# issuerctl

`issuerctl` is the offline half of **optimusIssuer**. It does the work that must
never touch a network: the key ceremony, the genesis trust list, emergency
signing when the service is down, and verification you can run anywhere.

It reads files and writes files. Nothing more. There is no daemon, no database,
no port to open, and no agent to reach. That is the point — the key that
authorises every credential in the deployment should live on a machine that
never joins the network, and this is the tool that runs there.

> [!NOTE]
> The service half, [`issuerd`](../issuerd), is what operators use day to day:
> a web portal, an approval queue, an audit log, and a connection to an
> OptimusDB agent. `issuerctl` is deliberately the opposite of that.

---

## Contents

- [Before you start](#before-you-start)
- [Part 1 — Create the two issuer keys](#part-1--create-the-two-issuer-keys)
- [Part 2 — Produce the genesis trust list](#part-2--produce-the-genesis-trust-list)
- [Part 3 — Issue a credential and verify it](#part-3--issue-a-credential-and-verify-it)
- [Part 4 — Break it on purpose](#part-4--break-it-on-purpose)
- [What this proves, and what it does not](#what-this-proves-and-what-it-does-not)
- [Command reference](#command-reference)
- [Troubleshooting](#troubleshooting)
- [Where this fits](#where-this-fits)

---

## Before you start

You need Go 1.27 (or Docker) and a terminal. You do **not** need a running
OptimusDB agent, Kubernetes, Keycloak, or an internet connection — the whole
walkthrough below runs on a laptop in a disconnected room, which is exactly how
a real key ceremony is run.

Build the binary once:

```bash
go build -o issuerctl ./cmd/issuerctl
```

<details>
<summary>Prefer not to install Go? Use the container image.</summary>

The published image carries `issuerctl` alongside `issuerd`:

```bash
docker run --rm -v "$PWD/ceremony:/work" -w /work \
  ghcr.io/georgegeorgakakos/optimusissuer:latest \
  issuerctl keygen --out root.key --label "Root — ICCS"
```

Files land in `./ceremony` on the host. Everything below works the same way;
just prefix each command with that `docker run` line.
</details>

Work in a scratch directory — you will delete it at the end:

```bash
mkdir -p ~/issuer-lab && cd ~/issuer-lab
```

---

## Part 1 — Create the two issuer keys

The design uses **two tiers**. A *root* key that exists to authorise other
issuers and is then locked away, and a *service* key that signs the credentials
applications actually use. Compromising the service key is recoverable; it can
be revoked and replaced by the root. Compromising the root is not.

Create the root key:

```bash
./issuerctl keygen --out root.key --label "Root issuer — ICCS"
```

```
DID:  did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
key:  root.key (mode 0600)

Publish the DID. Never copy the key file off this machine.
```

Create the service key:

```bash
./issuerctl keygen --out service.key --label "Service issuer — optimusIssuer prod"
```

Look at what a key file actually is:

```bash
cat root.key
```

```json
{
  "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "keyType": "Ed25519",
  "created": "2026-09-25T09:14:02Z",
  "label": "Root issuer — ICCS",
  "privateKeyMultibase": "z… 44 base58 characters, redacted …"
}
```

Three of those five fields are public. The DID *is* the public key, encoded —
which is why no certificate authority, no registry, and no lookup service is
involved anywhere in this system. Anyone holding the DID can verify a signature
made by this key, and nobody can forge one.

`privateKeyMultibase` is the secret, and it is the only one. The file is written
`0600` and `keygen` refuses to overwrite an existing path, so a second ceremony
cannot silently destroy the first key.

Confirm you can read a key's identity without printing the secret:

```bash
./issuerctl inspect --key service.key
```

```
DID:      did:key:z6MktcocpWfAFxv1utTDQzy8pHpzWnGL5u3vANasYxTTVfyE
type:     Ed25519
created:  2026-09-25T09:14:18Z
label:    Service issuer — optimusIssuer prod
```

> [!IMPORTANT]
> In a real ceremony the root key is generated on an air-gapped machine, backed
> up to two encrypted offline media held by different people, and never copied
> anywhere else. The `.key` files are gitignored and CI fails the build if one
> is ever committed — a key that reaches a public repository is compromised
> permanently and must be rotated, not merely deleted.

---

## Part 2 — Produce the genesis trust list

An agent verifies two things about every credential: that the signature is
valid, and that the signer is an issuer it trusts. The second question is
answered by the trust list. The list itself lives in the replicated `kbtrust`
store, but the agents have to start from *somewhere* — and that bootstrap list
is produced here, offline, with `genesis`.

```bash
./issuerctl genesis \
  --key root.key    --name "Root issuer — ICCS" \
  --key service.key --name "Service issuer — prod" \
  --out issuers.json
```

```bash
cat issuers.json
```

```json
[
  {
    "_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "record_type": "trusted_issuer",
    "name": "Root issuer — ICCS",
    "may_issue": [
      "OptimusDBCapability"
    ],
    "max_delegation_depth": 2,
    "status": "active",
    "added_at": "2026-09-25T09:16:40Z",
    "added_by": "genesis"
  },
  {
    "_id": "did:key:z6MktcocpWfAFxv1utTDQzy8pHpzWnGL5u3vANasYxTTVfyE",
    "record_type": "trusted_issuer",
    "name": "Service issuer — prod",
    "may_issue": [
      "OptimusDBCapability"
    ],
    "max_delegation_depth": 2,
    "status": "active",
    "added_at": "2026-09-25T09:16:40Z",
    "added_by": "genesis"
  }
]
```

Note what is *not* in that file: no secrets. It is entirely public data — a list
of who is allowed to vouch for whom. It ships to every agent as a ConfigMap
(`deploy/06-genesis-configmap.yaml`), and it can be read by anyone without
weakening anything.

`status` is the field that makes revocation work without certificate revocation
lists: flip an issuer to `revoked` in `kbtrust` and every credential it ever
signed stops being accepted as that record replicates.

---

## Part 3 — Issue a credential and verify it

Now play the part of an application asking for access. An application's DID is
generated the same way — it is just another key pair — so make one:

```bash
./issuerctl keygen --out app.key --label "Weather ingest app"
APP_DID=$(./issuerctl inspect --key app.key | awk '/^DID:/{print $2}')
echo "$APP_DID"
```

Sign a credential for it with the **service** key:

```bash
./issuerctl issue \
  --key service.key \
  --subject "$APP_DID" \
  --name "Weather ingest" \
  --org  "ICCS" \
  --capability "read:swarmkb" \
  --capability "write:kbsensors" \
  --days 30 \
  --out app.vc.json
```

```
issued  urn:uuid:5f3c1b8e-9a2d-4f61-b0c7-2e8d1a4f6b09
subject did:key:z6MkrJVnaZkeFzdQyMZu1cjSopiRcyM4jRmPPRWc4gYW5NEd
expires 2026-10-25T09:18:07Z
written app.vc.json
```

`issue` verifies its own output before writing it, with the same code path an
agent runs. If that self-check ever fails it refuses to write the file at all,
so a malformed credential never reaches a subject.

Open the credential:

```bash
cat app.vc.json
```

The two parts worth reading are the capabilities and the proof:

```json
  "credentialSubject": {
    "id": "did:key:z6MkrJVnaZkeFzdQyMZu1cjSopiRcyM4jRmPPRWc4gYW5NEd",
    "name": "Weather ingest",
    "organisation": "ICCS",
    "capabilities": [
      {
        "action": "read",
        "store": "swarmkb"
      },
      {
        "action": "write",
        "store": "kbsensors"
      }
    ]
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-09-25T09:18:07Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:z6Mktcoc...#z6Mktcoc...",
    "proofValue": "z5ZtJwp3Tz3RMPfbRzUKRJRMXzdjaeueQDMJoH6ce6HCUAv..."
  }
```

The `verificationMethod` repeats the issuer DID after a `#`. That is not
redundancy: it is what lets a verifier confirm the key that signed is a key the
named issuer controls, which is checked before the signature itself is.

The grant travels *inside* the credential. There is no permissions table on the
agent side to keep in sync, no role to look up, and nothing to query at request
time — the agent reads the capabilities out of the document it was handed and
checks that the signature over them holds.

Verify it:

```bash
./issuerctl verify --credential app.vc.json
```

```
signature   valid
issuer      did:key:z6MktcocpWfAFxv1utTDQzy8pHpzWnGL5u3vANasYxTTVfyE
subject     did:key:z6MkrJVnaZkeFzdQyMZu1cjSopiRcyM4jRmPPRWc4gYW5NEd
expires     2026-10-25T09:18:07Z
capability  read on swarmkb
capability  write on kbsensors

Note: this checks the signature only. An agent additionally requires
the issuer to appear in its trust list with status active.
```

> [!IMPORTANT]
> `verify` answers *"was this signed by the key it claims, and has it expired?"*
> It deliberately does **not** consult the trust list, because there is no trust
> list on an offline machine. A valid signature from an unknown issuer is still
> worthless to an agent. Both checks are required, and the second one lives on
> the agent.

---

## Part 4 — Break it on purpose

A verifier that always says yes is worse than no verifier. Four tampering tests,
each one thing a real attacker would try.

<details>
<summary><strong>1. Widen a capability</strong> — change what the credential grants</summary>

```bash
cp app.vc.json tampered.json
sed -i 's/"store": "kbsensors"/"store": "*"/' tampered.json
./issuerctl verify --credential tampered.json
```

```
error: verify: signature does not verify
```

The signature covers the canonicalised document, capabilities included. Editing
a single character anywhere in the subject invalidates it, and there is no way
to repair it without the service key.
</details>

<details>
<summary><strong>2. Alter the signature</strong> — try to forge a proof</summary>

```bash
cp app.vc.json forged.json
python3 - <<'PY'
import json
d = json.load(open('forged.json'))
p = d['proof']['proofValue']
d['proof']['proofValue'] = p[:-4] + ('AAAA' if p[-4:] != 'AAAA' else 'BBBB')
json.dump(d, open('forged.json','w'), indent=2)
PY
./issuerctl verify --credential forged.json
```

```
error: verify: signature does not verify
```

An Ed25519 signature is 64 bytes over the canonical digest. There is no partial
credit: a single altered byte fails, and searching for one that does not is the
same as breaking the curve.
</details>

<details>
<summary><strong>3. Rename the issuer</strong> — claim it came from the root</summary>

```bash
ROOT_DID=$(./issuerctl inspect --key root.key | awk '/^DID:/{print $2}')
SVC_DID=$(./issuerctl inspect --key service.key | awk '/^DID:/{print $2}')
sed "s|$SVC_DID|$ROOT_DID|g" app.vc.json > impersonated.json
./issuerctl verify --credential impersonated.json
```

```
error: verify: signature does not verify
```

The DID *is* the public key, so changing the issuer changes the key the
signature is checked against — and the service key's signature does not verify
under the root key. This is the property that makes a trust list of bare DIDs
sufficient, with no certificate chain to validate.
</details>

<details>
<summary><strong>4. Extend the expiry</strong> — buy yourself another year</summary>

The credential you issued lasts thirty days. Give it until 2030:

```bash
python3 - <<'PY'
import json
d = json.load(open('app.vc.json'))
d['expirationDate'] = '2030-01-01T00:00:00Z'
json.dump(d, open('extended.json','w'), indent=2)
PY
./issuerctl verify --credential extended.json
```

```
error: verify: signature does not verify
```

The expiry lives *inside* the signed document, so moving it breaks the
signature before the clock is even consulted. The same applies in the other
direction — you cannot shorten someone else's credential either, which is why
revocation is a separate record in `kbtrust` rather than an edit.

Verify the honest file still passes, so you know the test discriminates:

```bash
./issuerctl verify --credential app.vc.json   # signature valid
```
</details>

---

## What this proves, and what it does not

| Proven on this laptop | How |
|---|---|
| Identities are self-certifying | The DID is the public key; no registry was contacted |
| Grants are unforgeable | Every edit to the credential broke the proof |
| Issuers are distinguishable | A credential cannot be re-attributed to another DID |
| Expiry cannot be extended | The date is covered by the signature |
| Nothing depends on the network | The whole sequence ran disconnected |

| Not proven here | Where it is proven |
|---|---|
| The agent accepts a valid presentation | Agent-side verifier (`optimusdb`) |
| The trust list gates unknown issuers | Agent reading `kbtrust` |
| Revocation propagates | `kbtrust` replication across agents |
| Replay is prevented | Challenge/nonce exchange at the agent |
| Operators are authenticated | Keycloak OIDC in `issuerd` |

Clean up when you are done — these are real keys, even if they were only ever
used for a demo:

```bash
cd ~ && rm -rf ~/issuer-lab
```

---

## Command reference

All six commands are local; none opens a socket.

| Command | What it does | Required flags |
|---|---|---|
| `keygen` | Create an Ed25519 key pair, print its DID | `--out` |
| `inspect` | Show a key's DID, type, creation time and label | `--key` |
| `issue` | Sign a credential offline | `--key` `--subject` `--out` `--capability` |
| `verify` | Check a credential's signature and expiry | `--credential` |
| `genesis` | Emit the bootstrap trusted-issuer list | `--key` (repeatable) |
| `revoke` | Emit a revocation record for `kbtrust` | `--key` `--credential` |

<details>
<summary>All flags, per command</summary>

**keygen** — `--out FILE` (required), `--label TEXT`.
Refuses to overwrite an existing file. Writes mode `0600`.

**inspect** — `--key FILE`. Never prints the private key.

**issue** — `--key FILE`, `--subject DID`, `--out FILE`, `--capability ACTION:STORE`
(repeatable, at least one required), `--name TEXT`, `--org TEXT`,
`--days N` (default 90). Self-verifies before writing.

**verify** — `--credential FILE`. Signature and expiry only; see the callout in
Part 3.

**genesis** — `--key FILE` (repeatable, at least one), `--name TEXT` (repeatable,
positionally matched to the keys; falls back to each key's stored label),
`--out FILE` (stdout if omitted).

**revoke** — `--key FILE`, `--credential ID`, `--subject DID`, `--reason TEXT`,
`--out FILE` (stdout if omitted). The record must then be written into the
`kbtrust` store on any agent; it takes effect as it replicates.
</details>

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `keys: create root.key: open root.key: file exists` | `keygen` never overwrites. Choose another path, or delete the old key deliberately — knowing that anything it signed becomes unverifiable once it is gone. |
| `keys: root.key has mode 0644; it must not be readable by group or others (chmod 600)` | Exactly that: `chmod 600 root.key`. On a Windows bind mount Docker reports `0777` regardless of the host permissions; that is a development-only situation and `OPTIMUS_ALLOW_INSECURE_KEY_PERMS=1` exists for it. Never set it in Kubernetes. |
| `invalid value "read" for flag -capability: expected action:store, got "read"` | `--capability` takes both halves: `--capability read:swarmkb`. Use `"*"` explicitly for a wildcard; an empty half is rejected rather than guessed at. |
| `verify: signature does not verify` on a file you did not edit | The JSON was reformatted or re-serialised by something in between. The proof covers the canonical form (JCS, RFC 8785), so pretty-printers that reorder keys are safe — but ones that alter number or string encoding are not. Re-issue rather than repair. |
| `verify: verificationMethod ... does not belong to issuer ...` | The `issuer` field and the key named in the proof disagree. Either the document was edited, or two different keys were involved in producing it. |
| A credential came out with no `expirationDate` | `--days 0` or a negative value means *no expiry is set*, not an expiry in the past. A credential without an expiry never times out and can only be stopped by revoking it. Always pass a positive `--days`. |
| `--out is required` | `keygen` and `issue` write files rather than printing secrets to a terminal that may be logged. |
| Verify succeeds for an issuer you do not recognise | Working as designed; see the callout in Part 3. The trust list check is the agent's job. |

---

## Where this fits

```
issuerctl  (this tool, offline)        issuerd  (service, online)
├── root key ceremony                  ├── request queue and approvals
├── service key ceremony               ├── signing with the service key
├── genesis trust list ────────────────┤   mounted from a Secret
├── emergency signing                  ├── audit log
└── revocation records ────────────────┤   writes to kbtrust
                                       └── operator portal (Keycloak)
                                                    │
                                        OptimusDB agents verify:
                                        signature + trust list + expiry
```

- Parent project and architecture — [`../../README.md`](../../README.md)
- Genesis list deployment — [`../../deploy/06-genesis-configmap.yaml`](../../deploy/06-genesis-configmap.yaml)
- Key handling rules, rotation and incident response — [`../../SECURITY.md`](../../SECURITY.md)
- The service — [`../issuerd`](../issuerd)

---

*optimusIssuer is part of OptimusDB, developed at ICCS/AUEB within the EU
Horizon Europe project Swarmchestrate (Grant Agreement 101135012).*
