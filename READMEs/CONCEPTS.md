# Key concepts

The conceptual foundations of authentication and authorisation in OptimusDB.
This document states *what the model is and why*. It contains no instructions —
for those, see [`cmd/issuerctl/README.md`](cmd/issuerctl/README.md) to run the
primitives locally, and [`SECURITY.md`](SECURITY.md) for operational procedure.

---

## 1. The problem

OptimusDB agents are operated by **different organisations**. An agent must be
able to decide whether an incoming request is authorised, and it must do so:

- **locally** — no call to a central service, which would reintroduce the single
  coordinator the architecture exists to remove;
- **independently** — three agents reach the same verdict without coordinating,
  holding no shared session state;
- **without gaining the ability to forge** — an agent verifies a request without
  acquiring anything that would let it produce that request itself.

The third requirement is the hard one, and it eliminates most of the standard
answers.

## 2. The governing constraint

> **A secret that a verifier must know is a secret that verifier can use.**

Any scheme in which the verifier validates a request by comparing against a
stored secret — API keys, shared HMAC keys, passwords — places that secret on
every verifier. With *n* independently operated agents, each client secret
exists in *n + 1* places, and any agent can impersonate any client to any other
agent.

Public-key signatures break the symmetry. The verifier holds a public key: it
can check a signature and cannot produce one. This single property is what makes
federated verification possible, and everything below is machinery serving it.

## 3. The three roles

| Role | Holds | Can do | Cannot do |
|---|---|---|---|
| **Issuer** | its private key | grant authority by signing credentials | read or write agent data |
| **Holder** (an application) | its private key, and credentials issued to it | prove its identity, exercise granted capabilities | widen its own grant |
| **Verifier** (an agent) | a list of trusted issuer identifiers — public data only | check any credential offline | forge a request, or mint authority |

No role holds another's secret. No secret crosses an organisational boundary at
any point in the lifecycle, including onboarding.

## 4. Identity is a public key

An identity is a [`did:key`](https://w3c-ccg.github.io/did-method-key/)
identifier. It is not an account, a record, or a name in a registry. It is the
public key itself, encoded as text:

```
did:key:z6Mko2s2i1HLaAE9NTQTiDRkdkrM3GfWebD3h7yRTBBB1nhy
         │└──────────────────────── base58btc ─────────────────────────┘
         └ multibase prefix

decodes to 34 bytes:
  ed01                                                              multicodec: Ed25519 public key
  7f79383208bf936fcc31c9a6e2bf32cfd43cf4320597714381bc4f6073f582fc  the key
```

Consequences:

- **Resolution is decoding, not lookup.** Recovering the public key from a DID
  is a local string operation. No network, no registry, no blockchain, no
  directory service, no availability dependency.
- **Identities are self-issued.** Any party generates its own identity in
  milliseconds. Nobody administers accounts for anybody else — the requirement
  that makes cross-organisational onboarding tractable.
- **An identity cannot be reassigned.** Changing the DID in a document changes
  the key its signature is checked against, so a signed document cannot be
  re-attributed to another identity.

Identity is therefore free, unlimited, and requires no coordination. It also
conveys **no authority whatsoever** — see next.

## 5. Authority travels with the request

Authority is expressed as a **capability credential**: a W3C Verifiable
Credential, signed by an issuer, naming a subject DID and the specific
(action, store) pairs that subject may exercise.

```json
"credentialSubject": {
  "id": "did:key:z6Mki22nVCGFGbjSFYn3ahctWpGzyEi7ZFTrP9d6ffWRUeHh",
  "capabilities": [
    { "action": "read",  "store": "swarmkb" },
    { "action": "write", "store": "kbsensors" }
  ]
}
```

The grant is **inside the document the caller presents**, covered by the
issuer's signature. The verifier does not consult a permission table, because
there is no permission table.

This is the difference between a credential and an API key. An API key is an
opaque identifier that means nothing until dereferenced against state the
verifier holds; the state must therefore be replicated to every verifier and
kept synchronised. A credential is self-describing and self-authenticating: it
carries its own meaning and its own proof.

The operational consequence is that **onboarding a new application requires no
change to any agent**. The ten-thousandth application costs exactly what the
first did.

Capabilities are deliberately not roles. A role is a name that must be
interpreted consistently by every verifier — that is, shared state again, with
the additional failure mode that the same name can mean different things in
different organisations.

## 6. Trust is a short, public list

An agent holds one piece of security configuration: the list of issuers whose
signatures it accepts.

```json
{
  "_id": "did:key:z6Mko2s2i1HLaAE9NTQTiDRkdkrM3GfWebD3h7yRTBBB1nhy",
  "record_type": "trusted_issuer",
  "name": "ICCS issuer",
  "may_issue": ["OptimusDBCapability"],
  "max_delegation_depth": 1,
  "status": "active"
}
```

Properties:

- **It lists issuers, never subjects.** Applications appear nowhere. The list
  is bounded by the number of participating organisations, not the number of
  clients — typically two to five entries.
- **It contains nothing secret.** It is public data and may be published.
- **It is the authorisation half of verification.** Signature validity proves
  *authenticity*: the document was signed by whoever holds that key, unaltered.
  The trust list supplies *authority*: that key is one this deployment accepts.
  Both are required; either alone is meaningless.
- **It is live data.** The list is a replicated `kbtrust` store, so an issuer can
  be added or marked `revoked` at runtime and the change propagates to every
  agent without redeployment.

### Bootstrap

The first entries cannot be authorised from inside the system — an empty system
has no authority to vouch for its own first issuer. The genesis list is
therefore produced offline at a key ceremony, distributed as a ConfigMap, and
read at agent start-up to seed `kbtrust`.

**The root of trust is a human decision recorded outside the system.** This is
not a weakness of the design; it is a property shared by every trust system
(browser root stores, `authorized_keys`, GPG fingerprints), none of which can
escape it. What the design can do is make that decision small, rare, public and
auditable: one short file, produced once.

## 7. Possession is proved, not asserted

A credential establishes what its subject may do. It does not establish that the
caller *is* that subject — a credential file is not secret and may be copied.

On each request the caller constructs a **Verifiable Presentation**: the
credential, wrapped and signed with the holder's private key over a
challenge obtained from the agent immediately beforehand.

```
app ──── GET /auth/challenge ────▶ agent      nonce, single-use, 60s, domain-bound
app ◀─── {"challenge": "a1b2…"} ──
app ──── request + presentation ─▶ agent      signed over that nonce
```

The private key is never transmitted. What travels is a signature that is valid
only for that nonce, that agent, and that minute.

This is the distinction between a **bearer** credential and a **holder-bound**
one. A bearer token — an API key, a JWT — grants access to whoever possesses it,
so a single appearance in a log file, proxy trace or stack dump is a compromise.
A presentation is worthless without the private key that produced it, and
replaying a captured one fails against a nonce that has already been consumed.

## 8. The verification algorithm

Every check is local. No network calls, no shared state, no coordination.

| # | Check | Establishes |
|---|---|---|
| 1 | Presentation signature verifies under the holder DID | the caller controls that identity |
| 2 | Challenge is current, unused, and bound to this agent | the request is not a replay |
| 3 | Credential signature verifies under the issuer DID | the grant is unaltered and genuinely issued |
| 4 | Issuer appears in the trust list with `status: active` | the grant comes from a recognised authority |
| 5 | Within validity window; no revocation record present | the grant is still in force |
| 6 | Capabilities cover the requested (action, store) | this specific operation is permitted |

Any failure yields `401` and no state change. Cost is dominated by two Ed25519
verifications — on the order of a hundred microseconds.

## 9. Design rationale

| | Shared secret (API key) | Central IdP (OIDC/JWT) | Capability credential |
|---|---|---|---|
| Verifier must hold a secret | **yes, on every agent** | no | no |
| A compromised agent can impersonate clients | **yes** | no | no |
| Authority service on the critical path | at onboarding | **at every authentication** | never |
| Disclosure in a log grants access | **yes** | **yes** | no |
| Subject can create its own identity | no | no | **yes** |
| Cost of onboarding client *n* | write to every agent | account in the IdP | **no agent change** |
| Verdict available during partition | yes | **no** | yes |

The central-IdP column is the serious alternative and reaches most of the same
places: offline verification against a published key, no shared secret. What
remains is that its tokens are bearer credentials, that identities are
administered centrally rather than self-generated, and that the issuing service
must be reachable whenever a client authenticates. Each of those is acceptable
inside one organisation and problematic across several.

**The justification rests entirely on the federation premise.** In a
single-organisation deployment with one operations team, API keys or OIDC are
the correct choice and this model is unjustified complexity.

## 10. Non-goals and known limits

Stated plainly, because they are the questions a reviewer will ask.

- **Revocation is eventually consistent.** A revocation record replicates; until
  it arrives, a lagging agent still accepts the credential. This is no better
  than a distributed deny-list. Exposure is bounded primarily by **short validity
  periods**, not by revocation latency.
- **Key custody moves to the client.** Every application now holds a private key
  that can be stolen or lost. This is a real increase in operational burden over
  a string in an environment variable, and it is transferred to application
  developers.
- **Canonicalisation is a correctness dependency.** Signatures are computed over
  a canonical serialisation, which must agree byte-for-byte across independent
  implementations. This project uses **JCS (RFC 8785)** rather than the
  URDNA2015 normalisation named in the W3C suite — a deliberate, documented
  deviation trading strict specification conformance for a canonicalisation that
  is simple enough to reimplement correctly. Credentials produced here are
  therefore not interchangeable with general-purpose W3C VC tooling without
  agreement on this point.
- **The HTTP surface is not the only entry point.** Credential checks govern the
  agent's HTTP API. Replication over libp2p is a separate door, governed by
  OrbitDB access controllers. A complete authorisation story requires both; they
  are independent mechanisms and changing an access controller changes a store's
  address.
- **Delegation depth is bounded but unimplemented.** `max_delegation_depth`
  appears in the trust list and is reserved; chained delegation is not yet
  verified.

## 11. Vocabulary

| Term | Meaning here |
|---|---|
| **DID** | `did:key` identifier; an Ed25519 public key in text form |
| **Issuer** | party whose signature confers authority |
| **Holder** | party a credential was issued to; the subject |
| **Verifier** | an agent evaluating a request |
| **Credential (VC)** | signed document granting capabilities to a subject |
| **Presentation (VP)** | credential wrapped in a fresh holder signature over a challenge |
| **Capability** | an (action, store) pair |
| **Trust list** | issuer DIDs an agent accepts; the `kbtrust` store |
| **Genesis list** | the bootstrap trust list, produced offline |
| **Challenge** | single-use nonce binding a presentation to one agent and moment |

## 12. Where the code lives

| Concept | Package |
|---|---|
| DID encoding, decoding, validation | `internal/did` |
| Canonicalisation (JCS) | `internal/canonical` |
| Credential types, signing, verification | `internal/credential` |
| Key loading and custody checks | `internal/keys` |
| Issuance service and trust-list API | `internal/api` |
| Offline ceremony and verification tool | `cmd/issuerctl` |

`internal/did`, `internal/canonical` and `internal/credential` have no
dependency on the service and are intended to be vendored into verifying agents
unchanged, so that issuer and verifier share one implementation of the rules.

## 13. References

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [The `did:key` Method](https://w3c-ccg.github.io/did-method-key/)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 8032 — Ed25519](https://www.rfc-editor.org/rfc/rfc8032)

---

*OptimusDB is developed at ICCS/AUEB within the EU Horizon Europe project
Swarmchestrate (Grant Agreement 101135012).*
