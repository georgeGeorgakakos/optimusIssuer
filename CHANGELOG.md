# Changelog

All notable changes to optimusIssuer.

## [1.0.0] — 2026-09-17

First release.

### Added
- Go service with an embedded React interface, served from a single static
  binary
- Ed25519 credential signing with JCS (RFC 8785) canonicalisation
- Self-verification immediately after signing, using the same code path an
  OptimusDB agent runs
- `did:key` encoding and resolution, requiring no network
- Three privilege tiers: public request submission, operator issuance, admin
  trust-list management
- Keycloak OIDC for operators, with a cached key set so a brief Keycloak
  outage does not lock out a running instance
- Records written to `kbtrust`, `kbissuance` and `whoiswho`; no database of
  its own
- `issuerctl` for the key ceremony, offline issuance and verification
- Two-tier key model: an offline root issuer authorising a service issuer
- Kubernetes manifests including a NetworkPolicy restricting egress to the
  agents, Keycloak and DNS
- Ten tests covering the sign-serialise-verify round trip, tampering, expiry,
  issuer mismatch, capability matching and canonicalisation stability

### Design notes
- Canonicalisation uses JCS rather than the W3C's URDNA2015. The deviation is
  deliberate and documented; credentials are not interoperable with a strict
  RDF-canonicalising verifier.
- Revocation is not immediate. It takes effect as the record replicates.
- One replica, deliberately: a second would place another copy of the key in
  memory for no availability gain.
