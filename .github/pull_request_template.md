## What this changes

<!-- One or two sentences. -->

## Why

<!-- The problem, not the patch. -->

## Checklist

- [ ] `go test ./... -count=1` passes
- [ ] `go vet ./...` is clean
- [ ] `make ui` builds, if the frontend changed
- [ ] No key material, credential or `secret.yaml` is included

## If this touches `internal/canonical` or `internal/did`

These packages must produce byte-identical output to the verifier inside the
OptimusDB agent. A divergence makes every credential fail to verify, and the
symptom in the field is a bad signature rather than a serialisation fault.

- [ ] The canonicalisation and round-trip tests pass
- [ ] The corresponding change has been made, or raised, in the agent
- [ ] A credential issued before this change still verifies after it
