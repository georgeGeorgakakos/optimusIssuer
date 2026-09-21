# Contributing

## Getting set up

```bash
git clone https://github.com/georgeGeorgakakos/optimusIssuer.git
cd optimusIssuer

go mod download        # creates go.sum on first run
cd web && npm install && cd ..

make keygen            # a development key, gitignored
make test
```

### GoLand

Open the repository root. GoLand will detect `go.mod` and index the module.

Committed run configurations appear in the run menu:

| Configuration | Does |
|---|---|
| `issuerd (dev)` | Runs the service with operator authentication disabled |
| `issuerd (against cluster)` | Runs locally against the deployed agents and Keycloak |
| `issuerctl keygen` | Creates `./dev.key` |
| `All tests` | The whole suite |
| `Canonicalisation tests` | The subset that must pass before any release |

If the module does not resolve, check that **Go Modules** is enabled in
Settings → Go → Go Modules, and that the GOROOT points at Go 1.21 or later.

### WebStorm

Open `web/` as its own project rather than the repository root — the frontend
has its own `package.json` and lockfile, and WebStorm indexes it more usefully
on its own.

Two committed npm configurations: `vite dev` and `vite build`.

During development, run `issuerd` from GoLand on `:8090` and `vite dev` from
WebStorm on `:5173`. Vite proxies `/api` to the Go service, so the interface
behaves as it does in production without rebuilding the binary on every change.

## The rule that matters

`internal/did` and `internal/canonical` must produce **byte-identical output**
to the verifier inside the OptimusDB agent.

If they diverge, every credential this service issues fails to verify, and the
symptom is a signature error — which sends people to look at key handling
rather than at serialisation. That is a slow and unpleasant bug to find.

Before changing either package:

1. Run `Canonicalisation tests` and confirm they pass beforehand.
2. Make the change.
3. Run them again.
4. Verify that a credential issued **before** the change still verifies
   **after** it. `issuerctl verify` does this with no network.
5. Raise the corresponding change in the agent, or explain in the pull request
   why the agent is unaffected.

## Style

Go code is formatted with `gofmt` and passes `go vet`. Comments explain why
something is done, not what the line does; the code already says what.

React components are function components with hooks. No state management
library — the interface has five views and no shared state worth abstracting.

## What not to commit

`.gitignore` covers these, but they are worth naming:

- `*.key`, `dev.key` — key material
- `*.vc.json` — issued credentials
- `secret.yaml` — a rendered Kubernetes Secret
- `issuers.json` — harmless, but belongs with the deployment rather than here

CI fails the build if a private key or a tracked `.key` file appears. A key in
the git history is not fixable by deleting the file in a later commit; the key
must be rotated.

## Releasing

```bash
git tag v1.0.1
git push origin v1.0.1
```

The release workflow builds and pushes the container image to GHCR, and
attaches `issuerctl` binaries for five platforms. Those binaries are attached
because the key ceremony is performed on a machine that is not expected to have
a Go toolchain.
