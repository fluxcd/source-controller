# AGENTS.md

Guidance for AI coding assistants working in `fluxcd/source-controller`. Read this file before making changes.

## Contribution workflow for AI agents

These rules come from [`fluxcd/flux2/CONTRIBUTING.md`](https://github.com/fluxcd/flux2/blob/main/CONTRIBUTING.md) and apply to every Flux repository.

- **Do not add `Signed-off-by` or `Co-authored-by` trailers with your agent name.** Only a human can legally certify the DCO.
- **Disclose AI assistance** with an `Assisted-by` trailer naming your agent and model:
  ```sh
  git commit -s -m "Add support for X" --trailer "Assisted-by: <agent-name>/<model-id>"
  ```
  The `-s` flag adds the human's `Signed-off-by` from their git config — do not remove it.
- **Commit message format:** Subject in imperative mood ("Add feature X" instead of "Adding feature X"), capitalized, no trailing period, ≤50 characters. Body wrapped at 72 columns, explaining what and why. No `@mentions` or `#123` issue references in the commit — put those in the PR description.
- **Trim verbiage:** in PR descriptions, commit messages, and code comments. No marketing prose, no restating the diff, no emojis.
- **Rebase, don't merge:** Never merge `main` into the feature branch; rebase onto the latest `main` and push with `--force-with-lease`. Squash before merge when asked.
- **Pre-PR gate:** `make tidy fmt vet && make test` must pass and the working tree must be clean after codegen. Commit regenerated files in the same PR.
- **Flux is GA:** Backward compatibility is mandatory. Breaking changes to CRD fields, status, CLI flags, metrics, or observable behavior will be rejected. Design additive changes and keep older API versions round-tripping.
- **Copyright:** All new `.go` files must begin with the boilerplate from `hack/boilerplate.go.txt` (Apache 2.0). Update the year to the current year when copying.
- **Spec docs:** New features and API changes must be documented in `docs/spec/v1/` — one file per CRD: `gitrepositories.md`, `ocirepositories.md`, `helmrepositories.md`, `helmcharts.md`, `buckets.md`, `externalartifacts.md`. Update the relevant file in the same PR that introduces the change.
- **Tests:** New features, improvements and fixes must have test coverage. Add unit tests in `internal/controller/*_test.go` and other `internal/*` packages as appropriate. Follow the existing patterns for test organization, fixtures, and assertions. Run tests locally before pushing.

## Code quality

Before submitting code, review your changes for the following:

- **No secrets in logs or events.** Never surface auth tokens, passwords, or credential URLs in error messages, conditions, events, or log lines. Use `fluxcd/pkg/masktoken` and the `internal/error` sanitizers.
- **No unchecked I/O.** Close HTTP response bodies, file handles, and archive readers in `defer` statements. Check and propagate errors from `io.Copy`, `os.Remove`, `os.Rename`.
- **No path traversal.** Validate and sanitize file paths extracted from archives or user input. Use `securejoin` to ensure paths stay within the expected root. Never `filepath.Join` with untrusted components without validation.
- **No unbounded reads.** Use `io.LimitReader` when reading from network or archive sources. Respect existing size limits; do not introduce new reads without bounds.
- **No command injection.** Do not shell out via `os/exec`. Use Go libraries for git, helm, OCI, and cloud operations.
- **No hardcoded defaults for security settings.** TLS verification must remain enabled by default; proxy and auth settings come from user-provided secrets, not environment variables.
- **Error handling.** Wrap errors with `%w` for chain inspection. Do not swallow errors silently. Return actionable error messages that help users diagnose the issue without leaking internal state.
- **Resource cleanup.** Ensure temporary files, directories, and cloned repos are cleaned up on all code paths (success and error). Use `defer` and `t.TempDir()` in tests.
- **Concurrency safety.** Do not introduce shared mutable state without synchronization. Reconcilers run concurrently; per-object work must be isolated. Respect the existing `Storage.LockFor` pattern.
- **No panics.** Never use `panic` in runtime code paths. Return errors and let the reconciler handle them gracefully.
- **Minimal surface.** Keep new exported APIs, flags, and environment variables to the minimum needed. Every export is a backward-compatibility commitment.

## Project overview

source-controller is a core component of the [Flux GitOps Toolkit](https://fluxcd.io/flux/components/). It reconciles five custom resources in the `source.toolkit.fluxcd.io` API group — `GitRepository`, `OCIRepository`, `HelmRepository`, `HelmChart`, and `Bucket` — by fetching upstream content, verifying it (PGP, Cosign, Notation), and packaging it into an immutable `Artifact` (tarball or chart). Artifacts are written to a local filesystem rooted at `--storage-path` and served over HTTP from `--storage-addr` so downstream controllers (kustomize-controller, helm-controller, source-watcher) can consume them. Status conditions, events, and the artifact URL/revision are what other Flux controllers key off.

## Repository layout

- `main.go` — manager wiring: flags, scheme registration, `Storage` init, feature gates, setup of the five reconcilers, and the artifact file server.
- `api/` — separate Go module (`github.com/fluxcd/source-controller/api`) holding the CRD types. The root module pulls it via a `replace` directive.
  - `api/v1/` — current storage version. Per-kind `*_types.go`, shared `artifact_types.go`, `condition_types.go`, `source.go`, `sts_types.go`, `ociverification_types.go`, `groupversion_info.go`, and generated `zz_generated.deepcopy.go`.
  - `api/v1beta1/`, `api/v1beta2/` — older versions kept for conversion/compat.
- `config/` — Kustomize overlays. `config/crd/bases/` holds generated CRDs (one YAML per kind); do not hand-edit. `config/default/`, `config/manager/`, `config/rbac/`, `config/samples/`, `config/testdata/` cover install, manager Deployment, RBAC, samples, and fixtures.
- `internal/` — controller implementation (not importable by other modules).
  - `controller/` — the five reconcilers, `Storage` (artifact lock, archive, GC, serving), `artifact.go`, `source_predicate.go`, envtest suite (`suite_test.go`), and per-kind `*_test.go` integration tests.
  - `reconcile/` — shared reconcile loop primitives; `reconcile/summarize/` collapses sub-results into terminal status and patches.
  - `helm/` — Helm logic split into `chart/` (local/remote chart builders, dependency manager, `secureloader`), `repository/` (HTTP and OCI `ChartRepository`), `getter/`, `registry/` (OCI client + auth), `common/`.
  - `oci/` — OCI auth plus `verifier.go`; `cosign/` and `notation/` implement the two `OCIRepository` verification providers.
  - `index/` — digest indexing for chart repositories.
  - `cache/` — in-memory TTL cache for Helm index files with Prometheus metrics.
  - `digest/` — canonical digest algorithm selection (sha256/384/512, blake3) and a hashing writer.
  - `predicates/`, `features/`, `fs/`, `util/`, `tls/`, `transport/`, `object/`, `error/`, `mock/` — small helpers; names match their responsibilities.
- `pkg/` — importable provider clients consumed by `BucketReconciler`: `azure/` (Azure Blob), `gcp/` (GCS), `minio/` (S3). These are semi-public API.
- `hack/` — `boilerplate.go.txt` license header, `api-docs/` templates, `ci/e2e.sh`.
- `tests/` — `listener/`, `proxy/`, `registry/` harnesses used by integration tests.
- `docs/` — `spec/` (user-facing API docs per version), `api/` (generated reference), `internal/release.md`, `diagrams/`.

## APIs and CRDs

- Group: `source.toolkit.fluxcd.io`. Storage version: `v1`. `v1beta1` and `v1beta2` remain for compatibility.
- Kinds: `GitRepository`, `OCIRepository`, `HelmRepository`, `HelmChart`, `Bucket`. Shared `Artifact` type in `api/v1/artifact_types.go`; shared conditions in `api/v1/condition_types.go`; `Source` interface in `api/v1/source.go`.
- CRD manifests under `config/crd/bases/source.toolkit.fluxcd.io_*.yaml` are generated from kubebuilder markers. Never edit them by hand — update the types and run `make manifests`.
- `api/v1*/zz_generated.deepcopy.go` is generated — update types and run `make generate`.
- `api/` is a distinct Go module so external projects can depend on the types without pulling controller deps. The root module uses `replace github.com/fluxcd/source-controller/api => ./api`.

## Build, test, lint

All targets live in the top-level `Makefile`. Extra `go test` flags go via `GO_TEST_ARGS` (default `-race`). Tool binaries install into `build/gobin/` on first use.

- `make tidy` — tidy both the root and `api/` modules.
- `make fmt` / `make vet` — run in both modules.
- `make generate` — `controller-gen object` against `api/` (deepcopy).
- `make manifests` — regenerate CRDs and RBAC from `+kubebuilder` markers.
- `make api-docs` — regenerate `docs/api/v1/source.md`.
- `make manager` — static build of `build/bin/manager`.
- `make test` — chains `install-envtest` + `test-api` + `go test ./...` with coverage and `KUBEBUILDER_ASSETS` set to envtest binaries.
- `make test-api` — unit tests inside `api/`.
- `make test-ctrl GO_TEST_PREFIX=<name>` — run one reconciler suite under `internal/controller`.
- `make install` / `make uninstall` / `make run` / `make deploy` / `make dev-deploy` / `make docker-build` / `make docker-push` — cluster workflows.
- `make verify` — runs `fmt vet manifests api-docs tidy` and fails on a dirty tree. CI uses this.
- `make e2e` — shells out to `hack/ci/e2e.sh`.

## Codegen and generated files

Check `go.mod` and the `Makefile` for current dependency and tool versions. After changing API types or kubebuilder markers, regenerate and commit the results:

```sh
make generate manifests api-docs
```

Generated files (never hand-edit):

- `api/v1*/zz_generated.deepcopy.go`
- `config/crd/bases/*.yaml`
- `docs/api/v1/source.md`

Load-bearing `replace` directives in `go.mod` — do not remove:

- `Masterminds/semver/v3` pinned (see issue #1738).
- `opencontainers/go-digest` pinned to a master snapshot for BLAKE3 support.

Bump `fluxcd/pkg/*` modules as a set — version skew breaks `go.sum`. Run `make tidy` after any bump.

## Conventions

- Standard `gofmt`. Every exported name needs a doc comment; non-trivial unexported declarations should have one too.
- Reconcilers follow the Flux sub-reconciler pattern: the top-level `Reconcile` invokes an ordered slice of step functions, then `summarize.Processor` (in `internal/reconcile/summarize/`) collapses their `reconcile.Result` + errors into terminal conditions and patches status. Don't set conditions directly from step code.
- Status writes go through the patch helper with `metav1.Condition` values from `api/v1/condition_types.go` and `fluxcd/pkg/apis/meta` (`Ready`, `Reconciling`, `Stalled`, kind-specific `ArtifactInStorage`, `SourceVerified`, `FetchFailed`, etc.). Use `fluxcd/pkg/runtime/conditions`.
- Events: `EventRecorder` wired to `fluxcd/pkg/runtime/events.Recorder`. Event reasons match condition reasons.
- Artifacts: create via `Storage.NewArtifactFor`, persist with `Storage.Archive`/`Storage.Copy` inside the per-object lock (`Storage.LockFor`), publish via `Storage.SetArtifactURL`, and run `Storage.GarbageCollect` after a successful write honoring `--artifact-retention-ttl` and `--artifact-retention-records`.
- TLS/transport: build `http.Transport` via `internal/transport` and TLS configs via `internal/tls`. Proxy, HTTP/2, and keepalive settings must stay consistent.
- Feature gates go through `internal/features` plus `fluxcd/pkg/runtime/features`. Define the constant in `features.go` with its default; check with `features.Enabled(...)`.
- Digests default to `internal/digest.Canonical` and can be overridden by `--artifact-digest-algo`. Hash through the writer in `internal/digest` — never import `crypto/sha256` directly.

## Testing

- Integration tests live next to the reconcilers in `internal/controller/*_test.go`. `suite_test.go` spins up `testenv.Environment` (`fluxcd/pkg/runtime/testenv`), a local `testserver.ArtifactServer`, an in-memory distribution registry, and `foxcpp/go-mockdns`.
- `make install-envtest` downloads kube-apiserver/etcd binaries into `build/testbin/`. `make test` sets `KUBEBUILDER_ASSETS` to that path. On macOS the Makefile forces `ENVTEST_ARCH=amd64`.
- Plain Go + Gomega (`gomega.NewWithT(t)`); no Ginkgo. Reuse the package-level `k8sClient`, `testEnv`, `testStorage`, and `testServer` from `suite_test.go`.
- Tests unset `HTTP_PROXY`/`HTTPS_PROXY` and set `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_NOSYSTEM=true` to isolate from the developer's environment. Do the same for new git-shelling tests.
- Run a single test: `make test GO_TEST_ARGS="-v -run TestGitRepositoryReconciler_reconcileSource"`.
- Run one reconciler suite: `make test-ctrl GO_TEST_PREFIX=TestHelmChart`.
- Fixtures: `internal/controller/testdata`, `internal/helm/testdata`, `internal/fs/testdata`. Reuse; don't add new large binaries.

## Gotchas and non-obvious rules

- Two Go modules: root and `api/`. `make tidy`, `fmt`, `vet`, `test` iterate both. A change to `api/` types requires running `make generate` **and** `make manifests` and committing the regenerated files in the same PR.
- `make verify` is the CI gate — a dirty diff means you forgot to run codegen or tidy.
- The `replace` directives in `go.mod` (semver and go-digest) exist for correctness. Leave them alone.
- `Storage` serializes writes per object via `fluxcd/pkg/lockedfile` and expects `--storage-path` to be a real local directory. Never write artifacts outside `Storage.BasePath` — the file server exposes that path verbatim at `--storage-addr`.
- Workload Identity is feature-gated by `auth.FeatureGateObjectLevelWorkloadIdentity` (from `fluxcd/pkg/auth`). Token caching is opt-in via `--token-cache-max-size`.
- `CacheSecretsAndConfigMaps` (in `internal/features`) is off by default; `Secret`/`ConfigMap` lookups bypass the cache and hit the API server directly. Mind that before adding new secret reads to a hot path.
- The controller watches a label-selected subset of its CRs — see `Cache.ByObject` in `mustSetupManager`. Adding a new kind requires updating both `main.go` and the scheme.
- `pkg/azure`, `pkg/gcp`, `pkg/minio` are importable by external consumers. Treat their exported surface as semi-public API.
