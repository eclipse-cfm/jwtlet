# Jwtlet

Jwtlet is an [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) OAuth 2.0 token exchange service for participant
context operations. Clients exchange a Kubernetes service account token for a signed JWT that encodes participant
context claims. The service validates the incoming token against a Kubernetes OIDC issuer, resolves resource mappings
and scope-to-claims mappings, and signs the resulting token via HashiCorp Vault.

Jwtlet runs two HTTP servers: a **token exchange API** (default port 8080) and a **management API** (default port 8081)
for administering resource and scope mappings.

## Building

Requires Rust (stable toolchain).

```bash
# Build all crates
cargo build

# Build the release binary
cargo build --release -p jwtlet-server
```

## Running the Tests

Unit and integration tests:

```bash
cargo nextest run
```

or 

```bash
cargo test
```

End-to-end tests run against a local [kind](https://kind.sigs.k8s.io/) Kubernetes cluster with Vault. Requires Docker
and `kind` installed.

```bash
cd e2e

make all          # full cycle: cluster setup, build, test, cleanup

# or individual steps:
make setup        # create KIND cluster and initialize Vault
make build        # build and load the Docker image into the cluster
make test         # run tests
make cleanup      # tear down the cluster
```

## Running the Server

Pass a TOML config file as the first argument, or set `JWTLET_CONFIG_FILE`:

```bash
jwtlet-server /path/to/config.toml
# or
JWTLET_CONFIG_FILE=/path/to/config.toml jwtlet-server
```

Individual settings can also be overridden with environment variables using the `JWTLET__` prefix (double underscore as
the nesting separator), e.g. `JWTLET__TOKEN_EXCHANGE_PORT=9090`.

### Configuration Reference

```toml
# Ports and bind address
token_exchange_port = 8080   # default
management_port = 8081   # default; must differ from token_exchange_port
bind = "0.0.0.0"

# Storage backend: "memory" (default) or "postgres"
[storage_backend]
type = "memory"
# type = "postgres"
# url  = "postgresql://user:pass@host:5432/jwtlet"

# Kubernetes OIDC validation
[k8s]
api_server_url = "https://kubernetes.default.svc"               # required
cluster_issuer = "https://kubernetes.default.svc.cluster.local" # required
token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"

# Token issuance
[token]
client_audience = "https://kubernetes.default.svc.cluster.local" # required – expected aud of incoming tokens
audience = "my-service"                                    # required – aud of issued tokens
participant_context_claim = "jwtlet_pc"  # default
token_ttl_secs = 3600         # default

# Vault signing backend
[vault]
url = "http://vault:8200"           # required
token_file = "/vault/secrets/.vault-token" # use token_file in production
# token    = "s.xxxxx"                     # or a literal token for development

# Management API authorization
# Keys are Kubernetes service account identifiers; values are lists of roles.
# A caller must hold the "management:write" role to use any management endpoint.
[service_accounts]
"system:serviceaccount:my-namespace:my-sa" = ["management:write"]
```

### Management API Authentication

All management API endpoints (`/api/v1/mappings`, `/api/v1/scopes`) require a
`Authorization: Bearer <token>` header. The token must be a valid Kubernetes service
account token issued with the same audience as `token.client_audience`. Jwtlet
verifies the token via the Kubernetes TokenReview API and checks that the resolved
service account identity holds the `management:write` role.

To obtain a suitable token from within a cluster:

```bash
kubectl create token my-sa -n my-namespace \
  --audience=https://kubernetes.default.svc.cluster.local
```

### Logging

Set `RUST_LOG` to control verbosity (`trace`, `debug`, `info`, `warn`, `error`):

```bash
RUST_LOG=debug jwtlet-server config.toml
```

## Container Image

Multi-architecture images (`linux/amd64`, `linux/arm64`) are published to the GitHub
Container Registry:

```bash
docker pull ghcr.io/eclipse-cfm/jwtlet:latest
```

| Tag | Points at |
| --- | --- |
| `latest` | the most recent stable release |
| `0.2.0` | that exact release |
| `0.2` | the latest patch on the `0.2` minor line |
| `main` | the current `main` branch |
| `sha-<short>` | a specific commit |

Pre-releases (for example `0.2.0-rc.1`) are published under their exact version only —
they never move `latest` or the minor-line tag.

## Releasing

Releases are cut by pushing a git tag. The `Release` workflow verifies the tag, builds and
publishes the image, and then creates the GitHub Release.

1. Bump `version` under `[workspace.package]` in the root `Cargo.toml`. All crates inherit
   it via `version.workspace = true`, so this is the only version to change.
2. Run `cargo check` so `Cargo.lock` picks up the new workspace-member versions.
3. Commit as `chore: release 0.2.0` and merge to `main`.
4. Tag the merge commit and push it:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

The tag must match the `Cargo.toml` version exactly, or the workflow fails before anything
is published. Use a `v0.2.0-rc.1` style tag to cut a pre-release.

## License

Apache-2.0
