# Security Assessment: Jwtlet Token Exchange Implementation

**Date:** 2026-09-30
**Version reviewed:** 0.0.2 (`34307c7`); findings remediated in the same change set

This is a code-level security review of the token exchange flow and the
management API. It complements [token-exchange-threat-model.md](token-exchange-threat-model.md),
which analyses the *conceptual model*. This document asks a different question:
*given the model, does the code enforce every check the model relies on?*

## Scope and Method

Reviewed crates:

| Crate             | Areas                                                                           |
|-------------------|---------------------------------------------------------------------------------|
| `jwtlet-core`     | `token` (exchange), `resource` (mapping verification), `k8s` (TokenReview), `saccount` |
| `jwtlet-server`   | `exchange` / `management` HTTP handlers, `assembly`, `config`, `server`         |
| `jwtlet-postgres` | `resource_store`                                                                 |

The review traced a `/token` request end to end: form parsing, subject token
verification, mapping resolution, scope-to-claim expansion, audience resolution
and token generation. It also traced the management API authentication and
authorization path, and the startup/configuration path.

Severity scale:

| Severity | Meaning                                                                                     |
|----------|---------------------------------------------------------------------------------------------|
| High     | A check the security model relies on is missing; exploitable under realistic cluster setups |
| Medium   | A weakening of a documented security property, or a missing defence-in-depth layer         |
| Low      | Hardening, robustness or operational hygiene                                                |

## Summary

| ID  | Title                                                                              | Severity   | Location                                             | Status |
|-----|------------------------------------------------------------------------------------|------------|------------------------------------------------------|--------|
| F1  | TokenReview response audiences are not verified                                    | High       | `jwtlet-core/src/k8s/mod.rs`                         | Fixed  |
| F2  | Any authenticated K8s identity is accepted, not only service accounts              | Medium     | `jwtlet-core/src/k8s/mod.rs`                         | Fixed  |
| F3  | Management and exchange callers may share a token audience                         | Medium     | `jwtlet-server/src/assembly/mod.rs`                  | Accepted risk |
| F4  | Reserved claims enforced only on write; custom claims can shadow registered claims | Medium     | `jwtlet-core/src/token/mod.rs`, `resource/mod.rs`    | Fixed  |
| F5  | No `jti`, no upper bound on token TTL                                              | Low–Medium | `jwtlet-core/src/token/mod.rs`, `config/mod.rs`      | Fixed  |
| F6  | Duplicate requested scopes are not normalized                                      | Low        | `jwtlet-core/src/resource/mod.rs`, `exchange/mod.rs` | Fixed  |
| F7  | K8s API client has no timeout and no HTTPS enforcement                             | Low        | `jwtlet-server/src/assembly/mod.rs`, `config/mod.rs` | Fixed  |
| F8  | Literal Vault token written to a predictable, world-readable temp file            | Low        | `jwtlet-server/src/assembly/mod.rs`                  | Fixed  |
| F9  | Management input validation gaps; scope "create" silently upserts                  | Low        | `jwtlet-core/src/resource/`, `jwtlet-postgres`       | Fixed  |
| F10 | Example configuration uses the API server audience as `token.client_audience`     | Low        | `README.md`, `e2e/manifests/jwtlet-config.yaml`      | Mitigated |

---

## Findings

### F1 — TokenReview response audiences are not verified

**Severity:** High
**Location:** `crates/jwtlet-core/src/k8s/mod.rs` (`K8sTokenReviewVerifier::verify_token`)

**Description.** The verifier sends `spec.audiences = [client_audience]` to the
TokenReview API and then only checks `status.authenticated` and `status.user`.
The Kubernetes API contract requires TokenReview clients to verify that
`status.audiences` intersects the requested audiences: authenticators that are
not audience-aware (OIDC, webhook, static and bootstrap tokens, and in some
configurations legacy secret-based SA tokens) can return `authenticated: true`
with the API server's own audiences instead of the requested one.

**Impact.** Audience binding of the subject token is the primary replay defence
the architecture relies on (trust assumption 1 of the threat model, and
"Audience binding" in `security-architecture.md`). Without the check, any
credential the API server accepts — for example a human operator's `kubectl`
OIDC token or a token leaked from an unrelated integration — is accepted by
`/token` if its username matches a mapping. The management API uses the same
verifier and is equally affected.

**Recommendation.** Deserialize `status.audiences` and reject the review unless
it contains the requested audience.

**Resolution.** `TokenReviewStatus` now deserializes `audiences`, and
`verify_token` rejects the review unless it contains the requested audience.

### F2 — Any authenticated K8s identity is accepted, not only service accounts

**Severity:** Medium
**Location:** `crates/jwtlet-core/src/k8s/mod.rs` (`UserInfo`), consumed in
`token/mod.rs` and `jwtlet-server/src/management/mod.rs`

**Description.** Only `status.user.username` is read, and it is used verbatim as
the mapping `client_identifier` and as the management principal. There is no
check that the identity is a service account (`system:serviceaccount:` prefix,
`system:serviceaccounts` group). The SA `uid` is not read either, so a service
account that is deleted and recreated with the same namespace/name inherits all
mappings of its predecessor.

**Impact.** Widens the set of identities able to call `/token` and the
management API to every authenticator configured on the API server. Combined
with F1, it enables exchanging non-workload credentials. SA recreation
aggravates threat model T6 (stale mappings).

**Recommendation.** By default, require the identity to be a service account
(prefix and group). Surface `uid` so it can be recorded in `act`; pinning
mappings to a SA UID is a follow-up that changes the storage schema.

**Resolution.** `UserInfo` now reads `uid` and `groups`. With the new
`require_service_account` builder option (default `true`), the verifier requires
both the `system:serviceaccount:` prefix and the `system:serviceaccounts` group.
The SA UID is propagated as `act.k8s_uid` in issued tokens. Pinning mappings to a
UID remains a follow-up (schema change).

### F3 — Management and exchange callers may share a token audience

**Severity:** Medium
**Location:** `crates/jwtlet-server/src/assembly/mod.rs` (`assemble`)

**Description.** When `management.client_audience` is unset, or equal to
`token.client_audience`, the server logs a warning and continues. Every token
accepted by `/token` is then also a valid bearer for the management API.

**Impact.** Removes the cryptographic separation between workload SAs and
orchestrator SAs that `security-architecture.md` lists as a security property.
The only remaining barrier is the `service_accounts` role list.

**Recommendation.** Make `management.client_audience` mandatory and distinct
from `token.client_audience`; fail configuration validation otherwise.

**Resolution (accepted risk).** Enforcement was briefly added and then reverted:
`management.client_audience` remains optional, falls back to
`token.client_audience`, and a shared audience only produces a startup warning.
The risk is accepted because management access still requires an explicit role in
the `service_accounts` allowlist, and F2 limits callers to service accounts.
Deployments are encouraged to configure a distinct management audience (as the
README and e2e setup do); enforcing it can be revisited later.

### F4 — Reserved claims enforced only on write; custom claims can shadow registered claims

**Severity:** Medium (defence in depth)
**Location:** `crates/jwtlet-core/src/token/mod.rs` (`exchange_token`),
`crates/jwtlet-core/src/resource/mod.rs` (`RESERVED_CLAIMS`)

**Description.**

- `TokenClaims.custom` is `#[serde(flatten)]`. A custom claim named `sub`, `iss`,
  `aud`, `exp`, … produces a JWT payload with **duplicate keys**; most JSON
  parsers keep the last occurrence, i.e. the custom value.
- The reserved-claim denylist is enforced only in
  `ResourceService::save_scope_mappings` / `update_scope_mapping`. Scope mappings
  written directly to Postgres (migrations, restores, manual SQL, other tools)
  are copied into issued tokens unfiltered.
**Impact.** A single bad row in `scope_mappings` could override `sub` (the
participant context) or `aud` in issued tokens, bypassing mapping and audience
checks entirely. Relates to threat model T3.

**Recommendation.** Filter reserved keys again at issuance time, logging a
warning when anything is dropped.

**Resolution.** `exchange_token` drops any reserved key from scope-derived claims
at issuance time and logs a warning. The denylist itself is unchanged (`sub iss aud
exp iat nbf act jti`): extending it to claims such as `scope` would break the
documented use of scope mappings to build the token's `scope` claim.

### F5 — No `jti`, no upper bound on token TTL

**Severity:** Low–Medium
**Location:** `crates/jwtlet-core/src/token/mod.rs`, `crates/jwtlet-server/src/config/mod.rs`

**Description.** Issued tokens carry no `jti`, so downstream services cannot
detect replay and a future denylist or introspection endpoint has no key.
`token.token_ttl_secs` is only required to be positive, with no maximum.

**Impact.** Aggravates threat model T5 (transferable bearer tokens) and T7
(revocation latency equals TTL). A misconfigured TTL silently produces
long-lived tokens.

**Recommendation.** Add a random `jti` to every issued token and cap
`token_ttl_secs` in configuration validation.

**Resolution.** Every issued token carries a random UUID `jti`.
`token.token_ttl_secs` is capped at 86400 by configuration validation. Bounding the
issued token's lifetime by the subject token's `exp` is not possible with
TokenReview, which does not return it.

### F6 — Duplicate requested scopes are not normalized

**Severity:** Low
**Location:** `crates/jwtlet-core/src/resource/mod.rs` (`ResourceService::verify`),
`crates/jwtlet-server/src/exchange/mod.rs`

**Description.** A request with `scope=a a` expands scope `a` twice: string
claims are concatenated with themselves (`"x x"`) and non-string claims fail
with a claim conflict. The response echoes the raw `scope` parameter instead of
the granted scope set.

**Impact.** Malformed claim values and inconsistent error behaviour; no
privilege gain.

**Recommendation.** Deduplicate requested scopes (ordered set) before expansion
and return the normalized scope string.

> An empty or missing `scope` yields a token with no scope-derived claims. This
> is intended: `scope` is optional per `security-architecture.md`.

**Resolution.** Requested scopes are deduplicated into an ordered set in both the
HTTP handler and `ResourceService::verify`; the response `scope` is the normalized,
space-joined set (omitted when empty).

### F7 — K8s API client has no timeout and no HTTPS enforcement

**Severity:** Low
**Location:** `crates/jwtlet-server/src/assembly/mod.rs` (`create_k8s_verifier`),
`crates/jwtlet-server/src/config/mod.rs`

**Description.** The `reqwest` client used for TokenReview has no connect or
request timeout. `k8s.api_server_url` is not required to use `https`, although
Jwtlet's own SA token is sent to it as a bearer credential.

**Impact.** A slow or unreachable API server stalls every `/token` and
management request (resource exhaustion). A plain-HTTP URL leaks Jwtlet's SA
token.

**Recommendation.** Configure connect and request timeouts; reject non-`https`
API server URLs.

**Resolution.** The TokenReview client uses a 5 s connect timeout and a 10 s
request timeout, and warns when the cluster CA is missing. Configuration
validation rejects a non-`https` `k8s.api_server_url`.

### F8 — Literal Vault token written to a predictable, world-readable temp file

**Severity:** Low
**Location:** `crates/jwtlet-server/src/assembly/mod.rs` (`create_vault_client`)

**Description.** When `vault.token` is configured, the token is written to
`$TMPDIR/jwtlet_vault_token` with the default umask (typically `0644`),
following symlinks at a predictable path.

**Impact.** Local disclosure of the Vault token to other users of the host, and
symlink clobbering. The option is documented as development-only but nothing
prevents its use elsewhere.

**Recommendation.** Create the file exclusively (`create_new`) with mode `0600`
at an unpredictable path.

**Resolution.** The token is written with `create_new` and mode `0600` to a
uniquely named file (`jwtlet_vault_token-<uuid>`).

### F9 — Management input validation gaps; scope "create" silently upserts

**Severity:** Low
**Location:** `crates/jwtlet-core/src/resource/mod.rs`, `resource/mem.rs`,
`crates/jwtlet-postgres/src/resource_store.rs`

**Description.**

- Resource mappings accept empty `clientIdentifier` / `participantContext`,
  empty or whitespace-containing scopes (which can never be requested, since
  request scopes are whitespace-separated), and empty audiences.
- `POST /api/v1/scopes` is a create operation but upserts: an existing scope's
  claims are silently overwritten, and the audit log records "scope mapping
  created".

**Impact.** Silent policy overwrites and a misleading audit trail (threat model
T8); dead or confusing mapping entries.

**Recommendation.** Validate mapping fields on create/update. Make scope
creation fail with `409 Conflict` when the scope already exists; updates go
through `PUT`.

**Resolution.** `ResourceService::save`/`update` reject empty identifiers, empty
or whitespace scope names and empty audiences (`400 Bad Request`). Scope creation
(memory and Postgres stores) fails with `409 Conflict` when a scope already exists
or repeats within the batch, and the batch is rolled back.

### F10 — Example configuration uses the API server audience as `token.client_audience`

**Severity:** Low
**Location:** `README.md`, `e2e/manifests/jwtlet-config.yaml`

**Description.** The documented example and the e2e deployment set
`token.client_audience` to `https://kubernetes.default.svc.cluster.local`, the
Kubernetes API server's own audience. Every automounted SA token carries that
audience.

**Impact.** Authorization is not weakened: any SA can authenticate, but a token is
only issued if a resource mapping exists, and management access still requires a
role in `service_accounts`. The risk is credential replay outside Jwtlet: every
subject token presented to Jwtlet is also a valid credential against the
Kubernetes API, so anything that captures it — request logging, a proxy or
sidecar, or Jwtlet itself if compromised — can act as that SA against the cluster
with its RBAC permissions. Operators copying the example inherit this setup.

**Recommendation.** Use a dedicated audience for exchange (and a different one for
management) and issue projected SA tokens for it.

**Resolution (mitigated).** The README and the e2e manifests/tests now use
dedicated audiences (`jwtlet-exchange`, `jwtlet-management`). Jwtlet logs a warning
at startup when either client audience equals `k8s.cluster_issuer` or
`k8s.api_server_url`. Turning this into a validation error is recommended once
existing deployments have migrated.

---

## Checked and Found Adequate

- All SQL is parameterized.
- Missing mapping, disallowed scope and disallowed audience all return the same
  `403 unauthorized_client` with no description (no enumeration oracle).
- Audience resolution (`resolve_audience`) matches the documented rules.
- `act` is inserted after scope claims and `act` is on the reserved list, so it
  cannot be overridden by a scope mapping.
- `grant_type` and `subject_token_type` are validated.
- Bearer header parsing is safe; subject tokens are not logged.
- Request bodies are bounded by axum's default limit (2 MB).
- An empty or missing `scope` is accepted by design (see F6 note).

## Relation to the Threat Model

| Finding | Related threat-model item                                   |
|---------|-------------------------------------------------------------|
| F1, F2  | Trust assumption 1 (TokenReview is authoritative)           |
| F3      | Two-tier SA model                                           |
| F4      | T3 (scope claims are declarative)                           |
| F5      | T5 (transferable tokens), T7 (revocation latency)           |
| F10     | Trust assumption 1, two-tier SA model                       |
| F9      | T8 (audit trail)                                            |
