# Jwtlet Security Architecture

Jwtlet is a token exchange service implementing [RFC 8693 OAuth 2.0 Token Exchange][rfc8693].
It accepts Kubernetes service account tokens as input, verifies the caller's identity via the
Kubernetes TokenReview API, evaluates an authorization policy expressed as resource and scope
mappings, and issues signed JWTs via HashiCorp Vault's transit engine.

This document describes the security model, trust chain, data model, and protocol behavior.
For a security threat analysis see [token-exchange-threat-model.md](token-exchange-threat-model.md).

---

## Architecture

Jwtlet runs two independent HTTP servers on separate ports:

| Server         | Default port | Purpose                                                 |
|----------------|--------------|---------------------------------------------------------|
| Token exchange | 8080         | `/token` exchange endpoint and `/.well-known/jwks.json` |
| Management API | 8081         | Mapping and scope administration                        |

The separation means management API exposure is independently controllable at the network
level — the exchange endpoint can be cluster-internal while the management API is restricted
to operator namespaces or kept entirely off-network.

## Trust Chain

```
K8s API server  ──(TokenReview)──►  Jwtlet verifies SA identity
                                         │
                                    policy lookup
                                         │
                                    ResourceMapping: (clientId, participantContext, scopes, audiences)
                                    ScopeMapping:    scope → {claim: value, ...}
                                         │
                                    Vault transit sign
                                         │
                                    Issued JWT: sub=participantContext, aud=audience,
                                               claims from scopes, act={SA identity}
                                         │
                                    Downstream service validates against Jwtlet JWKS
```

**What each layer proves:**

- K8s proves *who is calling* — the SA identity is authoritative via TokenReview.
- The resource mapping proves *what they are allowed to do* — which participant contexts
  and scopes a given SA may request.
- Vault proves *the token is genuine* — the transit signing key is accessible only to Jwtlet.
- The JWKS endpoint enables downstream services to independently verify the signature.

---

## Two-Tier Service Account Model

The model enforces a strict separation between two SA classes:

**Orchestrator SAs** hold `jwtlet:management:mappings:write` and/or `jwtlet:management:scope:write` roles. They
administer authorization policy via the management API — creating, updating, and deleting resource and scope mappings.
Orchestrators are not expected to call `/token`; they are the policy administrators, not policy subjects.

**Workload SAs** are the subjects of policy. They hold no management API roles. They call
`/token` to obtain JWTs for downstream services and cannot modify their own mappings.

The boundary between tiers is enforced by the `service_accounts` config section, which
enumerates the specific SA identities that hold management roles. Only those SAs can
authenticate successfully against the management API. All other SAs are rejected at the
authorization middleware layer before any handler runs.

This is a hard configuration boundary, not a runtime check: if an SA is not listed in
`service_accounts`, it has no management access regardless of any other credential it holds.

---

## Identity Verification

Every request to `/token` submits a Kubernetes SA token as the `subject_token` form field
(RFC 8693 form-encoded body). There is no Authorization header on the exchange endpoint.
Jwtlet calls the K8s TokenReview API to verify the subject token:

```
POST https://{api_server}/apis/authentication.k8s.io/v1/tokenreviews
Authorization: Bearer {jwtlet_own_sa_token}
Body: { "spec": { "token": "{caller_token}", "audiences": ["{token.client_audience}"] } }
```

The TokenReview response carries the SA's `sub` (`system:serviceaccount:{ns}:{name}`)
and `iss` (the cluster OIDC issuer URL). These are the authoritative inputs to the exchange
pipeline; no claim from the incoming token is trusted directly.

**Audience binding.** The SA token must be projected with the audience matching
`token.client_audience`. Jwtlet additionally requires the TokenReview response's
`status.audiences` to contain the requested audience: authenticators that are not
audience-aware may report a token as authenticated without honoring the requested
audience. This prevents replay of SA tokens against other services in the cluster.
`token.client_audience` should be a dedicated value rather than the API server's own
audience: tokens bound to that audience are also valid Kubernetes API credentials, so a
token presented to Jwtlet could be replayed against the cluster (Jwtlet warns at startup
if it is).

**Service accounts only.** Jwtlet accepts only Kubernetes service account identities:
the TokenReview user must have a `system:serviceaccount:` username and belong to the
`system:serviceaccounts` group. Identities from other API server authenticators (OIDC
users, static or bootstrap tokens) are rejected. The SA's UID, when returned, is recorded
in the issued token's `act.k8s_uid` claim.

**Management API identity.** The management API uses a separate `management.client_audience`
value. When configured, management callers must present SA tokens bound to that distinct
audience, providing cryptographic separation between exchange callers and management callers.
If `management.client_audience` is absent, it falls back to `token.client_audience` — a
configuration Jwtlet warns about at startup. Access is then gated only by the
`service_accounts` role list.

---

## Policy Model

### Resource Mappings

A `ResourceMapping` grants specific SA access to exchange for a specific participant context:

```json
{
  "clientIdentifier": "system:serviceaccount:ns:sa-name",
  "participantContext": "payment-org",
  "scopes": [
    "connector:write",
    "catalog:read"
  ],
  "audiences": [
    "https://payment-service.example.com"
  ]
}
```

| Field                | Type          | Semantics                                                               |
|----------------------|---------------|-------------------------------------------------------------------------|
| `clientIdentifier`   | String        | SA `sub` from TokenReview — exact match required                        |
| `participantContext` | String        | Logical identity that will become `sub` in the issued token             |
| `scopes`             | Set\<String\> | The scopes this SA is permitted to request for this context             |
| `audiences`          | Set\<String\> | Allowed `aud` values for issued tokens; empty = only the global default |

The composite key is `(clientIdentifier, participantContext)`. A single SA may hold multiple
mappings — one per participant context it is permitted to act on behalf of.

Multiple SAs may map to the same participant context with different scope sets. This is the
intended mechanism for partitioning capabilities within a shared logical identity:

```
sa-connector  → payment-org  scopes=[connector:write]
sa-ih         → payment-org  scopes=[ih:write]
```

Both produce tokens with `sub=payment-org` but with different injected claims. Blast radius
for a compromised SA is bounded to the scopes in its specific mapping.

### Scope Mappings

A `ScopeMapping` defines the claims injected when a given scope is granted:

```json
{
  "scope": "connector:write",
  "claims": {
    "role": "connector-agent",
    "connector_id": "connector-123"
  }
}
```

Scope mappings are **global** — `connector:write` injects the same claims regardless of which
participant context or SA references it. Modifying a scope mapping affects every SA and context
that references it simultaneously.

**Claim injection is declarative.** Claims are injected unconditionally; Jwtlet does not
verify the SA's real-world role against any external system. The claims represent an
orchestrator's policy declaration, not a live authorization query. Claims may become stale
if the real-world state changes before an orchestrator updates the mapping.

**Reserved claims denylist.** The following claim keys may not be set via scope mappings and
are rejected at write-time:

```
sub  iss  aud  exp  iat  nbf  act  jti
```

These claims are set authoritatively by Jwtlet during token generation and cannot be
overridden by scope expansion. The denylist is enforced twice: when scope mappings are
written, and again when a token is issued, so rows written to the store by other means
cannot inject them either.

**Scope mapping creation.** `POST /api/v1/scopes` fails with `409 Conflict` if a scope
already exists (the whole batch is rejected); existing scopes are changed with `PUT`.
Scope names must be non-empty and contain no whitespace.

**Scope claim conflict detection.** If a token exchange request includes multiple scopes whose
mappings define the same claim key, the exchange fails with a `409 Conflict` response. Claim
key uniqueness across the requested scope set is enforced at exchange time.

---

## Token Exchange Protocol

### Request

The `/token` endpoint accepts RFC 8693 form-encoded requests:

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={k8s_sa_token}
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&resource={participant_context}
&scope={space_separated_scopes}    (optional)
&audience={target_audience}        (optional)
```

| Parameter            | Required | Description                                                            |
|----------------------|----------|------------------------------------------------------------------------|
| `grant_type`         | Yes      | Must be `urn:ietf:params:oauth:grant-type:token-exchange`              |
| `subject_token`      | Yes      | The K8s SA token to verify via TokenReview                             |
| `subject_token_type` | Yes      | Must be `urn:ietf:params:oauth:token-type:jwt`                         |
| `resource`           | Yes      | The participant context being requested (`sub` of the issued token)    |
| `scope`              | No       | Space-separated list of scopes to request                              |
| `audience`           | No       | Requested `aud` for the issued token; must be in the mapping allowlist |

The `audience` parameter requests a specific `aud` value in the issued token.
If absent, the global `token.audience` default is used (subject to the mapping's audience
allowlist — see below).

### Processing Pipeline

1. **Verify SA token** — TokenReview against `token.client_audience`; the response must confirm
   that audience and identify a service account. Extracts `sub`, `iss` and the SA UID.
2. **Resolve mapping** — look up `(sub, resource)` in the resource store, where `resource` is the requested participant
   context.
3. **Verify scopes** — requested scopes are deduplicated; all of them must be present in the mapping's `scopes` set.
   Any scope not in the set returns `401 Unauthorized`.
4. **Expand scopes to claims** — for each requested scope, merge its `ScopeMapping.claims`
   into the outgoing claims map. Duplicate claim keys across scopes return `409 Conflict`.
5. **Resolve audience** — apply the audience allowlist logic (see below).
6. **Build JWT claims** — assemble `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `act`, and custom claims
   (reserved keys are dropped from the custom claims).
7. **Sign via Vault** — call Vault transit `sign` operation with the configured key.
8. **Return** — RFC 8693 response with `access_token`, `token_type=Bearer` and the normalized
   (deduplicated, sorted) `scope`.

### Audience Resolution

The audience for the issued token is resolved as follows, where `allowed` is
`ResourceMapping.audiences` and `default` is `token.audience`:

| Requested | Allowlist               | Result                                      |
|-----------|-------------------------|---------------------------------------------|
| None      | Empty                   | `default`                                   |
| None      | Contains `default`      | `default`                                   |
| None      | Non-empty, no `default` | `401 Unauthorized`                          |
| `req`     | Empty                   | `req` only if `req == default`, else `401`  |
| `req`     | Non-empty               | `req` only if `req ∈ allowlist`, else `401` |

An empty allowlist means only the global default is valid; callers may not request an
alternative audience. A non-empty allowlist restricts the issued token to the enumerated
targets regardless of what the caller requests.

### Issued Token Structure

```json
{
  "sub": "payment-org",
  "iss": "https://jwtlet.example.com",
  "aud": "https://payment-service.example.com",
  "iat": 1700000000,
  "nbf": 1700000000,
  "exp": 1700003600,
  "jti": "5f0c6f0e-8d2a-4f7e-9d7e-2b1f4c3a9e10",
  "act": {
    "sub": "system:serviceaccount:ns:sa-connector",
    "iss": "https://kubernetes.default.svc.cluster.local",
    "k8s_uid": "0d2f6b1e-7c4a-4e59-9b3f-6a8e2c1d5f70"
  },
  "role": "connector-agent",
  "connector_id": "connector-123"
}
```

| Claim  | Source                                                     |
|--------|------------------------------------------------------------|
| `sub`  | `participantContext` from the exchange request             |
| `iss`  | Jwtlet's own issuer identity (Vault key identifier)        |
| `aud`  | Resolved from request + allowlist                          |
| `iat`  | Current time                                               |
| `nbf`  | Current time                                               |
| `exp`  | `iat + token_ttl_secs` (default 3600s, maximum 86400s)     |
| `jti`  | Random UUID, unique per issued token                       |
| `act`  | `{sub: SA identity, iss: cluster issuer, k8s_uid: SA UID}` from TokenReview |
| *rest* | Merged from scope mapping claim expansion                  |

The `act` claim implements RFC 8693 delegation semantics. It records the K8s SA that
performed the exchange and can be used by downstream services to trace the original caller.
`act.iss` is the K8s cluster OIDC issuer and can be validated by downstream services that
know the expected cluster identity.

---

## Signing and Key Distribution

Vault's transit engine provides asymmetric signing. The signing key name is derived from
`{signing_key_prefix}-{participant_context_claim}`, defaulting to `signing-jwtlet_pc`. A
single key is shared across all participant contexts.

**JWKS endpoint.** `GET /.well-known/jwks.json` returns the Vault-backed public key in
JWK Set format. The endpoint is unauthenticated (standard for JWKS per RFC 7517).
Downstream services fetch this endpoint to obtain the verification key.

Downstream services must not cache JWKS responses indefinitely; they should re-fetch on
`kid` mismatch to handle key rotation. On key rotation, a grace period where both old and
new keys appear in the JWKS response prevents rejection of in-flight tokens.

---

## Management API

The management API runs on a separate port and requires a K8s SA token in the Authorization
header. Three roles control access:

| Role                               | Permitted operations                         |
|------------------------------------|----------------------------------------------|
| `jwtlet:management:read`           | `GET /api/v1/mappings`, `GET /api/v1/scopes` |
| `jwtlet:management:mappings:write` | Create, update, delete resource mappings     |
| `jwtlet:management:scope:write`    | Create, update, delete scope mappings        |

Read and write privileges are strictly separated. Holding `jwtlet:management:mappings:write` does not confer
read access; `jwtlet:management:read` must be explicitly granted.

### Endpoints

```
GET    /api/v1/mappings                    List all resource mappings
POST   /api/v1/mappings                    Create a resource mapping
PUT    /api/v1/mappings/{clientId}/{ctx}   Update a resource mapping
DELETE /api/v1/mappings/{clientId}/{ctx}   Delete a resource mapping
DELETE /api/v1/mappings/{clientId}         Delete all mappings for a client

GET    /api/v1/scopes                      List all scope mappings
POST   /api/v1/scopes                      Create a scope mapping
PUT    /api/v1/scopes/{scope}              Update a scope mapping
DELETE /api/v1/scopes/{scope}              Delete a scope mapping
```

### Audit Logging

Every mutation emits a structured `tracing::info!` event with the following fields:

| Field       | Value                                        |
|-------------|----------------------------------------------|
| `actor`     | The orchestrator SA's `sub` from TokenReview |
| `client_id` | The affected `clientIdentifier` (mappings)   |
| `context`   | The affected `participantContext` (mappings) |
| `scope`     | The affected scope name (scope mappings)     |

These events provide a who/what-key audit trail. Before/after state for update and delete
operations is delegated to the database layer: enable `pgaudit` on the Postgres backend
to capture full DML-level change history. The two layers together form a complete audit
trail — the application log records who acted; the database log records what changed.

---

## Security Invariants

The following properties are enforced by the implementation and must hold for the security
model to be sound:

1. **SA identity is always from TokenReview.** The `act.sub` and the `clientIdentifier`
   lookup key come exclusively from the TokenReview response. No claim from the incoming
   token is used directly. The response must confirm the requested audience and identify
   a Kubernetes service account.

2. **Scope expansion cannot override reserved claims.** The reserved claims denylist
   (`sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `act`, `jti`) is enforced at scope mapping
   write time. A scope mapping that attempts to set any of these is rejected at the
   management API with HTTP 400. Reserved keys are also dropped at issuance time.

3. **Scopes are all-or-nothing.** The exchange fails if any single requested scope is
   not present in the mapping. Partial scope grants are not issued.

4. **Audience is constrained by the mapping.** A caller cannot obtain a token for an
   audience not permitted by the mapping's `audiences` allowlist. The caller's requested
   audience is validated against the allowlist; a mismatch returns `401 Unauthorized`.

5. **Management and exchange callers are independently authenticated.** When
   `management.client_audience` is set to a value distinct from `token.client_audience`,
   the audience binding on the SA token cryptographically separates the two caller
   populations. An exchange caller's SA token cannot be replayed against the management API.
   Otherwise, management access is gated only by the `service_accounts` role list.

6. **Claim conflicts across scopes are rejected.** If two scopes in the same exchange
   request expand to the same claim key, the exchange fails rather than silently overwriting.

---

## Deployment Security Requirements

The security model requires the following from the deployment environment and downstream
services. Failure to adhere to these rules invalidates the model's guarantees.

**Downstream services must:**

- Validate the JWT signature against the Jwtlet JWKS endpoint
- Perform strict `aud` validation — reject tokens where `aud` does not exactly match their
  own identifier
- Validate `exp` and reject expired tokens
- Log `act.sub` to preserve the chain-of-custody record
- Optionally reject tokens where `act.iss` does not match the expected K8s cluster issuer

**Operators must:**

- Treat orchestrator SA credentials as CA-equivalent secrets — rotate on any suspected
  compromise, limit distribution, and audit access
- Use dedicated values for `token.client_audience` and `management.client_audience`, never
  the Kubernetes API server audience, and issue projected SA tokens for them
- Set `token_ttl_secs` to the shortest value consistent with operational requirements;
  3600s (the default) is too long for sensitive participant contexts
- Enable `pgaudit` on the Postgres backend in production deployments
- Forward application logs to an append-only external store inaccessible to orchestrator SAs
- Assign non-overlapping scope sets to SAs sharing a participant context
- Apply least-privilege scope assignment — grant only the scopes a workload actually requires

[rfc8693]: https://www.rfc-editor.org/rfc/rfc8693
