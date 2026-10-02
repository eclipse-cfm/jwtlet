# Threat Analysis: Jwtlet Token Exchange Model

This is an architectural threat analysis of the token exchange protocol and
resource/scope mapping model — not a code audit. It asks: is the conceptual
model sound, and where does it break regardless of how correctly the code is
written?

For the code-level review of how the implementation enforces this model, see
[security-assessment.md](security-assessment.md).

---

## Model Summary

```
K8s SA token (audience-bound)
     │
     ▼  TokenReview
Jwtlet verifies SA identity
     │
     ▼  policy lookup
ResourceMapping: (clientId, participantContext, scopes, audiences)
ScopeMapping:    scope -> {claim: value, ...}
     │
     ▼  Vault transit sign
Issued JWT: sub=participantContext, aud=audience, claims from scopes, act={SA identity}
     │
     ▼
Downstream service validates JWT against Jwtlet JWKS
```

**Core premise:** K8s proves *who is calling*. The resource mapping proves *what
they are allowed to do*. The issued token asserts a logical identity
(participant context) with privileges derived from scope → claim expansion.

### Two-Tier SA Model

The model distinguishes two distinct SA tiers with no overlap:

- **Orchestrator SAs** (`jwtlet:management:mappings:write`, `jwtlet:management:scope:write`): dedicated
  administrative identities that configure authorization policy. They define
  which workload SAs map to which participant contexts with which scopes. They
  are expected to be few in number, tightly controlled, and are not themselves
  token exchange consumers — they do not call `/token`.
- **Workload SAs** (no management access): the subjects of policy. They call
  `/token` to obtain JWTs for downstream services. They have no access to the
  management API and cannot modify their own mappings.

The separation between tiers is enforced by K8s RBAC: only SAs listed in
Jwtlet's `service_accounts` config gain orchestrator privileges. If that config
or the underlying K8s RBAC is misconfigured, the separation collapses.

---

## Trust Assumptions the Model Requires

1. K8s TokenReview responses are authoritative and unforgeable
2. The Vault signing key is secret and accessible only to Jwtlet
3. Orchestrator SA credentials are not compromised
4. Orchestrator SAs configure mappings correctly and without malice
5. Downstream services validate the issued JWT fully (signature, `aud`, `exp`)
6. The JWKS endpoint response is not tampered with in transit
7. Participant context strings are meaningful, stable identifiers
8. Scope strings are used consistently across all participant contexts
9. The K8s RBAC policy that restricts `service_accounts` membership to
   orchestrator SAs is itself correctly administered

If any of these fail, the model's security guarantees collapse — independently
of implementation quality.

---

## Threat Analysis

---

### T1 — Orchestrator SA Compromise: Full Policy Rewrite
**Likelihood:** Low
**Impact:** Critical

Orchestrator SAs hold `jwtlet:management:mappings:write` and `jwtlet:management:scope:write` by design — their
explicit purpose is to create and modify mappings for workload SAs. This is not
a confused deputy; it is the intended trust delegation. The threat is that an
attacker gains control of an orchestrator SA.

A compromised orchestrator SA can:
1. Create arbitrary mappings: any workload SA → any participant context → any scopes
2. Silently modify existing mappings to escalate a target SA's privileges
3. Delete mappings to cause denial-of-service for legitimate workload SAs
4. Redefine scope mappings to inject arbitrary claims into all tokens for any SA
   that references those scopes

This is functionally equivalent to CA key compromise: one credential controls
the entire authorization policy. Unlike a PKI where a compromised CA produces
detectable certificate artifacts, a compromised orchestrator SA leaves changes
that are indistinguishable from legitimate operator actions unless an audit trail
exists.

**Structural mitigation:** Treat orchestrator SA credentials as a CA-equivalent
trust anchor. Apply the same operational controls: minimize the number of
orchestrators, rotate credentials on any suspected compromise, and ensure audit
logging is forwarded to an external append-only store (see T8). Audit log
existence is the primary detection mechanism — without it, orchestrator
compromise is silent.

---

### T2 — Shared Context Identity Is Differentiated Only by Scopes and act
**Likelihood:** Medium
**Impact:** Medium

Multiple workload SAs can legitimately map to the same participant context with
different scopes — this is a design feature, not a defect. For example:
- `sa-connector-agent` → `participant-context` with scopes `[connector:write]`
- `sa-ih-agent`        → `participant-context` with scopes `[ih:write]`

Both produce tokens with `sub=participant-context`, but with different injected
claims. The scope assignment is the per-SA access control within a shared
context.

The threat arises when two SAs sharing a context have **overlapping scopes**.
In that case, the authorization claims in the issued token are identical
regardless of which SA triggered the exchange. The tokens are distinguishable
via `act.sub`, which records the originating SA — but only if the downstream
service is built to inspect it. Services that authorize solely on `sub` and
injected claims cannot differentiate the two SAs.

**Consequence:** Within a participant context, the granularity of access control
is the scope assignment. If scopes are distinct, blast radius is bounded to the
compromised SA's own capabilities. If scopes overlap, compromise of either SA
yields the same authorization claims, making the two SAs functionally equivalent
to services that don't inspect `act`.

**Structural mitigation:** Within a participant context, each SA should hold a
distinct, non-overlapping scope set. Use namespaced scopes (e.g.,
`connector:write`, `ih:write`) to make the intent explicit and reduce accidental
overlap. Downstream services that need to distinguish which SA acted within a
shared context must validate and log `act.sub`.

---

### T3 — Scope Claims Are Declarative, Not Verified
**Likelihood:** High
**Impact:** High

Scope mappings inject claims unconditionally. When `read` maps to
`"role": "reader"`, Jwtlet issues that claim to *any* SA that has `read` in its
mapping — without verifying that the SA is actually a reader in any external
system. The claim is an orchestrator's declaration, not a live authorization
check.

**Consequence:** Scope assignment simultaneously controls access (can this SA
exchange?) and attribute assertion (what does the token claim?). These are
coupled: revoking a scope removes both the access gate and the associated claims
in one operation, which is usually correct. The risk is purely temporal — the
orchestrator's declaration is a snapshot. If a SA's real-world role changes but
the mapping is not updated, the token continues asserting stale claims for every
exchange until an orchestrator intervenes.

**Structural mitigation:** Treat Jwtlet-issued claims as slowly changing policy
assertions, not real-time attribute queries. Design downstream services to
re-verify critical attributes out-of-band for high-stakes decisions.

---

### T4 — Scope Namespace Is Global, Not Per-Context
**Likelihood:** High
**Impact:** Medium

Scope mappings are global: `read` maps to the same claims regardless of which
participant context references it. An orchestrator who redefines the `read` scope
affects every workload SA in every context that has `read` in its mapping.

**Consequence:** A single scope mapping change has a blast radius proportional to
how many resource mappings reference that scope. Targeted privilege modification
is not possible at the scope level without scope renaming.

**Structural mitigation:** Use namespaced scope strings (e.g.,
`payment:read`, `analytics:read`) to achieve per-domain isolation. This is a
naming convention, not a model enforcement — the model has no namespace concept
and cannot prevent a scope from being referenced across domains.

---

### T5 — Issued Tokens Are Transferable Within Their Audience
**Likelihood:** High
**Impact:** Medium

Issued JWTs are bearer tokens. Any holder — legitimate or not — can present them
to any service that accepts them for the full TTL. There is no binding between a
token and the workload SA that triggered the exchange, and no one-time-use
mechanism. `act` records the originating SA for audit purposes but does not
prevent relay.

**Consequence:** A stolen issued token is immediately usable by an attacker
until expiry.

**Structural mitigation:** Keep TTL short to limit the window of exposure for a
stolen token.

---

### T6 — Mapping Has No Expiry or Lifecycle Management
**Likelihood:** High
**Impact:** Medium

Resource mappings have no `valid_until`, `created_at`, or `last_reviewed` field.
A mapping created for a temporary integration, a contractor's SA, or a
decommissioned service remains active indefinitely until an orchestrator
explicitly deletes it.

**Consequence:** The mapping set accumulates stale entitlements over time.
There is no mechanism for periodic re-certification. An attacker who acquires an
old SA token (within its K8s TTL) for a forgotten mapping gains access.

**Structural mitigation:** Add `expires_at` to `ResourceMapping`. Require
orchestrators to re-certify mappings periodically. Alternatively, integrate with
a K8s SA deletion webhook.

---

### T7 — Policy Change Is Not Retroactive for Issued Tokens
**Likelihood:** High
**Impact:** Medium

When an orchestrator deletes a mapping or restricts scopes, already-issued tokens
remain valid until their `exp`. A token issued one second before a mapping
deletion continues to grant access to downstream services for the full TTL.

**Consequence:** The effective revocation latency equals `token_ttl_secs`.
For the default 3600s TTL, an attacker has up to one hour of access after
the mapping is removed.

**Structural mitigation:** Keep TTL short (< 5 min for sensitive contexts). A
token introspection endpoint (RFC 7662) would eliminate this window entirely but
is not part of the current model.

---

### T8 — Management API Audit Trail Lacks Durability Guarantee
**Likelihood:** Medium
**Impact:** Critical

Every management API mutation emits a structured `tracing::info!` event
recording the orchestrator's `sub`, the operation type, and the affected mapping
key. This covers detection of unauthorized mutations if logs are forwarded to an
external aggregator.

One gap remains at the application layer: Jwtlet emits structured logs to
stdout; there is no internal append-only store. The audit trail is only as
durable and tamper-resistant as the log aggregation infrastructure (e.g., a
SIEM, CloudWatch, Loki). An attacker with node-level access could clear logs
before they are forwarded.

Before/after state for update and delete operations is intentionally delegated
to the database. The Postgres backend provides complete before/after change
capture via `pgaudit` or logical replication — more reliably and at finer
granularity than application-level logging, and with no risk of being bypassed
by application code. For the in-memory backend (dev/test only), before/after
state is not a production concern.

**Consequence:** Orchestrator compromise (T1) is detectable if application logs
are forwarded to an external aggregator and `pgaudit` (or equivalent) is enabled
on the Postgres backend. Without either, forensic reconstruction after a
compromise is incomplete.

**Structural mitigation:** Forward structured application logs to an append-only
external store that orchestrator SAs cannot access. Enable `pgaudit` on the
Postgres backend to capture full before/after state for all DML operations.
Together these provide a complete, two-layer audit trail: the application log
records *who* made the change; the database log records *what* changed.

---

### T9 — Orchestrator Scope Over-Provisioning Silently Expands Blast Radius
**Likelihood:** Low
**Impact:** Medium

The threat is scope assignment error by an orchestrator: if a SA is granted
broader scopes than its operational role requires, or scopes that overlap with
another SA in the same context, the effective blast radius of a compromise
expands silently. The model has no mechanism to detect or prevent
over-provisioning at the scope level.

**Consequence:** A compromised SA cannot exceed the scopes defined in its
mapping — the risk is entirely in how the orchestrator configured it. Correctly
partitioned scopes bound blast radius to the SA's actual operational need;
over-provisioned scopes expand it without any visible signal.

**Structural mitigation:** Apply least-privilege scope assignment: each SA
should hold only the scopes its workload actually requires, even within a shared
context. Use the `audiences` allowlist to further constrain where tokens can be
used. Audit scope assignments periodically against actual workload requirements.

---

## Structural Limitations of the Model

These are properties of the model that cannot be fixed by implementation
improvements alone:

| Limitation                    | Description                                                                                        |
|-------------------------------|----------------------------------------------------------------------------------------------------|
| Stateless tokens              | Once issued, tokens cannot be revoked without introspection infrastructure                         |
| Global scope namespace        | Scopes are shared across all contexts; per-context scope semantics require naming conventions      |
| No temporal mapping lifecycle | Mappings don't expire; access accumulates without re-certification                                 |
| Incomplete audit trail        | Application logs capture who/what-key; before/after state requires pgaudit on the Postgres backend |
| Scope overlap risk            | Multiple SAs sharing a context with overlapping scopes collapse per-SA accountability              |

---

## Summary

The model is sound for its stated purpose: **attesting K8s workload identity
to downstream services with policy-controlled claim injection.** The two-tier SA
model (orchestrators configure policy; workload SAs consume it) is a clean
separation that avoids conflating the management plane with the data plane.
Multiple SAs mapping to the same participant context with distinct scopes is
an intended design feature that enables fine-grained capability partitioning
within a shared logical identity. It is well-suited to environments where:
- K8s is the authoritative identity provider
- A small number of trusted orchestrator SAs administer the mapping store
- Downstream services validate `aud`, log `act.sub`, and use short-TTL tokens
- SAs sharing a participant context hold distinct, non-overlapping scope sets

The model becomes insecure when:
- Orchestrators over-provision scopes, allowing a compromised SA access beyond
  its operational need
- Token TTLs are long (default 3600s makes revocation slow)
- Scope mappings are treated as real-time authorization rather than
  slowly-changing declarations
- Orchestrator SA credentials are not treated as CA-equivalent high-value secrets
- Downstream services perform loose JWT validation

The highest structural risk is **T1 (orchestrator SA compromise)**. Structured
audit logging is in place, making compromise detectable if logs are forwarded to
an external aggregator and `pgaudit` is enabled on the Postgres backend. The
remaining gap (T8) is log durability: application logs are only as
tamper-resistant as the aggregation infrastructure they are forwarded to.
