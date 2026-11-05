# UTOP14 — Project Roadmap and Status

Last updated: M14.3.22 (2026-11-06)

This document is the durable status record for the UTOP14 development effort.
It separates **development completion** from **production readiness**: a phase
marked COMPLETE means the development work and its local verification are
finished, not that the project is approved or safe to deploy.

Every future milestone must update the phase status, the checkpoint evidence,
and the current-status summary at the bottom of this file.

---

## How to read this document

- **Phases** are high-level workstreams, numbered 1–6.
- **Milestones** (M13, M14.x, M14.3.x) are the individual implementation
  increments inside a phase.
- **Status** is one of: `NOT STARTED`, `IN PROGRESS`, `BLOCKED`, `COMPLETE`.
- A phase may only move to `COMPLETE` when its checkpoint completion criteria
  and required evidence are both satisfied.
- An **accepted** finding stays listed as an open item with its acceptance
  rationale and the decision checkpoint that owns it. Acceptance is not
  completion.

---

## Phase 1 — Foundation and administration

**Status: COMPLETE**

### Phase objective

Deliver the application foundation: Flask application factory, blueprints,
configuration separation, PostgreSQL persistence with Alembic migrations,
customer authentication, product catalogue with variants and stock, and the
administrative product/inventory workflows.

### Included milestones / workstreams

- Application factory, blueprints, configuration and environment handling.
- SQLAlchemy models, migrations, and the seeded catalogue.
- Registration, login, session handling, and role separation.
- Product, category, variant, size, colour, image, and stock administration.
- Cart and checkout foundations (continued in later phases).
- Dark premium streetwear design system and responsive layouts.

### Checkpoint completion criteria

- Migrations apply cleanly from an empty database to a single head.
- Registration, login, and admin CRUD covered by tests.
- Configuration never commits secrets; `.env` is ignored.

### Dependencies and known blockers

None outstanding.

### Evidence required to mark complete

Satisfied: full test suite green, single Alembic head, no secrets in version
control.

---

## Phase 2 — Security events and admin viewer

**Status: COMPLETE**

### Phase objective

Add the permanent append-only audit log and the security-event pipeline, plus
the administrator viewer that exposes security events without granting the
application role write access to protected records.

### Included milestones / workstreams

- M13: permanent append-only audit log with transaction atomicity and
  trigger-enforced immutability.
- M14.1: security-event persistence and sequence privileges.
- M14.2: admin security-event viewer and its access controls.

### Checkpoint completion criteria

- Audit rows cannot be updated or deleted by the application role, including
  via trigger disabling or ownership changes.
- Security events persist atomically with their business transaction.
- The viewer is restricted to the administrative role and cannot be reached by
  a customer session.
- The ownership model (schema owner / app / retention roles) is enforced.

### Dependencies and known blockers

- The viewer has a known exposure: **M14.2 F-02** (query string, access log,
  redirect, and referrer leakage). Tracked in Phase 5.

### Evidence required to mark complete

Satisfied: append-only and viewer tests green; ownership and privilege
verification scripts pass on a disposable cluster.

---

## Phase 3 — Authentication protection and retention hardening

**Status: IN PROGRESS**

### Phase objective

Harden authentication abuse controls and make security-event retention
operationally safe: rate limiting, retention holds, a SECURITY DEFINER pruning
function, strict ownership and privilege boundaries, and a verification script
that can be trusted as a production gate.

### Included milestones / workstreams

- Login rate limiting, identifier/scope handling, and HTTP 429 behaviour.
- Retention holds, concurrency locking, and the retention run log.
- SECURITY DEFINER retention function and runner-only pruning.
- M14.3.1 → M14.3.16: ownership model, ACL matrices, parameter ACLs, persistent
  GUC allowlists, cluster-level checks.
- M14.3.17: cross-database managed-role GUC inventory failure (HIGH, fixed in
  M14.3.18).
- M14.3.18: cross-database and cluster configuration hardening.
- M14.3.19: independent review of M14.3.18 — found a temporary-catalog
  false-PASS (HIGH), a provisioning qualification gap (MEDIUM), and an
  overstated documentation claim (LOW).
- M14.3.20: full `pg_catalog` qualification of the verifier, provisioner, and
  ownership template.
- M14.3.21: independent review of M14.3.20 — **APPROVED WITH CONDITIONS**
  (R1 `array_append`, R2 `search_path` pinning, R3 test assertions).
- **M14.3.22 (current checkpoint):** closes R1, R2, R3, adds a catalog-derived
  static qualification test, and creates this roadmap.

### Checkpoint completion criteria

- Every security script resolves catalog objects explicitly and pins
  `search_path`.
- A catalog-derived static test proves no unqualified catalog reference can be
  introduced silently.
- Temporary-catalog and hostile-search-path regressions fail closed with the
  specific expected diagnostic.
- Cross-database and cluster-level configuration checks are fail-closed.
- An independent review of M14.3.22 returns APPROVED (or APPROVED WITH
  CONDITIONS with no open security conditions).

### Dependencies and known blockers

- Open until an independent review of M14.3.22 completes.
- Accepted design decisions that remain in force:
  - The schema owner may hold `search_path` because it is the trusted DDL
    boundary and already owns the schema and objects; parameter ACLs remain
    default-deny for it.
  - The DBA / schema-owner trust boundary is accepted (see Phase 5).
- Known non-blocking items carried into Phase 5 (below).

### Evidence required to mark complete

- M14.3.22 local commit with passing quality gates.
- A separate read-only independent review approving M14.3.22.
- Documented evidence that M14319-01, M14319-02, and M14319-03 are closed.

---

## Phase 4 — Independent approval and M14.3 integration

**Status: NOT STARTED**

### Phase objective

Complete the independent security approval for the M14.3 security work and
integrate the approved branch, without deploying.

### Included milestones / workstreams

- Independent read-only review of the final M14.3 security state.
- Closure of any remaining review findings.
- Branch integration (merge) after approval.
- PR #14 review and update.
- Release notes and security changelog for M14.3.

### Checkpoint completion criteria

- Independent review verdict APPROVED for the final M14.3 commit.
- No open HIGH or MEDIUM findings.
- PR #14 approved and merged by the project owner.
- No production deployment performed as part of this phase.

### Dependencies and known blockers

- Depends on Phase 3 completion.
- Requires a decision from the project owner on the accepted DBA/schema-owner
  trust boundary.

### Evidence required to mark complete

- Review report with verdict and commit SHA.
- Merge commit on the main branch.
- Updated PR record.

---

## Phase 5 — Remaining security and functional backlog

**Status: NOT STARTED**

### Phase objective

Close or formally accept the remaining security and functional gaps that are
outside the M14.3 hardening scope.

### Included milestones / workstreams

The following items are known, open, and **not fixed**. None may be marked
complete without its own milestone and evidence.

| ID | Item | Current state |
|---|---|---|
| B-01 | M14.2 F-02: query-string, access-log, redirect, and referrer exposure | Open |
| B-02 | Targeted login denial-of-service (identifier bucket) | Open |
| B-03 | Application clock-skew considerations | Open |
| B-04 | Retention hold extension and metadata mutation boundary (RR-03) | Open |
| B-05 | Retention run-log spoofing boundary (RR-04) | Open |
| B-06 | Retention scheduler, rate-limit TTL cleanup, run-log cleanup | Open |
| B-07 | Runner credentials, monitoring, backup/restore, operational runbook | Open |
| B-08 | Privacy / data-classification sign-off | Open |
| B-09 | App `DELETE` privilege on `auth_rate_limits` | **Accepted risk** |
| B-10 | DBA / schema-owner trust boundary | **Accepted boundary** |
| B-11 | Extension-owned objects outside the application ACL matrix | **Accepted exclusion** |
| B-12 | Connection-pool recycling after provisioning | Documented operational step |
| B-13 | Cluster-level configuration invisible to PostgreSQL catalogs | DBA audit procedure |

### Acceptance rationale (accepted items only)

- **B-09 — App `DELETE` on `auth_rate_limits`.** Accepted because the
  application must remove expired rate-limit buckets to keep the table bounded,
  and the table contains no audit-grade data. Decision checkpoint: Phase 5
  review; revisit if rate-limit history becomes an investigation requirement.
- **B-10 — DBA / schema-owner trust boundary.** Accepted as an infrastructure
  trust boundary: an operator with schema-owner or superuser rights can already
  change the data model, so the verifier's guarantees are explicitly scoped to
  the application role. Decision checkpoint: Phase 4 owner sign-off.
- **B-11 — Extension-owned objects.** Accepted exclusion: extension-managed
  objects are outside the application ACL matrix and are inventoried separately.
  Decision checkpoint: Phase 5 review.
- **B-12 — Connection-pool recycling.** Documented operational step: pooled
  connections keep their old `search_path` until they reconnect. Decision
  checkpoint: deployment runbook (deferred, see below).
- **B-13 — Cluster configuration invisible to catalogs.** Accepted operational
  control: settings not visible through `pg_settings`/`pg_file_settings` require
  the documented DBA audit procedure. Decision checkpoint: Phase 6 acceptance.

### Checkpoint completion criteria

- Every B-item is either fixed with evidence or accepted with a written
  rationale and an owner decision recorded in this file.
- No item is silently dropped or merged into "COMPLETE".

### Dependencies and known blockers

- B-01 and B-08 require product/security decisions outside engineering.
- B-07 requires infrastructure work that is deferred (see below).

### Evidence required to mark complete

- Per-item milestone records, tests, or signed acceptance notes.

---

## Phase 6 — Final development acceptance

**Status: NOT STARTED**

### Phase objective

Declare development complete: all development phases closed, documentation
consistent, and the repository in a state that is ready for a separate
production-readiness effort.

### Included milestones / workstreams

- Final documentation consistency pass (README, roadmap, runbooks).
- Final quality-gate run on the accepted commit.
- Development acceptance sign-off.
- Handover of the deferred production items to the operations stream.

### Checkpoint completion criteria

- All previous phases COMPLETE or their accepted items explicitly recorded.
- Full test suite, lint, dependency check, and migration cycle green on the
  accepted commit.
- Written development-acceptance decision.

### Dependencies and known blockers

- Depends on Phases 3, 4, and 5.
- Production readiness is explicitly out of scope (see below).

### Evidence required to mark complete

- Signed development-acceptance record referencing the final commit SHA.

---

## Production Readiness — Deferred

**Production deployment is not authorized as part of development completion.**
The following workstreams are explicitly deferred and are not required to mark
the development phases complete:

- Ubuntu VM provisioning and migration.
- PostgreSQL VM configuration, tuning, and hardening.
- Gunicorn process management and supervision.
- Nginx reverse proxy, TLS termination, and static asset serving.
- Production secrets management and key rotation.
- Backup, restore, and disaster-recovery procedures.
- Production monitoring, alerting, and log aggregation.
- Deployment automation and release process.
- Production verification, smoke tests, and go-live approval.

These items require a separate production-readiness milestone with its own
evidence and sign-off. Nothing in this roadmap authorizes a deployment.

---

## Current status summary

| Item | Value |
|---|---|
| Current phase | Phase 3 — Authentication protection and retention hardening (`IN PROGRESS`) |
| Current milestone | M14.3.22 — Final catalog qualification remediation and roadmap |
| Last completed independent review | M14.3.21 (verdict: APPROVED WITH CONDITIONS) |
| Next checkpoint | Independent review of M14.3.22 (M14.3.23) |
| Remaining high-level phases | 4 (Phase 3 completion, then Phases 4, 5, 6) |
| Outstanding blockers | B-01 … B-13 (Phase 5), plus Phase 3 review completion |
| Development complete | **NO** |
| Production deployment authorized | **NO** |

### Milestone history (most recent first)

| Milestone | Outcome |
|---|---|
| M14.3.22 | Closes M14.3.21 R1/R2/R3; catalog-derived qualification test; this roadmap |
| M14.3.21 | Independent review of M14.3.20: APPROVED WITH CONDITIONS |
| M14.3.20 | Full `pg_catalog` qualification of verifier, provisioner, template |
| M14.3.19 | Independent review of M14.3.18: REJECTED (temp-catalog false PASS) |
| M14.3.18 | Cross-database and cluster configuration hardening |
| M14.3.17 | Cross-database managed-role GUC failure discovered |
| M14.3.16 | Parameter ACLs and persistent GUC allowlists |
| M13 / M14.1 / M14.2 | Audit log, security events, admin viewer |
