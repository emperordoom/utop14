# UTOP14 — Project Roadmap and Status

Last updated: Phase 4 / M14.3 formally CLOSED (`COMPLETE`) following Project Owner decision and PR #17 (`da869008feb177d88835ee54eac4c0ca4b37158c`) integration (2026-11-21)

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

**Status: COMPLETE**

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
- **M14.3.22:** closes R1, R2, R3, adds a catalog-derived
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

- Nothing blocks Phase 3 closure.
- Accepted design decisions that remain in force:
  - The schema owner may hold `search_path` because it is the trusted DDL
    boundary and already owns the schema and objects; parameter ACLs remain
    default-deny for it.
  - The DBA / schema-owner trust boundary is accepted (see Phase 5).
- The production backlog in Phase 5 is **not** resolved by Phase 3 completion.

### Closure record (M14.3.24)

Phase 3 is COMPLETE based on the M14.3.23 independent review.

| Evidence | Result |
|---|---|
| M14.3.1 PostgreSQL rate-limit foundation | Delivered |
| M14.3.2 login abuse protection | Delivered |
| M14.3.3 retention implementation and review remediation | Delivered |
| M14.3.10–M14.3.20 ownership, ACL, GUC, and catalog hardening | Delivered |
| M14.3.21 independent review | APPROVED WITH CONDITIONS |
| M14.3.22 implementation | COMPLETE |
| M14.3.23 independent review | **APPROVED** |

**Reviewed SHA:** `a8e9a9b6ea251f9bb183e373f218764e68538481`.
The approval applies to this exact commit; any later change to the reviewed
scripts requires a new review.

Completion means the Phase 3 development workstream and its review criteria are
complete. It does **not** mean the Phase 5 production blockers are resolved, and
it does not authorize deployment.

---

## Phase 4 — Independent approval and M14.3 integration

**Status: COMPLETE**

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

- Independent review verdict APPROVED for the M14.3 code commit
  (`a8e9a9b6ea251f9bb183e373f218764e68538481`), with subsequent non-code commits
  (`de32fe1eada8e5d39b8a86846c0fb50472a4e10f` doc-only and
  `d37648b61d0d5053cbd61c0ef4fc172f03d3d937` CI-only) verified via diff review
  and accepted by the Project Owner.
- No open HIGH or MEDIUM findings.
- PR #14 merged and accepted by the Project Owner (historical governance note:
  no formal GitHub review was recorded on PR #14, `reviews: []`).
- Administrative closure documentation integrated into `main` and formal
  Project Owner closure decision recorded.
- No production deployment performed as part of this phase.

### Dependencies and known blockers

- None outstanding for Phase 4 closure (Phase 4 was previously `IN PROGRESS` /
  `PENDING` until administrative closure documentation merged in PR #17 at
  `da869008feb177d88835ee54eac4c0ca4b37158c` and the Project Owner issued formal
  closure approval).
- Phase 3 is COMPLETE based on the M14.3.23 approval of
  `a8e9a9b6ea251f9bb183e373f218764e68538481`.
- PR #14 (`emperordoom/utop14`, `main` ←
  `feature/security-retention-ownership-fix`) is **MERGED** at
  `75af830c8dcc53b42c621a36f3a8e99a64fc4881` (`2026-11-05T20:59:55Z`).
- PR #17 (`emperordoom/utop14`, `main` ← `docs/phase4-m143-closure`, commit
  `76c5c9735589bba007c2f871c1bc9b823e820ad9`) integrated the Phase 4 closure
  documentation into `main` at `da869008feb177d88835ee54eac4c0ca4b37158c`
  (`2026-11-21T10:21:37Z`).
- Phase 4 completion does **not** close Phase 5 backlog items (B-01 through
  B-13), does **not** authorize Phase 5 commencement, and does **not**
  authorize production deployment or production provisioning.

### Integration and administrative closure record

**Final Phase 4 status breakdown (historically `IN PROGRESS` / `PENDING` prior to PR #17 and formal Project Owner closure approval):**

- PR #14: **MERGED** (`75af830c8dcc53b42c621a36f3a8e99a64fc4881`).
- PR #17 (Phase 4 closure documentation): **MERGED** (`da869008feb177d88835ee54eac4c0ca4b37158c`).
- M14.3 code/integration (`d37648b`): **ACCEPTED** by Project Owner.
- B-10: **ACCEPTED** by Project Owner with documented scope.
- M14.3.23 independent review evidence: **ACCEPTED** by Project Owner.
- Phase 4 formal closure: **COMPLETE** (**APPROVE COMPLETE** by Project Owner).
- Production deployment: **NOT AUTHORIZED / NOT PERFORMED** as part of this
  phase.
- Production provisioning: **NOT AUTHORIZED**.
- Phase 5 formal commencement: **NOT STARTED / NOT YET APPROVED**.

**Formal Project Owner decisions:**

- **Independent review evidence decision:**
  `ACCEPT — The durable M14.3.23 APPROVED record in docs/PROJECT_ROADMAP.md is accepted as administrative evidence of the independent review for Phase 4, notwithstanding the absence of a standalone review report committed to the repository. GitHub formal review records remain reviews: [].`
- **Phase 4 closure decision:**
  `APPROVE COMPLETE — Phase 4 / M14.3 is formally approved for closure following the completion and integration of its administrative closure documentation.`

| Evidence | Result |
|---|---|
| Repository & PR | `emperordoom/utop14` — PR #14 (`feat(auth): implement login rate limiting and security event retention`), `main` ← `feature/security-retention-ownership-fix` |
| Approved code SHA (M14.3.23 independent review) | `a8e9a9b6ea251f9bb183e373f218764e68538481` (**APPROVED**) |
| Documentation-only commit (M14.3.24) | `de32fe1eada8e5d39b8a86846c0fb50472a4e10f` (`README.md`, `docs/PROJECT_ROADMAP.md`) |
| CI-only commit / final PR #14 head | `d37648b61d0d5053cbd61c0ef4fc172f03d3d937` (`.github/workflows/ci.yml` only — adds fail-closed disposable PostgreSQL privilege job; zero changes to `app/`, `scripts/`, `migrations/`, or `tests/`) |
| Project Owner decision on `d37648b` | **ACCEPTED** as part of PR #14 integration |
| Project Owner decision on B-10 | **ACCEPTED** with documented scope (see B-10 rationale below) |
| Project Owner decision on M14.3.23 review evidence | **ACCEPTED** (durable roadmap record accepted; GitHub formal reviews remain `reviews: []`) |
| PR #14 CI checks (`d37648b`) | **PASSED** — runs `42106435696` (`pull_request`) and `42106423779` (`push`), covering `Tests and quality gates` and `Disposable PostgreSQL ownership and privilege tests` |
| PR #14 merge commit on `main` | `75af830c8dcc53b42c621a36f3a8e99a64fc4881` (merged `2026-11-05T20:59:55Z`) |
| Post-merge `main` CI (`75af830`) | **SUCCESSFUL** (run `42108528343`) |
| GitHub formal reviews on PR #14 | None recorded (`reviews: []`); preserved as a historical governance fact |
| Closure documentation PR (#17) | **MERGED** (`2026-11-21T10:21:37Z`) — commit `76c5c9735589bba007c2f871c1bc9b823e820ad9`, merge commit `da869008feb177d88835ee54eac4c0ca4b37158c`, CI runs `44893514786` (`pull_request`) & `44893971048` (`push`) **SUCCESSFUL** (GitHub formal reviews: `reviews: []`) |
| Release notes & security changelog | [`docs/M14.3_RELEASE_NOTES.md`](M14.3_RELEASE_NOTES.md), [`docs/M14.3_SECURITY_CHANGELOG.md`](M14.3_SECURITY_CHANGELOG.md) (**INTEGRATED** on `main` via PR #17) |
| Project Owner Phase 4 closure decision | **APPROVE COMPLETE** |

### Evidence required to mark complete

- Review report with verdict and commit SHA — **satisfied** (M14.3.23 independent review APPROVED for `a8e9a9b6ea251f9bb183e373f218764e68538481`; subsequent doc-only `de32fe1eada8e5d39b8a86846c0fb50472a4e10f` and CI-only final PR #14 head `d37648b61d0d5053cbd61c0ef4fc172f03d3d937` verified via diff review and accepted by Project Owner; Project Owner formally **ACCEPTED** the durable M14.3.23 record in `docs/PROJECT_ROADMAP.md` as administrative review evidence, with GitHub formal reviews remaining `reviews: []`).
- Remote PR head equal to the accepted SHA and CI green on that head — **satisfied** (`d37648b61d0d5053cbd61c0ef4fc172f03d3d937`, runs `42106435696` & `42106423779`).
- Merge commit on the `main` branch — **satisfied** (`75af830c8dcc53b42c621a36f3a8e99a64fc4881`, post-merge CI run `42108528343`).
- Closure documentation (`README.md`, `docs/PROJECT_ROADMAP.md`, `docs/M14.3_RELEASE_NOTES.md`, `docs/M14.3_SECURITY_CHANGELOG.md`) integrated into `main` — **satisfied** (PR #17 merged at `da869008feb177d88835ee54eac4c0ca4b37158c`, CI runs `44893514786` & `44893971048` successful).
- Formal Project Owner closure decision — **satisfied** (**APPROVE COMPLETE**).

Completion of Phase 4 means M14.3 approval, integration, and administrative closure records are complete. It does **not** close Phase 5 backlog items (B-01 through B-13), does **not** start Phase 5, and does **not** authorize production provisioning or deployment.

---

## Phase 5 — Remaining security and functional backlog

**Status: NOT STARTED**

### Phase objective

Close or formally accept the remaining security and functional gaps that are
outside the M14.3 hardening scope.

### Included milestones / workstreams

The following items are known, open, and **not fixed**. None may be marked
complete without its own milestone and evidence.

| ID | Item | State | Classification |
|---|---|---|---|
| B-01 | M14.2 F-02: query-string, access-log, redirect, and referrer exposure | Open | Required before development acceptance |
| B-02 | Targeted login denial-of-service (identifier bucket) | Open | Required before development acceptance |
| B-03 | Application clock-skew considerations | Open | Required before development acceptance |
| B-04 | Retention hold extension and metadata mutation boundary (RR-03) | Open | Required before development acceptance |
| B-05 | Retention run-log spoofing boundary (RR-04) | Open | Required before development acceptance |
| B-06 | Retention scheduler; rate-limit TTL and run-log cleanup | Open | Operational prerequisite for production only |
| B-07 | Runner credentials, monitoring, backup/restore, operational runbook | Open | Operational prerequisite for production only |
| B-08 | Privacy / data-classification sign-off | Open | Required before development acceptance |
| B-09 | App `DELETE` privilege on `auth_rate_limits` | **Accepted risk** | Accepted risk requiring explicit documented acceptance |
| B-10 | DBA / schema-owner trust boundary | **Accepted boundary** | Accepted risk requiring explicit documented acceptance |
| B-11 | Extension-owned objects outside the application ACL matrix | **Accepted exclusion** | Accepted risk requiring explicit documented acceptance |
| B-12 | Connection-pool recycling after provisioning | Documented operational step | Operational prerequisite for production only |
| B-13 | Cluster-level configuration invisible to PostgreSQL catalogs | DBA audit procedure | Operational prerequisite for production only |

Classification records where an item must be resolved; it does **not** close the
item. Every row above remains open or accepted, never fixed.

### Subsequent PRs merged on `main` (distinct from Phase 4 / M14.3 and Phase 5 closure)

Merging a pull request into `main` does **not** by itself close Phase 5 backlog
items or start Phase 5 formally. Formal Phase 5 commencement is **NOT YET
APPROVED**, and each backlog item requires its own acceptance-criteria
verification before its state can change:

- **PR #15** (`feature/admin-security-event-filter-state`, head
  `3a4a52948dc1d562588caead3dbd8261b02ec240`) — merged into `main` at
  `661a75a195b161390756e84074a5598fa63eb522` (`2026-11-06T06:00:34Z`),
  post-merge CI run `42171754682` successful. Relevant to **B-01**; does not
  automatically close B-01's acceptance criteria.
- **PR #16** (`feature/retention-time-runlog-integrity`, head
  `64d1510558a3d4629757f30e61eb66c9127e560d`) — merged into `main` at
  `5fac70ee63628da06d4597d9a4ed4708743e6755` (`2026-11-06T08:22:57Z`),
  post-merge CI run `42187271370` successful. Relevant to retention time and
  run-log integrity; does not automatically close Phase 5 acceptance criteria.

**Note on `README.md` status wording:** `README.md` on `main` contains
`remediated` statements reflecting code implemented in subsequent PRs (PR #15
and PR #16). Those statements describe code implementation on `main` only and
do **not** automatically close Phase 5 backlog items B-01, B-03, or B-05 in this
roadmap; formal backlog closure still requires verification and approval under
the Phase 5 process.

**Deferred enhancement:** none recorded at this checkpoint. New candidates must
be added here with an explicit decision before they are treated as deferred.

### Acceptance rationale (accepted items only)

- **B-09 — App `DELETE` on `auth_rate_limits`.** Accepted because the
  application must remove expired rate-limit buckets to keep the table bounded,
  and the table contains no audit-grade data. Decision checkpoint: Phase 5
  review; revisit if rate-limit history becomes an investigation requirement.
- **B-10 — DBA / schema-owner trust boundary.** Project Owner decision:
  `ACCEPT — B-10 is accepted as an infrastructure trust boundary. The verifier's guarantees apply to application and retention roles. DBA/schema-owner authority remains outside that guarantee and must be governed through separate operational controls.`
  Scope limitation at PR #14 (`d37648b61d0d5053cbd61c0ef4fc172f03d3d937` /
  `75af830c8dcc53b42c621a36f3a8e99a64fc4881`): while `README.md` uses the label
  `OPS-01` for the M14.3.3 four-role ownership model (`utop14_schema_owner`,
  `utop14_app`, `utop14_retention_owner`, `utop14_retention_runner`), PR #14
  did **not** implement a `NOLOGIN` schema owner plus a separate
  `utop14_migrator` role (`utop14_schema_owner` remained permitted to be
  `LOGIN` and `SUPERUSER`). Any follow-on migrator-separation workstream
  (`utop14_migrator`, `NOLOGIN` enforcement on `utop14_schema_owner`, `SET ROLE`
  in `migrations/env.py`, and base-role/prestep/rollback scripts) is a separate
  workstream outside PR #14 approval and is not active as part of M14.3;
  acceptance of B-10 does not certify every future DBA control. Decision
  checkpoint: Phase 4 owner sign-off (**ACCEPTED**).
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
| Last completed phase | Phase 4 — Independent approval and M14.3 integration (**COMPLETE** — Project Owner **APPROVE COMPLETE**) |
| PR #14 status | **MERGED** (`75af830c8dcc53b42c621a36f3a8e99a64fc4881`, `2026-11-05T20:59:55Z`) |
| PR #17 status (Phase 4 closure docs) | **MERGED** (`da869008feb177d88835ee54eac4c0ca4b37158c`, `2026-11-21T10:21:37Z`, CI `44893514786` / `44893971048` successful) |
| M14.3 code / integration (`d37648b`) | **ACCEPTED** by Project Owner |
| B-10 trust boundary | **ACCEPTED** by Project Owner with documented scope |
| M14.3.23 review evidence | **ACCEPTED** by Project Owner (durable roadmap record accepted; GitHub formal reviews remain `reviews: []`) |
| Last completed independent review | M14.3.23 (**APPROVED** for `a8e9a9b6ea251f9bb183e373f218764e68538481`), followed by doc-only `de32fe1eada8e5d39b8a86846c0fb50472a4e10f` and diff review + Project Owner acceptance of CI-only `d37648b61d0d5053cbd61c0ef4fc172f03d3d937` (no formal GitHub review recorded, `reviews: []`) |
| Next checkpoint | Project Owner decision on formal Phase 5 commencement (not yet approved) |
| Phase 5 formal commencement | **NOT STARTED / NOT YET APPROVED** |
| Remaining high-level phases | 2 (Phases 5, 6) |
| Outstanding blockers | B-01 … B-13 (Phase 5; PR #15 & PR #16 merged on `main` but do not auto-close Phase 5 criteria) |
| Development complete | **NO** |
| Production provisioning authorized | **NO** |
| Production deployment authorized | **NO** |

### Milestone history (most recent first)

| Milestone | Outcome |
|---|---|
| Phase 4 formal closure | Project Owner issued **ACCEPT** for M14.3.23 durable review evidence and **APPROVE COMPLETE** for Phase 4 / M14.3 following PR #17 (`da869008`); Phase 5 remains `NOT STARTED` and production remains `NOT AUTHORIZED` |
| PR #17 (`da869008`) | Merged `docs/phase4-m143-closure` (`76c5c973`) into `main` (`2026-11-21T10:21:37Z`, CI `44893514786` / `44893971048` successful; `reviews: []`), integrating `docs/M14.3_RELEASE_NOTES.md`, `docs/M14.3_SECURITY_CHANGELOG.md`, and roadmap/README closure records |
| PR #16 (`5fac70ee`) | Merged `feature/retention-time-runlog-integrity` (`64d15105`) into `main` (`2026-11-06T08:22:57Z`, CI `42187271370` successful); relevant to retention time/run-log integrity, does not auto-close Phase 5 criteria |
| PR #15 (`661a75a1`) | Merged `feature/admin-security-event-filter-state` (`3a4a5294`) into `main` (`2026-11-06T06:00:34Z`, CI `42171754682` successful); relevant to B-01, does not auto-close B-01 criteria |
| PR #14 (`75af830c`) | Merged `feature/security-retention-ownership-fix` (`d37648b6`) into `main` (`2026-11-05T20:59:55Z`, CI `42106435696` / `42106423779` / `42108528343` passed; no formal GitHub review recorded) |
| M14.3.24 | Phase 3 closed; Phase 4 started; integration readiness and PR #14 plan recorded (`de32fe1e`) |
| M14.3.23 | Independent review of M14.3.22: APPROVED (`a8e9a9b6`) |
| M14.3.22 | Closes M14.3.21 R1/R2/R3; catalog-derived qualification test; this roadmap |
| M14.3.21 | Independent review of M14.3.20: APPROVED WITH CONDITIONS |
| M14.3.20 | Full `pg_catalog` qualification of verifier, provisioner, template |
| M14.3.19 | Independent review of M14.3.18: REJECTED (temp-catalog false PASS) |
| M14.3.18 | Cross-database and cluster configuration hardening |
| M14.3.17 | Cross-database managed-role GUC failure discovered |
| M14.3.16 | Parameter ACLs and persistent GUC allowlists |
| M13 / M14.1 / M14.2 | Audit log, security events, admin viewer |
