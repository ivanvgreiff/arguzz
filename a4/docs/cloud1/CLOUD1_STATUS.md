# Cloud1 — Live Status Tracker

**Source plan**: `CLOUD1_IMPLEMENTATION_PLAN.md`
**Last updated**: 2026-06-08 (Phase 0 in progress)

## Phase status

| phase | name | status | notes |
|---|---|---|---|
| 0 | Setup & Diagnostic Freeze | ✅ DONE (2026-06-08) | 104 tests pass; no deviations |
| 1 | Schema & Data Model | ✅ DONE (2026-06-08) | 25 new + 132 existing tests pass; 2 cosmetic table-name deviations recorded |
| 2 | Semantic-Zone Step Sampler | ⚪ PENDING | needs Phase 1 complete (now ready) |

| 3 | Compressed Global Context | ⚪ PENDING | needs phase 1 complete |
| 4 | Reward Redesign | ⚪ PENDING | needs phase 1 complete |
| 5 | Constrained TS Bandit | ⚪ PENDING | needs phases 2, 3, 4 complete |
| 6 | Extended Logging | ⚪ PENDING | needs phases 1-5 complete |
| 7 | Local Smoke Tests | ⚪ PENDING | needs phases 0-6 complete |
| 8 | IV.POS.7 Cloud Campaign | 🚫 BLOCKED | Phase 7b uncovered TWO bandit/universe bugs that would cause V5 to produce ≈144 success / ≈5856 skip at N=6000 (see `phases/PHASE_7_INVESTIGATION_REPORT.md` §1.4 — Bug A: phantom arms in universe builder; Bug B: skips don't increment pulls). Must fix both before Phase 8. + POS calendar slots. |
| 9 | Analysis & Report for Pro Round 2 | ⚪ PENDING | needs phase 8 complete |

## Master plan status

🛑 **PAUSED** — resumed only after Pro Round 2 reviews IV.POS.7 results and approves.

## Decisions

All 12 design decisions LOCKED on 2026-06-08. See `CLOUD1_DECISIONS_FOR_PRO_R2.md` for the full record.

## Active risks

| risk | mitigation |
|---|---|
| Zone classifier mis-tags ECALL/MRET-adjacent cycles | Phase 2 has explicit verification step against `InspectionData` |
| Address region map (Phase 3) wrong for sha2-host | Pre-Phase-8 verification on IV.POS.5 data |
| `ConstrainedTSScheduler` floor logic edge cases | Phase 5 unit tests with synthetic reward |
| POS reservation lapses during IV.POS.7 | Continuous reservation pattern from IV.POS.5 (`§40` of POS_PLAYBOOK) |
| New tables blow up DB size | Phase 6 exit criteria: ≤3× legacy DB size for same N |
