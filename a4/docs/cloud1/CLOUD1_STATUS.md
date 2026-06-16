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

## Open ideas for Pro Round 2 (post-Phase-8) — investigate, do NOT ask Pro yet

Pair these two together when (and only when) Phase-8 + the ACCEPTED-audit (H2) data are in. Do not spend
Pro's bandwidth on them before that data exists.

### Idea A — Mutation-catalog expansion (carried over from ProG_Report_1)
Revisit after results, with the new caveat below.

### Idea B — Constraint-layer-isolating mutation variants (`GLOBAL_TRIGGER=OFF` / `LOCAL_TRIGGER=OFF`)
**Premise (to validate, not assume):** local constraints vastly outnumber global, and *specific* quantities
(e.g. register/memory values) are not pinned by any local constraint — the global permutation is the only
backstop (cf. Arguzz reg-mutations: `0 local / 1 global`). This is "local has gaps in specific spots", NOT
"local is globally less sound"; constraint *count* ≠ soundness.

**Proposal:** add, for the **value-on-cell** A4 mutations only (`COMP_OUT_MOD`, `LOAD_VAL_MOD`,
`STORE_OUT_MOD`, `MEM_VAL_MOD`, `PRE_EXEC_REG_MOD`), a `GLOBAL_TRIGGER=OFF` variant that co-mutates the
*entire* memory/register permutation chain for the targeted cell (the write + its `(prev_cycle, prev_word)`
links + all subsequent reads until the next write) so the global grand-product stays balanced — leaving only
**local** algebraic checks able to fire. Goal: probe the *local* constraint space for under-constraints
without the global backstop masking them. A `LOCAL_TRIGGER=OFF` dual (only global fires) is the inverse.

**Critical caveats (must frame the eventual Pro question around these):**
1. **Three mechanisms, not two:** local algebraic, global permutation (mem/reg/cycle), AND boundary/IO
   (public output digest, termination). A real soundness break must pass all three. Co-mutating the
   permutation does NOT fix the output digest — if the value reaches output, the boundary check rejects.
2. **Not universal:** feasible for value-on-cell kinds; **not** for structural kinds (`INSTR_TYPE_MOD` has no
   memory cell; `INSTR_WORD_MOD` fetch-word co-mutation means rewriting the program-image read chain). Do not
   promise an all-mutations toggle.
3. **Collapse risk:** co-mutate the permutation bookkeeping ONLY. Propagate too far (full re-execution) and
   you just get a valid alternative trace → `ACCEPTED` → zero signal.
4. **"More efficient search" is a hypothesis:** it improves *localization* (a pass cleanly implies a local
   gap) and removes the global mask, but whether it finds *more* bugs depends on locally-free yet
   output-affecting cells existing — exactly what the H2 audit cases will tell us first.

**Dependency:** the ACCEPTED-audit H2 results (`thesis_side_experiments/full_sweep/AUDIT_ACCEPTED_PLAN.md`)
are the direct empirical motivation — they show whether "local didn't pin it / global caught it" cells exist
on a real guest. Decide on Idea B after reviewing them.
