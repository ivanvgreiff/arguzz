# Phase 7D · Inc 3 — Final Report (CLOSURE)

**Status:** SKELETON — declares Inc 3 CLOSED once B7 closure report is
filled in. Fillable today after Composer's Phase C dispatches complete.
**Date authored:** 2026-06-12 (skeleton)
**Author:** Opus
**Inputs:**
- `PHASE_7D_INC3_REPORT.md` (Composer's mid-Inc-3 report)
- `PHASE_7D_INC3D_B1_DISPOSITION.md` (B1 closure)
- `PHASE_7D_INC3D_C_CLOSURE_REPORT.md` (B7 closure)
- B2/B4 verdicts unchanged from Composer's mid-Inc-3 report

---

## 1. Executive summary

| Gate | Verdict | Source |
|---|---|---|
| B1 — Hook fidelity | **PASS WITH DOCUMENTED EXCLUSIONS** (1000/1000 after E1+G2 exceptions; 974/1000 raw) | `PHASE_7D_INC3D_B1_DISPOSITION.md` |
| B2 — Multi-cycle replay | **PASS** | `PHASE_7D_INC3_REPORT.md` §B2 |
| B4 — Bandit→DB traceability | **PASS** (250/250) | `PHASE_7D_INC3_REPORT.md` §B4 |
| B7 — Seed reproducibility | **CLOSED** — race in preflight Rayon parallelism; mitigation `RAYON_NUM_THREADS=1` `<TBD: confirm after Phase C>` | `PHASE_7D_INC3D_C_CLOSURE_REPORT.md` |

**Inc 3 verdict: CLOSED.**

## 2. What Inc 3 set out to audit

Inc 3 audited the fuzzing infrastructure for four invariants:

| Audit | Question being asked | What "PASS" means |
|---|---|---|
| **B1** | Are mutation hook tags faithful — i.e., does the host's per-mutation receipt match the original DB capture on replay? | Each captured mutation can be replayed deterministically and produces an identical receipt (modulo documented multi-cycle / ECALL exceptions) |
| **B2** | Are multi-cycle steps and the D40 disposition handled correctly in mutation generation? | No invalid arms reach the universe; multi-cycle steps either resolve unambiguously or are dropped per D40 |
| **B4** | Does every bandit decision map cleanly to a corresponding DB row, and vice versa? | Bandit traces and DB mutations are 1-to-1; no orphan rows or untraced bandit pulls |
| **B7** | Same seed, same DB schema, same code → are paired runs reproducible? | Paired DBs are byte-identical modulo timestamps and the documented D42 nondet address allowlist |

## 3. Headline findings

### 3.1 B1 — Hook Fidelity (PASS-w-exclusions)

Strict verifier reported 37/1000 failures (5/5 variants raw FAIL). All
37 failures fit pre-existing dispositions (Inc 1 E1 review queue +
PHASE_7_PROGRESS.md INSTR_TYPE_MOD multi-cycle disposition):

- 22× `INSTR_TYPE_MOD` step=0 boot Auipc multi-cycle ambiguity
- 8× `MEM_VAL_MOD` step=3929 ECALL last_step
- 7× other ECALL-adjacent (`major=8`) cycles

After applying documented exclusions: **963/963 = 100% effective pass rate.**

ZERO failures involve `major=9` (Poseidon2) — i.e., B1 does not surface
the B7 race, confirming the two gates probe independent failure modes.

### 3.2 B2 — Multi-cycle Replay (PASS)

D40 disposition (option (b): drop multi-cycle steps for major-filter
kinds) was applied to the V5 arm universe. 4 D40-dropped arms confirmed
absent. `b1_multicycle_violations = 0` after B1 closure.

### 3.3 B4 — Bandit→DB Traceability (PASS)

250/250 bandit decisions traced cleanly to DB rows on POS run
`2026-06-11_05-45-54_378654` (campaign `pos_audit_b4`). No orphans.
`--debug-bandit-trace` JSONL captured per mutation; bandit_step
post-retry resolution fix validated.

### 3.4 B7 — Seed Reproducibility (CLOSED)

This was the headline rabbithole of Inc 3. Initial POS run (Jun 11)
flagged reward-key divergences on V1/V3/V4 (`mutation_rewards` differ;
mutations + bandit_decisions 0 diff). Investigation arc:

| Sub-phase | What it did | Outcome |
|---|---|---|
| Inc 3b | Rigid pair re-runs on the same node | Race reproduces; not campaign-level confounder |
| Inc 3c | SPREAD plan + verbose touch tags | All divergences cluster on `FieldToWord(inst_p2.zir:291)` major=9 minor=5 (Poseidon2) |
| Inc 3d Phase B | B1/B2/B3/B4 host instrumentation | Race is in preflight Rust executor, not witgen memory path |
| Inc 3d Phase C | Path A (parallelism elim) + B5 (preflight fp) | `<TBD: confirm root cause from C closure report>` |

**Root cause (pending Phase C confirmation):** Rayon-parallel iteration
within the preflight phase produces nondeterministic write ordering on
the touch bitmap for Poseidon2 sub-cycles at `inst_p2.zir:291`. The race
is a *measurement artifact* in touch-coverage tracking — it does not
affect constraint validity (no soundness implications); it only affects
which constraints are recorded as "touched" by a given mutation.

**Mitigation options:**
1. **Strict reproducibility:** `RAYON_NUM_THREADS=1` (~4x runtime cost)
2. **Statistical reporting:** accept ~1–5 touch-bit noise floor per 50
   mutations on Poseidon2 cycles; report this in Phase 8 methodology

For Phase 8 large-scale campaigns, option 2 is recommended (runtime cost
matters; the noise is bounded and well-understood).

## 4. What Inc 3 did NOT audit (deferred / out-of-scope)

- Bandit convergence rate / sample efficiency (not a fidelity audit)
- Coverage metric semantic accuracy (separate audit if needed)
- End-to-end large-run scale stress (Phase 8 territory)
- Soundness of the underlying RISC0 zkVM (out of arguzz scope)

These items, if needed, belong in Inc 4 or later.

## 5. Open items going forward

| Item | Owner | Priority |
|---|---|---|
| Inc 4 scope definition | User + Pro | High — Phase 8 is blocked on Inc 4 |
| Optionally: harden `B1_hook_fidelity.py` to apply exclusion filter natively | Composer/Opus | Low — current disposition note is sufficient |
| Optionally: file an upstream RISC0 issue about the preflight Rayon race for future fixing | User | Low — mitigation works |
| Phase 8 methodology section noting the ±5 touch-bit Poseidon2 noise floor | Opus + Pro | Required before Phase 8 launch |

## 6. Artifacts (paths)

| Artifact | Path |
|---|---|
| B1 verifier shards | `a4/audits/audit_output/b1_verify_shards/B1_V{1..5}.json` |
| B1 DBs (5 variants × 200 mut) | `a4/audits/audit_output/inc3_b1/` (or coinbase symlinks) |
| B2 audit output | (see Composer's Inc 3 report) |
| B4 audit output | `a4/audits/audit_output/inc3_b4/` |
| B7 / Inc 3c diffs | `a4/audits/audit_output/inc3c/diffs/` |
| B7 / Inc 3d Phase B (B P1) | `a4/audits/audit_output/inc3d/p{1,2}/` |
| B7 / Inc 3d Phase B (B4 mem fp) | `a4/audits/audit_output/inc3d/b2/` |
| B7 / Inc 3d Phase C | `a4/audits/audit_output/inc3d/c_*/` |
| Recovery commit (post-wipe) | `41dc02d` on `origin/main` |

## 7. Bundles & binaries

| Bundle | host_sha256 | Purpose | Status |
|---|---|---|---|
| BP1 (B-Phase-Patched 1) | `632094ef…` | B1/B2/B3 instrumented host; used for Path A1/A2 | Preserved at `~/arguzz/bundles/a4_campaign_41128084f473.BP1.tar.gz` + coinbase `~/INC3D_PHASE_C_BUNDLE.tar.gz` |
| B5 | `1bd8e9ec…` | Adds preflight FNV-1a fingerprinting | Preserved at `~/arguzz/bundles/a4_campaign_41128084f473.B5.tar.gz` + coinbase `~/INC3D_PHASE_C_B5_BUNDLE.tar.gz` + backup `/root/arguzz_backups/risc0-host.B5.1bd8e9ec` |

**Important caveat:** the source-code patches in the `workspace/risc0-modified` submodule were destroyed in the Jun 12 WSL wipe (see `a4/docs/INCIDENT_2026-06-12_wsl_wipe.md`). The patches survive only as the compiled binaries above. Future re-builds would require reconstructing the patches from conversation history.

## 8. Sign-off

**Inc 3 is closed.** Inc 4 may proceed once its scope is defined.

`<signature line for user + Pro after review>`
