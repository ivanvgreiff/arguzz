# Phase 7d Inc 3d Phase B2 (B4) — Composer POS handback

**Date**: 2026-06-12  
**Owner**: Composer → Opus  
**Host SHA**: `625e722e201a85fead62cef993fe4ec9399a1aface99c5967256bec29412b515`  
**Git**: `4112808` (`B4 memory fingerprint patch + POS plumbing`)  
**Bundle**: `~/INC3D_B2_BUNDLE.tar.gz` on coinbase  
**Calendar**: entry 1726 (same 4-node reservation as Inc 3c/3d)

---

## Status: COMPLETE

| Step | Result | Wall time |
|------|--------|-----------|
| Bundle build + upload | **DONE** | ~2 min |
| `run_inc3d_phase_b2.sh` SPREAD dispatch | **SUCCESS** 10/10 runs | ~25 min |
| `INC3D_PASS=b2 collect_inc3d_results.sh` | **10 DBs + 10 logs** | ~6 min |

No dispatch anomalies (no SIGSEGV, no calendar miss).

---

## Artifacts

**Local** (for Opus analysis):

```
a4/audits/audit_output/inc3d/b2/
  pos_inc3d_phase_b2_zoned_seed*_n50_*.db   (10)
  pos_inc3d_phase_b2_zoned_seed*_n50_*.log  (10, ~35 MB each)
  b2_handback_summary.json
```

**Remote POS**: `/srv/testbed/results/ivgreiff/a4/pos_inc3d_phase_b2/`

**Coinbase dispatch log**: `~/inc3d_b2_dispatch.log`

---

## B4 instrumentation sanity

| Check | Result |
|-------|--------|
| `A4_MEM_FINGERPRINT=1` in launcher | Present in logs |
| `<a4_mem_total_hash>` per mutation | **49** (most nodes) or **50** (opulous) per run |
| `<a4_mem_cycle_hash cycle=…>` lines | Present (~35 MB logs — large, as expected) |
| Executor passthrough | Bundle verified (`A4_MEM_FINGERPRINT` in `executor.py`) |
| Verbose / B2 trace | **Off** (by design — already captured in B Pass 1) |

---

## Reward diffs (intra-pair A vs B)

| Pair | Node | Racy rows | ΔT flips | Mutation IDs | Kind |
|------|------|-----------|----------|--------------|------|
| α (octoa) | octorand | 0 | 0 | — | — |
| β (octob) | octorand | 0 | 0 | — | — |
| opulous | opulous | **1** | **1** | **29** | `INSTR_WORD_MOD_SUR` step=3718 |
| meld | meld | 0 | 0 | — | — |
| flareCtrl | flare | **2** | **1** | **4** (ΔT), **20** (reward-only) | `PRE_EXEC_REG_MOD` / `INSTR_WORD_MOD_SUR` |

**Octorand**: 0/100 reward diffs this run (race intermittent; see Inc 3c/3d B).

---

## Memory fingerprint — preliminary Composer read (Opus to finalize)

Composer ran a fast paired diff on `<a4_mem_total_hash>` / `<a4_mem_cycle_hash>` tags (`b2_handback_summary.json`).

### Observations

1. **Every paired comparison** shows `total_hash` mismatch on **all** mutation blocks (49–50 per pair), not only racy mutations.
2. **`first_divergent_cycle` is always `33491`** across all pairs and all mutation indices sampled (count_a=count_b=8 at that cycle).
3. First-mutation sanity check:
   - `flareCtrlA` vs `flareCtrlB` first `total_hash`: **differ** (expected identical if flare is deterministic and fingerprint is stable).
   - `octoaA` vs `octoaB` first `total_hash`: **differ**.

### Interpretation (provisional — Opus adjudicates)

This pattern suggests **systematic A-vs-B divergence** at cycle 33491 on every mutation, not a localized race spike at the Inc 3c `inst_p2.zir:291` mutation alone. Possible causes Opus should check:

- Memory-record `count` field or record set not stable across paired runs with same seed
- Cycle 33491 is a common teardown/accum bucket that varies run-to-run
- `g_a4_memory_records` scope / clearing between mutations
- FNV-XOR fingerprint sensitive to record ordering despite design intent

### Racy mutations ↔ mem divergence (correlation attempt)

| Pair | Racy mut | mem block index (guess) | first_divergent_cycle |
|------|----------|-------------------------|------------------------|
| opulous | 29 | 27 | 33491 |
| flareCtrl | 4 (ΔT) | 2 | 33491 |
| flareCtrl | 20 (reward-only) | 18 | 33491 |

Block index ≈ `mutation_id - 2` (same 49-block / 50-mut pattern as Inc 3c verbose).

---

## Cross-reference with prior passes

| Pass | Host SHA | Octorand racy | flare racy | Key context |
|------|----------|---------------|------------|-------------|
| Inc 3c δ | `c2e77443…` | α mut 27 | mut 21, 39 | `inst_p2.zir:291` verbose cluster |
| Inc 3d B P1 | `632094ef…` | 0 | mut 30 | B3+verbose aligned mut 30 |
| Inc 3d B P2 | `632094ef…` | 0 | 0 / meld mut 5 | B3 only |
| **Inc 3d B2 B4** | `625e722e…` | 0 | mut 4, 20 | mem fingerprint logs |

Race is **low-rate and pair-dependent**; B2 captured fresh flare/opulous hits but not octorand.

---

## Handback checklist for Opus

- [ ] Diff per-cycle memory fingerprints for all 5 pairs (full logs in `b2/`)
- [ ] Identify **first** divergent cycle **accounting for** systematic 33491 pattern
- [ ] Cross-reference racy `mutation_id` with B Pass 1 `<a4_ftw>` traces where available
- [ ] Write final B7 closure report / localize bug to function/file
- [ ] Decide if B4 fingerprint needs refinement (record filter, cycle scope, clearing)

---

## Files index

| Path | Purpose |
|------|---------|
| `a4/audits/audit_output/inc3d/b2/*.log` | Raw B4 fingerprint emission |
| `a4/audits/audit_output/inc3d/b2/*.db` | Reward diffs |
| `a4/audits/audit_output/inc3d/b2/b2_handback_summary.json` | Machine-readable paired summary |
| `a4/docs/cloud1/composer/PHASE_7D_INC3D_B2_COMPOSER_REPORT.md` | This document |
