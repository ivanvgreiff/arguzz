# Phase 7 — Hook 3 / compressed_global diagnostic

**Date**: 2026-06-09  
**Per**: `PHASE_7_INVESTIGATION_REPORT.md` §1.5 (Opus must-do #2)

## 1. Campaign log grep (all 5 × 7b variants)

```bash
rg -c '<a4_family_residue' a4/runs/pos_smoke_7b/*/flare/*.log   # → 0 each
rg -c '<a4_family_detail'  a4/runs/pos_smoke_7b/*/flare/*.log   # → 0 each
```

**Interpretation**: Campaign `.log` files contain Python fuzzer output only — **host stdout is not tee'd into the log**. Zero matches are **not** evidence that Hook 3 env vars are missing.

## 2. One-shot host run (`run_a4_mutation`)

Single `LOAD_VAL_MOD` sample from V5 DB:

| Tag | Count |
|-----|-------|
| `<a4_family_residue>` | 4 |
| `<a4_family_detail>` | 1 |
| `<a4_load_val_mod>` | 1 |

Parsed `family_residues` includes `memory` with `nonzero: true`. **Hook 3 plumbing (env → host → parser) is OK.**

## 3. DB state (V5 `cTS_semantic_v2`)

| Table | Rows | Notes |
|-------|------|-------|
| `hook3_raw` | 144 | `family_residues` + `family_details` populated |
| `hook3_raw.compressed_ctx_json` | NULL all | extractor returned empty set |
| `compressed_global_coverage` | **0** | no first-hit rows written |
| `global_failures` | 291 | constraint path healthy |

## 4. Root cause (branch 1 vs 2)

Opus §1.5 branches:

1. **Plumbing** — ruled out (§2–3).
2. **Empty signal** — ruled out (`nonzero: true` memory residues in `hook3_raw`).

**Actual bug**: `extract_compressed_global_contexts` expected `broken_addrs` as bare integers; production Hook 3 emits **rich dicts** (`addr`, `byte_addr`, `type`, …). Every dict failed `int(raw_addr)` and was skipped → zero compressed contexts.

**Fix**: `a4/standalone/compressed_global_extractor.py` — `_coerce_broken_addr()` / `_coerce_broken_index()` accept dict entries.

## 5. Gate reclassification

- `check_smoke_db.py` `compressed_global_coverage >= 1` is a **valid system gate** once the extractor fix ships; it was failing due to schema mismatch, not guest selection.
- Re-verify on next 7b run or offline replay of `hook3_raw` → `compressed_global_coverage` backfill (optional).

## 6. Deferred

`bandit_skip_log` table → Phase 8 prep (per Opus).
