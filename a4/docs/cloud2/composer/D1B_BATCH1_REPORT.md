# D1.B Batch 1 — Composer Report

**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.3.1 (Batch 1) + v0.4 §3.2.5 (Batch 1.6)  
**Scope:** §3.1 tasks 1–5 + §3.2.5 Batch 1.6 extractor fix + replay  
**Branch:** `cloud2` (uncommitted — awaiting Ivan review + D2 ack before squash commit)  
**Date:** 2026-06-08 (Batch 1); 2026-06-17 (Batch 1.6 amendment)

---

## 1. Spec review verdict

**Greenlight confirmed.** v0.3.1 resolves the stale-string issues flagged in the pre-implementation review (`parse_memory_byte_addr`, `d1e_handoff_CGC_saturation.md`, first-hit semantics in §1.3/§3.3). Batch 1 scope is well-bounded: analysis-only, no `compressed_global_extractor.py` edits, hybrid counting rule (§1.5) is load-bearing and implemented.

**No blocking disagreements.** One implementation bug found during audit (wrong D1.A DB path — fixed; see §6).

---

## 2. Data audit summary (task 1)

**Output:** `a4/runs/iv_pos_8/d1b/d1b_batch1_data_audit.csv` — **30 rows** (10 V1 + 10 V5 + 5 D1.A decayexp + 5 D1.A decayepoch).

| Check | Result |
|---|---|
| `memory_parse_none_count` (malformed dict-strings) | **0** across all 30 DBs |
| `ctx_json` well-formed JSON | **30/30** (`ctx_json_all_well_formed=True`) |
| `ctx_json` malformed memory rows | **0** |
| Memory `ctx_json` keyset (observed) | Uniform: `{address_bucket, address_region, cycle_phase, family, txn_role}` |
| CGC row count range | 137–197 |
| `global_failures` present | All 30 DBs non-zero |

**`address_region` distribution (memory-family CGC rows only):** Predominantly `user` + `zero_page` only (e.g. V1 seed1234: `user=36, zero_page=33`). **Post-Batch 1.6:** this collapse is now understood as the `_coerce_broken_addr` labeling bug, not genuine geography — see §9.

**`byte_addr` stats:** Parsed via `parse_memory_byte_addr()` (not `int(address)`). Min/max/mean populated per DB; no parse failures.

**D1.A discovery:** Flat files under `a4/runs/iv_pos_8/d1a/dbs/` — not covered by `discover.py` default root. Custom `discover_d1a_dbs()` in `build_batch1_audit.py` matches on `cTS_semantic_v2_decayexp` / `cTS_semantic_v2_decayepoch` + `seed(\d+)`.

---

## 3. Smoke validation (task 5)

**Output:** `a4/runs/iv_pos_8/d1b/d1b_batch1_smoke.txt`

```
R2-V5 pos_iv_pos_7_ts_b1_cTS_semantic_v2_seed1234_n6000.db: production=183 region_only=96 log4_explicit=110 inequality_ok=True page_class=NotImplementedError(implemented in Batch 2 (after page_class in Batch 1.5))
D1.A-decayexp flare_pos_iv_pos_8_d1a_b1_cTS_semantic_v2_decayexp_seed1234_n6000.db: production=192 region_only=99 log4_explicit=113 inequality_ok=True page_class=NotImplementedError(implemented in Batch 2 (after page_class in Batch 1.5))
```

**Inequality `region_only ≤ log4_explicit ≤ production_log2`:** Holds on both smoke DBs (hybrid total per §1.5).

**`count_cgc_page_class`:** Raises `NotImplementedError` as specified (Batch 2 counter; `page_class()` stub until Batch 1.5).

---

## 4. Unit tests (task 4)

**File:** `a4/runs/iv_pos_7/analysis/test_cgc_variants.py`

```
9 passed in 0.33s
```

| Test | What it validates |
|---|---|
| `test_cgc_key_region_only_edge_cases` | Empty `ctx_json`, `invalid`, missing fields |
| `test_cgc_key_log4_explicit_halves_buckets` | log4 pairs collapse (buckets 0–1 → log4_0, 2–3 → log4_1) |
| `test_region_only_collapses_log2_buckets_within_region` | 32 log2 buckets → 1 key per region |
| `test_page_class_stubs_raise` | Batch 1.5 stub |
| `test_count_cgc_page_class_stub_raises` | Batch 2 counter stub |
| `test_memory_subset_inequality` | §1.5.1 memory-only: region ≤ log4 ≤ production |
| `test_hybrid_total_inequality` | §1.5 hybrid total on V5 seed1234 |
| `test_lookup_families_constant_across_variants` | Lookup `ctx_key` pass-through unchanged |
| `test_invariants_hold_across_v1_v5_seeds` | All 20 R2 V1+V5 seeds |

---

## 5. Files created / modified

| Path | Purpose |
|---|---|
| `a4/runs/iv_pos_7/analysis/cgc_variants.py` | §1.2 keys, §1.5 hybrid counters, Batch 1.5/2 stubs |
| `a4/runs/iv_pos_7/analysis/test_cgc_variants.py` | Batch 1 unit tests |
| `a4/runs/iv_pos_8/d1b/analysis/build_batch1_audit.py` | 30-DB audit + smoke runner |
| `a4/runs/iv_pos_8/d1b/d1b_batch1_data_audit.csv` | Cat-A data audit (task 1) |
| `a4/runs/iv_pos_8/d1b/d1b_batch1_smoke.txt` | Smoke output (task 5) |
| `a4/docs/cloud2/composer/D1B_BATCH1_REPORT.md` | This report |
| `a4/standalone/compressed_global_extractor.py` | Batch 1.6: `_coerce_broken_addr` field priority (§3.2.5 authorized exception) |
| `a4/standalone/tests/test_compressed_global_extractor.py` | Batch 1.6: Tests A–E |
| `a4/runs/iv_pos_8/d1b/analysis/replay_cgc_corrected.py` | Batch 1.6: 30-DB replay tool |
| `a4/runs/iv_pos_8/d1b/d1b_batch1_replay_corrected.csv` | Batch 1.6: before/after comparison |
| `a4/runs/iv_pos_8/d1b/replay_artifacts/d1b_batch1_replay_corrected.sha256` | Replay CSV provenance |

**Not touched (per §2.2):** `coverage_db.py`, production POS pipelines.  
**Batch 1.6 exception (§3.2.5):** `compressed_global_extractor.py:216` field-priority fix — see §9.

---

## 6. Implementation notes & feedback for Opus/Ivan

### 6.1 What was implemented exactly

1. **`cgc_variants.py`**
   - `parse_memory_byte_addr()` — `ast.literal_eval` → `byte_addr`
   - `cgc_key_region_only`, `cgc_key_log4_explicit`
   - `page_class`, `cgc_key_page_class` — `NotImplementedError("populated in Batch 1.5")`
   - Hybrid counters: `count_cgc_region_only`, `count_cgc_log4_explicit`, `count_cgc_production_log2`
   - Memory-subset helpers for tests: `count_cgc_memory_*`
   - `count_cgc_page_class` — `NotImplementedError` until Batch 2
   - §1.4 aliases: `compressed_global_context_final_*`
   - Repo-root `sys.path` insert (same pattern as `collection_validator.py`) for `a4.standalone` import

2. **Hybrid counting (§1.5):** Memory rows re-bucketed; lookup families (`u8`, `u16`, `cycle`) use production `ctx_key` unchanged. Verified on V5 seed1234: `region_only_total = memory_region_keys + distinct_lookup_ctx_keys`.

3. **Audit script bugfix:** Initial version set `D1A_DBS = d1b/dbs` (wrong). Corrected to `d1a/dbs`. Without this, audit silently produced 20 rows.

### 6.2 Observations (non-blocking)

- **Lookup family presence:** Smoke V5 DB has `cycle` only (no `u8`/`u16` in CGC table). Hybrid rule still correct — empty lookup sets add 0.
- **`region_only` is not “too coarse”:** Hybrid totals are 96–99 on smoke DBs (>> 5), so W-R1 “too coarse” risk (§4) does not trigger on spot check.
- **Split stub timing:** `page_class()` → Batch 1.5; `count_cgc_page_class()` → Batch 2. Intentional per spec tasks 2–3; smoke documents both.

### 6.3 Suggested Batch 1.5 parallel research (Q-BATCH-MODEL)

Safe to start during this review checkpoint:
- Shell `readelf -S` on canonical guest ELF → draft `d1b_guest_elf_layout.json`
- Aggregate `byte_addr` histograms from the 30-row audit CSV for `user_other` gate preview

No code dependency on Batch 1 review outcome for read-only ELF research.

### 6.4 Open questions for Opus review

1. **Audit CSV `address_region_distribution`:** Scoped to `family='memory'` only. Should Batch 2 artifact builder also snapshot lookup-family counts separately? (Not required by §3.1; optional clarity.)
2. **D1.A duplicate seeds:** Two decayexp files for seed1238 (`flare` vs `flare_pos_..._b1c_...`); audit picks newest mtime. Confirm this matches D1.A collection intent.
3. **§8 commit step:** Report written; **no git commit** until Ivan explicitly requests (user rule). Squash commit to `cloud2` pending D2 ack.

---

## 7. Exit criteria checklist (§3.1 + §3.2.5)

| Criterion | Status |
|---|---|
| All unit tests green | ✅ 9/9 |
| Data audit CSV, 30 DBs, no NULL/missing surprises | ✅ |
| Smoke inequality `region_only ≤ log4_explicit ≤ production` | ✅ |
| Batch 1 Composer report | ✅ (this file) |
| Ivan Q-PC-1..4 resolved before Batch 1.5 | ✅ (resolved 2026-06-17 per spec §7) |
| Opus + Ivan review pass | ⏳ pending |
| Batch 1.6: patch + Tests A–E green | ✅ 85/85 extractor tests |
| Batch 1.6: full standalone suite | ✅ 515 passed, 7 skipped |
| Batch 1.6: 30-DB replay CSV + lookup invariant | ✅ 30/30 lookup match |
| Batch 1.6: D2 coordination before push | ⏳ awaiting ack |

---

## 8. Commands to reproduce

```bash
cd /root/arguzz/a4/runs/iv_pos_7
python3 -m pytest analysis/test_cgc_variants.py -v

python3 /root/arguzz/a4/runs/iv_pos_8/d1b/analysis/build_batch1_audit.py

# Batch 1.6
python3 -m pytest a4/standalone/tests/test_compressed_global_extractor.py -q
python3 -m pytest a4/runs/iv_pos_7/analysis/ -q
python3 a4/runs/iv_pos_8/d1b/analysis/replay_cgc_corrected.py
```

---

## 9. Batch 1.6 follow-up: `_coerce_broken_addr` field-priority fix

**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.4 §3.2.5  
**Date:** 2026-06-17

### 9.1 Bug statement

`a4/standalone/compressed_global_extractor.py` `_coerce_broken_addr()` preferred Hook 3 fields in order `("addr", "byte_addr", "address")`. Hook 3 emits both `addr` (circuit **word** address) and `byte_addr` (VM **byte** address = `addr × 4`). D8 `address_region()` and `address_bucket()` are defined on byte addresses. Using `addr` mis-labels memory contexts whose word and byte VM bands differ.

**Fix (one line, landed):**

```python
for key in ("byte_addr", "addr", "address"):
```

### 9.2 Verification SQL (representative)

```sql
-- Invariant: byte_addr == addr * 4 (V5 s1234: 13670/13670)
-- Region mismatch: V5 58.9%, V1 53.2%, D1.A decayexp 55.7%
```

Stored `compressed_global_coverage` memory rows collapsed to `{user, zero_page}` only on all 30 audit DBs. True byte_addr geography spans 9 regions.

**Above-4G (D42):** 0.3–0.6% of memory dicts — not 30–50%.

### 9.3 Scope

| Component | Affected? |
|---|---|
| Memory CGC keys | **Yes** (~53–59% mis-labeling pre-fix) |
| Lookup families | **No** |
| Local channel / arms / scheduler | **No** |
| D1.B re-bucket variants | **Indirect** — Batch 2 needs corrected baseline |

### 9.4 Regression tests + suite

Tests A–E in `test_compressed_global_extractor.py`: **85/85 passed**. Full `a4/standalone/tests/`: **515 passed, 7 skipped**. `a4/runs/iv_pos_7/analysis/`: **45 passed**.

### 9.5 Replay results

**CSV:** `d1b_batch1_replay_corrected.csv` (30 rows)  
**sha256:** `4ea8521a65f312a5b5a60172b7fff014ee3af18e3214c641cb14eaf1e4c75ebc`  
**Lookup invariant:** 30/30 DBs (`prod_buggy_lookup_keys == prod_corrected_lookup_keys`)

**V5 s1234:** memory 89→117 (+28); total 183→211; regions `{user,zero_page}` → 9 regions.

**Corpus-wide:** memory Δ mean +20.7/DB (range 0–32).

**Replay methodology note:** Memory re-extracted from `hook3_raw` via patched extractor. Lookup keys taken from `hook3_raw.compressed_ctx_json` first-hit aggregation (patch-invariant; avoids needing per-DB `InspectionData` reload for `mutation_major`).

### 9.6 Implications + pushback

- Batch 2 uses `production_log2_corrected` from replay, not stored CGC table.
- No cloud1 re-dispatch; NFP-10 verified; disclosure at Batch 3.
- D2 ack required before push (`compressed_global_extractor.py` shared with D2.B).
- **Spec fix needed:** §3.3 Batch 2 task 1 still references reading stored `first_hit_mutation_id` — contradicts §3.3 prerequisite.

---

*End of D1.B Batch 1 + Batch 1.6 Composer report.*
