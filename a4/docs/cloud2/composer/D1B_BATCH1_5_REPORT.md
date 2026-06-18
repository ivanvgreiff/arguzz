# D1.B Batch 1.5 — Composer Report

**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.4.1 §3.2  
**Scope:** ELF-mandatory `page_class` layout derivation + `page_class()` / `cgc_key_page_class()` implementation  
**Branch:** `cloud2` (uncommitted — Ivan commits when D1.B fully complete)  
**Date:** 2026-06-17

---

## 1. Spec review verdict

**Greenlight — Batch 1.5 spec is correct and actionable.** No blocking pushback.

| Item | Verdict |
|---|---|
| ELF mandatory + hard-fail | Correct — ELF present (248292 B) |
| Half-open section convention | Correct — implemented per §0.4 |
| Q-PC-EHF fold `.eh_frame` into `rodata` | Correct default — `[.rodata.addr, .data.addr)` |
| Empirical gate ≤ 15% `user_other` | **PASS** at 3.158% |
| `count_cgc_page_class` deferred to Batch 2 | Correct per spec task 7 vs §3.3 |

**Minor note (non-blocking):** §1.2 draft table lists `text` end as `TEXT_START + .text.size`; Batch 1.5 correctly uses `[TEXT_START, .rodata.addr)` per §0.4 gap-folding rule. JSON artifact reflects the latter.

---

## 2. What was implemented

### 2.1 Layout derivation script

**File:** `a4/runs/iv_pos_8/d1b/analysis/build_page_class_layout.py`

Tasks automated:
1. Pin + sha256 guest ELF
2. `readelf -S` section parse + `_end` symbol
3. `memory.rs` constant parse + equality check
4. Build `_PAGE_CLASS_USER_LAYOUT` (half-open convention)
5. Empirical validation over 30 Cat-A DBs via `parse_memory_byte_addr` + `page_class`
6. Write JSON, markdown report, matplotlib histogram

### 2.2 `page_class()` in `cgc_variants.py`

- Loads layout from `d1b_guest_elf_layout.json` at import (embedded fallback if JSON missing)
- Q-PC-3 pass-through: non-`user` regions → `address_region`; `user_bigint` → `"user_bigint"`
- `user` band sublabels from ELF layout; remainder → `user_other`
- `count_cgc_page_class` **still** `NotImplementedError` (Batch 2 counter per spec)

### 2.3 Unit tests

**File:** `a4/runs/iv_pos_7/analysis/test_cgc_variants.py` — **15/15 passed**

Replaced Batch 1 stub tests with:
- ELF-derived range probes (midpoint per band)
- `user_other` in high user slab
- Pass-through (`user_regs`, `zero_page`, `user_bigint`)
- Stack-text gap folded into `stack`
- `parse_memory_byte_addr` memory vs cycle vs malformed
- Empirical gate documented in JSON

---

## 3. Artifacts

| Artifact | Path | Notes |
|---|---|---|
| Machine-readable layout | `a4/runs/iv_pos_8/d1b/d1b_guest_elf_layout.json` | Provenance + empirical block |
| Human report | `a4/runs/iv_pos_8/d1b/d1b_page_class_layout.md` | Pro-disclosure draft |
| Histogram PNG | `a4/runs/iv_pos_8/d1b/plots/d1b_page_class_histogram.png` | 30-DB label distribution |

**Guest ELF sha256:** `3e5082ad7ee76bad8be4e403a6a13b566f2a06cbb85b947fae9cbbd0dfd05494`

---

## 4. Derived layout (final)

| page_class | Range | Source |
|---|---|---|
| `stack` | `[0x00010000, 0x00200800)` | Below `TEXT_START` |
| `text` | `[0x00200800, 0x00219db8)` | `[TEXT_START, .rodata.addr)` |
| `rodata` | `[0x00219db8, 0x0022133c)` | `[.rodata.addr, .data.addr)` incl. `.eh_frame` |
| `data_bss` | `[0x0022133c, 0x00221488)` | `[.data.addr, _end)` |
| `heap` | `[0x00221488, 0x42000000)` | Bump heap to HOST_ECALL |
| `host_ecall` | `[0x42000000, 0x42000100)` | GLOSSARY / D42 |
| `user_other` | remainder in `user` | Default fallback |

**Q-PC-EHF:** `fold_into_rodata` (documented in JSON `q_pc_ehf` field).

**memory.rs validation:** `STACK_TOP=0x00200400`, `TEXT_START=0x00200800`, `GUEST_MIN_MEM=0x00004000`, `GUEST_MAX_MEM=0xC0000000` — all match expectations.

**ELF `.text` start:** `0x00200800` == `TEXT_START` ✓

---

## 5. Empirical validation (30 Cat-A DBs)

| Metric | Value |
|---|---|
| Total `user`/`user_bigint` `byte_addr` hits | 153,577 |
| `user_other` fraction | **3.158%** (gate ≤ 15%) |
| Gate | **PASS** |
| Stack-text gap hits `[0x00200400, 0x00200800)` | 926 (classified as `stack`) |

**Label distribution (hits, not CGC keys):**

| Label | Hits |
|---|---|
| `text` | 100,364 |
| `stack` | 29,410 |
| `heap` | 9,948 |
| `user_other` | 4,850 |
| `data_bss` | 4,359 |
| `rodata` | 3,633 |
| `user_bigint` | 1,013 |

`user_other` hits concentrate in the high user slab past `host_ecall` (sample addrs ~`0x4200_xxxx`–`0x4240_xxxx`) — consistent with bump-heap / runtime allocations outside ELF-fixed sections. No Ivan escalation required.

---

## 6. Exit criteria checklist (§3.2)

| Criterion | Status |
|---|---|
| `d1b_guest_elf_layout.json` + sha256 | ✅ |
| `_PAGE_CLASS_USER_LAYOUT` shipped in `cgc_variants.py` | ✅ |
| `d1b_page_class_layout.md` written | ✅ |
| page_class unit tests green | ✅ 15/15 |
| `user_other` ≤ 15% | ✅ 3.158% |
| Q-PC-EHF resolved (fold) | ✅ |
| Opus + Ivan review pass | ⏳ pending |

---

## 7. Plan position

```
Batch 1     ✅ ACCEPTED
Batch 1.6   ✅ IMPLEMENTED (local) — awaiting Ivan commit gate + D2 ack
Batch 1.5   ✅ IMPLEMENTED (this report)
Batch 2     ⏳ NEXT — build_d1b_artifacts.py on corrected replay maps (v0.4.1 §3.3)
Batch 3     ⏳ Recommendation + NFP-10 disclosure
```

**Batch 2 prerequisites now satisfied for `page_class()`** (layout + function). Still blocked on Ivan's commit preference and D2 coordination for the 1.6 extractor patch, but **Batch 2 implementation can proceed in parallel** since it is analysis-only on existing DBs.

---

## 8. Commands to reproduce

```bash
cd /root/arguzz
python3 a4/runs/iv_pos_8/d1b/analysis/build_page_class_layout.py
cd a4/runs/iv_pos_7
python3 -m pytest analysis/test_cgc_variants.py -v
```

---

## 9. Pushback / open items for Opus

1. **None blocking.** Batch 1.5 spec §3.2 matches implementation.
2. **Informational:** `user_other` at 3.16% is acceptable but non-trivial — mostly high-address heap traffic; worth one sentence in Batch 3 Pro disclosure.
3. **Batch 2 ready:** `page_class()` is live; `count_cgc_page_class` + `build_d1b_artifacts.py` are the next Composer deliverables per v0.4.1 §3.3.

---

## 10. Batch 1.5b follow-up: `user_dynamic` layout extension

**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.4.3 §3.2.4  
**Date:** 2026-06-17

### 10.1 Rationale (enhancement, not bug fix)

§0.4 originally assigned the upper user band `[0x42000100, 0xBFFF0000)` to implicit `user_other`. Batch 1.5 implemented that correctly (3.158% gate pass). Batch 1.5b promotes the catch-all to explicit **`user_dynamic`** for Pro-disclosure clarity — per Composer/Opus v0.4.3 review.

### 10.2 Change

Added layout entry: `(0x42000100, 0xBFFF0000, "user_dynamic")` after `host_ecall`. Upper bound `0xBFFF0000` aligns with D8 `user` band end; `user_bigint` pass-through unchanged (Q-PC-3).

### 10.3 Results after re-derivation

| Metric | Before 1.5b | After 1.5b |
|---|---|---|
| `user_other` fraction | 3.158% | **0.0%** |
| `user_dynamic` hits | 0 | **4850** |
| Other label counts | unchanged | unchanged |
| CGC key count impact | — | **None** (label swap only) |

**Tests:** 16/16 pass (was 15).

### 10.4 Files touched

- `cgc_variants.py` — fallback layout + JSON reload
- `build_page_class_layout.py` — derivation + empirical uses built layout (not stale import)
- `d1b_guest_elf_layout.json`, `d1b_page_class_layout.md`, histogram — regenerated
- `test_cgc_variants.py` — `user_dynamic` + `user_bigint` tests

---

*End of D1.B Batch 1.5 + 1.5b Composer report.*
