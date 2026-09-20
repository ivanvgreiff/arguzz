# AP.B2 Report — Constraint-polynomial fix (Route 2, superseded)

**Status:** Route 2 incomplete — see **`AP_B2_COMPOSER_REPORT.md`** for full Composer work log and Opus review. Route 1 (zirgen regen) is the path forward.

**Date:** 2026-06-22  
**Summary:** Surgical poly patch fixed honest proofs but not mutated accept (26 live AndEqz folds). GP1 false-pass fixed. Bracket 0/15.

## What changed (Opus directives)

Per `a4/docs/cloud3/AP_B2_ROOT_CAUSE.md`, the planted hole was moved from **witgen-only** to **witgen + constraint polynomial**:

| Layer | Change |
|-------|--------|
| `steps.cpp/.cu/.cuh` | `exec_ReadReg` → `exec_MemoryReadNoIsRead` (witgen) |
| `rust_poly_fp_{0..3}.cpp` | Zero IsRead@ReadReg subs, arg0 loads, FpExt mix terms (72 sites) |
| `poly_ext.rs` | `Sub(a,b)` → `Sub(0,0)` on IsRead@ReadReg (16 sites) |
| `ap_isread_patch.py` | Extended patch + revert; GP1 counts active constraint sites |
| `ap_b1_verify.py` | GP1 poly checks + mutated V0 smoke (one corpus entry) |

**New bench-isread hash:** `808152f14f411b10274cd1e97b84d63c375c4a96b932d5002ae9baf2e2dfb858`  
(old witgen-only: `efed784a…` — invalid for bracket)

## Gate results

| Gate | Result | Notes |
|------|--------|-------|
| GP1 | **PASS** | `poly_fp_active=0`, `poly_ext_sub_active=0`; RAM/fetch IsRead retained |
| GP2 | **PASS** | Fingerprints + host emit |
| V0 honest | **PASS** | Both patched and bench-isread verify honest guest |
| V0 mutated | **FAIL** | `race_0000_s51_txn15613`: bench **reject**, patched **reject (0,1,0)** ✓ |
| GP3 | **PASS** | 15-entry corpus |
| GP4 | **FAIL** | bench accept **0/15** (see bracket) |
| GP5 | **FAIL** | genuine **0/15** |

## Bracket symptom (mutated config)

```
patched:     exit 101, IsRead logged, layers (0,1,0)  ← correct reject bracket
bench-isread: exit 101, 0 logged failures, layers (0,0,0), panic "verify segment"
```

Honest runs verify on bench-isread. Mutated runs complete witgen (~15s) then fail **internal verify_integrity** — same outer symptom as witgen-only hole, but cause differs:

- Witgen IsRead eqz is removed (no logged failures)
- C++ `rust_poly_fp` + `poly_ext` Sub terms are neutralized
- **26 `poly_ext` AndEqz steps** on IsRead@ReadReg remain (replacing with `True` breaks honest proofs)
- Possible **C++/Rust poly drift** or **tap witness** paths still coupling IsRead witness bits into the mix polynomial

## Interpretation

1. **Opus root cause confirmed:** witgen-only hole could never produce bench accepts; constraint poly edit was required.
2. **Route 2 surgical patch is necessary but not yet sufficient** for mutated accept — likely needs zirgen regen (Route 1) or a safer AndEqz neutralization that preserves step indices without breaking honest proofs.
3. **(0,1,0) theory remains untested** until bench-isread accepts at least one mutated corpus entry under verify.

## Next steps

1. **Route 1:** Build zirgen; change `ReadReg` → `MemoryReadNoIsRead` in `mem.zir`/`inst.zir`; regen `steps.*`, `rust_poly_fp_*`, `poly_ext.rs` atomically.
2. **Route 2 refinement:** Neutralize AndEqz without `True` (e.g. ensure Sub output wire is wired to zero constant); audit variable reuse (e.g. `x424` arg0 load at fp_0:3336 used at 4104).
3. Re-run V0 mutated smoke → bracket when `mutated_bench_accepts=true`.

## Artifacts

- `a4/runs/iv_pos_9/ap/ap_b1_verify.json`
- `a4/runs/iv_pos_9/ap/ap_b2_verify.json` (after bracket)
- `a4/runs/iv_pos_9/ap/ap_bracket_table.json`
- `a4/scripts/ap_isread_patch.py`
