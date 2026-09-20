# AP.B2 Composer Report — Route 2 attempt, Opus review, Route 1 path

**Date:** 2026-06-22  
**Author:** Composer (implementation) · reviewed by Opus  
**Scope:** Fix AP.B2 bracket failure per Opus root-cause directives (`a4/docs/cloud3/AP_B2_ROOT_CAUSE.md`)

---

## Executive summary

Opus correctly identified that AP.B1’s witgen-only hole could never produce bench accepts: proof validity is enforced by the **constraint polynomial** (`rust_poly_fp_*` + `poly_ext.rs`), not witgen `eqz` logs.

Composer extended the patch into the constraint-polynomial layer (Route 2 surgical), hardened gates, rebuilt binaries, and ran the bracket. **Honest proofs now verify on bench-isread** (proving the witgen-only diagnosis). **Mutated bracket still fails 0/15** because the surgical patch is structurally incomplete: **26 live `AndEqz` folds** on IsRead@ReadReg in `poly_ext.rs` were never neutralized, and hand-editing the dual prover/verifier representations is unsafe.

**Opus verdict:** Stop Route 2. Commit to **Route 1 (zirgen regen)**. The mutated V0 smoke gate (which failed) is the only trustworthy build gate; the old GP1 Sub-only counter false-passed and has been fixed.

---

## 1. What Composer did (chronological)

### 1.1 Extended `a4/scripts/ap_isread_patch.py`

**Witgen (unchanged from AP.B1):**
- Inserted `exec_MemoryReadNoIsRead` in `steps.cpp`, `steps.cu`, `steps.cuh`
- Redirected `exec_ReadReg` call site from `exec_MemoryRead` → `exec_MemoryReadNoIsRead`

**Constraint polynomial — Route 2 surgical (new):**

| Artifact | Mechanism | Sites touched |
|----------|-----------|---------------|
| `rust_poly_fp_{0..3}.cpp` | Zero `auto xN = a - b` subs after IsRead@ReadReg loc comments | 16 |
| same | Zero `auto xN = arg0[...]` loads (prevent witness leakage to later FpExt, e.g. fp_0:3336 → 4104) | 14 |
| same | Drop FpExt mix terms: `FpExt xN = xA + xB * poly_mix[k]` → `FpExt xN = xA` | 28 |
| `poly_ext.rs` | In-place `PolyExtStep::Sub(a,b)` → `Sub(0,0)` on IsRead@ReadReg lines | 16 |

**Not touched (critical gap):**
- **26 `PolyExtStep::AndEqz(...)` lines** on IsRead@ReadReg — these are the binding constraint folds the verifier enforces

**Iterations and mistakes:**
1. First poly_ext patch **inserted duplicate `Sub(0,0)` lines** instead of replacing in-place → shifted PolyExt wire indices → broke proofs entirely
2. Attempted `AndEqz` → `PolyExtStep::True` → broke **honest** proofs (even with refined fp patch)
3. Attempted zeroing all `arg0` stores → broke honest proofs
4. Final honest-passing config: sub + arg0-load + FpExt in `rust_poly_fp_*`; Sub-only in `poly_ext.rs`; **AndEqz left live**

**Revert path:** witgen markers removed in-place; poly files reverted via `git checkout` in `risc0-modified`

### 1.2 Hardened `a4/scripts/ap_b1_verify.py`

**GP1 (initial — false pass, now fixed):**
- Originally counted `poly_*_active` = un-zeroed `Sub(` lines only → reported `poly_ext_active=0` while **26 AndEqz folds live**
- **Fixed per Opus:** form-agnostic loc-tag count — `poly_fp_isread_readreg_loc_tags` + `poly_ext_isread_readreg_loc_tags` must be **zero** (post-regen: tags absent, not zeroed); also reports `poly_ext_isread_readreg_andeqz`
- Current Route-2 tree: GP1 **correctly FAILS** (66 + 42 loc tags remain)

**V0 mutated smoke (authoritative behavioral gate):**
- Runs one `(0,1,0)` corpus entry (`race_0000_s51_txn15613`) through bench + patched bracket
- Requires: bench accept + patched reject
- **Correctly FAILED** throughout — this is what caught the incomplete patch

### 1.3 Rebuilt binaries (`a4/scripts/build_ap_binaries.sh`)

| Binary | SHA256 | Notes |
|--------|--------|-------|
| patched | `705cad81…` | Control; intact IsRead |
| bench-isread (final Route 2) | `808152f14f411b10274cd1e97b84d63c375c4a96b932d5002ae9baf2e2dfb858` | Invalid for bracket accept; honest verifies |
| bench-isread (witgen-only, obsolete) | `efed784a…` | Pre-fix; do not use |

Build time: ~25 min full (patched + bench-isread); ~8–11 min bench-only rebuild after patch iteration.

### 1.4 Bracket replay (`ap_b2_replay.py --bracket-only`)

15-entry corpus from 600-target POS screen (`ap_corpus_010.json`):

| Gate | Result |
|------|--------|
| GP3 corpus | **PASS** (15 entries) |
| GP4 bench accept / patched reject | **FAIL** 0/15 accept, 15/15 patched reject |
| GP5 genuine soundness | **FAIL** 0/15 |

**Per-config pattern (all 15 identical after poly fix):**

```
patched:      exit 101, 1 IsRead failure, layers (0,1,0)  ← correct reject bracket
bench-isread: exit 101, 0 logged failures, layers (0,0,0), panic "verify segment"
```

Honest guest on bench-isread: **Verifier success** (Route 2 partially works).  
Mutated guest on bench-isread: witgen completes (~15–18s), prover `verify_integrity` fails internally.

---

## 2. Opus review — what Composer got right and wrong

### Correct (structure + judgment)

- Extended patch to **constraint polynomial**, not witgen alone ✓
- Added **mutated V0 smoke** as hard gate ✓ (only gate that caught the real problem)
- Rebuilt, documented honestly, recommended Route 1 when Route 2 stalled ✓
- Identified AndEqz as blocker ✓

### Wrong (proven from source)

**1. `poly_ext` Sub-only patch is ineffective on the binding constraint**

Example from committed `poly_ext.rs` after patch:

```
PolyExtStep::Sub(0, 0), // AP_PLANTED ... IsRead mem.zir:79 at ReadReg ...
PolyExtStep::AndEqz(79, 752), // ... IsRead mem.zir:79 at ReadReg ...
```

`AndEqz(79, 752)` folds **step index 752** into the constraint accumulator. That is not the Sub on the line above it in the source listing — it references a shared subexpression DAG node. Zeroing adjacent Sub lines does not remove the fold the verifier evaluates.

Counts on current tree: **16 Sub + 26 AndEqz = 42** IsRead@ReadReg lines in `poly_ext.rs`; **66** loc tags in `rust_poly_fp_*`.

**2. GP1 false-passed**

Old logic: `count_poly_ext_active` = un-zeroed `Sub(` only → `0` while 26 AndEqz live → GP1 PASS was meaningless.

Fixed: loc-tag count (form-agnostic). Route 2 tree now GP1 FAIL (66+42 tags). Post-regen expectation: **0 tags** (absent, not patched-to-zero).

**3. Route 2 is unsafe, not merely incomplete**

- `AndEqz(79, 752)` and `AndEqz(93, 752)` share step 752 across constraints
- Prover (`rust_poly_fp`, FpExt + `poly_mix[k]`) and verifier (`poly_ext`, AndEqz) are **different representations** that must drop the **identical** constraint set with **identical** mix enumeration
- Hand-editing both around shared subexpressions is error-prone and unverifiable → **dead end for thesis-grade benchmark**

---

## 3. Pre-regen `.zir` verification (faithful edits)

Source at `zirgen/zirgen/circuit/rv32im/v2/dsl/` (already edited for AP):

**`mem.zir` — `MemoryReadNoIsRead`:**

```zir
component MemoryReadNoIsRead(cycle: Reg, addr: Val) {
  io := MemoryIO(2*cycle, addr);
  IsForward(io);          // kept
  GetData(io.newTxn, 0, 1)  // kept
  // IsRead(io) omitted — only delta from MemoryRead
}
```

**`inst.zir` — ReadReg uses NoIsRead:**

```zir
component ReadReg(...) {
  addr := Reg(...);
  MemoryReadNoIsRead(cycle, addr)   // not MemoryRead
}
```

**RAM / fetch paths still use IsRead-bearing `MemoryRead`:**

| Path | File | Call |
|------|------|------|
| Fetch / decode | `inst.zir:31` | `MemoryRead(cycle, pc_addr)` in `DecodeInst` |
| RAM load | `inst_mem.zir:14,26` | `MemoryRead(cycle, addr.addr)` |
| All other mem reads | various | `MemoryRead(...)` — not ReadReg |

Regen from these `.zir` files should remove IsRead@ReadReg loc-tags from **all** generated artifacts atomically.

---

## 4. Route 1 scoping — zirgen build

### 4.1 Repository state

| Repo | Path | HEAD |
|------|------|------|
| zirgen | `/root/arguzz/zirgen` | `df6fb9dda1c20209058d6ee90a8912351b741081` (2026-01-20, ZIR-387) |
| risc0-modified | `workspace/risc0-modified` | `28e53771f89d7b9271a83be687ef545b947f65a0` |

Zirgen is a **separate git repo** at `/root/arguzz/zirgen` (not a submodule of risc0-modified in this workspace). **Version pin risk #1:** must confirm the zirgen revision that originally produced the committed `steps.cpp` / `rust_poly_fp_*` / `poly_ext.rs` in risc0-modified. If regen uses a different zirgen, layout/taps/control-IDs may drift → guest image ID and proof compatibility break across the whole build.

### 4.2 Codegen entry point

From `zirgen/zirgen/circuit/rv32im/v2/dsl/BUILD.bazel`:

```python
build_circuit(
    name = "codegen",
    outs = [
        "steps.cpp", "steps.cu",
        "rust_poly_fp_{0..3}.cpp",
        "eval_check_{0..3}.cu",
        "poly_ext.rs",  # via ZIRGEN_OUTS
        "layout.*", "steps.cuh", ...
    ],
    bin = "//zirgen/Main:gen_zirgen",
    extra_args = [
        "top.zir",
        "--circuit-name=rv32im_v2",
        "--validity-split-count=4",
        "--protocol-info=RV32IM:v2rev2___",
    ],
)
```

**Bazel target:** `//zirgen/circuit/rv32im/v2/dsl:codegen`

### 4.3 Toolchain requirements

| Requirement | Status in this environment |
|-------------|---------------------------|
| Bazel | **Not installed** (`which bazel` → missing) |
| LLVM/MLIR | Pinned in `zirgen/WORKSPACE` (commit `39df4945…`) — fetched by Bazel on first build |
| Conda rules | `rules_conda` in WORKSPACE — may need conda env for some deps |
| Build time | Unknown; expect significant first-build (LLVM fetch + compile) |

### 4.4 Regen workflow (planned)

1. **Pin zirgen revision** — `df6fb9d`; protocol-info matches (`RV32IM:v2rev2___`). **Hard gate:** `ap_zirgen_regen.sh control-check` must pass before holed regen.
2. Install Bazel 6.x via bazelisk (`USE_BAZEL_VERSION=6.0.0`) — **done in this environment**
3. `bash a4/scripts/ap_zirgen_regen.sh control-check` — unmodified `.zir` vs committed artifacts
4. `bash a4/scripts/ap_zirgen_regen.sh holed-regen` — install full artifact set:
   - `risc0/circuit/rv32im/src/zirgen/{poly_ext.rs,info.rs,taps.rs,layout.rs.inc,...}`
   - `risc0/circuit/rv32im-sys/kernels/cxx/{steps.cpp,rust_poly_fp_*.cpp,...}`
   - `risc0/circuit/rv32im-sys/kernels/cuda/{steps.cu,steps.cuh,eval_check_*.cu,...}`
5. `bash a4/scripts/build_ap_binaries.sh --from-regen` — patched from git-clean circuit; bench from holed regen (**no** `ap_isread_patch.py`)
6. Gates: GP1 total loc-tags == 0; V0 mutated smoke pass; then GP4/GP5 bracket

See also: `AP_B2_OPUS_REVIEW_RESPONSE.md` for Opus gap-by-gap response.

### 4.5 Fallback (Opus: last resort only)

If pinned zirgen is genuinely unbuildable: **do not resume regex neutralization.** Alternative is a PolyExtStep-DAG transformer that repoints IsRead@ReadReg AndEqz operands to known-zero steps + corresponding `rust_poly_fp_*`/CUDA drops, gated by automated honest+mutated proof check — effectively writing a mini-codegen; more work and risk than building zirgen.

---

## 5. Gate summary (current tree)

| Gate | Pass? | Trustworthy? | Notes |
|------|-------|--------------|-------|
| GP1 (fixed) | **FAIL** | Yes | 66 fp + 42 ext loc tags; 26 AndEqz live |
| GP1 (old Sub-only) | PASS | **No** | False pass — do not use |
| GP2 fingerprint | PASS | Yes | |
| V0 honest | PASS | Yes | Both hosts verify |
| V0 mutated | **FAIL** | **Yes — authoritative** | bench reject, patched reject ✓ |
| GP3 corpus | PASS | Yes | 15 entries |
| GP4/GP5 bracket | FAIL | Yes (confirms hole incomplete) | 0/15 bench accept |

---

## 6. Files changed by Composer

| File | Change |
|------|--------|
| `a4/scripts/ap_isread_patch.py` | Extended: witgen + rust_poly_fp + poly_ext surgical patch; revert via git checkout |
| `a4/scripts/ap_b1_verify.py` | GP1 loc-tag gate + mutated V0 smoke; loosened witgen (function-name); steps.cu scan; info.rs check |
| `a4/scripts/ap_zirgen_regen.sh` | **New** — control-check / holed-regen / holed-check |
| `a4/scripts/build_ap_binaries.sh` | `--from-regen` for post-regen builds |
| `workspace/risc0-modified/.../steps.{cpp,cu,cuh}` | AP witgen markers (bench build) |
| `workspace/risc0-modified/.../rust_poly_fp_*.cpp` | AP_PLANTED zero comments (Route 2) |
| `workspace/risc0-modified/.../poly_ext.rs` | Sub→Sub(0,0) only; AndEqz intact |
| `a4/builds/ap/bench-isread/risc0-host` | Rebuilt |
| `a4/runs/iv_pos_9/ap/ap_b1_verify.json` | Gate results |
| `a4/runs/iv_pos_9/ap/ap_b2_verify.json` | Bracket GP3–GP5 |
| `a4/runs/iv_pos_9/ap/ap_bracket_table.json` | 15-row bracket |
| `a4/runs/iv_pos_9/ap/AP_B2_REPORT.md` | Initial status doc |
| `a4/docs/cloud3/AP_B2_ROOT_CAUSE.md` | Opus root cause (pre-existing) |

---

## 7. Conclusions

1. **Opus root cause confirmed:** witgen-only hole → 0 logged failures + verify segment panic; bracket oracle was correct.
2. **Route 2 partial success:** honest bench-isread verifies → poly/witgen layer diagnosis validated.
3. **Route 2 cannot complete bracket:** 26 AndEqz folds + shared subexpression DAG + dual representations → surgical patch is incomplete and unsafe.
4. **Mutated V0 smoke works as designed** — only gate that cannot be fooled by Sub-only counters.
5. **Next action:** Scope/install Bazel, pin zirgen revision, regen from `.zir`, replace surgical patches, re-run V0 → bracket.

The `(0,1,0)` theory — whether removing IsRead makes those reads verify — **remains untested** until a genuinely holed circuit (Route 1) passes mutated V0 smoke.
