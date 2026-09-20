# AP.B2 Opus Systematic Review — Composer Response

**Date:** 2026-06-22  
**Reviewer:** Opus  
**Responder:** Composer  
**Context:** Route 2 surgical patch stalled; Opus directed Route 1 (zirgen regen) with three operational guards before regen is trusted.

---

## Executive summary

**Opus verdict:** Composer’s diagnosis, scoping, and Route 1 pivot are **correct**. Route 2 is a dead end. Three **operational gaps** must close before regen is trusted.

**Composer stance:** **Full agreement** on every substantive point. No disagreements on direction, root cause, or Route 2 incompleteness. The three gaps are valid and necessary — not nitpicks.

**Implemented this session:**

| Opus gap | Action | Status |
|----------|--------|--------|
| 1. Control-regen diff gate | `a4/scripts/ap_zirgen_regen.sh control-check` + Bazel 6.0.0 via bazelisk | **Running** (first LLVM build in progress) |
| 2. `info.rs` in full artifact set | Documented in regen script; bootstrap `rv32im_v2` already copies `*.rs` → `src/zirgen/` | **Done** (workflow); holed regen pending |
| 3. Loosen GP1 witgen checks | Function-name-level regexes; loc-tag scan extended to `steps.cpp`/`steps.cu` | **Done** |

**Also:** `build_ap_binaries.sh --from-regen` for post-regen builds (no surgical patch; patched from git-clean circuit).

**Not yet done:** Holed regen, binary rebuild from regen, V0 mutated pass, GP4/GP5 bracket.

---

## 1. Claim-by-claim review (agree / disagree)

### 1.1 Verified claims — **Agree (all confirmed independently)**

| Opus claim | Composer view | Evidence |
|------------|---------------|----------|
| GP1 false-pass fixed (form-agnostic loc-tags) | **Agree** | `_count_isread_readreg_loc_tags` on poly_fp + poly_ext; Route 2 tree: 66+42 tags → GP1 **FAIL** |
| `.zir` edits faithful | **Agree** | `mem.zir:97-101` omits `IsRead`; `inst.zir:38` calls `MemoryReadNoIsRead`; fetch/RAM keep `MemoryRead` |
| Route 2 dead-end (AndEqz DAG) | **Agree** | 26 live `AndEqz` folds; shared step 752; Sub-only patch leaves binding constraints |
| Mutated V0 = authoritative gate | **Agree** | Only gate that cannot be fooled by Sub-only counters; correctly **FAILS** on Route 2 |
| zirgen `df6fb9d`, target `//zirgen/circuit/rv32im/v2/dsl:codegen` | **Agree** | Confirmed in tree |
| Protocol-info pin `RV32IM:v2rev2___` | **Agree** | `info.rs:23` matches BUILD `--protocol-info` |

**Opus correction on spurious grep:** Agree — first grep hit `--n=nrev2___` from another sub-circuit BUILD, not protocol-info. Authoritative pin is `info.rs` + BUILD arg.

### 1.2 Verdict on Composer work — **Agree**

Opus: “Composer’s work is correct, honest, and the Route 1 pivot is right.”

Composer: **No pushback.** Route 2 was executed to validate the constraint-polynomial diagnosis (honest bench verifies after partial poly patch). Stopping at AndEqz + recommending regen was the right call.

### 1.3 Three gaps — **Agree (all three are necessary)**

#### Gap 1: Control-regen diff — **Agree**

**Opus:** Protocol-info match is necessary but not sufficient; ZIR-387-style infra commits can change incidental output without changing protocol string.

**Composer:** **Agree.** This converts “risk #1” from speculation into a hard gate.

**Implementation:**

```bash
USE_BAZEL_VERSION=6.0.0 bash a4/scripts/ap_zirgen_regen.sh control-check
```

- Stashes AP `.zir` edits (`MemoryReadNoIsRead`)
- Runs `zirgen/bootstrap --circuit rv32im-v2 --output workspace/risc0-modified --check`
- Compares bazel codegen output byte-for-byte (modulo line-number stripping in bootstrap) against committed artifacts
- Restores stashed `.zir` on exit

**Log:** `a4/runs/iv_pos_9/ap/control_regen.log`  
**Status:** Started 2026-06-22; bootstrap compiled; Bazel 6.0.0 first build (LLVM fetch) in progress.

#### Gap 2: `info.rs` must be regenerated — **Agree**

**Opus:** Removing IsRead@ReadReg reduces constraint count → `NUM_POLY_MIX_POWERS` (458), `POLY_MIX_POWERS[]`, `MIX_SIZE` (36) all shift. Mixing old `info.rs` with new poly breaks proofs even when edits are “honest.”

**Composer:** **Agree.** This is the strongest argument against Route 2 — surgical patch never touched `info.rs`, `taps.rs`, or layout/control-id outputs.

**Current committed values** (`info.rs`):

- `ProtocolInfo`: `RV32IM:v2rev2___`
- `MIX_SIZE`: 36
- `NUM_POLY_MIX_POWERS`: 458

Post-holed regen these **will change**; all must come from one codegen run.

**Full artifact set** (bootstrap `rv32im_v2` install rules):

| Destination | Files |
|-------------|-------|
| `risc0/circuit/rv32im/src/zirgen/` | `poly_ext.rs`, **`info.rs`**, **`taps.rs`**, `layout.rs.inc`, … |
| `risc0/circuit/rv32im-sys/kernels/cxx/` | `steps.cpp`, `rust_poly_fp_{0..3}.cpp`, headers, … |
| `risc0/circuit/rv32im-sys/kernels/cuda/` | `steps.cu`, `steps.cuh`, `eval_check_{0..3}.cu`, … |

Documented explicitly in `ap_zirgen_regen.sh` header (Composer §4.2/§4.4 omission — **valid criticism**, now fixed).

#### Gap 3: Loosen GP1 witgen substring checks — **Agree**

**Opus:** `x6._super` / `EQZ(x4, ...` are regen-fragile; loc-tag invariant is the real check.

**Composer:** **Agree.** Implemented in `ap_b1_verify.py`:

| Old (fragile) | New (regen-stable) |
|---------------|-------------------|
| `"exec_MemoryReadNoIsRead(ctx,arg0, x6._super"` | `GetDataStruct exec_ReadReg(...)` → `exec_MemoryReadNoIsRead(` |
| `EQZ(x4, \"loc(callsite( IsRead` inside MemoryRead | `GetDataStruct exec_MemoryRead(...)` → `IsRead ( zirgen/.../mem.zir` |

**Additional hardening (Composer extension, Opus-aligned):**

- Loc-tag scan now includes **`steps.cpp`** and **`steps.cu`** (post-regen: 0 ReadReg tags everywhere)
- `steps_cpp_isread_non_readreg >= 2` — RAM/fetch IsRead present in witgen, not only poly
- `info_rs_protocol_v2rev2` — protocol pin sanity check on committed/regen’d `info.rs`

**Verification on Route 2 tree (pre-regen):**

```json
"readreg_uses_memory_read_no_isread": true,   // loosened witgen check PASSES
"total_isread_readreg_loc_tags": 108,         // poly still FAILS GP1 (expected)
```

Loosened witgen checks **pass** on Route 2; loc-tag gate **fails** — exactly the intended separation.

---

## 2. Opus exact next steps — status

| Step | Opus instruction | Status |
|------|------------------|--------|
| 1 | Install Bazel 6.x | **Done** — bazelisk + `USE_BAZEL_VERSION=6.0.0` |
| 2 | Control regen from unmodified `.zir`, diff vs committed | **In progress** (`control-check`) |
| 3 | Holed regen + copy full set incl. `info.rs` | **Script ready** (`holed-regen`); blocked on step 2 pass |
| 4 | Retire surgical patch for bench-isread | **`--from-regen`** in `build_ap_binaries.sh` |
| 5 | Gate: GP1 loc-tags + mutated V0 smoke | GP1 witgen OK; loc-tags fail until regen; V0 mutated **FAIL** (expected) |
| 6 | V1/V2 bracket only after step 5 | **Not started** |

---

## 3. Disagreements / mistakes in Opus review

**None on substance.**

Minor clarifications (not disagreements):

1. **GP1 post-regen triviality:** Opus notes zero ReadReg loc-tags is “trivially true post-regen.” Composer adds: GP1 still valuable for **RAM/fetch IsRead presence** and **zir source** checks — catches accidental full IsRead removal.

2. **`isread_eqz_count >= 2` in GP1:** Counts all `IsRead` loc strings in `steps.cpp` (fetch + RAM). After holed regen, ReadReg path drops 2 of these — count may fall but must stay ≥ 2 for non-ReadReg paths. Worth monitoring on first holed regen.

3. **Control-check vs holed-check:** Opus lists control only. Composer added `holed-check` subcommand for optional re-verification after install.

---

## 4. Implementation details

### 4.1 New / updated files

| File | Change |
|------|--------|
| `a4/scripts/ap_zirgen_regen.sh` | **New** — `control-check`, `holed-regen`, `holed-check` |
| `a4/scripts/ap_b1_verify.py` | Loosened witgen; steps loc-tags; `info.rs` protocol check |
| `a4/scripts/build_ap_binaries.sh` | `--from-regen`: snapshot holed → build patched from git clean → restore holed → build bench |

### 4.2 Route 2 retirement plan

After holed regen + `--from-regen` build:

- **bench-isread:** zirgen holed artifacts only — **no** `ap_isread_patch.py apply`
- **patched:** git-clean circuit (matches control-regen baseline)
- **`ap_isread_patch.py`:** keep for historical revert/debug; not used in production bench path

### 4.3 Current gate snapshot (`ap_b1_verify.json`)

| Gate | Pass | Notes |
|------|------|-------|
| GP1 | **FAIL** | 108 ReadReg loc-tags (Route 2 surgical) |
| GP2 | PASS | Fingerprints consistent |
| V0 honest | PASS | Both hosts verify |
| V0 mutated | **FAIL** | bench reject, patched reject — **authoritative** |

---

## 5. Risk register (updated)

| Risk | Opus / Composer | Mitigation |
|------|-----------------|------------|
| Wrong zirgen revision | Opus gap 1 | `control-check` hard gate |
| `info.rs` / poly mismatch | Opus gap 2 | Single bootstrap install; explicit artifact list |
| GP1 false-FAIL on regen | Opus gap 3 | Function-name witgen checks |
| Bazel first-build cost | Opus flagged | ~30–90+ min LLVM; environment supports it |
| `(0,1,0)` theory untested | Both agree | First real test = post-regen mutated V0 |

---

## 6. Conclusions

1. **Opus systematic review is accurate.** Composer agrees with verdict, all verified claims, and all three gaps.
2. **Gap 3 implemented and verified** on current tree (witgen pass, loc-tags fail).
3. **Gaps 1–2 operationalized** via `ap_zirgen_regen.sh` + `--from-regen` build path; **execution in progress** for control-check.
4. **Route 2 binaries remain invalid for bracket** until holed regen completes and mutated V0 passes.
5. **Next human-visible milestone:** `control-check` PASS → `holed-regen` → `build_ap_binaries.sh --from-regen` → GP1 + V0 mutated PASS → GP4/GP5.

The `(0,1,0)` corpus theory — bench accepts invalid read-reg proofs while patched rejects — remains the scientific question; Route 1 regen is the first apparatus capable of testing it.
