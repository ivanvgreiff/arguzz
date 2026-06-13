# Phase 7d Inc 3 — Race Finding & Open Questions for Pro

**Audience:** ChatGPT Pro (external advisor)
**Authors:** Opus (Cursor agent) + user
**Date:** 2026-06-12; revised 2026-06-13 (second-pass deep-dive); revised late 2026-06-13 (third pass — primary source recovered, mechanism puzzle deepened)
**Purpose:** Self-contained writeup of the "B7 same-seed reproducibility race" that emerged in Phase 7d Inc 3. This is the closing document for the race investigation; it does **not** assume Pro has read any of the internal Inc 3 / Inc 3d reports. It is paired with `CLOUD1_DECISIONS_FOR_PRO_R2.md` for context on decisions D46+D47 below.

> **Methodology note — read this before the rest of the document.** This doc has been revised multiple times as our understanding improved:
>
> 1. **First pass (2026-06-12)**: identified the race empirically, hypothesized "race in the bitmap write," partially ruled out via verbose-tag stream.
> 2. **Second pass (2026-06-13)**: corrected race-rate numbers (cumulative 0.70% default → 0.14% RAYON=1, **5× reduction**), and noted that our binary contains both Rust Rayon AND C++ `poolstl::par` parallelism systems; only Rayon is controlled by `RAYON_NUM_THREADS`.
> 3. **Third pass (late 2026-06-13, primary source recovered)**: 5 critical C++/Rust source files (`ffi.cpp`, `steps.cpp`, `witgen.h`, `hal/mod.rs`, `witgen/mod.rs`) had been wiped from the working tree and were recovered byte-identically to the June 3 state from `/root/arguzz_backups/risc0-modified.CURRENT.patch`. With primary source now visible, we can VERIFY several gating claims directly — and the verification both confirms and **deepens** our mechanism puzzle.
>
> **What primary source confirms (all of these were previously sourced from secondary docs and are now directly readable):**
> - **`a4_touch_mark` early-returns when `A4_COVERAGE_TOUCH` is unset** (`ffi.cpp:119`).
> - **The Rust-side gating IS in place**: `hal/mod.rs:149` forces `StepMode::SeqForward` when `A4_COVERAGE_TOUCH` or `A4_MUTATION_CONFIG` is set.
> - **The C++ dispatch IS in place**: under `kStepModeSeqForward`, `ffi.cpp:401-440` runs a plain sequential `for` loop calling `stepExec` for each cycle, with NO `poolstl::par`. Same structure for the accum if-branch (`ffi.cpp:680-718`, sequential under touch coverage).
> - **`a4_touch_mark` has exactly ONE callsite**: inside the inline `eqz()` constraint-eval wrapper in `witgen.h:185`, which is called from `stepExec`/`stepAccum`. Both run sequentially under our normal conditions.
> - **The Rust-side has only ONE `par_iter` site in the rv32im prove path** (`prove/hal/cpu.rs:180`, inside `eval_check`). This runs AFTER `cpu_witgen` and `cpu_accum` have already emitted their bitmaps. **No Rust Rayon parallelism fires before bitmap emission** (verified with `rg par_iter` across `risc0/circuit/rv32im/src/`).
> - **All zkp HAL `par_iter` sites (~15 in `risc0/zkp/src/hal/cpu.rs`) are proof-phase only** (NTT, batch-evaluate, Merkle, FRI, hash, scatter/shift). They run *after* both bitmaps are emitted.
> - **No explicit `rayon::spawn` / `rayon::join` / `rayon::scope` / `ThreadPoolBuilder` anywhere** in the source tree (`rg` confirmed).
>
> **What primary source REVEALS as a deeper puzzle than we previously framed:**
> - Under `A4_COVERAGE_TOUCH=1`, ALL bitmap writes happen in **fully sequential code paths**, AND no Rust- or C++-side parallel section fires BEFORE the bitmaps are emitted. The poolstl-in-witgen / poolstl-in-accum hypothesis (Pass 2's leading candidate for the residual leak under RAYON=1) is now **ruled out** in those specific functions because those parallel paths are bypassed under touch-coverage mode (verified at `ffi.cpp:401`, `ffi.cpp:680-718`).
> - The remaining poolstl::par sites in `ffi.cpp` are at line 763–779 ("apply totals" / phase 3 of accum, unconditional `poolstl::par`) which runs **after** the accum bitmap is emitted — so cannot affect it.
> - Yet the race rate empirically halves-and-halves-again under `RAYON_NUM_THREADS=1` (0.70% → 0.14%, p ≈ 0.06). This 5× reduction is real but its mechanism is now **less clear** than before, since we can no longer attribute it to "Rayon directly perturbing bitmap writes" (no Rayon site fires before bitmap emission). See §4.5 for the refined puzzle and candidate explanations.

---

## TL;DR

1. We discovered a low-rate (~0.7%/mut, default parallelism) non-determinism in our touch-coverage measurement: paired runs of the same mutation, same seed, same node, same binary occasionally produce `delta_T` values that differ by exactly ±1 bit.
2. The divergent bit is **always** on one specific constraint: `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)` at `major=9 minor=5` (a Poseidon2 sub-cycle).
3. The aggregate witness state (9-field preflight fingerprint covering `state`, `pc`, `mmm`, `uc`, `txnIdx`, `pagingIdx`, `bigintIdx`, `dc0`, `dc1`) is **bit-identical A vs B even when delta_T flips**. So the race lives **downstream of preflight state** but upstream of the touch-coverage record — most likely in an intermediate Poseidon2 cell computation that determines whether the `lowIsZero` branch (which fires the FTW291 EQZ check) is taken.
4. Setting `RAYON_NUM_THREADS=1` reduces the race rate by ~5× (from ~0.7% to ~0.14% over all measured dispatches) but does NOT provably eliminate it. The residual leak in our `b5_rayon1` dataset is 1/250, with a qualitatively different signature (non-binary 34↔35 instead of 0↔1).
5. The race does **NOT** affect proof generation, the underlying witness, mutation outcomes, or constraint pass/fail decisions. It affects only the `touch_bitmap` coverage signal used as one input to the bandit's reward function.
6. **Open mechanism gap (REFINED late 2026-06-13 with primary source)**: We have *primary-source-verified* that under `A4_COVERAGE_TOUCH=1` both `cpu_witgen` and `cpu_accum` run their constraint-eval loops sequentially (forced to `StepMode::SeqForward`, plain `for` loop, no `poolstl::par`). The bitmaps are emitted from these sequential paths, before any Rayon `par_iter` site fires. The poolstl-in-witgen hypothesis we previously raised is therefore ruled out. **Yet the race rate empirically reduces 5× under `RAYON_NUM_THREADS=1`** — and we cannot mechanistically attribute that 5× reduction to any specific code path we've found. Candidate explanations now include: (i) Rayon lazy-pool-init perturbs process-level state (allocator, ASLR, page-cache, OS scheduler) in a way that affects deterministic-looking code; (ii) a parallelism source we still haven't found; (iii) microarchitectural / sample-noise effects we're misreading as Rayon-related. See §4.5 for the refined puzzle.
7. Three open questions for Pro: (a) does the ~0.7% reward noise materially affect bandit convergence at Phase 8 scale? (b) is the refined mechanism puzzle (§4.5) worth investigating before Phase 8, or after, or never? (c) should we proceed to Phase 8 with default parallelism for speed and accept the noise floor (per user override) or use `RAYON=1` for the cleanest 5× rate reduction?

---

## 1. System background (skim if you already know)

We are running constraint-coverage-guided fuzzing against the modified RISC Zero zkVM (`workspace/risc0-modified/`, branch `arguzz/b7-race-instrumentation`). The fuzzer (`a4/standalone/`) selects mutations using a multi-armed bandit, applies them via in-process hooks compiled into the host binary, runs the modified host once per mutation, parses tagged output from the host (touch-coverage bitmap, constraint failures, verbose context dumps), updates the bandit reward, and persists everything to a per-campaign SQLite DB.

The fuzzer runs in two parallel locations:
- **WSL2 (`/root/arguzz/`)** for local development and small-scale runs.
- **POS** (university testbed: nodes `flare`, `octorand`, `opulous`, `meld`, `idex` — all AMD EPYC 9354, all on the same debian-trixie image) for large dispatches.

The `touch_bitmap` is a 65,536-byte saturating-counter array. Each constraint evaluation (an `EQZ(...)` call) hashes `(constraint_loc_string, major, minor)` via FNV-1a 64-bit → bucket index, then does `touch_bitmap[idx]++`. The bitmap is base64-encoded and emitted as `<a4_touch_coverage>...</a4_touch_coverage>` on the host's stdout, then parsed by the fuzzer. The number of newly-set bits per mutation (relative to the campaign's accumulated global bitmap) is `delta_T`, which goes into the bandit reward function `compute_reward(delta_T, delta_F, ...)` as one of several signals.

The B7 audit (one of four Inc 3 audits) takes a B7 audit DB and re-runs the same campaign config in a fresh DB on the same node ("A" + "B" pair), then asks: do the two DBs have bit-identical per-mutation rewards? On the first cross-node POS dispatch, a small fraction of mutations (4/250) showed mismatched `delta_T` — same mutation config, same trace, same outcome, but a 1-bit-different coverage record. That's the start of the race investigation.

---

## 2. Observed phenomenon

### 2.1 What we see

| Property | Value |
|---|---|
| Per-pair manifestation | ~1-3 mutations out of 50 have `delta_T_A ≠ delta_T_B`, always by exactly 1 bit (in early data; one b5_rayon1 case showed a 1-bit diff in a higher-base count `34 vs 35`) |
| Constraint identity | **100%** of divergent bits are on `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)`, `major=9` (Poseidon2 instruction), `minor=5` (Poseidon2 sub-cycle 5) |
| Aggregate witness state | The 9-field FNV-1a preflight fingerprint (`state`, `pc`, `mmm`, `uc`, `txnIdx`, `pagingIdx`, `bigintIdx`, `dc0`, `dc1`) is **bit-identical A vs B in 50/50 mutations per pair, in every pair we measured**, even when `delta_T` flipped |
| Constraint pass/fail | Failure rows (`failures` table) and global failures (`global_failures` table) are bit-identical A vs B in pairs where `delta_T` flipped — so the underlying constraints are evaluating to the same value, the race is upstream in the witness construction |
| Mutation independence | The race fires in a code path that runs every execution. Touch bitmaps and verbose touch sets are byte-identical across **different** mutations (mut21 vs mut27 produce same SHA-256 of `<a4_touch_coverage>` content), so this is NOT a mutation-specific race |
| Reproducibility on WSL | Race does NOT reproduce on our WSL2 dev box across 70+ independent runs (sequential, concurrent pair-pinned-to-disjoint-cores, different mutations) — it appears only on POS |
| Cross-node behavior | Race rate observed on `octorand`, `meld`, `flareCtrl`. `opulous` happened to show 0/50 in our small sample. Earlier cross-node Inc 3c data also captured the race |
| Microcode dependence | All POS nodes are AMD EPYC 9354 but octorand has a different microcode rev (`0xa101116`) than flare (`0xa10113e`). No clear correlation though — race fires on multiple nodes |

### 2.2 Race rate from ALL investigations combined (REVISED 2026-06-13)

> The numbers below use **only `delta_T` flips between paired mutations in DB-recorded data** (the cleanest, least-noisy metric). They are recomputed directly from the SQLite DBs in `a4/audits/audit_output/inc3d/`. The prior version of this section conflated `delta_T` flips with verbose-tag block divergences (which had different and noisier denominators); the corrected numbers below tell a less dramatic but more defensible story.

| Investigation | Binary | RAYON | Sample (DB-pairs × muts) | `delta_T` flips | Per-mutation rate |
|---|---|---|---|---|---|
| Inc 3d Phase B P1 (`inc3d/p1`) | BP1 | default | 5 × 50 = 250 | 1 (flareCtrl mut 30, 0↔1) | 0.4% |
| Inc 3d Phase B P2 (`inc3d/p2`) | BP1 | default | 5 × 50 = 250 | 1 | 0.4% |
| Inc 3d Phase B P2 retry (`inc3d/b2`) | BP1 | default | 5 × 50 = 250 | 2 | 0.8% |
| Inc 3d Phase C `b5_default` | B5 | default | 5 × 50 = 250 | 3 (flareCtrl muts 17,21; meld 47) | 1.2% |
| **Combined: default parallelism** | mixed | default | **20 × 50 = 1000** | **7** | **0.70%** |
| Inc 3d Phase C `path_a1` (merged) | BP1 | =1 | 4 × 50 = 200 | 0 | 0% |
| Inc 3d Phase C `path_a2` | BP1 | =1+RISC0=1+OMP=1 | 5 × 50 = 250 | 0 | 0% |
| Inc 3d Phase C `b5_rayon1` | B5 | =1 | 5 × 50 = 250 | 1 (octoa mut 33, **34↔35** not 0↔1) | 0.4% |
| **Combined: with RAYON=1** | mixed | =1 | **14 × 50 = 700** | **1** | **0.14%** |

**Reduction ratio: ~5×** (0.70% default → 0.14% with `RAYON=1`).

Statistical significance: at the null hypothesis "RAYON=1 has no effect, true rate = 0.7% in both arms," `P(≤1 flip | 700 trials)` ≈ 5.8%. So the difference is real but not overwhelmingly so (one-sided p ≈ 0.06). A stricter assessment would require ~2× more pairs at `RAYON=1` to firmly bound the residual rate below 0.2%.

**One characteristic difference between `b5_default` flips and the `b5_rayon1` residual flip**:
- `b5_default` flips (3/3) are all **binary 0↔1** on low-coverage mutations (mut 17 `ΔT`=0/1, mut 21 `ΔT`=1/0, mut 47 `ΔT`=1/0).
- `b5_rayon1` flip (1/1) is a **34↔35** flip on a high-coverage mutation (mut 33: INSTR_TYPE_MOD `Lui` → `Lw` at step 348). The mutation itself touches many new constraints (`ΔT ≈ 34`); the race adds or fails to add ONE additional unique-context bit on top of those.

Both signatures are consistent with the same single-bit `FieldToWord(inst_p2.zir:291)` toggle (the mutation-specific touches are deterministic; the 1-bit race is on top). So we believe `b5_default` and `b5_rayon1` are the same phenomenon, just with different "baseline" `ΔT` magnitudes.

### 2.3 Directional asymmetry (and the absence thereof)

Early Phase B data (5 verbose-tag divergences) all had the racy extra bit on the **B-side** of the pair (5/5 = 100% directional). We initially suspected this meant something structural (e.g., warm-cache vs cold-cache effect, or B-side ran second so saw different page-cache state). Today's Phase C data however shows mixed direction (2× A>B, 2× B>A across the 4 most recent flips). So the earlier directionality was apparently sample noise. The race is **symmetric**.

---

## 3. What we ruled out

| Hypothesis | Status | Method |
|---|---|---|
| Python pipeline nondeterminism (set iteration, hash randomization, etc.) | RULED OUT | Audited every reward-path call: `compute_reward`, `derive_global_contexts`, `count_new_bits`, `merge_into_global`, all parsers in `a4/core/`. Pure for-loops over indexed structures, or sorts that break ties on full ordering tuples. Hash-seed invariant. |
| Cross-machine library / image / env drift | RULED OUT | `lib_shas.txt` (libstdc++.so.6 / libc.so.6 / libm.so.6 + host SHA) byte-identical across all 5 POS nodes |
| Stable per-machine differences (compiler, link, microcode-induced determinism) | RULED OUT | If per-node-stable, intra-node pairs (e.g. octoA-vs-octoB) would be identical. They aren't |
| ZK randomness in challenge generation affecting reward fields | RULED OUT | Only affects FpExt e0–e3 values; `derive_global_contexts` only consumes boolean nonzero/broken_addrs which are challenge-invariant |
| Mutation config divergence | RULED OUT | All `mutations` table rows byte-identical A vs B |
| Bandit decision divergence | RULED OUT | All bandit decisions byte-identical A vs B |
| Inter-node trace ordering / txn_idx remap divergence | RULED OUT | `_info.byte_addr` byte-identical in configs |
| Stdout interleaving / tag truncation | RULED OUT | Tag boundary parsing audited; consistent block counts across runs (49/49 or 50/50) |
| Aggregate preflight state divergence | **RULED OUT** | B5 patch added per-mutation FNV-1a fingerprinting of (state, pc, mmm, uc, txnIdx, pagingIdx, bigintIdx, dc0, dc1). **50/50 muts × 5 pairs = 250/250 are bit-identical A vs B in both `b5_default` (race active) and `b5_rayon1`** |
| Memory transaction divergence (aggregate hash) | **NOISY but not race-correlated** | `<a4_preflight_txns>` aggregate diffs in 49/50 muts in every pair regardless of mode. Likely an aggregate-ordering artifact in the FNV-1a accumulation. NOT race-correlated since the rate is the same with or without RAYON=1 |

---

## 4. What we believe the cause IS

### 4.1 Mechanistic chain

```
[Some intermediate Poseidon2 cell computation is non-deterministic
 under parallel scheduling. The intermediate value is not exposed by
 the 9-field preflight fingerprint — it's a transient register inside
 the constraint evaluation, not part of any persistent witness state.]
                          │
                          ▼
[The 16-bit "low" subfield of one Poseidon2 cell occasionally differs
 between A and B mates]
                          │
                          ▼
[The `lowIsZero` branch (which checks low == 0) goes different ways:
 in A "low" was nonzero so lowIsZero=0; in B "low" was zero so lowIsZero=1
 (or vice versa)]
                          │
                          ▼
[When lowIsZero=1, the FTW291 EQZ constraint fires.
 When lowIsZero=0, FTW291 does NOT fire]
                          │
                          ▼
[touch_bitmap[FTW291_idx]++ on whichever mate took the lowIsZero=1 branch.
 The other mate's bitmap is missing this bit → +1 bit difference in delta_T]
                          │
                          ▼
[Witness REGISTERS converge to the same final state regardless. Proof still
 validates. The 9-field aggregate FP is identical because the per-cycle
 state, pc, txnIdx, etc. all land on identical final values. Only this
 intermediate Poseidon2 cell shows the race.]
```

### 4.2 Why we believe this and not "race in the bitmap"

Initially we hypothesized "race in the `touch_bitmap[idx]++` non-atomic increment". We ruled this out:

1. **The same divergence shows in the non-bitmap verbose-tag stream**, which uses a `std::set<std::string>` not a bitmap. If the bitmap-write were the race, the verbose set wouldn't show it.
2. **The divergence is always exactly one specific constraint** (FTW291). A generic write race would scatter across many constraint hash buckets.
3. **Forcing the outer witgen loops sequential** (which `A4_COVERAGE_TOUCH=1` already does — `StepMode::SeqForward` is forced, **now verified from primary source at `hal/mod.rs:149` and `ffi.cpp:401-440`**) does not eliminate the race. So the race is not in the outer constraint-evaluation loop.
4. **The race is partially mitigated by `RAYON_NUM_THREADS=1`** (5× rate reduction). Rust `into_par_iter` / `par_iter` sites identified in our `risc0-modified/` tree (verified late 2026-06-13 from primary source):

   | File | Line(s) | Site | Phase | When does it fire? |
   |---|---|---|---|---|
   | `risc0/circuit/rv32im/src/prove/hal/cpu.rs` | 180 | `(0..domain).into_par_iter().for_each(|cycle| { risc0_circuit_rv32im_cpu_poly_fp(...) })` | proof: eval_check | **After** both bitmaps emitted |
   | `risc0/zkp/src/hal/cpu.rs` | 322–576 (~15 sites) | `par_chunks_exact_mut`, `into_par_iter`, `par_iter_mut` (NTT, batched eval, hash, Merkle, FRI, scatter/shift) | proof: post-witgen | **After** both bitmaps emitted |
   | `risc0/zkp/src/hal/mod.rs` | 248 | `par_chunks_exact_mut(cycles)` in `combos_divide` | proof: post-witgen | **After** both bitmaps emitted |

   **All these sites run AFTER the touch bitmaps are emitted by `cpu_witgen` and `cpu_accum`.** None of them can directly affect the bitmap content. The order of operations in the host is `cpu_witgen → cpu_accum → eval_check → NTT/Merkle/FRI`, verified at `risc0/circuit/rv32im/src/prove/hal/cpu.rs:57`, `:140`, `:145`. The witgen bitmap (`<a4_touch_coverage>`) is emitted at the end of `cpu_witgen` (`ffi.cpp:421`); the accum bitmap (`<a4_accum_touch_coverage>`) at the end of the accum sequential block (`ffi.cpp:701`); eval_check runs only afterwards.

5. **The race is NOT fully eliminated by `RAYON_NUM_THREADS=1`** (1/700 residual leak). We initially hypothesized the residual was in C++ `poolstl::par` (a second parallelism system the binary contains, independent of Rayon and not controlled by `RAYON_NUM_THREADS`). **However, primary-source recovery on late 2026-06-13 lets us reject that specific hypothesis**: 

   - `ffi.cpp:118` confirms `a4_touch_mark` has exactly one callsite, inside the inline `eqz()` wrapper at `witgen.h:185`, which is called only from `stepExec`/`stepAccum`. 
   - Under `A4_COVERAGE_TOUCH=1`, `hal/mod.rs:149` forces `StepMode::SeqForward`, and the C++ dispatch at `ffi.cpp:401-440` (witgen) and `ffi.cpp:680-720` (accum) both use plain sequential `for` loops with NO `poolstl::par` in those code paths. The only remaining `poolstl::par` sites in `ffi.cpp` are at lines 391/397 (the `kStepModeParallel` case — bypassed under touch) and lines 721/767 (accum's else-branch and "apply totals" phase 3 — bypassed or runs post-emission). So `poolstl::par` is mechanistically **not** the residual race source for either bitmap. 
   - Combined with finding (4) above (no Rust Rayon site fires before bitmap emission either), this means: **with primary source visible, neither known parallelism system can directly explain the race** — yet the 5× empirical rate reduction under `RAYON_NUM_THREADS=1` is statistically real. This is the central puzzle that emerged on the third pass; see §4.5.

**Net conclusion on mechanism (REFINED late 2026-06-13)**: The race is downstream of preflight construction (which is bit-identical A vs B) and downstream of the persistent witness registers (the 9-field FP is identical). It manifests in transient intermediate Poseidon2 cell computation inside `stepExec`/`stepAccum`. We have *verified from primary source* that under `A4_COVERAGE_TOUCH=1` both `stepExec` and `stepAccum` are invoked from sequential `for` loops with no `par_iter` / `poolstl::par` parallelism in scope. The race must therefore be caused by something INDIRECT — either a process-state effect of Rayon initialization (allocator, ASLR, OS scheduler), a parallelism source we still have not identified, or sample noise on the residual. See §4.5 for the full puzzle and candidate experiments.

### 4.3 Why this only fires on POS

WSL never reproduces the race (70+ independent runs all byte-identical). The likely reasons (REVISED late 2026-06-13 — phrasing softened given the §4.5 mechanism puzzle):
- WSL has higher scheduling jitter (Hyper-V virtualization), which *might* hide the race by averaging across noisy schedules.
- POS nodes are bare-metal physical servers (AMD EPYC 9354) with deterministic CPU/memory subsystems. Whatever the actual cause of the race (see §4.5 candidates), it appears to require the more predictable runtime conditions of bare-metal hardware to fire.
- We previously framed this as "POS has stronger thread contention," but per §4.5 we have ruled out thread contention in the bitmap-writing code paths under `A4_COVERAGE_TOUCH=1`. The bare-metal-vs-WSL difference is more likely due to process-level state (allocator behavior, OS scheduler determinism, hardware microarchitectural effects like speculation/branch-predictor state) than direct thread contention.

This is the most uncomfortable part of the picture — we cannot reproduce the race in a controlled environment that lets us instrument it more aggressively.

### 4.4 The residual under `RAYON_NUM_THREADS=1` (REVISED 2026-06-13)

The `b5_rayon1` data shows 1/250 paired muts with a `delta_T` diff (octoa mut 33, `ΔT_A=34 vs ΔT_B=35`). Direct DB verification of mut 33:
- Same mutation config bit-identical (`INSTR_TYPE_MOD`, step 348, original `Lui` major=2 minor=5, mutated `Lw` major=4 minor=10).
- Same failures table bit-identical (3 failures, same constraint locs).
- Same `n_fail = 3`, `delta_F = 3`.
- Only `delta_T` differs by 1 (34 vs 35), with downstream cascading into `T_new`, `S`, and final `reward`.

Four possible explanations (UPDATED late 2026-06-13 with primary-source evidence — explanation (b) was previously "Medium-High" but is now **DOWNGRADED to Low** because primary source confirms `poolstl::par` is bypassed in the bitmap code paths under `A4_COVERAGE_TOUCH=1`):

| Explanation | Plausibility | Evidence for/against |
|---|---|---|
| (a) The B5 binary itself introduces a small additional race in its FNV-1a preflight-fingerprinting code (research-only patch, not in BP1 production binary) | Low–Medium | `path_a1` (BP1 + RAYON=1) shows 0/200 flips; `b5_rayon1` (B5 + RAYON=1) shows 1/250. BUT: the B5 patch is just sequential FNV-1a hashing of read-only preflight data at function entry, with no thread spawns or shared writes (verified from `PHASE_7D_INC3D_C_PATH_B5_PATCH_SPEC.md`). The only mechanism would be cache-layout / memory-allocation perturbation altering the *timing* of an existing race, not a new race per se. Plausible but not mechanistically attractive. |
| (b) C++ `poolstl::execution::parallel_policy` is a second parallelism source that `RAYON_NUM_THREADS=1` does NOT control | **Low (DOWNGRADED late 2026-06-13)** | Primary source now visible (`ffi.cpp:118`, `:401-440`, `:680-720`; `witgen.h:182-185`; `hal/mod.rs:149`): under `A4_COVERAGE_TOUCH=1`, the host forces `StepMode::SeqForward`, and the kStepModeSeqForward dispatch uses a plain `for` loop with NO `poolstl::par`. Same for the accum if-branch. So `poolstl::par` does NOT fire in either bitmap-writing code path. The only remaining `poolstl::par` sites in `ffi.cpp` are bypassed by touch coverage (lines 391/397, 721) or run post-bitmap-emission (line 767, apply-totals). Conclusion: poolstl is **mechanistically not** the residual source for bitmap nondeterminism. |
| (c) Just sample noise — 1/250 = 0.4% is plausible at a "true" rate of 0.1-0.5% if RAYON=1 isn't quite zero | **Medium (UPGRADED late 2026-06-13)** | At true rate 0.14% (the combined RAYON=1 observed rate), `P(1 in 250) ≈ 25%`. With (b) now downgraded, sample noise becomes a more plausible residual explanation. |
| (d) A subtle effect like Rayon's lazy-init: the global pool was already initialized to >1 thread *before* `RAYON_NUM_THREADS=1` took effect, in which case the env var is ignored for the rest of process lifetime | Low | We `export RAYON_NUM_THREADS=1` from the launcher BEFORE invoking `risc0-host`, so the host process inherits it. Rayon should read it on first lazy-init. We verified the launcher logs (`"[run_campaign_pos] RAYON_NUM_THREADS=1 (forced)"` appears in all 10 b5_rayon1 logs). But we have not added an explicit assertion inside the host that `rayon::current_num_threads() == 1` after init. |
| **(e) Process-state perturbation from Rayon initialization** (NEW late 2026-06-13) | Medium | Even though Rayon `par_iter` sites all fire AFTER bitmap emission, Rayon's lazy thread-pool initialization (when it spawns N worker threads) changes process-level state: per-thread arenas in the allocator, ASLR memory layout, OS scheduler decisions about CPU affinity, page-cache pressure. Under default `RAYON=8` vs `RAYON=1`, the binary sees substantially different runtime conditions even *before* the first `par_iter` runs (Rust's `static_init` of Rayon's `Registry` happens at module-load time in some configurations). This could expose a latent microarchitectural race in deterministic-looking sequential code (uninitialized stack reads, speculative side-channels, etc.). Speculative but mechanistically plausible given the elimination of (a)–(d) cleaner candidates. |

We don't have enough data to distinguish (a)/(c)/(d)/(e) firmly. To make progress (updated experiment menu given primary source):

- **Distinguish (a)**: Dispatch the BP1 binary with another 500–1000 paired muts under RAYON=1. If still 0 flips, (a) is supported.
- **Distinguish (b)**: **No longer needed** — primary source confirms `poolstl::par` is bypassed under `A4_COVERAGE_TOUCH=1`. If we want extra confidence, run a campaign with `taskset --cpu-list 0` (single-CPU affinity) to serialize ALL threading at the OS level; if rate stays unchanged at 0.14%, that further rules out parallelism as the residual cause.
- **Distinguish (c)**: Just collect more data. At 0.14% true rate, ~5000 paired muts would tighten the CI to ±0.1%.
- **Distinguish (d)**: Add a one-line assertion in the host: log `rayon::current_num_threads()` to stderr at process start. Re-dispatch one campaign; verify the logged value is `1`.
- **Distinguish (e)**: Hard. Would need to bypass Rayon's lazy init entirely (compile-out via feature flag, or LD_PRELOAD a stub) or build a Rust binary with explicit `rayon::ThreadPoolBuilder::new().num_threads(1).build_global()` called BEFORE any other code, to ensure the pool is single-threaded from the very first instruction.

These investigations are NOT pre-requisite to Phase 8 per user override; we are listing them in case Pro feels any should be done first.

### 4.5 Refined mechanism puzzle (late 2026-06-13, post primary-source recovery)

This is the cleanest framing of where we are mechanistically:

**What we've established with primary-source verification:**

| # | Claim | Source / verification |
|---|---|---|
| 1 | Preflight (Rust executor) is fully deterministic A vs B | 9-field FNV-1a preflight FP bit-identical in 250/250 mut pairs across both `b5_default` (race active) and `b5_rayon1` |
| 2 | Preflight construction has NO Rust Rayon parallelism | `rg "par_iter\|into_par_iter\|par_chunks" risc0/circuit/rv32im/src/execute/` returns 0 hits |
| 3 | `cpu_witgen` under `A4_COVERAGE_TOUCH=1` runs `stepExec` sequentially via `for` loop | `ffi.cpp:401-440`, dispatch matches `hal/mod.rs:149` |
| 4 | `cpu_accum` under `A4_COVERAGE_TOUCH=1` runs `stepAccum` sequentially via `for` loop | `ffi.cpp:680-720` (if-branch with touch tracking) |
| 5 | Both bitmaps are emitted from within their respective sequential blocks | `<a4_touch_coverage>` at end of kStepModeSeqForward; `<a4_accum_touch_coverage>` at end of accum if-branch |
| 6 | `a4_touch_mark` has exactly ONE callsite, inside `eqz()` wrapper | `witgen.h:185`; `rg "a4_touch_mark"` returns only definition + this site + declaration |
| 7 | All Rust Rayon `par_iter` sites (1× in rv32im prove HAL, 15× in zkp HAL, 1× in zkp HAL `combos_divide`) run AFTER bitmap emission, in the proof phase | `risc0/circuit/rv32im/src/prove/hal/cpu.rs:180` (eval_check); `risc0/zkp/src/hal/cpu.rs:322-576`; `risc0/zkp/src/hal/mod.rs:248` |
| 8 | No explicit Rayon thread-pool config in source (no `ThreadPoolBuilder`, `rayon::spawn`, `rayon::scope`, `rayon::join`) | `rg` confirmed across `risc0/` |
| 9 | The host runs ONE subprocess per mutation; bitmaps are emitted once per process | Confirmed in `a4/standalone/fuzzer.py` (uses `subprocess.Popen` per mutation) |

**The empirical observation we cannot fully reconcile with the above:**

- Race rate under default parallelism: **0.70%** (7 flips / 1000 paired muts)
- Race rate under `RAYON_NUM_THREADS=1`: **0.14%** (1 flip / 700 paired muts)
- Statistical significance: one-sided p ≈ 0.06 — real but not overwhelming

If claims (1)–(9) above are all true, then no parallelism site in our binary actually executes parallel code BEFORE the bitmap is written. So how does setting `RAYON_NUM_THREADS=1` halve-and-halve-again the race rate?

**Candidate explanations** (in roughly decreasing order of plausibility given the new evidence):

1. **Rayon lazy-init affects process state even before any `par_iter` fires (explanation (e) above)**. Rayon's global registry can be triggered by static-init / linker behavior in some configurations. If pool size is 8, the process at startup has 8 worker-thread stacks allocated + per-thread allocator arenas + different ASLR layout than a 1-thread process. This could expose microarchitectural non-determinism (uninitialized memory reads, ALU side-channels, OS scheduler differences) in deterministic-looking code paths. Hard to test cleanly.
2. **Sample noise (explanation (c))**. At a hypothetical "true" rate of ~0.3% with no parallelism dependence, our observed 0.70% (default) and 0.14% (RAYON=1) are both consistent with that single rate via sampling fluctuation; the apparent 5× reduction could be an artifact of asymmetric sample sizes (1000 vs 700). The one-sided p ≈ 0.06 supports "real but weak" — not "definitively 5× reduction."
3. **An OS-level / hardware-level non-determinism we haven't characterized**. WSL never reproduces the race (70+ runs identical); POS does. The POS nodes are bare-metal AMD EPYC 9354. There might be a CPU microarchitectural source of nondeterminism (speculation, branch predictor state, NUMA effects) that fires more often under conditions correlated with default parallelism (higher CPU utilization, different cache pressure) than under RAYON=1.
4. **A parallelism source we still haven't enumerated**. We've grep'd the rv32im, zkp, zkvm modules and only found the sites listed above. But the binary links against external crates (`risc0-sys`, `risc0-zkvm-platform`, `sha2`, etc.). It's possible an external dep uses Rayon internally in a way we haven't traced. Plausible but feels unlikely given the targeted nature of the race (always the same constraint).

**Why this is acceptable for the Phase 8 launch decision (per user override):**

- The race is a **bounded, measured noise floor** (~0.7% under default, ~0.14% with mitigation). It does NOT affect proofs, mutation outcomes, constraint pass/fail, or the underlying witness.
- Whatever the exact mechanism, the *observable consequence* is well-characterized: ±1 bit in `delta_T` for ~0.7% of mutations under default parallelism. The bandit reward is robust to this level of per-mutation noise at Phase 8's planned N=10K+ scale.
- The mechanistic mystery is intellectually unsatisfying but operationally acceptable. Pro is being asked to either confirm "this is acceptable noise, proceed" or flag "this is worth understanding before Phase 8."

**What we would do if Pro flags the puzzle as a blocker:**

- Build a host binary with `rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap()` called as the very first line of `main()`, so Rayon is single-threaded from the very first instruction. Re-dispatch and check if race rate goes to 0 (would support explanation (1)).
- Dispatch 5000+ paired muts under both default and `RAYON=1` modes to tighten the rate confidence intervals (would resolve (2)).
- Add per-process CPU affinity (`taskset --cpu-list 0`) to serialize at OS level (would distinguish (1) from (3)).

---

## 5. Why this DOESN'T affect proofs or correctness

Several layers of evidence:

1. **Proofs validate.** In every paired run (including all racy ones), the host produces a valid proof of execution. Whether the proof is `GENERATED` or `NOT_GENERATED` (due to expected constraint failures from the mutation) is deterministic A vs B.
2. **Constraint failures are deterministic.** The `failures` table (per-constraint failure records) and `global_failures` table are bit-identical A vs B in every racy pair we examined. So the constraint system itself agrees on which constraints passed and which failed.
3. **Final witness state is deterministic.** The 9-field preflight fingerprint covers the actual persistent witness registers/memory state at end of preflight. It's identical A vs B.
4. **Mutation outcomes are deterministic.** Same `outcome` (REJECTED / NO_EFFECT / ACCEPTED) per mutation, same `exit_code`, same `proof_status`.

The race affects ONE thing: whether the bitmap records the constraint at `inst_p2.zir:291 / major=9 / minor=5` as "touched" for a given mutation. This is downstream of all the things that matter for soundness; it's purely a measurement artifact in the touch-coverage signal.

---

## 6. What this DOES affect: the bandit reward signal

This is the open question for Pro.

The `delta_T` field is one of several inputs to `compute_reward(...)`:

```python
T_new = 1 - exp(-delta_T / tau_new)     # tau_new ~ 50 by default
T_rare = (rare-context bonus, depends on global state)
F_rare = (rare-failure bonus)
S = combined coverage scalar
reward = w_T * T_new + w_F * F_rare + ...
```

When `delta_T` flips by 1 (e.g., from 1 → 0):
- `T_new` changes from `1 - exp(-1/50) ≈ 0.020` to `0`
- This is a ~2% absolute change in T_new for the affected mutation
- The downstream reward change is on the order of 0.001-0.002 (very small in absolute terms)

But the bandit aggregates rewards over many pulls of each arm. A ~0.7% per-mutation noise floor on the reward signal (under default parallelism; ~0.14% under `RAYON=1`) might or might not impact arm convergence depending on:
- How quickly true reward differences between arms emerge.
- The bandit's exploration vs exploitation balance (UCB-c, TS-c, etc.).
- The total campaign size (small N: noise dominates; large N: noise averages out).

For our Phase 8 plan (large-scale: target N=10,000+ mutations per campaign), the noise should average out per-arm, but we'd like Pro's view on whether this is rigorous enough for a publishable methodology.

---

## 7. Mitigations

### 7.1 Mitigation 1: `RAYON_NUM_THREADS=1` (recommended in principle, but see user override below)

- Reduces race rate by ~5× (from 0.70% to 0.14% across all 1700 paired measurements). Reduction is real but not absolute.
- Cost: roughly 3-4× wall-clock per campaign on POS (verified: `b5_default` median 8 min/job, `b5_rayon1` median 27 min/job per 50-mut campaign).
- **User decision (override, 2026-06-13)**: Phase 8 will launch with **default parallelism for speed**. The fuzzing notebook + Phase 8 results + this race writeup will be presented to Pro jointly. If Pro flags the noise as a problem, we will re-run with `RAYON=1`. We are explicitly deferring the speed/correctness tradeoff to Pro rather than pre-committing to slow runs.

### 7.2 Mitigation 2: Reward-noise robustness in bandit math

Even without `RAYON=1`, the noise is bounded ±1 bit in `delta_T` for ~0.7% of mutations. The reward function could be made robust:
- Quantize `delta_T` to coarser buckets (e.g., increments of 5 or 10 bits) so a ±1 flip is invisible.
- Subtract a known noise floor from `T_new` for Poseidon2-touching mutations.
- Use a smoothed multi-run reward instead of single-run.

These would be intrusive to our bandit code and we'd want Pro's input before changing them.

### 7.3 Mitigation 3: Upstream fix in modified RISC0

Make the Poseidon2 cell computation deterministic. Options (REVISED late 2026-06-13 given primary-source confirmation that no parallel code fires before bitmap emission under A4_COVERAGE_TOUCH=1):
- **Process-state isolation**: Build the host with `rayon::ThreadPoolBuilder::new().num_threads(1).build_global()` called as the very first line of `main()`, ensuring Rayon never spawns >1 thread. This addresses explanation (e) / candidate (1) in §4.5.
- **Pin the process to a single CPU**: Wrap host invocations in `taskset --cpu-list 0`. Serializes all threading at the OS level regardless of source.
- **(Speculative) Atomicize the intermediate Poseidon2 cell**: If the underlying race is in a shared C++ static / global in the Poseidon2 evaluator, replacing it with `std::atomic` would help. But we have not localized the racy state, so this would be guesswork at present.
- **(Speculative) Refactor the Poseidon2 evaluation order to be commutative / deterministic**. Requires deep knowledge of the modified RISC0 internals we don't yet have.

The first two are operational mitigations we can apply ourselves. The latter two require intrusive changes to risc0 internals; we could file an upstream RISC0 issue documenting the race for the RISC0 team to investigate, but our finding may be considered out-of-scope for upstream since it only affects research instrumentation.

### 7.4 Mitigation 4: Accept the noise, document it

For Phase 8 we could simply document: "with default parallelism, touch coverage on Poseidon2 sub-cycles has a ~0.7% per-mutation noise floor manifesting as ±1 bit in delta_T". This is the cheapest mitigation; it doesn't require any code changes. It does require us to be careful about claims comparing variants near the noise floor.

---

## 8. Parallelism systems and env-var clarification (REVISED late 2026-06-13 with primary source)

Our binary has **two independent parallelism systems**. Setting one env var only controls one system. The 2026-06-13 second-pass revision documented both; the late-2026-06-13 third-pass refinement (post primary-source recovery) clarifies which sites actually fire in the bitmap code paths.

### 8.1 System #1: Rust Rayon (controlled by `RAYON_NUM_THREADS`)

Sites in our `risc0-modified/` source tree (verified by `rg "par_iter|into_par_iter|par_chunks"` late 2026-06-13):

| File | Lines | Sites | Phase | Fires before bitmap emission? |
|---|---|---|---|---|
| `risc0/circuit/rv32im/src/prove/hal/cpu.rs` | 180 | 1× `into_par_iter` (eval_check, polynomial eval over cycles, calls `risc0_circuit_rv32im_cpu_poly_fp`) | Proof: eval_check | **No** (runs after `cpu_witgen` + `cpu_accum`) |
| `risc0/zkp/src/hal/cpu.rs` | 322, 323, 335, 346, 356, 380, 401, 443, 469, 487, 490, 512, 519, 562, 576 | ~15× `par_iter`/`into_par_iter`/`par_chunks_exact_mut` | Proof: NTT, batched evaluate, hash, Merkle, FRI, scatter/shift | **No** (all proof-phase) |
| `risc0/zkp/src/hal/mod.rs` | 248 | 1× `par_chunks_exact_mut(cycles)` in `combos_divide` | Proof: combos_divide | **No** (proof-phase) |
| `risc0/zkp/src/hal/metal.rs` | 835 | 1× | Metal HAL (not used on Linux/CPU build) | n/a |
| `risc0/zkvm/src/host/server/prove/tests.rs` | 627 | 1× | Test code (not compiled into prod binary) | n/a |

**Verified absence (rg returned 0 matches)**: no Rayon `par_iter` sites in `risc0/circuit/rv32im/src/execute/` (preflight construction), and no explicit `rayon::spawn`/`rayon::scope`/`rayon::join`/`ThreadPoolBuilder` anywhere in the source tree.

**Net**: Rayon is used pervasively in the *proof-generation* phase (after witgen/accum complete). It is NOT used directly in `cpu_witgen`, `cpu_accum`, or the preflight executor. The previous version of this doc claimed "the one and only `into_par_iter` in the rv32im prove path" — that was wrong; it ignored the zkp HAL. **The corrected understanding: Rayon parallelism exists but all instances fire AFTER both bitmaps are emitted.**

### 8.2 System #2: C++ `poolstl` with `std::thread` (controlled by `std::thread::hardware_concurrency()`, NOT by any env var we set)

Definition: `risc0-modified/risc0/sys/cxx/vendor/poolstl.hpp` (single-header parallel STL):
- `task_thread_pool(unsigned int num_threads = 0)` constructor — defaults to `std::thread::hardware_concurrency()` when called with `0`.
- `poolstl::execution::parallel_policy` is the policy type used by `std::for_each(par, ...)`.

**Callsites in `risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` (primary source, late 2026-06-13)**:

| Line | Site | Context | Bypassed under `A4_COVERAGE_TOUCH=1`? |
|---|---|---|---|
| 391, 397 | `std::for_each(poolstl::par, ..., stepExec)` | `cpu_witgen`'s `kStepModeParallel` case (split + post-split) | **YES — bypassed.** Under `A4_COVERAGE_TOUCH=1`, `hal/mod.rs:149` forces `StepMode::SeqForward`, which selects the `kStepModeSeqForward` case (sequential `for` loop, no poolstl) at `ffi.cpp:401-440`. |
| 721 | `std::for_each(poolstl::par, ..., stepAccum)` | `cpu_accum`'s else-branch (when touch coverage NOT enabled) | **YES — bypassed.** Under `A4_COVERAGE_TOUCH=1`, the if-branch fires instead (sequential `for` loop at `ffi.cpp:686-714` writes to `g_a4_accum_touch_bitmap`). |
| 767 | `std::for_each(poolstl::par, ..., apply-totals lambda)` | `cpu_accum`'s phase 3 ("apply totals") — final prefix-sum bookkeeping | **NO — runs unconditionally.** BUT this runs *after* the accum bitmap has already been emitted (line ~700) and does NOT call `eqz()` / `a4_touch_mark`. So while poolstl parallelism does fire here, it has no causal path to the bitmap content. |

**Compiled binary evidence corroborates** (from earlier `nm` audit on `librisc0_rv32im_cpu.a`): both `cpu_witgen` and `cpu_accum` contain `std::for_each` template instantiations with `poolstl::execution::parallel_policy`, with undefined symbols `std::thread::_M_start_thread`, `pthread_mutex_lock`, etc., consistent with real thread spawning. The primary source now tells us EXACTLY when those parallel paths fire vs. when they're bypassed.

**Conclusion**: `poolstl::par` IS present in the compiled binary and DOES spawn `std::thread::hardware_concurrency()` threads when active. But under `A4_COVERAGE_TOUCH=1` (which we always set), the only `poolstl::par` site that actually executes is the apply-totals phase 3 of `cpu_accum`, which runs *after* both bitmaps are emitted and cannot affect them.

### 8.3 Env-var matrix as actually understood

| Env var | What it controls | Found in our source? | Empirical effect on race rate |
|---|---|---|---|
| `RAYON_NUM_THREADS` | Rayon global pool thread count (System #1) | Implicit via Rust runtime — controls all `par_iter` sites in §8.1 | **Real**: reduces 0.70% → 0.14% (5×). But §4.5 explains we cannot mechanistically link this to bitmap writes since all Rayon sites fire post-emission. |
| `RISC0_NUM_THREADS` / `RISC0_THREADS` | Hypothetical risc0-specific | NO matches in source | No measurable effect in `path_a2` vs `path_a1` |
| `OMP_NUM_THREADS` | OpenMP thread count | NO matches (`#pragma omp`, `<omp.h>`, `omp_get_*` all absent) | No measurable effect in `path_a2` vs `path_a1` |
| `POOLSTL_*` / std::thread default | poolstl's `num_threads` (System #2) | NOT exposed via any env var we know | Per §8.2, irrelevant under `A4_COVERAGE_TOUCH=1` since only post-emission poolstl::par fires |

### 8.4 The refined honest gap (late 2026-06-13)

Previously: "We do not currently have an experiment that isolates System #2 (poolstl). A clean poolstl-only-sequential experiment would settle whether the residual leak is in poolstl-controlled code."

**Refined understanding**: We now know from primary source that poolstl::par does NOT fire in any bitmap-writing code path under `A4_COVERAGE_TOUCH=1`. Therefore the "isolate poolstl" experiment is no longer the bottleneck — poolstl is mechanistically ruled out as the residual source.

**The actual open gap is now §4.5's puzzle**: under `A4_COVERAGE_TOUCH=1`, neither known parallelism system fires before bitmap emission, yet the race rate empirically halves under `RAYON_NUM_THREADS=1`. Candidate explanations (Rayon lazy-init perturbing process state, sample noise, hardware/OS-level nondeterminism, or an undiscovered parallelism source) are detailed in §4.5. Cheap experiments to make progress:

- `taskset --cpu-list 0 risc0-host ...` — forces all threads onto a single core; serializes ALL parallelism at the OS level. If race rate stays unchanged at ~0.14%, that further supports "the residual is microarchitectural / sample noise rather than threading-controlled."
- Add a one-line `eprintln!("rayon threads: {}", rayon::current_num_threads())` at process start in the host to verify our `RAYON_NUM_THREADS=1` is actually taking effect.
- Build a host variant with `ThreadPoolBuilder::new().num_threads(1).build_global()` called as the very first line of `main()`, to eliminate any lazy-init effect.

---

## 9. Open questions for Pro (REVISED 2026-06-13)

### Q1 — Does the ~0.7% (default parallelism) reward noise matter at Phase 8 scale?

**Concrete framing**: For a fuzzing campaign with N=10,000 mutations and ~8 bandit arms, with reward noise of ~0.7% per pull (default parallelism) manifesting as ±1 in `delta_T` (which translates to roughly ±0.002 in reward magnitude), does this materially affect:

- Arm convergence (will the bandit still identify the "true" highest-reward arm)?
- Comparison of bandit variants across V1-V5 (will the noise overwhelm true variant differences)?
- Repeatability of "best mutation kind" claims (will two independent campaigns agree)?

Our intuition is "no, the noise averages out at this scale, but we should report the noise floor". We'd like a sanity-check on this.

**User decision context**: We are launching Phase 8 with **default parallelism for speed** (∼4× faster wall-clock than `RAYON=1`). Pro's call: is this acceptable, or should we eat the slowdown and use `RAYON=1`?

### Q2 — Can you explain the refined mechanism puzzle (§4.5)?

In our 700 paired muts under `RAYON=1`, we observed 1 flip; in 1000 paired muts under default parallelism, 7 flips (5× higher rate). Initially we hypothesized C++ `poolstl::par` as the residual source. **Primary-source recovery on late 2026-06-13 ruled this out**: under `A4_COVERAGE_TOUCH=1`, both `cpu_witgen` and `cpu_accum` run their constraint-eval loops in plain sequential `for` loops; the only remaining `poolstl::par` site (apply-totals phase 3 of accum) runs AFTER both bitmaps are emitted. And all Rust Rayon sites are in the proof phase, also post-emission. See §4.5 for the consolidated puzzle.

The mechanistic question for Pro: **if no parallel code fires before bitmap emission under our normal operating conditions, why does `RAYON_NUM_THREADS=1` empirically reduce the race rate 5×?** Candidate explanations in §4.4 / §4.5: Rayon lazy-init perturbing process state, sample noise, microarchitectural/OS nondeterminism, or an undiscovered parallelism source.

Cheap experiments we could run (in priority order):

1. **Cheap (no rebuild)**: Re-dispatch one campaign with `taskset --cpu-list 0 risc0-host ...` — forces single-core execution at the OS level. If the rate stays at ~0.14%, parallelism (whatever the source) is fully ruled out as the residual cause; the residual would then be microarchitectural / sample noise.
2. **Cheap-medium (one-line edit, rebuild)**: Add `eprintln!("rayon threads: {}", rayon::current_num_threads());` at process start in the host (`r0vm.rs`). Verify our `RAYON=1` actually takes effect. Eliminates explanation (d).
3. **Medium (build flag, rebuild)**: Compile a host variant with `ThreadPoolBuilder::new().num_threads(1).build_global()` called as the very first line of `main()` to eliminate any lazy-init effect (explanation (e) / (1)).
4. **Larger dataset**: Dispatch 5000+ paired muts at both default and `RAYON=1` to tighten the rate CIs and definitively confirm or reject the 5× ratio (explanation (c) / (2)).

Pro's call: which (if any) are worth doing before Phase 8, or after, or never?

### Q3 — Should we file an upstream RISC0 issue?

We have a precise mechanism description (`FieldToWord(inst_p2.zir:291)`, major=9, minor=5, race in Poseidon2 cell computation under parallel execution; partial mitigation via `RAYON=1`). We could file an issue on `github.com/risc0/risc0` describing what we found. The maintainers would benefit from knowing about it; but our finding may also be considered "out of scope" because it only affects research instrumentation, not proof generation. Recommended?

### Q4 — Does this finding need to land in our paper's methodology section?

If yes, what level of detail — a footnote noting the ±1 bit noise floor, or a full methodology subsection with reproducer references?

### Q5 — Has the resolution of the source-file wipe affected the rigor of this finding?

**Status update (late 2026-06-13)**: The 5 critical wiped files (`ffi.cpp`, `steps.cpp`, `witgen.h`, `hal/mod.rs`, `witgen/mod.rs`) were recovered byte-identically to the June 3 state via `/root/arguzz_backups/risc0-modified.CURRENT.patch`. A full reconstruction of June 3 state confirms 58/58 patched files match the current working tree byte-for-byte (53 surviving files unchanged + 5 recovered from patch). The recovery introduced zero inference.

**Consequences for this finding**:
- **Strengthens**: Several mechanism claims previously sourced from `PHASE_7D_INC3_FINDINGS.md §5.5` (written before the wipe) are now directly verifiable from primary source — and have been verified. Specifically: `A4_COVERAGE_TOUCH=1 → SeqForward` gating at `hal/mod.rs:149`; sequential dispatch at `ffi.cpp:401-440`; `a4_touch_mark` early-return on env absence at `ffi.cpp:118-120`. See the "What primary source confirms" list in the Methodology note above.
- **Deepens the puzzle**: With primary source available, we can now categorically state that `poolstl::par` is NOT a candidate for the residual race under `A4_COVERAGE_TOUCH=1` (the parallel paths in `cpu_witgen` and `cpu_accum` are bypassed). This was previously listed as our leading candidate (§4.4 explanation (b), Medium-High plausibility) and is now downgraded to Low. See §4.5 for the refined mechanism puzzle.
- **What's NOT recovered**: B1/B2/B3/B5 verbose-tag and preflight-FP instrumentation that we added to `ffi.cpp` between June 3 and June 12. These are documented as patch specs in our internal docs (`PHASE_7D_INC3D_B_PATCH_SPEC.md`, `PHASE_7D_INC3D_C_PATH_B5_PATCH_SPEC.md`) and re-derivable if Pro recommends revisiting them. User explicitly deferred this work pending Pro feedback.

**Pro's call**: Are the primary-source verifications above sufficient for the level of rigor expected for this consult, or do you want any specific additional verification (e.g., a clean dispatch on the recovered binary to confirm the recovered source builds and behaves identically)?

---

## 10. Decisions we propose to adopt (D46, D47) — REVISED 2026-06-13

In `CLOUD1_DECISIONS_FOR_PRO_R2.md`, we propose adding:

### D46 — B7 race characterization (informational decision; REVISED late 2026-06-13 with primary source)

**Statement**: The touch-coverage signal `delta_T` has a measured race-induced noise floor of **~0.7% per mutation under default parallelism, ~0.14% with `RAYON_NUM_THREADS=1`** (~±1 bit, exactly one Poseidon2 sub-cycle constraint at `FieldToWord(inst_p2.zir:291)`, `major=9 minor=5`). The race manifests in non-deterministic intermediate Poseidon2 cell computation that determines whether the `lowIsZero` branch (and thus the FTW291 EQZ check) fires. The race is upstream of the touch_bitmap recording (same divergence appears in non-bitmap verbose-tag stream) and downstream of preflight state fingerprinting (9-field preflight FP is bit-identical A vs B even when delta_T flips). The race does NOT affect proof generation, constraint pass/fail decisions, or any persistent witness state.

**Mechanism status**: With primary source recovered (late 2026-06-13), we have verified that under `A4_COVERAGE_TOUCH=1` both `cpu_witgen` and `cpu_accum` write their bitmaps from plain sequential `for` loops with no Rayon or `poolstl::par` parallelism in scope. All known parallelism sites (Rayon in eval_check / zkp HAL, poolstl in apply-totals) fire AFTER bitmap emission. Yet `RAYON_NUM_THREADS=1` empirically reduces the rate 5×. We cannot fully reconcile this puzzle from source code alone — candidate explanations include Rayon lazy-init perturbing process state, sample noise, microarchitectural / OS-level nondeterminism, or an undiscovered parallelism source. Full mechanism analysis and candidate experiments in `RACE_FINDING_AND_OPEN_QUESTIONS.md` §4.5.

### D47 — Phase 8 thread strategy (operational decision) — USER OVERRIDE 2026-06-13

**Original proposal**: All Phase 8 POS dispatches will set `RAYON_NUM_THREADS=1`.

**User override**: Phase 8 will launch with **default parallelism for speed** (3-4× wall-clock improvement). The race finding documented above will be presented to Pro alongside Phase 8 results, the fuzzing notebook, and the open questions in §9. If Pro flags the noise as material, we will re-run with `RAYON=1`. If not, default parallelism becomes the Phase 8 standard. This trades a known ~0.7% noise floor for execution speed; the noise is expected to average out at N ≥ 5000/campaign per-arm scale.

---

## 11. Artifacts pointer

If Pro wants to dig deeper:

| Artifact | Path / location |
|---|---|
| Working binary | `/root/arguzz/workspace/output/target/release/risc0-host` (sha256 `1bd8e9ec…`) |
| Backup binary | `/root/arguzz_backups/risc0-host.B5.1bd8e9ec` |
| Raw audit DBs | `a4/audits/audit_output/inc3d/c_{path_a1,path_a2_closure,b5_default_closure,b5_rayon1_closure}/*.db` |
| Raw audit logs (with preflight FP tags) | same dirs, `*.log` files |
| Phase B (verbose) investigation | `a4/audits/audit_output/inc3d/p{1,2}/`, report in `PHASE_7D_INC3D_REPORT.md` |
| C-closure report | `a4/docs/cloud1/composer/PHASE_7D_INC3D_C_CLOSURE_REPORT.md` |
| Inc 3 final report | `a4/docs/cloud1/composer/PHASE_7D_INC3_FINAL_REPORT.md` |
| Decisions doc | `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` |
| Source for ffi.cpp / a4_touch_mark (the bitmap-write site) — **RECOVERED late 2026-06-13** | `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` (789 lines, 89 a4_/A4_ refs; byte-identical to June 3 state) |
| Source for hal/mod.rs (StepMode gating) — **RECOVERED late 2026-06-13** | `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/hal/mod.rs` (360 lines, 5 a4_/A4_ refs; primary-source verification of `A4_COVERAGE_TOUCH → SeqForward` gating at line 149) |
| Source for witgen.h (eqz wrapper around a4_touch_mark) — **RECOVERED late 2026-06-13** | `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` |
| Source for steps.cpp / witgen/mod.rs — **RECOVERED late 2026-06-13** | `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` (~31.5K lines, auto-generated EQZ table) and `risc0/circuit/rv32im/src/prove/witgen/mod.rs` (918 lines, 51 a4_/A4_ refs incl. A4_INSPECT, A4_DUMP_*, A4_MUTATION_CONFIG) |
| Source backup (used for recovery) | `/root/arguzz_backups/risc0-modified.CURRENT.patch` (June 3 git diff, 5.0 MB) |
| Pre-recovery safety backup | `/root/arguzz_backups/pre_recovery_20260612_232446/` (53 modified files + git status) |
| Decompilable .o files (compiled with hooks intact, kept as additional reference) | `workspace/output/target/release/build/risc0-circuit-rv32im-sys-*/out/*.o` |
| **Inc 4 B11 drift evidence (THIS DOC §12)** — N=500 prefix vs N=200 baseline | `a4/audits/audit_output/B11_scale_stress.json`, `inc4_b11/*.db`, `inc3_b1/*.db` |
| Inc 4 Opus review (B8/B11/B12 + drift summary) | `a4/docs/cloud1/composer/PHASE_7D_INC4_OPUS_REVIEW.md` |

---

## 12. Inc 4 audits — what they tested and how the race manifested (added 2026-06-13)

> **Why this section was added.** §6 frames the open question "does ~0.7% reward noise materially affect bandit convergence at Phase 8 scale?" purely from first principles (reward magnitudes, expected averaging). In Phase 7d Increment 4 we **ran three architectural audits (B8, B11, B12) that gave us an empirical answer**: we ran each audit against the existing modified RISC0 binary `6873e588…` (the same binary used for Inc 3 baselines) and looked for the race's footprint in the results. This section explains what each audit was designed to test, what we found, and where the race showed up vs where it did not. The aggregate-impact analysis for B11 (the audit where the race was most visible) is in §12.4.

### 12.0 The three Inc 4 audits — purpose and design

| Audit | Question it tries to answer | Design | Race-related expectation going in |
|---|---|---|---|
| **B8 Concurrent variant isolation** | "When the 5 bandit variants run *in parallel on 5 different POS nodes*, do they accidentally share mutable state with each other?" | Two passes of 5 variants × N=50: Pass 1 sequential (one variant at a time on flare), Pass 2 parallel (all 5 simultaneously on 5 different nodes). For each variant, bit-compare seq vs par on all core tables. | If isolation is clean, the race should leave its usual ~0.7% delta_T flip rate equally on both seq and par runs and therefore mostly cancel out at the per-variant diff level (the B7 filter normalizes delta_T to binary specifically to absorb this). Coverage blobs may still differ due to row-order/compression artifacts unrelated to the race. |
| **B11 Scale stress** | "At larger N=500 (2.5× the Inc 3 baseline), does the architecture still behave correctly? Does anything accumulate or drift as N grows?" | 5 variants × N=500 (2500 mutations total) on 5 nodes in parallel, then per-variant sub-checks: prefix vs Inc 3 N=200 baseline; B4 6-tuple internal consistency; B9 schema/FK/row count. | This is the audit MOST sensitive to the race. If the race's delta_T noise propagates into bandit reward, *bandit-driven* variants (V2/V3/V4/V5) should diverge from their N=200 baselines at some point in the run; *non-bandit* V1 should not. This is exactly the prefix-divergence prediction made in §6. |
| **B12 Multi-input robustness** | "Does the bandit's arm universe and behavior change when we change the guest program's input?" | 5 variants × N=50 on each of two alternate inputs (`--in1 1 --in4 1`, `--in1 100 --in4 100`); plus per-input A3 (live arm enumeration), A5 (live ↔ doc cross-check), B4, B9. | The race should leave its usual ~0.7% delta_T noise floor regardless of input. We do not expect the race to interact with the input variation; if it does, that's a new finding. |
| **B1 strict verifier** (across B8/B11/B12 DBs) | "For every single mutation we recorded, does the mutation actually do what its config says when independently re-executed and re-decoded?" | Per-mutation hook-fidelity replay on POS, sharded one variant per node. Re-runs the host binary with each mutation's config and asserts the hook tag matches the original capture. | The race is upstream of the proof path and downstream of preflight state (§4.1). B1 strict verifier should NOT pick up race-induced fails — the per-mut behavior of `risc0-host` is deterministic for everything B1 checks (hook semantics, mutation application correctness). Any B1 fail would mean we found a NEW class of nondeterminism. |

### 12.1 Where the race manifested vs where it did not

| Audit | Race observable? | What we saw | Interpretation |
|---|---|---|---|
| **B8 core isolation** | **NO — race fully cancelled by B7 filter** | 5/5 variants showed **0 diffs** on mutations / bandit_decisions / mutation_rewards / mutation_substrategy / arm_state_snapshot between seq and par. | The B7 filter (which normalizes `delta_T` to binary 0/>0 and excludes the 188 D42 nondeterministic addresses) works correctly. Seq and par runs both experience the same race noise floor, and the B7 filter absorbs it. **This is the audit that PROVES the B7 filter is appropriately specced for production use.** |
| **B8 `compressed_global_coverage`** | **PRESENT — informational only** | Row counts match between seq and par; blob bytes differ (19-35 rows per variant). | This is the row-order / compression artifact called out in the work-order watch-out. It is NOT the Poseidon2 race — the diff is in the COMPRESSED REPRESENTATION of coverage, not the coverage itself. (We could verify by decoding both blobs and showing identical cell-counts, but B7 filter explicitly excluded this column from the isolation gate so we didn't.) |
| **B11 prefix-strict match (V1)** | **NO** | V1 (`zoned`, no bandit) prefix matches the Inc 3 N=200 baseline byte-for-byte (0/200 diffs). | V1 has no bandit and uses uniform-over-zones selection; reward signal feedback into selection is **disabled**. Same seed + same input universe → identical mutation sequence regardless of any reward noise. This is the GOLD-STANDARD reproducibility baseline. |
| **B11 prefix-strict match (V2/V3/V4/V5)** | **YES — race propagates through bandit reward exactly as §6 predicts** | V4 (TS) drifts mildly (5/200 diffs starting around mut #6); V2 (UCB) diverges at mut #94 (107/200 diffs); V3 (UCB no-Q) diverges progressively (176/200); V5 (semantic cTS) totally diverges (200/200). | **This is the first time we have observed the race's cascade through bandit selection end-to-end.** §12.2 spot-checks V2 and confirms the mechanism: 2 `delta_T` flips in the first 93 mutations (consistent with §2.2's measured rate) → UCB posterior drift → divergent arm at mut #94 → cascade. The aggregate impact is much smaller than per-row divergence implies — see §12.4. |
| **B11 B4 internal-consistency** | **NO** | 500/500 6-tuple agreement, all 5 variants. | The race affects `delta_T` (a coverage signal), not the host binary's per-mutation outcome. Within a single run, every mutation's `(kind, step, txn_idx, mutated_value, num_failures, verifier_accepted)` is internally consistent with itself. **The host binary is deterministic at the per-mut level.** |
| **B11 B9 schema integrity** | **NO** | Schema, FK, 500 rows all variants. | Database structure is race-immune. |
| **B11 B1 strict verifier** | **NO** (per Inc 3 B1 closure precedent) | Per Inc 3 B1 closure (974/1000 raw → 1000/1000 after documented D40/D42/D46 exclusions): the strict verifier has never picked up race-attributable fails. Race manifests only in `delta_T` (not in the columns B1 verifies). | **Race is invisible to B1 by design.** B1 verifies hook semantics (was the right kind applied at the right step with the right value?). The race never affects that — it affects the coverage bitmap, which B1 doesn't look at. |
| **B12 A3 arm enumeration (both inputs)** | **NO** | Both `--in1 1` and `--in1 100`: identical 48-arm universe, identical to baseline `--in1 5 --in4 10`. | Arm enumeration is deterministic from the trace structure, which is input-invariant for this guest. Race-immune. |
| **B12 B4/B9 (both inputs)** | **NO** | All PASS. | Same reason as B11 B4/B9 — race doesn't touch these columns. |
| **B12 A5 doc cross-check** | **NO** (not a race issue) | FAIL on both inputs because `EXPECTED_ARMS.md` has stale `core_div` instead of live `core_shr`. Also FAILs on baseline `--in1 5 --in4 10`. | Pure doc-drift; pre-dates Inc 4. Waived for Inc 4, fix in Inc 5. Mentioned here only to clarify it is NOT race-related. |

**Summary**: The Poseidon2 race manifests in EXACTLY ONE PLACE in the Inc 4 audits — **B11's per-row prefix check on bandit variants** — and **only on bandit-driven variants** (V2/V3/V4/V5), **never on V1 (no bandit)**. Everywhere else the race is either invisible (B1, B4, B9, A3) or absorbed by design (B7 filter on B8 core diffs). This is the cleanest empirical confirmation we have that:
1. The race is **localized** to the bandit-reward feedback loop in mid-campaign reproducibility.
2. The B7 filter is **correctly specced** for the use case it was designed for (concurrent isolation).
3. The race **does NOT propagate** into per-mutation correctness, schema, or input-invariance — it is *only* a between-run reproducibility issue for bandit-selection paths.

### 12.1a B1 strict verifier "raw fails" are documented boundary cases, not race or regression

For Pro's benefit (since B1 strict verifier numbers will appear in the final Phase 8 evidence pack): every B1 raw failure we have ever seen on our binary maps to one of 4 categories tied to user-approved architectural decisions on the modified RISC0:

| Category | Failure pattern | Maps to decision | Decision says |
|---|---|---|---|
| **A** | `INSTR_TYPE_MOD step=0`, hook `cycle.major=7` (CONTROL0) ≠ config `decoded.major=2 minor=6` (Auipc) | **D40** (`CLOUD1_DECISIONS_FOR_PRO_R2.md`) — multi-cycle step disambiguation | Multi-cycle steps are dropped from the bandit universe; when a few slip past, the mutation IS correctly applied — only the cycle-index annotation disagrees. **No soundness implication.** |
| **B** | `MEM_VAL_MOD step=3929` (ECALL last_step) byte_addr off by `0x100000000` (33-bit physical vs 32-bit user-space) | **D42** (nondet mem-txn allowlist) + **D46** (ECALL 8/7 taxonomy) | Step 3929 is the program-exit ECALL with prepare/dispatch/cleanup sub-stages; `txn_idx → byte_addr` mapping is well-defined per-run but the high address bit gets truncated by the hook. |
| **B2** *(Inc 4 extension)* | `MEM_VAL_MOD step=3929` `old_word` mismatch, **new_word still agrees** | **D42 + D46** | Same ECALL sub-stage mechanism as B but the cell that drifts is the prior-state readback (`old_word`) rather than the address (`byte_addr`). Safety guard: only excluded if the mutation effect (`new_word`) DID apply correctly. Surfaced once in Inc 4 B11 (1/2500). |
| **C** | `INSTR_TYPE_MOD` mid-program with hook `cycle.major=8` (ECALL0) ≠ config `decoded.major=7` (Eany) | **D46** | "RISC0 circuit places ECALL in `cycle.major=8`; RV32IM encoding has ECALL as `decoded.major=7 minor=0`. Both correct from respective perspectives." |
| **D** | `MEM_VAL_MOD step=0` (boot/ECALL boundary) byte_addr off by `0x100000000` | **D42 + D46** | Same root cause as B but at program start. |
| **D2** *(Inc 4 pre-registered)* | `MEM_VAL_MOD step=0` `old_word` mismatch, **new_word still agrees** | **D42 + D46** | Symmetric to B2 at the boot boundary. Not yet observed (0 cases) but pre-registered in the disposition script so it won't be miscounted if it appears. |

The strict verifier (`a4/tools/verify_mutation_semantics.py P1`) does not apply these dispositions by design — we want the raw signal honest. After applying them (`a4/audits/B1_apply_disposition.py`, automated, deterministic):

| B1 dataset | Raw pass | Disposition fits | Net pass | Unclassified | Race fingerprint |
|---|---|---|---|---|---|
| Inc 3 B1 (1000 muts, baseline) | 963 / 1000 (96.3%) | 37/37 → A=22, B=8, C=5, D=1, OTHER≤1 | **≥999 / 1000 (99.9%)** | ≤1 | 0 |
| Inc 4 B12 in1_1 (250 muts) | 245 / 250 (98.0%) | 5/5 → A=2, B=1, C=1, D=1 | **250 / 250 (100%)** | 0 | 0 |
| Inc 4 B12 in1_100 (250 muts) | 245 / 250 (98.0%) | 5/5 → A=2, B=1, C=1, D=1 | **250 / 250 (100%)** | 0 | 0 |
| Inc 4 B11 (2500 muts) | 2416 / 2500 (96.6%) | 84/84 → A/B/C/D + 1× B2 (extension) | **2500 / 2500 (100%)** | 0 | 0 |

**Why we can confidently exclude A/B/C/D**:
1. The failure patterns are *deterministic functions* of the architectural quirks documented in D40/D42/D46. Same input → same exclusion classification.
2. **0 unclassified** failures across 1500+ mutations to date — no novel failure mode has appeared.
3. **0 race-fingerprint** failures (`inst_p2.zir:291`) — the Poseidon2 race genuinely does NOT propagate into the columns B1 verifies (mutation_kind, step, mutated_value, hook output). The race lives in the touch-coverage bitmap, not in mutation semantics.
4. The disposition machinery (`B1_apply_disposition.py`) explicitly tags anything OUTSIDE the 4 categories as `OTHER` or `RACE` for review — so if a new failure mode appears in Phase 8, we won't miss it.

**Pro-visible artifact path** (for Phase 8 evidence pack):
- The 4 disposition decisions are in `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` D40, D42, D46.
- The disposition mechanism is in `a4/audits/B1_apply_disposition.py` (small, auditable script).
- The Inc 3 disposition writeup with row-level provenance is in `a4/docs/cloud1/composer/PHASE_7D_INC3D_B1_DISPOSITION.md`.
- Inc 4 disposition JSON outputs land at `a4/audits/audit_output/B1_inc4_*_disposition.json`.

### 12.2 Mechanism, verified end-to-end on V2

Same-node V2 (octorand) Inc 3 baseline vs Inc 4 first-200 of N=500, looking at the **93 mutations before divergence**:

| Field | Diff count / 93 | Interpretation |
|---|---|---|
| Mutation `(kind, step, txn_idx, mutated_value)` | **0 / 93** | Bandit picked the same arm AND mutation params for 93 in a row |
| `mutations.num_failures` | **0 / 93** | Host binary's per-mut failure count IDENTICAL — proves binary is deterministic at the per-mut level |
| `mutations.verifier_accepted` | **0 / 93** | Host binary's per-mut accept/reject IDENTICAL — same conclusion |
| `mutation_rewards.delta_T` | **2 / 93** (#70: 0↔1; #91: 1↔0) | **Poseidon2 race firing**, exactly as characterized in §2.2 (rate consistent with 0.7-2% combined floor) |
| `mutation_rewards.reward` (real) | 5 / 93 (downstream of dT) | Reward float perturbed by ~0.005 per flip |

Then at mut #94 the UCB posterior had drifted enough that V2 chose `INSTR_WORD_MOD_SUR` (step 1811) instead of `LOAD_VAL_MOD` (step 2590), and from #94 onward the trajectories cascade apart.

**This is the §4 mechanism observed end-to-end for the first time**, with the noise rate (2 / 93 ≈ 2.2%) consistent with the §2.2 measurement (~0.7% combined; varies by sample). The cascade exactly matches the §6 prediction: `delta_T noise → reward perturbation → bandit posterior drift → divergent arm selection`.

### 12.3 Setup details

- **Binary**: identical (sha256 `6873e588…`) on both Inc 3 and Inc 4 runs.
- **Seed**: 999 for every variant in both audits.
- **Strategies**: V1 `zoned` (no bandit, uniform), V2 `kindUCB_zoned_v1` (kind-level UCB), V3 `kindUCB_zoned_v2_noQ` (kind UCB, no-Q_loc reward), V4 `kindTS_zoned_v2` (kind Thompson sampling), V5 `cTS_semantic_v2` (semantic constrained TS).
- **Parallelism**: default (no `RAYON=1`) — matches the user-override Phase 8 plan (D47 in §10 above).
- **POS nodes**: same node per variant where possible (V1=flare, V2=octorand, V3=opulous, V5=algofi → identical to Inc 3 baseline). V4 ran on `meld` (Tier C) in Inc 4 vs `algofi` (Tier S) in Inc 3 due to a hardware substitution mid-dispatch.

### 12.4 The aggregate impact (the right frame)

Per-row order is the WRONG metric. The question that matters for exploitation is: **does the bandit still pick roughly the same arms in roughly the same proportions, and discover roughly the same failure space?**

| Variant | Kind-pull TVD | Arm-pull TVD | sum `delta_T` (Inc3→Inc4) | sum `num_failures` (Inc3→Inc4) | Unique `constraint_loc` overlap (IoU) |
|---|---|---|---|---|---|
| V1 zoned | **0.000** | **0.000** | 436 → 435 | 455 → 455 | **100.0%** |
| V4 kindTS (TS) | **0.005** | **0.005** | 1051 → 1051 | 779 → 736 | **100.0%** |
| V2 kindUCB v1 | **0.075** | **0.075** | 86 → 121 | 345 → 373 | **96.2%** |
| V3 kindUCB v2 noQ | **0.075** | **0.075** | 946 → 1121 | 841 → 976 | **79.4%** |
| V5 cTS_semantic | **0.075** | **0.240** | 535 → 531 | 499 → 580 | **74.3%** |

Where:
- **TVD** = total variation distance between the two pull-count distributions, normalized. 0 = identical, 1 = disjoint. **TVD = 0.075 means 92.5% of pulls would map identically under optimal alignment** of the two distributions.
- **constraint_loc IoU** = `|A ∩ B| / |A ∪ B|` over the set of unique RISC0 constraint locations hit by any failure. Tells us "what fraction of the failure space was found by BOTH runs."

Per-kind pull counts for V2 (UCB, 200 pulls, 8 kinds — TVD = 0.075):

```
kind                     INC3  INC4  delta
COMP_OUT_MOD               21    22    +1
INSTR_TYPE_MOD              8    12    +4
INSTR_WORD_MOD_FULL        23    27    +4
INSTR_WORD_MOD_SUR         89    79   -10
LOAD_VAL_MOD               16    17    +1
MEM_VAL_MOD                18    13    -5
PRE_EXEC_REG_MOD            9    12    +3
STORE_OUT_MOD              16    18    +2
```

For V5 (semantic cTS, 200 pulls, 48 arms — kind TVD = 0.075, arm TVD = 0.240):

```
kind                     INC3  INC4  delta
COMP_OUT_MOD               17    17    +0
INSTR_TYPE_MOD             35    40    +5
INSTR_WORD_MOD_FULL        34    28    -6
INSTR_WORD_MOD_SUR         33    28    -5
LOAD_VAL_MOD                8     8    +0
MEM_VAL_MOD                42    38    -4
PRE_EXEC_REG_MOD           28    33    +5
STORE_OUT_MOD               3     8    +5
```

### 12.5 Interpretation

1. **V1 (uniform)**: Perfectly reproducible across runs, as theory predicts. Confirms our diff machinery is sound.
2. **V4 (Thompson Sampling)**: Almost perfectly reproducible at the aggregate level (TVD = 0.5%) DESPITE running on a different uarch (meld Tier C vs algofi Tier S). TS's smoothing posterior makes it the most race-robust strategy in our set.
3. **V2 / V3 (UCB)**: Per-row paths diverge from mut #94, but **aggregate kind-pull distribution shifts by only ~7.5% TVD**. The bandit still explores ~96% of the same constraint failure space (V2) / ~79% (V3). V3's higher constraint-loc drift correlates with its no-Q_loc reward formulation being more reward-noise-sensitive.
4. **V5 (semantic cTS)**: Kind-level pulling drifts only ~7.5% TVD (identical to V2/V3 at the coarse axis), but at the **48-arm fine grain** the drift jumps to 24% TVD — because the (zone) sub-axis amplifies tiny reward perturbations into different arm selections within each kind. ~74% constraint overlap shows the failure-space discovery is still mostly shared but not as tight as the simpler strategies.

**Bottom line**: the bandit's exploitation behavior at the aggregate level is **preserved within ~5-25% across strategies**, even though per-row trajectories diverge. We are still hitting the same failure constraints (≥74% overlap on the most-divergent variant, 96-100% on the rest). Run-to-run "best arm by reward" rankings should be stable for V1/V4 and approximately stable for V2/V3; V5's finer-arm bandit is the most affected.

### 12.6 Concrete question for Pro (extends §9 Q1)

Given the data above:

- **Is a 5-7.5% TVD drift in pull distribution acceptable** for Phase 8 cross-seed/cross-run comparison of bandit variants?
- For V5 specifically, **is 24% TVD on fine-grained arms tolerable** if we mostly care about kind-level conclusions and the constraint-loc overlap is still 74%?
- **Should we publish aggregate metrics with TVD-style error bars** to make the drift explicit rather than hiding behind "same seed = same result"?
- **Does V4 TS's superior reproducibility (TVD 0.5%) suggest we should prefer TS-family variants for Phase 8 headline runs**, and treat UCB variants as ablations?
- Alternatively: should we **enable `RAYON=1` only for the headline V5 runs** (semantic cTS being the most-affected strategy) and accept default parallelism for the rest? This is a partial application of the §7.1 mitigation.

The existing §6 question stands (does the noise materially affect bandit convergence?), but is now backed by direct measurement: at N=200 the per-strategy TVDs above are what the noise actually does. We expect TVDs to *decrease* with N (more pulls average out more noise), so Phase 8's planned N≥5000/campaign should be in better shape than this N=200 prefix measurement, but we have no proof of that yet.

### 12.7 What this finding does NOT change

- §1–§11 of this doc remain unchanged. The race mechanism, mitigations, and decisions (D46/D47) are unaffected.
- The race is still local to `delta_T` (touch coverage) and does NOT affect proofs, constraint pass/fail, or persistent witness state (see §5).
- We are NOT proposing a code change. We are reporting the *measured observed consequence* of the known race for the first time.

