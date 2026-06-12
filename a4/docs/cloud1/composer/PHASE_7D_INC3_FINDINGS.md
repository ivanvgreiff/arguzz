# Phase 7d Inc 3 — Consolidated Findings (Opus living doc)

**Status**: 🟡 LIVING — B1 CLOSED; B7 SHARPENED, NOT YET CLOSED
**Last updated**: 2026-06-11 16:45 (UTC-4)
**Owner**: Opus
**Purpose**: Single source of truth for what we know, what we're still uncertain about, and what we're doing about it in Inc 3. Composer's Inc 3 report (`PHASE_7D_INC3_REPORT.md`) and Inc 3b report (`PHASE_7D_INC3B_REPORT.md`) are the empirical inputs; this doc is the diagnosis, plan, and consolidated reasoning.

## TL;DR (most recent state)

| Gate | Status | Evidence |
|---|---|---|
| **B1 hook fidelity** | ✅ **CLOSED — 1000/1000 PASS** | Inc 3b §A.2 across 5 variants on 5 POS nodes |
| **B7 same-seed reproducibility** | 🔬 **Sharpened to "octorand has intra-node race"; root cause hunt active (Phase δ)** | Inc 3b §B.2: flare intra-pair 0 diffs / octorand intra-pair 1 reward diff at PRE_EXEC_REG_MOD mut id=25 step=2296, delta_T (1 vs 0) |
| **B2 multi-cycle replay** | ✅ PASS (Inc 3 §B2) | — |
| **B4 bandit→DB traceability** | ✅ PASS (Inc 3 §B4) | — |

**Phase 7d completion gate**: B7 closure (= identifying and explaining the octorand race mechanism). Once closed, Phase 7d architecture audit is complete and we proceed to Phase 8 (large-scale fuzzing).

---

## 1. Inc 3 audit verdicts (combined Inc 3 + Inc 3b)

| Audit | Inc 3 verdict | Inc 3b verdict | Coverage |
|---|---|---|---|
| **B1** Hook fidelity (strict verifier) | FAIL 963/1000 | ✅ **PASS 1000/1000** (post Option B fix) | 5 variants × 200 muts |
| **B2** Multi-cycle replay (D40 universe enforcement) | PASS | — | universe queries only |
| **B4** Bandit → DB traceability | PASS | — | 50 muts × 4 bandit variants |
| **B7** Same-seed reproducibility | FAIL (cross-node, 4/250) | FAIL **per-node** on octorand (1/50 on intra octoA-vs-octoB); flare clean | Inc 3b adds per-node fingerprints + same-node pairs |

**Gate**: B1 is closed. B7 is reduced to a specific, well-characterized phenomenon (octorand intra-node race) but mechanism not yet identified. Phase δ is the closure task.

---

## 2. What is downstream of B1 and B7

The user's framing is correct: every other concern is downstream.

- **Phase 8 large-scale fuzzing campaigns**: Need B7 to know paired runs are reproducible (otherwise ablation comparisons are confounded by node-jitter, not bandit choice).
- **Reward signal trust**: Needs B1 (otherwise some fraction of mutations get reward attributed to the wrong arm).
- **V1-vs-V2-vs-…-V5 bandit comparisons**: Needs both.
- **Crash reproducibility / post-mortem**: Needs B7.

B2 is already PASS (universe-side enforcement) and B4 is already PASS (bandit→DB pipeline). No action required on these two.

---

## 3. B1 — root cause and proposed fix

### 3.1 Symptom

Every B1 failure (37 across 1000 mutations) is exactly one of two forms:

**Form A — `cycle_shift_at_step` for `INSTR_TYPE_MOD`:**
```
hook old=7/0 != config exp_old=2/6   ← step=0, all variants
hook old=8/0 != config exp_old=0/7   ← step=446, V5 only
```

**Form B — `byte_addr mismatch` for `MEM_VAL_MOD`:**
```
byte_addr 268435328 != config 0x10fffff80   ← step=3929 (= lastCycle-1), or step=0
```

Distribution across variants:
- V1: 1 fail (1 multicycle)
- V2: 2 fail (1 multicycle, 1 byte_addr)
- V3: 10 fail (9 multicycle)
- V4: 12 fail (8 multicycle)
- V5: 12 fail (9 multicycle)

The variant skew (V3-V5 fail more) is fully explained by D54: those variants have boundary-step semantic zones as first-class arms; their bandits sample those arms; their mutations land on boundary steps more often, exposing the bug more often.

### 3.2 Root cause — TWO bugs (proven locally)

**Bug 1 (real semantic mis-routing, all `cycle_shift_at_step` failures, 30/37 cases)**:

The universe-gen and the runtime hook disagree on **which cycle to mutate for INSTR_TYPE_MOD when step has multiple cycles**.

- Universe-gen (`InspectionData._build_indices` line 59): `self._step_to_cycle = {c.step: c for c in self.cycles}` — Python dict-comprehension semantics: **on key collision, LAST cycle wins**. So `data.get_cycle(0)` returns the LAST cycle at step=0, which is the user-instruction MISC2 (major=2 minor=6).
- Runtime hook (`witgen/mod.rs` line 268-280, INSTR_TYPE_MOD): iterates `trace.cycles` and takes the **FIRST** cycle where `cycle.user_cycle == target_step`, **with no major filter**. At step=0 this is a CONTROL0 init cycle (major=7 minor=0).

Empirically reproduced locally (this pass):
- step=0 has **16,574** cycles (most are init / page-table / register-init)
- Universe records `_step_to_cycle[0]` → cycle_idx=16573 major=2 minor=6 (last user instruction)
- Hook lands on cycle_idx=0 major=7 minor=0 (first CONTROL0 init)
- D40 filter counts 1 matching cycle (only the MISC2 at idx 16573 passes the `major<=6` filter), so step=0 is NOT dropped — but the hook doesn't apply that filter.

For comparison, `INSTR_WORD_MOD` already correctly applies the filter in the hook (`mod.rs` line 296: `if cycle.user_cycle == target_step && (cycle.major <= 6 || cycle.major == 8)`). INSTR_TYPE_MOD just missed it.

**Bug 2 (verifier-display only, all `byte_addr mismatch` failures, 7/37 cases)**:

The MEM_VAL_MOD hook prints `byte_addr` with u32 multiplication overflow:
- Hook (`witgen/mod.rs` line 574): `txn.addr * 4` where both operands are u32. For high-address txns (`addr > 2^30`), this overflows and wraps modulo 2^32.
- Universe-gen (`fuzzer.py` line 1607): `f"0x{target.byte_addr:08x}"` where `target.byte_addr = txn.addr * 4` computed in Python (arbitrary precision, no overflow).

Empirically reproduced locally (this pass):
- `addr = 1140850656 = 0x43FFFFE0` (a system / page-table address that gets touched at step=3929 teardown)
- Universe stores `byte_addr = 4,563,402,624 = 0x10FFFFF80` (33-bit; Python int)
- Hook prints `byte_addr = 268,435,328 = 0x0FFFFF80` (u32-wrapped)
- Difference = exactly `2^32`

**Critically, the mutation itself is applied correctly**: `txn.addr == 1140850656` matches in both, `txn.word` is mutated as configured. Only the *printed* byte_addr differs, which the strict verifier compares as integers and reports as a "fidelity" failure.

So Bug 2 is purely cosmetic / verification-strictness — it doesn't affect actual fuzzing. But it must be fixed for B1 to pass.

### 3.3 Why these failures concentrate where they do

- **Bug 1 affects boundary steps** because that's where multiple cycles share a user_cycle (init cycles at step=0, teardown cycles at step=3929, ECALL handler cycles at step=446). Mid-trace steps have 1 user-instruction cycle ↔ 1 user_cycle so the bug doesn't manifest.
- **Bug 2 affects mutations on high-address (page-table / system) txns**, which only occur during boundary-step teardown / init in this binary.

Both bugs concentrate at boundary steps, which is why the failure distribution skews to V3-V5 (those variants have boundary-step semantic zones as first-class arms and pull them more often).

### 3.4 Why this does NOT break architectural correctness in a deep way

- The bandit math, reward function, zone classification, touch coverage, trace generation, and arm-state tracking are all unaffected.
- Bug 1 only causes wrong-cycle mutations at boundary steps (3% of selections). The wrong mutation still produces a valid (different) reward signal; it just lands on an init / teardown cycle instead of the user-instruction cycle.
- Bug 2 doesn't affect any mutation; only the verifier comparison.
- The fix is in three small edits (one Python, two Rust).

### 3.5 Fix specification (Option B — unified cycle-resolution rule)

**Architectural rule** (the invariant we enforce in both places):

> For any (kind, step) mutation where the kind has a major-filter (INSTR_TYPE_MOD, INSTR_WORD_MOD_*, etc.), the canonical cycle is the **first cycle whose `user_cycle == step` AND `major` satisfies the kind's filter**.

This rule is already implemented correctly in INSTR_WORD_MOD (both sides agree). We extend it to INSTR_TYPE_MOD.

For kinds that address by `txn_idx` (MEM_VAL_MOD, COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, PRE_EXEC_REG_MOD), the mutation itself is unambiguous (`trace.txns[txn_idx]` is canonical). Only the cycle-lookup for logging needs the filter; the actual mutation is correct without changes.

**Edits**:

1. `a4/standalone/mutations/instr_type_mod.py` — `get_targets_at_step`: replace `data.get_cycle(step)` (which returns the LAST cycle at step due to dict-comp last-wins semantics) with a forward-scan that picks the FIRST cycle at `step` with `major in VALID_MAJORS` (= {0..6}). This matches the hook's new filtered behavior.

2. `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` — INSTR_TYPE_MOD hook (line 268-280): add `cycle.major <= 6` to the iteration filter, identical to how INSTR_WORD_MOD already filters on line 296. This is a one-line addition.

3. `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` — MEM_VAL_MOD hook (lines 574, 577): cast to u64 before multiplying by 4. `txn.addr * 4` → `(txn.addr as u64) * 4`. Two-character change in two lines.

After (2) and (3), the host binary must be rebuilt.

**No other kinds need changes** because:
- INSTR_WORD_MOD already correctly filters in the hook AND universe-gen picks the right cycle (instr_word_mod has its own selection logic that already filters by major).
- MEM_VAL_MOD / COMP_OUT_MOD / LOAD_VAL_MOD / STORE_OUT_MOD / PRE_EXEC_REG_MOD all address by `txn_idx` directly; the mutation target is canonical regardless of cycle disambiguation. Their universe-gen uses `data.get_cycle(step)` which may return the wrong cycle for logging/classification purposes (subtle non-correctness in `txn_type` labels at boundaries), but this does NOT cause B1 failures because the verifier only checks (txn_idx, addr, old_word, new_word, byte_addr) — all of which are correct.

### 3.6 Implementation status — DONE + verified locally

| Edit | File | Status |
|---|---|---|
| #1 | `a4/standalone/mutations/instr_type_mod.py::get_targets_at_step` | ✅ applied — picks FIRST cycle at step with `major ∈ VALID_MAJORS = {0..6}` instead of `data.get_cycle(step)` |
| #2 | `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` INSTR_TYPE_MOD branch | ✅ applied — added `&& cycle.major <= 6` to the cycle iteration filter |
| #3 | `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` MEM_VAL_MOD logging | ✅ applied — `txn.addr * 4` → `(txn.addr as u64) * 4` (both occurrences, lines 574 + 577) |

Host binary rebuilt: `workspace/output/target/release/risc0-host` — `cargo build --release` in `workspace/output/`, 5m 22s, exit 0.

**Local verification** (this pass):

(a) Bug 1 repro — INSTR_TYPE_MOD step=0:
- BEFORE: hook reports `old=(7,0)` (CONTROL0 init cycle)
- AFTER: hook reports `old=(2,6)` (MISC2 user instruction at cycle_idx=16573) ✓ matches universe expectation

(b) Bug 2 repro — MEM_VAL_MOD step=3929 txn_idx=34676 (high address):
- BEFORE: hook prints `byte_addr=268,435,328` (0x0FFFFF80, u32-wrapped)
- AFTER: hook prints `byte_addr=4,563,402,624` (0x10FFFFF80, u64 correct) ✓ matches universe expectation

(c) Verifier on 5 previously-failing V1 boundary mutations (ids 8, 10, 52, 76, 155): **5/5 PASS**.

(d) Regression test on 12 mid-trace mutations across all 6 affected kinds: **12/12 PASS** — no collateral damage.

**Status**: ready for full POS B1 re-run (Composer task — see `PHASE_7D_INC3B_WORK.md`).

---

## 4. B7 — root cause investigation status

### 4.1 Empirical observations

- 4 divergent reward rows out of 250, all `delta_T` ±1 bit:
  - V1 (zoned): mid=35 (MEM_VAL_MOD step=3780)
  - V3 (kindUCB_zoned_v2_noQ): mid=14 (INSTR_TYPE_MOD step=3928), mid=25 (COMP_OUT_MOD step=3016)
  - V4 (kindTS_zoned_v2): mid=37 (INSTR_TYPE_MOD step=1660)
  - V2 and V5: 0 divergences
- All other reward fields (`delta_F`, `n_fail`, `r_rep`, `d_loc`, `d_glob`, failure list) are identical at the divergent rows.
- All mutation configs are byte-identical between paired runs.
- All bandit decisions are byte-identical between paired runs.
- The `hook3_raw.raw_json` for the divergent rows shows different memory-family residue `(e0, e1, e2, e3)` values, but identical `compressed_ctx_json`.

### 4.2 Causes ruled out (with evidence)

| Hypothesis | Status | Evidence |
|---|---|---|
| Python reward calc nondeterminism | RULED OUT | Pure for-loops over indexed arrays; no set iteration in fields that affect `delta_T` |
| Python hash randomization affecting mutation selection | RULED OUT | All 50 mutation configs byte-identical between runA and runB |
| Inter-node trace ordering divergence (txn_idx remapping) | RULED OUT | `_info.byte_addr` byte-identical in configs |
| Same-machine host nondeterminism | RULED OUT | 5 local reruns of V1 mut 35 → byte-identical touch bitmaps |
| ZK challenge randomness affecting reward fields | RULED OUT | Only affects FpExt `e0…e3` values; `derive_global_contexts` consumes only the boolean `nonzero` and `broken_addrs`, both invariant under ZK noise |
| Same-CPU-model differences | RULED OUT | flare and octorand both AMD EPYC 9354, same libstdc++/glibc/kernel/SIMD flags |
| Build differences | RULED OUT | Same `host_sha256`, same `git_commit` on both nodes |

### 4.3 Localization

Cross-machine pairwise reward-row diff matrix for V1 zoned (50 mutations each):
```
                local-A    local-B    POS-A (flare)   POS-B (octorand)
local-A           ─          0           0                 1
local-B                      ─           0                 1
POS-A                                    ─                 1
POS-B                                                      ─
```

**3 out of 4 sources agree perfectly** (local-A, local-B, POS-A flare). Only POS-B (octorand) is the outlier.

### 4.4 Causes NOT yet investigated (and that we should)

| Hypothesis | Why it's still in the space | Cost to investigate |
|---|---|---|
| `a4_touch_mark` reachable from a parallel code path that isn't witgen's stepExec | Module-scope `g_a4_touch_bitmap`; if ANY parallel caller exists anywhere in autogen / prove, it races | Grep host source (cheap) |
| Code writing to `g_a4_touch_bitmap` AFTER witgen returns but BEFORE Rust reads stdout | Bitmap is cleared post-emission, but if anything writes between emission and clearing of the previous run it could race | Read full ffi.cpp control flow |
| stdout interleaving truncating `<a4_touch_coverage>` tag | Parser uses `re.search`; truncation could yield different bitmap | Check actual stdout from POS-B (need POS access) |
| POS injects env vars (`RAYON_NUM_THREADS`, `MALLOC_ARENA_MAX`) that vary per node | `pos.commands.launch` env not fully observed | Dump env in launcher (cheap, POS task) |
| Test-node image drift between allocations under same image label | "debian-trixie" image identifier, but image contents could update | Checksum key binaries on flare and octorand (cheap, POS task) |
| octorand-specific stable mechanism vs intra-octorand racy | Don't know if the 1-bit divergence is the SAME bit on octorand each time | Re-run B7 zoned twice pinned to octorand (medium, POS task) |
| Hash-randomized set iteration in B7 audit or fuzzer affecting reward fields | Haven't audited the audit script for nondeterminism | Grep / read audit code (cheap, local) |
| Identification of WHICH constraint context (loc, major, minor) is the divergent bit | Bitmap is not stored per-mutation; verbose mode would identify it | Re-run mut 35 locally with VERBOSE; for octorand, need POS task |

### 4.5 Phased investigation plan

**Phase α** (CHEAP, LOCAL, do first): Audit B7 + fuzzer + audit_common for any nondeterminism source affecting reward fields. ✅ **DONE** — see §4.6.

**Phase β** (CHEAP, LOCAL, do second): Capture verbose touch contexts for V1 mut 35 locally; build the candidate set of constraint contexts that could be the divergent bit. ✅ **DONE** — see §4.7.

**Phase γ** (POS-required, MEDIUM): Dispatch B7 zoned twice pinned to a single node (octorand and flare separately) to determine stable-vs-racey-per-node. Also dump env + checksum key binaries on each node at allocation time. Also capture verbose touch output for ALL 50 mutations on both nodes. **Status**: Composer task — see §8.

**Phase δ**: Mechanism hunt based on what α/β/γ revealed. **Status**: Opus task — back-to-Opus once γ reports.

### 4.6 Phase α results

Audited:
- `a4/audits/B7_seed_reproducibility.py` — `_diff_tables` uses `set(ra) | set(rb)` but only breaks on first per-column diff; order does NOT affect the diff COUNT. Audit is sound.
- `a4/standalone/coverage_state.py::compute_reward` — `f_weights` builds list from iterating `ext_contexts` (a set, hash-order-dependent). BUT the list is then `sort(reverse=True)` by `(weight, context_tuple)` and Python tuple comparison breaks ties by the context tuple (which is fully ordered), so `F_rare` is hash-seed-invariant. Deterministic.
- `a4/standalone/coverage_state.py::update_state` — set/dict reads/writes but no order-sensitive operations affecting persisted state. Deterministic.
- `a4/standalone/coverage_state.py::derive_global_contexts` — set comprehensions with deterministic membership tests; the `sorted(ctx)` safety-cap path is sorted-deterministic. Deterministic.
- `a4/core/touch_coverage.py::count_new_bits, merge_into_global` — pure for-loops over indexed bitmap. Deterministic.
- All trace/constraint/touch/family parsers in `a4/core/` — pure regex over line-iterated stdout. Deterministic.
- `a4/standalone/fuzzer.py` reward-path call sites — pass `exec_result.touch_bitmap`, `failures`, `global_contexts` directly into `compute_reward`; no intermediate set-iteration. Deterministic.

**Conclusion**: The Python pipeline is fully deterministic given the host's stdout. **The divergence must be in the host's stdout** (specifically the `<a4_touch_coverage>` base64 bitmap, since `compressed_ctx_json` and `family_residue nonzero` flags are identical between flare and octorand at mid=35).

### 4.7 Phase β results

Ran V1 MEM_VAL_MOD step=3780 txn_idx=31423 word=0xBE951694 locally with `A4_COVERAGE_TOUCH_VERBOSE=1`:
- Touched 1615 distinct `(loc, major, minor)` contexts
- Maps to 1600 unique FNV-1a bitmap buckets
- 15 buckets have hash collisions (2+ contexts hashing to same bucket)
- Bitmap nonzero count exactly matches verbose unique-bucket count (1600 == 1600) — no spurious extra bits, no missing bits

This is the **local-deterministic universe of contexts** that any flare/octorand mut 35 touch bitmap must be a subset of (assuming no contexts beyond what local touches exist). If octorand has 1 extra bucket, it must be either:
- a bucket NOT in the 1600 local-touched set (= a constraint that fires on octorand at mut 35 but never on WSL/flare), OR
- a bucket IN the 1600 set that octorand's earlier mut N missed (so octorand's global went into mut 35 missing that bit), making it count as "new" at mut 35

Snapshot saved at `/tmp/v1_mut35_verbose.json`.

**Cannot proceed further locally** — pinpointing the specific bit requires octorand's actual mut 35 verbose touch output (Phase γ).

### 4.8 What Phase γ must collect

For Composer to enable the mechanism hunt (Phase δ), the POS dispatch must capture:

1. **Verbose touch output (`<a4_touch_verbose>` and `<a4_touch_debug>`)** for every host invocation in the campaign on both nodes. Requires setting `A4_COVERAGE_TOUCH_VERBOSE=1` in the launcher env.
2. **Full per-node env dump** at the start of `run_campaign_pos.sh`: `env > $RESULTS/env.txt; cat /proc/cpuinfo | head -50 > $RESULTS/cpuinfo.txt; uname -a > $RESULTS/uname.txt; cat /proc/meminfo > $RESULTS/meminfo.txt; sha256sum /lib/x86_64-linux-gnu/libstdc++.so.6 /lib/x86_64-linux-gnu/libc.so.6 > $RESULTS/lib_shas.txt`.
3. **Same-node paired runs**: dispatch B7 zoned `seed=999 n=50` TWICE pinned to octorand alone, then TWICE pinned to flare alone. (4 runs total; 2 same-node pairs).
4. **Cross-node paired runs (reproduce the original)**: dispatch B7 zoned ONCE on flare and ONCE on octorand (1 run each, paired by audit) to verify the original 1-bit divergence reproduces.

Expected outcomes and what they tell us:
| Result | Interpretation |
|---|---|
| octorand-pair: 0 diffs; flare-pair: 0 diffs; cross-node: 1 diff | Each node is internally deterministic; nodes disagree by a stable per-node mechanism (microcode / NUMA / env). δ: hunt the cross-node difference using the env dumps. |
| octorand-pair: 1 diff; flare-pair: 0 diffs; cross-node: 1 diff | octorand has intra-node nondeterminism; flare doesn't. δ: hunt thread races / racy memory in the host that manifest on octorand specifically. |
| octorand-pair: 0 diffs; flare-pair: 1 diff (different mut) | Both nodes have intra-node nondeterminism; just rare. δ: hunt host races regardless of node. |
| octorand-pair: 1 diff (different mut each time) | Pure intra-node racy. δ: same as above. |
| All pairs: 0 diffs (cross-node also 0) | The original divergence was a one-off transient. Re-run a few more samples to confirm. |

Phase γ is well-scoped, doesn't need code changes (just env dump additions to the launcher), and is the smallest empirical step that constrains the next move.

---

## 5. Inc 3b results (Composer empirical, 2026-06-11)

### 5.1 B1 closure (5×200 = 1000 muts, 5-way POS parallel)

| Variant | Node | Failures | Verdict |
|---|---|---|---|
| V1 zoned | flare | 0/200 | PASS |
| V2 kindUCB_zoned_v1 | octorand | 0/200 | PASS |
| V3 kindUCB_zoned_v2_noQ | opulous | 0/200 | PASS |
| V4 kindTS_zoned_v2 | meld | 0/200 | PASS |
| V5 cTS_semantic_v2 | idex | 0/200 | PASS |
| **Total** | | **0/1000** | **PASS** |

Both Bug 1 (INSTR_TYPE_MOD cycle-shift) and Bug 2 (MEM_VAL_MOD byte_addr overflow) fully resolved across all variants and all 5 POS nodes. Patched host SHA `c2e77443…`. B1 gate cleared.

Smoke ensemble (§A.3): pre-fix host vs post-fix host on 100 mutations seed=12345 → 0 reward-row diffs. No collateral damage. (Ran on WSL by mistake — that's a procedural slip with no analytical consequence.)

### 5.2 B7 Phase γ — what was learned

Composer ran 4 same-node paired campaigns (zoned, seed=999, n=50) with the pre-fix host on debian-trixie:

| Pair | Same node? | `mutation_rewards_diff` | Pass? |
|---|---|---|---|
| flareA vs flareB | yes (flare) | **0** | PASS |
| octoA vs octoB | yes (octorand) | **1** | FAIL |

The single octorand diff (verified by Opus from the DBs):
- **mut id=25, kind=PRE_EXEC_REG_MOD, step=2296** (mid-trace, not a boundary)
- `delta_T`: octoA=1, octoB=0
- Downstream cascade only: T_new (0.028 → 0), T_rare (0.226 → 0.20), S (0.313 → 0.305), reward (0.0699 → 0.0681)
- All other 49 mutations identical between the two runs

Fingerprint per node:
- **`libstdc++.so.6` / `libc.so.6` / `libm.so.6` / host binary**: identical SHAs across flare and octorand ✓
- **`cpuinfo` microcode**: flare `0xa10113e` vs octorand `0xa101116` — **different revisions**
- **CPU flags**: `amd_lbr_pmc_freeze` present on octorand only (more recent AMD feature)
- `env.txt`: only SSH client IP/port differs (expected)

### 5.3 B7 hypothesis-space reduction

| Hypothesis | Status after Inc 3b | Why |
|---|---|---|
| Python pipeline nondeterminism | Ruled out (Inc 3 Phase α) | Pure deterministic data structures |
| Cross-machine library / image / env drift | **Ruled out** | `lib_shas.txt` matches across nodes |
| Stable per-machine differences (compiler / link / static config) | **Ruled out** | If stable per-node, octoA and octoB would produce IDENTICAL output (both differ from flare in the same way); they don't — they differ from each other |
| **Per-machine racy host behavior on octorand** | ✅ **Confirmed** | octoA-vs-octoB shows 1 bit diff with everything else identical |
| CPU microcode plausibility-multiplier | Open candidate | Different microcode rev on octorand; doesn't directly cause intra-octorand divergence but could explain why race exposes on octorand and not flare |
| `g_a4_touch_bitmap[idx]++` non-atomic race | Open candidate | Increment is non-atomic; if ANY parallel call path reaches `a4_touch_mark`, racy |
| Race inside witgen `stepExec` accessing shared mutable state | Open candidate | Even with outer loop sequential (forced by `A4_COVERAGE_TOUCH=1`), inner can race |
| Memory allocator / std::set ordering / std::map iteration in verbose context tracking | Open candidate | Hash table reorderings, allocator behaviors are microcode-sensitive |

### 5.4 Why this is NOT a cross-node mystery anymore

Original framing (Inc 3): "Why does octorand disagree with flare?"

Re-framing (Inc 3b): "octorand disagrees with itself across runs. flare doesn't. The mechanism is a race condition that the octorand microcode exposes (or the flare microcode masks). The cross-node disagreement seen in Inc 3 was just one realization of the same intra-octorand race."

The cross-node disagreement at mut 35 (MEM_VAL_MOD step=3780) and the intra-octorand disagreement at mut 25 (PRE_EXEC_REG_MOD step=2296) are different *realizations* of the same underlying mechanism. They land on different mutations because of stochastic scheduling, but they share:
- Same node family (octorand)
- Same delta_T ±1 shape
- Same single-bit nature

This is consistent with "race condition that fires probabilistically, ~1/50 mutation rate."

### 5.5 Confirmed system invariants from code-read (Opus)

Reading `risc0/circuit/rv32im/src/prove/hal/mod.rs` lines 146-153 and `ffi.cpp`:
- When `A4_COVERAGE_TOUCH=1` is set, `StepMode::SeqForward` is **forced** for the witgen step loop.
- In `kStepModeSeqForward` (ffi.cpp line 401-438), the loop `for (cycle=0; cycle<lastCycle; cycle++) stepExec(...)` is **single-threaded**.
- In the accum phase 1 (ffi.cpp line 673-724), when `A4_COVERAGE_TOUCH=1` is set, the accum loop is **also forced sequential** (line 686-688).
- The non-atomic `g_a4_touch_bitmap[idx]++` (line 128-129) is only called from `a4_touch_mark`, which is called from `stepExec` and `stepAccum` — both of which are forced sequential when touch coverage is on.

**This means the OUTER loops are guaranteed single-threaded.** The race must be either:
- (a) Inside `stepExec` / `stepAccum` (sub-function-level parallelism)
- (b) In a different phase that touches `g_a4_touch_bitmap` without honoring the env-var gating
- (c) Below the host code — at the CPU / memory subsystem level (very unlikely but possible with microcode differences)

This is the structural surface area that Phase δ must explore once we have the divergent context.

---

## 6. Phase δ — closure plan

### 6.1 Objective

Identify the **exact constraint context `(loc, major, minor)` whose touch bit racily differs on octorand**, then trace that context through the witgen code to identify the racy code path, and confirm the mechanism (e.g., "non-atomic bitmap increment from a parallel iterator escapes the SeqForward guard at line X").

### 6.2 Why the patched host (c2e77443) is fine for this

The patched host has:
- B1 fix in `instr_type_mod.py` (universe-gen only; not in compiled binary)
- B1 fix in Rust `INSTR_TYPE_MOD` hook (only fires when `mutation_type==INSTR_TYPE_MOD`)
- B1 fix in Rust `MEM_VAL_MOD` logging (only prints byte_addr; doesn't change behavior)
- **Verbose touch emission code in `ffi.cpp`** (was already present before B1 fix)

The B7 races we've observed are on `PRE_EXEC_REG_MOD step=2296` (intra-octorand) and `MEM_VAL_MOD step=3780` (cross-node). Neither is `INSTR_TYPE_MOD`, neither is at a boundary, neither exercises the byte_addr-printing path. So my B1 fix CANNOT affect the race reproduction.

Using the patched host means we don't need to build a separate "pre-fix + verbose" binary. We can just dispatch the existing patched host to octorand with `A4_COVERAGE_TOUCH_VERBOSE=1` and we'll get the verbose output.

Risk mitigation: if for any reason the race does NOT reproduce on the patched host (e.g., we got unlucky and 100 muts isn't enough), we fall back to building a pre-fix-mutation + verbose-emission host. But this is unlikely to be needed.

### 6.3 Experiment design

**6.3.1 Capture phase (Composer, POS)**

Dispatch the patched host bundle to octorand for 4 paired runs + 1 flare control pair (see `PHASE_7D_INC3C_WORK.md` §2 for the exact layout):
- α: octorand n=50 seed=999 (primary race capture)
- β: octorand n=50 seed=999 (reproducibility of α)
- γ: octorand n=50 seed=1000 (seed sensitivity)
- δ: octorand n=50 seed=1001 (second seed sensitivity)
- ctrl-flare: flare n=50 seed=999 (negative control — confirms patched host doesn't introduce a new flare race)

All runs with `A4_COVERAGE_TOUCH_VERBOSE=1`, `telemetry_level=full`. Total: 10 runs × 50 muts × ~3 sec/mut = ~25 min POS compute; ~1 hour wall-time after dispatch / pull-back overhead. We keep `n=50` so the existing `B7_seed_reproducibility.py` matchers work without modification.

**6.3.2 Parsing (Opus, post-capture)**

For each pair, parse the per-mutation `<a4_touch_verbose>` line from each host invocation (captured to `campaign.log` by `run_campaign_pos.sh`, see §93/§249 in that script). For each pair:
- Compute the verbose context set for each (mutation_id, run) tuple.
- For each mutation where the reward-row diff (mutations table) shows divergence, compute the symmetric difference of the verbose context sets between the two same-pair runs.
- The contexts in the symmetric difference are the candidate racy constraint contexts.

If across all racy mutations (~2 expected per octorand pair × 4 pairs = ~8 total bits), the divergent contexts cluster on ONE or a SMALL set of `(loc, major, minor)`, that's the racy constraint family.

**6.3.3 Code trace (Opus)**

For each identified `(loc, major, minor)`:
- `loc` is a string like `AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:67)`. The file:line points to the ZIR constraint source.
- Read the witgen-generated code that evaluates this constraint (auto-generated from the .zir).
- Identify any non-trivial memory access pattern: read of a shared mutable, write to a global, dispatch through a function pointer, etc.
- Cross-reference with `ffi.cpp::a4_touch_mark` call sites to find where in the witgen `stepExec` / `stepAccum` chain this constraint gets touched.

**6.3.4 Race confirmation (Opus + Composer)**

Two complementary confirmations:

(a) **Static**: trace from the racy `(loc, major, minor)` back through the witgen code to a specific call path; identify either (i) a non-atomic shared write, (ii) an unsafe iteration over a structure with non-deterministic ordering, or (iii) a path that escapes the forced sequential mode.

(b) **Dynamic** (optional if static is conclusive): build a host variant that makes `bitmap[idx]++` atomic (e.g., `__sync_fetch_and_add`) and re-run the octorand pair. If atomicizing eliminates the race, that's mechanism-confirmation by intervention.

### 6.4 What constitutes 100% closure

B7 is closed when ALL of the following hold:
1. We have the **exact `(loc, major, minor)`** of the divergent context (from verbose capture).
2. We can **point to the specific witgen code path** that touches it and explain why it races on octorand.
3. We can **describe the role of microcode**: either (a) the race is purely software and microcode is a red herring, or (b) the race exists in software but specific microcode behavior is required to expose it (and we can name what about the microcode).
4. We have a **stated fix** (even if we choose not to apply it): e.g., "make the bitmap increment atomic" or "remove the parallel iterator from this code path."
5. We **understand the impact on prior fuzzing campaigns**: how many bits of prior reward signal are affected, and whether it materially changes any decision we made.

If we cannot reach (1) after the capture phase (e.g., verbose contexts don't cluster), we widen the experiment — more pairs, different seeds, different mutation kinds.

---

## 7. Opus open work after Inc 3b

- [x] Document Inc 3 findings (this file)
- [x] B7 Phase α/β (Inc 3 — Python + local determinism audit)
- [x] B1 Option B fix designed, implemented, locally verified
- [x] Inc 3b work order written (`PHASE_7D_INC3B_WORK.md`)
- [x] Reviewed Inc 3b results, verified all claims from artifacts (§5)
- [x] Designed Phase δ closure plan (§6)
- [ ] Write Composer Phase δ work order (`PHASE_7D_INC3C_WORK.md`)
- [ ] After capture lands: parse verbose contexts, trace divergent `(loc, major, minor)` to code, identify race mechanism
- [ ] Update this doc with closure summary; mark B7 PASS; mark Phase 7d complete

---

## 7. Cross-references

- `PHASE_7D_INC3_REPORT.md` — Composer's empirical Inc 3 results
- `PHASE_7D_INC3_WORK.md` — Original Inc 3 work order (B1/B2/B4/B7)
- `/root/arguzz/a4/audits/audit_output/inc3_b7/` — B7 paired DB outputs
- `/root/arguzz/a4_coverage.db` — historical campaign DB (local)
- `/tmp/b7_local_A.db`, `/tmp/b7_local_B.db` — Opus's local paired B7 zoned runs (for cross-check vs POS)
- `coinbase:~/b1_verify_work/out/B1_V*.json` — Composer's B1 strict verifier outputs (now complete)
