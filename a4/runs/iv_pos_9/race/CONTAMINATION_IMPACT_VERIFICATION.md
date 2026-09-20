# A3 bug race — impact of the Track-B 3-kind binary-mismatch contamination (verified)

**Date:** 2026-06-27 · **Author:** Opus (Track A). **Trigger:** `a4/runs/iv_pos_9/sweep/CONTAMINATION_AND_FIX_3KIND.md`.
**Question:** did the 3-kind silent-skip contamination affect the A3 thesis race result (4×10×N=5000, the
A4-findable VerifyOpcode race)? **Verdict: the headline result is UNAFFECTED and proven real; a bounded
second-order effect inflates the A4/Hybrid find COUNTS via the bandit (not the verdict).** Verified
empirically (binary + all 40 DBs + control replay), not by inference.

## 1. The contamination, and whether it reached our binaries — YES
The 3 A4 kinds `TXN_PREV_WORD_MOD`/`TXN_PREV_CYCLE_MOD`/`CYCLE_DIFF_COUNT_MOD` lack witgen handlers at
HEAD `93bda33b` (added later in `6556e8d7`). Our race binaries are head `93bda33b`, so they are affected:
- **`strings` on BOTH our binaries** (holed `53ee6663…`, control `4e0f841c…`): the 3 kinds = **0**, but
  **`INSTR_TYPE_MOD` = present**, `INSTR_WORD_MOD`/`MEM_VAL_MOD` present.
- **Silent-skip signature in our DBs:** for the 3 kinds, **applied == accepted exactly** (V5 15327==15327,
  Hybrid 7227==7227) and **`num_failures=0` on all 1541** (V5) — no trace change. Control replay of a
  sample: `invalid_config_noop=True`, no VerifyOpcode reject (6/6). So V5/Hybrid did record fake
  `applied`/`accepted` no-ops for the 3 kinds. **Arguzz (V6) applies 0 of the 3 kinds → untouched.**

## 2. The headline result is UNAFFECTED (proven)
The finds come ONLY from `INSTR_TYPE_MOD`, which IS implemented:
- **Every find is `INSTR_TYPE_MOD`** (V5 821, Hybrid 389, both Arguzz 0). No contaminated kind is ever a find
  (the find predicate `is_decode_divergent_itm` excludes non-ITM by definition).
- **G-REPRO (control replay, 8/8 sampled thesis finds):** control **rejects @ `VerifyOpcode`** → the decode
  genuinely changed → **real finds, not silent skips.**
- **Arguzz** applies 0 ITM and 0 of the 3 kinds → `P(found)=0` is real and structural.
- ⇒ **`P(found)` (1.00/1.00/0/0), `conditional_find_density` (6.8%/7.2%, = finds/ITM-applied, bug-intrinsic),
  and the structural complementarity are UNAFFECTED.** The 3-kind no-ops only inflate the (correctly
  excluded) non-planted-accept counts and the `applied` denominator.

## 3. The second-order effect on the bandit (the real subtlety)
The cTS scheduler (V5/Hybrid) splits selections **floor 74% / adaptive 21% / cold 5%**.
- The dead arms earned the bandit's **minimum** reward: `num_failures=0` → Bernoulli failure every pull →
  posterior `alpha` frozen at prior 2.0, `beta` grows (2→11→26→50) → `mean_reward → 0.02`. The **adaptive**
  component correctly **avoided** them (≈475 floor vs ≈9 adaptive picks per kind).
- (Note: `mutation_rewards.reward=1.0` for the no-ops is a **degenerate logging fallback** when all reward
  components are 0 — the bandit does NOT use it; its posterior fell. Worth fixing in the reward log, but it
  did not corrupt selection.)
- **ITM is the top live arm** (posterior 0.18) → captured **72% of all adaptive picks** (752/seed). Because
  the dead arms vacated the adaptive competition, **ITM's adaptive selection is inflated vs a clean run**,
  where the 3 working kinds (≈ OTHER-live: n_fail≈2.5, posterior≈0.1) would reclaim some adaptive budget.

**Direction:** our A4/Hybrid find COUNTS are a **mild over-estimate** of a clean-cTS run.
**Magnitude (precise, from partitioning finds by selection mode):**

| variant | total finds (10 seeds) | FLOOR/cold = robust (fixed per-arm, dead-arm-independent) | ADAPTIVE = confound-exposed |
|---|---|---|---|
| V5_control | 821 | **392 (48%)** | 429 (52%) |
| Hybrid_cTS | 389 | **308 (79%)** | 81 (21%) |

Floor finds are guaranteed regardless of the dead arms (the floor share of ITM is set by the arm count,
which is identical clean or dead). So the clean-cTS count is **bounded below** by the floor finds
(V5 ≥392 ≈ 39/seed, Hybrid ≥308 ≈ 31/seed) and **above** by our counts (82 / 39 per seed). Even the worst
case keeps `P(found)=1.0` with huge margin. Find-rate is mode-independent (floor 8.6–8.9% ≈ adaptive
4.1–5.7%), confirming the rate is bug-intrinsic.

## 4. Bottom line + recommendation
- **The thesis headline (the complementarity: A4/Hybrid find the decode hole, pure Arguzz cannot) stands as
  published — it is proven robust and the finds are real.** No re-run needed for that claim.
- **For the absolute find COUNT / a quantitative "cTS schedules ITM at rate X" claim:** report
  `conditional_find_density` (clean, bug-intrinsic) + `P(found)` (clean) as the load-bearing numbers and
  note the absolute count is scheduler-dependent and mildly contamination-inflated — **OR** re-run
  V5_control + Hybrid_cTS on a **fixed** binary (cherry-pick `6556e8d7` onto the Seam-B worktree → rebuild
  holed+control, new guest_image_ids; ~20 jobs). The 20 Arguzz runs are valid as-is (binary-invariant).
- **Prevention (shared):** add the runner guard — record `outcome=not_applied` when the host emits
  `<a4_error>invalid config` — and fix the reward log's 1.0-fallback for zero-signal mutations.

## 5. Fix recipe for a FUTURE Track-A campaign (build the 3 kinds live; isolation-safe)
**Essence:** the *only* change vs the original Seam-B build is "cherry-pick `6556e8d7` before compiling."
Verified clean: `93bda33b:witgen/mod.rs == 28e53771:witgen/mod.rs` (empty diff → pure replay); `6556e8d7`
edits `witgen/mod.rs` ONLY (not `rv32im.rs`/load_rs2, not the `rust_poly_fp_*/steps.cpp/poly_ext.rs`
artifacts that carry our VerifyOpcode hole) → bug + load_rs2 preserved, no conflict with the patch.

Worktrees (do NOT touch the others): ours = `workspace/risc0-seamb` (93bda33b). Off-limits:
`risc0-clean-28e53771`@53c21894 (sweep, already fixed), `risc0-modified`@6556e8d7 (AP/race),
`risc0-a1-vuln`@088a0753 (CVE).

1. **Clean base** on `risc0-seamb`: revert the artifact-only VerifyOpcode patch (it's reproducible via
   the script): `git -C workspace/risc0-seamb checkout -- risc0/circuit/rv32im-sys/.../{rust_poly_fp_*,steps}.cpp risc0/circuit/rv32im/src/zirgen/poly_ext.rs`.
2. **Add handlers:** `git -C workspace/risc0-seamb cherry-pick 6556e8d7` (clean replay). Verify
   `git grep -c TXN_PREV_CYCLE_MOD -- .../witgen/mod.rs` ≥1 for all 3 kinds; `rv32im.rs` untouched.
3. **Build CONTROL** (handlers, no hole): `cargo build --release -p risc0-host` → control. (NEVER broad-
   `pkill` cargo — shared across worktrees; target by path/PID.)
4. **Build HOLED** (handlers + hole): re-apply `python a4/scripts/ap_verifyopcode_patch.py` (artifact-only,
   composes with the handlers) → `cargo build --release -p risc0-host` → bench-verifyopcode.
5. **Verify the 3 kinds are LIVE:** `strings` both binaries → the 3 kinds now ≥1 (were 0), INSTR_TYPE_MOD
   still present; replay a `TXN_PREV_CYCLE_MOD` injection → now `applied` with `num_failures>0` (a real
   reject), NOT `<a4_error>invalid config`. Re-run A3 Stage-0: ITM finds still reject @ VerifyOpcode (bug
   intact), negative control → 0.
6. **Re-fingerprint + re-wire:** read the rebuilt fingerprints; update `generate_race_manifests.py`
   `EXPECT_HEAD_SHA` to the new HEAD (+ `EXPECT_GUEST_ID` only if the guest image actually changed —
   adding a host-side witgen handler should not change the guest ELF); re-bundle + re-deploy. Guard still
   asserts `planted_bug=verifyopcode/none, load_rs2=1`.
7. **Prevention:** land the runner guard (record `not_applied` on `<a4_error>invalid config`) so a missing
   handler can never silently mis-record again.
