# C1.1 — Fix site sampling + flag symmetry, re-run pilot

Supersedes the sampling portion of `C1_SPEC.md`. The C1 pipeline/classifier are correct
and stay as-is. This increment fixes **where** we inject and **with which flags**, then
re-runs the pilot. Do not modify anything outside `thesis_side_experiments/bias_campaign/`.

## Why (root causes found in source review)

1. **Harness sampled the bootloader.** `sample_eligible_step` returns `steps[seed % len]`
   over a **trace-ordered** list, so seeds 0–49 = first 50 executor steps = machine-mode
   bootloader. Max inject step was 528 while the real trace runs to ~4000.
2. **Arguzz is blind, A4 is target-validated.** `rv32im.rs::is_injection` fires purely on
   `current_step == injection_step` (no pc/privilege/target check) → Arguzz injected into
   kernel space (98/300 runs, `pc ≥ 0xC000_0000`). A4 returns `None` with no witness target
   → 50 skips. This is an architectural asymmetry, not a bug to normalize away.
3. **Flag asymmetry.** `FAULT_INJECTION_ENABLED` is auto-set only when `A4_MUTATION_CONFIG`
   is present (`witgen/mod.rs:224`), i.e. only for A4. Arguzz proves without it and hits the
   raw `preflight.rs` OOB → some `PREFLIGHT_CRASH` are a flag artifact. (`SeqForward` is
   already symmetric: forced by `A4_COVERAGE_TOUCH`, set for both.)

Memory map (from `platform.rs`): user space = `[0x0001_0000, 0xC000_0000)`; kernel/machine =
`[0xC000_0000, 0xFF00_0000)`; memory-mapped user regs at `0xffff_0080`.

## Design decision (important)

We measure two different things and must not conflate them:

- **MARGINAL (primary).** Each fuzzer samples its **own native, user-space** reachable
  sites. Captures selection bias + propagation bias. This is the primary metric
  (target/fail distribution over L1 / L2 / ACCUM / G).
- **MATCHED (secondary, prep for C3).** Both fuzzers pinned to the **same** validated
  user-space site. Isolates propagation given an equal target. No silent step-shift.

Plus an explicit **SELECTION-BIAS metric**: per kind, how many user-space sites each fuzzer
can target, and the Arguzz-only fraction (sites A4 structurally cannot reach).

## Tasks

### T1 — Tag site space in `guest_sites.py`
- For each trace step record, add `"space"`: `"user"` if `0x10000 <= pc < 0xC0000000`,
  else `"kernel"` (or `"zero"` for `pc < 0x10000`).
- Build `eligible_steps_by_kind` from **user-space steps only**.
- Add `a4_valid_steps_by_kind`: the subset of user-space steps where `build_a4_config`
  returns non-`None` (pre-validate by calling the A4 creators during site build, using a
  throwaway seed). This is the source of truth for A4’s reachable set and the matched set.
- Persist counts: `{kind: {arguzz_reachable, a4_reachable, both, arguzz_only}}`.

### T2 — Spread sampling across the full trace
- Replace `sample_eligible_step`’s `steps[seed % len]` with seeded sampling that spreads
  across the whole eligible list (e.g. seeded-shuffle then index by seed, or evenly-strided
  index `steps[(seed * len // N) % len]`). Goal: inject steps must span the full trace, not
  the first 50.
- MARGINAL mode:
  - Arguzz: sample from `eligible_steps_by_kind[kind]` (user-space).
  - A4: sample from `a4_valid_steps_by_kind[kind]` → **no skips**.
- MATCHED mode: sample from `a4_valid_steps_by_kind[kind]`, run **both** fuzzers at that
  exact step. Remove the `arguzz_step + attempt` retry/`seed+attempt` shift in
  `run_a4_kind` — if a site is invalid it should not be in the list. Drop (don’t shift).

### T3 — Equalize `FAULT_INJECTION_ENABLED`
- In `run_arguzz.py`, add `FAULT_INJECTION_ENABLED=1` to the Arguzz run env so proving
  continues past the structural preflight OOB and we observe constraint failures.
- Keep a **secondary native-crash measurement**: a small Arguzz sub-run (e.g. N=20/kind)
  **without** `FAULT_INJECTION_ENABLED` to report Arguzz’s native crash propensity honestly.
  Label these rows distinctly (e.g. `fuzzer="arguzz_native"`), do not mix into the main
  marginal distribution.

### T4 — Re-run pilot (MARGINAL), keep matched as a labeled subset
- N = 50 seeds/kind/fuzzer, 6 aligned kinds, c0/c1 guest, same `DEFAULT_ENV`.
- Write to a fresh DB (`artifacts/c1_1/pilot.db`); keep the watchdog.
- Regenerate `guest_sites.json` (do not reuse the kernel-contaminated one).

### T5 — Report `artifacts/c1_1/C1_1_REPORT.{md,json}`
Add to the existing report shape:
- `injection_space_breakdown`: must be ~100% user for both fuzzers (sanity).
- `step_coverage`: min/max/distinct inject steps per fuzzer — max must approach trace length.
- `selection_bias`: the per-kind reachable/arguzz_only table from T1.
- `outcome_distribution`, `target_category_distribution`, `fail_category_distribution`
  (L1/L2/ACCUM/G), `reachability`, `detection_rate`, `soundness_escapes` — as in C1.
- `native_crash_rate`: from the T3 secondary sub-run.

## Acceptance gate
- C0 regression still green; classifier unchanged.
- **0 kernel-space injections** for either fuzzer in the main marginal runs.
- **0 A4 skips** (A4 only sampled from `a4_valid_steps_by_kind`).
- Inject-step coverage spans the full trace (max ≈ trace_step_count, not ~528).
- Both fuzzers: 50/50 active per kind on the marginal set.
- ≥5 outcome classes observed; 0 soundness escapes.
- Selection-bias table populated (shows the Arguzz-only reachable fraction per kind).
- Determinism spot-check (3 seeds × 2 runs) passes.

## Notes
- This is still local. Do not start C2/POS until C1.1 gate is green.
- If `FAULT_INJECTION_ENABLED=1` for Arguzz changes witness semantics in a way that makes a
  failure’s `loc`/residue look inconsistent with the injected value, flag it (don’t silently
  accept) — we validated provenance in M2 and want the same discipline here.
