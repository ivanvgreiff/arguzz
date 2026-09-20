# IV.POS.9 Track-B — sweep re-run due to the Arguzz step-domain mismapping

**Created 2026-06-27.** A bug found by Track A (the Arguzz **step-domain / zone mismapping**, fixed `68d90aa`)
contaminates part of the Track-B multi-guest coverage sweep. These docs are the Track-B response: the impact
analysis, the re-run plan, and the data-hygiene plan that guarantees we never plot buggy data.

## TL;DR

- **The bug:** Arguzz bandit arms compute `zone = step_to_zone[executor_step]`, but that table is keyed by
  **witgen `user_cycle`** — and the two counters drift by the running host-ecall count. So every Arguzz arm's
  **zone label is scrambled** (injection + `opcode_class` are fine). Fix: translate `executor → user_cycle`
  before the lookup (rebuild-free, Python only). Full mechanism: `../arguzz_step_domain_fix/`.
- **Track-B impact:** the **CGC** (compressed-global) metric — our headline — embeds the mislabeled
  `zone/major`, so it's wrong on **every Arguzz surface**, and the bandit's reward was inflated on the
  cTS/Hybrid runs.
- **Verdict by variant:** **V5_control** = valid (A4-only; keep). **V6_cTS, Hybrid_cTS** = confounded
  (re-run). **V6_uniform** = selection sound but CGC labels wrong (re-run recommended).
- **The trap:** the just-finished **3-kind re-run** fixed the binary but ran the **pre-fix** bundle — so its
  **Hybrid_cTS half is still confounded**; only its **V5_control half** survives.
- **Re-run:** V6_cTS + Hybrid_cTS (+ V6_uniform), N=5000 × seeds 1234/1235/1236 × g0–g3, on the
  **same binary** + bundle `68d90aa`. **Gate per guest first** (the fix was only N=1000-validated on Track A's
  guest). **Keep V5_control** from the 3-kind re-run.
- **Hygiene:** quarantine the pre-fix `data/` DBs; build a provenance-stamped `data_clean/`; make the notebook
  **refuse to plot** anything not provenance-verified.

## Read order

1. **[01_FINDINGS_AND_IMPACT.md](01_FINDINGS_AND_IMPACT.md)** — how the bug lands on our 4 variants and our
   metrics; the two-bug (3-kind × step-domain) interaction; full data inventory; what's valid vs confounded.
2. **[02_RERUN_PLAN.md](02_RERUN_PLAN.md)** — the fixed bundle, the **mandatory per-guest validation gate**,
   the re-run scope (+ the V6_uniform and V5 decisions), POS dispatch, post-run verification.
3. **[03_DATA_HYGIENE_AND_MAPPING.md](03_DATA_HYGIENE_AND_MAPPING.md)** — quarantine, the clean dataset,
   provenance manifest + self-identifying DBs, and the exact variant→display-label→PNG mapping checklist.
4. **[04_EXECUTION_RUNBOOK.md](04_EXECUTION_RUNBOOK.md)** — the exact reproducible procedure used to deploy +
   launch on the throttled POS: the `dangerouslyDisableSandbox` gotcha, base64-not-heredoc, parallel
   hash-gated deploy, node recovery (allocate+reset), the run-gate (glibc), and the launch. Read this to redo it.
5. **[05_SWEEP_HISTORY_AND_PROVENANCE.md](05_SWEEP_HISTORY_AND_PROVENANCE.md)** — the auditable record: the 3
   sweep runs, the 2 errors that caused re-runs, which DBs belong to which run, the final valid-data lineage,
   and how to confirm any DB's provenance. Reconstructed from git + per-DB fingerprints, not memory.

## Status

- [x] Bug understood & Track-B impact analyzed (source-grounded).
- [x] Plan written (these docs).
- [ ] **Awaiting user go-ahead** on: (D1) re-run vs recompute V6_uniform; (D2) keep vs re-run V5_control.
- [ ] Per-guest validation gate.
- [ ] Re-run + clean-dataset assembly + notebook/HTML regen + headline re-derivation.

> Note: the POS dispatch host (coinbase) had a tmpfs-full outage 2026-06-27 (now recovered). The re-run must
> stage the bundle on a **disk-backed** path, not coinbase `/tmp` (RAM). See [02 §4](02_RERUN_PLAN.md).
