# A3.1 — race harness + unit tests + Stage-0 ground truth: DONE & GREEN

**Date:** 2026-06-23 · **Author:** Opus (OCP) · **Spec:** `../../../docs/cloud3/IV_POS_9_A3_SEAMB_RACE_SPEC.md` (v0.3).
**Scope:** local, **zero POS** — the certainty gate (G-UT/G-NEG/G-CTRL) that must pass before any POS dispatch (A3.2).

## What was built
| file | role |
|---|---|
| `a4/pos/fingerprint_guard.py` | + `verifyopcode` profile (`load_rs2_present=1, planted_bug=verifyopcode`); head/guest enforcement already supported |
| `race/oracle.py` | accepts via the **`verifier_accepted` COLUMN** (F10, not the Arguzz-only `config_json.soundness_signal`); ITM-decode-divergent filter; control-confirm with **LOCUS parse @ VerifyOpcode** (`CONSTRAINT_CONTINUE=1`); guards the control binary (G-CTRL); pluggable `control_check_fn` for testability |
| `race/markers.py` | per-(variant,seed) found / first_find_idx (censored=N+1) / n_finds / n_applied / n_instr_type_mod_applied / find_density / **conditional_find_density** / find_kinds; per-variant P(found) + discovery CDF; JSON+CSV |
| `a4/pos/generate_race_manifests.py` | D2.F-clone chain manifest; **guard-prefixed** every job (`--profile verifyopcode --head-sha --guest-id`, abort rc 87); Seam-B guest args; `pos_iv_pos_9_a3seamb_*` run-ids; host = `/root/a4_campaign/bin/risc0-host` (bundle ships the holed binary) |
| `race/tests/test_race.py` | 12 unit tests (pure-logic/mocked, fast) |
| `race/run_stage0.py` | the gated integration on the real binaries |

## Gate results (all GREEN)
- **G-UT (unit tests):** 12/12 pass (`pytest`, 0.36 s). Covers: the `verifyopcode` profile (passes holed, fails control + guest-id mismatch); confirmed-find; no-op exclusion; result-changer-not-an-accept; control-guard; markers extraction + censoring; discovery CDF; conditional density (Arguzz n_itm=0 → None, not div0); manifest generator (guard prefix, holed host, no control target, rc 87); variant launch argv; triage import; **F10 regression** (A4 accept via column, not soundness_signal).
- **G-UT (Stage-0 ground truth):** **PASS.** Both binaries guarded; the 12 certified bracket finds → **12 planted_bug_find, 0 unexpected** (control rejects each @ VerifyOpcode, locus-parsed); the no-op (`CYCLE_DIFF_COUNT_MOD`) → NON_PLANTED; the result-changer (`verifier_accepted=0`) → not extracted; markers `found=True, n_finds=12`.
- **G-NEG:** an ITM mutation on the **control** binary **rejects** (verifier not success) ⇒ a control campaign yields 0 finds — the harness does not false-positive.
- **G-CTRL:** `oracle.guard_control` asserts the control fingerprint before trusting its rejects.

## Notes / honest caveats
- Stage-0's `conditional_find_density=0.92` is a **synthetic-DB artifact** (every ITM row there is a find or a known result-changer). The **real** find-per-ITM rate (low single-digit %, F5 is n=1) is **measured in A3.2/S1**, not here. Stage-0 only validates that the marker *computes correctly*.
- A3.1 is **local + zero-POS** by design. The remaining BLOCKING item before A3.3 (the thesis race) is the **budget reconciliation** (spec §5): A3.2/S1 must produce the real fast-node per-mut time + cTS ITM-rate, from which S2's N (≤5000 cap) and wall-clock are set and surfaced to Ivan.

## Next: A3.2 (S1 smoke, first POS dispatch)
Bundle the holed binary (G-BUNDLE: assert host_sha == archived), generate the smoke manifest (`generate_race_manifests.py --stage smoke`, 4 var × 3 seeds × N=2000), dispatch via the chain dispatcher (guard-prefixed). Then: markers extract; A4 finds, Arguzz ITM-applied = 0; **measure real timing + cTS ITM-rate → set S2 N**.
