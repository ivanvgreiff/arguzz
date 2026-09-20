# Review — IV.POS.9 Spec A3 (Seam-B / VerifyOpcode race harness)

**Reviewer:** Claude (this session) · **Date:** 2026-06-23 · **Subject:** `IV_POS_9_A3_SEAMB_RACE_SPEC.md` (OCP draft v0.1, commit `37f8e36`).
**Method:** section-by-section read of the spec cross-checked against the actual code (`variants.py`, `fuzzer.py`, `arguzz_bridge.py`, `l1_signals.py`, `fingerprint_guard.py`) and the certified artifacts (`ap_seamb_verify.json`, both binaries' live fingerprints). Not a paper review — every load-bearing claim was checked on disk.

---

## 0. Bottom line

**The spec is sound and ready to implement with minor edits.** The harness reuses validated machinery, the oracle design is the correct fix for the `(0,1,0)` no-op-mirage that sank the IsRead work, and the contamination guardrail is real (I confirmed it on the binaries). I found **no blocking errors**. I have **2 things I'd change before A3.1** (both about internal consistency / certainty, not correctness of the idea), **4 hardening recommendations** the user's "binary must be what we think it is" mandate justifies, and **1 budget reconciliation** that directly answers OCP's open question.

Recommendation on OCP's (a)/(b): **(a) — write the unit tests + Stage-0 now**, after applying edits #1–#2. Stage-0 is pure-local, zero-POS, and it validates the oracle on known-answer data *before* we burn ~340 node-hours. There is no reason to hold it.

---

## 1. What I verified on disk (so this review is grounded, not assumed)

| Claim in spec | Verified? | Evidence |
|---|---|---|
| bench binary self-reports `planted_bug=verifyopcode`, `load_rs2_present=1`, head `93bda33b` | ✅ | live `A4_INSPECT_FINGERPRINT=1` on `bench-verifyopcode/risc0-host` |
| control reports `planted_bug=none`, **identical** guest_image_id + instrumentation_hash + head | ✅ | live fingerprint on `control/risc0-host` — bench & control differ ONLY in `planted_bug` |
| proposed profile `{load_rs2_present:1, planted_bug:"verifyopcode"}` matches bench / fails control | ✅ | `fingerprint_guard.assert_fingerprint` checks exactly those two fields |
| V5_control (a4) can apply `INSTR_TYPE_MOD` | ✅ | `fuzzer.MUTATION_KINDS` includes it; `_active_mutation_kinds()` returns the full list for V5 |
| V6_uniform / V6_cTS (arguzz) **cannot** apply `INSTR_TYPE_MOD` | ✅ | `MUTATION_KINDS_ARGUZZ_FULL` (arguzz_bridge.py) has **no** `INSTR_TYPE_MOD`; uniform driver keys on `_PRE_POST_BY_KIND`, which also lacks it (a stray pick would `KeyError`, not silently mutate) |
| Hybrid_cTS can apply `INSTR_TYPE_MOD` | ✅ | `_arguzz_strategy_config()` gives Hybrid `a4_kinds = _active_mutation_kinds()` (full A4 set incl. `INSTR_TYPE_MOD`) **plus** the 4 selected arguzz kinds |
| `SUBSTRATEGY_EXCLUDED_KINDS={INSTR_TYPE_MOD}` does **not** block application | ✅ | it only means INSTR_TYPE_MOD has no sub-strategy fields (`l1_signals.py:14,24`); it's still a live arm |
| "12 certified finds" exist and are replayable | ✅ | `ap_seamb_verify.json`: `holed_accept=12`, `accepters_reject_on_control=12` (all `VerifyOpcodeF3F7`); 44 result-changers reject@`MemoryWrite` on holed (scope intact) |

**The single most important structural fact for the whole thesis claim is confirmed:** the A4↔Arguzz split is *real at the kind-pool level*. V6_uniform/V6_cTS literally do not have `INSTR_TYPE_MOD` in their pool, so their "0 finds" is a property of the mutation surface, not RNG luck. This is exactly the complementarity statement — and it's load-bearing for §3's headline. See flag #5 for the framing nuance this creates.

---

## 2. Section-by-section assessment

- **§0 / §0.1 (scope, headline, live findings):** Correct and honest. The "raw `verifier_accepted` is noisy" finding (CYCLE_DIFF_COUNT_MOD 8/8 accept, one also accepts on control) is the empirical justification for the oracle and it's right — those are benign no-ops. Good that the hypothesis is framed as *falsifiable*.
- **§1 (binaries + guardrail):** Correct. The profile addition is well-formed and I confirmed it discriminates bench from control. See flags #3, #4 for hardening.
- **§2 (oracle):** This is the heart of the spec and it is **correct**. Keying the "find" on the *control-reject locus = VerifyOpcode* (not merely "accepts on holed") is what makes it robust: it (a) excludes no-ops that accept on both, and (b) refuses to credit a variant for finding a *different* soundness gap. The locus-keying means a CYCLE_DIFF/COMP_OUT accept can never be miscounted as the planted find (it would reject elsewhere or not at all). This is the right fix for the mirage that sank `(0,1,0)`.
- **§3 (markers):** Sound. Kaplan–Meier discovery CDF with censoring=N+1 is the correct treatment for "Arguzz never finds it." See flag #6 for one metric I'd add.
- **§4 (driver reuse):** Correct — pointing `--host` at the holed binary makes `verifier_accepted` reflect the holed verdict, no hot-loop driver changes. The new code (oracle.py, markers.py, manifest generator) is appropriately small and well-tested.
- **§5 (budget):** Arithmetic is right (2000×30s=16.7h; ceil(12/8)=2 waves×17h≈1.5d; ceil(40/8)=5 waves×17h≈3.5d). **But the target N for S2 is internally inconsistent — flag #1.** Also the cost basis needs one caveat — flag #2.
- **§6/§7 (unit tests + gates):** Strong. 10 tests + Stage-0 + 6 blocking gates is the right certainty layer. test #4 (result-changer rejects@MemoryWrite ⇒ not an accept) directly re-uses the 44 we certified. G-NEG (control campaign → 0 finds) is the essential negative control.
- **§8 (batches):** Reasonable. A3.1 = local harness+tests+Stage-0; gated correctly.
- **§9 (risks):** Good coverage. The "Hybrid excludes INSTR_TYPE_MOD" risk is actually **already mitigated by code** (Hybrid's a4 arm is the full set), but the "confirm in A3.1" action is still prudent — keep it.
- **§10 (reuse for rs1==rs2):** Correct and forward-looking; the mirror-result framing is right.

---

## 3. Flags / changes (prioritized)

### Edit #1 — Reconcile the S2 `N` (do before A3.1). *Consistency / feasibility.*
The doc says three different things for the thesis stage:
- §5 table A3.S2: **N=5000** (extend to 10000)
- §5 cost bullet: "A3.S2 (40 jobs, **N=2000**) ≈ ~3.5 days. At N=5000 ≈ ~9 days."
- §5 recommendation: "**N=2000** for the first thesis run (≈5 days S1+S2)"
- §8 A3.3: "4×≥10×**5000**"

These can't all hold. The "**≈5 days, fits the 1-week window**" promise is only true if **S2 defaults to N=2000**. N=5000 → ~9 days → blows the 1-week window. **Fix:** make S2 default **N=2000**, with N=5000/10000 reserved *only* for censored-but-interesting cells (i.e., a V5/Hybrid seed that hasn't found by 2000, which would itself be a surprise). Update the §5 table and §8 A3.3 to match the recommendation. This is the direct answer to "sanity-check the budget vs the 1-week window": **N=2000 fits; N=5000 does not.**

### Edit #2 — State the hot-loop `CONSTRAINT_CONTINUE` mode + caveat the cost for all-reject jobs. *Cost accuracy.*
§0.1 measured ~30 s/mutation with `CONSTRAINT_CONTINUE=1` on a V5 run that had accepts. §2 condition 2 says the accept verdict is taken with `CONSTRAINT_CONTINUE` **OFF**. The spec never states which mode the *hot loop* runs in, and it matters: for the **Arguzz variants nearly every mutation is a reject**, and a reject's cost depends on whether the prover short-circuits at the constraint (OFF) or runs to completion + verify (=1, the ~30 s worst case). 30 s is a safe **upper bound**, so the budget won't blow up — but the doc should (a) state the hot-loop mode explicitly, and (b) note that an all-reject Arguzz job may be materially *cheaper* than 30 s/mut if run with short-circuit, which is upside, not risk. Recommend a 1-line measurement of one all-reject V6 job in A3.2 to firm the Arguzz-side number.

### Recommendation #3 — Guard the **control** binary in the oracle, not just the race host. *Certainty / Ivan's mandate.*
The contamination guardrail (§1, G-FP) prefixes the *race* job (holed host). But the **oracle's ground truth comes from re-running on the control binary**, and nothing in the spec guards the control at oracle time. Given the user's explicit "we must be 100% certain the binary is the one we think," `oracle.py` should fingerprint-assert the control before trusting its rejects — a new `"control"` profile `{load_rs2_present:1, planted_bug:"none"}` **plus** an assertion that the control's `guest_image_id` equals the holed binary's. Cheap, and it closes the one place a swapped binary could silently corrupt ground truth.

### Recommendation #4 — Pin `head_sha` + `guest_image_id` in the guard, not just `planted_bug`. *Defense-in-depth.*
The §1 table lists "head `93bda33b`, guest_image_id = Seam-B guest" as fingerprint invariants, but the proposed profile only encodes `load_rs2_present` + `planted_bug`, and `assert_fingerprint` does **not** check `risc0_head_sha` at all. `planted_bug=verifyopcode` is currently unique enough to be sufficient — but to actually honor the table, add `--guest-id <seamb image id>` to the guard prefix and add a `risc0_head_sha` check to `assert_fingerprint` (or document explicitly that planted_bug is the sole asserted discriminator and head/guest are informational). Pick one; today the table over-claims what the command enforces.

### Recommendation #5 — Frame the Arguzz result as **surface complementarity**, not a search loss. *Thesis-claim integrity.*
Because V6_uniform/V6_cTS structurally cannot emit `INSTR_TYPE_MOD` (verified §1), their "0 finds" is true *by construction*. The spec already says the right thing in non-goals ("no claim MAB beats Arguzz") and §5 ("pure-Arguzz applies zero INSTR_TYPE_MOD"). Keep that discipline in the A3.4 writeup: the claim is *"this bug lives on the A4 trace-edit surface, outside Arguzz's during-execution surface,"* not *"Arguzz searched and failed."* The one genuinely empirical thing the Arguzz arm tests is the **falsifier**: can any during-exec kind (esp. `INSTR_WORD_MOD`, which *is* in their pool) trigger VerifyOpcode by a side route? Mechanistically it shouldn't (a pre-exec word edit is re-decoded into a self-consistent word↔type triple, so VerifyOpcode stays satisfied), and the oracle will catch it if it does. That falsifier is the reason to run Arguzz at all — see #7.

### Recommendation #6 — Add a **conditional** find-density. *Sharper signal.*
`find_density = n_finds / n_applied` conflates "how often the selector schedules INSTR_TYPE_MOD" with "how often INSTR_TYPE_MOD hits the hole." For the findability question, also record `n_instr_type_mod_applied` and `conditional_hit_rate = n_finds / n_instr_type_mod_applied`. The 12 certified finds suggest the per-substitution hit rate is high, so this cleanly separates "scheduler picks it rarely" (a scheduler story) from "it picks it but it misses" (a mutation story). Derivable from `find_kinds` + raw rows, but worth materializing.

### Recommendation #7 (decision for Ivan, not a defect) — Asymmetric N to save ~half the compute.
Since the Arguzz arms are 0-by-construction and need N only large enough to (a) confirm `INSTR_TYPE_MOD` application = 0 and (b) catch the falsifier, they don't need the full thesis N. Running V6_uniform+V6_cTS at, say, N=1000 / fewer seeds while V5_control + Hybrid get the full N would roughly halve POS hours (~20 of the ~40 S2 jobs are Arguzz). **Tradeoff:** it breaks the clean equal-N / paired-RNG design the spec values for a tidy comparison table. My call: defensible to keep equal N for presentation cleanliness, but if node availability is tight for the 1-week window, cut Arguzz N first — it costs nothing scientifically. Flagging as Ivan's budget call.

### Minor — escalate `other_soundness`, don't just log it.
The oracle's third bucket (`accepts on holed, rejects on control NOT at VerifyOpcode`) would mean the holed binary accepted something the control rejects at a non-planted locus — i.e., a *scope leak* of the fold-neutralization (the exact failure mode the IsRead saga had). The seamb cert says scope is tight (44 result-changers still reject@MemoryWrite on holed), so this should be empty — but if a row lands in `other_soundness`, treat it as a **blocking investigation**, not a logged curiosity. Add that to G-REPRO.

### Minor — fast-path vs per-find control re-run (S1).
§2's optional fast-path ("an INSTR_TYPE_MOD accept is a planted find by construction") is sound *given* VerifyOpcode pins label↔word 1:1 (empirically true for all 56). But on the **first** thesis run I'd run the full control re-run for **every** accept in S1 (accepts are a minority; cheap) and only enable the fast-path for S2 once S1 confirms 100% agreement. The spec already calls it a "spot-check" — just make S1 per-find explicit.

---

## 4. OCP's open question — my answer

> "(a) write the unit tests + Stage-0 (local, no POS) so implementation can start the moment the spec passes review, or (b) hold for review."

**Go with (a)**, after applying Edit #1 (S2 N reconciliation) and Edit #2 (state hot-loop mode). Rationale:
- Stage-0 + the 10 unit tests are **100% local, zero POS cost**, and they validate the oracle on the 12+44 known-answer cases *before* any node-hours are spent. That is precisely the certainty gate that was missing in the IsRead work.
- The recommendations #3–#7 are small and can land inside A3.1 (they're mostly a few lines in `oracle.py` / the guard / markers) — they don't need to block starting.
- On the budget question OCP flagged: **N=2000 fits the 1-week window (S1 ~1.5d + S2 ~3.5d ≈ 5d on 8 nodes); N=5000 does not (~9d).** So adopt N=2000 as the thesis default and the window is safe with margin.

**Net:** approve the spec to proceed to A3.1 with Edits #1–#2 applied and Recs #3–#7 folded into the batch. No blocking errors found; the design correctly internalizes every lesson from the IsRead failure.

---

# Second pass — review of v0.2 (OCP commit `17b240e`)

**Date:** 2026-06-23 (PM) · Re-checked the D2.H reuse against the actual D2.H code.

## A. Consistency verdict: PASS. The D2.H integration is correct.

I verified OCP's headline catch (F10) on disk, and it is real:
- `propagation_triage.extract_accepts()` (line 128–140) filters `WHERE outcome='applied' AND json_extract(config_json,'$.soundness_signal')=1`.
- `soundness_signal` is written **only** on the Arguzz paths (`v6_uniform_driver.py:191`, `arguzz_invoke.py:98/199`) — **never** the A4 (cli) path.
- The A4 path records the accept in the **`mutations.verifier_accepted` column** (`fuzzer.py:537`).
- ⇒ Reusing `extract_accepts` verbatim would return **zero A4 accepts** and report A4=0 — the exact opposite of the truth. OCP's generalization (query the `verifier_accepted` column) is the correct fix, and test 12 (`test_accept_signal_column`) is the right regression guard.

I also verified the triage reconciliation:
- `classify_semantics()` flags `accepted_propagated_candidate` only when `post_pc_changed or post_trace_changed` (line 328). Seam-B finds are **result-preserving** (no post-injection trace divergence), so the triage would label them **`accepted_noop`**.
- ⇒ OCP is right to demote the triage to a **secondary severity characterizer** and make **control-reject@VerifyOpcode** the primary oracle. This is internally consistent and correctly reasoned.

**All seven of my v0.1 flags were addressed:** #1 N (Ivan chose N=5000 — see open item below), #2 hot-loop mode stated, #3 control guarded (G-CTRL + test 5), #4 head/guest pinned, #5 structural-complementarity framing, #6 conditional density, #7 asymmetric-N noted. The new **honest severity framing (§0)** is a genuine improvement — it preempts the "this is just a no-op" misread.

## B. Open items / things I'd still change (none block A3.1; some block A3.2 = first POS dispatch)

1. **(Blocks A3.2, not A3.1) The N=5000 wall-clock no longer reconciles with the 1-week window, and v0.2 dropped the day estimates.** At the F2 upper bound (30 s/mut, 8 nodes): S2 = 40 jobs × N=5000 × 30 s = 5 waves × ~42 h ≈ **~9 days** — over the 1-week window. v0.2 only says "the fast POS pool is faster" without a number. **This must be resolved before the official race.** Recommend: make S2's N **data-driven** — A3.2/S1 measures (a) the *real* POS per-mut time and (b) cTS's actual ITM-scheduling rate, then size S2's N from those, with 5000 as a cap. Don't pre-commit 9 days of nodes on a 30 s dev-box extrapolation.

2. **The ≈4 % find-per-ITM (F5) is a point estimate from n=1 success (1/24).** Its real 95% CI is roughly 0.1 %–21 % — far too wide to *size* N=5000 confidently. (Note the curated bracket gave 12/56 ≈ 21 %, because it was hand-built to include result-coincident substitutions; the natural campaign rate is the relevant, and uncertain, one.) Fold into item 1: let S1 produce a real find-rate with a CI before committing S2's N.

3. **A5's fallback "bias toward ITM" would contaminate the scheduler-quality signal.** §3 wants `conditional_find_density` and "does cTS schedule ITM often enough" as a *natural* scheduler measurement; biasing the selector toward ITM to manufacture more finds destroys exactly that signal. **Change:** if finds are too few, raise N — do **not** bias the production campaign. If you need to nail the 4 % find-rate precisely, run a *separate* ITM-forced micro-campaign kept distinct from the scheduler-behavior run.

4. **(Implementation requirement for A3.1 — make explicit so it isn't missed) The oracle must extract the failure *locus*, not just pass/fail.** Condition 3 is "control rejects **at VerifyOpcode***" — confirming this requires running the control re-run with `CONSTRAINT_CONTINUE=1` and parsing the named eqz failure (`VerifyOpcodeF3` / `VerifyOpcodeF3F7`, `inst.zir:102/103/104`). A bare "control rejected" is insufficient (a result-changer rejects at `MemoryWrite`, which must NOT be credited as the planted find). State the control re-run mode + locus-parsing in §2.3.

5. **Naming nit:** F4/F8 say finds reject at `VerifyOpcodeF3`, but `ap_seamb_verify.json` records `VerifyOpcodeF3F7`. Both are real arms (different substitutions hit funct3 vs funct7 arms). The oracle should match **any** of the three `VerifyOpcode*` arms (102/103/104), not a hard-coded one — §2.1 already uses the `VerifyOpcode*` wildcard, so just confirm the implementation honors the family.

## C. One substantive point for Ivan (not a defect — a thesis-framing reality)

The honest-severity framing is correct and I endorse it, but be clear-eyed about what the A4 side demonstrates: a **genuine soundness underconstraint** (the decode binding is gone — the verifier accepts a proof whose instruction type contradicts the fetched word) that is, in practice, **result-preserving / low-severity / non-propagating**. It is also a **planted, known** bug deliberately built for `INSTR_TYPE_MOD` (Track A is a *detection* race + harness validation, not discovery). That's all legitimate for the complementarity claim — but the **high-severity** half of the table is the Arguzz/CVE side (`rs1==rs2`, value-corruption, permutation-bound). Present them as a pair: *A4 reaches the local/decode constraint family; Arguzz reaches the value/permutation family.* Neither alone is the headline — the **complementarity** is.

## D. Answers to your two questions

**Is v0.2 consistent (esp. w.r.t. D2.H)?** Yes — verified on disk. The one thing that no longer reconciles is the **budget vs the 1-week window** (item B1), and there are two implementation requirements to state explicitly (B4 locus-parsing, B3 no-bias fallback). None of these block starting A3.1.

**What's left before the official POS bug race (A3.3)?**
1. **A3.1 (local, zero POS) — do now.** Build `oracle.py` (column query + control-guard + locus-parsing), `markers.py`, `generate_race_manifests.py`, the `verifyopcode` profile + `--expect-head/--expect-guest-id`, the 13 unit tests, and Stage-0 ground truth. Gate: G-UT, G-NEG, G-CTRL. *This is the certainty gate IsRead lacked.*
2. **Resolve the budget (B1/B2)** — commit to a data-driven S2 N; get a real POS per-mut number.
3. **A3.2 / S1 smoke (POS, small)** — validates fingerprint+bundle+dispatch end-to-end, measures real per-mut time and cTS ITM-rate, confirms A4-finds / Arguzz-ITM=0. Gate: G-FP, G-BUNDLE, G-SMOKE.
4. **Then A3.3 — the official thesis race.** Gate: G-REPRO; all DBs fingerprinted.

**OCP's a-vs-b (start A3.1 now vs hold for review):** **Start A3.1 now.** It's local and zero-POS; the separate-Opus review (this doc) can proceed in parallel. The only thing that must be settled before **POS dispatch (A3.2)** is the budget/timeline — not before A3.1.

---

# Third pass — review of the built A3.1 harness (OCP commit `bbbb16e`)

**Date:** 2026-06-23 (eve) · Read every harness file + ran the tests myself.

## Verdict: PASS — the A3.1 harness is correct and the certainty gate is real.

Verified on disk (not on trust):
- **F10 fix implemented + tested.** `oracle.extract_accepts` queries `WHERE outcome='applied' AND verifier_accepted=1` (the universal column), and `test_accept_signal_column` asserts an A4 accept with NO `soundness_signal` is still caught. This is the bug that would have reported A4=0.
- **Locus parsing is real (my B4 flag).** `run_control_replay` runs the control with `CONSTRAINT_CONTINUE=1`; `loc_is_verifyopcode` parses the named failures and requires `VerifyOpcode` in the locus. A result-changer rejecting at `MemoryWrite` is NOT credited.
- **Control is guarded (G-CTRL, my B-#3).** `guard_control` asserts the control's fingerprint (`planted_bug=none` + head + guest) before its rejects are trusted; `test_oracle_guards_control` covers it.
- **Schema matches real data.** `is_decode_divergent_itm` keys on `major`/`minor`/`_info.original_major`/`original_minor` — I confirmed the certified config files use exactly that schema, so Stage-0 validates against REAL configs, not just synthetic.
- **Manifest well-formed.** Guard-prefixed (`verifyopcode` + `--head-sha` + `--guest-id`, abort rc 87), holed host, `EXPECT_GUEST_ID` matches the live bench fingerprint, no stop-on-bug, smoke=12 jobs/N=2000, thesis=40 jobs/N≤5000 (data-driven).
- **markers.py correct** (censoring=N+1, `conditional_find_density=None` when n_itm=0, CDF excludes censored). **12/12 unit tests pass** (ran them).

## Flags (none blocking dispatch; #1 worth fixing)

1. **Falsifier gap (the one real flaw).** `classify_run` control-checks **only** `INSTR_TYPE_MOD` accepts; every non-ITM accept is marked `NON_PLANTED` with **no** control check (`test_oracle_noop_excluded` even asserts "control must not be called for non-ITM"). But the spec's advertised **falsifier** — "does any *Arguzz* fault produce an accepted decode-divergent trace?" — lives precisely in the non-ITM accepts. As built, a genuine Arguzz find at VerifyOpcode would be **silently labeled NON_PLANTED and missed**, so the experiment cannot actually falsify its own hypothesis. It's mechanistically near-impossible (only a label↔word desync triggers VerifyOpcode, which Arguzz kinds don't produce), but the spec §2.3 itself calls for "+ a sample of non-ITM accepts" and that sampling is not implemented. **Fix:** in the Arguzz runs (accepts are rare → cheap), control-check non-ITM accepts too and credit a VerifyOpcode-locus reject as a find regardless of `kind`; or soften the spec's "must be able to falsify" wording to "falsifier is mechanistically precluded + spot-checked."
2. **Stage-0 trusts holed-accept from the prior cert** — it re-proves only the control-reject locus for the 12, not the holed-accept (those came from `mutated_v0`). Acceptable; the fullest loop would re-prove holed-accept too.
3. **`first_find_idx = min(find_ids)` assumes `mutations.id` is a per-attempt index incl. skips.** Confirm/document; `conditional_find_density` is the robust metric regardless.
4. **Doc/impl naming:** spec says `--expect-head`/`--expect-guest-id`; code uses `--head-sha`/`--guest-id`. Harmless (manifest is internally consistent) — reconcile the spec text.

## CORRECTION to the budget (supersedes my earlier "~9 days" figure)

My v0.1/v0.2 ETAs used the **30 s/mut dev-box upper bound (F2)**. That is the slow WSL2 box, **not** the POS nodes. The directly-comparable number is **F16** in the D2.F ledger (`central-planning-1.md`): the *same* full prove+verify fuzzer workload, measured on the EPYC pool — **V5/A4 ≈ 2.95 s/mut, V6/Arguzz ≈ 2.46 s/mut** (sequential mode, which the race's `A4_COVERAGE_TOUCH=1` also forces). The fast nodes are ~10× the dev box.

On the standard 8 fast nodes (Tier S EPYC 9354 ×4: flare/polynize/opulous/octorand; Tier A EPYC 7543 ×4: algofi/gard/goracle/zone), at ~3 s/mut:
- **Smoke (12 jobs, N=2000):** ~1.7 h/job × ceil(12/8)=2 waves ≈ **~3–4 hours**.
- **Real (40 jobs, N=5000):** ~4.2 h/job × ceil(40/8)=5 waves ≈ **~21 hours (< 1 day)**.
- **Real (40 jobs, N=2000):** ≈ **~8 hours**.

**⇒ N=5000 fits the 1-week window with enormous margin (~1 day, not ~9).** My earlier budget flag (#1, "N=5000 blows the window") is **retracted** — it was an artifact of the dev-box number. The smoke still earns its keep by confirming the real per-mut time on the node *and* measuring cTS's ITM-scheduling rate (which sets whether N=5000 yields enough finds — a find-COUNT question, not a wall-clock one).
