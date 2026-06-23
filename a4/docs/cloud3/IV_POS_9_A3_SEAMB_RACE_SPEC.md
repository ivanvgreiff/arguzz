# IV.POS.9 — Spec A3 (first instance): the A4-findable-bug RACE on POS (Seam-B / VerifyOpcode)

**Version:** v0.3 — third pass (incorporates the second separate-Opus review of v0.2) · **Date:** 2026-06-23 · **Author:** Opus (OCP).
**Track:** A (known-bug detection race — the security claim). **Governing:** `ProG_Report_5.md` §3; `New_Master.md` (cloud3) §L4/L9/L11/L13/L14, gates G10–G13.
**Establishes the reusable race harness** and runs its **first campaign**: the four variants racing to find the certified A4-findable VerifyOpcode underconstraint (`AP_SEAMB_RESULT.md`). The `rs1==rs2` CVE race (A1+A2) reuses this harness later.

> **v0.2 changes:** (1) **reuse the D2.H soundness machinery** (`soundness_signal`, `extract_accepts`, the DB schema, the propagation triage) — v0.1 reinvented the oracle; (2) **reconcile the D2.H propagation triage** — it would call the Seam-B finds *no-ops* (they're result-preserving by construction), so the planted-bug oracle is control-reject@VerifyOpcode, with the triage used as a *secondary severity characterizer*; (3) **N=5000** on the fast 8-node pool (Ivan); (4) guard the **control** binary too + pin `head_sha`/`guest_image_id`; (5) **conditional density** marker; (6) Arguzz=0 framed as **structural surface complementarity** (true by construction) with a falsifier; (7) a **facts-vs-assumptions audit** (§0.2).
>
> **v0.3 changes (2nd Opus review):** (a) **budget reconciliation** — S2's N is **data-driven from S1's measured fast-node timing + ITM-rate**, N=5000 as the target/cap, wall-clock surfaced to Ivan and gated before A3.3 (the ≈9-day estimate at 30s/mut is a dev-box upper bound; fast nodes unknown until S1) (§5); (b) **4% find-rate is n=1** (CI ≈0.1–21%) — treated as "low single-digit," S1 measures the real rate (F5); (c) A5 fallback is **raise N or a SEPARATE forced micro-campaign — never bias the main scheduler** (would contaminate the cTS-ITM-rate signal); (d) the oracle **parses the control failure LOCUS** (`VerifyOpcode*` via `CONSTRAINT_CONTINUE=1`), not just "control rejected" (§2.3). All 4 are non-blocking for A3.1.

---

## 0. Scope, headline question, and the honest severity framing

**Headline question.** On a binary whose ONLY planted hole is the removed `VerifyOpcode*` decode-equality: **which of the four variants discover it, how often, and at what mutation index?** **No stop-on-first-bug** — full N, record every find + its index.

**Variants** (`variants.py`): `V5_control` (a4), `V6_uniform` (arguzz), `V6_cTS` (arguzz), `Hybrid_cTS` (hybrid). All four race, including `V6_uniform`, to test whether pure Arguzz finds an A4-surface bug.

**Hypothesis (TO TEST, not assume):** A4-surface variants (`V5_control`, `Hybrid_cTS`) apply `INSTR_TYPE_MOD` → find it; pure-Arguzz (`V6_uniform`, `V6_cTS`) **structurally cannot** apply `INSTR_TYPE_MOD` (F7) → find it never. The campaign must be able to **falsify** this (an Arguzz find — via some other fault that produces an accepted decode-divergent trace — would be a real, important result).

**Honest severity framing (critical — read this).** Because the hole is **scoped to decode** (rd-write integrity `MemoryWrite@99/100` is INTACT), the only accepted type-substitutions are **result-preserving** (mv-like cycles where the substituted op coincides — F5). So a find = *"the verifier accepts a proof whose instruction-type contradicts the fetched word, with no value change."* This is a genuine soundness **underconstraint** (the decode binding is gone) but a **non-propagating / low-severity** one. **This is not a weakness — it is the point:** A4's post-execution surface reaches the **local/decode** constraint family; the value/memory bugs (rs1==rs2 CVE) are Arguzz's domain (permutation-bound — `AP_SEAMB_OPTION_B_ANALYSIS.md`). The Seam-B race is the **A4 side** of the complementarity claim; the CVE race is the Arguzz side.

**Non-goals.** Not the CVE race (A1/A2/later). Not a coverage sweep (Track B, separate OCP). Not "MAB beats Arguzz."

### 0.1 What is FACT (verified live this session, on the actual binaries)
| # | fact | evidence |
|---|---|---|
| F1 | the campaign runs on the holed binary; records `kind`, `verifier_accepted`, replayable `config_json` (A4_MUTATION_CONFIG-compatible) | N=12 + N=24 live runs |
| F2 | per-mutation cost ≈ **30 s** (full prove+verify, `ProverOpts::fast`, `CONSTRAINT_CONTINUE=1`) **on this dev box** — an UPPER bound; the fast 8-node POS pool is faster | timed N=12 (6:20 incl. setup) |
| F3 | raw `verifier_accepted` is **noisy** — benign kinds accept on BOTH binaries (`CYCLE_DIFF_COUNT_MOD` 8/8 accepted, and a sampled one **verifies on control**) ⇒ control-reject discriminator is **mandatory** | live replay on control |
| F4 | the campaign's **own** `INSTR_TYPE_MOD` path produces a genuine find (`AddI→OrI` @ step 267: holed-accept, **control reject @ VerifyOpcodeF3**) | forced N=24 + control replay |
| F5 | find rate is **single-digit %** per applied `INSTR_TYPE_MOD` (only result-coincident mv-like cycles accept; the rest reject at `MemoryWrite`) — **observed 1/24, which is n=1: 95% CI ≈ 0.1–21%, too wide to size N. Treat as "low, single-digit"; S1 measures the real rate.** | forced N=24 (indicative only) |
| F6 | the `verifyopcode` profile **matches the holed binary, fails the control** (planted_bug is the sole discriminator; identical head/guest_id/instr_hash) | separate-Opus live fingerprint |
| F7 | `INSTR_TYPE_MOD` ∈ A4 arm universe, **ABSENT from `MUTATION_KINDS_ARGUZZ_FULL/_SELECTED`** ⇒ Arguzz CANNOT apply it (complementarity is structural) | separate-Opus on disk |
| F8 | the 12 certified Stage-0 finds (holed-accept; control reject @ VerifyOpcodeF3; 44 result-changers reject @ MemoryWrite) | `ap_seamb_verify.json` |
| F9 | D2.H provides a reusable soundness oracle stack: `soundness_signal` (= prover success), `extract_accepts` (DB query), `propagation_triage` (noop/propagated/hidden), baseline-pairing | `propagation_triage.py`, `arguzz_invoke.py`, `coverage_db.py` |
| F10 | the A4 (cli) accept signal is the **`mutations.verifier_accepted` COLUMN**, NOT `config_json.soundness_signal` (which is Arguzz-only) — so D2.H's `extract_accepts` must be generalized to the column or it misses all A4 finds | live DB: find id=19 `verifier_accepted=1`, `soundness_signal=ABSENT` |

### 0.2 What is ASSUMPTION (to be VALIDATED in A3.1/A3.2 — never trusted on faith)
| # | assumption | how it gets validated |
|---|---|---|
| A1 | `markers.py` extraction (first-find idx, densities, CDF, censoring) is correct | unit tests on synthetic DBs (§6) |
| A2 | the race manifest generator (clone of `generate_d2f_manifests.py`) emits correct jobs (holed host, guard prefix) | unit test + dry-run (§6) |
| A3 | the POS bundle + dispatch + guard wiring works for the race | A3.2 smoke + G-FP/G-BUNDLE |
| A4 | control-confirmation re-run cost is bounded | only `INSTR_TYPE_MOD` accepts re-run (~4 % × ITM-applied; Arguzz ≈ 0) |
| A5 | N=5000 yields a robust find count for A4 variants (≥~10) | depends on cTS's ITM-application rate AND the real find-per-ITM rate — **both measured in S1**; if finds are too few, **raise N or run a SEPARATE forced-ITM micro-campaign** for the bug-intrinsic rate — **NEVER bias the main scheduler** (that would contaminate the "how often does cTS naturally pick ITM" signal we are measuring) |
| A6 | paired-seed RNG is comparable across cli vs driver launchers | not load-bearing (we compare kind-reachability, not RNG luck); noted in analysis |

---

## 1. Binaries, guest, and the contamination guardrail (HARD)

| role | path | fingerprint asserted |
|---|---|---|
| **bug binary** (race target) | `a4/builds/ap_seamb/bench-verifyopcode/risc0-host` | `planted_bug=verifyopcode`, `load_rs2_present=1`, `risc0_head_sha=93bda33b…`, `guest_image_id=<Seam-B id>` |
| **control** (oracle ground truth) | `a4/builds/ap_seamb/control/risc0-host` | `planted_bug=none`, `load_rs2_present=1`, same head + guest id |

- **Guest:** Seam-B minimal ALU guest (944 AddI cycles). Host args `--ctrl 7 --gseed 12345 --rounds 5`.
- **New profile** in `fingerprint_guard.py`: `"verifyopcode": {"load_rs2_present": 1, "planted_bug": "verifyopcode"}`.
- **Guard, per job, BLOCKING (L14):** `fingerprint_guard <host> --profile verifyopcode --expect-head 93bda33b… --expect-guest-id <id>` — assert **planted_bug AND head_sha AND guest_image_id** (v0.1 only checked planted_bug; **Opus #4**). Nonzero ⇒ abort + record. Bundle `host_sha256` asserted == archived holed sha.
- **The CONTROL binary is guarded too (Opus #3).** `oracle.py` asserts the control's fingerprint (`planted_bug=none`, same head/guest) before using its rejects as ground truth — the rejects are the oracle, so the control deserves the same provenance certainty as the race host.

---

## 2. The bug oracle — reuse D2.H, with control-reject as the planted-bug ground truth

### 2.0 What we reuse from D2.H, and why the propagation triage is SECONDARY here
D2.H's soundness stack (F9) is built for **discovering unknown** soundness bugs and deciding whether an accept **propagates**:
- the **accept (candidate) signal**. **REUSE the concept, but NOT the query.** D2.H `extract_accepts()` (`propagation_triage.py:128`) pulls `outcome='applied' AND json_extract(config_json,'$.soundness_signal')=1` — that `soundness_signal` tag is set **only on the Arguzz (`arguzz_invoke`) path**. **F10 (verified live): A4 (cli) mutations do NOT carry `config_json.soundness_signal`; their accept is the `mutations.verifier_accepted` COLUMN** (the genuine find id=19 had `soundness_signal=ABSENT`, `verifier_accepted=1`). **Reusing `extract_accepts` verbatim would miss EVERY A4 find and report A4=0 — the exact opposite of the truth.** So the race oracle queries the universal column: `outcome='applied' AND verifier_accepted=1` (works for both A4-cli and Arguzz-driver paths). This is a *generalization* of D2.H's query, not a reuse of it.
- `propagation_triage.classify_semantics()` — classifies an accept as `accepted_noop` / `accepted_propagated_candidate` / `accepted_hidden_global_reject` via **baseline-vs-mutated trace divergence**. **REUSE** as the secondary characterizer (§2.2).

**The catch (and why v0.1's control-reject oracle is right):** the Seam-B finds are **result-preserving** (F5) ⇒ **no post-injection trace divergence** ⇒ the propagation triage would label them **`accepted_noop`**. So the propagation triage is the WRONG *primary* detector for a planted **decode** bug. The correct primary detector is **does the clean control reject this exact mutation at `VerifyOpcode`** — which is the planted-bug analog of D2.H's baseline-pairing (D2.H compares *traces*; we compare *verify verdicts*). We therefore use the triage as a **secondary characterizer** (it confirms the finds are non-propagating — the honest severity statement — and reuses the D2.H code).

### 2.1 Primary oracle (planted-bug detection)
A mutation is a **confirmed planted find** iff all hold:
1. **`mutations.verifier_accepted == 1` AND `outcome='applied'`** on the bug binary (the universal column — F10; NOT `config_json.soundness_signal`, which is Arguzz-only; `CONSTRAINT_CONTINUE=1` hot loop, real prove+verify).
2. **Decode-divergent:** `kind == INSTR_TYPE_MOD` and `mutated (major,minor) ≠ original` (from `config_json`). *(Non-ITM accepts are spot-checked — §2.3.)*
3. **Control REJECTS at `VerifyOpcode*`** (`inst.zir:102/103/104`) on the identical replayed `config_json` (A4_MUTATION_CONFIG). **Ground truth.**

**No-op exclusion** is exactly condition 3: benign accepts (e.g. `CYCLE_DIFF_COUNT_MOD`, F3) verify on the control too ⇒ excluded. This is the empirically-validated discriminator (F3) — the fix for the `(0,1,0)` mirage that sank Seam A.

### 2.2 Secondary characterization (reuse `propagation_triage`)
Run `propagation_triage.classify_semantics()` on each confirmed find ⇒ expected `accepted_noop`/cosmetic (result-preserving). Report the distribution; it is the honest severity statement and a reuse cross-check. *(If any find triages as `accepted_propagated_candidate`, that's a surprise worth surfacing — a result-changing decode substitution that slipped past MemoryWrite.)*

### 2.3 Cost-bounded confirmation + LOCUS parsing (implementation requirement)
Hot loop runs only on the **bug binary**. Post-hoc, re-run on control: **all `INSTR_TYPE_MOD` accepts** (the planted-find candidates — bounded: low-single-digit % × ITM-applied, F5) **+ a sample of non-ITM accepts** (to catch any surprise soundness signal the holed binary admits that control rejects). Fast-path: an ITM accept with `mutated≠original` is a planted find by construction (control reject @ VerifyOpcode guaranteed — F8) → control re-run is a **spot-check**, not per-find.

**LOCUS parsing is mandatory (Opus #4).** The control re-run runs with **`CONSTRAINT_CONTINUE=1`** and the oracle **parses the `<constraint_fail>` locus** — a confirmed find requires the control to fail specifically at `VerifyOpcode*` (`inst.zir:102/103/104`), NOT merely "control rejected." Rationale/defense-in-depth: although result-changers are already excluded at condition 1 (they reject on the *holed* binary at `MemoryWrite` ⇒ `verifier_accepted=0` ⇒ never a candidate), parsing the locus prevents miscrediting any future mutation kind whose control-reject is at a *different* constraint. (Reuse the `<constraint_fail>` parser from `a4/core/constraint_parser.py`.)

---

## 3. Markers — how we judge variant performance

Per mutation (in `coverage_db.mutations`): `id` (mutation **index** 1..N), `kind`, `verifier_accepted`, `outcome`, `config_json`. Derived per **(variant, seed)**:

| marker | definition |
|---|---|
| `found` | ≥1 confirmed planted find in N |
| `first_find_idx` | mutation index of the first confirmed find; **censored = N+1** if none |
| `n_finds` | confirmed planted finds in N |
| `n_applied` | mutations with `outcome='applied'` (fair denominator; excludes skips — reuse D2.H `n_applied`) |
| `n_instr_type_mod_applied` | applied `INSTR_TYPE_MOD` (the bug's reachable surface for this variant) |
| `find_density` | `n_finds / n_applied` (overall hit rate) |
| **`conditional_find_density`** | `n_finds / n_instr_type_mod_applied` (**Opus #6** — separates "scheduler rarely picks ITM" from "the bug is rare within ITM"; expect ≈ **4 %**, F5) |
| `find_kinds` | histogram of `kind` among finds (expect: all `INSTR_TYPE_MOD`) |
| `triage_class` | secondary `propagation_triage` label among finds (expect: non-propagating) |

Aggregated per **variant** over ≥10 paired seeds (same seed set across all 4):
- **`P(found)`** — fraction of seeds with a find.
- **discovery CDF** — "mutations-to-first-find" Kaplan–Meier curve (ProG §3), with censoring shown.
- mean `find_density`, `conditional_find_density`, `n_instr_type_mod_applied`.

**Framing of the headline result (Opus #5):** Arguzz `P(found)=0` is **structural surface complementarity** (F7: Arguzz cannot apply `INSTR_TYPE_MOD`), **not** a search-efficiency loss — report it as "the bug is off Arguzz's attack surface." The genuine empirical questions are: (a) the **falsifier** — does any Arguzz fault ever produce an accepted decode-divergent trace (expect no); (b) for A4/Hybrid — `first_find_idx`, `conditional_find_density`, and whether cTS *schedules* ITM often enough to find it fast (a scheduler-quality signal).

---

## 4. Campaign driver (reuse) + new glue

**Reuse as-is:** the variant launchers (`variant_launch_command` → `cli.py fuzz` for V5/V6_cTS/Hybrid, `v6_uniform_driver` for V6_uniform); per-mutation record + `verifier_accepted` (`fuzzer.py:536-537`); `coverage_db`; `soundness_signal` + `extract_accepts` + `propagation_triage` (D2.H). **Each variant already does a full prove+verify per mutation** — pointing `--host` at the holed binary makes `verifier_accepted` reflect the holed verdict (F1). No driver changes for the hot loop.

**New (small, unit-tested) code under `a4/runs/iv_pos_9/race/`:**
- `fingerprint_guard.py` += `verifyopcode` profile + `--expect-head`/`--expect-guest-id` enforcement.
- `oracle.py` — reads a run DB, reuses `extract_accepts`, applies §2.1 (control-confirm, with the control **guarded**), tags `triage_class` via §2.2.
- `markers.py` — §3 extraction → `race_markers.json` + per-variant CSVs + discovery CDF.
- `generate_race_manifests.py` — clone of `generate_d2f_manifests.py`; emits (variant × seed × N) jobs, host = holed binary, **guard-prefixed `--profile verifyopcode --expect-head/--expect-guest-id`**.

---

## 5. Budgets (NO stop-on-first-bug; POS for all full campaigns; local only for S0 + unit tests)

| stage | scope | where | gate |
|---|---|---|---|
| **A3.S0 — deterministic ground truth** | the 12 finds + a no-op + a result-changer, through `oracle.py`; **negative control** = short control-binary campaign → 0 finds | local | 12 `planted_bug_find`; no-op excluded; result-changer not-an-accept; control → 0 |
| **A3.S1 — smoke** | 4 var × 3 paired seeds × **N=2000** | POS | DBs complete + `verifyopcode` fingerprint recorded; markers extract; A4 finds, Arguzz ITM-applied = 0; **measure cTS's ITM rate to confirm N=5000 yields ≥~10 finds (A5)** |
| **A3.S2 — thesis** | 4 var × **≥10 paired seeds** × **N = min(5000, S1-data-driven)** | POS (fast 8-node pool) | full markers + discovery CDFs; per-job fingerprint recorded; **wall-clock surfaced to Ivan before dispatch** |

**Cost + the budget reconciliation (Opus #1, BLOCKING before A3.2→A3.3, NOT before A3.1).** The only honest cost number we have is ≈30 s/mut on **this dev box** (F2, CONSTRAINT_CONTINUE=1 hot loop) — at which N=5000 × 40 jobs / 8 nodes ≈ **~9 days > the 1-week window**. We do NOT yet know the **real per-mut time on the fast 8-node pool** (Ivan: "way faster") nor the **real cTS ITM-rate / find-per-ITM** (F5 is n=1). So:
- **N=5000 is the target/cap (Ivan).** It is **NOT silently dropped.**
- **S2's actual N is set data-driven from S1's measurements** — S1 (small, POS) yields the *real* fast-node per-mut seconds, the cTS ITM-application rate, and the find-per-ITM rate. From those: `wall ≈ ceil(jobs/nodes) × N × t_mut`, and the **min N for a robust A4 find count** (≥~10 finds ⇒ ≥~`10 / (ITM_rate × find_per_ITM)` mutations). Choose S2 N = min(5000, N that fits the window) and surface the wall-clock to Ivan **before A3.3 dispatch**.
- If the fast nodes make N=5000 fit (e.g. ~10 s/mut ⇒ ~3 days), do 5000. If not, Ivan decides (more nodes / accept longer / lower N) — an explicit decision, gated, never a silent change.
- **Asymmetric-N option (Opus #7, Ivan's call):** Arguzz arms apply **zero** ITM (F7) ⇒ 0 finds by construction at any N; they could run a smaller N to halve their POS hours. Default **equal N** for a cleaner falsifier (Arguzz genuinely searches the full N and still finds nothing) unless node-time is tight.

---

## 6. Unit tests (MUST pass before A3.S1 — the certainty layer; `a4/runs/iv_pos_9/race/tests/`)

1. `test_fingerprint_profile` — `verifyopcode` PASSES holed, **FAILS control** and any sweep/vuln fp; `--expect-head`/`--expect-guest-id` enforced.
2. `test_oracle_confirmed_find` — a recorded ITM accept (e.g. the live `AddI→OrI`) → `planted_bug_find` (control rejects @ VerifyOpcode).
3. `test_oracle_noop_excluded` — a `CYCLE_DIFF_COUNT_MOD` accept (verifies on control, F3) → **not** a find.
4. `test_oracle_result_changer` — `AddI→And` (rejects on holed @ MemoryWrite) → not-an-accept → not a find.
5. `test_oracle_guards_control` — `oracle.py` refuses to run if the control binary's fingerprint ≠ `{planted_bug:none, head, guest}` (Opus #3).
6. `test_markers_extraction` — synthetic DB → correct `first_find_idx`, `n_finds`, `find_density`, `conditional_find_density`, censoring (=N+1).
7. `test_markers_cdf` — multi-seed synthetic → correct per-variant discovery CDF + median.
8. `test_conditional_density` — `n_finds / n_instr_type_mod_applied` correct, and `n_instr_type_mod_applied=0` ⇒ defined (NaN/None, not div0) for Arguzz arms.
9. `test_manifest_generator` — right job count; each job holed host + `verifyopcode` guard + head/guest expectations; control never a race target.
10. `test_variant_launch_cmds` — all 4 variants → valid argv (`--host` holed).
11. `test_triage_reuse` — `propagation_triage.classify_semantics` runs on a find and returns a class (reuse smoke).
12. **`test_accept_signal_column`** (F10 regression) — a synthetic DB with an A4 accept that has `verifier_accepted=1` but NO `config_json.soundness_signal` → the oracle **must** count it (guards against the `extract_accepts`-verbatim bug that would report A4=0).
13. `test_ground_truth_s0` (integration, gated on binaries) — the 12 + negative control through oracle→markers → 12 finds on holed, 0 on control; AND the live find `AddI→OrI@267` is detected.

**Gate G-UT:** all green AND A3.S0 green ⇒ A3.S1 may dispatch.

---

## 7. Correctness gates (BLOCKING — POS-time protection)
| gate | check |
|---|---|
| **G-UT** | §6 unit tests + A3.S0 ground truth green |
| **G-FP** (per job) | guard `--profile verifyopcode --expect-head --expect-guest-id` exit 0; recorded; nonzero ⇒ abort |
| **G-BUNDLE** | bundle `host_sha256` == archived holed sha; guard embedded in the launcher |
| **G-CTRL** | `oracle.py` asserts the control fingerprint before using its rejects (Opus #3) |
| **G-NEG** | control-binary campaign → 0 confirmed finds (no false positives) |
| **G-SMOKE** | A3.S1 DBs complete; markers extract; A4 finds, Arguzz ITM-applied = 0; cTS ITM-rate confirms N=5000 adequacy (A5) before A3.S2 |
| **G-REPRO** | every find replayable (control re-run reproduces reject @ VerifyOpcode) |

---

## 8. Batches
- **A3.1 — harness + unit tests + ground truth (A3.S0).** `verifyopcode` profile (+head/guest enforcement); `oracle.py` (reuse `extract_accepts`+`propagation_triage`, guard control); `markers.py`; `generate_race_manifests.py`; launcher guard wrapper; all §6 + S0. **Local, zero POS.** *Gate: G-UT, G-NEG, G-CTRL.* **(Opus: do this now.)**
- **A3.2 — smoke (A3.S1).** Bundle holed binary; dispatch 4×3×2000 to POS; markers; confirm cTS ITM-rate ⇒ N=5000 adequacy. *Gate: G-FP, G-BUNDLE, G-SMOKE.*
- **A3.3 — thesis (A3.S2).** Dispatch 4×≥10×5000 (fast pool); full markers + discovery CDFs. *Gate: G-REPRO; all DBs fingerprinted.*
- **A3.4 — analysis + writeup.** `race_markers.json` + CSVs + CDF plot + results doc (P(found), first-find, densities, conditional density, triage-class, the complementarity verdict + honest severity). Feeds the thesis Track-A A4 side.

---

## 9. Risks & mitigations
| risk | mitigation |
|---|---|
| **Misread as "weak/no-op" result** (the finds are result-preserving; the propagation triage calls them no-ops) | §0/§2.2 honest framing: it's a *decode underconstraint* on A4's surface — the point of the complementarity claim, not a defect; report the planted-bug oracle result AND the triage class side-by-side |
| cTS down-weights `INSTR_TYPE_MOD` ⇒ slow/no find for A4 | `conditional_find_density` + `n_instr_type_mod_applied` separate scheduler-choice from bug-rarity; S1 measures the ITM rate; if cTS rarely schedules ITM, that's a real scheduler finding (report it) |
| ≈4 % find-per-ITM ⇒ too few finds at small N | N=5000 (justified §5); S1 confirms adequacy before S2 |
| wrong binary bundled | G-FP + G-BUNDLE (the `verifyopcode`+head+guest profile fails any other binary) |
| benign accepts inflate finds | §2.1 control-reject discriminator (F3) + `test_oracle_noop_excluded` |
| control-confirmation cost | only ITM accepts re-run (~4 %×ITM) + a non-ITM sample; Arguzz accepts ≈ 0 |
| paired-seed RNG differs cli vs driver | not load-bearing (kind-reachability, not RNG luck) — noted in analysis (A6) |

## 10. Reuse for the `rs1==rs2` CVE race (later)
Same harness; bug binary = A1 vuln build (`98387806`, `--profile race`); guest = A2 `rs1==rs2` guests; **here the propagation triage IS the right primary oracle** (the CVE bug is value-changing/propagating — the strong journal oracle, L4a) with control-reject as confirmation. Markers, dispatch, unit-test scaffolding, gates carry over. **Expected mirror:** Arguzz/Hybrid find the CVE; pure A4 does not (value is permutation-bound). The two races = the full complementarity table.
