# Bias Campaign Plan — Arguzz (executor-stage) vs A4 (witness-stage)

**Status:** DRAFT for review. Supersedes the `M6` stub in `../minimal_add/EXPERIMENT_PLAN_V2.md`.
**Owner model:** Opus plans/reviews; composer implements per phase; each phase gated.
**Isolation rule (hard):** all new code lives under `thesis_side_experiments/`. We **read** `a4/`
Python modules and **invoke** the prebuilt `risc0-host` / minimal host binaries. We do **not** modify
`a4/`, `workspace/risc0-modified/`, or `workspace/output/` without explicit approval.

---

## 0. Goal

Quantify, with real distributions, **how the constraint-failure bias differs between Arguzz and A4**,
then use that measured bias to find a single-instruction example that *clearly and interpretably*
demonstrates it for the thesis.

### Why we pivoted here
The `add`/`a1` example cannot show the bias cleanly: Arguzz executor-stage injection on an **operand**
crashes the prover in preflight (`wrap_memory_txns` OOB) *before* constraint evaluation, while A4
produces clean `{IsRead, MemoryWrite}` failures (see `../minimal_add/artifacts/FINDINGS.md` M3 +
`verify_crash`). So instead of asserting a bias on one instruction, we **measure** it across many
mutations and *then* pick an instruction that provably exhibits it.

### The hypothesis to measure
- **A4** holds the execution fixed/correct and corrupts the **witness** → always reaches constraint
  evaluation → lands surgically on witness/memory-consistency constraints (`IsRead`, `MemoryWrite`,
  global memory argument). Probes **constraint soundness** directly.
- **Arguzz** corrupts the **execution**; the witness faithfully records the perturbed run → three
  outcome classes:
  1. **VALID / no signal** — perturbed run still legal → proof valid (constraint coverage "miss").
  2. **PREFLIGHT_CRASH** — malformed trace the prover bookkeeping can't handle → no constraint data.
  3. **CONSTRAINT_REJECT** — out-of-band change trips a (often broader, propagation-spread) set.

**Claim under test:** A4 reaches evaluation reliably and concentrates on memory/witness-consistency
constraints; Arguzz's signal is diluted across crash/valid/constraint outcomes and, when it rejects,
spreads differently. The campaign produces the frequency distributions that prove/characterize this.

---

## 1. Locked design decisions (defaults; revisit if results demand)

| Decision | Choice |
|---|---|
| Guests | **Both**: c0/c1 differential guest (`workspace/output`) for aggregate realism; small controlled guests (built in C5) for clean example discovery |
| Comparison modes | **Both**: aggregate distributional + matched/paired on aligned kinds |
| Kinds (first) | **6 aligned axes** (stage-paired, see below). Arguzz-only / A4-only kinds characterized separately, not compared head-to-head. |
| Storage | **One shared SQLite** (`runs` w/ `fuzzer` column + `failures` + `global_failures`), written by **our own runners** for both fuzzers (we drive A4 via `run_a4` + a4 mutation creators, not A4's `CoverageDB`). `a4/` core untouched. (Refined in C1_SPEC §2 from the original separate-DBs idea.) |
| Outcome classifier | **Parse-based, fuzzer-agnostic** (NOT exit-code based). |
| **Primary metric** | **Distribution of *targeted* and *failed* constraints across categories: LOCAL_INTRASTEP vs LOCAL_INTERSTEP (memory-consistency) vs GLOBAL** (+ ACCUM), per fuzzer and per kind. Per-constraint-loc frequency is a secondary refinement. |

### Aligned vs unique kinds (from source — same fault concept, paired by stage)
| Fault concept | A4 (witness-stage) | Arguzz (executor-stage) |
|---|---|---|
| Register value (read) | `PRE_EXEC_REG_MOD` | `PRE_EXEC_REG_MOD` |
| Compute / dest write | `COMP_OUT_MOD` | `COMP_OUT_MOD` |
| Load value | `LOAD_VAL_MOD` | `LOAD_VAL_MOD` |
| Store output | `STORE_OUT_MOD` | `STORE_OUT_MOD` |
| **Memory value** | `MEM_VAL_MOD` | `PRE_EXEC_MEM_MOD` / `POST_EXEC_MEM_MOD` |
| Instruction word | `INSTR_WORD_MOD_FULL` | `INSTR_WORD_MOD` |

- **Arguzz-only:** `PRE_EXEC_PC_MOD`, `POST_EXEC_PC_MOD`, `POST_EXEC_REG_MOD`, `BR_NEG_COND`.
- **A4-only:** `INSTR_TYPE_MOD`, `INSTR_WORD_MOD_SUR`.

---

## 2. Unified outcome taxonomy (parse-based classifier)

Classify each run from raw stdout/stderr, independent of host exit conventions (the minimal host
`panic!`s at `main.rs:106` on prove error; a Rust preflight panic aborts via SIGABRT; the c0/c1 host
may differ). Precedence top→bottom:

| Class | Detection (parse) |
|---|---|
| `PREFLIGHT_CRASH` | `panicked at ...preflight.rs:227` (or any `preflight.rs` panic) |
| `OTHER_CRASH` | other `panicked at` / crash signal, **and** zero `<constraint_fail>` emitted |
| `ACCEPTED` (soundness escape) | injection applied **and** `<record>{"context":"Verifier","status":"success"}` (verifier accepted a faulted run) |
| `CONSTRAINT_REJECT` | ≥1 `<constraint_fail>` (record full set: loc, phase, major, minor, value) |
| `GLOBAL_REJECT` | 0 local fails but a Hook-3 family residue nonzero / global residue nonzero |
| `VERIFY_REJECT` | proof produced, no constraint fails, verifier failed |
| `VALID_NO_SIGNAL` | injection applied, proof valid, no fail/residue (Arguzz changed the computation legally) |
| `NO_INJECTION` | `<fault>` for target step absent (injection didn't fire) — drop from stats, log separately |

Notes:
- A run can be `CONSTRAINT_REJECT` **and** have nonzero global residue — record both; primary class is
  `CONSTRAINT_REJECT`.
- For Arguzz, also record the **injected target** parsed from `<fault>` (`kind`, `step`, register/addr,
  value) and whether the target register is an operand consumed that cycle (predicts `PREFLIGHT_CRASH`).
- `ACCEPTED` is the headline soundness signal for both fuzzers (mirrors A4's exit-code-2 gate).

---

## 3. Data schema (shared, for apples-to-apples)

Reuse A4's `failures` table shape verbatim so both fuzzers' constraint hits are directly comparable.
Each fuzzer writes its **own** SQLite DB; an analysis module reads both.

**`runs`** (one row per mutation/injection):
`run_id, fuzzer ('arguzz'|'a4'), guest, kind, seed, inject_step, target_desc, outcome_class,
constraint_fail_count, global_nonzero (bool), verifier_success (bool), injected (bool), raw_log_path`

**`failures`** (mirror of A4 `CoverageDB.failures`):
`run_id, constraint_type, constraint_loc, cycle, step, pc, major, minor, value, full_loc, phase`

**`global_failures`** (mirror): `run_id, family, address`

For A4: read directly from its `CoverageDB` (`mutations`, `failures`, `global_failures`,
`local_coverage_v2`) — no need to re-run through a custom writer; the analysis layer adapts A4's schema
to the shared view. For Arguzz: the new runner writes the shared schema directly.

---

## 4. Constraint categories + bias metrics (C4)

### 4.0 Constraint category taxonomy (THE PRIMARY AXIS)
Every targeted/failed constraint is classified into one of these, computable from already-parsed data:

| Category | Detection rule | Meaning |
|---|---|---|
| **L1 — LOCAL_INTRASTEP** | `<constraint_fail>` `phase=local` AND `loc` does **not** contain `mem.zir` | single-cycle internal correctness (decode, ALU, bit/twit ranges, IsZero, OneHot, NormalizeU32, AddrDecompose, VerifyOpcode, …) |
| **L2 — LOCAL_INTERSTEP** | `<constraint_fail>` `phase=local` AND `loc` contains `mem.zir` | per-transaction memory-consistency linking the read/write chain across steps (`IsRead@79/80`, `MemoryWrite@99/100`, `IsCycle@61/62`, `MemoryIO@69-74`) |
| **ACCUM** | `<constraint_fail>` `phase=accum` | accumulator-column update logic |
| **G — GLOBAL** | Hook-3 family residue nonzero (`memory`/`u16`/`u8`/`cycle`) and/or global residue nonzero | whole-trace permutation/lookup argument closure |

(L2 rule = `mem.zir` in loc; refine later if interstep constraints are found outside `mem.zir`.)

### 4.1 PRIMARY deliverable — category distributions (target & fail), per fuzzer × kind
- **FAIL distribution:** share of failures (and share of runs with ≥1 failure) landing in {L1, L2, ACCUM, G}.
- **TARGET distribution:** from touch coverage (`A4_COVERAGE_TOUCH_VERBOSE` local + accum verbose sets),
  classify each *touched* context into {L1, L2, ACCUM} (global targeting is whole-trace/trivial, so for G
  we measure failing only).
- **Conditional fail-rate:** P(fail in category | category targeted) — separates "did it aim there" from
  "did it break it there."
This is the headline: *how often does each fuzzer target and fail L1 vs L2 vs G.*

### 4.2 Secondary metrics
1. **Outcome distribution** (§2 classes): Arguzz `PREFLIGHT_CRASH` / `VALID_NO_SIGNAL` rate vs A4's
   near-100% evaluation-reached.
2. **Reachability:** P(reaches constraint eval) = 1 − P(`PREFLIGHT_CRASH`/`OTHER_CRASH`). Expect A4 ≫ Arguzz.
3. **Detection rate:** P(any reject signal | reached eval).
4. **Per-constraint frequency distribution:** over `CONSTRAINT_REJECT` runs, normalized hit frequency
   per `constraint_loc` and `(loc,major,minor)` — refinement *within* each category.
5. **Bias score:** per-category and per-loc `log2( freq_A4 / freq_arguzz )` with Laplace smoothing;
   contingency table + standardized residuals; bootstrap CIs over seeds.
6. **Matched-pair signature diffs (C3):** aligned kind at matched site → set-diff of failed locs/categories
   (A4-only, Arguzz-only, shared) + outcome-class pairing.

All metrics conditioned **per kind** and **per guest**. Expectation to test: A4 fail-mass concentrates in
**L2 + G** (witness/memory-consistency) and reliably reaches eval; Arguzz spreads across
crash/valid and, when it rejects, leans differently (e.g. `PRE_EXEC_REG_MOD` shows the crash bias;
`COMP_OUT_MOD`/`STORE_OUT_MOD` modify an existing write in place — no extra same-cycle txn — so both
fuzzers likely reach eval, a prime C5 example candidate).

---

## 5. Phases

### C0 — Parity harness + classifier  ⬜
**Objective:** an Arguzz campaign runner that mirrors A4 and a fuzzer-agnostic classifier; both
validated against known ground truth.
**Actions:**
- `arguzz_campaign.py`: loop over `(kind, inject_step, seed)`; drive host via `--trace --inject
  --seed --inject-step --inject-kind`; parse `<fault>`, `<constraint_fail>`, family/global, verifier;
  write shared schema. Reuse `a4.common.trace_parser`, `a4.core.constraint_parser`,
  `a4.core.touch_coverage` (read-only imports).
- `classify.py`: implements §2 taxonomy from raw log.
- `a4_adapter.py`: read an A4 `CoverageDB` into the shared `runs`/`failures` view.
- Step enumeration: derive valid inject steps from one `--trace` baseline run per guest (parse
  `<trace>`/`<fault>` step range), cache to JSON.
**Acceptance:**
- Reproduces M2 (A4 `PRE_EXEC_REG_MOD` on a1 → `{IsRead@79, MemoryWrite@99}`, both p−5) via adapter.
- Reproduces `verify_crash`: Arguzz `PRE_EXEC_REG_MOD` on add operands → `PREFLIGHT_CRASH`; non-operands
  → `CONSTRAINT_REJECT` with 4–7 fails.
- Classifier buckets a hand-labeled set of ≥10 runs with 100% agreement.
- Determinism: same `(fuzzer,kind,step,seed)` → identical outcome+failure set across 2 runs.

### C1 — Pilot (small N)  ⬜
**Objective:** validate the full pipeline at small scale before spending compute.
**Actions:** both fuzzers, 5 aligned kinds, N≈50 mutations/kind, fixed seed set, on c0/c1 guest.
Produce a draft C4 report.
**Acceptance:** no pipeline errors; outcome distributions populated; Arguzz crash/valid classes appear;
A4 reaches-eval ≈100%; runtime measured to budget C2.

### C2 — Aggregate campaign  ⬜
**Objective:** statistically meaningful distributions.
**Actions:** scale N per kind (target set in C1 from power analysis; e.g. ≥500/kind/fuzzer); fixed,
recorded seed sets; c0/c1 guest (+ controlled guest if ready). Parallelize (see §7).
**Acceptance:** seed-reproducible DBs; per-kind N met; coverage of the constraint universe logged.

### C3 — Matched/paired campaign  ⬜
**Objective:** head-to-head on identical sites.
**Actions:** for each aligned kind, enumerate matched (step/cycle, instruction) sites; run both fuzzers
at each; pair results; record signature set-diffs + outcome-class pairing.
**Acceptance:** ≥K matched sites/kind; pairing keyed correctly; A4-only/Arguzz-only/shared loc sets emitted.

### C4 — Bias analysis & figures  ⬜
**Objective:** the deliverable that tells us the bias.
**Actions:** compute all §4 metrics; produce tables + plots (outcome-class bars, per-constraint
frequency, bias-score ranking, phase/global splits). Render via a Cursor **canvas** for review
(quantitative artifact — see canvas skill).
**Acceptance:** bias ranking with CIs; reachability & detection rates; per-kind breakdowns; a written
interpretation mapping numbers → the §0 hypothesis (confirm/refute/refine).

### C5 — Example discovery  ⬜
**Objective:** find 1–2 single-instruction examples that *clearly* exhibit the dominant measured bias,
both fuzzers **non-crashing** and interpretable.
**Actions:** from C4, pick (kind, instruction) candidates where A4 and Arguzz both reach eval and their
failure sets differ intuitively (current lead: `COMP_OUT_MOD`/`STORE_OUT_MOD` on a destination write).
Build minimal controlled guests; verify with the ZIR-residue provenance method (predicted == observed
field-element residue) from M2.
**Acceptance:** ≥1 example with full provenance, reproducible, both fuzzers non-crashing, failure-set
contrast that maps to an intuitive constraint story.

### C6 — Thesis prose  ⬜ (needs approval to edit `thesis.md`)
Translate the measured bias + chosen example into intuitive constraint language (no raw ZIR).

---

## 6. Isolation & reproducibility rules
- New code only under `thesis_side_experiments/bias_campaign/`. `a4/`, `workspace/risc0-modified/`,
  `workspace/output/` are read/invoke-only; any change there needs explicit approval.
- Every campaign records: host binary path + sha256, guest, seed set, kind set, git rev, timestamp.
- All randomness seeded and logged; DBs are the source of truth; raw logs archived per run.
- Verify production `risc0-host` mtime/sha unchanged after each phase.

## 7. Compute & parallelism
- Per-run cost ~30–90s (fast prover, tiny guests). Aggregate campaign is the bottleneck.
- Parallelize with a process pool (see `verify_crash_condition.py` ThreadPool pattern); A4 already has
  `run_replicates.py` + POS dispatch for multi-seed scale-out if needed.
- Crashing runs are cheap (abort early in preflight); valid/reject runs pay full prove.
- C1 measures real throughput → set C2 N from a target margin-of-error per per-constraint frequency.

## 8. Risks & open questions
- **Comparability validity:** aligned kinds mutate at different stages; the matched comparison must be
  framed as "same fault concept, different stage," not identical operations. Document explicitly.
- **`VALID_NO_SIGNAL` interpretation:** for the differential c0/c1 guest, an Arguzz change may surface as
  a c0≠c1 mismatch (the guest's own check) rather than a constraint failure — record guest-commit value
  to distinguish "legal alternate run" from "guest-detected divergence."
- **A4 `SKIPPED` vs Arguzz `NO_INJECTION`:** normalize both as "no mutation applied," exclude from
  rejection-rate denominators, report separately.
- **Step alignment between fuzzers:** Arguzz step numbering (executor) vs A4 step (witness) differ by a
  fixed offset (we saw add: Arguzz 187 / A4 185). C0 must establish and record the mapping per guest.
- **[C0 review → fix in C1] Host-panic vs prover-crash confound:** the minimal_add host `panic!`s at
  `main.rs:106` on any `prove` Err, so the classifier's `OTHER_CRASH` rule (any panic + 0 constraint
  fails) would mislabel global-only / verify-only rejections as crashes, and `VERIFY_REJECT`/
  `GLOBAL_REJECT` can't fire. Fix: treat only prover-internal panic paths (`preflight.rs`, `witgen`,
  risc0 crate) as crashes; classify `main.rs` host panics as non-crash. Decide using the production
  `risc0-host`'s actual error behavior in C1.
- **[C0 review] Soundness-escape not masked:** surface `verifier_success` independently in the analysis
  layer so an `ACCEPTED` (faulted run the verifier still accepts) is never hidden under
  `CONSTRAINT_REJECT`.
