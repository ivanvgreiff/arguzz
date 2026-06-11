# Minimal-Add Experiment — Master Plan V2

**Supersedes** `PLAN.md`. Companion: `artifacts/GUIDANCE_FOR_COMPOSER.md` (forensics + fixes).

**Roles.** Opus = planner/reviewer (gates each milestone). Composer = implementor.
**Isolation (hard rule).** Only edit files under `thesis_side_experiments/minimal_add/`.
`a4/`, `workspace/risc0-modified/`, `workspace/output/` are READ-ONLY. Editing `a4/docs/thesis.md`
needs explicit user approval (it lives outside this tree). If a step seems to require touching
read-only code, STOP and ask.

**Fuzzers (modern only).**
- **Arguzz** = executor-stage `--inject --inject-kind PRE_EXEC_REG_MOD` in `thesis-minimal-host`.
- **A4** = witness-stage `A4_MUTATION_CONFIG` via the `a4.core` / `a4.standalone` package.
- Never use `a4/arguzz_dependent/` or `a4.cli compare`.

---

## 0. Goals (short → long term)

1. **Add-example ground truth (primary, now).** With 100% confidence, characterize for the single
   `add s0,a0,a1` (3+4=7): how each fuzzer mutates it, which **local** constraints are *touched*
   and which *fail*, and which **global** (accum/Hook-3) constraints fail — apples-to-apples on
   register **a1**.
2. **Bias comparison (the point).** Determine **how Arguzz and A4 differ in which constraints they
   break.** This difference is the deliverable for thesis §3.3.3 and the seed of the campaign.
3. **Statistics campaign (short-term next).** If the single add can't, by itself, prove the bias
   *generalizes*, design a campaign — built on the add-example harness — that quantifies the
   constraint-failure bias across many instructions/sites.
4. **Understanding (long-term).** Explain *why* the bias exists (propagation vs isolation) and what
   bug classes each fuzzer is structurally biased toward.

---

## 1. The signals we have (ground truth, no code changes)

Every constraint is checked by `eqz(ctx, val, loc)` in `witgen.h`, which:
- calls `a4_touch_mark` → records the constraint context **`(loc, major, minor)`** as *touched*
  (i.e. EQZ was actually evaluated — the constraint was active);
- if `val != 0` (violated) prints `<constraint_fail>{cycle,step,pc,major,minor,loc,value,phase}`
  with `phase = "local"` (witgen) or `"accum"` (accumulator/global phase).

| Need | Mechanism | Env | Tag |
|------|-----------|-----|-----|
| Constraints **touched**, local pass (exercised) | un-hashed verbose set | `A4_COVERAGE_TOUCH=1 A4_COVERAGE_TOUCH_VERBOSE=1` | `<a4_touch_verbose>` |
| Constraints **touched**, accum pass | un-hashed verbose set | same | `<a4_accum_touch_verbose>` |
| Constraints **touched** (compact) | hashed bitmaps | `A4_COVERAGE_TOUCH=1` | `<a4_touch_coverage>`, `<a4_accum_touch_coverage>` |
| Constraints **failed** | per-cycle, phase-tagged | `CONSTRAINT_CONTINUE=1` | `<constraint_fail>` (`phase` = local **or** accum) |
| **GLOBAL** memory/lookup residue (Hook 3) | per-family grand-product residue | `A4_FAMILY_RESIDUE=1` | `<a4_family_residue>`, `<a4_family_detail>`, `<a4_family_stats>` |
| Final accumulator residue | accum residue | `A4_GLOBAL_RESIDUE=1` | `<a4_global_residue_*>` |
| Per-step txns | preflight dump | `A4_INSPECT=1 A4_DUMP_STEP=<s>` | `<a4_txn>` etc. |

**Phase / taxonomy — read carefully (this is subtle):** every constraint is an `eqz(ctx,val,loc)`
in `witgen.h`; `phase` = `is_accum_phase ? "accum" : "local"`, i.e. **which proving pass** ran the
check, NOT the thesis's local/interstep/global split.
- **`phase="local"`** (witgen pass) = within-cycle constraints **plus the memory-consistency checks**
  `IsRead@mem.zir:79` / `MemoryWrite@mem.zir:99`. So the thesis's *interstep* memory constraints show
  up here as `phase=local`.
- **`phase="accum"`** (accumulation pass) = the **accumulator-column update constraints** that build
  the grand-product/permutation accumulator. This is accumulation machinery — **NOT** the global
  multiset closure. (Ignore the loose "global constraint" wording in `ffi.cpp:107`.)
- **GLOBAL constraints = Hook 3 family residues** (`A4_FAMILY_RESIDUE`): after accumulation, per family
  (`memory`, `u16`, `u8`, `cycle`) it recomputes `Σ count·inv(hash)` with the Fiat-Shamir mix
  challenges. Zero ⇒ that family's whole-trace permutation/lookup argument closes; **nonzero ⇒ the
  global argument for that family failed.** This is the thesis's "Global Constraints"
  (`register_memory_argument` → `memory` family; range/program lookups → `u8`/`u16`/`cycle`).

**Therefore the thesis bias mapping is:**
`local/interstep` = `phase="local"` `<constraint_fail>` set; `global` = **Hook 3 family residues**;
`phase="accum"` failures are a **distinct third bucket** (record them, but do NOT call them global).

**Answer to "is there something more granular than the bitmap?":** Yes —
`A4_COVERAGE_TOUCH_VERBOSE` gives the exact set of `loc|major|minor` contexts checked.

### 1a. How to know a constraint's TRUE meaning with 100% confidence (dual method)

Composer's plain-English labels are navigation aids (mostly heuristic from names). For any constraint
we make a thesis claim about (i.e. the ones that **fail** in M2/M3), pin it to ground truth two ways
that must agree:

- **(A) Static — read the ZIR DSL source.** Every `loc` is an exact `file:line:col` into
  `zirgen/zirgen/circuit/rv32im/v2/dsl/*.zir`. Read that line and follow the callsite chain to get the
  literal equation. Example verified live:
  - `IsRead` (`mem.zir:79-80`): `oldTxn.dataLow = newTxn.dataLow` (+ high). `oldTxn`=prev memory state
    (`prevData`), `newTxn`=current access (`data`) → **a READ asserts current value == claimed previous
    value at that addr.**
  - `MemoryWrite` (`mem.zir:99-100`): `newTxn.dataLow = data.low`, where `data` flows from
    `WriteRd → write_data = NormalizeU32(AddU32(rs1,rs2))`. → **MemoryWrite@99 is where ADD arithmetic
    is enforced: recorded rd-write == circuit-recomputed (rs1+rs2).** (There is no standalone
    `rs1+rs2=rd` polynomial; it lives here.)
- **(B) Dynamic — decode the failure residue.** The `value` in `<constraint_fail>` is the BabyBear
  residue = exactly `(LHS − RHS)` of that equation. Choose a mutation with a known delta, **predict**
  the residue, and confirm. Verified live: for A4 `a1: 4→9`, both `IsRead` and `MemoryWrite` reported
  `value = p−5 = 2013265916 = −(9−4)` — IsRead because read 9 vs prev 4; MemoryWrite because recorded
  s0 write 7 vs recomputed 3+9=12 (the +5 propagates into the ALU). Static + dynamic agree ⇒ 100%.

**Standing rule:** every failing constraint in M2+ gets a provenance record
`{loc, exact .zir line(s) + verbatim equation, predicted residue, observed residue, match?}`.

**Known facts / limitations to respect (do not paper over):**
- Touch is keyed by `(loc, major, minor)` **without cycle**, so "touched at cycle 15424" can't be
  isolated; the right denominator is "touched for the Add's `(major=0, minor=0)` context" across the
  run. For this minimal guest that is the correct, representative universe. `<constraint_fail>` IS
  per-cycle, so *failures* are pinned to the add cycle exactly.
- `a4/core/touch_coverage.py` parses the local touch **bitmap** and the **accum** verbose set, but has
  no parser for the **local** verbose set `<a4_touch_verbose>`. Do NOT write a new one from scratch —
  reuse the existing regex in `a4/standalone/tests/run_diagnostic_campaign.py`
  (`VERBOSE_RE = r'<a4_touch_verbose>\[(.*?)\]...'`) inside the experiment scripts (don't edit `a4/`).
- Validate `A4_INSPECT` works simultaneously with `--inject` (M3) before relying on it.

---

## 2. Milestones (each is an Opus review gate)

Each milestone: **do the steps → meet acceptance criteria → report the listed fields → wait for
Opus review before the next.** Build/parse code lives in `run_phases.py` (or split scripts) under
the experiment dir.

### M0 — Reproduce & freeze baseline (determinism)
**Goal:** the binary, guest, baseline, and add site are stable and self-consistent.
- Rebuild via `build.sh`; confirm `workspace/output/target/release/risc0-host` mtime unchanged.
- `--trace` baseline; **dedupe the doubled trace** (use first block only when parsing).
- **Pin the add site by parsing** (not hardcoding): find the single guest `add` (instr `Add`,
  operands a0/a1→s0) → record Arguzz step, pc; derive A4 step via `pc+4`.
- A4 inspect (`A4_INSPECT=1`, then `A4_DUMP_STEP`) → confirm cycle 15424, major 0 / minor 0,
  txns a0 READ 3 / a1 READ 4 / s0 WRITE 7.
- Determinism: run baseline twice; confirm **zero** `<constraint_fail>` and identical touch sets.

**Acceptance:** add site auto-derived = (187, 2099232); baseline proves clean (output 7, verifier OK,
0 failures); touch set reproducible across 2 runs.
**Report:** add site, txn card, baseline local touch-set size, baseline accum touch-set size.

### M1 — Enumerate the Add's constraint universe (no mutation)
**Goal:** the exact set of constraints the Add exercises (the denominator for bias).
- Baseline run with `A4_COVERAGE_TOUCH=1 A4_COVERAGE_TOUCH_VERBOSE=1 A4_FAMILY_RESIDUE=1 A4_GLOBAL_RESIDUE=1 CONSTRAINT_CONTINUE=1`.
- Parse `<a4_touch_verbose>` (reuse the `run_diagnostic_campaign.py` regex); filter to
  `major==0 && minor==0` → **Add local constraint universe** (list of `loc`). Parse
  `<a4_accum_touch_verbose>` → **accum-pass constraint universe** (distinct bucket, not "global").
- Confirm the global signal is silent on a clean trace: all Hook-3 family residues **zero**.
- Cross-check: `distinct_touched(bitmap)` count is consistent with verbose set size.
- Map each `loc` to plain English from `a4/docs/global/PRESENTATION_DEEP_DIVE.md`.

**Acceptance:** local@major0/minor0 list + accum list with human labels; bitmap vs verbose counts
reconcile; baseline has 0 `<constraint_fail>` and all Hook-3 family residues zero.
**Report:** the lists with labels + confirmation residues are zero at baseline.

### M2 — Ground-truth A4 (witness) mutation on a1
**Goal:** 100% confidence on what A4's `a1: 4→9` does and what fails (local + global).
- Re-run A4 `PRE_EXEC_REG_MOD` (`next_read`, a1 read txn) with the full env from M1.
- Dump post-mutation add-cycle txns → confirm **a1 READ=9, s0 WRITE=7 (unchanged)** = *isolation*.
- Collect ALL `<constraint_fail>`; bucket into **local** (`phase=local`) / **accum** (`phase=accum`);
  dedupe by `(loc,major,minor)`.
- Collect **Hook-3 family residues** (the GLOBAL signal) + final accumulator residue.
- Validate causality: IsRead `value == (4-9) mod p == p-5 == 2013265916`. ✔ already seen — reconfirm.

- **Constraint provenance (per §1a):** for each failing `loc`, record exact `.zir` line + verbatim
  equation + predicted residue vs observed `value` (must match).

**Acceptance:** complete A4 column — local fail set {IsRead, MemoryWrite, …}, accum fail set (if any),
Hook-3 family residues (expect `memory` nonzero), every numeric field validated; txn dump proves
isolation; provenance records present for every failing constraint with predicted==observed residue.
**Report:** the A4 column (template in §3) + provenance records.

### M3 — Make Arguzz target a1, ground-truth executor mutation
**Goal:** apples-to-apples; Arguzz corrupts **a1** with a clean value; full capture.
- **Seed sweep** (timeout-killed; `<fault>` prints during execution): find seeds where
  `info == "a1 = V"`. Per user: keep sweeping for a **clean V** (e.g. small, or one giving an
  interpretable IsRead delta), not just the first hit. Record seed + V. Widen range if needed.
- First confirm `A4_INSPECT=1 A4_DUMP_STEP=185` works **with** `--inject`; if not, capture the
  post-inject txns another supported way before relying on it.
- Run Arguzz inject (chosen seed) with full env (`CONSTRAINT_CONTINUE`, `A4_COVERAGE_TOUCH(_VERBOSE)`,
  `A4_FAMILY_RESIDUE`, `A4_GLOBAL_RESIDUE`) — **fix `run_phases.py` Phase 3 to pass env**.
- Dump post-inject add-cycle txns → confirm **a1 READ=V, s0 WRITE=3+V** = *propagation*.
- Collect ALL `<constraint_fail>` bucketed local/accum, **and Hook-3 family residues (global)**.
- Validate causality: IsRead `value == (4 - V) mod p` (magnitude `|V-4|`) → proves it's a1.
- **Key question:** is the `memory` family residue nonzero (global argument also breaks) or zero
  (propagation keeps the global memory argument closed while only local IsRead trips)? This is the
  crux of the bias.

**Acceptance:** complete Arguzz column, field-element-validated to a1; txn dump proves propagation;
Hook-3 residues recorded; run no longer crashes (exit is controlled, not −11).
**Report:** the Arguzz column (template in §3).

### M4 — Bias comparison (core deliverable)
**Goal:** definitively state how Arguzz vs A4 differ in *which constraints break* for this add.
- Build a single matrix over the M1 universe: per `loc`, columns
  `{Arguzz touched, Arguzz fail, A4 touched, A4 fail}`, split **local** vs **accum**, **plus a separate
  GLOBAL row from Hook-3 family residues** (memory/u16/u8/cycle) for each fuzzer.
- Highlight the **delta** on all three levels: which local constraints fail under A4 but not Arguzz
  (and vice versa), and — most important — whether the **global (Hook-3) memory family** breaks for
  one fuzzer but not the other.
- State the mechanism in plain English (propagation vs isolation) backed by the txn dumps.

**Acceptance:** one matrix sufficient to write §3.3.3 from facts.
**Opus verdict (gate):** decide (a) the single add cleanly demonstrates the bias → proceed to prose
+ a confirmatory campaign; or (b) it's ambiguous/contradicts current prose → campaign required to
characterize. **Report the raw matrix regardless; do not bend data to the hypothesis.**

### M5 — Thesis prose (gated; needs user approval to edit `thesis.md`)
- Rewrite §3.3.3 using the M4 matrix and plain-English constraint labels. Replace the fictional
  step-209 `x1/x2/x3` table with the real add, real `loc`s, real local/global split.
- Resolve the author's open note: frame the axis as **propagating (executor) vs isolated (witness)**
  mutation, not the imprecise "local vs global" wording (registers are memory-mapped in RISC Zero v2;
  there is no standalone `rs1+rs2=rd` polynomial — all reads/writes flow through `mem.zir`).
- **Do not edit `a4/docs/thesis.md` without user approval.**

### M6 — Statistics campaign design (short-term next; built on M0–M4 harness)
**Trigger:** almost certainly needed — a single add proves *existence*, not *generality/magnitude* of
the bias. Draft (Opus + user finalize before any large run):

- **Population / sites.** Sample injection sites across instruction families (R-type ALU add/sub/and/
  or/xor/shift, mul/div/rem, loads/stores of varied width, branches/jumps) and PC zones (user vs
  runtime). For each site identify an operand register/txn.
- **Matched pairs.** Per site, run **Arguzz** (executor, operand register via seed-targeting) and
  **A4** (witness, same register/txn, `next_read` and `prev_write`) with identical full env.
- **Per-run observable.** The *set* of failing constraint contexts `(loc, major, minor, phase)` +
  Hook-3 family residues + exercised (touch) set as denominator.
- **Bias metrics.**
  - Distribution over constraint families per fuzzer (local vs accum; per-`loc` rates).
  - `fail/touch` ratio per constraint family (controls for what's even exercised).
  - Mean #local vs #global failures per injection (propagation → fewer, downstream-consistent).
  - **Interaction stats:** co-occurrence (which constraints fail together) per fuzzer — directly
    encodes propagation structure.
  - Quantify divergence between the two fuzzers' failure distributions (e.g. χ²/KL) for a headline
    number.
- **Controls.** Fixed seeds + repeats for determinism; record everything; CONSTRAINT_CONTINUE so each
  run yields the *full* failure set, not just the first.
- **Cost.** Proof generation dominates — use the minimal/curated guests; budget runs; consider
  `ProverOpts::fast`. Estimate runtime from M2/M3 timings before committing.
- **Output.** Tables/plots of the two distributions + the divergence statistic → the empirical
  backbone of the "Arguzz is biased toward local constraints / A4 shifts toward interstep+global"
  claim.

**Long-term:** interpret the bias in bug-class terms — which underconstraint/soundness vs
overconstraint/completeness regions each stage is structurally more likely to probe.

---

## 3. Report-back templates

```
M2 (A4 witness, a1 4->9)
  add-cycle txns post-mut: a1 READ=__ (exp 9)  s0 WRITE=__ (exp 7, unchanged)  -> ISOLATION
  LOCAL fails (phase=local): [ (loc, major, minor), ... ]   e.g. IsRead@mem.zir:79, MemoryWrite@mem.zir:99
  ACCUM fails (phase=accum): [ ... ]    (distinct bucket; NOT global)
  GLOBAL (Hook3 residues): memory nonzero?__  u16__ u8__ cycle__   final_accum_residue:__
  IsRead value=__  (check == p-5 == 2013265916)
  exit_code:__

M3 (Arguzz executor, a1)
  seed=__  injected a1 = V=__
  A4_INSPECT+inject works? __
  add-cycle txns post-inject: a1 READ=__ (exp V)  s0 WRITE=__ (exp 3+V)  -> PROPAGATION
  LOCAL fails (phase=local): [ ... ]
  ACCUM fails (phase=accum): [ ... ]
  GLOBAL (Hook3 residues): memory__ u16__ u8__ cycle__   final_accum_residue:__
  IsRead value=__  (check == (4 - V) mod p)
  exit_code:__

M4 delta
  LOCAL fails in A4 but NOT Arguzz: [...]   ; in Arguzz but NOT A4: [...]
  ACCUM fails delta: [...]
  GLOBAL (Hook3) difference: does memory family break for A4 only, or both? ...
```

---

## 4. Open risks to retire early
- A4_INSPECT × --inject compatibility (M3) — verify before depending on the post-inject dump.
- A clean a1-hitting seed with an interpretable V exists in a reasonable sweep window (M3).
- Touch granularity is context-level not cycle-level (§1) — denominator interpreted accordingly.
- `<a4_touch_verbose>` actually emits under `A4_COVERAGE_TOUCH_VERBOSE` (M1).
