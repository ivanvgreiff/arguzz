# Guidance for Composer — minimal_add experiment (review by Opus)

**Role split:** Opus = planner/reviewer. Composer = implementor. Do the steps below,
report the requested data back, and Opus will judge whether the thesis §3.3.3 claim is
grounded. **Do not modify anything outside `thesis_side_experiments/minimal_add/`.**
If you think you need to touch `a4/`, `workspace/risc0-modified/`, or `workspace/output/`,
STOP and ask first.

Use only the **modern** fuzzers:
- Arguzz = executor-stage inject in the host (`--inject --inject-kind PRE_EXEC_REG_MOD`).
- A4 = witness-stage mutation via `A4_MUTATION_CONFIG` (the `a4.core` / `a4.standalone` package).
- Do **NOT** use `a4/arguzz_dependent/` or `a4.cli compare` (outdated coupled model).

---

## 1. Verdict on current work

Not thesis-ready yet. The skeleton is good, isolation is honored, and the A4 side is
correct and interpretable. But the headline comparison is **apples-to-oranges** and several
phases are asymmetric or broken.

### What is correct — keep it
- **Isolation verified.** The patched hook files (`execute/rv32im.rs`, `prove/witgen/mod.rs`)
  were last edited Feb/Mar 2026 — untouched by this experiment. Only `thesis_side_experiments/`
  is new. Good.
- **Guest is clean:** one R-type `add`, operands `a0=3, a1=4 → s0=7`. (Registers are
  `a0/a1/s0`, NOT the `t0/t1/t2` the comment claims — cosmetic, fix later.)
- **A4 witness mutation is correct and interpretable.** a1 READ word 4→9 →
  `IsRead@mem.zir:79` + `MemoryWrite@mem.zir:99`, Hook 3 `memory` nonzero.
- **Step alignment works:** A4 step 185 ↔ Arguzz step 187 (A4 records *next* PC, so
  `a4_pc = arguzz_pc + 4`; the step index offset of −2 is separate and fine).

### Forensic proof the comparison is broken (so you trust the fix)
BabyBear prime `p = 2^31 − 2^27 + 1 = 2013265921`. The `<constraint_fail>` `value` field is
the failing residue mod p:
- **A4 run:** value `2013265916 = p − 5 = −(9−4)`. The `−5` is exactly the a1 read delta
  (mutated 9 vs stored 4). **This proves A4's IsRead is the a1 operand.** Correct.
- **Arguzz run:** `<fault>` says `t0 = 1068323197` (a RANDOM, non-operand register), and the
  IsRead value `2013245062 = p − 20859`. The `20859` magnitude is the **t0** corruption, not
  the add operands. So Arguzz never touched the add's inputs; it crashed (`exit −11`) on an
  unrelated register. **The two columns are not comparing the same thing.**

---

## 2. Root causes to fix

| # | Problem | Why it matters |
|---|---------|----------------|
| P0-1 | Arguzz `PRE_EXEC_REG_MOD` hits a **random** register (`random_register_addr()` = `rng.random_range(1..=31)`), seed 42 → `t0`. | Thesis example is about mutating the add's operand (rs2 = a1). Must target a1. |
| P0-2 | Phase 3 (Arguzz) subprocess passes **no env**; Phase 4 (A4) sets `CONSTRAINT_CONTINUE` + `A4_COVERAGE_TOUCH` + `A4_FAMILY_RESIDUE`. | Asymmetric. Arguzz crashes (−11) instead of logging all failures; Hook 3 never measured for Arguzz. |
| P0-3 | Only the *first* Arguzz constraint failure is captured (crash). | Can't compare the full constraint-break set. |
| P1-1 | Phase 2 `touch_at_add.txt` is empty — filter looks for per-step JSON inside a single bitmap blob. | Touch table (universe of exercised constraints) is missing. |
| P2-1 | Guest comment `t0/t1/t2`; `baseline_trace.txt` logs the trace twice. | Cosmetic / parsing hygiene. |

---

## 3. The fix — do these in order

### Step 1 — Make Arguzz corrupt **a1** (rs2 of the add), via seed sweep
`random_register_addr()` is seeded deterministically by `--seed`, and the register choice is
the first RNG draw at the inject step, so each seed → a fixed register. a1 is register index
**11**. The `<fault>` line prints during **execution** (before the slow prove), so kill early
with a timeout to make the sweep fast.

```bash
HOST=thesis_side_experiments/minimal_add/target/release/thesis-minimal-host
for S in $(seq 0 400); do
  line=$(timeout 20 "$HOST" --inject --inject-step 187 \
           --inject-kind PRE_EXEC_REG_MOD --seed "$S" 2>&1 | grep -m1 '<fault>')
  echo "$S | $line"
done | grep '"info":"a1 ='
```

- Pick the **first** seed whose fault is `a1 = <V>`. Record the seed and the value `V`.
- Prefer a `V` that is a small, clean delta from 4 if available (mirrors thesis 4→9), but any
  `V ≠ 4` is acceptable as long as you report it. Avoid `V` that traps before witgen.
- Sanity: a1 has ~1/31 odds per seed, so expect a hit within ~30–60 seeds.

### Step 2 — Run BOTH sides symmetric + full capture
Every run gets `CONSTRAINT_CONTINUE=1 A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1`.

**Fix `run_phases.py` Phase 3** so the Arguzz subprocess receives that env (currently
`subprocess.run(arguzz_cmd, ...)` with no `env=`). Use the a1-seed from Step 1 instead of 42.

**Also dump the post-inject txns for BOTH** to capture the ground-truth mechanism difference:
- Arguzz inject run **+** `A4_INSPECT=1 A4_DUMP_STEP=185`. Expect the add cycle to show the
  *propagated* state: a1 READ = `V`, s0 WRITE = `3+V` (executor recomputed the result).
- A4 run already shows the *isolated* state: a1 READ = 9, s0 WRITE = **7** (unchanged — the
  ALU output was not recomputed).

This propagation-vs-isolation dump is the single most important piece of evidence for §3.3.3.

### Step 3 — Capture & classify ALL constraint failures
For each side, parse every `<constraint_fail>`, dedup by `(loc, major, minor)`, and record
`phase`. Record Hook 3 families for **both**. Put it in `comparison_matrix.json`.

### Step 4 — Validate causality with the field-element check
For a1-targeted Arguzz with value `V`, the `IsRead` `value` must be `(4 − V) mod p`
(magnitude `|V−4|`). Confirm it matches a1 — NOT some other register. (A4 already checks out:
`p − 5`.) Only claim "Arguzz broke the add's rs2 read" once this matches.

### Step 5 — Phase 2 touch table
The current filter is wrong (single bitmap blob, not per-step JSON). Either:
- (a) decode the `A4_COVERAGE_TOUCH` bitmap for cycle **15424** (the add) and list the
  exercised constraint locs, or
- (b) defer Phase 2 and mark `touch_at_add.txt` as future work.

**Flag for Opus:** tell me which you can do cleanly; (a) is preferred but don't invent a
parser that misreports. Do not fabricate a touch table.

### Step 6 — Cosmetic / hygiene
- Guest comment `t0/t1/t2` → `a0/a1/s0`.
- When parsing `baseline_trace.txt`, use only the first trace block (the prove pipeline logs
  the trace twice).

---

## 4. Report back to Opus (exact fields)

Fill this in and I will review before any thesis prose is written:

```
SITE: arguzz_step=187, a4_step=185, cycle=15424, pc=2099232(+4), add s0,a0,a1 (3+4=7)

ARGUZZ (executor, a1-targeted):
  seed=?, injected: a1 = V=?
  post-inject add-cycle txns (A4_DUMP_STEP=185): a1 READ=?  s0 WRITE=?
  full failure set: [{loc, major, minor, phase}, ...]
  IsRead value = ?   (check: == (4 - V) mod p ?)
  Hook3 families: ?
  exit_code: ?

A4 (witness, a1 read 4->9):
  post-mut add-cycle txns: a1 READ=9  s0 WRITE=?  (expect 7, unchanged)
  full failure set: [...]
  IsRead value = 2013265916 (== p-5)  [confirm]
  Hook3 families: memory nonzero?
  exit_code: ?
```

---

## 5. Hypothesis to confirm or REFUTE (do not assume the answer)

Working hypothesis for §3.3.3 (Opus will accept/reject based on your data):

- **Arguzz (executor):** the corruption happens *before* execution, so the rest of the trace
  is rebuilt *consistently* with the bad value (read=V, ALU=3+V, write=3+V). The only thing it
  can't reconcile is the link to the **past** legitimate value (stored 4 ≠ read V) →
  expected to break **IsRead only**.
- **A4 (witness):** the corruption is *isolated* to one recorded read; everything else
  (prev_word=4, s0 write=7, the ALU result) is untouched. So the bad read is inconsistent with
  **both** the past (prev_word) **and** the same-cycle computation (write/ALU) → breaks
  **IsRead + MemoryWrite**.

If confirmed, this **refines the thesis**: the real axis is *propagating* (executor) vs
*isolated* (witness) mutation — NOT the current prose's "local vs global/interstep" wording,
which is imprecise because in RISC Zero v2 registers are memory-mapped and *all* reads/writes
flow through the `mem.zir` argument (there is no standalone "rs1+rs2=rd" polynomial to break).
This directly resolves the author's open note at the end of `thesis.md` §3.3.3.

If instead Arguzz-on-a1 *also* breaks MemoryWrite (distinction collapses for a single add),
then the simple example is not sufficient and we escalate to the multi-instruction campaign
to collect constraint-failure / interaction statistics. **Report the raw result either way;
do not bend the data to fit the hypothesis.**
