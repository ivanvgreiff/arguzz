# EXPECTED_ARMS.md — Canonical (kind, semantic_zone) matrix

**Purpose:** non-circular ground truth for Phase 7d Audit A5. This file
asserts, for each well-known guest input, which `(mutation_kind,
semantic_zone)` arms SHOULD exist after the universe builder runs, and
roughly how many steps each arm should contain. The builder is correct
iff its output matches this matrix.

**About uncertainty (read before extending this file):** the categorizations
below are not all created equal. Three classes:

| Class | Meaning | How to verify |
|---|---|---|
| **ALGO** (algorithmic) | Defined by code; no uncertainty | trust the definition |
| **EMPIRICAL** (deterministic per guest) | Step counts; depend on the specific guest trace | re-run audit A3 with the new input; copy the numbers |
| **UNCERTAIN** (policy choice or unverified assumption) | Choices we made without external evidence (e.g., "core_other for major=12 BIGINT" — is this semantically right?). | Resolve via Phase 7d Audits **E1 (instruction decoding)**, **E2 (failure-class fingerprinting)**, **E3 (multi-classification probe)**, and **E4 (manual review queue)** before relying on them. |

Arms tagged 🟡 **UNCERTAIN** below have at least one open question that
Audit E will answer; their step-count gates are wider (±20% instead of ±5%)
until E1-E4 close them out. Arms tagged 🟢 **CONFIRMED** are validated by an
E-suite audit.

**Update protocol:** when adding a new input variant or guest:
1. Run `a4/audits/A3_arm_step_integrity.py` against the new trace.
2. Copy the arm table here.
3. Add a manual "reason this arm exists" column for any non-obvious arm
   (e.g. `LOAD_VAL_MOD|post_ecall` exists because the post-ECALL fallthrough
   sometimes contains an immediate load).
4. Note which arms are EXPECTED-DROPPED (the phantom-pruning catches them).

**Audit script:** `a4/audits/A5_canonical_match.py` parses this file and
diffs the universe builder's output against it. Exact arm presence/absence
must match; step counts must match within ±5%.

---

## Guest: sha2-host @ `--in1 5 --in4 10` (BASELINE)

**Trace shape:**
- total cycles: 32768
- total steps: 3930
- total txns: 34724 (8780 reg, 25944 mem)
- ECALL-containing steps: 33

**Universe shape:**
- expected arms: **48**
- expected dropped arms: **5**

### Kept arms (48)

Status column: 🟢 confirmed by E-audit, 🟡 uncertain (gate widens to ±20% until E-audit resolves), 🔵 algorithmic/trivial (no E-audit needed).

| arm | step count | tolerance | status | notes |
|---|---:|:-:|:-:|---|
| COMP_OUT_MOD\|post_ecall                | 11 | ±2 | 🟡 | comp in cycle e+1 — but is "post_ecall = e+1 only" the right semantic boundary, or should it extend to e+2..e+N? (E3) |
| COMP_OUT_MOD\|core_arithmetic         | 1690 | ±5% | 🟢 | main ALU body — confirmed by major∈{0,1,2} predicate |
| COMP_OUT_MOD\|core_mul                  | 66 | ±5% | 🟢 | MUL block (major=3) |
| COMP_OUT_MOD\|core_div                  | 22 | ±5% | 🟡 | DIV/REM/SRL/SRA block (major=4) — DIV0 actually contains shift/right ops too; is this semantically a single zone or should we split? (E1, E3) |
| INSTR_TYPE_MOD\|step0                    | 1 | exact | 🔵 | always present (singleton) |
| INSTR_TYPE_MOD\|pre_ecall               | 18 | ±2 | 🟡 | non-singleton pre_ecall steps with major≤6 — but pre_ecall classifier puts the ECALL cycle itself in pre_ecall (D13); some steps in this zone might be "the ECALL step" while others are "the step containing pre-ECALL setup." Do we want to split? (E3) |
| INSTR_TYPE_MOD\|post_ecall              | 32 | ±2 | 🟢 | every post_ecall step has a regular instruction (confirmed by A2) |
| INSTR_TYPE_MOD\|core_arithmetic       | 2443 | ±5% | 🟢 | every arithmetic step |
| INSTR_TYPE_MOD\|core_memory_load       | 678 | ±5% | 🟢 | every load step |
| INSTR_TYPE_MOD\|core_memory_store      | 596 | ±5% | 🟢 | every store step |
| INSTR_TYPE_MOD\|core_mul                | 100 | ±5% | 🟢 | |
| INSTR_TYPE_MOD\|core_div                | 23 | ±5% | 🟡 | core_div confusion (E1) |
| INSTR_WORD_MOD_FULL\|last_step           | 1 | exact | 🟡 | is the last step's cycle a real instruction fetch or a halt cycle that's not actually mutable? (E2: does mutation produce any effect?) |
| INSTR_WORD_MOD_FULL\|pre_ecall          | 32 | ±2 | 🟡 | includes the ECALL cycle itself (major=8 allowed); does mutating the ECALL fetch produce a different failure class than mutating a pre-ECALL ALU fetch? (E2) |
| INSTR_WORD_MOD_FULL\|post_ecall         | 32 | ±2 | 🟢 | |
| INSTR_WORD_MOD_FULL\|core_arithmetic  | 2443 | ±5% | 🟢 | |
| INSTR_WORD_MOD_FULL\|core_memory_load  | 678 | ±5% | 🟢 | |
| INSTR_WORD_MOD_FULL\|core_memory_store | 596 | ±5% | 🟢 | |
| INSTR_WORD_MOD_FULL\|core_mul           | 100 | ±5% | 🟢 | |
| INSTR_WORD_MOD_FULL\|core_div           | 23 | ±5% | 🟡 | |
| INSTR_WORD_MOD_SUR\|last_step            | 1 | exact | 🟡 | same uncertainty as FULL|last_step |
| INSTR_WORD_MOD_SUR\|pre_ecall           | 32 | ±2 | 🟡 | |
| INSTR_WORD_MOD_SUR\|post_ecall          | 32 | ±2 | 🟢 | |
| INSTR_WORD_MOD_SUR\|core_arithmetic   | 2443 | ±5% | 🟢 | |
| INSTR_WORD_MOD_SUR\|core_memory_load   | 678 | ±5% | 🟢 | |
| INSTR_WORD_MOD_SUR\|core_memory_store  | 596 | ±5% | 🟢 | |
| INSTR_WORD_MOD_SUR\|core_mul            | 100 | ±5% | 🟢 | |
| INSTR_WORD_MOD_SUR\|core_div            | 23 | ±5% | 🟡 | |
| LOAD_VAL_MOD\|post_ecall                 | 2 | ±1 | 🟡 | **VERY RARE (2)**. Is this real or is the post_ecall window too narrow? Should LOAD_VAL_MOD also have arms in pre_ecall? (E3 — investigate why only 2) |
| LOAD_VAL_MOD\|core_memory_load          | 586 | ±5% | 🟢 | every load with non-zero reg destination |
| MEM_VAL_MOD\|step0                       | 1 | exact | 🟡 | step 0 has a mem write but the host I/O variance (D42) affects MEM_VAL targets; should we permit MEM_VAL_MOD on step 0 at all? (E2: does mutation actually take effect?) |
| MEM_VAL_MOD\|last_step                   | 1 | exact | 🟡 | similar I/O concern |
| MEM_VAL_MOD\|pre_ecall                  | 32 | ±2 | 🟡 | every pre_ecall step has mem txn — but ECALL steps' mem txns may be host-controlled (D42 allow-list); some may be non-targetable. (E2) |
| MEM_VAL_MOD\|post_ecall                 | 21 | ±2 | 🟡 | |
| MEM_VAL_MOD\|core_arithmetic           | 848 | ±5% | 🟡 | only 848/2443 arith steps have mem txns. Why these and not the others? (E1 + E2) |
| MEM_VAL_MOD\|core_memory_load          | 678 | ±5% | 🟢 | |
| MEM_VAL_MOD\|core_memory_store         | 596 | ±5% | 🟢 | |
| MEM_VAL_MOD\|core_branch                | 24 | ±5% | 🟡 | branch steps with mem txns?? branches don't load/store. Are these branch instructions doing memory access via JAL/JALR PC update, or is this an unexpected classification? (E1 + E3) |
| MEM_VAL_MOD\|core_mul                   | 34 | ±5% | 🟡 | subset of mul steps with mem txns — same question as core_arithmetic above. (E1) |
| MEM_VAL_MOD\|core_div                    | 1 | exact | 🟡 | the famous one — step 3921 only. We accept this empirically; is the mem txn at this step actually mutable? (E2) |
| PRE_EXEC_REG_MOD\|step0                  | 1 | exact | 🟡 | step 0 has reg writes from POSEIDON setup; PRE_EXEC_REG_MOD assumes a normal RV32IM instruction. Does the mutation actually achieve its semantic purpose at step 0? (E2) |
| PRE_EXEC_REG_MOD\|post_ecall            | 14 | ±2 | 🟡 | only 14 of 32 post_ecall steps have a real PRE_EXEC_REG target. Why? (E3) |
| PRE_EXEC_REG_MOD\|core_arithmetic     | 2242 | ±5% | 🟢 | most arith steps have a reg read; the 201 without reg reads are zero-arg ops |
| PRE_EXEC_REG_MOD\|core_memory_load     | 669 | ±5% | 🟢 | |
| PRE_EXEC_REG_MOD\|core_memory_store    | 586 | ±5% | 🟢 | |
| PRE_EXEC_REG_MOD\|core_mul              | 66 | ±5% | 🟢 | |
| PRE_EXEC_REG_MOD\|core_div              | 22 | ±5% | 🟡 | |
| STORE_OUT_MOD\|core_memory_store       | 596 | ±5% | 🟢 | every store step is a target |

### Expected-DROPPED arms (5) — phantom-pruning catches these

These `(kind, zone)` intersections look non-empty when computed coarsely
(`get_valid_steps_for_kind ∩ zone_to_steps`), but every step in the
intersection rejects the mutation module's `get_targets_at_step` probe.
The universe builder correctly drops them.

| arm | reason |
|---|---|
| COMP_OUT_MOD\|step0 | step 0 has no compute-instruction WRITE txn (POSEIDON setup only) |
| COMP_OUT_MOD\|pre_ecall | ECALL steps don't have a compute-instruction destination register |
| INSTR_WORD_MOD_FULL\|step0 | step 0 is a special preamble, no fetch txn to mutate |
| INSTR_WORD_MOD_SUR\|step0 | same |
| PRE_EXEC_REG_MOD\|pre_ecall | ECALL cycle has no pre-execution register read in the form PRE_EXEC_REG_MOD targets |

### Zones EMPTY on this guest (8 of 17)

| zone | reason |
|---|---|
| pre_mret | classifier limitation — MRET cycles not detectable from major alone |
| post_mret | same |
| pre_halt | same |
| post_halt | same |
| core_sha | sha2-host uses non-accelerated SHA in user space (major 0-2 ALU ops, not major 11 SHA0) |
| core_poseidon | major-9/10 cycles only at step 0 which is captured by step0 singleton |
| core_other | no major-8/12 cycles outside ECALL boundary handling |

---

## Guest: sha2-host @ `--in1 1 --in4 1` (SMALL INPUT)

**Status:** FILLED (Inc 4 B12 pre-flight, 2026-06-08). Source: `a4/audits/audit_output/A3_arms_in1_1_in4_1.json`.

**Trace shape (A3):**
- total steps: 3930 (identical to baseline — sha2-host trace is input-invariant for in1/in4 in range 1–100)
- expected arms: **48**
- expected dropped arms: **13** (phantom pruning; more coarse intersections than baseline's 5 because fewer steps qualify per dropped arm at this input, but same kept set)

**Adjudication (E3 mini-session):**
- **New arms vs baseline:** none (0/48 difference in arm presence)
- **Dropped arms vs baseline:** none
- **Step counts vs baseline:** identical on all 48 kept arms (surprising but confirmed — guest cycle mix does not change with `--in1 1 --in4 1` for sha2-host)
- **Verdict:** 🟢 all 48 arms inherit baseline status; no new categorization decisions required

### Kept arms (48)

**Identical to baseline** (`--in1 5 --in4 10` section above). A3 confirms exact same 48 `(kind, zone)` pairs with identical step counts. A5 tolerance gates use the baseline table.

### Expected-DROPPED arms

Same 5 phantom arms as baseline (see baseline section). A3 additionally reports 13 coarse intersections dropped by phantom pruning at this input.

---

## Guest: sha2-host @ `--in1 100 --in4 100` (LARGE INPUT)

**Status:** FILLED (Inc 4 B12 pre-flight, 2026-06-08). Source: `a4/audits/audit_output/A3_arms_in1_100_in4_100.json`.

**Trace shape (A3):**
- total steps: 3930 (identical to baseline)
- expected arms: **48**
- expected dropped arms: **13**

**Adjudication (E3 mini-session):**
- **New arms vs baseline:** none — `core_sha`, `core_other`, `core_poseidon` remain empty (no BigInt/SHA accelerator cycles unlocked)
- **Dropped arms vs baseline:** none
- **Step counts vs baseline:** identical on all 48 kept arms
- **Verdict:** 🟢 inherit baseline; the "10× more arithmetic" hypothesis does NOT hold for this guest — input size does not alter the static trace shape

### Kept arms (48)

**Identical to baseline** (`--in1 5 --in4 10` section above).

### Expected-DROPPED arms

Same as small-input section.

---

## Invariants that MUST hold across all sha2-host inputs

If any of these is violated for an input, the universe builder has a bug.

1. **Always present singletons:** `INSTR_TYPE_MOD|step0`, `MEM_VAL_MOD|step0`, `MEM_VAL_MOD|last_step`, `INSTR_WORD_MOD_FULL|last_step`, `INSTR_WORD_MOD_SUR|last_step`, `PRE_EXEC_REG_MOD|step0` — exactly 1 step each.

2. **Empty on every sha2-host input:** `pre_mret`, `post_mret`, `pre_halt`, `post_halt`, `core_sha`, `core_poseidon`, `core_other`. (Until classifier limitations are addressed.)

3. **STORE_OUT_MOD only ever appears in `core_memory_store` zone** (other zones empty for this kind).

4. **LOAD_VAL_MOD only appears in `core_memory_load`** (plus a small `post_ecall` count from ECALL fallthroughs that immediately load).

5. **Arm count for sha2-host is ≤ 53** (52 from naive intersection minus at least 5 phantom drops = 48 baseline; up to +5 if other inputs unlock additional arms).

---

## Open questions about categorization (Audit E to resolve)

These are NOT bugs — they're open semantic questions where we picked a
specific categorization that may or may not match what the bandit/researcher
would want. Each will be resolved by the E-audits (E1-E4 in
`phases/PHASE_7D_ARCHITECTURE_AUDIT.md`).

| Q | Question | Answered by |
|---|---|---|
| Q1 | At multi-major steps (e.g., step has both major=0 ALU AND major=8 ECALL cycles), which zone wins? Currently the LAST `data._step_to_cycle` entry's major decides, but our classifier rules give pre_ecall precedence. Are there steps where this differs and which is "right"? | E3 (multi-classification probe) |
| Q2 | Is the post_ecall zone too narrow (only e+1)? Some semantic ECALL boundary effects may extend to e+2..e+N. | E3 + E2 (does mutation at e+2 produce ECALL-related failures?) |
| Q3 | Does `core_div` actually behave semantically as a single zone or should it be split into `core_div_real` (DIV/REM) and `core_shift_right` (SRL/SRA)? Currently they share major=4. | E1 (independent decode) + E2 (failure-class fingerprint) |
| Q4 | Are `MEM_VAL_MOD|core_branch` (24 arms) and `MEM_VAL_MOD|core_arithmetic` (848 arms) actually mutating memory transactions that the constraint system checks? Or are some of these "memory" txns actually internal scratch buffers? | E1 + E2 |
| Q5 | Why does `LOAD_VAL_MOD|post_ecall` have only 2 steps? Should this zone have more LOAD targets? | E3 (manual enumerate why each post_ecall step is/isn't a LOAD target) |
| Q6 | Does mutating the cycle at `last_step` (singleton arms `INSTR_WORD_MOD_*|last_step`, `MEM_VAL_MOD|last_step`) produce any observable effect, or is this a no-op terminal cycle? | E2 (run mutations at these steps, observe outcomes) |
| Q7 | Is `core_other` (currently empty for sha2-host) the right destination for major=12 (BIGINT)? Or should we add a `core_bigint` zone for guests that use BigInt accelerator? | Future (when we test on a BigInt-using guest) |
| Q8 | For MRET/halt-adjacency (`pre_mret`, `post_mret`, `pre_halt`, `post_halt` — currently empty), can we detect them from the trace? Cycle.major=7 (CONTROL0) covers MRET but also branches; would need to look at the actual instruction word. | E1 (decode major=7 cycles by instruction word; report which are MRET vs branches) |
| Q9 | After D50, does splitting `core_div` actually produce useful bandit signal differentiation? Or do DIV and SRL behave statistically the same under our coverage metrics? | E2 (failure-class fingerprinting on both halves) |
| Q10 | After D53 (post_ecall = first user-PC step), how many post_ecall steps are at e+1 vs e+2 vs e+3+? | Already partly answered by `audit_output/E6_post_ecall_window_evidence.json`; rerun A3 post-D53 implementation |
| Q11 | After D54 (HYBRID kernel_other zone), is the resulting `kernel_other` arm exercising distinct constraint families compared to the user-only zones? Specifically: do kernel_other failures fingerprint differently from `core_arithmetic` failures? If they fingerprint identically, HYBRID may not be worth the extra zone. | E2 (failure-class fingerprinting on kernel_other vs user-only core_* zones) |
