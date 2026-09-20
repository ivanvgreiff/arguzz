# Diagnosis package for Pro — why V6_uniform beats V6_cTS on the rs1==rs2 known-bug race, and how to fix the scheduler without overfitting

**Audience:** the reviewer ("Pro") who authored ProG_Report_1..5. This document assumes the vocabulary of
those reports (A4, Arguzz, V5/V6/Hybrid, cTS = ConstrainedTS, uniform = ArguzzScheduler, semantic zone, arm,
Bernoulli floor, INSTR_WORD_MOD and the other Arguzz mutation kinds, the bug-race decomposition
`P(find) = P(select instruction) × P(apply) × P(diverge) × P(accept)`, raw accept vs accept-of-wrong). New or
shifted terms are defined inline. Pro has **no source-code access**, so every mechanism is recreated here.

**What this document is for.** We ran the known-bug race (RISC Zero #3181 / the rs1==rs2 divide bug) across the
four variants. **V6_uniform found the bug; V6_cTS, Hybrid_cTS, and V5 found 0.** We want Pro to diagnose, from
the bug mechanics + the scheduler mechanics + the recorded per-mutation database, **how cTS should be modified
(or what a new variant should look like) to beat uniform on this bug WITHOUT overfitting** — i.e. it must remain
a good general soundness-bug finder, not a divide-specific hack.

**Companion documents** (can be provided alongside this one; this doc is self-contained but they have full
depth):
- `CVE_CONSTRAINT_AUDIT_PLAN.md` — the complete, measurement-grounded mechanism of the bug (transaction
  sequencing, memory-permutation cancellation, why only the same-register alias is accepted). **§1 below
  recreates the essentials.**
- `WHY_V6CTS_MISSES_THE_CVE.md` — our **earlier** scheduler analysis. **Partly superseded:** it attributed
  cTS's miss to "coverage reward starving the rare op." The database (§5) shows cTS's reward was *identically
  zero* and the semantic zones were *misaligned* with the inject-step space — different root causes. Read it
  only with that caveat.
- `NON_ALIAS_SUBSTITUTION_TEST_PLAN.md` — the experiments confirming the bug is narrow (same-register only).

**A standing honesty note:** we have been wrong about this bug's mechanism more than once during investigation,
and (see §5) our earlier scheduler explanation was also wrong in its specifics. The §5 database numbers are
directly measured and re-verified across all 6 seeds; the **opinions in §7 may still be wrong** and are flagged
as such. Please weigh the data over our interpretation.

---

## 1. The bug (self-contained; full detail in `CVE_CONSTRAINT_AUDIT_PLAN.md`)

**Guest program under test (the "A2 guest").** A RISC-V program that runs two divide-family instructions on
source registers pinned one bit apart:
```
remu a4, a0, a1     # a0 = x10 = 9 ,  a1 = x11 = 12602 ;  honest remainder = 9 % 12602 = 9
divu s0, a2, a3     # a2 = x12 = 9 ,  a3 = x13 = 12602 ;  honest quotient  = 9 / 12602 = 0
```
The committed journal mixes both results (`acc = r_rem*1000003 + r_div`). Honest journal = 9000027.

**The Arguzz mutation that triggers the bug.** `INSTR_WORD_MOD` flips bits of the fetched instruction word. A
**single-bit flip of the rs2 field's low bit** turns `remu a4,a0,a1` into **`remu a4,a0,a0`** — the second
source register is aliased to the first (rs1 == rs2). The committed output then diverges: `9 % 9 = 0` (remu) or
`9 / 9 = 1` (divu), so the journal becomes 0 or 9000028 — an **accept-of-wrong** if the proof still verifies.

**Why the buggy circuit accepts it, and why ONLY this aliasing mutation (not a substitution to any other
register) — measured, not assumed.** RISC Zero's memory/register accesses are checked by a global *permutation
argument*: every access emits two records, an "old" record (count −1, at the value/cycle of the previous access
to that address) and a "new" record (count +1, at this access's value/cycle); the proof verifies only if all
records cancel in pairs. The fault-injection harness suppresses an internal address-consistency check, so the
circuit (which decodes the **original** word and therefore reads registers a0 and a1) consumes the executor's
transactions positionally even when addresses don't match. Key consequence, all confirmed by re-running the
binary with transaction-level tracing:
- **Alias `rs2:=a0` (the bug):** the executor reads register a0 **twice on the same cycle**. The circuit's
  "read a1" slot consumes the second a0 read, whose previous-access cycle EQUALS its own cycle (same-cycle
  re-read). So its two permutation records land on the *identical* (address, cycle, value) tuple and
  **self-cancel** — the bogus read is invisible to the permutation argument, and the buggy "is this read in
  order?" check accepts a zero cycle-gap. Proof verifies; journal is wrong. **Accept-of-wrong.**
- **Substitution to any OTHER register `rs2:=r` (r≠a0):** the executor reads register r, whose previous access
  was at an *earlier* cycle. The two records land at *different* cycles, do **not** cancel, and break the
  permutation argument → **proof rejected.** (We confirmed this directly: a forced `remu a4,a0,x9` mutation is
  rejected on the buggy binary, with the memory-permutation residue going non-zero.)

**So the bug is narrow: same-register / same-cycle.** Only the aliasing mutation (rs2 → rs1) produces a
self-cancelling record set that escapes detection. The fix (RISC Zero #3181) reads the register only once when
rs1==rs2 and tightens the cycle-ordering check.

**Implication for fuzzing — the find condition.** To find this bug, a single mutation must (a) be
`INSTR_WORD_MOD`, (b) land on one of the two divide instructions (each occurs **once** in the trace), and (c)
have `random_word` produce the specific single-bit rs2→rs1 alias. The operands are one bit apart by design, so
the single-bit-flip strategy aliases with probability ≈ 1/26–1/30 per `INSTR_WORD_MOD` attempt **on a divide
step**. Empirically (§5) the realized rate is 9 finds / 232 such attempts ≈ **1/26**.

---

## 2. The race setup

- **Target binary:** the vulnerable instrumented RISC Zero host (RISC Zero @ 98387806; pre-#3181). Every
  mutation runs the full prover+verifier; the run database records the outcome per mutation.
- **Budget:** N = 5000 mutations per (variant, seed); **6 seeds** (1234–1239); 4 variants. So 30000 mutations
  per variant, 120000 total.
- **Four variants:**
  - **V6_uniform** — Arguzz mutation surface (during-execution fault injection), scheduled by `ArguzzScheduler`
    (round-robin over instruction kinds). The Arguzz-paper baseline.
  - **V6_cTS** — same Arguzz surface, scheduled by `ConstrainedTSScheduler` (the constrained Thompson-sampling
    bandit over (kind, zone) arms).
  - **Hybrid_cTS** — A4 surface ∪ a selected set of Arguzz kinds, scheduled by cTS.
  - **V5_control** — A4-only surface (post-execution single witness-cell mutations), scheduled by cTS. A4 has
    **no** `INSTR_WORD_MOD` and structurally cannot produce a coherent rs2-alias, so it is a negative control.
- **Find oracle (how an accept-of-wrong is confirmed):** the run DB's `verifier_accepted` flag and a
  `soundness_signal` tag are NOISY raw signals (many false positives — a fault that verifies but whose committed
  output is unchanged is benign). The authoritative find count comes from an **output-based replay**: every
  recorded accept is re-executed on the vulnerable binary and classified by its committed output (0 =
  remu-alias, 9000028 = divu-alias, 9000027 = benign). This is indexing-independent and does not depend on any
  mechanistic assumption.

---

## 3. Arguzz mutation capabilities (what mutations CAN find this bug)

Arguzz applies one fault at one execution step (CLI: `--inject --inject-step S --inject-kind K --seed s`; the
seed deterministically fixes the mutation). The kinds:

| kind | what it changes | timing |
|---|---|---|
| **INSTR_WORD_MOD** | the fetched 32-bit instruction word (the only kind that can alias rs2→rs1) | at decode |
| PRE_EXEC_PC_MOD / POST_EXEC_PC_MOD | the program counter | pre / post exec |
| PRE_EXEC_MEM_MOD / POST_EXEC_MEM_MOD | a memory word | pre / post exec |
| PRE_EXEC_REG_MOD / POST_EXEC_REG_MOD | a register value | pre / post exec |
| COMP_OUT_MOD | an ALU result | post-compute |
| BR_NEG_COND | a branch's taken/not-taken | compute (branches only) |
| LOAD_VAL_MOD | a loaded value | post-load |
| STORE_OUT_MOD | a stored value | pre-store |

**`INSTR_WORD_MOD` internals (`random_word`).** It is **not instruction-field-aware** (explicit `// TODO:
instruction aware manipulations`). It picks one of 3 strategies uniformly and retries until the new word ≠ the
original AND decodes to a valid instruction:
- **Strategy 0 — single bit flip:** flip one random bit in bits 2–31. *This is the strategy that aliases rs2→rs1
  in one flip, because the operands are one bit apart.*
- **Strategy 1 — multi-bit flip:** flip N random bits (N ∈ 1..29) among bits 2–31.
- **Strategy 2 — random word:** a fully random 32-bit word `| 0x03`.

So the only kind that finds this bug is INSTR_WORD_MOD via strategy-0's single-bit rs2 flip — hence the ≈1/26
per-attempt rate on a divide step.

---

## 4. The two schedulers (mechanics; no source needed)

### 4.1 V6_uniform = `ArguzzScheduler` — round-robin over instruction KINDS
Each iteration: (1) pick the **instruction kind** with the fewest cumulative pulls (ties broken at random) from
~40 kinds (`add`, `sub`, …, `remu`, `divu`, …); (2) pick a **trace step** uniformly at random from the steps
that execute that kind; (3) pick a **mutation kind** uniformly at random from those valid for that instruction
class. No feedback, no rewards.
**Key property:** the *scheduling unit is the instruction kind*. `remu` and `divu` are each their own kind, each
with a step-set equal to exactly the step(s) where they occur (here {444} and {449} in the inject-step space).
So a rare instruction that occurs once still receives a full ≈1/40 share of the budget — *rarity is irrelevant*.

### 4.2 V6_cTS = `ConstrainedTSScheduler` — Thompson-sampling bandit over (kind, zone) ARMS
- **Arm** = `(mutation_kind, semantic_zone)` (plus surface/opcode-class/pre-post tags). A **semantic zone** is a
  circuit region label (core_arithmetic, core_div, core_memory_store, core_branch, kernel, ECALL, …, ~19 zones),
  assigned to each trace step from the step's cycle "major" field. **This campaign had 417 arms.**
- Each iteration picks an arm via four prioritized **tiers**, then a step **uniformly at random** from that
  arm's step-set, then injects the arm's mutation kind:
  1. **cold-start** — any arm with < 3 pulls (round-robin); measured 26% of pulls.
  2. **singleton** — force ≥5 pulls on arms in special single-step zones; 0.6%.
  3. **Bernoulli floor** — with probability 0.55 (constant), pick the least-pulled arm (pure exploration); 40%.
  4. **adaptive Thompson sampling** — sample θ_arm ~ Beta(1+successes, 1+failures) and pick argmax; 33%.
- **Reward** is Bernoulli (success ∈ {0,1}), intended to fire on coverage novelty; it updates the Beta
  posteriors. Hyperparameters this run: `tau_new=35, tau_d=3, tau_g=6, gamma=0.9965, K_T_rare=31`, floor =
  constant 0.55, `num_arms=417`.
**Key property:** the *scheduling unit is the (kind, zone) arm*. A rare instruction is **not** a first-class
unit; it is one step inside a zone-arm, and the within-arm step pick is uniform, so it competes for budget
against every other step in its zone.

---

## 5. The race results — MEASURED (run database, re-verified across all 6 seeds)

All tables are summed over the 6 seeds (30000 mutations per variant). Source query +
output: `logs/race_db_extract.txt`.

### 5.1 Outcome overview
| variant | INSTR_WORD_MOD muts | raw accepts (verifier) | replay-confirmed FINDS |
|---|--:|--:|--:|
| **V6_uniform** | 3757 | 854 | **9** (3 remu + 6 divu) |
| **V6_cTS** | **8470** | 1430 | **0** |
| Hybrid_cTS | 3442 | 5026 | 0 |
| V5_control | 0 | 10006 | 0 |

Note: **cTS issued MORE INSTR_WORD_MOD mutations than uniform (8470 vs 3757) and MORE raw accepts (1430 vs
854), yet found 0.** So cTS is not under-using the kind or failing to get accepts — it is **mis-targeting**
which steps it applies INSTR_WORD_MOD to.

### 5.2 Targeting the vulnerable divide instructions (inject steps 444=remu, 449=divu) — the core gap
| variant | muts @444 | muts @449 | INSTR_WORD @444 | INSTR_WORD @449 |
|---|--:|--:|--:|--:|
| **V6_uniform** | **910** | **910** | **114** | **118** |
| **V6_cTS** | **6** | **1** | **2** | **0** |
| Hybrid_cTS | 5 | 1 | 1 | 0 |
| V5_control | 5 | 1 | 0 | 0 |

uniform put ≈152 mutations/seed on EACH divide step (its round-robin gives remu and divu a full instruction-kind
share); cTS put essentially nothing. With ≈232 INSTR_WORD attempts on divide steps × (1/26 alias rate) ≈ 9, and
cTS's ≈2 attempts × (1/26) ≈ 0.08, the **expected** finds match the **observed** (9 vs 0) exactly. The entire
difference is the number of INSTR_WORD_MOD attempts that land on the divide instructions.

### 5.3 WHY cTS under-targets the divide — three measured, compounding causes
We re-verified each across all 6 seeds.

**(a) cTS's reward signal was identically ZERO — the bandit never learned.** In every V6_cTS seed, all 5000
rows of `mutation_rewards` have reward = 0 (and all components T_new, F_new, Q, S = 0). Contrast Hybrid_cTS:
~2900/5000 rewards > 0 (mean ≈ 0.20). So for V6_cTS the Beta posteriors never updated past their prior:
α stays 1, β = 1 + pulls, so a pulled arm's sampled θ ~ Beta(1, 1+pulls) *decreases* with its pull count — the
"adaptive" tier (33% of pulls) therefore favored the **least-pulled** arms, i.e. it behaved like more
exploration, not exploitation. Combined with floor (40%, least-pulled arm) and cold (26%, round-robin), all
three tiers push toward an **even spread over the 417 arms**. **cTS's learning never engaged for the pure-Arguzz
surface; its allocation was effectively uniform-over-arms — not a coverage-guided allocation.** (This corrects `WHY_V6CTS_MISSES_THE_CVE.md`, which assumed the reward was working and "starved" the
divide.)

**(b) Semantic-zone misalignment — the divide isn't in the "core_div" arm.** In every seed, the
`INSTR_WORD_MOD|core_div` arm's pulls inject at steps **441 and 436**, NOT the divide steps 444/449. And the
actual divide step 444 is classified into the **`core_memory_store`** zone (i.e. handled by the
`INSTR_WORD_MOD|core_memory_store` arm). So the zone labels are out of register with the inject-step space: the
arm *named* for division does not point at the division instructions, and the divisions are mislabeled into a
memory zone. A scheduler that "prioritized core_div" would therefore STILL miss this bug.

**(c) Within-arm dilution + uniform step pick.** The arm that actually contains divide step 444
(`INSTR_WORD_MOD|core_memory_store`) spans **140 distinct inject steps** (measured, one seed); it received 230
pulls, so the uniform within-arm step pick puts ≈230/140 ≈ 1.6 pulls on step 444 — matching the observed ≈2
INSTR_WORD on the divide. By contrast uniform's `remu` kind has a step-set of size 1 ({444}), so its ≈152 pulls
all land on the divide.

### 5.4 Bandit allocation detail (V6_cTS, summed over seeds)
- Pick-tier mix: **floor 39.9%, adaptive 33.3%, cold 26.2%, singleton 0.6%**.
- 417 distinct arms; top arms (≈250–370 pulls each) are spread across many (kind, zone) combinations — no strong
  concentration (consistent with the dead reward → no learning).
- The `INSTR_WORD_MOD|core_div` arm got 223 pulls (summed) but, per (b), they hit steps 441/436, not the divide.

### 5.5 Coverage is NOT the discriminator
Distinct constraint-locations reached per seed: **V6_cTS 36, V6_uniform 34**, Hybrid 50, V5 50. cTS reached
*more* constraint coverage than uniform yet found the bug 0 times; uniform found it 9 times with *less*
coverage. So on this bug, constraint-coverage and bug-discovery are **anti-correlated** — the bug needs many
*repeated* attempts on one rare instruction (depth), which yields little new coverage after the first hit.

---

## 6. The question for Pro

Given (i) the bug's find condition (many INSTR_WORD_MOD attempts on a once-occurring divide instruction × a
1/26 single-bit alias), (ii) uniform's instruction-kind round-robin that gives rare instructions a full share,
and (iii) cTS's measured failure modes (dead reward, zone misalignment, within-arm dilution):

**How should cTS be modified — or what should a NEW scheduler variant look like — so that it matches or beats
V6_uniform on this bug, WITHOUT overfitting?** "Without overfitting" means: it must not hard-code "target the
divide" or "prioritize INSTR_WORD_MOD"; it must remain a strong general soundness-bug finder (it should not lose
the coverage/breadth that cTS/Hybrid buy, and should still help on bugs that are NOT rare-instruction-localized,
e.g. the A4-side local-constraint bugs).

Sub-questions we'd value Pro's view on:
1. Is the right fix at the **reward** layer (make the reward fire for the Arguzz surface, and/or add an
   exploitation/rarity term), the **arm-granularity** layer (instruction-kind as a first-class unit, or a
   per-instruction floor), the **within-arm step** layer (non-uniform step pick favoring rare steps), or the
   **zone-alignment** layer (fix the step-indexing so zones point at the right instructions)?
2. How to keep coverage/breadth (cTS/Hybrid's strength) while guaranteeing rare-instruction depth — is a
   two-objective or two-phase scheduler warranted, and how to avoid it collapsing to either extreme?
3. What single change would you test first, and what would falsify it?

---

## 7. Our opinions (we may be wrong — do not over-weight; weigh §5 instead)

Offered only because the user asked; flagged as fallible.
- We suspect the **dead reward** is the largest single factor: cTS never learned, so it was effectively
  uniform-over-417-arms, which dilutes a once-occurring instruction far more than uniform-over-40-kinds does.
  But fixing it may not help this bug, because coverage-novelty reward is anti-correlated with the *repeated*
  attempts the bug needs (§5.5) — so reward-fixing alone might still under-target the divide.
- We suspect the **arm granularity** (kind × coarse zone) is the structural issue: a rare instruction is one
  step inside a 140-step zone-arm, whereas uniform makes it a first-class unit. A per-instruction-kind floor (or
  treating instruction kind as part of the arm key with a guaranteed floor) might recover uniform's fairness
  while keeping adaptivity — but risks arm-space explosion (Pro's prior concern about over-factorization).
- The **zone misalignment** looks like a concrete bug (zones computed in a different step-index than `--inject`);
  fixing it is necessary for any zone-based targeting to work, but is probably not sufficient by itself.
- A speculative "no-overfit" framing: a scheduler that guarantees every *instruction kind present in the trace*
  a minimum attempt budget (regardless of frequency), and only then spends remaining budget adaptively on
  coverage, might get uniform's rare-instruction depth AND cTS's breadth. We are unsure how this interacts with
  the A4 surface (where the unit is a witness cell, not an instruction).

---

## 8. Where the underlying data lives (for reproducibility / deeper reading)
- Per-mutation run databases: `a4/runs/iv_pos_9/race/cve_results/cve_thesis_b{1,2,3}/pos_iv_pos_9_cve_<variant>_seed<N>_n5000/run.db` (24 DBs; tables: `mutations`, `bandit_decisions`, `mutation_substrategy`, `mutation_rewards`, `reward_counterfactuals`, `coverage`, `campaign_params`, `failures`).
- Extraction script + raw output: `logs/race_db_extract.txt`.
- Output-based replay classification: `cve_replay_arith.json`, `cve_replay_nonarith.json`.
- Bug mechanism (full): `CVE_CONSTRAINT_AUDIT_PLAN.md`. Earlier (partly-superseded) scheduler note:
  `WHY_V6CTS_MISSES_THE_CVE.md`. Bug-narrowness experiments: `NON_ALIAS_SUBSTITUTION_TEST_PLAN.md`.
- Deeper scheduler mechanics (code-level): `PRO_APPENDIX_A_SCHEDULERS.md`. Deeper Arguzz mutation mechanics:
  `PRO_APPENDIX_B_MUTATIONS.md`. (Both are condensed into §3–§4 above; the appendices add the tier conditions,
  `random_word` strategies, and hyperparameters in full.)

---

## Document set to hand to Pro (in order)
1. **`PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md`** (this file) — self-contained; sufficient on its own.
2. `CVE_CONSTRAINT_AUDIT_PLAN.md` — optional, full bug mechanism with transaction traces.
3. `PRO_APPENDIX_A_SCHEDULERS.md`, `PRO_APPENDIX_B_MUTATIONS.md` — optional, code-level scheduler/mutation detail.
4. `NON_ALIAS_SUBSTITUTION_TEST_PLAN.md` — optional, confirms the bug is same-register-only.
5. `WHY_V6CTS_MISSES_THE_CVE.md` — only with the superseding caveat noted in its header and in the pointer above.
