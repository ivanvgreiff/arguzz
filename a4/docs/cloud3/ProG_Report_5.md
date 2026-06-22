According to the June 21 IV.POS.8 materials, your current checkpoint gives a sharper answer than the previous rounds: **Hybrid-cTS is the right architecture to carry forward for broad constraint-space exploration, but the evidence does not yet show that constrained Thompson sampling beats Arguzz’s round-robin scheduler on Arguzz’s own surface.** The result is **Case B**: V6-cTS ties V6-uniform on normalized local territory, while Hybrid wins territory by adding the A4 surface. The strongest new empirical fact is the local/global split: **A4 owns local per-row constraints; Arguzz owns global/permutation CGC structure; Hybrid is strong on both.**  

My top-level recommendation is:

> **Run the known-bug race first, then run a multi-guest coverage sweep. For the thesis, treat them as two different claims: bug-finding effectiveness and general coverage generalization. Do not collapse them into one giant experiment.**

The known-bug race answers the security question. The multi-guest sweep answers the architecture/generalization question. You need both, but the race should come first because it directly tests whether your current coverage proxy has predictive value for actual soundness discovery.

---

# 1. What your latest results imply

The four-variant experiment answered the first important integration question: Hybrid is not redundant. It combines A4’s local strength with most of Arguzz’s global reach. In the D2.H campaign, V5_control and Hybrid each reached **49/52** local locations, while V6_uniform and V6_cTS reached **37** and **36** respectively. On CGC, the ranking flipped: V6_cTS reached **670**, V6_uniform **565**, Hybrid **591**, and V5_control only **449**. 

That is a thesis-grade finding because it corrects a prior assumption. The original intuition was that A4’s post-execution witness mutations would be the “global/witness-internal” explorer. Your data says the reverse: **Arguzz reaches more global/permutation structure; A4 reaches more local `.zir` equality structure.** The clean control matters here: even feedback-free V6_uniform reached **565** CGC contexts versus A4’s **449**, so the global lead is not merely V6-cTS over-sampling `INSTR_WORD_MOD`. 

But the scheduler result is weaker. D2.G says V6-cTS does **not** beat V6-uniform on the authoritative normalized-local-territory gate: V6_cTS gets roughly **36.0** locs versus V6_uniform’s **35.0**, and pooled territory is **36** versus **37**. Hybrid wins territory, but that win is mostly because it carries A4’s surface, not because cTS proves superior to round-robin on the Arguzz-only surface. 

So the honest current claim is:

> **Hybrid is the broadest explorer. Constraint-space feedback has not yet been shown to improve Arguzz’s local-territory coverage, although V6-cTS has a non-gating CGC lead.**

This matters for your next steps. You should not spend the next phase trying to polish V6-cTS as if the bandit clearly won. The next work should test whether Hybrid’s broader exploration translates into bug-finding speed, and whether the local/global complementarity holds across guests.

---

# 2. Answer to Q1: multi-guest testing

## 2.1 Use several focused guests, not one mega-guest, for the thesis

For a master’s thesis, the best design is **a small suite of focused guests**, each constructed to exercise a distinct region of the zkVM constraint system. Do not make one huge “everything guest” as the primary evaluation.

A mega-guest has some appeal: it gives one large trace, many instruction classes, and one clean plot per variant. But it creates serious interpretation problems. If Hybrid wins on the mega-guest, you will not know whether it won because of ECALLs, memory pressure, Poseidon, BigInt, branches, MRET-like control, or simply trace size. If V6 wins, you will not know whether A4 was weak generally or whether the A4-relevant trace fields were diluted by irrelevant regions. For thesis purposes, that is too opaque.

A focused guest suite gives cleaner causal interpretation:

```text
guest A: current CircIL arithmetic/boolean/div baseline
guest B: ECALL/control-heavy guest
guest C: memory-stress + branch/control guest
guest D: accelerator / Poseidon / BigInt-style guest
guest E: known-bug remu/divu guest, used for race rather than coverage generalization
```

You can then show whether the local/global split is stable or guest-specific. D2.H already warns that all current results are single-guest and that guest-specific families such as Poseidon and BigInt could change the family picture; it also notes that currently-dead A4 paging/cycle kinds may activate on a Poseidon/paging guest. 

## 2.2 Recommended guest suite

I would run **three new guests plus the existing one** for the main multi-guest sweep.

### Guest 0 — current `sha2-host` CircIL baseline

Keep it. It is not actually SHA-2; it is a CircIL-generated metamorphic differential-equivalence program with arithmetic, boolean logic, `%` lowered to `remu/divu`, comparisons, muxes, and a 3961-step trace. It is a good integration and baseline guest, but it does not exercise SHA/Poseidon/paging/MRET meaningfully and does not contain the known `rs1`/`rs2` bug pattern. 

Use it as the anchor.

### Guest 1 — ECALL/control-boundary guest

Purpose: validate A4’s local/control advantage and test whether V5’s older ECALL/control wins generalize.

Structure:

```text
- repeated env::read calls
- repeated env::commit calls
- branches around commits
- conditional early exits
- possible panic-free boundary conditions
- enough user/kernel crossings to populate ECALL-adjacent semantic zones
```

Why: D2.H says A4 pulls ahead on decode/control families, especially `inst_control`, and that Hybrid’s A4 dilution caused it to miss some rare A4-only control locs. A control-heavy guest tells you whether that is an enduring A4 strength or a current-guest artifact. 

### Guest 2 — memory-stress + branch/control guest

Purpose: exercise memory permutation, `prev_word`, `prev_cycle`, load/store, branch, and global CGC behavior.

Structure:

```text
- array loads/stores
- dependent memory writes followed by reads
- nontrivial address arithmetic
- branches whose condition depends on loaded values
- maybe small loops if trace size remains manageable
```

Why: Arguzz’s global advantage likely comes from during-execution perturbations propagating through memory and lookup/permutation structures. A memory-stress guest tests whether V6/Hybrid CGC dominance strengthens when memory structure is intentionally dense.

### Guest 3 — accelerator / Poseidon / BigInt guest

Purpose: test under-explored families and activate dead/empty semantic zones.

Structure depends on what is easy in your RISC Zero setup, but the goal is:

```text
- direct use of available accelerator-backed operations
- Poseidon or BigInt paths if exposed
- trace regions involving accelerator state / backs / bigint bytes
```

Why: D2.H identifies `inst_p2` and `inst_div` as thinly covered blind-spot candidates, and notes that guest-specific families such as Poseidon/BigInt may change the picture. 

### Guest 4 — stock SHA guest only if cheap

Run stock SHA if it is easy, but I would not make it one of the thesis pillars unless it activates genuinely new circuit families. Your current harness name already caused confusion; adding a real SHA guest is useful for sanity, but it may not be as strategically valuable as ECALL/memory/accelerator guests.

## 2.3 Presentation format

For the thesis, show both **per-guest curves** and **aggregate tables**.

For each guest, use the D2.H-style two-panel plot:

```text
left: local constraint-location coverage curve
right: CGC coverage curve
```

Then add one compact summary table per guest:

```text
variant
local_final
local_AUC
CGC_final
CGC_AUC
exclusive_local
exclusive_CGC
time_to_80pct_local
time_to_80pct_CGC
soundness_candidates_strong
applied_pull_rate
wall-clock
```

And then one cross-guest aggregate figure:

```text
rows = guests
columns = variants
cell color = normalized rank or normalized coverage
split into local and CGC panels
```

Do not only show headline territory tables. Your main story is about exploration dynamics; curves show early saturation, delayed CGC growth, and whether one variant wins quickly or only at the tail. The D2.H notebook already says local coverage is flat by roughly 2–3k pulls while CGC keeps climbing toward N=10000, which is exactly the type of behavior curves expose and tables hide. 

## 2.4 Budget for multi-guest sweep

Use a staged design.

### Stage 1 — screening sweep

```text
guests: 3 new guests + current baseline
variants: V5_control, V6_uniform, V6_cTS, Hybrid_cTS
seeds: 3 paired seeds
budget: N = 5000 per run
```

Why 5000? Current local coverage saturates around 2–3k on `sha2-host`, while CGC still has headroom at N=10000. For a first pass, N=5000 is enough to reveal local behavior and early CGC ranking without spending the full budget everywhere.

### Stage 2 — thesis-grade rerun

Pick the two most informative guests from Stage 1 and run:

```text
seeds: 10 paired seeds
budget: N = 10000
```

Use N=10000 for final thesis plots, because your current four-variant campaign used N=10000 and because CGC continues to grow late. D2.H reports N=10000 jobs took roughly **5.5–9.2 hours** each depending on variant, so a full multi-guest expansion is expensive enough that staged triage is justified. 

## 2.5 One mega-guest as appendix, not main evidence

A mega-guest is useful after the focused suite:

```text
mega_guest = ECALL + memory + arithmetic/div + Poseidon/BigInt + branch/control
```

Use it as a stress test:

```text
Can the scheduler handle a large, mixed arm space?
Does Hybrid still avoid dilution?
Does V6-cTS over-concentrate on INSTR_WORD_MOD?
```

But do not make it the only generalization experiment. It is less interpretable and more likely to produce a result you cannot explain.

---

# 3. Answer to Q2: known-bug detection race

Run the known-bug race **before** the full multi-guest sweep. It directly answers the thesis’s security question: do your variants find an actual known soundness bug faster or more reliably than baseline Arguzz?

The Arguzz paper’s RISC Zero soundness bug is the right first target. The paper describes a `remu` example where the malicious prover changes the divisor register `rs2` to equal `rs1`, making the VM compute `remu rd, rs1, rs1`; the proof still verified because of a missing constraint. The paper also says the bug was not limited to `remu`; it affected three-register instructions such as `divu`, and it was patched across both RISC Zero and Zirgen. 

## 3.1 Correct an important guest-design detail

Do **not** build the normal guest instruction with `rs1 == rs2`.

You want the **fault** to create `rs1 == rs2`.

The bug pattern is:

```text
normal execution:
    remu rd, rs1, rs2
    with rs1 != rs2
    output = rs1 % rs2

malicious/faulted execution:
    remu rd, rs1, rs1
    output = rs1 % rs1 = 0

soundness failure:
    output changes / OOPS fires,
    but verifier still accepts proof
```

If the original guest already executes `remu rd, rs1, rs1`, then changing `rs2` to `rs1` is a semantic no-op. That would poison the benchmark.

## 3.2 Guest structure for the race

Use two bug-race guests: one minimal and one contextual.

### Race guest A — minimal bug microbenchmark

This is the clean benchmark.

Structure:

```rust
#[inline(never)]
fn remu_asm(a: u32, b: u32) -> u32 {
    // inline asm remu rd, rs1, rs2
    // ensure rs1 != rs2 in test inputs
}

#[inline(never)]
fn reference(a: u32, b: u32) -> u32 {
    a % b
}

fn main() {
    let a = 7u32;
    let b = 5u32;
    let x = remu_asm(a, b);
    let y = reference(a, b);

    if x != y {
        env::commit(&OOPS);
    } else {
        env::commit(&SUCCESS);
    }
}
```

Key requirements:

```text
- force actual RISC-V remu with three register operands
- avoid compiler constant-folding
- avoid immediate lowering
- use inline asm or black_box-style input barriers
- make rs1 != rs2 in the normal execution
- ensure the fault rs2 := rs1 changes output
- commit OOPS/SUCCESS explicitly
```

Use `a=7, b=5` for the first deterministic version because the paper’s example uses that shape, but also run several input pairs:

```text
(7, 5), (13, 5), (17, 3), (0xffffffff, 3), (2^31+1, 7)
```

Avoid `b=0` unless you explicitly want division-by-zero behavior. That is a different benchmark.

### Race guest B — contextual product-program benchmark

This is the thesis benchmark.

Structure:

```text
- 4–8 semantically equivalent functions
- 1–2 functions contain inline-asm remu/divu
- other functions compute equivalent results differently
- compare all outputs
- commit OOPS on first divergence, SUCCESS otherwise
- include decoy arithmetic/logic/memory instructions
```

This mirrors Arguzz’s product-program model more closely. The paper describes Arguzz as generating semantically equivalent program pairs, merging them into one Rust product program with a known output, and using fault injection to mimic malicious provers. 

The contextual benchmark prevents the race from being too trivial. It also lets you measure whether cTS/Hybrid can prioritize the bug-relevant instruction class amid decoys.

## 3.3 How big should the bug guest be?

Use three sizes.

### Size S — deterministic smoke test

```text
trace length: as small as practical
bug sites: 1 remu, optionally 1 divu
purpose: verify commit, build, instrumentation, pre-fix positive, post-fix negative
not for thesis headline
```

### Size M — main race

```text
trace length: roughly 500–3000 steps
bug sites: 2–6 remu/divu sites
decoys: arithmetic, bitwise, branches, memory reads/writes
purpose: final primary bug-race benchmark
```

This is the best thesis target. It is large enough that the scheduler matters but small enough that the race is interpretable.

### Size L — noisy stress race

```text
trace length: 3000–10000+ steps
bug sites: several remu/divu sites
decoys: many
purpose: appendix / robustness
```

Do not use Size L as the primary race unless Size M is too easy for all variants.

## 3.4 Variant set

Run all four variants:

```text
V5_control
V6_uniform
V6_cTS
Hybrid_cTS
```

Keep this exactly as you proposed. Even if the historical bug was found through during-execution `PRE_EXEC_REG_MOD`, the question “can A4 post-execution mutation expose this class?” is scientifically important. A negative A4 result is not a failure; it clarifies the limits of post-execution single-cell mutation.

## 3.5 Commit choice

`98387806` is plausible **if and only if** it is the last state before the RISC Zero #3181 fix **and** the corresponding constraint-system/Zirgen state is also vulnerable. But I would not trust the hash as a label until a smoke test proves it.

The paper says the RISC Zero bug affected versions **2.0.0, 2.0.1, and 2.0.2**, and that the root cause was a missing constraint distinguishing the first and second operand registers in three-register instructions. 

So define the benchmark commit operationally:

```text
vulnerable_commit:
    deterministic injected remu/divu fault produces OOPS
    proof verifies on pre-fix build
    same candidate fails/rejects after #3181 / Zirgen fix

fixed_commit:
    same guest, same input, same forced fault
    proof does not verify
```

If `98387806` passes that test, use it. If not, adjust to the nearest commit/tag that does. Also verify the Zirgen dependency/submodule state. The paper says fixes were needed in both the main RISC Zero implementation and Zirgen, so a RISC Zero commit hash alone may be insufficient if your checkout pulls a newer constraint-system dependency.

## 3.6 Budget and repetitions

Use a staged race.

### Stage 0 — deterministic harness validation

```text
variants: direct/manual forced fault only, not all fuzzers
seeds: not applicable
budget: tiny
goal:
    pre-fix accepts invalid
    post-fix rejects invalid
```

Do not run the competition before this passes.

### Stage 1 — smoke race

```text
variants: all 4
seeds: 3 paired seeds
budget: N = 2000
guest: Size S + Size M
goal:
    confirm at least V6_uniform or V6_cTS can rediscover bug
```

### Stage 2 — thesis race

```text
variants: all 4
seeds: 10 paired seeds minimum
budget: N = 5000 per variant/seed
stop rule: stop a run immediately after confirmed bug
guest: Size M
```

If many runs are right-censored at N=5000, extend censored runs to N=10000. If the bug is found by all variants in under a few hundred pulls, make the guest noisier rather than declaring victory too early.

### Stage 3 — final if compute allows

```text
seeds: 20 paired seeds
budget: N = 10000
guest: Size M or Size L
```

For a master’s thesis, **10 seeds is acceptable** if compute is tight. **20 seeds is stronger** if you can afford it.

## 3.7 Race metrics

Use bug-finding metrics, not coverage metrics, as the primary race endpoint.

Primary:

```text
find_rate_within_budget
median pulls_to_first_confirmed_bug
median wall_clock_to_first_confirmed_bug
survival curve / Kaplan-Meier curve over pulls
area under discovery curve
```

A run’s success should require:

```text
pre-fix:
    fault applied
    semantic output divergence or trace semantic divergence
    proof/verifier accepts

post-fix:
    same fault no longer accepted
```

Secondary:

```text
applied_pulls_to_bug
bug-relevant target attempts
target-op selection rate: remu/divu selected / total applied
target-field selection rate: rs2-to-rs1 or equivalent / target attempts
proof accepted rate conditional on target fault
noop accepted rate
false-positive count
local/CGC coverage at first bug
```

The most useful decomposition is:

```text
P(find bug)
= P(select bug-relevant instruction)
× P(apply bug-relevant mutation)
× P(output/trace diverges)
× P(proof accepts)
```

That turns a win/loss result into an explanation. For example, V6_uniform might win because it hits the relevant fault uniformly and often; V6_cTS might lose because it over-concentrates on non-target `INSTR_WORD_MOD`; Hybrid might win if it preserves enough Arguzz target attempts while adding A4 exploration.

## 3.8 How to treat A4 success fairly

A4 may not produce an application-level OOPS in the same way Arguzz does. Post-execution mutation can create an invalid witness whose public output remains unchanged. That can still indicate a constraint-system weakness if the proof accepts a trace that violates instruction semantics, but it is less directly comparable to Arguzz’s OOPS oracle.

So report two bug oracles:

### Strong application-level oracle

```text
accepted proof
public/journal output is wrong or OOPS
post-fix rejects
```

This is closest to Arguzz.

### Internal trace-soundness oracle

```text
accepted proof
trace/witness violates intended instruction semantics under a replay checker
post-fix rejects
public output may or may not change
```

This is fairer to A4.

For headline comparison against Arguzz, use the strong oracle. For A4 scientific interpretation, also report the internal trace oracle.

---

# 4. Answer to Q3: what else the results imply

## 4.1 Hybrid is the architecture to carry forward, but not the final scheduler

The current best architecture is Hybrid, but the current scheduler is not yet proven optimal. D2.H says Hybrid is the broadest single explorer: it matches A4 local breadth and inherits most of Arguzz’s global reach. But it also says Hybrid slightly dilutes rare A4 local depth, missing rare exclusive locs that pure V5 hits. 

Therefore, I would not replace V5_control with Hybrid everywhere. I would use:

```text
Primary broad explorer:
    Hybrid_cTS

Companion local-depth explorer:
    V5_control or A4-only cTS

Canonical Arguzz baseline:
    V6_uniform

Scheduler ablation:
    V6_cTS
```

In practical bug hunting, run Hybrid and V5_control in parallel when possible. Hybrid maximizes breadth; V5 preserves A4-only local depth.

## 4.2 V6-cTS needs arm-space simplification before you can judge feedback fairly

V6-cTS did not beat V6_uniform on local territory. That does not necessarily mean feedback is useless. Your own check-in notes V6-cTS ran a very large arm space, and D2.G suggests over-factorization as a likely driver of Case B. The D2.H report also notes that V6_cTS has low allocation entropy and visible `INSTR_WORD_MOD` escalation, i.e. the bandit concentrates. 

I would add one ablation:

```text
V6_cTS_lite
```

Collapse the arm key for Arguzz-only scheduling:

```text
from:
    kind × semantic_zone × opcode_class × pre_post × txn_role-ish dimensions

to:
    kind × coarse_opcode_class
    plus boundary/core zone only where it matters
```

Keep only dimensions that affect applicability or known mechanism. The current V6-cTS result may be a failure of arm geometry, not of feedback.

Do this **after** the known-bug race unless the race itself shows V6_cTS badly underperforms V6_uniform.

## 4.3 Do not prioritize D1.E before the bug race

D1.E is still a valid causal test, but it is not the next critical path. The open seam is that D1.E reward enrichment never ran; the four-variant campaign used the existing coverage-based reward. 

Run D1.E later if:

```text
- the known-bug race shows Hybrid/V5 often reaches relevant regions but does not isolate bugs;
- multi-guest sweep shows reward saturation before useful CGC/bug-proximity signals;
- V5_control remains strategically important as a local-depth companion.
```

Do not spend the next major block on V5-only reward rewiring before the known-bug race.

## 4.4 Keep acceptance out of the reward

Your new triage validates the earlier stance. The check-in says all **2795** accepted proofs across the campaign were filtered, deduped to **1423** trace reruns, and classified with **0 strong / 0 hidden** soundness candidates; the earlier ~3% Arguzz accepted set was explained by no-ops/proof-invisible mutations rather than bugs on this guest. 

So:

```text
accepted proof = triage queue signal
not bandit reward signal
```

This is important for the known-bug race too. Rewarding acceptance would select no-ops. Reward target attempts, coverage, and confirmed semantic divergence instead.

## 4.5 Your thesis claim should be precise

Do not frame the thesis as:

```text
MAB beats Arguzz.
```

That is not what the data says.

A better thesis claim is:

```text
Constraint-space feedback and semantic witness-fault scheduling expose complementary local/global regions of the RISC Zero constraint system. A hybrid A4+Arguzz architecture provides broader attack-surface coverage than either surface alone, and known-bug experiments evaluate whether this coverage translates into faster soundness-bug discovery.
```

This claim is supported by your current data and leaves room for the known-bug race to strengthen the security argument.

---

# 5. Concrete next plan

## Step 1 — Build the known-bug race first

Run:

```text
vulnerable RISC Zero commit: candidate 98387806, but verify by deterministic repro
fixed commit: #3181 / corresponding Zirgen fix state
guest: Size S smoke + Size M contextual product-program
variants: V5_control, V6_uniform, V6_cTS, Hybrid_cTS
seeds: 3 smoke, then 10 thesis
budget: N=2000 smoke, N=5000 thesis, extend censored runs to N=10000
```

Primary output:

```text
Kaplan-Meier time-to-first-confirmed-bug plot
find-rate table
conditional target-attempt decomposition
pre-fix vs post-fix validation table
```

## Step 2 — Run focused multi-guest screening

Run:

```text
guests:
    current CircIL arithmetic/div baseline
    ECALL/control-heavy
    memory-stress + branch/control
    accelerator/Poseidon/BigInt

variants:
    V5_control
    V6_uniform
    V6_cTS
    Hybrid_cTS

budget:
    N=5000, 3 seeds first
```

Then select 2 guests for:

```text
N=10000, 10 seeds
```

Primary output:

```text
per-guest local/CGC curves
per-guest territory tables
cross-guest heatmap
rank stability table
```

## Step 3 — Decide on V6_cTS_lite

If the known-bug race or multi-guest sweep shows V6_cTS underperforming V6_uniform while over-concentrating, implement:

```text
V6_cTS_lite = smaller Arguzz arm space
```

Then rerun only:

```text
V6_uniform
V6_cTS
V6_cTS_lite
Hybrid_cTS
```

on the most diagnostic guest.

## Step 4 — D1.E only after the above

Run D1.E if you still need to improve A4 local-depth scheduling or if Hybrid misses rare A4-only regions on multiple guests.

---

# 6. Final answers to your two main design choices

## Multi-guest: one big guest or multiple?

Use **multiple focused guests** for the thesis. Add one mega-guest only as an appendix stress test.

The focused suite gives interpretable evidence. The mega-guest gives robustness evidence but weak causal explanation.

## Known-bug race: guest and budget?

Use a **bug-targeting product-program guest**, not just a bare one-line remu program. The normal execution should have `rs1 != rs2`; the malicious fault should change `rs2` to `rs1`. Use inline asm to force `remu/divu`, prevent optimization, and compare against a reference function. Run all four variants. Use 10 paired seeds at N=5000, stop on first confirmed bug, and extend censored runs to N=10000. Include pre-fix and post-fix validation.

---

# 7. Bottom line

Your current results are good news, but they change the story.

The strongest architecture is **not pure A4** and not clearly **V6-cTS over Arguzz**. It is:

```text
Hybrid_cTS for breadth
+
V5_control as an A4 local-depth companion
+
V6_uniform as the canonical Arguzz baseline
+
known-bug race to test whether coverage predicts soundness discovery
```

The immediate priority is the **known-bug race**, because it directly tests the thesis’s security value. The second priority is the **focused multi-guest sweep**, because it tests whether the local/global complementarity is a stable architectural property or a `sha2-host` artifact.
