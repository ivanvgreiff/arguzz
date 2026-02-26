```Prompt
I am splitting this prompt into the following sections: 1) Main Prompt, 2) Discussions with other cryptography engineers at zkSecurity, and 3) Example outputs from current fuzzing logic.


# Main Prompt

I am working on a project where I have developed a fuzzing framework to find bugs in zero knowledge virtual machines, specifically RISC Zero. This fuzzing framework mutates different elements in a post-execution trace (i.e. a trace which is formed after the guest program was executed in the zkVM). I mutate things like e.g. at a specific position in the post-execution trace which corresponds to a specific instruction step, I mutate e.g. an instruction word like ADD to MUL, the value that gets written to a destination register, a value that is written to memory, etc. Then the zkVM continues processing this intermediate post-execution trace to generate a proof and if this proof gets accepted as a valid proof by the verifier, then this indicates a potential soundness bug in RISC Zero. 

Something I am exploring is how to use coverage to guide mutations to more efficiently find underconstraints within RISC Zero. The notion of "coverage" that I am using is not traditional and relies upon the zirgen constraint failures that occur during witness generation and proving and are reported back when a single mutation is executon on the post-execution trace and the zkVM processes that mutated post-execution trace to generate the proof. 

Currently my fuzzing framework uses python to hook into the zkVM and insert code in the zkVM's Rust source code to return all constraint failures that occur during a single run (note that in a campaign, I take a single guest program always with the same inputs and run it over and over only executing a single mutation type per run). My fuzzing framework ensures that the zkVM skips errors that arise so that I can collect all the different zirgen constraint failures that occur for a single mutation. I am thinking about now figuring out how to view these constraint failures from the perspective of coverage so I can incrementally execute mutations that are more likely to hit as many different constraints as possible.

I will share with you some notes that I took when meeting with my bosses (I work as a cryptography engineer at zkSecurity, these notes will be in Section 2: Discussions with other cryptography engineers at zkSecurity) that offer some more insight into what we are trying to accomplish. I want you to think critically about my notes and offer feedback and potential insights that are important to consider, as well as any meaningful information and guidance that would help me in accomplishing this goal. My goal is to 1) Figure out how to develop the best/optimal idea (conceptual) of constraint-failure-coverage, 2) Implement this constraint-failure-guided-coverage into my fuzzing framework.

I then want to provide your long and detailed report with your critical thoughts and recommendations to Claude Opus who has access to my repo where my fuzzing framework exists. Opus can read through source code and figure out the feasibility of implementing this improved constraint-guided-coverage concept. Remember, I already have access to detailed constraint failures induced by any mutation I execute on the post-execution trace (including granular information such as which specific zirgen constraint was violated), but there are something left to figure out and develop. This is where you can help me. What I think are some initial steps for me to do are:

1. Figure out how to hook into RISC Zero and know which constraints were tested (not necessarily violated) by a single mutated post-execution trace during the witness generation and proving phase of the zkVM.
2. Develop a conceptual framework for how to use "constraint failure information" and "constraint touched information" to create some kind of "map of coverage"
3. Figure out how to utilize this "map of coverage" in order to guide mutations within my fuzzing logic to better find more and more constraints, touch them, and see if they fail, so that hopefully we can uncover underconstraints in RISC Zero.

Overall, we want to 'maximize coverage' in our zkVM fuzzing campaings using some intellectual, academic, and rigoruous notion of constraint-coverage, and I need help in developing this concept (first on a conceptual level, that is what I want you to focus on) so that I can think about it, work on it, and develop it conceptually more before implementing it and testing it one day into my zkVM fuzzing logic.


# Discussions with other cryptography engineers at zkSecurity 

- Lets take a high level example: if you take an image and fuzz with totally random bytes, it will be garbage and you will have no progress in finding bugs
- In coverage based fuzzing, you start with a seed and see which branches it takes, and you create a report every time of what has been covered. You try incremental random stuff over and over and over time, the random stuff you try may lead incrementally to cover a bit more (went in some branches)
	- Then you say, okay this is a nice seed, let me go an mutate this seed to make more progress, and that is how eventually you may be able to generate images that completely pass when they should not pass, which is how (as an example in very high level) AFL works
- Going back to our fuzzing approach for zkVMs, we are thinking about a different kind of coverage and it is not straightforward what coverage means here and how we can leverage it
	- One intuition is that probably there are some constraints that are rather deep to hit, so if we introduce random errors it might be hard to each them. 
	- Thus it might be worth trying to figure out if there is any way to check WHICH constraints were checked (not just which constraints failed) based on some mutation we did and the initial seed
	- Obviously a constraint that failed was definitely hit, but a constraint that did not fail was it hit or not? 
	- How can we have a coverage metric similar to AFL (obviously AFL does not fully apply here), but if there is any way we can guide our mutation generation based on a report we generate when we run a mutant, that would be nice, but it is not clear how to do that
- Maybe another intuition here and another way to define this metric, would be to find some file e.g. `verifier.rs` where we can measure with some pre-existing tool which lines were exercised e.g. line coverage would be one way
	- One could have a big discussion as to whether line coverage is good or not
	- If there is a file where all the constraints are checked ==!== then there would be a branch for if it was respected and if it was not respected, so we would have both cases
	- But then, if there are some lines that are never reached (i.e. some constraints that are never exercised at all), or maybe we are always hitting one branch but not the other, then we could measure that
	- One question is what is that (set of) file(s) or functions that we want to cover and how easy would it be to measure these lines coverages
		- Rust may have some toolset to measure whether a set of unit tests has a certain line coverage e.g. Martin once used in one security audit one call (I think called llmcough or something) where you get a nice html out of a set of test cases, function by function or file by file what percentage of the lines/files were covered (and they had a couple different metrics not only line coverage but also others)
		- There should be some tooling for that, but it might not be trivial to hook it into our RISC Zero fuzzing infrastructure because the tooling is designed for classic unit tests in Rust
	- Overall there is some preexisting tooling that allows us to measure something standard like line coverage which can give us an idea of how much progress we are making when adding new test cases because we can just compare if the line coverage is increasing or not
		- What is not trivial would be how we increase it... How do we target these lines not being covered? Randomly we may never hit them unless we introduce the right mutations which could be manual work to try to hit that
- To reiterate, one question is if there is one place with a list of constraints that is like one big switch that we can just check, or it is distributed across many files, this can determine how difficult they are to track and if they are triggered or not
	- If there is a place that seems central where a family of constraints is handled and we can somehow map the constraints we are seeing violated against that list then we have some notion of coverage $\rightarrow$ might be a manual check
	- We need to see if we can leverage preexisting tooling that could be useful, but it could also be something ad-hoc where we identify a list of constraints and see if hit them all


# Example outputs from current fuzzing logic

## Examples of terminal output per-mutation

  [1] ✓ INSTR_WORD_MOD_SUR @ step 3923: 1 failures, 32126ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x01059593 -> 0xE8559593
       Surgical: imm = 16 -> 3717
       Original: SLLI x11, x11, 16
       Mutated:  SLLI x11, x11, -379
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20873: preflight=0x3fffc010, actual=0x3fffc005
         • [kernels/cxx/ffi.cpp:121] SKIP THROW: memory peek not in preflight
       Constraints hit (1 unique):
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=20873, step=3923, pc=0xC00000E4, major=3, minor=1


  [2] ✓ COMP_OUT_MOD @ step 608: 2 failures, 29332ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000004 -> 0x20000000
       Destination: rd = x16 (a6)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17217, step=608, pc=0x00206178, major=0, minor=0
         - MemoryWrite@mem.zir:99
           cycle=17217, step=608, pc=0x00206178, major=0, minor=0

...

  [5] ✓ MEM_VAL_MOD @ step 2919: 28 failures, 36312ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+28 new]
       Value: 0x00008067 -> 0xFFFF7F98
       Transaction: other_mem_read (READ) at address 0x00205e3c
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19647: preflight=0x3fffc021, actual=0x3fffc03e
         • [kernels/cxx/ffi.cpp:121] SKIP THROW: memory peek not in preflight
       Constraints hit (6 unique):
         - DecodeInst@inst.zir:29 (x21)
           cycle=19648, step=2920, pc=0x002053A4, major=0, minor=7
         - IsRead@mem.zir:79
           cycle=19647, step=2919, pc=0x002053A0, major=2, minor=4
         - IsRead@mem.zir:80
           cycle=19647, step=2919, pc=0x002053A0, major=2, minor=4
         - MemoryWrite@mem.zir:99 (x3)
           cycle=19664, step=2936, pc=0x00205450, major=2, minor=3
         - VerifyOpcodeF3@inst.zir:96
           cycle=19647, step=2919, pc=0x002053A0, major=2, minor=4
         - VerifyOpcodeF3@inst.zir:97
           cycle=19647, step=2919, pc=0x002053A0, major=2, minor=4

## Example of terminal output of campaign summary

============================================================
Campaign Summary
============================================================
Total mutations:     1000
Successful (caused failures): 992
Skipped (no valid target):    0
Total failures:      2766
Unique constraints:  36
New coverage:        2766
Execution time:      14876560ms

Outcome breakdown:
  REJECTED (mutation detected): 992
  CRASH (segfault, etc.):       8
  NO_EFFECT:                    0
  ACCEPTED (BUG!):              0
  SKIPPED:                      0

Mutations by kind:
  COMP_OUT_MOD: 132
  INSTR_TYPE_MOD: 120
  INSTR_WORD_MOD_FULL: 130
  INSTR_WORD_MOD_SUR: 115
  LOAD_VAL_MOD: 119
  MEM_VAL_MOD: 124
  PRE_EXEC_REG_MOD: 122
  STORE_OUT_MOD: 138
```


---

Below is a “handoff memo” you can paste directly to Claude Opus. I’m going to be very explicit about (a) what _constraint coverage_ can mean in a zkVM/AIR/zirgen setting, (b) which notions are actually useful for guiding mutations, and (c) what I think are the highest‑leverage instrumentation points and heuristics—given your current capability: **you already extract granular constraint failures (name + `.zir` location + cycle/step/pc/major/minor)**.

---

## Memo to Claude Opus: Constraint-(Failure)-Coverage for RISC Zero trace-mutation fuzzing

### Context recap (what we have today)

We have a fuzzing framework that:
- Executes a fixed guest program (same inputs) to obtain a _post-execution trace/witness-like artifact_.
- Mutates one element per run (instruction word/type, register write, memory value, etc.).
- Forces RISC Zero to continue witness generation/proving even after errors to collect **all** constraint failures observed in that run.
- Treats “proof accepted after mutation” as a **potential soundness bug** (underconstraint).

We currently log (per run):
- Mutation spec (kind, step, value change, decoded original/mutated instruction).
- zkVM internal errors (C++/Rust).
- **Constraint failures** with identifiers like `VerifyOpcodeF3@inst.zir:96` plus `cycle/step/pc/major/minor` and sometimes lane info like `(x21)`.

Goal:
1. Define a rigorous notion of **constraint coverage** that is useful for guiding search (AFL-like in spirit).
2. Implement **coverage-guided selection** of future mutations using that notion.

---

## 1) Critical observation: “constraints are always checked” is _true but not useful_

In AIR/STARK systems, validity is “the trace satisfies a set of polynomial constraints.” RISC Zero’s own documentation frames it this way: a trace is a grid of field elements and the trace is valid iff each constraint evaluates to 0.

However:
- In many zkVM/AIR designs (and in zirgen-generated circuits), _most constraints are gated_ by control/selector columns. So while the prover might “evaluate” the full validity polynomial everywhere, **many constraints are effectively inactive** in rows where their selector is 0.
- Also, RISC Zero’s RV32IM v2 uses a **major/minor dispatch** that selects which instruction-type component runs (ALU/misc vs mul vs div vs loads/stores vs ecall). DeepWiki summarizes this dispatch and the major mapping explicitly (0–2 misc/ALU, 3 mul, 4 div, 5 load, 6 store, 7 ecall). ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1-risc-v-circuits "RISC-V Circuits | risc0/zirgen | DeepWiki"))

So: a meaningful “touched” notion should correspond to **constraint families that were active (selector=1 / component executed)**, not merely “present in the circuit.”

---

## 2) Definitions: build a _3-level_ coverage model (family → context → instance)

### 2.1 Constraint family ID

This is basically what you already log:

- `ConstraintFamily := (constraint_name, zir_file, zir_line)`  
    Example: `MemoryWrite@mem.zir:99`, `DecodeInst@inst.zir:29`, `VerifyOpcodeF3@inst.zir:96`.

Family coverage answers: “Have we ever exercised/broken this family anywhere?”

### 2.2 Constraint context ID (the key upgrade)

A _family_ can be activated under different “semantic modes” (instruction-type, phase, lanes). Your logs already include excellent contextual keys: 

- `major/minor` (instruction dispatch state)
- sometimes `lane` like `(x21)` or `(x3)`
- the execution location `pc` / `step` / `cycle` 

Define a context key that is stable and informative, for example:

- `ConstraintContext := (ConstraintFamily, major, minor)`  
    Optionally refine:
- `ConstraintContext := (ConstraintFamily, major, minor, lane_kind, lane_idx_bucket)`
    or
- `ConstraintContext := (ConstraintFamily, major, minor, pc_bucket)`.

Why this matters:
- Pure family coverage will saturate quickly (you saw only 36 unique families in 1000 muts).
- Context coverage is closer to AFL’s “edge coverage”: it distinguishes **the same constraint family** when it is reached via different decode/control regimes (which in zkVMs is often where underconstraints hide).

Concrete anchor: the RV32IM circuit’s dispatch is major/minor-based ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1-risc-v-circuits "RISC-V Circuits | risc0/zirgen | DeepWiki")), and the core pipeline begins with `DecodeInst` and uses structured components for source reg read and destination write plus mem transaction handling ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1-risc-v-circuits "RISC-V Circuits | risc0/zirgen | DeepWiki")). So `(family, major/minor)` is a principled “path-sensitive” coverage axis.

### 2.3 Constraint instance ID (optional, but very powerful for guiding _where_ to mutate)

Instance is “the family/context at a particular locus.” For example:

- `ConstraintInstance := (ConstraintContext, step_bucket)`  
    where `step_bucket = step // B` for some B (e.g., 16, 32, 64).  
    Or:
- `(ConstraintContext, pc_bucket)`.

This is how you convert coverage into “where should I mutate next?”:

- If you’ve never seen `VerifyOpcodeF3` under `major=4` (div) in step region `[3000..3200]`, you can bias mutations toward steps whose instruction decode can be perturbed into that major.

Instance coverage can explode, so you likely want _bucketing_ + hashing (AFL bitmap style), not a giant exact map.

---

## 3) Two notions of coverage: “violated” vs “touched (active)”

### 3.1 Violated coverage (you already have)

- `ViolCov(run) = set of ConstraintContext (or Family) that produced at least one failure`

This is useful and cheap. But it’s biased: you only “see” constraints when you break them.

### 3.2 Touched/active coverage (the missing piece)

We want:

- `TouchCov(run) = set of ConstraintContext (or Family) that were *active* during this run`

Interpretation: “constraints whose selector was 1 / whose component branch executed / whose check was nontrivial.”

This is what your internal discussions are circling: a non-failing constraint might have been active and satisfied, or might never have been activated at all.

Important nuance: in zkVM circuits, “checked” can mean different things:
- **Evaluated but gated off** (selector=0) → should _not_ count as meaningful touch.
- **Evaluated with selector=1** → meaningful touch.
- **Violated** → definitely touched.

So the best conceptual rule is:

> A constraint is “touched” in a run if it is evaluated in a row where its _applicability predicate_ (selector) is non-zero.

This is the closest analog to “branch taken” coverage.

---

## 4) How to get “touched constraints” in zirgen/RISC Zero without drowning in data

You want to avoid “log every constraint evaluation at every row”—that’s huge.

### 4.1 Best conceptual instrumentation point: at constraint-check sites _after gating is resolved_

In many generated circuit kernels, constraints end up as something like:

- compute residual `r = expr(witness_cols, taps, ... )`
- enforce `r == 0` (or accumulate into validity poly)
- on debug/diagnostic build, failures are reported with metadata (file:line/name)

You already intercept the failure reporting path. Extend this same mechanism with a lightweight “coverage mark”:

- On _every_ constraint check, if its gating predicate indicates applicability (or if it is inside a branch that is only executed when applicable), set a bit in a coverage bitmap keyed by `(ConstraintContext)`.

Even if you can’t cleanly extract the selector value, there’s a pragmatic proxy:

**Proxy A: “branch-level touch” via major/minor dispatch**  
RISC Zero RV32IM v2 has a major/minor dispatch across instruction-type components ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1-risc-v-circuits "RISC-V Circuits | risc0/zirgen | DeepWiki")). If the codegen literally branches on major, then _constraints in non-selected components are never executed._ In that case, marking “touched constraint families” can be achieved by:

- instrumenting at component entry points (e.g., Misc/Mul/Div/Mem/ECall paths), or
- marking constraints whenever the checker function for that component runs.

This is coarser than selector-perfect marking, but likely good enough to guide fuzzing.

**Proxy B: “nontrivial residual” heuristic**  
If you can compute both:

- `r_raw = expr_without_selector`
- `sel = selector`  
    and the enforced residual is `sel * r_raw`, then treat touched if `sel != 0`.  
    If you can’t separate them, but you can detect whether the expression structurally depends on selector columns, you can approximate. This is harder; use it only if it’s already cheap in zirgen runtime.

### 4.2 Data structure: AFL-like bitmap with saturating counters

Do **not** emit massive sets back to Python per run. Instead:

- Maintain a fixed-size bitmap `cov_touch[MAP_SIZE]` in Rust/C++ (or wherever the constraint checks run).
- For each touched constraint context, compute `idx = hash(context_id) % MAP_SIZE` and increment a saturating 8-bit counter.
- Similarly maintain `cov_fail[MAP_SIZE]` (or reuse the same map with different hashes/prefixes).

Then return the bitmap(s) to Python per run as bytes. This matches how coverage-guided fuzzers scale.

### 4.3 Stable IDs: keep them deterministic across builds

A subtle pitfall: if `context_id` depends on pointer addresses or unstable ordering, you’ll get coverage noise.

Best stable ID components:
- constraint debug name + `.zir` file + line
- major/minor
- lane info (if any)
- optional coarse bucket of `pc` or `step`

Hash those stable strings/integers.

---

## 5) Using constraint coverage to guide mutations: don’t just “maximize failures”

Maximizing “number of failed constraints” is usually _anti_-helpful: it pushes you toward catastrophic divergence (decode breaks, memory address mismatch cascades) that yields lots of failures but little structured exploration.

Instead, your objective should be:

### 5.1 Primary objective: maximize _novel touched contexts_

Reward a run for producing new `TouchCov` bits, not for producing many failures.

This is the nearest analog to AFL “new edge coverage”.

### 5.2 Secondary objective: maximize _novel violated contexts_ (but with downweighting)

Failure coverage is useful for discovering constraints you can “hit” by perturbations, but it tends to rediscover the same few “fragile” checks. Add it as a weaker signal:

- `reward = α * new_touch + β * new_fail_weighted`

Where `new_fail_weighted` downweights common, low-value failures (like ubiquitous memory-preflight mismatch).

### 5.3 “Rarity weighting” (important)

Maintain global frequency `freq[context]`. Reward new hits more when they are rare:

- `rarity_reward(context) = 1 / sqrt(1 + freq[context])`  
    This prevents you from getting stuck repeatedly triggering the same memory constraint.

### 5.4 Add a “coherence” term so you don’t chase garbage

Because you “skip errors” and continue, many later failures may occur after the trace has diverged into nonsense. That can inflate coverage.

Heuristic: define a coherence score from internal errors:

- if run hits “internal proof verification failed” immediately, or memory preflight mismatch early, treat later coverage as lower signal.
- Or cap “effective” touched/failure marking after the first catastrophic divergence marker.

This is basically the zkVM analog of “don’t reward timeouts/crashes as coverage” unless you explicitly want them.

---

## 6) Mutation guidance: use coverage to choose _where_ and _how_ to mutate

You have multiple mutation kinds (`INSTR_WORD_MOD_SUR`, `MEM_VAL_MOD`, etc.). Treat each as an “arm,” and treat (step region, mutator kind) as a finer-grained arm.

### 6.1 Multi-armed bandit over mutation kinds

For each mutation operator:
- track average reward (new coverage) over time,
- allocate more budget to operators with higher reward using UCB1/Thompson sampling.

This is simple and often yields big gains vs uniform sampling.

### 6.2 Locality heuristics over step/pc

Maintain a heatmap:

- `score[pc_bucket]` = cumulative reward from mutations in that region
- `score[step_bucket]` similarly

Then bias selection toward buckets with recent novelty.

This is the constraint-world analog of “mutate near interesting bytes.”

### 6.3 Major/minor targeting (very high leverage)

DeepWiki’s RISC-V circuit summary gives a concrete major mapping (0–2 ALU/misc, 3 mul, 4 div, 5 load, 6 store, 7 ecall). ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1-risc-v-circuits "RISC-V Circuits | risc0/zirgen | DeepWiki"))

So you can define a campaign-level target:
- **Expand major coverage first**, then refine within a major.

Practical strategy:
1. Track which `(major, minor)` pairs you have seen in touched coverage.
2. Prefer instruction-word mutations that are likely to flip an instruction into an uncovered major.

This requires an _oracle_ to map an instruction word to major/minor. You likely already decode to assembly; extend that to compute the circuit’s major/minor class (or approximate via RISC-V opcode class).

Even if many such mutations fail, they will activate different instruction-type components and thus touch new constraints.

### 6.4 Lane-special-case targeting (where underconstraints often live)

Historical underconstraints often occur in “rare equality cases” (e.g., `rs1 == rs2`, aliasing, same-address hazards). A real RISC Zero underconstraint vulnerability (CVE-2025-52484) was exactly about a missing constraint for 3-register instructions when source registers coincide, allowing confusion between rs1 and rs2. ([GitHub](https://github.com/advisories/GHSA-g3qg-6746-3mg9 "zkVM Underconstrained Vulnerability · CVE-2025-52484 · GitHub Advisory Database · GitHub"))

You should explicitly model these “degenerate” cases as a coverage dimension:
- add a flag feature like `rs1_eq_rs2`, `rd_eq_rs1`, etc (derived from decoded instruction fields),
- incorporate it into `ConstraintContext` hashing.

Then guide mutations to produce and explore these degenerate cases, because they are disproportionately likely to reveal missing constraints.

(Do **not** interpret this as “reproduce the CVE”; the point is: data-dependent corner cases are where constraint gaps hide.)

---

## 7) Big conceptual pitfall: single-point mutations may never reach “deep” constraints

AFL works because it can build structured inputs that _still pass many checks_ and reach deeper branches. In your current setup, a single random mutation often causes early incoherence and cascades.

So coverage guidance alone might plateau unless you add **structure-preserving mutators**.

### 7.1 Add “repair-aware” or “coherence-preserving” mutators

Use the failure set as a diagnostic to propose minimal correlated edits that restore consistency.

Example pattern (conceptual):

- You mutate instruction word `ADD → MUL`, but decode/opcode constraints fail because the derived fields don’t match.
- A repair-aware mutator could also update the decoded fields / result reg write to match the new opcode semantics (still leaving some degree of freedom to test underconstraints).

Yes, this is multi-site mutation—still within “one logical mutation operator,” but it edits multiple trace elements consistently.

This is extremely important if your ultimate goal is _accepted proofs with wrong semantics_, i.e., underconstraint exploitation. Randomly breaking constraints mostly finds overconstraints/consistency checks; underconstraints are found by staying inside the constraint manifold while deviating semantically.

### 7.2 Think of your search as two regimes

- **Exploration regime**: maximize touched-context coverage (learn the constraint surface).
- **Exploitation regime**: minimize constraint violations while changing semantics (search for degrees of freedom).

A good architecture supports both:
- coverage-guided exploration to discover new components/constraints,
- then “constraint-satisfaction-guided” search near promising regions.

---

## 8) Rust line coverage: useful as a _sanity check_, not a primary metric

Your team’s idea about measuring line coverage (e.g., in `verifier.rs` or other files) is reasonable as a generic progress metric. In Rust, `cargo llvm-cov` (wrapper around `rustc -C instrument-coverage`) can produce line/branch coverage reports, including HTML. ([GitHub](https://github.com/taiki-e/cargo-llvm-cov?utm_source=chatgpt.com "GitHub - taiki-e/cargo-llvm-cov: Cargo subcommand to easily use LLVM ..."))

But be careful:

- Most proving/verifying code is executed regardless of which constraints are active; line coverage can saturate quickly and won’t distinguish subtle constraint activation.
- Generated kernels may be C++/CUDA; Rust coverage won’t see them.
- Line coverage does not naturally give a direct gradient for “which mutation should I do next.”

Recommendation: treat line/branch coverage as:

- a macro sanity metric (“are we exercising div/mul paths?”),
- not the core feedback signal.

---

## 9) Concrete implementation plan (high-level, Opus-friendly)

### Step 0: Establish baseline (unmutated) touch coverage

Run the prover on the unmutated trace with coverage instrumentation enabled:

- record `TouchCov_base` and `FailCov_base` (should be empty failures).  
    This baseline tells you which constraints/components the seed program naturally exercises.
    

### Step 1: Add “touch coverage” instrumentation

In the constraint checking loop (or component dispatch), implement:

- `mark_touched(constraint_family_id, major, minor, lane?, pc_bucket?, step_bucket?)`  
    Update bitmap counters.
    

### Step 2: Keep “failure coverage” as a second bitmap

Every time a failure is recorded, also:

- `mark_failed(context_id)`  
    This allows you to keep your current “unique constraints” metric, but make it AFL-like and fast.
    

### Step 3: Python side: corpus and scheduling

Maintain:

- `global_touch_bitmap`, `global_fail_bitmap`
    
- `corpus`: set of mutation specs that produced new bits
    
- `freq` maps (optional; can be approximated from counters)
    

Selection:

- Choose mutation spec from corpus with a power schedule favoring rare/novel contexts.
    
- Choose mutator kind via bandit/UCB.
    
- Choose step bucket biased by heatmap scores.
    
- Generate mutation parameters (value changes) with deterministic stage + random stage.
    

### Step 4: Reporting/visualization

Produce:

- coverage growth over time (touch + fail bit counts)
    
- per-mutator yield (new bits per run)
    
- top uncovered major/minor pairs
    
- top rare constraint contexts
    

---

## 10) Why this is “academically defensible”

RISC Zero’s own proof-system description emphasizes:

- the trace is a rectangular array (rows=cycles, cols=state), and
    
- constraints enforce computational integrity and must all evaluate to 0 for validity.
    

RISC Zero’s RV32IM v2 implementation (as summarized from the public zirgen repository indexing) uses:

- structured instruction decoding (`DecodeInst`) ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1.1-rv32im-core "RV32IM Core | risc0/zirgen | DeepWiki"))
    
- memory transaction components (`MemoryRead/Write`, `MemoryArg`, `MemoryIO`) ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1.1-rv32im-core "RV32IM Core | risc0/zirgen | DeepWiki"))
    
- a major/minor dispatch across instruction-type components ([DeepWiki](https://deepwiki.com/risc0/zirgen/4.1-risc-v-circuits "RISC-V Circuits | risc0/zirgen | DeepWiki"))
    

Therefore, defining coverage over:

- constraint families (syntactic constraints),
    
- contexts (dispatch regimes: major/minor and lanes),
    
- and instances (execution loci: pc/step buckets)
    

is a principled analog of AFL edge coverage, specialized to an AIR/constraint setting.

---

## 11) Extra: tie-in to real underconstraints (motivation)

Underconstraints are not hypothetical: RISC Zero has had public underconstrained-circuit vulnerabilities, including one rooted in a missing constraint for a rare register-aliasing case in 3-register instructions (CVE-2025-52484). ([GitHub](https://github.com/advisories/GHSA-g3qg-6746-3mg9 "zkVM Underconstrained Vulnerability · CVE-2025-52484 · GitHub Advisory Database · GitHub"))  
Security audits (e.g., Veridise) have also emphasized that underconstrained bugs are hard to catch with traditional testing and have used specialized tools plus fuzzing to find them. ([Smart contract audits from Veridise](https://veridise.com/wp-content/uploads/2025/04/VAR-Risc0-241028-Round2-V4.pdf "Veridise Auditing Report"))

That’s precisely why “coverage” in zkVM fuzzing should be _constraint-context aware_ and should explicitly encode corner-case regimes (aliasing, special states), not just “did we see this `.zir` line fail once.”

---

# Bottom line recommendation

If you want one “optimal” conceptual definition to implement first:

> **Constraint-context touched coverage** = set of `(ConstraintFamily, major, minor, optional_lane_bucket)` that were _active_ in a run, represented as an AFL-style bitmap; “violated coverage” is the analogous subset when residual ≠ 0.

Then use AFL-like corpus logic + rarity weighting + bandit scheduling to choose future mutations.

---

If you paste only one thing to Opus, paste sections **2–6** and **9**, since that’s where the actionable conceptual model + implementation blueprint lives.