I went through your notes against the whitepaper you attached, the current official proof-system docs, and the current public source layout. The first caveat is version drift: your notes are clearly about the older C++ / `rv32im-sys` pipeline, while current public mainline exposes Rust `rv32im/src/{execute,prove,verify}` plus generated `zirgen` modules, and older public issues still reference `rv32im-sys/cxx/step_exec.cpp`. So I can validate the architectural picture, but I cannot independently bless branch-specific counts like `1757`, `155`, `119`, or exact file paths without your exact commit. 

## Bottom line

I do **not** think you should abandon global signals. I **do** think you should stop aiming, at least initially, for “global hooks with the same per-constraint/source-location granularity as local `EQZ` hooks.” The protocol and the proof code are built around a **batched validity polynomial**, not a first-class API of individually named global constraints. In the whitepaper, the prover constructs `fvalidity(x) = Σ α_i C_i(...) / Z(x)`, and verification explicitly recomputes `fvalidity(z)` and rejects on mismatch before continuing with FRI. In current public code, the outer verifier interface sees `circuit.poly_ext(...).tot`, i.e. a mixed total, and the prover generates a combined `check_poly`. That is exactly the wrong layer if you want source-level provenance.

So my answer to your main question is:

**Useful global diagnostics are feasible without a total overhaul.
Local-parity global diagnostics are probably not feasible at your current hook points without codegen-level instrumentation.**

## What I think you are getting right

Your separation between the ordinary execution trace and the accumulator / auxiliary machinery is directionally right. RISC Zero’s own whitepaper says the accumulator columns are created during randomized preprocessing and are used for a PLONK-style permutation check and a PLOOKUP-style range check; the official proof-system docs likewise describe the auxiliary / accum columns as the place where permutation and lookup support live.

Your instinct that “global” is not naturally exposed in the same way as local rule checks is also right. The public protocol description frames everything as rule-checking polynomials over taps, enforced over the whole trace domain, then compressed into a combined validity polynomial. That is a strong hint that there may be no clean verifier-facing notion of “global constraint #Y failed because `a != b`” unless you instrument **before** batching and mixing.

Your idea that a **cheap binary global signal** would still be valuable for the bandit is right. Even if it is not as rich as local source-location failures, a signal like “accumulator residue is nonzero” or “combined check polynomial becomes nonzero only after finalization” is exactly the sort of information that can distinguish boring local breakage from potentially interesting cross-row inconsistencies. The whitepaper also makes clear that this accumulator machinery is driven by verifier randomness and has explicit Schwartz-Zippel soundness bounds, so it is legitimate to think of it as a probabilistic detector rather than a semantic debugger.

## What I think is incorrect or too strong

The strongest overclaim in your write-up is the idea that the permutation / lookup failure is enforced **only** as a “degree issue in FRI.” The official protocol does not say that. Verification includes a direct check that recomputed `fvalidity(z)` matches the purported value on the seal, and current public verifier code similarly reconstructs a `check` value and returns `InvalidProof` if it differs from the circuit’s mixed validity result. FRI is absolutely part of the soundness story, but it is not accurate to describe the failure mechanism as “FRI only.”

I would also downgrade your claim that “permutation and lookup are the only global mechanisms.” That is true for the 2023 whitepaper’s accumulator discussion, but the current official proof-system docs explicitly say the auxiliary trace also supports a bigint accelerator circuit. So that statement is version-specific, not a safe universal fact.

H1 needs a narrower statement. “Final accumulator total nonzero” is a very good diagnostic, but it is not a perfect oracle. The protocol uses verifier randomness in accumulator construction, and the whitepaper gives explicit Schwartz-Zippel soundness bounds for these grand-product arguments. So the right formulation is: **nonzero residue is strong positive evidence of inconsistency; zero residue is only an inconclusive negative.**

The biggest unresolved point is H2. I would not treat “`poly_fp` at cycle rows adds nothing new” as corrected understanding yet. Too much of your downstream plan depends on it. Until you instrument the combined check computation on finalized columns, H2 is still the pivot question, not a settled result.

I would also drop the expectation that you will get a natural diagnostic like “global constraint Y failed because values `a` and `b` mismatched.” Once constraints have been batched into the mixed validity polynomial, that semantic identity is gone. The natural objects at that layer are mixed field elements, residual totals, and maybe row / family provenance if you add it yourself.

## My actual recommendation

Do **not** move to a local-only bandit.

Do move to a **local-primary, global-coarse** bandit:

1. keep local touches / triggers as the main high-resolution signal;
2. add a cheap binary or family-level global residue signal now;
3. only chase source-level global provenance later, if the coarse signal actually produces valuable global-only hits.

That gets you the upside of global reasoning without stalling on an architectural moonshot.

## Revised master plan

I would reorder your plan pretty aggressively.

### Phase 0: Version-lock the target

Before any more theory work, pin the exact branch / commit and generated artifacts you are actually using. Right now your reasoning mixes older C++ witness-generation concepts with current public docs and code that have clearly drifted. Until the target is pinned, treat every exact numeric claim as branch-local.

### Phase 1: Kill or confirm H2 first

This should be the first real investigation, not Investigation A.

The current public prover has a `circuit_debug` path that scans the computed `check_poly` for nonzero entries and logs the first bad evaluation point. That is not per-constraint labeling, but it is exactly the kind of signal you need to decide whether the finalized validity check is already nonzero on actual cycle-domain points or only elsewhere. In other words, it answers the operational question behind H2.

What I would do on your branch:

* instrument the combined check computation on finalized columns;
* log whether it is nonzero on actual cycle rows;
* separately log a small sample of off-cycle extended-domain points.

Then interpret the results like this:

* **nonzero at cycle rows**: H2 is false, and hooking the finalized validity path is useful;
* **zero at cycle rows, nonzero off-cycle**: H2 is at least directionally right, and your best cheap signal is not per-row but aggregate / residue-based;
* **zero in both places until verifier mismatch**: you are missing a layer in your reconstruction and need to inspect DEEP / quotient handling, not just FRI.

That one experiment determines whether global hook work is worth pursuing inside `poly_fp` / `eval_check`.

### Phase 2: Implement a cheap global residue signal immediately

Independently of H2, implement the cheapest useful signal:

* final accumulator residue after the aux-trace finalization you already understand; or
* a shadow recomputation of that residue outside the verifier path.

Treat this as a **binary trigger**, not as a full explanation. Reward it, but make “zero residue” mean “nothing detected,” not “globally clean.”

### Phase 3: Build a shadow accumulator replay

This is the step I think you are currently missing.

Instead of trying to “hook global constraints” at the verifier layer, build a **shadow diagnostic replay** of the accumulator contributions using the same sampled randomness. For each argument family that exists in *your branch*—whether that is `memory / U16 / U8 / cycle`, or just coarser `memory / bytes` style buckets—compute:

* per-family final residue,
* the set of rows that contributed nonzero deltas,
* ideally the specific transaction tuples that stopped canceling.

This gets you most of the bandit value you actually care about:

* per-family global triggers,
* some notion of rarity / novelty,
* provenance in terms of rows / transactions,
* and a way to detect “global-only” mutants.

Crucially, this does **not** require extracting semantic labels from the mixed validity polynomial.

### Phase 4: Search for true global-only mutations

Your current mutation classes sound heavily biased toward value corruption, which will often trip local constraints first. To test whether global signals are worth the engineering cost, you need mutation families that try to preserve row-local semantics while breaking multiset / ordering / lookup consistency.

I would explicitly add mutation operators aimed at:

* reordering or swapping transaction-like records,
* duplicating / deleting a transaction-like contribution,
* perturbing count / index / cycle metadata rather than the raw data word,
* breaking consistency between “original order” and “sorted / lookup” views, if your branch exposes that.

Then measure the bucket that matters:

`verify fails && local_trigger_count == 0 && global_residue != 0`

If that bucket never appears even after structural mutations, global instrumentation may not be worth much for your current A4 mutation space. If it does appear, those are your premium bandit targets.

### Phase 5: Only then consider codegen instrumentation

If Phases 1-4 prove that global-only cases exist and matter, then the right way to get finer granularity is probably **codegen**, not ad hoc hooks around `poly_fp`.

The reason is protocol-level and architectural: constraints are batched into a mixed validity object, and the public verifier/prover interfaces only expose combined values. To recover local-like provenance, you need instrumentation **before** that mixing happens. In practice that means generated poly code or the generator itself, not just `verify_validity` or outer `poly_fp` entrypoints.

## What I would change in your bandit design

I would make global signals hierarchical.

Highest reward:

* mutation causes verifier failure,
* no local triggers,
* nonzero global family residue.

Next:

* no local triggers,
* combined finalized check goes nonzero at cycle rows or robustly off-cycle,
* but family attribution is coarse.

Then:

* local triggers exist, but the mutation also produces a rare / new global family residue.

Low reward:

* crashes,
* many repeated local failures,
* many family residues firing at once,
* dense combined-check failures across many rows / points.

The quality variable should incorporate **sparsity** on the global side too. A single-family residue with a small support set is better than a mutation that lights up everything.

## One extra suggestion I think is worth adding

Because the accumulator arguments are randomized, I would add a **confirmation pass across multiple random seeds** for only the most promising candidates. A mutation that still produces the same global-only behavior across several accumulator randomizations is much more interesting than one that disappears under a different challenge. The whitepaper’s preprocessing soundness discussion is exactly why this matters.

So the practical end state I would aim for is:

* fast path on every mutation: local touches / triggers + cheap global residue;
* medium path on top candidates: shadow per-family replay;
* expensive confirmation on elite candidates: rerun under several seeds.

That is where I land after revising your plan:

**Keep pursuing global diagnostics.
Stop expecting local-style per-constraint global labels at the current hook layer.
Reorder the project so H2 is tested first.
Implement binary and per-family shadow global signals now.
Escalate to codegen instrumentation only if those signals prove their value.**

A commit hash or tarball of the modified repo would let me turn this from an architectural review into a concrete hook-by-hook patch plan.
