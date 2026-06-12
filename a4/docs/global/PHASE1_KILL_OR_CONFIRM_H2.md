# Phase 1: Kill or Confirm H2 -- The Pivot Experiment

## What We Are Investigating and Why

### Background

We have a hypothesis called H2 (confidence: 70%) that states:

> **H2:** `poly_fp` evaluated at actual cycle rows produces the same results as the `step_TopAccum` EQZ checks. The apply-totals adjustment on accumulator columns algebraically cancels in the transition constraint, making `poly_fp` unable to detect permutation argument violations at cycle rows. Permutation violations only manifest at extended-domain points.

If H2 is TRUE: Hooking `poly_fp` at cycle rows gives us nothing new for global constraint detection. Our best option is the cheap binary residue check (Phase 2) and the shadow accumulator replay (Phase 3).

If H2 is FALSE: `poly_fp` at cycle rows can detect global violations per-cycle. This becomes a primary detection path and changes our entire strategy -- we would prioritize hooking `poly_fp` over the shadow replay approach.

**Everything downstream depends on this experiment.** That's why it's Phase 1.

### What Is poly_fp?

`poly_fp` is a C++ function that evaluates the "validity polynomial" for a single evaluation point. The prover calls it for every point in the "extended domain" (which is 4x the number of actual execution cycles). The result is used to build the "check polynomial" which the verifier later checks.

The extended domain has `domain = cycles * 4` points. Of these:
- **Cycle rows** (every 4th point): correspond to actual execution cycles where the witness was generated
- **Extended-domain points** (the other 3/4 of points): interpolation points between cycle rows

On a valid witness, `poly_fp` returns zero for ALL domain points. On a corrupted witness, some points will have non-zero results. The question is: WHERE do the non-zero values appear?

### What Exactly Is the Experiment?

We add temporary logging to `risc0_circuit_rv32im_cpu_poly_fp` (in `eval_check.cpp`) to record:
1. For each evaluation point: is the `poly_fp` result zero or non-zero?
2. Is that point a cycle row or an extended-domain point?

Then we run a COMP_OUT_MOD mutation (which we know breaks a memory value and causes verification failure) and analyze the results.

### The Three Possible Outcomes

**Outcome A: Non-zero at cycle rows.**
H2 is FALSE. `poly_fp` detects something at actual cycle rows that our EQZ hooks don't. This would mean the apply-totals cancellation hypothesis is wrong, and `poly_fp` is a viable hook point for per-cycle global detection.

**Outcome B: Zero at cycle rows, non-zero only at extended-domain points.**
H2 is directionally RIGHT. The permutation violation creates "wiggles" in the polynomial between cycle rows, but at cycle rows themselves the constraint values are zero (because apply-totals constructs the accumulator to satisfy transition constraints at cycle rows). Our best signals are aggregate/residue-based (Phase 2, Phase 3), not per-row.

**Outcome C: Zero everywhere.**
Something is fundamentally wrong with our understanding. The mutation should cause SOME non-zero `poly_fp` results (at minimum from the local MemoryWrite constraint violations at cycle rows). If we see zero everywhere, we have a bug in our instrumentation or a misunderstanding of how `eval_check` works.

---

## Implementation Plan

### Overview of Changes

We modify ONE file: [eval_check.cpp](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/eval_check.cpp).

The modification is purely diagnostic: when `A4_MUTATION_CONFIG` is set, we log `poly_fp` results to stdout before they are processed into the check polynomial. This is a temporary instrumentation that can be removed after the experiment.

**Important constraints for forward compatibility:**
- All output uses distinct XML-style tags that don't conflict with existing A4 tags
- The logging is behind the `A4_MUTATION_CONFIG` env var check (only active during A4 runs)
- We do NOT modify `poly_fp` itself (auto-generated code)
- We do NOT change the eval_check data flow (the results are still written to the check polynomial as before)
- The Rust-side `eval_check` calls `poly_fp` in parallel via `into_par_iter`. Our logging must be thread-safe. We use `printf` (thread-safe for complete calls) and collect counts with atomics.

### Step-by-Step Changes

#### Change 1: Add includes and diagnostic globals to eval_check.cpp

Add at the top of `eval_check.cpp`, after the existing includes:

```cpp
#include <atomic>
#include <cstdlib>
```

#### Change 2: Add diagnostic counters

Inside the `extern "C"` function, BEFORE the poly_fp call, add a static block for counters. These use atomics because `eval_check` is called from a parallel iterator on the Rust side.

However, there is a subtlety: the Rust `eval_check` function calls `risc0_circuit_rv32im_cpu_poly_fp` from a `par_iter` (parallel iterator). Each call is for a single cycle. We need to aggregate results across all calls.

We use static atomics that persist across calls within a single `eval_check` invocation, then emit the summary when the env var trigger is set. But since we can't easily know when "all calls are done" from inside the per-call function, we'll use a different approach: print per-call results and aggregate on the Python side.

Actually, a better approach: since the volume of calls is large (domain = cycles * 4, which could be ~65K), printing per-call would be too noisy. Instead, we use static atomic counters and emit the summary from a separate C function that Rust calls after the parallel loop.

But modifying the Rust side adds complexity. The simplest approach that works:

**Approach: Per-call logging with sampling, plus atomic counters for summary.**

For each call to `risc0_circuit_rv32im_cpu_poly_fp`:
1. Compute `poly_fp` as normal and store in `*result`
2. If `A4_MUTATION_CONFIG` is set:
   a. Check if `*result` is non-zero (any of the 4 FpExt elements)
   b. If non-zero: increment an atomic counter and log the first N occurrences
   c. Track separately: cycle-row non-zeros vs extended-domain non-zeros

For the summary, we add a new C function `risc0_circuit_rv32im_cpu_poly_fp_summary` that the eval_check Rust code can call after the parallel loop. But to avoid modifying Rust, we can instead use an `atexit` handler or simply emit the summary whenever the counters are non-zero and a call with a high cycle number comes in.

**Simplest viable approach:** Print aggregated stats from eval_check.cpp using a static flag and counters. After ALL poly_fp calls complete, the Rust code continues with other operations. We can detect "completion" by noting when we've seen `domain` calls. We know `domain = steps` (the second parameter to poly_fp). So after accumulating `steps` results, we emit the summary.

```cpp
static std::atomic<uint64_t> g_a4_poly_fp_calls{0};
static std::atomic<uint64_t> g_a4_poly_fp_nonzero_cycle{0};
static std::atomic<uint64_t> g_a4_poly_fp_nonzero_extended{0};
static std::atomic<uint64_t> g_a4_poly_fp_total_domain{0};
static bool g_a4_poly_fp_active = false;
```

#### Change 3: Modify risc0_circuit_rv32im_cpu_poly_fp

Replace the body of `risc0_circuit_rv32im_cpu_poly_fp` with instrumented version:

```cpp
extern "C" const char* risc0_circuit_rv32im_cpu_poly_fp(
    size_t cycle, size_t steps, FpExt* poly_mix, Fp** args, FpExt* result) {
  try {
    *result = circuit::rv32im_v2::poly_fp(cycle, steps, poly_mix, args);

    if (std::getenv("A4_MUTATION_CONFIG") != nullptr) {
      // First call: initialize
      if (g_a4_poly_fp_calls.load() == 0) {
        g_a4_poly_fp_active = true;
        g_a4_poly_fp_total_domain.store(steps);
        g_a4_poly_fp_nonzero_cycle.store(0);
        g_a4_poly_fp_nonzero_extended.store(0);
      }

      bool is_nonzero = (result->elems[0] != Fp(0) ||
                         result->elems[1] != Fp(0) ||
                         result->elems[2] != Fp(0) ||
                         result->elems[3] != Fp(0));

      constexpr size_t kInvRate = 4;
      bool is_cycle_row = (cycle % kInvRate == 0);

      if (is_nonzero) {
        if (is_cycle_row) {
          uint64_t prev = g_a4_poly_fp_nonzero_cycle.fetch_add(1);
          // Log first 10 cycle-row non-zeros for detailed inspection
          if (prev < 10) {
            size_t actual_cycle = cycle / kInvRate;
            std::printf("<a4_poly_fp_nonzero>{\"domain_idx\":%zu, \"actual_cycle\":%zu, "
                        "\"type\":\"cycle_row\", \"e0\":%u, \"e1\":%u, \"e2\":%u, \"e3\":%u}"
                        "</a4_poly_fp_nonzero>\n",
                        cycle, actual_cycle,
                        result->elems[0].asUInt32(), result->elems[1].asUInt32(),
                        result->elems[2].asUInt32(), result->elems[3].asUInt32());
          }
        } else {
          uint64_t prev = g_a4_poly_fp_nonzero_extended.fetch_add(1);
          // Log first 10 extended-domain non-zeros
          if (prev < 10) {
            std::printf("<a4_poly_fp_nonzero>{\"domain_idx\":%zu, \"actual_cycle\":null, "
                        "\"type\":\"extended\", \"e0\":%u, \"e1\":%u, \"e2\":%u, \"e3\":%u}"
                        "</a4_poly_fp_nonzero>\n",
                        cycle,
                        result->elems[0].asUInt32(), result->elems[1].asUInt32(),
                        result->elems[2].asUInt32(), result->elems[3].asUInt32());
          }
        }
      }

      uint64_t total_calls = g_a4_poly_fp_calls.fetch_add(1) + 1;

      // Emit summary when all calls complete
      if (total_calls == g_a4_poly_fp_total_domain.load()) {
        std::printf("<a4_poly_fp_summary>{\"domain\":%llu, \"nonzero_cycle_rows\":%llu, "
                    "\"nonzero_extended\":%llu}</a4_poly_fp_summary>\n",
                    (unsigned long long)g_a4_poly_fp_total_domain.load(),
                    (unsigned long long)g_a4_poly_fp_nonzero_cycle.load(),
                    (unsigned long long)g_a4_poly_fp_nonzero_extended.load());
        std::fflush(stdout);
        // Reset for potential next invocation
        g_a4_poly_fp_calls.store(0);
        g_a4_poly_fp_nonzero_cycle.store(0);
        g_a4_poly_fp_nonzero_extended.store(0);
        g_a4_poly_fp_active = false;
      }
    }
  } catch (const std::exception& err) {
    return strdup(err.what());
  }
  return nullptr;
}
```

### Thread Safety Analysis

The Rust side calls `risc0_circuit_rv32im_cpu_poly_fp` from `(0..domain).into_par_iter().for_each(...)`. This means multiple threads call our function concurrently. Our safety measures:

1. **Atomic counters** (`std::atomic<uint64_t>`): All counter increments use `fetch_add` which is atomic.
2. **printf**: POSIX guarantees `printf` calls are thread-safe (they acquire a lock on stdout). Individual `printf` calls won't interleave with each other. Since each `<a4_poly_fp_nonzero>` is a single `printf` call, each line will be complete.
3. **Summary emission**: The summary is emitted by exactly one thread (whichever increments the counter to `total_domain`). The `fetch_add` + comparison ensures exactly one thread sees `total_calls == domain`.
4. **Race on g_a4_poly_fp_active**: This is a non-atomic bool. It's set to true in a single early call and read later. In the worst case, a few early calls might miss the flag, but this doesn't affect correctness since we only use it for the logging path.

**Potential issue:** The "first call" detection (`g_a4_poly_fp_calls.load() == 0`) has a race window where multiple threads could see 0. This could cause multiple initializations. Fix: use `compare_exchange_strong` for the first-call detection, or accept that the counters might be reset multiple times (since they're all set to 0, re-initialization is idempotent).

**Simpler fix:** Initialize the counters to 0 statically (which they already are as static atomics). Don't reset in the "first call" -- instead reset only in the summary emission. The first call detection is only needed to set `total_domain`, which we can do with a `compare_exchange`:

```cpp
uint64_t expected = 0;
g_a4_poly_fp_total_domain.compare_exchange_strong(expected, steps);
```

This ensures only one thread sets the domain size.

### Testing Plan

#### T1: Compilation Test

After making changes, rebuild:
```bash
cd workspace/risc0-modified && cargo build -p risc0-circuit-rv32im-sys
cd workspace/output && cargo build --release -p risc0-host
```

#### T2: Clean Run (No Mutation)

Run without mutation to verify no poly_fp tags appear and the prover still succeeds:
```bash
/root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 | grep 'a4_poly_fp'
```
Expected: No output (no `A4_MUTATION_CONFIG` set, so logging is inactive).

#### T3: Single COMP_OUT_MOD (Quick Smoke Test)

```bash
echo '{"mutation_type": "COMP_OUT_MOD", "step": 785, "txn_idx": 16261, "word": 73117827}' > /tmp/test_mutation.json
A4_MUTATION_CONFIG=/tmp/test_mutation.json CONSTRAINT_CONTINUE=1 \
  /root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 > /tmp/phase1_single.txt
```

Check that the instrumentation produces output:
```bash
grep '<a4_poly_fp_summary>' /tmp/phase1_single.txt
grep '<constraint_fail>' /tmp/phase1_single.txt
```

Verify we see both local constraint failures and a poly_fp summary. If the summary is missing, the instrumentation has a bug.

#### T4: 100-Mutation Campaign (THE MAIN EXPERIMENT)

We reuse the existing diagnostic campaign infrastructure (`run_diagnostic_campaign.py`), which already:
- Runs inspection to discover valid steps and transaction indices
- Generates proper mutations across 8 types (COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, PRE_EXEC_REG_MOD, INSTR_TYPE_MOD, MEM_VAL_MOD, INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR)
- Sets `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE=1` (which triggers our poly_fp logging)
- Sets `A4_COVERAGE_TOUCH=1` and `A4_COVERAGE_TOUCH_VERBOSE=1` (which triggers our Step 1 accum hooks)
- Captures and parses constraint failures, touch bitmaps, and verbose sets

The campaign output already contains our new `<a4_poly_fp_summary>` and `<a4_poly_fp_nonzero>` tags (since `A4_MUTATION_CONFIG` is set). We need to:

1. **Add poly_fp parsing** to the campaign's per-run output processing. Extract `<a4_poly_fp_summary>` from each run's output.
2. **Add phase-aware failure counting.** The existing `parse_all_constraint_failures` returns `ConstraintFailure` objects. We need to also count failures by `"phase"` field (local vs accum) from the raw output, since the parser doesn't yet extract the phase field.
3. **Add an H2 analysis section** to the campaign report.

**Approach: Run the existing campaign and post-process its output.**

Rather than modifying the campaign script itself (which would risk breaking existing functionality), we:
1. Run `run_diagnostic_campaign.py` with `--num 100` which captures full stdout+stderr per run
2. Write a small post-processing script that re-scans the campaign's raw outputs for poly_fp tags and performs the H2 analysis

However, the campaign currently doesn't save raw per-run output to disk -- it only saves parsed results. We need either:
- **Option A:** Modify the campaign to also save raw output per run to a directory
- **Option B:** Write a thin wrapper that runs the campaign's `run_mutation` + `create_mutation` logic but saves raw output and adds poly_fp parsing

**Chosen approach: Option B** -- a dedicated Phase 1 campaign script that imports and reuses the campaign's `create_mutation`, `InspectionData`, mutation target functions, etc., but adds poly_fp-specific parsing and H2 analysis. This avoids modifying the battle-tested campaign script while reusing its proven mutation generation logic.

```bash
python -m a4.standalone.tests.run_phase1_h2_campaign \
    --host ./workspace/output/target/release/risc0-host \
    --num 100 --seed 42 \
    -- --in1 5 --in4 10
```

The script will:
1. Import `InspectionData`, `create_mutation`, mutation target getters, `ZonedStepSelector`, `create_generator` from the existing A4 infrastructure
2. Use the existing `run_mutation` function (which sets all required env vars)
3. For each run, parse BOTH the existing tags AND the new `<a4_poly_fp_summary>` / `<a4_poly_fp_nonzero>` tags
4. Count failures separately by phase (`"phase":"local"` vs `"phase":"accum"`)
5. Compare `nonzero_cycle_rows` against phase-local failure count for H2 analysis
6. Produce a dedicated H2 report at the end

**Campaign takes ~35 minutes** (100 runs x ~20s each).

#### T5: Result Interpretation

The campaign produces evidence at three levels:

**Level 1: H2 verdict**
For each run, compare `poly_fp_summary.nonzero_cycle_rows` against the number of local-phase constraint failures. The key metric:
- If `nonzero_cycle_rows > local_failure_count` for ANY run: H2 is REFUTED. Extra cycle-row non-zeros must come from accum constraints.
- If `nonzero_cycle_rows <= local_failure_count` for ALL 100 runs: H2 is CONFIRMED with high statistical confidence.

**Note on the comparison:** `nonzero_cycle_rows` counts domain points where poly_fp returned non-zero AND `cycle % 4 == 0`. Each local constraint failure at cycle C produces a non-zero poly_fp at domain point `C * 4`. But a single cycle can have MULTIPLE local failures (e.g., MemoryWrite at mem.zir:99 AND mem.zir:100 both fail at the same cycle). These are mixed together in poly_fp's single return value. So `nonzero_cycle_rows` should equal the number of DISTINCT CYCLES with at least one local failure, not the total failure count.

We therefore compare `nonzero_cycle_rows` against `distinct_failing_cycles` (number of unique cycle values across all local-phase failures).

**Level 2: Extended-domain patterns**
- How many extended-domain non-zeros per mutation? Is it proportional to local failures?
- This tells us about the "leakage" from local failures vs genuine accum violations at extended points.

**Level 3: Global-only mutations (H5 preview)**
- Any mutations where `local_failure_count == 0` but `nonzero_extended > 0`?
- These would be global-only mutations -- exactly the "premium bucket" from Phase 4.
- Finding them here (with existing mutation types) would be a strong early signal.

**Level 4: Mutation type patterns**
- Do INSTR_TYPE_MOD mutations behave differently from COMP_OUT_MOD?
- Does the number of non-zero cycle rows correlate with mutation type?

### Edge Cases and Potential Issues

1. **Parallel printf interleaving:** Each `<a4_poly_fp_nonzero>` is a single `printf` call. POSIX guarantees atomicity per call. However, the summary emission happens in one thread while other threads may still be printing non-zero lines. The summary might appear before the last few non-zero lines. This is OK -- we parse by tag, not by line order.

2. **Counter overflow:** With domain ~65K, uint64_t is more than sufficient.

3. **Multiple eval_check invocations:** If the prover calls `eval_check` more than once per proving session, the static counters would accumulate across invocations. The summary emission resets counters, so the second invocation starts fresh. This should be fine.

4. **The `steps` parameter vs actual cycle count:** In `poly_fp`, `steps` is the full domain size (cycles * INV_RATE), NOT the number of cycles. The Rust code passes `domain` as `steps` to the C++ function. So `cycle` ranges from 0 to `domain-1`, and `steps == domain`.

5. **What kInvRate means for cycle row detection:** `kInvRate = 4`. A point at index `cycle` is a cycle row if `cycle % 4 == 0`. The actual execution cycle number is `cycle / 4`. However, we need to verify this -- the Rust code uses `Val::ROU_FWD[po2 + EXP_PO2].pow(cycle)` where `EXP_PO2 = log2_ceil(INV_RATE) = 2`. The roots of unity for the execution trace are `omega^0, omega^4, omega^8, ...` where omega is the domain-size root. So `cycle % 4 == 0` corresponds to execution cycles. This matches standard STARK convention.

6. **Fp comparison semantics:** `Fp(0)` has `val = 0`. The comparison `elems[i] != Fp(0)` checks `val != 0`. This is correct for detecting non-zero field elements.

---

## Context: Why We Interpret Results This Way

### What poly_fp Does

The RISC Zero prover generates a proof by demonstrating that all constraint expressions evaluate to zero at every cycle. The way this works mathematically is:

1. The prover has N cycles of execution, each with values in data columns and accumulator columns.
2. The constraint expressions are algebraic formulas that should evaluate to 0 for every cycle if the execution was valid.
3. The prover treats these N-cycle values as evaluations of polynomials and extends them to a larger domain (4N points) using polynomial interpolation.
4. The function `poly_fp(cycle, steps, poly_mix, args)` evaluates the combined constraint polynomial at one point in this 4N-point domain. It reads column values via `args[group][col * steps + ((cycle - kInvRate * back) & mask)]`, which is direct array indexing into the extended column data.
5. If the constraint polynomial is the zero polynomial (all constraints satisfied), `poly_fp` returns zero for ALL 4N points. The prover then divides by the vanishing polynomial to get a low-degree check polynomial.

### Why Cycle Rows vs Extended Points Matters

At cycle rows (points 0, 4, 8, ...), the column values are the ACTUAL witness values that were stored during witgen and accum phases. At extended points (1, 2, 3, 5, 6, 7, ...), the column values are polynomial interpolations.

For **local constraints** (like MemoryWrite), the constraint expression uses data columns. If the data is corrupted, the constraint is non-zero at the corrupted cycle row. The polynomial interpolation spreads this non-zero value to nearby extended points too.

For **accum transition constraints**, the constraint expression references accum columns at the current row and the previous row. At cycle rows, the accum values were carefully constructed by prefix-sum + apply-totals to satisfy the transition constraint. Our hypothesis H2 says: at cycle rows, the transition constraint is `raw_delta[i] - 0 = delta[i]` (adjustment cancels), which is always satisfied. But at extended points, the polynomial interpolation of the accum columns doesn't satisfy the transition constraint as a polynomial identity (because the total is non-zero). So the constraint polynomial is non-zero at extended points.

### Why This Experiment Is Decisive

**If we see non-zero cycle-row results beyond the known local failures:** It means accum constraints CAN fail at cycle rows, refuting H2. This would happen if our algebraic cancellation analysis is wrong -- maybe apply-totals doesn't perfectly cancel, or maybe the transition constraint references different columns than we think. In this case, hooking `poly_fp` at cycle rows would detect global violations.

**If we see ONLY the expected local failures at cycle rows, plus extended-domain non-zeros:** It confirms that accum constraints pass at cycle rows (H2 is right) and the permutation violation lives only in the polynomial degree. The extended-domain non-zeros are a mix of local-failure leakage and accum-failure polynomial artifacts -- we can't easily separate them. This means `poly_fp` per-row hooking is useless for global detection, and we should proceed with Phase 2 (binary residue) and Phase 3 (shadow replay) instead.

**If we see zero everywhere:** Our instrumentation is broken or our understanding of when eval_check runs is wrong. We'd need to debug the instrumentation itself.

### Why We Compare nonzero_cycle_rows Against Distinct Failing Cycles

The `poly_fp` function returns a single mixed FpExt value per domain point. All constraints at that cycle are mixed together. So if cycle 16777 has two local failures (MemoryWrite at mem.zir:99 and mem.zir:100), poly_fp returns one non-zero value for domain point `16777 * 4` -- not two.

Meanwhile, `parse_all_constraint_failures` might report 2 failures at cycle 16777. If we compared `nonzero_cycle_rows` against total failure count, we'd incorrectly conclude that poly_fp "missed" one failure. The correct comparison is against the number of **distinct cycles** that have at least one local-phase failure.

If `nonzero_cycle_rows == distinct_failing_cycles`: only local failures show in poly_fp at cycle rows. H2 confirmed.
If `nonzero_cycle_rows > distinct_failing_cycles`: extra cycle rows have non-zero poly_fp from accum constraints. H2 refuted.

### Why a 100-Mutation Campaign Instead of a Single Run

A single mutation can give coincidental results. For example:
- The specific cycle might not exercise certain accumulator argument types
- The specific mutation type might happen to produce a pattern that looks like H2 confirmation when a different mutation would refute it
- Edge cases in the trace (first/last cycles, table split boundary) might behave differently

With 100 mutations spanning 5 types and many different target cycles, we get:
- **Statistical confidence**: If H2 holds across all 100, chance of a false confirmation is low
- **Coverage of argument types**: Different instructions exercise different lookup/permutation arguments
- **Coverage of trace positions**: Early, middle, and late cycles may interact differently with the accumulator
- **Bonus data for H5**: We might discover global-only mutations early, informing Phase 4

### Connection to Other Phases

- If H2 is confirmed (zero runs show cycle-row non-zeros beyond local failures): Phase 2 (binary residue) becomes the primary global signal. Phase 3 (shadow replay) becomes the primary per-family signal. `poly_fp` hooking is abandoned.
- If H2 is refuted (some runs show additional cycle-row non-zeros): Phase 2 is still useful as a cheap pre-check. But `poly_fp` hooking becomes viable for per-cycle global detection, potentially replacing or complementing Phase 3. We'd investigate which mutation types produce the extra non-zeros.
- The campaign's global-only bucket data directly feeds Phase 4 planning. If we find global-only mutations in the campaign, Phase 4's mutation design can build on those findings.
- Phase 5 (bandit integration) benefits from knowing the statistical distribution of cycle-row vs extended-domain non-zeros across mutation types.
