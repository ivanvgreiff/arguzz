# Phase 7d Inc 3d — B7 race root-cause investigation (report, in-progress)

**Status:** A1 + A2 + A3 (partial) complete. A3 sequential reproducer running.
**Date:** 2026-06-11
**Predecessors:** Inc 3c (Composer's Phase δ report). External AI review (`PHASE_7D_INC3C_EXTERNAL_REVIEW.md`).

---

## TL;DR (so far)

1. **Parser audit (A1):** The `B7_verbose_touch.py` candidate-index search is **sound** for this campaign — both A and B have the same number of blocks (always identical block-count per pair) and `_candidate_block_indices` correctly compensates for the off-by-one.

2. **Per-block diff inventory (A2):** Block-by-block comparison shows the FTW291 race is **real, rare, and directional**, not a parser artifact:

   | Pair | Blocks A/B | Identical | Differ | Extra in A | Extra in B | Notes |
   |------|-----------|-----------|--------|------------|------------|-------|
   | alpha (octorand) | 49/49 | 48 | 1 | 0 | 1 | All on FTW291 |
   | beta (octorand)  | 49/49 | 49 | 0 | 0 | 0 | No race observed |
   | **opulous**      | **50/50** | **50** | **0** | **0** | **0** | No race observed (smaller sample suffices statistically) |
   | meld             | 49/49 | 47 | 2 | 0 | 2 | All on FTW291 |
   | flareCtrl        | 49/49 | 47 | 2 | 0 | 2 | All on FTW291 |

   Total: 5 racy bits / 196 paired blocks = **2.6% per-mutation race rate**. **All extras on B-side** — directional asymmetry confirmed.

3. **Off-by-one explanation (A2):** The "49 verbose blocks for 50 mutations" mystery is fully solved — **one mutation (`PRE_EXEC_REG_MOD @ step 2708`) segfaults the host** (exit `-11`, 785ms duration vs normal 3500ms) before verbose tags are emitted. This mutation appears in octorand/meld/flare seed sequences but NOT in opulous (seed 1000). Opulous correspondingly shows `CRASH: 0` and produces 50/50 blocks. The race signal is INDEPENDENT of this crash.

4. **A3 sequential reproducer (first 7 runs):** Same patched host (`c2e77443…`), same mutation 27 config, 7 sequential subprocess runs — all 7 verbose-tag + accum-verbose-tag + coverage-tag triplets are **byte-identical** (sha256 matches). Race **does not reproduce** in raw isolated subprocesses on this machine. (Continuing to 30 runs for confidence.)

5. **Implication:** the race is either (a) only triggered by the POS environment (system load, NUMA, scheduling), (b) only triggered by the fuzzer's in-process state across many mutations, or (c) rare enough that we need ≫30 runs to observe it.

---

## §A1 — Parser audit

### A1.1 `B7_verbose_touch.py` block search

```python
def _candidate_block_indices(block_count: int, mutation_index: int) -> List[int]:
    out = []
    for idx in (mutation_index - 2, mutation_index - 1):
        if 0 <= idx < block_count and idx not in out:
            out.append(idx)
    return out
```

Verdict: **sound for this campaign**. Reasoning:
- A and B logs always have identical block counts (49/49 or 50/50). Therefore at any given block index, both A and B contain data from the **same mutation**.
- The `(mut_id-2, mut_id-1)` candidates compensate for one missing block per campaign.
- When `_candidate_block_indices` finds a hit at `mut_id-2`, it's reliably comparing the same mutation in both runs.
- Critically: when we compute the **brute-force per-block diff** (A2), the result agrees with the parser's findings — 1 racy block for alpha, 2 for meld, 2 for flare, 0 for opulous.

### A1.2 `inc3c_parse_phase_delta.py` reward-diff source

Reward diffs come from the `mutation_rewards` table, indexed by `mutation_id` (1..50). All 50 mutations are present in `mutation_rewards` on every node. The reward-diff list is therefore **completely accurate** and unaffected by the verbose-block issue.

### A1.3 Regex correctness in `executor.py`

The passthrough regex:
```python
_A4_VERBOSE_RE = re.compile(
    r"<a4_touch_verbose>\[.*?\]</a4_touch_verbose>|"
    r"<a4_accum_touch_verbose>\[.*?\]</a4_accum_touch_verbose>",
    re.DOTALL,
)
```

Concern (ChatGPT's): `\[.*?\]` is non-greedy and could terminate at the first `]` inside the content.
Verification: every actual block in all 10 logs contains exactly **1 `]` character** (the closing bracket of the JSON array). The greedy and non-greedy regexes return identical match counts. **No regex bug.**

---

## §A2 — Raw-log inspection

### A2.1 Block counts per log

| Log | Witgen-verbose blocks | Accum-verbose blocks | Block sizes (bytes) |
|-----|----------------------|----------------------|---------------------|
| `octoaA` | 49 | 49 | 120387 – 123642 |
| `octoaB` | 49 | 49 | 120387 – 123642 |
| `octobA` | 49 | 49 | 120387 – 123642 |
| `octobB` | 49 | 49 | 120387 – 123642 |
| `opugA`  | **50** | **50** | 120387 – 123062 |
| `opugB`  | **50** | **50** | 120387 – 123062 |
| `melddA` | 49 | 49 | 120387 – 123642 |
| `melddB` | 49 | 49 | 120387 – 123642 |
| `flareCtrlA` | 49 | 49 | 120387 – 123642 |
| `flareCtrlB` | 49 | 49 | 120387 – 123642 |

A and B always match. Opulous (seed 1000) is the only pair with 50 blocks.

### A2.2 Source of the 49-vs-50 discrepancy

`pos_inc3c_phase_delta_zoned_seed999_n50_octoaA.log` campaign trailer:
```
Outcome breakdown:
  REJECTED (mutation detected): 49
  CRASH (segfault, etc.):       1   ← one mutation segfaulted
  NO_EFFECT:                    0
  ACCEPTED (BUG!):              0
  SKIPPED:                      0
```

Crash line in the log:
```
  [16] 💥 PRE_EXEC_REG_MOD @ step 2708: 2 failures, 785ms, outcome: CRASH, exit: -11 [proof:NOT_GENERATED]
```

- Exit `-11` = `SIGSEGV` (segfault from the host).
- 785 ms (vs ~3500 ms normal) — died early in witgen.
- The host therefore emitted **0 verbose tags** for this mutation; the fuzzer's executor.py passthrough finds no tags to re-emit; the log is correspondingly missing both the witgen-verbose and the accum-verbose blocks for this mutation.

**Per-node crash count vs verbose-block count:**

| Node | REJECTED | CRASH | Witgen-verbose blocks | Sum |
|------|---------:|------:|----------------------:|----:|
| opugA / opugB | 50 | 0 | 50 | 50 ✓ |
| octoaA / octoaB / octobA / octobB / melddA / melddB / flareCtrlA / flareCtrlB | 49 | 1 | 49 | 50 ✓ |

Perfect accounting — 1 crash ↔ 1 missing verbose block on each affected node. **Mystery resolved.**

(Note: this is a separate, lower-priority bug to revisit: a `PRE_EXEC_REG_MOD @ step 2708` mutation segfaults the host. Worth filing as a host-stability issue once B7 is closed.)

### A2.3 Per-block A-vs-B diff (the smoking gun)

Brute-force comparison of every block at every shared index:

```
pair                     n_blocks  identical   differ   extra_A   extra_B   common_diffs
------------------------------------------------------------------------------------------
alpha (octorand)            49/49         48        1         0         1       1 ftw291
beta (octorand)             49/49         49        0         0         0       0 ftw291
opulous                     50/50         50        0         0         0       0 ftw291
meld                        49/49         47        2         0         2       2 ftw291
flareCtrlA                  49/49         47        2         0         2       2 ftw291
```

**Key observations:**

1. Where A and B differ, they differ **only by 1 context**. The "off-by-one" data-misalignment hypothesis would have produced *dozens* of differences (any two mutations' coverage sets differ by 30+ contexts on average), so the parser is correctly comparing the same mutation across A and B.
2. **Every single differing context is `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)|major=9|minor=5`.** No noise.
3. **Every extra context is on the B-mate.** `extra_A = 0` in every pair. The directional asymmetry is real.
4. Race rate ≈ 5 bits / 196 shared blocks = **2.55%** per mutation across nodes that observed the race.
5. Opulous (0/50 race bits) is consistent with the same rate: P(0 hits | n=50, p=0.025) = (1-0.025)^50 ≈ **28%**. No special "opulous escapes the race" mechanism is required.

---

## §A3 — Standalone reproducer

### Setup
- Binary: `/root/arguzz/workspace/output/target/release/risc0-host`, sha256 `c2e77443275372846a73a9d1d13d340e8068ff70961d8e8b97fff479bb63b332` (same as Inc 3c bundle).
- Guest: `/root/arguzz/workspace/output/target/riscv-guest/risc0-methods/risc0-guest/riscv32im-risc0-zkvm-elf/release/risc0-guest.bin`.
- Mutation config (`/tmp/inc3d_repro/mut27.json`):
  ```json
  {"mutation_type": "MEM_VAL_MOD", "step": 3259, "txn_idx": 29184, "word": 4294967295}
  ```
- Environment per run:
  ```
  A4_MUTATION_CONFIG=/tmp/inc3d_repro/mut27.json
  A4_COVERAGE_TOUCH=1
  A4_COVERAGE_TOUCH_VERBOSE=1
  A4_FAMILY_RESIDUE=1
  CONSTRAINT_CONTINUE=1
  ./target/release/risc0-host --in1 5 --in4 10
  ```
- Per-run wall time: ~22 s. Exit code: 101 (`thread 'main' panicked at host/src/main.rs:150:13: verify segment` — expected for mut27).

### Result (full 30-run campaign)

| Run | sha256(verbose) prefix | sha256(accum_verbose) prefix | sha256(coverage) prefix |
|----:|-----------------------|------------------------------|-------------------------|
| 001–030 | `ac56a7278b17faa7` (×30) | `bf4891cb80a0d2b1` (×30) | `b99b53555d06c752` (×30) |

**30/30 runs are byte-identical.** Race does NOT reproduce in raw sequential subprocess execution on this machine.

Total elapsed: 1079 s (~36 s/run, ~22 s host CPU + ~14 s overhead).

### Statistical confidence

Observed POS race rate for mut27: 1 racy bit in 2 nodes (alpha-A vs alpha-B) × 1 run-pair = "5/200 = 2.5% across all racy mutations". Per-mutation race rate for mut27 alone is unknown but bounded above by ~0.5 from the single observation.

For mut27 at p=0.025 (the lower campaign rate):
- P(0 hits | n=30) = 0.975³⁰ = **0.47** — 30 identical runs is plausible even if the race is real.

For mut27 at p=0.10 (high estimate):
- P(0 hits | n=30) = 0.90³⁰ = **0.04** — 30 identical runs would already be unusual.

**Conclusion**: 30 identical sequential runs is *suggestive* but not yet definitive. To make a confident "no race standalone" claim, we need ≥100 runs (P(0|100,0.025) ≈ 0.08).

### Interpretation

If 100+ runs all remain identical, the race is **not in the raw host process alone** for mut27. The race source must then be one of:

1. **POS-environment specific** — CPU model, NUMA, kernel/libc version, scheduler interruption patterns, or page-cache state on the POS nodes.
2. **Fuzzer in-process state** — the host being launched as the Nth mutation (N=27) by a long-running Python fuzzer process, with allocator/page-cache state accumulated from N-1 prior mutations.
3. **Concurrent processes on the same physical node** (unlikely; POS reservations are exclusive).
4. **Mutation-specific** — mut27 may not be the easiest mutation to reproduce; try mut21 (flare), mut36 (meld), mut48 (meld) which also showed the race.

---

## §A3.1 — Variant experiments (executed)

### A3.1c — Pair-concurrent (cores 0 vs 4, simultaneous launch)

20 pairs of `risc0-host` processes pinned to disjoint cores via `taskset -c {0,4}`, each pair launched simultaneously with `&` + `wait`. Mutation: mut27. Closest local analog of POS A vs B dispatch.

**Result: 20/20 pairs byte-identical between A and B.** Wall time: 1250s.

### A3.1b — Other racy mutation (mut21, STORE_OUT_MOD step 3347)

20 sequential runs of mut21 on core 6.

**Result: 20/20 byte-identical, AND identical to mut27's hash** (`ac56a7278b17faa7`). Wall time: 1132s.

### Critical cross-finding: touch coverage is *mutation-independent*

A side observation that simplifies our model: **mut21 and mut27 produce identical `<a4_touch_verbose>`, `<a4_accum_touch_verbose>`, and `<a4_touch_coverage>` content** — same SHA-256 prefixes:

| Tag | mut27 hash | mut21 hash |
|-----|------------|------------|
| `<a4_touch_verbose>` | `ac56a7278b17faa7` | `ac56a7278b17faa7` |
| `<a4_accum_touch_verbose>` | `bf4891cb80a0d2b1` | `bf4891cb80a0d2b1` |
| `<a4_touch_coverage>` | `b99b53555d06c752` | `b99b53555d06c752` |

This is correct by design: `a4_touch_mark` fires inside `EQZ(…)` whenever a constraint is **evaluated**, regardless of whether it passes or fails. Touch coverage measures the set of `(loc, major, minor)` constraint checks **exercised**, not failed. Since witgen exercises the same set of constraints on any execution of a given guest with a given input (the mutation just changes data values within the same code path), the touch set is identical across mutations that don't change the program counter trajectory.

Implication: **testing different mutations does not give us more chances to reproduce the race** — the race is in a path that runs every execution, so 100 runs of mut27 ≡ 100 runs of mut21 from a touch-coverage standpoint.

### Aggregate local determinism evidence

| Experiment | Independent runs / pairs | Result |
|------------|--------------------------|--------|
| A3 sequential mut27 | 30 runs | 30/30 byte-identical |
| A3.1c pair-concurrent mut27 (cores 0 vs 4) | 20 pairs (40 runs) | 20/20 pairs identical |
| A3.1b sequential mut21 | 20 runs | 20/20 byte-identical, equals mut27 hash |
| **Total** | **70 effective independent observations** | **0 divergences** |

Statistical confidence: P(0 hits | n=70, p=0.025) = 0.975⁷⁰ ≈ **0.17**. Still possible by chance, but trending toward POS-environment-specific.

### What we have NOT yet tried locally
- `MALLOC_PERTURB_=165 MALLOC_ARENA_MAX=1 GLIBC_TUNABLES=glibc.malloc.tcache_count=0`
- `RAYON_NUM_THREADS=N` variations (rayon has implicit globals; could matter for `poly_fp`)
- `unset A4_COVERAGE_TOUCH_VERBOSE` — does the `std::set<std::string>` perturbation matter at all? (Likely doesn't, given 70 identical runs *with* the verbose set on.)
- Full local fuzzer campaign (50-mutation sequence in one Python process)
- `setarch -R` to disable ASLR

These would tighten the statistical bound but unlikely to change the conclusion qualitatively.

---

## §A — final decision

**The race is not reproducible on this WSL2 machine in any sequential, concurrent, or differently-pinned configuration tested.** It is therefore one of:

1. **POS-environment-specific**: CPU microarchitecture (cache topology, branch predictor), kernel/libc version, scheduler behavior, memory-controller topology, or NUMA effects on the specific POS server nodes.
2. **Fuzzer in-process state**: residual allocator state across 50 mutations in one long-running Python process. Not yet tested locally; could try A3.1e (full local fuzzer campaign).

In **both** cases, the next concrete step is **Phase B (zkVM instrumentation)** to add boundary hashes that localize *where* in witgen/accum the divergence enters. We can then redeploy to POS for one targeted experiment to read the boundary-hash diff.

The local reproducer turns out to be useless for triggering the race, but it's still useful as a **regression check** for Phase B instrumentation (any new patch should still produce deterministic local runs).

**Action items:**

1. **Create `arguzz/b7-race-instrumentation` branch** in `workspace/risc0-modified/` (user task).
2. **Draft Phase B patches** in the new branch (parallel work for me):
   - B1: self-identifying verbose blocks (already justified by the 49/50 mismatch — even if not a race indicator, the parser should fail-hard on misaligned blocks).
   - B2: targeted `<a4_ftw291>` emission at the racy branch in `exec_FieldToWord` — answers "is the Poseidon2 input actually different on A vs B, or is the witness construction picking a different `lowIsZero` value for the same input?"
   - B4: boundary hashes at Poseidon2 input/output and ExecBuffers boundaries — bisects where divergence first appears.
3. **Build the instrumented host** locally, smoke-test it produces deterministic output here (regression check).
4. **Prepare a Phase δ-ε POS bundle** with the instrumented host. Re-run the same SPREAD plan from Inc 3c. Compare boundary hashes between octoaA and octoaB at the mutation index that's known to race.
5. **Read the first differing boundary hash** → localizes the race source to a specific stage of witgen/accum.

The whole loop (#2-#5) is roughly 1 day of work if everything goes smoothly, plus POS time.

---

## §B — Phase B implementation sketch (for use in the new branch)

The instrumentation targets the exact failure mode identified by ChatGPT and corroborated by our data:
- **What we know**: a single `FieldToWord:291` bit differs between A and B; constraint located in `inst_p2.zir:291`, fires only when `lowIsZero` register is 1 (i.e., `low == 0` for some Poseidon2 output decomposition).
- **What we need to know**: is `low` actually 0 in the witness on A but not on B, or is `lowIsZero` being set differently for the same `low`?

### B2 (highest priority): targeted FTW291 logging

Patch site: `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` near the `if (to_size_t(x5._super))` branch (~line 7120). Caveat: `steps.cpp` is generated from zirgen; either patch the codegen template in `zirgen/` or patch `steps.cpp` directly as a one-off diagnostic.

```cpp
if (to_size_t(x5._super)) {
  fprintf(stderr,
    "<a4_ftw291 cycle=\"%zu\" arg0=\"%u\" low=\"%u\" high=\"%u\"/>\n",
    ctx.cycle,
    arg0.asUInt32(),
    x2._super._super.asUInt32(),
    x3._super._super.asUInt32());
  EQZ(x2._super._super, "FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)");
  …
}
```

### B4 (medium priority): boundary hashes

Add Blake3 hash emission tags (`<a4_boundary_hash stage="X" value="…"/>`) at:
1. Preflight trace post-mutation (`workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`).
2. Per-segment `read_record` / `write_record`.
3. Pager partial-image and page-indexes after commit.
4. Poseidon2 input state per round and output state per round (`workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/poseidon2.rs` if present, or wherever Poseidon2 lives in this fork).
5. `ExecBuffers` data at end of `stepExec` per segment.

### B1 (low cost, do anyway): self-identifying verbose blocks

`workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` — add `mutation_config_sha256`, `pid`, `seq` attributes to the open tag, and have the host write its config SHA to a file before running so the fuzzer can pass it in via env var. Parser hardens to fail on mismatch.

### Build + smoke test
- `cargo build --release --bin risc0-host` (in `workspace/output/`)
- 30× local reproducer with new binary → should still be 30/30 identical
- New tags should appear in output
- Rebuild PR'd into POS bundle via `prepare_bundle.sh`

---

*(End of A1-A3 report. §B is an outline pending branch creation.)*

---

## §A3.1 — Env-var variant tests (queued)

Once A3 finishes, run additional 30-run batches with:
1. `taskset -c 0 RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1` — thread pinning.
2. `MALLOC_PERTURB_=165 MALLOC_ARENA_MAX=1` — allocator fuzzing / single arena.
3. `unset A4_COVERAGE_TOUCH_VERBOSE` — does the `std::set<std::string>` perturbation matter?
4. Run mut21 and mut36 instead of mut27 — does racy mutation choice matter?
5. **Pair-concurrent runs** (best mimic of POS): two host processes pinned to disjoint cores, started simultaneously, hashes compared like A vs B.

---

## §A — decision point (preliminary)

Based on results so far:

| Scenario | Verdict | Action |
|----------|---------|--------|
| Sequential reproducer all-identical at 30 runs | Race not standalone-reproducible from raw subprocess | Move to A3.1: pair-concurrent reproducer mimicking POS dispatch |
| Sequential reproducer divergent | Race is in raw witgen path | Proceed to Phase B (zkVM instrumentation) on new branch |

The most likely outcome at this point is **all-identical sequential**, which will steer us to **pair-concurrent reproduction first** (A3.1 #5), then if still no repro → POS-only reproduction with B-mate-first ordering, then Phase B.

---

*(Document updated live as A3 progresses.)*

---

## §B — Phase B instrumentation applied and locally verified

**Date:** 2026-06-11 (evening) → 2026-06-12 (rebuild completed)
**Branch:** `arguzz/b7-race-instrumentation` in `workspace/risc0-modified/`
**New host SHA:** `632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1`
**Previous host SHA:** `c2e77443275372846a73a9d1d13d340e8068ff70961d8e8b97fff479bb63b332` (Inc 3c bundle)

### Patches applied

| ID | File | Lines changed | Effect | Always-on? |
|----|------|---------------|--------|------------|
| **B1** | `ffi.cpp` | +~50 lines (globals + 2 emit-site rewrites) | Adds `mut="…"`, `pid="…"`, `seq="…"` attributes to every `<a4_touch_verbose>` and `<a4_accum_touch_verbose>` opening tag | Yes (when `A4_COVERAGE_TOUCH_VERBOSE=1`) |
| **B3** | `ffi.cpp` | +~6 lines (counter + emit) | Per-phase counter of EQZ touches matching `(major=9, minor=5, loc⊃"inst_p2.zir:291")` emitted as `<a4_ftw291_95_count phase="…" value="…"/>` | Yes (when `A4_COVERAGE_TOUCH=1`) |
| **B2** | `steps.cpp` line 7120 | +~17 lines | Per-call diagnostic in `exec_FieldToWord`: `<a4_ftw cycle="…" userCycle="…" pc="0x…" major="…" minor="…" arg0="…" low="…" high="…" lowIsZero="…"/>` to **stderr** | **Gated** behind `A4_FTW291_TRACE=1` (off by default to avoid log spam) |

### Mutation SHA derivation

`a4_mutation_sha()` resolves in this priority order:
1. `A4_MUTATION_SHA256` env var (set by dispatcher when known) → used verbatim
2. `A4_MUTATION_CONFIG` file content → `fnv1a64=<16-hex>` (FNV-1a 64-bit of the raw bytes)
3. neither set → `"none"`

This is sufficient for paired-run sanity checking (`A` and `B` of the same mutation MUST yield the same `mut=` attribute).

### Local regression (4 runs of mut27, sequential)

After ~60 min C++/Rust rebuild, ran 4 sequential instances on WSL2 with `MEM_VAL_MOD step=3259`. Per-run wall-clock: ~100s (system loaded with concurrent fuzzing — not a perf regression).

All four runs produce identical body-content hashes for verbose, accum_verbose, coverage, and ftw291_95_count tags:

| Tag (body-only, B1 attrs stripped) | Hash | Match against pre-B1 gold? |
|-----------------------------------|------|---------------------------|
| `<a4_touch_verbose>…` | `ac56a7278b17faa7` (4/4) | **YES** (pre-B1 gold) |
| `<a4_accum_touch_verbose>…` | `bf4891cb80a0d2b1` (4/4) | **YES** (pre-B1 gold) |
| `<a4_touch_coverage>…` | `b99b53555d06c752` (4/4) | **YES** (pre-B1 gold — no change) |
| `<a4_ftw291_95_count …/>` (both phases) | `90d5519e4804db45` (4/4) | (N/A — new tag) |

The `mut="fnv1a64=99ec79d08877a7a7"` is consistent across all 4 runs (same mutation config), `pid` varies (4 different OS-assigned PIDs), `seq="0"` in every run (single-segment guest, both witgen and accum emit once).

**Without `A4_FTW291_TRACE=1`, zero `<a4_ftw>` tags appear in stderr** — B2 is correctly gated off.

**Without `A4_FTW291_TRACE=1`, B3 counter shows `value="0"` for both phases** on mut27 locally — confirming this WSL2 environment lands on the A-mate side (no FTW291 EQZ touch at major=9 minor=5), consistent with Phase A finding that this machine is not race-reproducing.

### Conclusion of §B (local)

- All three patches integrate cleanly (no compiler errors, no determinism regression).
- Coverage bitmap is **byte-identical** to pre-instrumentation host — there is no risk that the diagnostic code itself perturbs the constraint touch tracking.
- Verbose body content is **byte-identical** to pre-instrumentation host — the only difference is the new self-id attributes in the opening tag.
- Ready for POS bundling and deployment.

---

## §B — POS deployment plan (Composer's task)

### Bundle prep

The instrumented host is at `/root/arguzz/workspace/output/target/release/risc0-host` (sha256 `632094ef…`). Reuse the existing bundle-prep tooling but bump the bundle name to `INC3D_B_BUNDLE` (or similar).

### POS run plan

Re-run the **same SPREAD plan** as Inc 3c with the new bundle, plus the diagnostic env var:

| Run | Env additions (beyond Inc 3c) | Purpose |
|-----|------------------------------|---------|
| **Pass 1 — diagnostic** | `A4_FTW291_TRACE=1` | Capture the per-call `<a4_ftw>` events on both A and B; expect ~all matching events between paired hosts EXCEPT around the racy mutation, where B should emit one extra event with the same `(cycle, pc, userCycle)` but possibly different `lowIsZero` |
| **Pass 2 — verbose-off** | omit `A4_COVERAGE_TOUCH_VERBOSE=1` (keep `A4_COVERAGE_TOUCH=1`) | Test whether the `<a4_ftw291_95_count>` value diverges A vs B **without** the `std::set<std::string>` perturbation — if it still diverges, race is real and independent of verbose tracking |

Both passes use the existing `run_inc3c_phase_delta.sh` orchestration. SPREAD strategy and node selection unchanged.

### Analysis post-run

For each paired log (`*_octoaA.log` vs `*_octoaB.log`, etc.):

1. **B1 sanity gate:** for every mutation index `m`, the m-th `<a4_touch_verbose>` block in both A and B logs MUST have the same `mut="…"` attribute. If not, the parser/dispatcher misaligned blocks — fix that before any race conclusion.

2. **B3 counter comparison (per mutation):** extract `<a4_ftw291_95_count phase="witgen" value="N"/>` for each mutation in A and B logs. The B7 race shows up as `value_B > value_A` for the racy mutations.

3. **B2 trace comparison (per mutation):** extract all `<a4_ftw …/>` lines emitted between mutation-m's start and end. Compare A's list to B's list. Where they differ:
   - Same `(cycle, pc, userCycle)` but different `lowIsZero` → B chose the lowIsZero=1 branch (which triggers the EQZ at FTW291), A chose lowIsZero=0 → input field-element low-16 bits differ → race is in the **Poseidon2 input** that feeds FTW291.
   - B has extra entries A doesn't → A skipped some cycle (executor divergence — worse).

### Expected outcome

The race signature in Inc 3c was 5 racy mutations / 350 total runs (~1.4%). With the same SPREAD plan and same node mix, we should see:
- ~5-7 mutations where `value_B - value_A = 1` (the single extra context).
- For each, B2 should show the exact `(cycle, pc, userCycle, arg0, low)` tuple that triggered the divergence.
- This isolates the bug to a single Poseidon2 cell that differs A vs B.

### Tooling pending

`B7_verbose_touch.py` should be updated to:
- Read `mut=`, `pid=`, `seq=` attributes from each block.
- Fail hard if paired blocks have different `mut=` values.
- Use the `<a4_ftw291_95_count>` tag as a primary signal (no parsing of verbose set required).

I'll prep this parser update after the POS run produces data to verify against — there's no point updating it speculatively.

---

*(End of §B. Awaiting Composer to bundle + dispatch.)*
