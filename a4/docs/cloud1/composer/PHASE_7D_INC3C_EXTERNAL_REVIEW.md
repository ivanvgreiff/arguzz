# Nondeterministic constraint-touch coverage in RISC Zero v2 fuzzing — request for external research help

**Date:** 2026-06-11
**Audience:** External reviewer (a fresh ChatGPT conversation) with **no prior context** on this project.
**Goal:** You should read this document end-to-end and either (a) identify the root cause of the nondeterminism described below, or (b) propose specific experiments to find it.

---

## 0. TL;DR for the impatient

We are fuzzing the **RISC Zero zkVM v2** witness generator (witgen) to find constraint-coverage gaps. We run the exact same mutation, on the exact same compiled host binary, on the exact same physical machine, in two separate fresh subprocesses (call them "Run A" and "Run B"). The mutation hook fires identically (we verified: the on-disk mutation config and the resulting `mutations` table in the campaign SQLite DB are **byte-identical**). The fuzzer is single-threaded Python; the host C++ witgen runs in `kStepModeSeqForward` (single-threaded mode) when `A4_COVERAGE_TOUCH=1`.

Despite all of that, the resulting **constraint-touch coverage bitmap differs between Run A and Run B**. Across a wide variety of mutations:

- On every node we've tested (`octorand`, `meld`, `flare`, `opulous` — these are physical Linux servers in a university testbed), the per-mutation `local_coverage_v2` table differs in **41–70 rows out of ~10 000**.
- For 5 specific mutations across these nodes, the difference cleanly localizes to **exactly one extra constraint-touch bit on Run B**, always on the same hashed bucket corresponding to a single source location:
  `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)` with `(major=9, minor=5)`.
- The asymmetry is **directional**: in 5/5 racy mutations the extra bit is on Run B (the second run), never on Run A. Probability of this being a symmetric random race ≈ `(½)^5 = 3.1%`.
- One node (`flare`) went from **0/50** divergent mutations in a previous campaign (with a pre-fix host binary that did not have a verbose-tracking `std::set`) to **2/50** in the current campaign (with a patched host that populates an `std::set<std::string>` on every constraint touch). Other deltas in the patched host are not believed to affect this path.

The racy source location is **inside an `if` branch in a Poseidon2 store-state component**: the branch is taken iff a specific Poseidon2 output field element's low 16 bits equal zero. So somewhere along the pipeline, the **value of that Poseidon2 output is differing across runs**, even though the input data should be identical.

We have ruled out all obvious parallelism in the constraint-touch path. The only non-sequential plumbing we cannot fully exonerate by inspection is a `thread::scope` producer-consumer pattern in the Rust executor that pipelines segment creation with guest emulation.

**We want help generating hypotheses about what might cause two fresh, single-threaded runs of the same mutation on the same binary on the same machine to produce different witness data.** Please research aggressively — including looking at public RISC Zero issues/PRs/changelogs, glibc allocator behavior, kernel scheduling, and any common patterns of latent nondeterminism in field-arithmetic / cryptographic-hash pipelines.

---

## 1. Project context (what is this project)

### 1.1 What is RISC Zero?

RISC Zero is a general-purpose zero-knowledge virtual machine (zkVM). A user writes a program ("guest") in Rust (or C/C++) targeting a RISC-V 32-bit instruction set, compiles it to a guest ELF, and then a **host** runs the guest *and* generates a STARK-based zero-knowledge proof that the guest executed correctly with the given inputs and produced the given outputs.

The host pipeline is roughly:

```
guest ELF + inputs
       │
       ▼
┌─────────────────┐
│   Executor      │  emulates RISC-V instructions, records a trace
│  (preflight)    │  of cycles + memory transactions + register reads/writes
└─────────────────┘
       │ PreflightTrace { cycles[], txns[], … }
       ▼
┌─────────────────┐
│   Witgen        │  for each cycle, evaluates the circuit's "step function"
│ (stepExec loop) │  to fill in trace cells (data, ctrl, accum buffers)
└─────────────────┘
       │ buffers populated
       ▼
┌─────────────────┐
│   Accum         │  runs accum/lookup-argument cycles (sequential phase 1,
│ (stepAccum +    │  parallel prefix-sum phase 2, parallel apply-totals phase 3)
│  prefix-sum +   │
│  apply totals)  │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Constraint eval │  evaluates polynomial constraints over the witness,
│ (poly_fp,       │  parallel across domain rows (`rayon::into_par_iter`)
│  eval_check)    │
└─────────────────┘
       │
       ▼
   STARK proof
```

The "circuit" is generated from a DSL called **zirgen** in `zirgen/circuit/rv32im/v2/dsl/*.zir`. zirgen compiles `.zir` files into auto-generated C++ (`steps.cpp`, `rust_poly_fp_*.cpp`) and Rust (`zirgen/steps.rs.inc`, `zirgen/poly_ext.rs`). The generated code is what `stepExec`, `stepAccum`, and `poly_fp` execute.

### 1.2 What is this fuzzing project?

We're building **Arguzz / A4**, a constraint-coverage-guided fuzzing framework for RISC Zero. The goal is to find soundness bugs: cases where a maliciously modified RISC Zero witness would still pass constraint checks (i.e., produce a verifiable proof of an invalid execution).

The approach:

1. Run the guest normally to produce a baseline preflight trace.
2. **Mutate** specific cells in the trace (instruction words, memory transaction words, instruction types, etc.) — these mutations represent "what could a malicious prover do?".
3. Run witgen + constraint evaluation on the mutated trace.
4. Observe (a) which constraints fail, (b) which constraint code paths were *touched* (whether they failed or not). This "touch coverage" is the feedback signal for our bandit-based mutation selector.
5. A "successful" mutation is one that triggers no constraint failures (i.e., the modified witness is accepted) but produces materially different output — that's a soundness gap.

The mutation kinds we support (the relevant ones for this issue):
- `INSTR_TYPE_MOD` — change cycle's `major`/`minor` (the instruction-class column)
- `INSTR_WORD_MOD` — change the instruction-fetch transaction's word
- `LOAD_VAL_MOD` — change a load-result write transaction's word
- `STORE_OUT_MOD` — change a store-data write transaction's word
- `MEM_VAL_MOD` — change a memory-read transaction's word
- `COMP_OUT_MOD`, `PRE_EXEC_REG_MOD` — other targeted register/word mutations

Each mutation is specified by a JSON config like:
```json
{"mutation_type": "MEM_VAL_MOD", "step": 3259, "txn_idx": 17000, "word": 12345678}
```

### 1.3 How the host instrumentation works

We've added hooks to the RISC Zero v2 host (a fork at `workspace/risc0-modified/`) that:

1. **Read a mutation config from `A4_MUTATION_CONFIG=/path/to/config.json`** — applied once during witgen entry, modifies the relevant cell in `PreflightTrace` before the main loop. Single-threaded.

2. **Track per-constraint "touch coverage" when `A4_COVERAGE_TOUCH=1`** — every call to the constraint-check macro `EQZ(val, loc_string)` increments a byte in a 64 KB bitmap, indexed by `FNV1a(loc_string) ^ major ^ minor`. Bitmap is emitted as base64 at end of witgen and accum phases.

3. **When `A4_COVERAGE_TOUCH_VERBOSE=1`** — additionally accumulate the *exact* `(loc, major, minor)` strings into a `std::set<std::string>` and emit the unique set at end of each phase. This is to disambiguate hash-bucket collisions and identify which specific source location is racing.

The relevant macro is in `witgen.h`:

```184:206:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h
inline void eqz(ExecContext& ctx, Val a, const char* loc) {
  a4_touch_mark(ctx, loc);
  if (a.asUInt32()) {
    // <---- PHASE 1.5: ENHANCED CONSTRAINT FAILURE TRACING ---->
    uint32_t step = ctx.preflight.cycles[ctx.cycle].userCycle;
    uint32_t pc = ctx.preflight.cycles[ctx.cycle].pc;
    uint8_t major = ctx.preflight.cycles[ctx.cycle].major;
    uint8_t minor = ctx.preflight.cycles[ctx.cycle].minor;
    printf("<constraint_fail>{\"cycle\":%zu, \"step\":%u, \"pc\":%u, \"major\":%u, \"minor\":%u, \"loc\":\"%s\", \"value\":%u, \"phase\":\"%s\"}</constraint_fail>\n",
           ctx.cycle, step, pc, major, minor, loc, a.asUInt32(),
           ctx.is_accum_phase ? "accum" : "local");
    fflush(stdout);
    // <---- END PHASE 1.5 ---->
    // <---- PHASE 2: CONSTRAINT CONTINUE MODE ---->
    if (std::getenv("CONSTRAINT_CONTINUE") != NULL) {
      return;  // Continue to next constraint
    }
    // <---- END PHASE 2 ---->
    std::stringstream ss;
    ss << "[" << ctx.cycle << "]: eqz failure at: " << loc;
    throw std::runtime_error(ss.str());
  }
}
```

And `a4_touch_mark` in `ffi.cpp`:

```118:137:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
void a4_touch_mark(ExecContext& ctx, const char* loc) {
  if (std::getenv("A4_COVERAGE_TOUCH") == nullptr)
    return;
  const PreflightCycle& cy = ctx.preflight.cycles[ctx.cycle];
  uint8_t major = cy.major;
  uint8_t minor = cy.minor;
  uint32_t h = a4_touch_hash(loc, major, minor);
  size_t idx = static_cast<size_t>(h) % kA4TouchMapSize;

  uint8_t* bitmap = ctx.is_accum_phase ? g_a4_accum_touch_bitmap : g_a4_touch_bitmap;
  if (bitmap[idx] < 255)
    bitmap[idx]++;

  if (std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr) {
    char key[4096];
    std::snprintf(key, sizeof(key), "%s|%u|%u", loc, (unsigned)major, (unsigned)minor);
    auto& vset = ctx.is_accum_phase ? g_a4_accum_touch_verbose_set : g_a4_touch_verbose_set;
    vset.insert(std::string(key));
  }
}
```

`g_a4_touch_bitmap` is a global 64 KB array (`kA4TouchMapSize = 65536`). `g_a4_touch_verbose_set` is a global `std::set<std::string>`.

### 1.4 The witgen / accum entry points (where parallelism could live)

In `ffi.cpp`, the witgen entry point is:

```380:447:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
const char* risc0_circuit_rv32im_cpu_witgen(uint32_t mode,
                                            ExecBuffers* buffers,
                                            PreflightTrace* preflight,
                                            uint32_t lastCycle) {
  LookupTables tables;
  size_t split = preflight->tableSplitCycle;
  try {
    switch (mode) {
    case kStepModeParallel: {
      auto begin1 = poolstl::iota_iter<uint32_t>(0);
      auto end1 = poolstl::iota_iter<uint32_t>(split);
      std::for_each(poolstl::par, begin1, end1, [&](uint32_t cycle) {
        stepExec(*buffers, *preflight, tables, cycle);
      });

      auto begin2 = poolstl::iota_iter<uint32_t>(split);
      auto end2 = poolstl::iota_iter<uint32_t>(lastCycle);
      std::for_each(poolstl::par, begin2, end2, [&](uint32_t cycle) {
        stepExec(*buffers, *preflight, tables, cycle);
      });
    } break;
    case kStepModeSeqForward: {
      if (std::getenv("A4_COVERAGE_TOUCH") != nullptr)
        std::memset(g_a4_touch_bitmap, 0, kA4TouchMapSize);
      if (std::getenv("A4_COVERAGE_TOUCH") != nullptr && std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr)
        g_a4_touch_verbose_set.clear();
      for (size_t cycle = 0; cycle < lastCycle; cycle++) {
        stepExec(*buffers, *preflight, tables, cycle);
      }
      …
    } break;
    case kStepModeSeqReverse: { … }
    }
  } catch (…) { … }
  return nullptr;
}
```

The Rust HAL (`prove/hal/cpu.rs`) chooses `kStepModeSeqForward` when `A4_COVERAGE_TOUCH=1` (we verified). So **the witgen step loop is single-threaded in our path**.

The accum entry point similarly has a sequential fork:

```673:725:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
    {
      nvtx3::scoped_range range("phase1");

      if (std::getenv("A4_MUTATION_CONFIG") != nullptr
          || std::getenv("A4_COVERAGE_TOUCH") != nullptr) {
        // A4: Sequential accum phase 1 to avoid data races on touch bitmap
        // and interleaved constraint_fail output (same rationale as witgen).
        if (std::getenv("A4_COVERAGE_TOUCH") != nullptr)
          std::memset(g_a4_accum_touch_bitmap, 0, kA4TouchMapSize);
        …
        for (size_t cycle = 0; cycle < lastCycle; cycle++) {
          stepAccum(*buffers, *preflight, tables, cycle);
        }
        …
      } else {
        auto begin = poolstl::iota_iter<uint32_t>(0);
        auto end = poolstl::iota_iter<uint32_t>(lastCycle);
        std::for_each(poolstl::par, begin, end, [&](uint32_t cycle) {
          stepAccum(*buffers, *preflight, tables, cycle);
        });
      }
    }
```

So `stepAccum` is also single-threaded in our path.

Accum phase 2 (prefix-sum) is `std::inclusive_scan` (sequential by the source comment: "poolstl does not support parallel inclusive_scan").

Accum phase 3 ("apply totals") is parallel:

```765:779:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
      auto begin = poolstl::iota_iter<uint32_t>(0);
      auto end = poolstl::iota_iter<uint32_t>(lastCycle);
      std::for_each(poolstl::par, begin, end, [&](uint32_t row) {
        size_t back1 = (row + lastCycle - 1) % lastCycle;
        std::array<Fp, 4> prev;
        for (size_t k = 0; k < 4; k++) {
          prev[k] = buffers->accum.get(back1, buffers->accum.cols - 4 + k);
        }
        for (size_t j = 0; j < machineColumns - 1; j++) {
          for (size_t k = 0; k < 4; k++) {
            size_t col = kUserAccumSplit + j * 4 + k;
            buffers->accum.set(row, col, buffers->accum.get(row, col) + prev[k]);
          }
        }
      });
```

But this phase **does not touch the bitmap or the verbose set** — it only manipulates the accum buffer. Each iteration reads columns `cols-4..cols` of row `back1` and writes columns `kUserAccumSplit..cols-4` of row `row` — no read/write overlap between threads.

Constraint evaluation `risc0_circuit_rv32im_cpu_poly_fp` is called in parallel from Rust:

```180:204:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/hal/cpu.rs
        (0..domain).into_par_iter().for_each(|cycle| {
            let args: Vec<*const Val> = args.iter().map(|x| (*x).as_ptr()).collect();
            let mut tot = ExtVal::ZERO;
            unsafe {
                risc0_circuit_rv32im_cpu_poly_fp(
                    cycle,
                    domain,
                    poly_mix_pows.as_ptr(),
                    args.as_ptr(),
                    &mut tot,
                )
            };
            let x = Val::ROU_FWD[po2 + EXP_PO2].pow(cycle);
            let y = (Val::new(3) * x).pow(1 << po2);
            let ret = tot * (y - Val::new(1)).inv();
            let check =
                unsafe { std::slice::from_raw_parts_mut(check.as_ptr() as *mut Val, check.len()) };
            for i in 0..ExtVal::EXT_SIZE {
                check[i * domain + cycle] = ret.elems()[i];
            }
        });
```

`poly_fp` *does not* call `a4_touch_mark` on the racy source location. We grepped: `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)` appears in `steps.cpp` (the witgen step code) but **not** in `rust_poly_fp_0.cpp`. So this parallel phase cannot be the source of the specific bit that's racing.

### 1.5 The Rust executor's thread::scope

This is the one piece of non-sequential plumbing we cannot fully exonerate. The Rust executor uses `std::thread::scope` to spawn a "segment callback" thread that consumes finalized segments from the main emulation loop via a `sync_channel`:

```227:288:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/execute/executor.rs
        let (commit_sender, commit_recv) = sync_channel(MAX_OUTSTANDING_SEGMENTS - 1);

        let initial_image = self.initial_image.clone();
        let (initial_digest, post_digest, post_image) = thread::scope(|scope| {
            let segment_callback_thread =
                scope.spawn(move || create_segments(initial_image, commit_recv, callback));

            while self.terminate_state.is_none() {
                …
                if self.segment_cycles() > segment_threshold {
                    …
                    Risc0Machine::suspend(self)?;

                    let partial_image = self.pager.commit();

                    let req = CreateSegmentRequest {
                        partial_image,
                        page_indexes: self.pager.page_indexes(),
                        input_digest: self.input_digest,
                        output_digest: self.output_digest,
                        read_record: std::mem::take(&mut self.read_record),
                        write_record: std::mem::take(&mut self.write_record),
                        …
                    };
                    if commit_sender.send(req).is_err() {
                        return Err(segment_callback_thread.join().unwrap().unwrap_err());
                    }
                    …
                }
                …
            }
            …
        })?;
```

`create_segments` is straightforward:

```128:179:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/execute/executor.rs
fn create_segments(
    initial_image: MemoryImage,
    recv: std::sync::mpsc::Receiver<CreateSegmentRequest>,
    mut callback: impl FnMut(Segment) -> Result<()>,
) -> Result<(Digest, Digest, MemoryImage)> {
    let mut existing_image = initial_image;
    let initial_digest = existing_image.image_id();

    while let Ok(req) = recv.recv() {
        let pre_digest = existing_image.image_id();
        let partial_image = compute_partial_image(&mut existing_image, req.page_indexes);

        for (idx, page) in req.partial_image.pages {
            existing_image.set_page(idx, page);
        }
        existing_image.update_digests();
        let post_digest = existing_image.image_id();

        let segment = Segment {
            partial_image,
            claim: Rv32imV2Claim { … pre_digest … post_digest … },
            read_record: req.read_record,
            write_record: req.write_record,
            …
        };
        …
        callback(segment)?;
    }
    Ok((…))
}
```

For our test guest (a tiny program — see §2 below), there's almost certainly only one segment, so the pipeline doesn't pipeline anything useful. But `thread::scope` still spawns a thread regardless. The `callback` is what ultimately invokes the witgen + accum + eval_check pipeline.

`MAX_OUTSTANDING_SEGMENTS = 5`, channel buffer size = 4. So up to 4 segments could be in flight simultaneously for larger programs. For our small program: just one.

### 1.6 What we know is deterministic

Things we have verified or are highly confident about:

- **The Python fuzzer is single-threaded** and deterministic given the same seed. Each mutation is generated by the fuzzer, written to a JSON config file, and applied to the host via `subprocess.run` (fresh process per mutation).
- **The mutation hook in the host is single-threaded** and applies the config deterministically (it just patches a specific trace cell based on the `step` / `txn_idx` keys in the JSON).
- **The `mutations` table in the campaign SQLite DB is byte-identical between Run A and Run B.** Same mutations, same order, same JSON configs.
- **The `bandit_decisions` table is byte-identical** between Run A and Run B (the bandit selector is deterministic given the same seed).
- **The Rust executor's data structures are mostly `BTreeMap`/`BTreeSet`** — ordered, deterministic iteration. We did find one `HashMap` in `execute/bigint/analyze.rs::IoCounter`, but it's only used with `entry().or_insert()` (never iterated), so it can't leak hash-seed nondeterminism.
- **The host's hot-loop containers (`std::map`, `std::set`, `std::vector`)** are all ordered, no `std::unordered_*` in the witgen path.
- **The witgen `stepExec` loop is single-threaded** when `A4_COVERAGE_TOUCH=1`. The accum phase 1 `stepAccum` loop is single-threaded under the same condition. Bitmaps are `memset(0)` at the start of each phase, populated, emitted at end.
- **Field arithmetic is exact integer math** modulo the Baby Bear prime `p = 2013265921`. No floating point in the witgen path.
- **The Poseidon2 implementation** (`execute/poseidon2.rs` and `prove/witgen/poseidon2.rs`) is straightforward sequential field arithmetic. No parallelism, no shared mutable state.

### 1.7 What is the relevance of `(major=9, minor=5)`?

In RV32IM v2, the trace has a `major` column indicating instruction class:
- `major = 0..6`: standard RISC-V instruction classes (LOAD, STORE, ALU, etc.)
- `major = 7, 8`: special cycle types (decode, control)
- `major = 9`: **Poseidon2 hashing cycles** (used for memory paging via Merkle tree)
- `major = 10..12`: BigInt, ECall, etc.

`minor = 5` within `major = 9` corresponds to one specific Poseidon2 sub-cycle (we believe `PoseidonStoreOut` based on the call-site chain in `poly_ext.rs:9226`).

So the racy constraint fires inside **Poseidon2's "store output to memory"** sub-step.

---

## 2. The test setup (what we run)

### 2.1 The guest program

A tiny RISC-V guest binary compiled from Rust. Invoked with arguments `--in1 5 --in4 10` (these are inputs to the guest). It does some computation involving the inputs and writes outputs. Probably ~10K user cycles. Small enough that the executor produces a single segment.

### 2.2 The campaign

A fuzzing campaign runs `N = 50` mutations (one per step). Each mutation:

1. The fuzzer picks a (mutation kind, target step, mutation parameters) using its bandit selector.
2. Writes a mutation config JSON to a tempfile.
3. Spawns a fresh subprocess: `risc0-host --in1 5 --in4 10` with env vars:
   - `A4_MUTATION_CONFIG=/tmp/mutation_NN.json`
   - `A4_COVERAGE_TOUCH=1`
   - `A4_COVERAGE_TOUCH_VERBOSE=1`
   - `A4_FAMILY_RESIDUE=1` (an unrelated debug feature)
   - `CONSTRAINT_CONTINUE=1` (don't throw on first constraint failure)
4. The subprocess runs the full pipeline (executor → witgen → accum → eval_check), emitting:
   - `<a4_touch_coverage>BASE64</a4_touch_coverage>` (the 64 KB bitmap as base64)
   - `<a4_accum_touch_coverage>BASE64</a4_accum_touch_coverage>`
   - `<a4_touch_verbose>["loc1|maj|min", "loc2|maj|min", …]</a4_touch_verbose>` (when verbose enabled)
   - `<a4_accum_touch_verbose>[…]</a4_accum_touch_verbose>`
   - `<constraint_fail>{…}</constraint_fail>` for each failing constraint.
5. The fuzzer parses these and writes to a SQLite DB:
   - `mutations` (the config that was applied)
   - `mutation_rewards` (a derived score)
   - `local_coverage_v2` (per-mutation, per-context first-hit tracking; key = `(constraint_loc, major, minor)`)
   - `compressed_global_coverage` (aggregate bitmap state)

The DB ends up with a row in `mutations` for each of the 50 muts, etc.

### 2.3 The reproducibility test (B7)

We run the same campaign **twice on the same node** under the same seed, producing two SQLite DBs (`*_A.db` and `*_B.db`). Then we run `B7_seed_reproducibility.py` which compares the two DBs:

- `mutations_diff`: count of rows in `mutations` that differ (expected: 0).
- `bandit_decisions_diff`: same for `bandit_decisions` (expected: 0).
- `mutation_rewards_diff`: rows in `mutation_rewards` that differ.
- `local_coverage_v2_diff`: rows in `local_coverage_v2` that differ.
- `compressed_global_coverage_diff`: rows in the aggregated bitmap table that differ.

**Pass criterion: `mutations_diff == 0 AND bandit_decisions_diff == 0 AND mutation_rewards_diff == 0`.** Coverage diffs alone don't fail the gate (but they're informative).

### 2.4 The POS testbed

We run on a university testbed called "POS". Each node is a physical Linux server. We reserve nodes via a web calendar; once reserved, we can dispatch "jobs" (which boot or reuse the node and run our binary). Node revisions matter — some have slightly different CPU microcode.

Tier S nodes (high spec, used for fuzzing): `octorand`, `meld`, `opulous`. `flare` is also a high-spec node we use as a control.

The current dispatch script (simplified):

```bash
run_node_pair() {
    local node="$1" seed="$2" sa="$3" sb="$4"
    write_manifest "$seed" "$sa" "$tmp/$sa.json"
    write_manifest "$seed" "$sb" "$tmp/$sb.json"
    dispatch "$tmp/$sa.json" "$node"   # Run A — first allocation
    dispatch "$tmp/$sb.json" "$node"   # Run B — second allocation, ~5-10 min later
}

# SPREAD plan: run 4 nodes in parallel
( run_node_pair octorand 999 octoaA octoaB
  run_node_pair octorand 999 octobA octobB ) &
( run_node_pair opulous  1000 opugA opugB ) &
( run_node_pair meld     1001 melddA melddB ) &
( run_node_pair flare    999  flareCtrlA flareCtrlB ) &
wait
```

So on each node, we run **Run A first, Run B second**, sequentially on that same node, each in its own POS allocation (under the same calendar reservation). Different nodes run in parallel.

Each "dispatch" claims the node via POS's allocation system. We're not 100% sure whether POS reboots the node between successive allocations on the same calendar entry — that's one of the things we want to investigate.

---

## 3. The bug we're investigating

### 3.1 What we observe

For each pair (A vs B), we measure:

| Pair | Node | Seed | `mutations_diff` | `mutation_rewards_diff` | `local_coverage_v2_diff` | `compressed_global_coverage_diff` | Verdict |
|------|------|------|------------------|--------------------------|---------------------------|------------------------------------|---------|
| alpha | octorand | 999 | 0 | 1 | 70 | 19 | **FAIL** |
| beta  | octorand | 999 | 0 | 0 | (not in summary) | (not in summary) | PASS |
| opulous | opulous | 1000 | 0 | 0 | 63 | 14 | PASS |
| meld | meld | 1001 | 0 | 2 | 41 | 10 | **FAIL** |
| flareCtrl | flare | 999 | 0 | 2 | 70 | 19 | **FAIL** |

Note that **opulous "passes" the gate (mutations + rewards identical) but its coverage data differs in 63 rows**. The race is firing on opulous too; it just doesn't happen to flip any reward bits in this specific 50-mutation sample.

### 3.2 The 5 racy mutations

For each FAILing pair, the differing mutation IDs and their kind/step:

```json
[
  {"pair": "alpha", "seed": 999, "racy_mutations": [
    {"mutation_id": 27, "kind": "MEM_VAL_MOD", "step": 3259,
     "delta_T_a": 0, "delta_T_b": 1,
     "reward_a": 0.1866197800, "reward_b": 0.1901660630}
  ]},
  {"pair": "beta", "racy_mutations": []},
  {"pair": "opulous", "racy_mutations": []},
  {"pair": "meld", "racy_mutations": [
    {"mutation_id": 36, "kind": "LOAD_VAL_MOD", "step": 2066,
     "delta_T_a": 0, "delta_T_b": 1,
     "reward_a": 0.1164989226, "reward_b": 0.1200664682},
    {"mutation_id": 48, "kind": "MEM_VAL_MOD", "step": 3810,
     "delta_T_a": 0, "delta_T_b": 0,
     "reward_a": 0.1312084839, "reward_b": 0.1316725797}
  ]},
  {"pair": "flareCtrl", "racy_mutations": [
    {"mutation_id": 21, "kind": "STORE_OUT_MOD", "step": 3347,
     "delta_T_a": 0, "delta_T_b": 1,
     "reward_a": 0.1264628581, "reward_b": 0.1299878912},
    {"mutation_id": 39, "kind": "INSTR_TYPE_MOD", "step": 3813,
     "delta_T_a": 0, "delta_T_b": 0,
     "reward_a": 0.1214374673, "reward_b": 0.1217110574}
  ]}
]
```

5 racy mutations in total, spread across 4 mutation kinds, 4 nodes, 5 different steps in the trace.

### 3.3 The racy verbose context

For each of the 5 racy mutations, we ran the verbose-touch diff (taking the `<a4_touch_verbose>[...]</a4_touch_verbose>` block emitted by the host for that mutation and computing symmetric set difference between A and B). **All 5 show the exact same diff**:

```json
{
  "mutation_id": 27,
  "flare_context_count": 1614,   // "flare" here means Run A
  "octo_context_count": 1615,    // "octo" here means Run B
  "extra_on_octo": [
    {"loc": "FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)",
     "major": 9, "minor": 5}
  ],
  "missing_on_octo": [],
  "delta_extra_count": 1,
  "delta_missing_count": 0
}
```

(The labels "flare"/"octo" are vestigial — they just mean "first log" and "second log" in the parser. In every case it's `A` vs `B`.)

**So:**
- Run A touches 1614 unique `(loc, major, minor)` contexts during witgen for that mutation.
- Run B touches 1615 unique contexts — exactly the same 1614 as A, plus one extra: `FieldToWord(inst_p2.zir:291)` with `major=9, minor=5`.
- The extra context is on Run B in **all 5 cases** (asymmetric, not symmetric).

### 3.4 The racy constraint

The source line `inst_p2.zir:291` is inside `FieldToWord` (a Poseidon2 helper that splits a field element into two u16 halves):

```280:298:/root/arguzz/zirgen/zirgen/circuit/rv32im/v2/dsl/inst_p2.zir
component FieldToWord(val: Val) {
  // Decompose a field element into two u16s
  public low := NondetU16Reg(val & 0xffff);
  public high := U16Reg((val - low) / 65536);
  // Check decomposition is unique
  // If low == 0, high must be < 30720, otherwise high must be <= 30719
  // Guess if low is zero
  lowIsZero := NondetBitReg(Isz(low));
  // Now check results:  Technically, prover could set low-is-zero to false even if
  // low was zero, but this only results in a stricter check of high, so it's pointless
  if (lowIsZero) {
    low = 0;                     // ← line 291, the racy constraint
    U16Reg(30720 - high);
  } else {
    U16Reg(30719 - high);
  };
  // Return as u32
  public ret := ValU32(low, high);
}
```

The generated witgen code for `FieldToWord`:

```7100:7140:/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp
FieldToWordStruct exec_FieldToWord(ExecContext& ctx, Val arg0, BoundLayout<FieldToWordLayout> layout1)   {
  // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:282)
  NondetU16RegStruct x2 = exec_NondetU16Reg(ctx, bitAnd(arg0, Val(65535)), LAYOUT_LOOKUP(layout1, low));
  // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:283)
  NondetU16RegStruct x3 = exec_U16Reg(ctx, ((arg0 - x2._super._super) * Val(2013235201)), LAYOUT_LOOKUP(layout1, high));
  // builtin Isz
  Val x4 = isz(x2._super._super);
  NondetRegStruct x5 = exec_NondetBitReg(ctx, x4, LAYOUT_LOOKUP(layout1, lowIsZero));
  // builtin Sub
  Val x6 = (Val(30720) - x3._super._super);
  ComponentStruct x7 = ComponentStruct{};
  // builtin Sub
  Val x8 = (Val(30719) - x3._super._super);
  ComponentStruct x9;
  if (to_size_t(x5._super)) {
    // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)
    EQZ(x2._super._super, "FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)");   // ← the racy touch
    // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:292)
    NondetU16RegStruct x10 = exec_U16Reg(ctx, x6, LAYOUT_LOOKUP(layout1, _2.arm0._0));
    x9 = x7;
  } else if (to_size_t((Val(1) - x5._super))) {
    // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:294)
    NondetU16RegStruct x11 = exec_U16Reg(ctx, x8, LAYOUT_LOOKUP(layout1, _2.arm1._0));
    x9 = x7;
  } else {
    …
  }
  return FieldToWordStruct{ .ret = … };
}
```

Translation:
- `arg0` = the input field element (a Baby Bear element, value in `[0, p)` with `p = 2013265921`).
- `x2 = low = arg0 & 0xffff` (the low 16 bits of `arg0`, written into a nondeterministic register).
- `x4 = isz(low)` — 1 if `low == 0`, else 0.
- `x5 = lowIsZero` register, written with `x4`.
- The `if (to_size_t(x5._super))` branch is taken iff `lowIsZero == 1` iff `arg0 & 0xffff == 0`.
- Inside the branch, `EQZ(x2, "…:291")` asserts that `low == 0` (which it must be, since the branch is only taken when `lowIsZero == 1` and the witgen sets `lowIsZero = isz(low)`).
- The **act of evaluating `EQZ(...)`** is what calls `a4_touch_mark`, which is what flips the touch bit.

So the touch bit on `inst_p2.zir:291` flips **iff `arg0 & 0xffff == 0`** for some Poseidon2 field-element input during this mutation's witgen run.

For the bit to differ between Run A and Run B, the value of `arg0 & 0xffff` must differ between the two runs — i.e., the **value of a specific Poseidon2 state element must differ between two ostensibly identical runs of the same mutation**.

### 3.5 The call chain to that constraint

From `poly_ext.rs:9226` the full callsite chain for `FieldToWord:291` is:

```
FieldToWord:291
  ← PoseidonStoreOut:302   (calls FieldToWord on prev.inner[i] for i in 0..8)
    ← PoseidonDoOut:317    (chooses StoreOut vs CheckOut)
      ← Poseidon0:478      (a Poseidon round driver)
        ← Top:83
          ← Top:24
```

So the racy bit flips inside Poseidon2 "store output to memory" — specifically when iterating the 8 output elements of the Poseidon state and decomposing them via `FieldToWord`. It flips iff one of those state elements has low-16-bits == 0.

The relevant zirgen for `PoseidonStoreOut`:

```300:314:/root/arguzz/zirgen/zirgen/circuit/rv32im/v2/dsl/inst_p2.zir
component PoseidonStoreOut(cycle: Reg, prev: PoseidonState) {
  for i : 0..8 {
    ftw := FieldToWord(prev.inner[i]);
    mw := MemoryWrite(cycle, prev.bufOutAddr + i, ftw.ret);
    AliasLayout!(mw.io.newTxn.dataLow, ftw.low.arg.val);
    AliasLayout!(mw.io.newTxn.dataHigh, ftw.high.arg.val);
  };
  isNormal := IsZero(prev.loadTxType - TxKindRead());
  outState := isNormal * StateDecode() + (1 - isNormal) * StatePoseidonPaging();
  nextState :=
    prev.hasState * StatePoseidonStoreState() +
    (1 -  prev.hasState) * outState;
  extInv := NondetExtReg(ExtInv(prev.zcheck));
  PoseidonState(GetDef(prev), nextState, 0, 0, 0, prev.mode, prev.inner, MakeExt(0))
}
```

So `prev.inner[0..8]` is the Poseidon state array. These values are populated upstream by the Poseidon2 host implementation, which is in `risc0/circuit/rv32im/src/execute/poseidon2.rs` and `risc0/circuit/rv32im/src/prove/witgen/poseidon2.rs`. Both files are pure sequential field arithmetic — no parallelism, no shared mutable state, no time-based RNG.

---

## 4. What we've already investigated and ruled out

### 4.1 Mutation-config nondeterminism — **ruled out**

`mutations_diff == 0` for all 5 racy pairs. The exact same mutation JSON is applied at the exact same step.

### 4.2 Bandit selector nondeterminism — **ruled out**

`bandit_decisions_diff == 0`. The Python bandit logic is deterministic.

### 4.3 Race on the touch bitmap during witgen — **ruled out**

`stepExec` is single-threaded when `A4_COVERAGE_TOUCH=1`. We verified by reading `ffi.cpp:401-438`. Only one thread writes to `g_a4_touch_bitmap` and `g_a4_touch_verbose_set` during witgen.

### 4.4 Race on the touch bitmap during accum phase 1 — **ruled out**

Same as above: `ffi.cpp:676-717` shows accum phase 1 is sequential when `A4_COVERAGE_TOUCH=1`. The accum bitmap (`g_a4_accum_touch_bitmap`) and verbose set are also written single-threaded.

### 4.5 Race during accum phase 3 (parallel "apply totals") — **ruled out for this bit**

Phase 3 is parallel but does not call `a4_touch_mark` and does not touch the bitmap. It only does arithmetic on the accum buffer with disjoint per-row writes.

### 4.6 Race during `poly_fp` (parallel constraint evaluation) — **ruled out for this specific bit**

`poly_fp` runs in parallel via `rayon::into_par_iter` and *does* go through some constraint checking logic, but `FieldToWord(...inst_p2.zir:291)` does not appear in the auto-generated `rust_poly_fp_0.cpp`. The touch on this specific source location is only emitted from `steps.cpp` (the witgen path), which is sequential.

(That said: `poly_fp` running in parallel could still cause **other** racy bits in `local_coverage_v2_diff` if `poly_fp` itself calls `a4_touch_mark` via `EQZ` in the generated `rust_poly_fp_*.cpp` files. We haven't fully audited that path; it's a candidate for explaining the bulk of the 41-70 `local_coverage_v2_diff` rows.)

### 4.7 Rust `HashMap` nondeterminism (random hash seed) — **ruled out**

`execute/r0vm.rs:193` uses `std::collections::BTreeMap` for memory. `pager.rs:236` uses `BTreeMap<u32, Page>`. `bigint.rs:41` uses `BTreeMap` for witness. The lone `HashMap` in `bigint/analyze.rs::IoCounter` is only used with `entry().or_insert()`, never iterated, so even though the hash seed is random, iteration order doesn't affect anything visible.

### 4.8 C++ `std::unordered_*` containers — **ruled out**

We grepped `kernels/cxx/`: only `std::map`/`std::set` (ordered), no `std::unordered_*` containers in the witgen path. The single `std::set<std::string> g_a4_touch_verbose_set` is iterated only at the end of each phase for emission (which doesn't feed back into witgen).

### 4.9 Mutation-rewards-diff is a downstream symptom, not a cause

`mutation_rewards_diff` is computed from the touch bitmap via a deterministic formula. If the bitmap differs, the reward can differ. The bitmap is the upstream cause.

### 4.10 Inc 3b → Inc 3c regression on `flare`

In an earlier campaign (Inc 3b) with a **pre-fix host** (no verbose-tracking `std::set` and no other unrelated fixes), `flare` had **0/50** divergent mutations. In the current campaign (Inc 3c) with the **patched host** that populates `g_a4_touch_verbose_set` on every touch, `flare` has **2/50** divergent mutations.

The patched host differs from the pre-fix host in:

1. **Touch-verbose `std::set<std::string>` population** — every constraint touch now does a `std::snprintf(key, 4096, ...)` and a `vset.insert(std::string(key))`. For ~10M EQZ calls per run, that's ~10M heap allocations.
2. **`INSTR_TYPE_MOD` cycle-selection fix** — added a `cycle.major <= 6` filter for that one mutation kind. Should not affect Poseidon2 paths.
3. **`MEM_VAL_MOD` byte_addr `u64` cast** — fixed an integer overflow in a debug print. Should not affect witgen semantics.
4. Some print/debug statements added to `constraint_fail` (only fires when a constraint *fails*, which is rare).

The simplest hypothesis: the **massive increase in `std::string` allocations** has perturbed the heap allocator in a way that exposes a previously-latent uninitialized-memory or pointer-dependent computation downstream.

We *cannot* test "verbose ON vs OFF" trivially because the absence of verbose tags means we can't identify which context is racing. So we'd need to compare aggregate bitmap divergence rates with verbose ON vs OFF, not per-context.

---

## 5. The directional asymmetry — strongest clue

Across all 5 racy mutations, the extra context is on Run B (the second run), not Run A (the first run). For a truly symmetric race, the expected distribution would be 50/50, so `P(5/5 same direction | symmetric race) = (½)^5 = 3.1%`.

This means one of:

1. **There's something systematically different about being "the second run" on a node**, even though each run starts as a fresh subprocess. Candidates:
   - File-system page cache is warm from Run A → faster I/O for Run B.
   - Allocator metadata in glibc may persist across processes if there's any shared memory between them (there shouldn't be, but worth checking).
   - The POS node's kernel may not be fully reset between successive allocations under the same calendar entry.
   - Any timer/clock state that affects subprocess startup.

2. **The race is symmetric but the bit-flip is monotonic** — i.e., the witgen *always* takes the branch in Run B and *never* takes it in Run A, because of some accumulated state. Unlikely but possible.

3. **There's a bug in our parser/comparison logic** that always identifies B as having the extra. We checked — `inc3c_parse_phase_delta.py` consistently passes `log_a` as `--flare-log` and `log_b` as `--octo-log`, and `B7_verbose_touch.py` computes `octo_set - flare_set` for "extra_on_octo". So "extra on B" is just "extra in the file that was passed second". If we swapped the order, the label would flip. But the SET DIFFERENCE itself is symmetric: if A had the extra in some runs, we'd see "missing_on_octo" be non-empty in those runs. It's always non-empty on `extra_on_octo` and empty on `missing_on_octo` — so it's a real asymmetry, not a labeling artifact.

**This asymmetry is the strongest clue we have. It points at something stateful between the two runs.** The two runs are in different processes (so no in-process state could leak), so the "state" must be in:
- The kernel
- The filesystem
- The hardware (CPU caches, branch predictor history, DRAM contents)
- POS's per-allocation reset behavior (if any)

### 5.1 Sub-hypothesis: B-mate inherits A-mate's heap layout via persistent kernel state

When a process exits, the kernel reclaims its pages but doesn't necessarily zero them immediately. A new process from the same binary will get ASLR'd addresses; glibc's `mmap`-based allocator will request pages from the kernel. The pages it receives may be **previously-used pages with stale contents**.

If anywhere in the host C++ or Rust code there's an **uninitialized read** (e.g., a `Vec::with_capacity(n)` followed by accessing index `i` without writing, or a `struct` field that isn't always initialized), the value read depends on whatever was previously in that page. Run A may always get one stale value (the one left there by the OS image at boot); Run B may always get a different stale value (the one left there by Run A's allocation pattern).

This would explain (a) why Run A is consistent across multiple campaigns on the same node, and (b) why Run B consistently differs by a small amount.

---

## 6. Hypotheses (ranked, with evidence for/against each)

### H1. Uninitialized memory read in the host pipeline (most likely)

**Mechanism**: Somewhere in `risc0-modified`, a buffer or struct field is read before being fully initialized. Its contents depend on heap layout (which is process-dependent due to ASLR + allocator state). The read value flows into the Poseidon2 input, occasionally producing a state element with low-16-bits == 0.

**Evidence for**:
- Each subprocess is fresh, so any nondeterminism between Run A and Run B must come from the OS/heap, not in-process state.
- The directional asymmetry (B always +1) is consistent with B inheriting some predictable heap state from A.
- The Inc 3b → Inc 3c regression on flare (0/50 → 2/50) is consistent with the verbose-set's heap pressure perturbing the allocator and changing what stale memory the witgen reads.

**Evidence against**:
- We haven't found a specific uninit read by inspection.
- A truly random uninit read would presumably affect many bits, not just one specific bucket.

**Test**: Run the host under Valgrind `--track-origins=yes --malloc-fill=0xAA --free-fill=0xBB` or build with `-fsanitize=memory` (MSan). MSan + the LLVM toolchain typically catches uninit reads cleanly.

### H2. Race in the `thread::scope` segment producer-consumer pattern

**Mechanism**: The Rust executor's `thread::scope` spawns a "segment callback" thread that runs the witgen for each segment. While the main thread keeps emulating, the segment thread runs witgen. Some shared state we haven't identified races.

**Evidence for**:
- This is the only piece of non-sequential plumbing in the data flow we have left.
- The thread is spawned regardless of segment count.

**Evidence against**:
- For our tiny guest, there's only one segment, so no pipelining occurs.
- The only data passed via the channel is `CreateSegmentRequest`, which is a self-contained value.
- `existing_image` is `MemoryImage::clone()`d into the spawned thread, so the main thread shouldn't be touching it.

**Test**: Build the host with `--cfg loom` or use ThreadSanitizer (`-Z sanitizer=thread` for Rust + `-fsanitize=thread` for C++) and re-run.

### H3. Latent race in `risc0_zkp` or `risc0_binfmt` that we haven't audited

**Mechanism**: The `risc0_zkp` crate has its own data structures, hash functions, and arithmetic. We've only audited `circuit/rv32im`. If `risc0_zkp` uses a `HashMap` with iteration somewhere on the witgen path, that would leak nondeterminism.

**Evidence for**: We haven't audited it.

**Evidence against**: `risc0_zkp` is mostly low-level field arithmetic, and the upstream RISC Zero project relies on deterministic prover output to produce verifiable proofs.

**Test**: Grep for `HashMap`/`HashSet` iteration patterns across the entire risc0 codebase.

### H4. POS node state persistence between successive allocations

**Mechanism**: POS doesn't fully reboot the node between Run A and Run B. Filesystem state, page cache, even some daemons may persist. This affects subprocess startup behavior (e.g., binary loading speed, mmap addresses).

**Evidence for**:
- The directional asymmetry is consistent with B inheriting state from A.

**Evidence against**:
- We don't yet know POS's reset behavior between allocations under the same calendar entry.

**Test**: Reserve two **separate** calendar entries for A and B (forcing full POS allocation cycle) and re-run.

### H5. CPU microcode or hardware-level nondeterminism

**Mechanism**: Some piece of the witgen uses a CPU instruction that has implementation-defined behavior (e.g., AVX-512 transient state, RDRAND, RDTSC) and produces slightly different values on different runs.

**Evidence for**:
- Different POS nodes have different microcode revisions.

**Evidence against**:
- Field arithmetic should be exact integer ops with no hardware nondeterminism.
- The race occurs on *all* nodes including ones with the same microcode.

**Test**: Pin to a single core (`taskset`), disable SMT, disable Turbo Boost; if race persists, it's not hardware-level.

### H6. Verbose-set's `std::string` heap pressure exposing a latent race

**Mechanism**: Populating `g_a4_touch_verbose_set` with ~10M `std::string`s per run dramatically perturbs the heap allocator's state. This exposes a previously-latent bug that wasn't visible without the verbose tracking.

**Evidence for**:
- Inc 3b (no verbose set) had flare 0/50; Inc 3c (with verbose set) has flare 2/50.

**Evidence against**:
- We can't easily test this without the verbose set (we need the verbose data to identify which bit is racing).

**Test**: Run with verbose ON and verbose OFF and compare aggregate `local_coverage_v2_diff` rates (not per-context, since we can't identify contexts without verbose).

### H7. Lookup-table population order leaking into the bitmap via hash collisions

**Mechanism**: The bitmap is keyed by `FNV1a(loc) ^ major ^ minor mod 65536`. If two distinct `(loc, major, minor)` tuples collide on the same bucket, the order in which they're touched might not matter for the bitmap (both contribute), but in a race, the order could matter.

**Evidence against**:
- We're using the **verbose set** (which is per-`(loc, major, minor)` not per-bucket) to identify the racy context, and it consistently points to one specific tuple.
- The `std::set` insertion is single-threaded (witgen is sequential under `A4_COVERAGE_TOUCH=1`).

---

## 7. Failed fix attempts

None yet specific to this race — we just identified it. Previous related fixes:

- We forced **`kStepModeSeqForward`** for witgen and **sequential `stepAccum`** for accum phase 1 when `A4_COVERAGE_TOUCH=1`, specifically to prevent races on `g_a4_touch_bitmap` and on `<constraint_fail>` stdout interleaving. This **did not** eliminate the race we're investigating now.
- We patched `executor.py` (the Python fuzzer wrapper) to re-emit `<a4_touch_verbose>` tags that were being swallowed by `subprocess.run`'s `capture_output=True`. This was needed to identify the racy context, but is unrelated to the underlying race.

---

## 8. What we want from external research

We want you to:

1. **Research aggressively online.** Look at the RISC Zero GitHub repos (`risc0/risc0`, `risc0/zirgen`), their issues and PRs. Look at any known nondeterminism / determinism-related issues. Look at their changelogs. Look at relevant CI tests.

2. **Look up known patterns** of latent nondeterminism in C++ codebases that:
   - Mix Rust and C++ via FFI.
   - Use `std::for_each(poolstl::par, …)` or similar parallel-stl wrappers.
   - Use rayon's `into_par_iter` on FFI calls.
   - Rely on `std::thread::scope` for producer-consumer patterns.
   - Use glibc's allocator on multi-core Linux with `MALLOC_ARENA_MAX > 1`.

3. **Think hard about the call chain** `FieldToWord:291 ← PoseidonStoreOut ← Poseidon2 ← memory paging`. The Poseidon2 hash is used in RISC Zero for the Merkle tree over RAM pages. If anywhere in the host's "pager" code there's nondeterminism in what gets hashed, that propagates here.

4. **Generate concrete experiment ideas** beyond what we've listed. Things we might not have thought of.

5. **Sanity-check our analysis.** Did we miss something obvious? Is there a simpler explanation we're not seeing?

### Specific questions

- Is there a known issue in RISC Zero v2 where Poseidon2 input data depends on heap layout?
- Is there a known issue with `std::thread::scope` + `sync_channel` + FFI callbacks producing nondeterministic results?
- Does `poolstl::par` (which is what the C++ code uses for parallel-for) have any known nondeterminism beyond standard parallel-execution semantics?
- Are there any known issues with glibc's allocator + `mmap` returning previously-used pages with stale contents?
- Is RDRAND used anywhere in the RISC Zero proving pipeline?
- Are there any known issues with the `risc0_zkp::field::baby_bear` crate or its `ExtVal` implementation?

### What to send back

Please respond with:
1. **Your best hypothesis** for the root cause, given the evidence.
2. **Specific code locations** to inspect (file paths, function names, line numbers) that we haven't already covered.
3. **Specific experiments** to run, ordered by cheapest-first / highest-information-gain.
4. **Any prior art** (RISC Zero issues, papers, blog posts) that discuss similar nondeterminism issues.

---

## 9. Reference: key files and their roles

| File | Role |
|------|------|
| `/root/arguzz/zirgen/zirgen/circuit/rv32im/v2/dsl/inst_p2.zir` | The zirgen DSL source. Line 291 is the racy constraint. |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` | Auto-generated C++ witgen step code (~30 KLOC). Contains `exec_FieldToWord`. |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/zirgen/poly_ext.rs` | Auto-generated Rust constraint polynomial. Shows full callsite chain. |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | C++ FFI shim. Contains `a4_touch_mark`, `risc0_circuit_rv32im_cpu_witgen` (witgen entry), `risc0_circuit_rv32im_cpu_accum` (accum entry). |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` | C++ witgen helpers including the `eqz` macro / EQZ that calls `a4_touch_mark`. |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/eval_check.cpp` | Wrapper around `poly_fp` for constraint evaluation. Has counters but no `a4_touch_mark`. |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/execute/executor.rs` | Rust executor. Contains the `thread::scope` segment-callback pattern. |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/execute/poseidon2.rs` | Pure Rust Poseidon2 implementation (sequential field arithmetic). |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/poseidon2.rs` | Witgen-side Poseidon2 driver (calls `on_poseidon2_cycle`). |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/hal/cpu.rs` | CPU HAL — selects witgen mode, calls `poly_fp` in parallel via `into_par_iter`. |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | Witgen entry — reads `A4_MUTATION_CONFIG` env and applies mutations to the preflight trace. |
| `/root/arguzz/a4/core/executor.py` | Python wrapper that spawns the host subprocess and parses output. |
| `/root/arguzz/a4/standalone/coverage_db.py` | SQLite schema for the campaign DB. |
| `/root/arguzz/a4/audits/B7_seed_reproducibility.py` | Compares two DBs for diff. |
| `/root/arguzz/a4/audits/B7_verbose_touch.py` | Extracts and diffs verbose-touch sets between two campaign logs. |
| `/root/arguzz/a4/pos/run_inc3c_phase_delta.sh` | The current dispatch script for the SPREAD plan. |

---

## 10. Reference: raw data from the failing pairs

### 10.1 `racy_context_summary.json`

```json
{
  "by_context": [
    {
      "loc": "FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)",
      "major": 9,
      "minor": 5,
      "occurrences": 5
    }
  ],
  "total_racy_bits": 5,
  "plan": "spread",
  "n_pairs_analyzed": 5,
  "verbose_files": 5
}
```

### 10.2 Per-pair B7 reproducibility verdicts

```json
[
  {"pair": "alpha (octorand)",     "mutations_diff": 0, "bandit_decisions_diff": 0, "mutation_rewards_diff": 1, "local_coverage_v2_diff": 70, "compressed_global_coverage_diff": 19, "verdict": "FAIL"},
  {"pair": "beta (octorand)",      "mutations_diff": 0, "bandit_decisions_diff": 0, "mutation_rewards_diff": 0, "verdict": "PASS"},
  {"pair": "opulous",              "mutations_diff": 0, "bandit_decisions_diff": 0, "mutation_rewards_diff": 0, "local_coverage_v2_diff": 63, "compressed_global_coverage_diff": 14, "verdict": "PASS"},
  {"pair": "meld",                 "mutations_diff": 0, "bandit_decisions_diff": 0, "mutation_rewards_diff": 2, "local_coverage_v2_diff": 41, "compressed_global_coverage_diff": 10, "verdict": "FAIL"},
  {"pair": "flareCtrl",            "mutations_diff": 0, "bandit_decisions_diff": 0, "mutation_rewards_diff": 2, "local_coverage_v2_diff": 70, "compressed_global_coverage_diff": 19, "verdict": "FAIL"}
]
```

Note that **opulous** has substantial coverage diff (63 rows in `local_coverage_v2`) yet **passes** the gate. The race is universal; it just doesn't always flip a reward bit.

### 10.3 The 5 racy mutations

```json
[
  {"node": "octorand", "pair": "alpha",     "mutation_id": 27, "kind": "MEM_VAL_MOD",    "step": 3259, "delta_T_a": 0, "delta_T_b": 1, "reward_a": 0.1866, "reward_b": 0.1902},
  {"node": "meld",     "pair": "meld",      "mutation_id": 36, "kind": "LOAD_VAL_MOD",   "step": 2066, "delta_T_a": 0, "delta_T_b": 1, "reward_a": 0.1165, "reward_b": 0.1201},
  {"node": "meld",     "pair": "meld",      "mutation_id": 48, "kind": "MEM_VAL_MOD",    "step": 3810, "delta_T_a": 0, "delta_T_b": 0, "reward_a": 0.1312, "reward_b": 0.1317},
  {"node": "flare",    "pair": "flareCtrl", "mutation_id": 21, "kind": "STORE_OUT_MOD",  "step": 3347, "delta_T_a": 0, "delta_T_b": 1, "reward_a": 0.1265, "reward_b": 0.1300},
  {"node": "flare",    "pair": "flareCtrl", "mutation_id": 39, "kind": "INSTR_TYPE_MOD", "step": 3813, "delta_T_a": 0, "delta_T_b": 0, "reward_a": 0.1214, "reward_b": 0.1217}
]
```

### 10.4 Each verbose-touch diff (5 files, all identical shape)

```json
{
  "_meta": {"audit": "B7_verbose_touch", "mutation_id": <varies>, "verbose_block_index": <varies>},
  "flare_context_count": 1614,         // Run A's unique-context count for that mutation
  "octo_context_count": 1615,          // Run B's unique-context count for that mutation
  "extra_on_octo": [
    {"loc": "FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)",
     "major": 9, "minor": 5}
  ],
  "missing_on_octo": [],
  "delta_extra_count": 1,
  "delta_missing_count": 0,
  "interpretation": "single extra bit on octorand"   // means "single extra bit on Run B"
}
```

### 10.5 Verbose-tag counts per log

For each of the 50 mutations, we get 1 `<a4_touch_verbose>[…]</a4_touch_verbose>` block (49 blocks per log due to an off-by-one in capture; the parser handles this by searching `mutation_id-1` and `mutation_id-2` candidate indices). The blocks each contain ~1614-1615 unique `(loc, major, minor)` entries — that's the constraint coverage for that mutation's witgen run.

---

## 11. Summary of asks

1. **Brainstorm root causes** consistent with the observed pattern (single subprocess, single-threaded witgen path, identical mutation config, different touch coverage, directional asymmetry favoring B).

2. **Research RISC Zero v2** for known nondeterminism in the Poseidon2 / pager / executor path.

3. **Propose specific experiments** ordered by information gain.

4. **Flag any obvious-in-hindsight** issue we've missed in this analysis.

5. **Identify any prior art** — issues, PRs, papers, blog posts — about subtle nondeterminism in zkVM provers, particularly RISC Zero or similar STARK/SNARK-prover pipelines.

Thank you.
