# Phase 7d Inc 3d — B7 race root-cause investigation (work order / plan)

**Date:** 2026-06-11
**Owner:** Opus (this conversation) + Composer (when POS work resumes)
**Successor to:** Inc 3c (`PHASE_7D_INC3C_REPORT.md` — flagged the racy context but did not close B7)
**Goal:** Close B7 by either (a) eliminating the race or (b) proving it is a measurement-pipeline artifact and fixing the pipeline.

---

## Context

Inc 3c (Composer's Phase δ) parsed 5 racy mutations across `octorand`, `meld`, `flare`, all clustering on a single constraint context:

> `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)`, `major=9, minor=5`

with a **directional asymmetry**: all 5 racy pairs show the extra context on the **B-mate** (the second of the two runs), never on the A-mate.

Two facts complicated immediate closure:
1. `flare` regressed from 0/50 (Inc 3b, pre-fix host, no verbose tracking) to 2/50 (Inc 3c, patched host with `std::set<std::string>` verbose tracking).
2. `local_coverage_v2_diff` is non-zero on **every** pair, including `opulous` which "passed" the mutations+rewards gate.

We sent a self-contained briefing (`PHASE_7D_INC3C_EXTERNAL_REVIEW.md`) to a fresh ChatGPT conversation. Their strongest counter-hypothesis was: **before chasing RISC Zero internals, rule out a measurement-pipeline artifact.** Specifically:

- `B7_verbose_touch.py` finds 49 verbose blocks per log but the campaign has 50 mutations.
- The parser compensates by trying `mutation_id-1` and `mutation_id-2` as candidate block indices, picking the smallest non-empty diff.
- This is exactly the kind of pipeline that can manufacture a stable "B has one extra rare context" pattern even when raw subprocess output is identical.

ChatGPT's ranked hypotheses:
1. **Verbose-block / mutation-block misassociation in the parser** — the directional asymmetry is naturally explained by a deterministic parser offset.
2. **In-process UB / uninitialized buffer / skipped writes in a mutated path** (not cross-process stale heap — anonymous `mmap` pages are zeroed on Linux per `man 2 mmap`).
3. **Verbose `std::set<std::string>` as a perturbation amplifier**, not the root cause.
4. **Unlikely**: RISC Zero Poseidon2 / BabyBear bug. They couldn't find a matching public issue.

Plus very actionable suggestions (self-identifying tags, raw-subprocess reproducer, targeted `FieldToWord:291` logging, boundary hashes, sanitizer builds).

We agreed with their priority ordering. **Phase A (measurement audit) runs on the current workspace with no zkVM changes; Phase B (instrumentation) requires a new branch in `workspace/risc0-modified/`; Phase C (sanitizer builds) is contingent on B's results.**

---

## Phase A — measurement-chain audit (NO zkVM changes, current workspace)

### A1. Parser audit
- **Files:** `a4/audits/B7_verbose_touch.py`, `a4/audits/inc3c_parse_phase_delta.py`.
- **Questions:**
  - Why does each log have 49 `<a4_touch_verbose>` blocks for 50 mutations? Is the missing block the baseline pre-loop run, or one of the 50?
  - Is the off-by-one identical between A and B logs (good — comparing same mutations) or different (bad — comparing different mutations)?
  - When `_candidate_block_indices` returns 2 candidates and `min(hits, key=...)` picks the smaller diff, can that systematically introduce a non-empty diff where none exists in the raw data?
- **Deliverable:** add to `PHASE_7D_INC3D_REPORT.md` §A1 — block count per log per mutation, candidate-index distribution, conclusion on whether the parser is sound.

### A2. Raw-log inspection
- **Files:** `a4/audits/audit_output/inc3c/pos_inc3c_phase_delta_zoned_seed999_n50_{octoaA,octoaB,flareCtrlA,flareCtrlB}.log`.
- For each log:
  - Count `<a4_touch_verbose>` and `<a4_accum_touch_verbose>` blocks.
  - For each block, parse it and record `(block_idx, n_contexts)`.
  - Compare A vs B: if both have same block count and same `n_contexts` per block, the symmetric diff at each block index is meaningful. If counts mismatch, the parser is making things up.
- **Deliverable:** §A2 — table of `(block_idx, n_ctx_a, n_ctx_b, diff)`.

### A3. Standalone reproducer (the decisive experiment)
- **Setup:**
  - Patched host: `/root/arguzz/workspace/output/target/release/risc0-host` (sha256 `c2e77443…`, matches Inc 3c bundle).
  - Guest: `/root/arguzz/workspace/output/target/riscv-guest/risc0-methods/risc0-guest/riscv32im-risc0-zkvm-elf/release/risc0-guest.bin`.
  - Mutation config: reconstruct **mutation 27** from `pos_inc3c_phase_delta_zoned_seed999_n50_octoaA.db` (the racy alpha mutation: `MEM_VAL_MOD step=3259`).
- **Run 100×:**
  ```bash
  for i in $(seq 1 100); do
    A4_MUTATION_CONFIG=/tmp/mut27.json \
    A4_COVERAGE_TOUCH=1 \
    A4_COVERAGE_TOUCH_VERBOSE=1 \
    A4_FAMILY_RESIDUE=1 \
    CONSTRAINT_CONTINUE=1 \
    /root/arguzz/workspace/output/target/release/risc0-host \
        --in1 5 --in4 10 > /tmp/raw_$i.log 2>&1
  done
  ```
- **Verify divergence (or not):**
  ```bash
  grep -o '<a4_touch_verbose>.*</a4_touch_verbose>' /tmp/raw_*.log | sha256sum
  grep -o '<a4_touch_coverage>.*</a4_touch_coverage>' /tmp/raw_*.log | sha256sum
  ```
  And per-file:
  ```bash
  for f in /tmp/raw_*.log; do
    echo "$f $(grep -o '<a4_touch_verbose>.*</a4_touch_verbose>' $f | sha256sum)"
  done | sort -k2 | uniq -f1 -c
  ```
- **Decision point:**
  - **All 100 identical** → race is a parser/capture artifact. Stop, fix the parser, write a small closure report. **Skip Phases B and C entirely.**
  - **≥ 1 divergent** → race is real. **Proceed to Phase B.**

### A3.1 (Free bonus, same workspace) — non-rebuild knobs
If A3 shows divergence, immediately re-run with each of these env-var combinations (no rebuild needed):
| Variant | Env | Tests hypothesis |
|---------|-----|------------------|
| `pin1`  | `taskset -c 0 RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1` | Thread interleaving / parallel-phase race |
| `arena1`| `MALLOC_ARENA_MAX=1 GLIBC_TUNABLES=glibc.malloc.tcache_count=0:glibc.malloc.arena_max=1` | glibc per-thread arena nondeterminism |
| `perturb`| `MALLOC_PERTURB_=165` | In-process uninit-read; if rate changes dramatically → UB confirmed |
| `noaslr`| run under `setarch -R` | ASLR-dependent pointer hashing |
| `noverbose`| omit `A4_COVERAGE_TOUCH_VERBOSE=1`, still set `A4_COVERAGE_TOUCH=1`, compare bitmaps only | Whether `std::set<std::string>` heap pressure is the trigger |

**Deliverable:** §A3 — 100-run hash table for vanilla, plus rate per A3.1 variant.

### A — Decision summary
| Outcome | Next action |
|---------|-------------|
| Parser artifact (A1+A2 show alignment issue and A3 vanilla all-identical) | Patch parser. Write `PHASE_7D_INC3D_REPORT.md` §"B7 closed via measurement fix". Done. |
| Real race, sensitive to thread pinning (A3.1 `pin1` eliminates) | Phase B with focus on parallel phases (poly_fp, accum phase 3, thread::scope). |
| Real race, sensitive to `MALLOC_PERTURB_` (A3.1 `perturb` changes rate) | Phase B + Phase C MSan rebuild. UB localized. |
| Real race, sensitive to verbose set (A3.1 `noverbose` eliminates) | Phase B B3 (non-allocating detector) first, then B4 (boundary hashes). |
| Real race, no env-var sensitivity | Phase B full sequence: B1 → B2 → B4 → C MSan. |

---

## Phase B — zkVM instrumentation (NEW BRANCH `arguzz/b7-race-instrumentation` in `workspace/risc0-modified/`)

**Only execute if A3 confirms real divergence.**

### B1. Self-identifying verbose blocks
- **Where:** `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp`, the two `<a4_touch_verbose>` / `<a4_accum_touch_verbose>` emission sites (lines ~426 and ~706).
- **Change:** include `mutation_config_sha256`, `pid`, and a monotonic `seq` in the open tag.
  ```cpp
  std::printf("<a4_touch_verbose mutation_sha256=\"%s\" pid=\"%d\" seq=\"%llu\">[",
              g_mut_sha, getpid(), (unsigned long long)g_seq++);
  ```
- **Parser change:** `B7_verbose_touch.py` must fail hard if (a) wrong number of blocks per log or (b) `mutation_sha256` mismatch between paired A/B blocks.

### B2. Targeted `FieldToWord:291` logging
- **Where:** `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` near line 7120 (the `if (to_size_t(x5._super))` branch).
- **Caution:** `steps.cpp` is auto-generated from zirgen. If we patch it directly, it'll be overwritten on regeneration. Either:
  - (a) Patch the codegen template in `zirgen/`, or
  - (b) Patch `steps.cpp` directly and document the patch as a one-off (acceptable for a diagnostic build).
- **Emit:**
  ```cpp
  fprintf(stderr,
    "<a4_ftw291 cycle=\"%zu\" userCycle=\"%u\" pc=\"%u\" arg0=\"%u\" low=\"%u\" high=\"%u\"/>\n",
    ctx.cycle,
    ctx.preflight.cycles[ctx.cycle].userCycle,
    ctx.preflight.cycles[ctx.cycle].pc,
    arg0.asUInt32(),
    x2._super._super.asUInt32(),
    x3._super._super.asUInt32());
  ```
- **Answers:** is the Poseidon2 input actually different between A and B, or are we comparing the wrong block?

### B3. Non-allocating racy-context detector
- **Where:** `a4_touch_mark` in `ffi.cpp`, alongside the `g_a4_touch_verbose_set` insertion.
- **Add:**
  ```cpp
  static uint64_t g_a4_ftw291_95_count = 0;  // sequential witgen, no atomic needed
  if (major == 9 && minor == 5 && strstr(loc, "inst_p2.zir:291") != nullptr)
    g_a4_ftw291_95_count++;
  ```
  Emit at end of each phase as `<a4_ftw291_95_count value="…"/>`.
- **Test:** run A3 reproducer with `A4_COVERAGE_TOUCH_VERBOSE` **off** but B3 counter on. If counts diverge → race is real and independent of the verbose set. If counts are deterministic without verbose → verbose set is the trigger.

### B4. Boundary hashes
- **Goal:** bisect *where* divergence first appears.
- **Add hash emission at:**
  1. Guest ELF digest (one-time print).
  2. Preflight `cycles[]` + `txns[]` hash **before** mutation hook.
  3. Preflight hash **after** mutation hook.
  4. `read_record` / `write_record` per segment.
  5. Pager `page_indexes()` and `compute_partial_image()` result.
  6. Poseidon2 input block per round (the 24-element state before permutation).
  7. Poseidon2 output state per round.
  8. `ExecBuffers.data` hash after `stepExec` per cycle (or summed-over-cycles).
- **Where:** `prove/witgen/mod.rs` for steps 2-3, `prove/witgen/poseidon2.rs` for steps 6-7, `ffi.cpp` for steps 4-5 and 8.
- **Hash function:** Blake3 (fast, no allocations).
- **Test:** run A3 reproducer twice, diff the boundary-hash lists. The first differing hash tells us which stage introduces nondeterminism.

### B5. Optional — synchronous executor
- **Where:** `prove/execute/executor.rs:227-232` `thread::scope`.
- **Change:** for single-segment runs (which our tiny guest is), call `create_segments` synchronously in the main thread (no `scope.spawn`). Guard behind env var `A4_NO_THREAD_SCOPE=1`.
- **Test:** if B4 shows divergence introduced at/after segment finalization, this would localize whether the `thread::scope` boundary itself is the issue.

---

## Phase C — sanitizer rebuilds (contingent on B)

### C1. MSan (`-fsanitize=memory -fsanitize-memory-track-origins=2`)
- Definitive on uninitialized reads.
- Requires rebuilding all C++ deps with MSan and Rust with `-Z sanitizer=memory` (nightly toolchain).
- **Trigger:** if B4 points to a witness-buffer or `ExecBuffers` divergence we can't pin down.

### C2. TSan (`-fsanitize=thread`)
- Definitive on data races.
- Same rebuild cost.
- **Trigger:** if B5 + B4 indicate the `thread::scope` boundary matters.

---

## Branch + repo hygiene

- **Phase A:** stay on `main` of `/root/arguzz`. No new branch.
- **Phase B/C:** user creates `arguzz/b7-race-instrumentation` in `workspace/risc0-modified/` (the risc0 fork). Diagnostic-only changes; not for merging into mainline. After Phase A confirms a real race, we'll prep an `INC3D_BUNDLE` from this branch for any POS re-run.
- **Reports:** consolidate findings in `a4/docs/cloud1/composer/PHASE_7D_INC3D_REPORT.md` as we go. Append per-phase sections (§A1, §A2, §A3, §B1, etc.).

---

## TODOs

- [x] A1 — parser audit (`B7_verbose_touch.py`, `inc3c_parse_phase_delta.py`) — sound, `_candidate_block_indices` heuristic is acceptable for this dataset
- [x] A2 — raw-log block-count inspection — confirmed 49/50 mismatch is due to `PRE_EXEC_REG_MOD step=2708` SIGSEGV, not a parser bug
- [x] A3 — 30× standalone reproducer on patched host — **all byte-identical** locally
- [x] A3.1 — env-var variants (pair-concurrent, mut21, mut27) — **all byte-identical** locally (70 effective observations, 0 divergences)
- [x] Decision: parser artifact vs real race — **real race, POS-environment-specific, not WSL2-reproducible**
- [x] Create `arguzz/b7-race-instrumentation` branch in `workspace/risc0-modified/`
- [x] B1 — self-identifying verbose blocks (`ffi.cpp`)
- [x] B2 — targeted `FieldToWord:291` logging (`steps.cpp` line 7120, gated `A4_FTW291_TRACE=1`)
- [x] B3 — non-allocating `<a4_ftw291_95_count>` counter (`ffi.cpp`)
- [x] Rebuild instrumented host (`632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1`)
- [x] Local regression — coverage/verbose body content matches pre-B1 gold (4/4 runs)
- [x] Composer handoff doc (`PHASE_7D_INC3D_B_HANDOFF.md`)
- [ ] Composer: bundle `INC3D_B_BUNDLE` and verify on POS-side
- [ ] Composer: dispatch Pass 1 (with `A4_FTW291_TRACE=1` + verbose) — same SPREAD plan as Inc 3c
- [ ] Composer: dispatch Pass 2 (without verbose, B3 counter only) — same SPREAD plan
- [ ] Opus: update `B7_verbose_touch.py` to consume B1 attributes (deferred until POS data available)
- [ ] Opus: analyze paired `<a4_ftw>` traces, identify the exact racy Poseidon2 input
- [ ] B4 — boundary hashes (deferred — try without first; B1+B2+B3 may be sufficient)
- [ ] (deferred) C1/C2 sanitizer rebuilds — only if B series can't localize
