# A4 Instrumentation Back-port Scoping — `ebd64e43` (#3305, patched) → `98387806` (soundness-bug commit)

**Date:** 2026-06-21 · **Author:** D2-Opus · **Method:** git diff/apply against the three commits in `workspace/risc0-modified`; no estimates — every number below is from a command.

**Question (Ivan):** "As long as the risc0 files we modified aren't too different between our commit and the bug commit, can we just copy-paste our hooks back in? Anything else needed? How extensive is the overhaul?"

**Answer:** **Yes — overwhelmingly copy-paste.** Of the 60 files our A4 instrumentation touches, **49 apply byte-identically** onto the bug commit and **2 more auto-merge**; the entire residue is **one mechanical regex** (`steps.cpp`) + **3 tiny Rust hand-merges (1 conflict-hunk each)** + lockfile regeneration. **The hook transplant is ~1–2 hours of code work.** It is *not* an extensive overhaul. The week's real cost is rebuild + validation + the campaign itself, not the transplant.

---

## 1. The three commits
| label | commit | date | meaning |
|---|---|---|---|
| OURS | `28e53771` | — | our A4 instrumentation commit (HEAD of `risc0-modified`) |
| BASE | `ebd64e43` (#3305) | 2025-08-09 | what OURS sits on (patched: has the #3181 fix) |
| BUG | `98387806` | 2025-05-21 | last good state *before* the #3181 fix — the target to find the bug |

Our instrumentation = the diff `BASE → OURS` (60 files; +64k/-7k lines, but most "lines" are clean copies of large generated C++). The back-port = re-applying that diff onto BUG.

## 2. Mechanical results (from `git apply`)

### 2a. Strict apply (`git apply --check`, no fuzz)
**49 of 60 files apply byte-clean.** Only **11 fail** strict apply: 4× `Cargo.lock`, `steps.cpp`, `recursion/.../program.rs`, and 5 rv32im Rust files (`executor.rs`, `rv32im.rs`, `hal/mod.rs`, `witgen/mod.rs`, `preflight.rs`).

### 2b. 3-way merge (`git apply --3way`, uses blob ancestry)
3-way **auto-resolves `executor.rs` and `rv32im.rs`**. Final **unmerged set = 7 files**, with conflict-hunk counts:

| file | conflict hunks | nature | work |
|---|---:|---|---|
| `rv32im-sys/kernels/cxx/steps.cpp` | 15 | auto-generated; our diff is 100% the assert-wrapping pattern | **regex re-apply** (~15 min) |
| `rv32im/src/prove/witgen/mod.rs` | 1 | our A4_INSPECT/A4_DUMP/A4_MUTATION_CONFIG hooks vs upstream churn | hand-merge (~20 min) |
| `rv32im/src/prove/hal/mod.rs` | 1 | our SeqForward-forcing block vs upstream `cfg_if` refactor | hand-merge (~15 min) |
| `rv32im/src/prove/witgen/preflight.rs` | 1 | 1-line cycle-diff formula (`txn.cycle - prev` vs `- 1 - prev`) | hand-merge (~5 min) |
| `recursion/src/prove/program.rs` | 1 | 2-line upstream change; **recursion circuit not needed for the rv32im bug** | skip or 5 min |
| `examples/hello-world/.../Cargo.lock` | 1 | dependency lockfile | **regenerate** (cargo) |
| `risc0/zkvm/methods/cfg/Cargo.lock` | 1 | dependency lockfile | **regenerate** (cargo) |

## 3. The two things that looked scary but aren't

### 3a. `steps.cpp` (18,839 upstream lines changed) — it's a regex, not a merge
Our entire `steps.cpp` modification is **one repeated pattern**: wrap every `assert(0 && "Reached unreachable mux arm");` in a `FAULT_INJECTION_ENABLED` gate that downgrades the assert to a printf-and-continue (needed so fault injection doesn't hard-abort on unreachable mux arms). Verified: our 938 added content-lines are entirely these blocks (670 are the gate markers); **zero** `eqz`/`touch`/`a4_` tokens are added here.
- BASE `steps.cpp` has **134** such asserts; BUG `steps.cpp` has **125** — same pattern, near-same count.
- → The transform is **position-independent**: re-run the same find-and-wrap script on the bug commit's native `steps.cpp`. The 15 git-conflicts are an artifact of position-based patching, not real semantic conflicts.

### 3b. Constraint-coverage transfers for *free*
The touch/coverage mechanism (`a4_touch_mark`, the `eqz()` wrapper, the `EQZ` macro) lives entirely in **`witgen.h`**, which **applies byte-clean** (0 upstream churn). The bug commit's native `steps.cpp` already issues **1868 `EQZ()` calls** (BASE: 1912). Once our `witgen.h` is in place, every one of those routes through the instrumented `eqz()` → coverage works automatically. **No `steps.cpp` work for coverage.**
- *Caveat:* the constraint-loc **universe differs** at the bug commit (different circuit → different EQZ sites/line numbers). That's fine for bug-finding (we need the accept/reject oracle, not identical loc IDs), but the D2.H coverage *numbers* are not comparable across commits.

## 4. The heavy hooks all copy-paste clean
The load-bearing C++ instrumentation applies **byte-identically** (0 upstream churn): `ffi.cpp` (447 lines: `touch_bitmap`, `a4_touch_mark`, `A4_GLOBAL_RESIDUE`, `A4_TRACE_TXN`, `eqz_wrap`, `a4_base64_encode`), `witgen.h` (the EQZ/touch macro), `eval_check.cpp`, `tables.h`, `buffers.h`, and all recursion/keccak `step_*.cpp`. These handwritten kernel files simply did not change upstream between May and Aug 2025.

## 5. "Anything else?" — beyond the textual hook transplant
1. **Toolchain: no work.** `RUST_TOOLCHAIN_VERSION = 1.85.0`; the bug commit (May) is *after* the toolchain bump (`4c65c85a`, March) → already matches our build.
2. **Rebuild `risc0-host` at the bug commit** (`cargo build --release`). This regenerates the 4 conflicting `Cargo.lock`s automatically (re-add the `fuzzer_utils` path dep). Build wall-time, not engineering effort.
3. **a4/ Python harness:** it parses the host's stdout tags (`A4_INSPECT`, `A4_DUMP*`, constraint-failure lines) emitted by our `witgen/mod.rs` hooks. Since those hooks are re-applied, the output **format is preserved** and the harness should run unchanged. Two checks: (a) re-validate the **smoke oracle** (currently 8/0/0) at the bug commit; (b) confirm nothing in the harness hardcodes a specific `constraint_loc` from the patched circuit (it parses dynamically, so low risk).
4. **Build the bug-targeting guest:** a guest containing a 3-register op with `rs1 == rs2` (e.g. inline-asm `remu x3, x5, x5`). The current guest has `remu` but only with distinct source registers, so it can't trigger the bug.
5. **Validate the bug is live:** after build, confirm a mutation that exploits the missing same-register constraint is **ACCEPTED** (the soundness signal) — i.e. the oracle that reports 0 accepts on the patched tree now reports >0 on the bug commit.

## 6. Loose ends (honest)
- **Uncommitted change:** `risc0-modified` has 1 dirty working-tree file, `rv32im/src/prove/witgen/mod.rs` (on top of `28e53771`). It folds into the `witgen/mod.rs` merge already in the conflict set — no new file, but include it when porting.
- **recursion/keccak instrumentation** is in the touched set and applies clean, but is **not needed** for the rv32im soundness bug — can be dropped to simplify if desired.
- The completeness bug (`4c65c85a`, 134 commits back, March) would be a *separate, larger* back-port (more upstream churn); out of scope here.

## 7. Effort summary
| task | effort |
|---|---|
| 49 byte-clean files | 0 (automatic) |
| 2 auto-merged Rust files | 0 (automatic) |
| `steps.cpp` assert-wrap | ~15 min (regex script) |
| 3 small Rust hand-merges | ~40 min |
| lockfiles | 0 (cargo regenerates on build) |
| **CODE TRANSPLANT TOTAL** | **~1–2 hours** |
| rebuild + smoke-validate + bug guest | hours of build/run wall-time |

**Conclusion:** Ivan's intuition holds. This is a copy-paste back-port with a thin, well-localized residue, not an overhaul. The gating cost for the week is build + validation + running the campaign — not transplanting the hooks.
