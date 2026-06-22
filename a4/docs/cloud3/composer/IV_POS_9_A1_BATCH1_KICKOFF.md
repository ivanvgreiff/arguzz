# Composer Kickoff — A1.B1: MODE-2 existence proof + canonical trigger

**Parent spec:** [`../IV_POS_9_A1_VULN_BUILD_SPEC.md`](../IV_POS_9_A1_VULN_BUILD_SPEC.md) §3 · **Batch:** A1.B1 (first batch of Track A) · **Status:** READY
**Mechanism authority:** [`../BUG_MECHANISM_VERIFIED.md`](../BUG_MECHANISM_VERIFIED.md) · **Gate this batch satisfies:** **G9**.
**Reviewer:** Opus (review after this batch before A1.B2/B3 conclusions are trusted).

---

## 0. Objective (one paragraph)
Use the **original Arguzz fuzzer (MODE 2)** to **re-find the known RISC Zero soundness bug** (CVE-2025-52484 / #3181, the same-source-register `rs1==rs2` double-read divergence) at the vulnerable commit `98387806`, and prove the commit pair brackets the fix. This is the cheapest, already-wired confirmation that our target is genuinely vulnerable — it must pass **before** we invest in the MODE-1 back-port (A1.B2). The batch's other product is the **canonical trigger record**: the exact (instruction shape, diverged operand, accept-of-wrong manifestation) that A1.B3 and A2 will reproduce.

## 1. Context you need (self-contained)
- **The bug:** an instruction encoding `rs1==rs2` (e.g. `remu x3,x5,x5`) causes two unconstrained reads of one register in one cycle pre-fix; a malicious prover makes the second read diverge and recomputes the result, so only the missing second-read memory constraint is violated. **The exploit witness is coherent** (`read_rs2≠read_rs1` AND result recomputed) — MODE-2's during-execution injection produces this naturally. (Full detail in the mechanism doc.)
- **MODE 2 is already wired for this commit.** `projects/risc0-fuzzer/risc0_fuzzer/settings.py:7-23` lists `98387806…` in `RISC0_AVAILABLE_COMMITS_OR_BRANCHES`; `injection_sources/rv32im_rs_9838780.py` is the frozen vulnerable `rv32im.rs` with injection hooks, selected by commit hash in `injection_sources/__init__.py:26-27` and applied during install by `zkvm_repository/injection.py:18-43`. The metamorphic oracle is `RUST_GUEST_CORRECT_VALUE = 0xDEADBEEF` (`settings.py:36`); soundness = output divergence under injection with the proof still accepted (`libs/zkvm-fuzzer-utils/zkvm_fuzzer_utils/fuzzer.py:447-464`).
- **Toolchain:** `RUST_TOOLCHAIN_VERSION = "1.85.0"` (`settings.py:25`); build per `projects/risc0-fuzzer/Dockerfile` (rzup toolchain + system deps). `RISC0_ZKVM_GIT_REPOSITORY` is the DanielHoffmann91 fork.

## 2. Deliverables
1. A successful **MODE-2 fuzzing run at `98387806`** that records at least one soundness finding (output-divergence-with-acceptance) on an `rs1==rs2` `remu`/`divu` op.
2. **`a1b1_canonical_trigger.md`** — the trigger contract: the instruction shape (proving `rs1==rs2`), the diverged operand/read, the diverged value, the honest vs faulted committed output, and the seed/inputs.
3. **MODE-2 pre/post-fix record**: `checked_findings.csv` from `check` at `98387806` (expect `fixed=False`) and at `67f2d81` (the #3181 fix; expect `fixed=True`).

## 3. Steps
1. **Build/install vulnerable risc0 (MODE 2).** In the risc0-fuzzer container:
   `risc0-fuzzer install <vuln_dir> --commit-or-branch 98387806fe8348d87e32974468c6f35853356ad5 --zkvm-modification -v2`
   Confirm the install overwrote `…/rv32im/src/execute/rv32im.rs` with the frozen `rv32im_rs_9838780.py` content (the injection harness) and patched the Cargo.tomls + assertion gates (`injection.py:18-140`).
2. **Re-find the bug.** `risc0-fuzzer run --commit-or-branch 98387806… --zkvm <vuln_dir> --out <find_dir> --seed <S> --fault-injection --timeout <T> -v2`.
   - If the random scheduler does **not** surface an `rs1==rs2` op within the timeout, **curate** the input: use the project generator / a guest seed that emits a same-register `remu`/`divu` (and/or `--no-schedular`). Document whatever you did to make the op appear — the race fairness later depends on knowing this.
3. **Capture the canonical trigger** from `findings.csv` + `injection.csv` + the trace: instruction shape (verify both source register fields are identical), which read was diverged, the diverged value, honest vs faulted committed output. Write `a1b1_canonical_trigger.md`.
4. **Pre/post-fix via `check`.** Run `risc0-fuzzer check <findings.csv> --commit-or-branch <c> --zkvm <dir> --out <dir>` twice — at `98387806` (expect `fixed=False`) and at `67f2d81c638bff5f4fcfe11a084ebb34799b7a89` (expect `fixed=True`) — and save both `checked_findings.csv`.

## 4. Acceptance (G9) — all must hold
- [ ] A soundness finding is recorded at `98387806` on a verified `rs1==rs2` op (output diverges under injection; proof accepted).
- [ ] `check` at `98387806` → `fixed=False`; `check` at `67f2d81` → `fixed=True`.
- [ ] `a1b1_canonical_trigger.md` fully specifies the trigger (an independent reader could reproduce it).

## 5. Guardrails / what NOT to do
- **Do not** treat a generic output divergence as the bug — it must be on an `rs1==rs2` op and must be **accepted** by the prover (a *rejected* divergence is the circuit working correctly).
- **Do not** modify the frozen `rv32im_rs_9838780.py` or the oracle — this batch *uses* the existing MODE-2 setup; changes to the injector belong to no batch (it's ground truth).
- **Do not** touch the MODE-1 (`a4/`) tree in this batch — that's A1.B2.
- **Do not** claim A1 done — G9 is one of six A1 gates.

## 6. Definition of done
The three deliverables exist, G9's three checks pass, and the canonical trigger is written in enough detail that A1.B3 can reproduce the same (instruction, diverged read, accept-of-wrong) in MODE 1. Hand the trigger record to A1.B3/A2.
