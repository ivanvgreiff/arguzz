# AUDIT E5 — EXECUTABLE SPEC (Composer)

Goal: **prove, with witness-level evidence, that the 37 fired+`ACCEPTED` Arguzz runs are real.**
Rationale, hypotheses (H1/H2/BUG), and controls are in `AUDIT_ACCEPTED_PLAN.md` — read it first.
This file is the step-by-step build/run/analyze instructions.

## Hard constraints (READ FIRST)

- **All proving runs go on POS. NOTHING proves locally.** Use the user's reserved nodes only:
  **`meld`, `idex`, `tinyman`**. Do not touch any other node. (`run_e5.py`'s `RESERVED_NODES` guard does
  NOT include these three, so they are usable; the stale `--nodes` help text that says "NOT meld" is wrong —
  the authoritative guard is `RESERVED_NODES` and the N=250 run already used idex/tinyman/meld.)
- **Frozen host only.** `thesis_side_experiments/full_sweep/frozen_host/thesis-full-sweep-host.e0frozen`,
  `sha256 = 84ae495e5afd8261324d7daf09a02d1f9cb8437aad4edbb2de478362e2728b45`. On-node it lands at
  `/root/a4_campaign/bin/risc0-host`. Every runner must SHA-verify before running (the existing scripts do).
- **Do not modify anything under `workspace/`, `a4/` (except read), or rebuild the host.** Only add files
  under `thesis_side_experiments/full_sweep/audit/` and `thesis_side_experiments/pos/` (`*_audit*` files).
- **Analysis = pure log parsing** (no proving) → may run on coinbase or wherever the pulled logs are; it is
  NOT a "local prove" and is allowed.
- **Retain everything raw**: gzipped full host logs for every run, plus parsed canonical JSON. Never discard.

## The instrumentation you will use (already in the frozen host)

Setting `A4_INSPECT=1 A4_DUMP_ALL_TXNS=1` makes the host print the **complete witness** to stdout:

- `<a4_inspect_meta>{"cycles":N,"txns":M}</a4_inspect_meta>` — counts.
- `<a4_cycle_info>{"cycle_idx":I,"step":S,"pc":P,"txn_idx":T,"major":MA,"minor":MI}</a4_cycle_info>` — every cycle.
- `<a4_all_txn>{"txn_idx":N,"step":S,"txn_type":"reg|mem","addr":A,"cycle":C,"word":W,"prev_cycle":PC,"prev_word":PW}</a4_all_txn>` — every transaction.
- `<a4_all_txn_summary>{"total":T,"reg_count":R,"mem_count":M}</a4_all_txn_summary>` — totals.

Every constraint the prover evaluates is a pure function of `(cycles[], txns[])`. So **diffing this dump
clean-vs-mutated is necessary and sufficient** to decide an acceptance (see plan §1). The dump is independent
of the Arguzz executor injection (which happens earlier, in `execute/rv32im.rs::step`), so it captures the
*mutated* witness when injection is on, and the clean witness when off.

Keep the existing E5 env on too (so residues/constraints are also logged for cross-check):
`CONSTRAINT_CONTINUE=1 A4_COVERAGE_TOUCH=1 A4_COVERAGE_TOUCH_VERBOSE=1 A4_FAMILY_RESIDUE=1 A4_GLOBAL_RESIDUE=1`.

Host invocations (frozen host = `$HOST`):
- **Baseline (clean):** `$HOST --trace`   (NO `--inject`, NO `A4_MUTATION_CONFIG`).
- **Arguzz mutated:** `$HOST --trace --inject --inject-step <STEP> --inject-kind <KIND> --seed <SEED>`.

The guest is fixed and deterministic, so **one** baseline witness is the reference for all 37 diffs.

---

## STEP 1 — Build the audit run-list (local, no proving)

Create `thesis_side_experiments/full_sweep/audit/build_run_list.py`. It reads
`artifacts/e5/sample_set.json` (full `site`/`inject_step`/`seed`) and `artifacts/e5/atoms_n250/` and emits
`audit/run_list.json`:

- **Targets (the 37):** every atom with `outcome_class == "ACCEPTED"` AND `fired(a)` where
  `fired(a) = "<fault" in (a.get("fault_info") or "")` for arguzz. Verify the count is **37**
  (30 `POST_EXEC_PC_MOD` + 7 `INSTR_WORD_MOD`); abort if not. For each, look up `inject_step`, `seed`,
  `mutation_type` from `sample_set.json` by `sample_id`.
- **Baseline:** one entry `{"run_id":"baseline","kind":"baseline","repeat":2}` (repeat=2 → determinism C1).
- **Positive controls (MUST break → non-empty diff):** include these known fired rejects (look up
  step/seed/kind from `sample_set.json`), and assert each has a non-empty `constraints[]` in its atom:
  - `arguzz__INSTR_WORD_MOD__default__s0757` — 32 breaks incl intrastep `MemoryWrite(mem.zir:99)` @ cycle 13640 + `DecodeInst` (same family as targets).
  - `arguzz__INSTR_WORD_MOD__default__s0761` — global-only `[0,0,1]` (tests that a global-only break still shows a txn diff).
  - `arguzz__POST_EXEC_MEM_MOD__default__s2046` — clear intrastep `MemoryWrite` changes.
  - `arguzz__POST_EXEC_REG_MOD__default__s2673` — register-write break.
  Also auto-add the first fired `CONSTRAINT_REJECT` for `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`
  (sorted by sample_id) so all break-families are represented.
- Tag each entry with `expect: "accept" | "break"` and carry `source_sid` + the atom's `constraints[]`
  cycles (for the linkage check in STEP 4).

Run it locally; commit `audit/run_list.json`. Print a summary table (targets=37, controls=N, baseline=1×2).

---

## STEP 2 — On-node audit runner

Create `thesis_side_experiments/pos/thesis_audit_run.sh` (model it on `thesis_run_e5.sh`, but it iterates
`run_list.json` and turns on the witness dump). Requirements:

- SHA-verify `$HOST` against `THESIS_HOST_SHA` (abort on mismatch). `WORK=/root/a4_campaign`,
  `HOST=$WORK/bin/risc0-host`, `MANIFEST=$WORK/thesis/audit_run_list.json`,
  `RESULTS=$WORK/thesis/e5_audit_results`. `mkdir -p $RESULTS`; `pos_upload` on EXIT trap (as in e5 script).
- Export: `CONSTRAINT_CONTINUE=1 A4_COVERAGE_TOUCH=1 A4_COVERAGE_TOUCH_VERBOSE=1 A4_FAMILY_RESIDUE=1
  A4_GLOBAL_RESIDUE=1 A4_INSPECT=1 A4_DUMP_ALL_TXNS=1`.
- **Each node runs the FULL run_list (no sharding)** — we want cross-node determinism evidence.
- For each run entry:
  - `kind=="baseline"`: cmd `[$HOST, --trace]`; if `repeat==2` run twice → `baseline.log.gz` and
    `baseline.rerun.log.gz`.
  - `kind=="arguzz"`: cmd `[$HOST, --trace, --inject, --inject-step <step>, --inject-kind <mtype>, --seed <seed>]`.
  - Save full `stdout+stderr` (decode `errors="replace"` — trace bytes can be non-utf8) gzipped to
    `$RESULTS/<NODE>__<run_id>.log.gz` (prefix with `$(hostname)` so 3 nodes don't collide).
  - `timeout 900`. On non-zero exit, still save the log and record `STATUS=ERR` in `run_summary.txt`
    (do NOT abort the whole batch).
- Write `$RESULTS/<NODE>__run_summary.txt` with one line per run.

## STEP 3 — Bundle + dispatch to POS (meld, idex, tinyman)

- Create `thesis_side_experiments/pos/prepare_audit_bundle.sh` (clone `prepare_e5_bundle.sh`): same frozen
  host + SHA gate; additionally stage `audit/run_list.json` → `thesis/audit_run_list.json`,
  `pos/thesis_audit_run.sh` → `thesis/thesis_audit_run.sh`, the control A4 configs if any control is A4
  (there are none here — all controls are arguzz — so skip), and the existing `e5_sample_set.json`.
  Output `bundles/thesis_e5_audit_*.tar.gz`. Keep the `host_sha256` assertion.
- Create `thesis_side_experiments/pos/dispatch_thesis_audit.py` (clone `dispatch_thesis_e5.py`): change the
  on-node runner to `thesis_audit_run.sh`, set `THESIS_MANIFEST=$WORK/thesis/audit_run_list.json` and
  `THESIS_RESULTS=$WORK/thesis/e5_audit_results`, and **set `THESIS_SHARD_COUNT=1` for every node** (each
  node runs the full list). Keep the `EXPECTED_HOST_SHA` gate.
- Dispatch (run on coinbase inside tmux, as the e5 path does):
  ```
  source /srv/testbed/pos/cli/venv3/bin/activate
  cd ~/arguzz
  python thesis_side_experiments/pos/dispatch_thesis_audit.py \
    --bundle ~/thesis_e5_audit_<...>.tar.gz \
    --nodes meld idex tinyman \
    --allocation-duration 0 --image debian-trixie --await --await-timeout 3600 \
    --out ~/thesis_audit_dispatch.json
  ```
  `--allocation-duration 0` = reuse the user's existing calendar reservation (do NOT create/trim calendar
  entries; the nodes are already reserved). The run is ~45 host invocations/node → expect a few minutes.
- Wait for `await rc=0`. Note: the e5 dispatch had a false-alarm exit-1 from a `tee` wrapper — judge success
  by `await rc` per node + presence of all expected logs, not only the tmux rc file.

## STEP 4 — Pull + analyze (local log-parsing, no proving)

1. **Pull:** `scp -r ivgreiff@coinbase...:/root/a4_campaign/thesis/e5_audit_results/
   thesis_side_experiments/full_sweep/artifacts/e5/audit_raw/`.
2. Create `audit/parse_trace.py`: for a log, extract `<a4_inspect_meta>`, all `<a4_cycle_info>`,
   all `<a4_all_txn>`, `<a4_all_txn_summary>` into a canonical dict:
   `{"meta":{cycles,txns}, "cycles":[{cycle_idx,step,pc,major,minor,txn_idx}...],
   "txns":[{txn_idx,step,txn_type,addr,cycle,word,prev_cycle,prev_word}...]}`. Sort by `txn_idx`/`cycle_idx`.
   Also extract verifier verdict (`status:"success"`/reject), any `<constraint_fail>`/residue tokens, and the
   `<fault>` line.
3. Create `audit/analyze_audit.py` with these gates (all must PASS for a conclusive audit):
   - **C2 completeness** (per log): `len(cycles)==meta.cycles` and `len(txns)==meta.txns==summary.total`.
     If any mismatch, the dump is truncated → STOP and report (the diff would be unsound).
   - **C1 determinism**: `diff(baseline, baseline.rerun)==∅` on (cycles, txns), and the `meld` baseline ==
     `idex` baseline == `tinyman` baseline (cross-node). If any non-empty → STOP (nondeterministic witness).
   - **C3 positive controls**: for each control, `diff(control, baseline) ≠ ∅`, AND at least one differing
     txn/cycle row lies at a `cycle` listed in that control atom's `constraints[]` (proves the diff tool
     surfaces real, constraint-relevant changes and localizes correctly). If a control's diff is empty →
     STOP (the tool is blind; fix the parser/dump).
   - **C4 independent failure-signal sweep**: every target (accepted) log has verifier `status:"success"`,
     ZERO `<constraint_fail>`, and no nonzero-residue token. (Don't trust only our parser.)
   - **Classify each of the 37**: `diff(target, baseline)`:
     - empty → **H1** (witness identical → trivially valid). For POST_EXEC_PC also assert
       `new_pc == pc+4` from the `<fault>` line and that the site instruction is non-control-flow / not-taken.
     - non-empty but verifier `success` + zero residues → **H2** (changed-but-valid evasion). Record exactly
       which `(txn_idx/cycle, field)` changed; for INSTR_WORD note whether the changed bits are an
       un-constrained field (e.g. ECALL `rs1`) or a self-consistent alternative.
     - non-empty AND any constraint should fire / verifier not success → **BUG** → escalate; audit FAILS.
4. Emit `audit/INV2_REPORT.md`: the C1–C4 control results, a per-target table
   `sample_id | mechanism | new_pc/word | H1/H2/BUG | #changed_txns | changed_rows`, and the
   H1/H2 counts. Write per-target diffs to `audit/diffs/<sample_id>.diff.json`.

## STEP 5 — Investigation 1 (static, no proving): `audit/INV1_CODE_TRACE.md`

Read and cite (file:line) `execute/rv32im.rs::step`/`random_pc`/`random_word` and the circuit `.zir`
(`mem.zir` MemoryWrite/IsRead/IsCycle ≈ :99/:100/IsRead; `inst.zir` DecodeInst :29 / VerifyOpcode* :96-97;
`u32.zir` AddrDecompose :67). Produce:
1. **Mutation → trace-event table**: for `POST_EXEC_PC_MOD` and `INSTR_WORD_MOD`, exactly which
   `cycles[]`/`txns[]` fields each can change, and why.
2. **Answer, with citations:** (a) does the circuit decode the **program-memory (committed)** word or the
   executed `new_word`? (b) which instruction-word bits are constrained per opcode — does ECALL bind `rs1`?
   (c) is there any constraint that can distinguish *who/when* set the next pc, i.e. can a value-equal
   `set_pc(pc+4)` ever be caught? Use the STEP-4 diffs as corroboration.
3. **Per-mechanism H1/H2 prediction** (PC+4, ecall-rs1, store-imm0, branch/format flips) that must match the
   empirical STEP-4 classification. Any mismatch ⇒ investigate before concluding.

## STEP 6 — Verdict + relabel

Write `audit/AUDIT_SUMMARY.md`: pass/fail of all gates, H1/H2/BUG counts, and the conclusion (acceptances
real? any H2 worth escalating?). Only if zero BUG and all gates pass: update `TRIPLES_N250.md`/write-ups to
relabel the 37 `(0,0,0)` as **"verified — none broken (H1 no-op / H2 evasion)"** with a footnote to this audit.

## Acceptance gates (the whole audit PASSES only if)

1. C2 completeness PASS for every log. 2. C1 determinism PASS (rerun + cross-node). 3. C3 every positive
control diff non-empty AND cycle-localized. 4. C4 zero failure signals in all 37. 5. All 37 ∈ {H1,H2},
zero BUG. 6. STEP-5 static predictions == STEP-4 empirical for every mechanism. 7. Verifier `success`
reproduced for all 37 on the frozen host.

## Deliverables

`audit/build_run_list.py`, `audit/run_list.json`, `pos/thesis_audit_run.sh`, `pos/prepare_audit_bundle.sh`,
`pos/dispatch_thesis_audit.py`, `audit/parse_trace.py`, `audit/analyze_audit.py`, `audit/INV2_REPORT.md`,
`audit/diffs/*.json`, `audit/INV1_CODE_TRACE.md`, `audit/AUDIT_SUMMARY.md`, and the retained
`artifacts/e5/audit_raw/*.log.gz`. Report which gates passed/failed and the H1/H2/BUG tally.
