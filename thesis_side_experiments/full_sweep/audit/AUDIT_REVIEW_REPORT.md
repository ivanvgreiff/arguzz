# E5 Acceptance Audit — Detailed Review Report

For Opus/user review of AUDIT E5 (37 fired+ACCEPTED Arguzz runs, N=250 distribution study).

## 1. Executive summary

**Audit verdict: PASS.** All acceptance gates hold after correcting the diff methodology.

- **37/37 targets classified H1** (witness structurally equivalent to clean baseline).
- **0 H2, 0 BUG** — no false accepts detected; no soundness-evasion cases in this set.
- **138/138** audit logs pulled from POS (meld, idex, tinyman); C2 completeness PASS.
- Independent verifier `status:success` reproduced for all 37 on frozen host `sha256=84ae495e…`.

## 2. POS proving run (Investigation 2 data collection)

| Item | Value |
|------|-------|
| Allocation | `ivgreiff_260614_232222_120672` |
| Nodes | meld, idex, tinyman (full run_list per node, no sharding) |
| Invocations/node | 46 (37 targets + 7 controls + baseline×2) |
| Total logs | 138 gz files under `artifacts/e5/audit_raw/` |
| Host | frozen `thesis-full-sweep-host.e0frozen` (SHA verified on-node) |
| Env | `A4_INSPECT=1 A4_DUMP_ALL_TXNS=1` + E5 constraint/residue flags |
| Wall time | ~16 min dispatch (21:22–21:38 UTC 2026-06-14) |

Runner: `pos/thesis_audit_run.sh` via `dispatch_thesis_audit.py`. All three nodes returned `await rc=0`.

## 3. Critical methodology finding — baseline txn word noise

The first analysis pass reported **FAIL** (C1/C3) and **H2=37** because `diff_traces` treated raw `word`/`prev_word` as part of the txn identity key.

**Finding:** comparing meld `baseline` vs `baseline.rerun` (no injection) shows:

- **0** cycle diffs
- **0** txn topology diffs (same txn_idx/step/type/addr/cycle keys)
- **376** txn rows where only `word`/`prev_word` differ (188 word-only + 188 prev_word cascade)

The same 752 raw txn symdiff appeared on every target vs baseline — entirely explained by this baseline noise pattern. **Semantic diff** (topology + value changes beyond noise, mapped to `cycle_idx`) fixes classification and C3 localization.

Interpretation: the A4 dump faithfully records trace rows, but BabyBear-encoded `word` values in `<a4_all_txn>` are not bit-stable across prover invocations for some rows. **Constraint-relevant structure** (cycles[], txn layout) *is* stable. See `prove/witgen/mod.rs:179` for dump source.

## 4. Gate results (corrected analysis)

- **C2_completeness**: PASS — all logs complete
- **C1_determinism**: PASS — cycles+txn topology match all nodes; baseline word noise=376 txns (excluded from semantic diff)
- **C3_controls**: PASS — 7 controls OK
- **C4_failure_signals**: PASS — all targets clean
- **C5_no_BUG**: PASS — H1=37 H2=0 BUG=0
- **C6_inv1_match**: PASS — POST_EXEC H1=30/30 INSTR_WORD H1=7/7 H2=0

## 5. Per-mechanism findings

### POST_EXEC_PC_MOD (30 targets) — all H1

- Every fault line is `pc:X => pc:X+4` (verified in raw logs).
- Semantic diff vs baseline: **empty** (0 cycle_idx changes, 0 topology changes).
- Static explanation (INV1): injection runs *after* `exec_rv32im`; for sequential non-taken instructions natural next PC is already `pc+4`, so `set_pc(pc+4)` is a trace no-op.
- Circuit has no constraint binding *provenance* of PC updates — only resulting PC/cycle sequence.

### INSTR_WORD_MOD (7 targets) — all H1

- Fault lines show `word:OLD => word:NEW` at inject sites; all verifier success, 0 constraints.
- Semantic diff vs baseline: **empty** for all 7.
- Static explanation (INV1): `DecodeInst` (`inst.zir:25-34`) loads the instruction via `MemoryRead` at PC — **committed program memory**, not the executor's mutated `word` (`rv32im.rs:656-662`). Mutations that preserve observable txn/cycle behavior under memory-decoded constraints are invisible to the prover.

| sample_id | step | fault (abbrev) |
|-----------|------|----------------|
| arguzz__INSTR_WORD_MOD__default__s0804 | 170 | word:115 => word:131187 |
| arguzz__INSTR_WORD_MOD__default__s0824 | 214 | word:30483491 => word:30483619 |
| arguzz__INSTR_WORD_MOD__default__s0852 | 271 | word:8463875 => word:10561027 |
| arguzz__INSTR_WORD_MOD__default__s0871 | 309 | word:115 => word:524403 |
| arguzz__INSTR_WORD_MOD__default__s0892 | 370 | word:1488531 => word:35042963 |
| arguzz__INSTR_WORD_MOD__default__s0905 | 422 | word:366691 => word:268802147 |
| arguzz__INSTR_WORD_MOD__default__s0914 | 453 | word:33947747 => word:33948259 |

### Positive controls (C3) — all break semantically

Named controls (s0757, s0761, s2046, s2673) show large cycle/txn structural diffs. Auto controls COMP/LOAD/STORE show value-only diffs localized to atom `cycle_idx` (e.g. COMP s0000 → cycle_idx 13624 = MemoryWrite break site).

## 6. INV1 static analysis

See **`audit/INV1_CODE_TRACE.md`** for file:line citations. Headlines:

1. **(a) Committed vs executed word:** Circuit decodes via `MemoryRead` at PC; executor may run `random_word` — divergence is intentional injection design, not a dump bug.
2. **(b) ECALL rs1:** `OpECALL` (`inst_misc.zir:224-226`) only verifies opcode/f3/f7; rs1 unconstrained → rs1 bit-flips can be H1.
3. **(c) PC overwrite:** No constraint distinguishes `set_pc` source; value-equal pc+4 overwrite is undetectable → H1 for POST_EXEC_PC.

## 7. What the first pass got wrong

| Issue | Root cause | Fix |
|-------|------------|-----|
| C1 FAIL | Compared raw word in txn key | Structural determinism + noise set |
| C3 FAIL (COMP/LOAD/STORE) | Used txn `cycle` field vs atom `cycle_idx` | Map txn_idx→cycle_idx |
| H2=37 | Conflated baseline word noise with mutation | Semantic diff excluding noise |

## 8. Residual risks / limitations

- **Encoder noise:** We exclude empirically measured baseline noise; if noise correlated with mutation (not observed here), could mask H2. All 37 targets show *identical* raw diff shape to baseline.rerun — strong evidence they are H1 not masked H2.
- **INSTR_WORD store-imm0:** Plan flagged as H2 suspect; none of the 7 accepts show semantic witness change — consistent with decode-from-memory + equivalent execution, not contradiction.
- **Step 6 relabel:** `TRIPLES_N250.md` not updated in this pass; recommend relabel 37 `(0,0,0)` entries after Opus sign-off.

## 9. Deliverables checklist

- [x] `audit/build_run_list.py`, `run_list.json` (37 targets + 7 controls + baseline×2)
- [x] `pos/thesis_audit_run.sh`, `prepare_audit_bundle.sh`, `dispatch_thesis_audit.py`
- [x] `artifacts/e5/audit_raw/*.gz` (138 files)
- [x] `audit/parse_trace.py`, `audit/analyze_audit.py` (semantic diff)
- [x] `audit/diffs/*.json` (37 target diffs)
- [x] `audit/INV2_REPORT.md`, `audit/AUDIT_SUMMARY.md`
- [x] `audit/INV1_CODE_TRACE.md`
- [x] This report

## 10. Conclusion for thesis

The 37 fired+ACCEPTED Arguzz outcomes are **verified real** on the frozen host. They are not parser false positives (C4 clean, controls work). They are not nondeterministic artifacts (C1 structural PASS). Each acceptance is **H1**: the mutation does not change the constraint-relevant witness relative to a clean run.

This does **not** prove the circuit is fully sound — it proves these particular acceptances are explainable without accusing the E5 pipeline of mislabeling.
