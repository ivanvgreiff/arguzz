# Phase 7d Inc 5 — Per-Arm Evidence Pack (E5) — Composer Work Order

**From:** Opus
**To:** Composer
**Status:** Locked work order. Do NOT modify scope without escalation.
**Contract:** Execute end-to-end. Ping once at completion with the standard format. No intermediate pings.
**Process reference:** `a4/docs/cloud1/composer/PHASE_7D_INC5_PROCESS.md`

---

## 0. TL;DR

**Goal**: produce 48 per-arm evidence files (`audit_output/per_arm_evidence/<kind>_<zone>.md`) showing each kept arm's correctness with concrete worked examples, plus an index and a summary JSON.

**Single command** to run the entire pipeline (after preflight passes):

```bash
bash a4/audits/inc5_e5_pipeline.sh
```

**Acceptance gate**: every kept arm has an `.md` file with EXAMPLE 1 (✓ CORRECT) populated; aggregate verdict per arm is ✓; index `README.md` exists; summary JSON has `verdict: PASS`. The pipeline prints `INC5 GATE: PASS` at the end.

**Wall time estimate**: ~3 hours total (~2400 mutations + per-arm evidence generation + index build). All local on WSL — no POS needed.

**No POS dispatch in this increment.** Everything runs on WSL against `/root/arguzz/workspace/output/target/release/risc0-host` (the Inc 3 baseline binary, SHA `6873e588…`).

---

## 1. Background and scope

### What E5 is

Per Pro decision **D44** (`CLOUD1_DECISIONS_FOR_PRO_R2.md`): "Per-arm human-readable evidence pack."

For each of the 48 kept arms in `EXPECTED_ARMS.md` baseline (`sha2-host @ --in1 5 --in4 10`), produce **one markdown file** containing:

1. **The arm's CLAIM**: zone meaning, kind's allowed majors, what cell the mutation targets.
2. **A concrete CORRECT example (EXAMPLE 1)**: one mutation from that arm with trace context (cycle.major/minor/pc, txns), independent re-decode confirming `cycle.major == decoded.major` (or D46 acceptance), the mutation config + hook output, the outcome (exit code, failures, reward), and a ✓ CORRECT verdict with 2-3 sentence justification.
3. **An INCORRECT example (EXAMPLE 2, IF ONE EXISTS)**: same fields, but for a row where the strict verifier flagged a mismatch. Must include the disposition category (A/B/B2/C/D/D2 from `B1_apply_disposition.py`) and a 2-3 sentence reading of why it's a documented exclusion rather than an arm-classification bug.
4. **A per-arm aggregate verdict**: ✓ / ⚠ / ✗ based on:
   - ✓ if N_CORRECT ≥ 1 AND zero rows fall outside disposition (`OTHER` count = 0).
   - ⚠ if any row falls outside disposition but matches the RACE fingerprint (cosmetic — bandit reward only).
   - ✗ if any row falls outside both disposition AND race (this is a real failure; gate FAILS).

### What E5 is NOT

- **Not a re-run of B1/B4/B7 on new data.** E5 reuses Inc 3 and Inc 4 mutation outputs. If the existing data is insufficient (e.g., an arm has <10 representative rows), E5 may run a **targeted, small** local fuzz (e.g., N=50 with kind-restricted selector) to fill that arm's row pool. This is bounded by §5.3.
- **Not a Pro-facing document.** E5 outputs are *for the user* to spot-check internally. They reference Pro-facing docs (decisions, race, disposition) but the audience is Ivan + Opus + Composer.
- **Not new audit infrastructure.** E5 reuses `B1_hook_fidelity.py` (verifier), `B4_bandit_db_traceability.py` (joined trace), and `B1_apply_disposition.py` (exclusion classifier).

### Why this is the last Inc of Phase 7d

After E5, the only remaining work is final-report writeup. Phase 8 unblocks the moment Inc 5 gate is GREEN and the final report is reviewed.

---

## 2. Inputs (consumed by the pipeline)

All paths are repo-relative.

| Input | Path | Purpose | Validated by preflight |
|---|---|---|:-:|
| Inc 3 baseline binary | `workspace/output/target/release/risc0-host` (SHA `6873e588…`) | Mutation execution + B1 verifier | ✓ SHA check |
| Inc 3 baseline DBs | `a4/runs/inc3_baseline/v{1..5}.db` | Source of per-arm mutation rows | ✓ existence + row count check |
| Inc 3 B1 disposition output | `a4/audits/audit_output/B1_inc3d_disposition.json` | Reference for OTHER classification | ✓ existence + schema |
| Inc 4 B11 DBs (POS-mirror) | `a4/runs/inc4_b11/v{1..5}.db` | Extra row pool for rare arms (esp. INSTR_WORD_MOD ones) | ✓ existence + row count |
| Inc 4 B1 disposition outputs | `a4/audits/audit_output/B1_inc4_*_disposition.json` | Pre-classified OTHER reference | ✓ existence |
| `EXPECTED_ARMS.md` baseline | `a4/docs/cloud1/EXPECTED_ARMS.md` | List of 48 kept arms + 5 dropped | ✓ parse-check via `audit_common.parse_expected_arms_baseline` |
| `GLOSSARY.md` | `a4/docs/cloud1/GLOSSARY.md` | Variable definitions referenced by every evidence file | ✓ existence |
| `B1_apply_disposition.py` | `a4/audits/B1_apply_disposition.py` | Categorize raw failures into A/B/B2/C/D/D2/RACE/OTHER | ✓ importable |

If preflight fails any of these checks, **STOP and fix the gap before dispatch**. Do NOT proceed.

---

## 3. Outputs (artifacts produced)

| Output | Path | Description |
|---|---|---|
| Per-arm evidence files | `a4/audits/audit_output/per_arm_evidence/<KIND>_<ZONE>.md` × 48 | One file per kept arm |
| Per-arm STUB files | `a4/audits/audit_output/per_arm_evidence/_stubs/<KIND>_<ZONE>.md` × ~49 | One file per multi-guest-only arm (not exercised by baseline) |
| Index | `a4/audits/audit_output/per_arm_evidence/README.md` | Table of all 48 arms with ✓/⚠/✗ status + clickable links |
| Summary JSON | `a4/audits/audit_output/E5_summary.json` | Machine-readable: per-arm verdicts, gate result, source data hashes |
| Run log | `a4/audits/audit_output/E5_run.log` | Full stdout/stderr of `inc5_e5_pipeline.sh` |
| Final report | `a4/docs/cloud1/composer/PHASE_7D_INC5_REPORT.md` | Composer's wrap-up referencing the artifacts above |

---

## 4. Required scripts (Composer writes these)

These do not exist yet. Composer writes them in order:

### 4.1 `a4/audits/inc5_preflight.py` — Pre-flight validator

Pure Python, no side effects. Reads inputs from §2, exits 0 if all checks pass, exits nonzero with explicit failure list otherwise.

**Required checks** (each must print PASS/FAIL with one-line evidence):
- Host binary exists + SHA matches `6873e58812eaef6f95cd6fa0a6db97b86dcf6f31df2c39ada1ae3c2a2a55a6a4` (Inc 3 canonical baseline; verify with `sha256sum`)
- Each Inc 3 baseline DB exists, has ≥ 200 rows in `mutations`, has all expected tables (`bandit_decisions`, `mutation_rewards`, `hook3_raw`)
- Each Inc 4 B11 DB exists, has ≥ 500 rows
- `B1_inc3d_disposition.json` schema check (top-level `summary`, `per_variant`, `needs_review`)
- `EXPECTED_ARMS.md` parses cleanly via `parse_expected_arms_baseline`, returns ≥ 48 kept arms
- `GLOSSARY.md` exists and is non-empty
- `B1_apply_disposition.py` imports cleanly and `categorize({})` returns a valid category
- Disk space ≥ 2 GB free in `a4/audits/audit_output/`
- `pytest a4/standalone/tests/ -q` exits 0 (no regressions)

Print final line: `INC5 PREFLIGHT: PASS` (or `INC5 PREFLIGHT: FAIL — N issues`).

Estimated size: ~200 LOC.

### 4.2 `a4/audits/E5_per_arm_evidence.py` — Evidence generator

For each arm in `EXPECTED_ARMS.md` baseline `### Kept arms (48)`:

1. Load all candidate mutation rows for this arm from Inc 3 DBs (`SELECT … WHERE kind=? AND step IN (…)` using zone classifier to find matching steps).
2. If row pool < 10, augment from Inc 4 B11 DBs.
3. If row pool still < 5, run a **bounded targeted fuzz** (max N=50, single-kind selector, seeded `INC5_SMOKE_SEED=20260613`) writing to a temp DB. This is the ONLY case where Inc 5 generates new mutations.
4. For each candidate row, run `verify_sample()` from `verify_mutation_semantics.py` strict mode. Categorize result via `B1_apply_disposition.categorize()`.
5. Pick EXAMPLE 1 = first row classified `PASS` (or absent in failures list).
6. Pick EXAMPLE 2 = first row classified anything OTHER than PASS or RACE (i.e., a B1 disposition row — A/B/B2/C/D/D2). If only RACE rows exist, use one with a clear note.
7. Render markdown using the template in §6.
8. Aggregate per-arm verdict: ✓ if zero OTHER, ⚠ if any RACE, ✗ if any OTHER. **EXAMPLE 2 is informational, not gating** — what gates is the absence of OTHER rows in the candidate pool.

Estimated size: ~350 LOC.

### 4.3 `a4/audits/E5_build_index.py` — Index builder

After all evidence files exist, generate `README.md` index with:
- One-paragraph intro pointing at PHASE_7D_INC5_REPORT.md and decisions doc.
- Table of 48 arms with columns: arm name, status (✓/⚠/✗), N CORRECT, N exclusion, N RACE, N OTHER, file link.
- Footer with stub-file pointer (`_stubs/` directory for non-exercised arms).
- Summary line: `INC5 INDEX: 48/48 ✓` or detail if not all green.

Estimated size: ~100 LOC.

### 4.4 `a4/audits/inc5_e5_pipeline.sh` — Single-command driver

Bash script that runs the whole pipeline. **Crucially:** `set -uo pipefail` (no `-e` — we want individual step failures to be reported, not silently abort). At the end, prints `INC5 GATE: PASS` or `INC5 GATE: FAIL: <reason>`.

Sequence:
```bash
#!/usr/bin/env bash
set -uo pipefail
cd /root/arguzz

LOG=a4/audits/audit_output/E5_run.log
mkdir -p a4/audits/audit_output/per_arm_evidence/_stubs

# Step 1: preflight
python3 -m a4.audits.inc5_preflight 2>&1 | tee -a "$LOG"
preflight_rc=${PIPESTATUS[0]}
[[ $preflight_rc -ne 0 ]] && { echo "INC5 GATE: FAIL: preflight" | tee -a "$LOG"; exit 1; }

# Step 2: per-arm evidence generation (the heavy step ~2-3 hr)
python3 -m a4.audits.E5_per_arm_evidence 2>&1 | tee -a "$LOG"
evidence_rc=${PIPESTATUS[0]}
[[ $evidence_rc -ne 0 ]] && { echo "INC5 GATE: FAIL: evidence_gen" | tee -a "$LOG"; exit 2; }

# Step 3: build index + summary
python3 -m a4.audits.E5_build_index 2>&1 | tee -a "$LOG"
index_rc=${PIPESTATUS[0]}
[[ $index_rc -ne 0 ]] && { echo "INC5 GATE: FAIL: index" | tee -a "$LOG"; exit 3; }

# Step 4: stub generation for multi-guest-only arms
python3 -m a4.audits.E5_per_arm_evidence --stubs-only 2>&1 | tee -a "$LOG"

# Step 5: acceptance gate
python3 - <<'PY' 2>&1 | tee -a "$LOG"
import json, sys
s = json.load(open('a4/audits/audit_output/E5_summary.json'))
assert s['verdict'] == 'PASS', f"verdict={s['verdict']}"
assert s['n_arms_correct'] >= 48, f"only {s['n_arms_correct']}/48 arms ✓"
assert s['n_arms_incorrect'] == 0, f"{s['n_arms_incorrect']} arms ✗"
print(f"INC5 GATE: PASS ({s['n_arms_correct']}/48 ✓, {s['n_arms_warning']} ⚠, {s['n_arms_incorrect']} ✗)")
PY
```

Estimated size: ~80 lines including comments.

---

## 5. Constraints and edge cases

### 5.1 Disposition reuse (no re-classification logic)

Every classification decision must go through `B1_apply_disposition.categorize()`. Do NOT write a separate categorizer in `E5_per_arm_evidence.py`. If you find a failure that genuinely doesn't fit any category, **STOP and ping Opus** — that's a new disposition pattern and needs adjudication (like the B2 case in Inc 4), not a script-side patch.

### 5.2 GLOSSARY references mandatory (D45)

Every evidence file must reference `GLOSSARY.md` either inline (per-variable footnote) or via a top-of-file link. Use the template in §6. This is **non-negotiable** per D45.

### 5.3 Bounded targeted fuzz limits (§4.2 step 3)

If an arm has <5 candidate rows after combining Inc 3 + Inc 4 sources, you may run a targeted fuzz with these constraints:

- N ≤ 50 mutations
- Single-kind selector (e.g., `--kind LOAD_VAL_MOD` to focus the arm)
- Seeded `INC5_SMOKE_SEED=20260613` for reproducibility
- Temp DB only (`/tmp/inc5_arm_<kind>_<zone>.db`); do NOT commit
- Log the augmentation in the evidence file's metadata block ("Row pool: 48 from Inc 3 + 2 from Inc 4 + 5 from targeted fuzz seed 20260613")

If even after targeted fuzz you have <5 rows (genuine zero-bite arm), generate the file with whatever rows you have, mark verdict ⚠ "weak signal — N=X rows," and reference E2's per-arm bite report for context.

### 5.4 Multi-guest-only arms (§3 stubs)

Per D43 + EXPECTED_ARMS.md, ~49 arms exist in the codebase but are not exercised by the baseline guest (`core_sha`, `core_poseidon`, `core_other`, `pre_mret`, `post_mret`, `pre_halt`, `post_halt` zones). Generate stub `.md` files for these in `_stubs/` with a 5-line note: "NOT EXERCISED by current guest (`sha2-host @ --in1 5 --in4 10`). See `EXPECTED_ARMS.md` §Multi-guest arms and `PHASE_7D_ARCHITECTURE_AUDIT.md §6.3`. Will be re-evaluated when a second guest is added in Phase 10."

### 5.5 No POS dispatch

Inc 5 is WSL-only. If you find yourself wanting to dispatch to POS, **STOP and ping Opus** — that's a scope creep that should be its own work order. The Inc 3/4 DB pool plus bounded targeted fuzz should cover every arm without needing POS.

### 5.6 Disk and time guardrails

- Total Inc 5 disk consumption ≤ 500 MB (mostly evidence markdowns + summary JSON; targeted fuzz temp DBs are auto-cleaned).
- Total wall time budget: 5 hours hard ceiling. If the pipeline approaches 4 hours, halt and ping Opus with state. If it's running close to budget because evidence generation is genuinely slow (not a hang), let it finish.

---

## 6. Evidence file template

```markdown
# Arm `<KIND>|<ZONE>` — Per-Arm Evidence

**Status:** ✓ CORRECT (or ⚠ WEAK SIGNAL / ✗ INCORRECT)
**Audit:** Phase 7d Inc 5 — E5
**Generated:** <ISO timestamp>
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `<KIND>` — mutates `<one-line description of cell from mutation module docstring>`
- **Zone**: `<ZONE>` — defined as `<one-line description from semantic_zones.py>`
- **Allowed majors**: `<list from kind's filter>` (per `inspection_data.py:194-228`)
- **Expected step count for this guest**: `<from EXPECTED_ARMS.md>` (status: `<🟢/🟡/🔵 from EXPECTED_ARMS>`)
- **D-decisions touching this arm** (if any): D40 (multi-cycle), D42 (nondet mem-txn), D46 (ECALL 8/7), D54 (kernel_other zone), etc.

## 2. Row pool

- From Inc 3 baseline DBs: <N> rows
- From Inc 4 B11 DBs: <N> rows
- From targeted fuzz (if applicable): <N> rows, seed=20260613, kind=<KIND>
- **Total candidates**: <N>
- **Distribution**: <N> PASS, <N> exclusion (<breakdown by category>), <N> RACE, <N> OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `<DB_path>` mutation_id=<id>, variant=<variant>, step=<step>

### Trace context

| Field | Value |
|---|---|
| step | <step> |
| cycle.major | <maj> |
| cycle.minor | <min> |
| pc | `0x<hex>` |
| zone classifier | `<ZONE>` (matches arm) |
| txns at step | <list of (idx, role, addr)> |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x<hex>` | — |
| insn_decode.DecodedInsn.major | <maj> | <Y/N> |
| insn_decode.DecodedInsn.minor | <min> | <Y/N> |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `<one-line summary of config_json>` |
| Mutation effect (new_word / new_kind / etc.) | `0x<hex>` |
| Hook stdout tag | `<full tag>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: <code>
- Constraint failures: <count> (top families: <list>)
- Reward v2 components: l_new=<n>, g_new=<n>, s_new=<n>, scalar=<float>

### Verdict

✓ CORRECT. The mutation was applied to the expected cell at the expected step; the hook captured it faithfully; the trace context matches the arm's claim about which majors/zones this kind targets.

---

## 4. EXAMPLE 2 — exclusion case (if any)

**Row source**: `<DB_path>` mutation_id=<id>, variant=<variant>, step=<step>

### Disposition classification

- Category: **<A/B/B2/C/D/D2>**
- Maps to decision: <D40/D42/D46>
- Why excluded: <2-3 sentence explanation tying the failure pattern to the architectural quirk>

### Trace context, re-decode, mutation, outcome

(Same table layout as EXAMPLE 1, but for the exclusion row.)

### Verdict

⚠ EXCLUSION. This row's hook tag mismatch is a known boundary case under <D-decision>; the mutation effect itself was applied correctly (`new_word` agreement verified). Documented in `PHASE_7D_INC3D_B1_DISPOSITION.md` §<X>.

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | <n> |
| Exclusion (A/B/B2/C/D/D2) | <n> |
| RACE (informational) | <n> |
| OTHER (counts as failure) | <n> |

**Arm verdict: ✓ CORRECT** (zero OTHER rows; <n> exclusion rows fall within documented disposition framework).
```

If Composer needs to deviate from this template (e.g., extra rows in §3 to clarify a complex case), that's allowed — just keep the §1-§2-§5 structure intact so the index builder can parse aggregate verdicts.

---

## 7. Acceptance gate (the only thing that matters)

**Pipeline passes iff** `python3 -c "import json; s=json.load(open('a4/audits/audit_output/E5_summary.json')); assert s['verdict']=='PASS' and s['n_arms_incorrect']==0 and s['n_arms_correct']>=48"` exits 0.

Concretely:
- `n_arms_correct` ≥ 48 (every baseline arm has ✓ aggregate verdict)
- `n_arms_incorrect` == 0 (zero arms with ✗ — i.e., zero arms with OTHER rows)
- `n_arms_warning` may be > 0 (⚠ for weak signal or RACE-only rows is allowed)
- Index `README.md` exists and renders without errors
- Run log `E5_run.log` exists and ends with `INC5 GATE: PASS`

---

## 8. Failure modes and recovery

Pipeline can fail at preflight, evidence generation, index build, or gate check.

| Failure | What it means | What Composer does |
|---|---|---|
| Preflight FAIL (missing DB / wrong SHA) | Input data not where expected | Fix the gap (e.g., rsync DBs from coinbase). Re-run preflight. Do NOT proceed until PASS. |
| Preflight FAIL (pytest regression) | A fast test broke | STOP and ping Opus. Don't try to fix tests yourself. |
| Evidence gen crashes on a specific arm | Probably a missing zone classifier mapping or DB schema drift | Log the arm + traceback to the run log. Continue with remaining arms (the script must not abort the whole batch on one arm crash). After the run, ping Opus with the failed-arm list. |
| Evidence gen finds new OTHER classification | A failure that doesn't match A/B/B2/C/D/D2/RACE | **STOP immediately.** Do NOT extend the disposition script yourself. Ping Opus with: full row JSON, the arm, the variant, the mutation_id. This needs disposition adjudication (like Inc 4 B2). |
| Index build crashes | Probably a malformed evidence file | Identify which file via the traceback, fix the file (or regenerate just that arm), re-run index. |
| Gate check FAIL with `n_arms_incorrect > 0` | At least one OTHER row landed in an arm | Identical to "Evidence gen finds new OTHER classification" — STOP and ping Opus with the offending arm and row. |
| Pipeline hangs (no progress for 30 min) | Some long-running fuzz or DB query is stuck | Kill the process. Capture last 100 lines of log. Ping Opus with the hang context. |

In all "STOP and ping Opus" cases, **do NOT attempt a workaround**. The point of Inc 5 process is single-round resolution per genuinely-new issue. Composer attempting a fix on a disposition boundary case turns it into N rounds.

---

## 9. Composer's response to this work order

```
□ Read this work order end-to-end (this section + §0-§8).
□ Write inc5_preflight.py (§4.1). Run it. Fix any failures it reports BEFORE writing the heavier scripts.
□ Write E5_per_arm_evidence.py (§4.2). Spot-check on 2 arms manually (e.g., one
  🟢 CONFIRMED arm and one 🟡 UNCERTAIN arm) before running on all 48.
□ Write E5_build_index.py (§4.3).
□ Write inc5_e5_pipeline.sh (§4.4).
□ Run bash a4/audits/inc5_e5_pipeline.sh. Watch run log.
□ If gate PASSes: write PHASE_7D_INC5_REPORT.md (per §10), single commit of all
  Inc 5 artifacts (scripts + outputs + report), and ping Opus.
□ If gate FAILs with a recoverable issue (§8 table): recover, re-run, gate again.
□ If gate FAILs with "STOP and ping Opus" issue: ping immediately with state, do
  NOT continue.
```

## 10. Final report format (`PHASE_7D_INC5_REPORT.md`)

Composer writes this AFTER gate is PASS:

```markdown
# Phase 7d Inc 5 — Per-Arm Evidence Pack — Final Report

**Composer status:** COMPLETE. Gate: GREEN.
**Wall time:** <X> hours (preflight + evidence + index + acceptance).
**Artifacts:** 48 per-arm evidence files + index + summary JSON + run log.
**Commit:** <sha>.

## Summary

- 48/48 baseline arms ✓ CORRECT.
- <N> arms with ⚠ (weak signal — list them with reason).
- 0 arms ✗ INCORRECT.
- <N> exclusion rows total (breakdown by category A/B/B2/C/D/D2).
- <N> RACE rows total (cosmetic).
- 0 OTHER rows (disposition framework complete on this dataset).

## Anomalies

<list of anything unexpected, or "none">

## Artifact paths

- Evidence files: `a4/audits/audit_output/per_arm_evidence/*.md`
- Index: `a4/audits/audit_output/per_arm_evidence/README.md`
- Summary JSON: `a4/audits/audit_output/E5_summary.json`
- Run log: `a4/audits/audit_output/E5_run.log`
- Stubs (multi-guest-only arms): `a4/audits/audit_output/per_arm_evidence/_stubs/*.md`

## Phase 7d closure

This was the last Inc of Phase 7d. With Inc 5 GREEN:
- All 17 audits complete (A1-A5, B1-B12, E1-E5).
- Per-arm evidence available for human spot-check.
- Disposition framework empirically exhaustive on ~4000 mutations.
- Phase 8 is unblocked pending final-report writeup.

Opus to write `PHASE_7D_FINAL_REPORT.md` + flip `CLOUD1_STATUS.md` to Phase 8 READY.
```

## 11. Final ping format (the ONLY message Composer sends Opus)

```
Inc 5 closeout complete. 48/48 arms ✓ CORRECT. Gate: PASS. Commit <sha>.
Run wall time: <X>h. Artifacts at a4/audits/audit_output/per_arm_evidence/.
Anomalies: <list or 'none'>.
```

No intermediate pings. No "I'm starting step X" updates. No "should I do Y?" questions. The work order has the answer or the issue is a §8 blocker.

---

## 12. What I (Opus) will do after Composer's ping

1. Spot-check 5 evidence files (one per kind, mix of zones).
2. Verify index renders correctly.
3. Verify summary JSON matches gate result.
4. If all clean: write `PHASE_7D_FINAL_REPORT.md` (~1 day), flip CLOUD1_STATUS.md.
5. Hand off to user for Phase 8 launch decision.

If spot-check reveals issues: ONE round of corrections. We do NOT enter Inc 5b.
