# Phase 7d Inc 5 — Composer Handoff (E5 Per-Arm Evidence Pack)

**Author:** Composer (Cursor agent session, 2026-06-13/14)  
**Status:** IN PROGRESS — evidence generation **29/48 arms complete**; pipeline interrupted mid-run  
**Audience:** Future Composer sessions, Ivan, Opus  
**Primary work order:** `a4/docs/cloud1/composer/PHASE_7D_INC5_WORK.md`  
**Process contract:** `a4/docs/cloud1/composer/PHASE_7D_INC5_PROCESS.md`

---

## 1. What this increment is for (the “why”)

Phase 7d is the architecture audit that must complete before Phase 8 (the large 300k-mutation campaign). Inc 4 closed with B11/B12 GREEN. **Inc 5 is the last increment of Phase 7d.**

Inc 5 delivers **E5 — the per-arm human-readable evidence pack** (Pro decision **D44** in `CLOUD1_DECISIONS_FOR_PRO_R2.md`). The goal is not new POS runs or new audit infrastructure. It is to produce **48 markdown files** (one per *kept* arm in `EXPECTED_ARMS.md` baseline) that a human can spot-check and say: “yes, this arm’s mutations are semantically correct on this guest.”

Each evidence file must contain:

1. **Arm claim** — what the `(kind, zone)` pair means, which majors it targets, glossary link (D45).
2. **Row pool** — how many mutation rows came from Inc 3 DBs, Inc 4 B11 DBs, and (if needed) bounded targeted fuzz.
3. **EXAMPLE 1 (✓ CORRECT)** — a concrete mutation with trace context, independent re-decode, hook payload, outcome.
4. **EXAMPLE 2 (exclusion, if any)** — a row classified A/B/B2/C/D/D2/RACE via `B1_apply_disposition.categorize()`.
5. **Aggregate verdict** — ✓ if ≥1 PASS and zero `OTHER`; ✗ if any `OTHER`; ⚠ for weak signal or RACE-only.

**Acceptance gate:** `E5_summary.json` has `verdict: PASS`, `n_arms_correct >= 48`, `n_arms_incorrect == 0`. Pipeline prints `INC5 GATE: PASS`.

After Inc 5 GREEN: Opus writes `PHASE_7D_FINAL_REPORT.md`, flips `CLOUD1_STATUS.md` to Phase 8 READY. **No calendar/POS reservation is needed for Inc 5** — everything is WSL-local against the Inc 3 canonical host binary and existing Inc 3/4 DB mirrors.

---

## 2. Architectural context (how E5 fits the audit stack)

E5 **reuses** existing audit tooling; it does not invent new classifiers:

| Tool | Role in E5 |
|---|---|
| `a4/tools/verify_mutation_semantics.py::verify_sample()` | Strict B1 verifier per candidate row (runs host with `A4_MUTATION_CONFIG`) |
| `a4/audits/B1_apply_disposition.py::categorize()` | Post-hoc exclusion taxonomy (A/B/B2/C/D/D2/RACE/OTHER) — **mandatory**; never reimplement |
| `a4/audits/audit_common.py` | `parse_expected_arms_baseline()`, `load_inspection()`, paths |
| `a4/standalone/zone_classifier.py` | Zone at step for trace tables |
| `a4/core/insn_decode.py` | Independent re-decode of instruction word at PC |
| Inc 3 DBs `a4/runs/inc3_baseline/v{1..5}.db` | Primary row pool (200 mut/variant, cTS_semantic_v2 / V5) |
| Inc 4 B11 DBs `a4/runs/inc4_b11/v{1..5}.db` | Augmentation for rare arms (500 mut/variant) |

**Critical rule from work order §5.1 / §8:** If `categorize()` returns `OTHER`, **STOP immediately** and ping Opus. Do not extend disposition yourself (Inc 4 B2 pattern). Composer attempting fixes turns a single-round contract into N rounds.

**Critical rule from work order §5.5:** No POS dispatch. If you think you need POS, that's scope creep — ping Opus.

---

## 3. What was done before this session (Inc 4 → Inc 5 bridge)

Inc 4 closeout was **ACCEPTED** by Opus. Key artifacts:

- B11: 2500/2500 net PASS after B2 disposition extension for V5 mut235 (`MEM_VAL_MOD` ECALL `old_word` drift).
- B12: 250/250 net PASS on both input configs.
- Commit `493765d` — Inc 4 GREEN report + B2 patch.
- POS allocation cleanup (per-node `pos allocations free -k`); §12.46 added to `POS_PLAYBOOK.md`.

Opus shipped `PHASE_7D_INC5_WORK.md`, `PHASE_7D_INC5_PROCESS.md`, and a draft `inc5_preflight.py`. Composer fixed preflight gaps before E5 work:

| Fix | Detail |
|---|---|
| Host SHA | Canonical `6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444` (Opus copy had typo `…12eaef6f…`) |
| `expected_arms` check | `parse_expected_arms_baseline()` returns `{"arms": {...}}` — must check `len(parsed["arms"])`, not `len(parsed)` |
| DB symlinks | `a4/runs/inc3_baseline/v{1..5}.db` → Inc 3 POS audit DBs; `a4/runs/inc4_b11/v{1..5}.db` → Inc 4 B11 node DBs |
| Disposition JSONs | Generated `B1_inc3d_disposition.json` (1000/1000); symlinked `B1_inc4_b11_disposition.json` |
| pytest timeout | Suite takes ~9.5 min (472 passed); raised preflight timeout from 600s → **900s** |
| `collect_inc4_b1_results.sh` | Fixed testbed find logic for `B1_V{n}.json` beside log files |

**Preflight result:** `INC5 PREFLIGHT: PASS` (19/19 checks).

---

## 4. What Composer wrote in this session (new code)

Three pipeline scripts were implemented per work order §4.2–§4.4:

### 4.1 `a4/audits/E5_per_arm_evidence.py` (~580 LOC)

**Behavior:**

1. Parse 48 kept arms from `EXPECTED_ARMS.md`.
2. For each arm `kind|zone`:
   - Load candidate rows from Inc 3 DBs via `bandit_decisions.selected_arm = kind|zone`.
   - If pool < 10, augment from Inc 4 B11 DBs.
   - If pool still < 5, run **bounded targeted fuzz** (N≤50, `--kind <KIND>`, `--selector cTS_semantic_v2`, `seed=20260613`, temp DB `/tmp/inc5_arm_<kind>_<zone>.db`).
   - For each row: `verify_sample()` → if fail, `categorize()`; `OTHER` raises `RuntimeError` (exit 3).
   - Pick EXAMPLE 1 = first PASS; EXAMPLE 2 = first exclusion or RACE.
   - Write `audit_output/per_arm_evidence/<KIND>_<ZONE>.md`.
3. Per-arm errors are caught and logged; batch continues (work order §8).
4. Writes `audit_output/E5_arm_stats.json` with per-arm counters.

**CLI flags:**

```bash
python3 -m a4.audits.E5_per_arm_evidence [--arms kind|zone ...] [--no-fuzz] [--stubs-only]
```

- `--arms` — process only listed arms (pipe-separated keys like `LOAD_VAL_MOD|core_memory_load`).
- `--no-fuzz` — skip targeted fuzz augmentation (faster debugging).
- `--stubs-only` — write `_stubs/` markdown for multi-guest-only zones (§5.4).

### 4.2 `a4/audits/E5_build_index.py` (~120 LOC)

After all 48 evidence files exist:

- Parses aggregate verdict lines from each `.md`.
- Writes `audit_output/per_arm_evidence/README.md` (48-row table).
- Writes `audit_output/E5_summary.json` with gate fields: `verdict`, `n_arms_correct`, `n_arms_warning`, `n_arms_incorrect`, `n_other_rows_total`, per-arm breakdown, source SHA256s.

### 4.3 `a4/audits/inc5_e5_pipeline.sh`

Single-command driver (`set -uo pipefail`, no `-e`):

1. Preflight → 2. Evidence gen → 3. Index → 4. Stubs → 5. Python gate assert on `E5_summary.json`.

Log: `a4/audits/audit_output/E5_run.log`.

---

## 5. Spot-check before full run

Two arms were verified manually before launching the full pipeline:

| Arm | Status in EXPECTED_ARMS | Pool | Result |
|---|---|---:|---|
| `LOAD_VAL_MOD\|core_memory_load` | 🟢 | 14 rows (4 Inc3 + 10 Inc4) | 14 PASS, ✓ |
| `LOAD_VAL_MOD\|post_ecall` | 🟡 (rare, doc says 2 steps) | 14 rows | 14 PASS, ✓ |

Wall time for 2 arms: **~10 minutes** (~28 `verify_sample` host invocations). This established ~5 min/arm as a rough planning number (varies with pool size and targeted fuzz).

---

## 6. Full pipeline run — what happened

**Command launched (background):**

```bash
bash a4/audits/inc5_e5_pipeline.sh
```

**Timeline:**

| Phase | Result |
|---|---|
| Preflight | PASS (~6 min pytest this run) |
| Evidence generation | **Started; interrupted at 29/48 arms** |
| Index / stubs / gate | **Not reached** |

**Wall time before stop:** ~4 hours 8 minutes (started `2026-06-13T23:11:51Z`, terminal ended `2026-06-14T03:19:04Z`).

**How it stopped:** Shell process ended with `exit_code: unknown` while **targeted fuzz** was running (`INSTR_WORD_MOD_SUR`, mutation 8/50 in a 50-mutation campaign). No `STOP:` / `OTHER` / `INC5 GATE: FAIL` in log. This is consistent with **session/timeout interruption**, not a disposition failure.

**Last evidence file written:** `INSTR_WORD_MOD_SUR_post_ecall.md` (mtime ~23:10 local).

---

## 7. Current artifact inventory (as of handoff)

### 7.1 Evidence files present (29/48)

```
COMP_OUT_MOD_core_arithmetic.md
COMP_OUT_MOD_core_div.md
COMP_OUT_MOD_core_mul.md
COMP_OUT_MOD_post_ecall.md
INSTR_TYPE_MOD_core_arithmetic.md
INSTR_TYPE_MOD_core_div.md
INSTR_TYPE_MOD_core_memory_load.md
INSTR_TYPE_MOD_core_memory_store.md
INSTR_TYPE_MOD_core_mul.md
INSTR_TYPE_MOD_post_ecall.md
INSTR_TYPE_MOD_pre_ecall.md
INSTR_TYPE_MOD_step0.md
INSTR_WORD_MOD_FULL_core_arithmetic.md
INSTR_WORD_MOD_FULL_core_div.md
INSTR_WORD_MOD_FULL_core_memory_load.md
INSTR_WORD_MOD_FULL_core_memory_store.md
INSTR_WORD_MOD_FULL_core_mul.md
INSTR_WORD_MOD_FULL_last_step.md
INSTR_WORD_MOD_FULL_post_ecall.md
INSTR_WORD_MOD_FULL_pre_ecall.md
INSTR_WORD_MOD_SUR_core_arithmetic.md
INSTR_WORD_MOD_SUR_core_div.md
INSTR_WORD_MOD_SUR_core_memory_load.md
INSTR_WORD_MOD_SUR_core_memory_store.md
INSTR_WORD_MOD_SUR_core_mul.md
INSTR_WORD_MOD_SUR_last_step.md
INSTR_WORD_MOD_SUR_post_ecall.md
LOAD_VAL_MOD_core_memory_load.md
LOAD_VAL_MOD_post_ecall.md
```

All 29 completed arms reported **0 OTHER** rows in spot-checks of structure; aggregate verdicts are ✓ CORRECT where generated.

### 7.2 Missing arms (19/48) — exact list

```
INSTR_WORD_MOD_SUR|pre_ecall
MEM_VAL_MOD|step0
MEM_VAL_MOD|last_step
MEM_VAL_MOD|pre_ecall
MEM_VAL_MOD|post_ecall
MEM_VAL_MOD|core_arithmetic
MEM_VAL_MOD|core_memory_load
MEM_VAL_MOD|core_memory_store
MEM_VAL_MOD|core_branch
MEM_VAL_MOD|core_mul
MEM_VAL_MOD|core_div
PRE_EXEC_REG_MOD|step0
PRE_EXEC_REG_MOD|post_ecall
PRE_EXEC_REG_MOD|core_arithmetic
PRE_EXEC_REG_MOD|core_memory_load
PRE_EXEC_REG_MOD|core_memory_store
PRE_EXEC_REG_MOD|core_mul
PRE_EXEC_REG_MOD|core_div
STORE_OUT_MOD|core_memory_store
```

**Note:** The remaining work is heavily weighted toward `MEM_VAL_MOD` (10 arms) and `PRE_EXEC_REG_MOD` (7 arms). These kinds have larger per-row verify cost and more boundary disposition cases (D42/D46) — expect exclusions in EXAMPLE 2, not necessarily gate failures, as long as `OTHER` stays zero.

### 7.3 Not yet created

| Artifact | Path |
|---|---|
| Index | `a4/audits/audit_output/per_arm_evidence/README.md` |
| Summary JSON | `a4/audits/audit_output/E5_summary.json` |
| Stub files | `a4/audits/audit_output/per_arm_evidence/_stubs/*.md` (~56: 8 kinds × 7 empty zones) |
| Final report | `a4/docs/cloud1/composer/PHASE_7D_INC5_REPORT.md` |
| Git commit | Single commit of scripts + outputs + report (per §11) |
| Opus ping | One message at closeout only |

### 7.4 Partial stats file

`a4/audits/audit_output/E5_arm_stats.json` currently reflects **only the spot-check run** (2 arms), not the full pipeline. It will be **overwritten** on the next `E5_per_arm_evidence` invocation. Do not treat it as authoritative until a complete run finishes.

---

## 8. Do you need to overwrite existing evidence files?

**No.** Overwriting was suggested only as the lazy path if you re-ran the *entire* pipeline from scratch (`inc5_e5_pipeline.sh` step 2 processes all 48 arms unconditionally). That would re-verify and rewrite all 29 finished files — wasteful (~2+ extra hours) but harmless.

**Recommended resume approach:** use `--arms` to process **only the 19 missing arms**:

```bash
cd /root/arguzz
export PYTHONPATH=/root/arguzz

python3 -m a4.audits.E5_per_arm_evidence --arms \
  "INSTR_WORD_MOD_SUR|pre_ecall" \
  "MEM_VAL_MOD|step0" \
  "MEM_VAL_MOD|last_step" \
  "MEM_VAL_MOD|pre_ecall" \
  "MEM_VAL_MOD|post_ecall" \
  "MEM_VAL_MOD|core_arithmetic" \
  "MEM_VAL_MOD|core_memory_load" \
  "MEM_VAL_MOD|core_memory_store" \
  "MEM_VAL_MOD|core_branch" \
  "MEM_VAL_MOD|core_mul" \
  "MEM_VAL_MOD|core_div" \
  "PRE_EXEC_REG_MOD|step0" \
  "PRE_EXEC_REG_MOD|post_ecall" \
  "PRE_EXEC_REG_MOD|core_arithmetic" \
  "PRE_EXEC_REG_MOD|core_memory_load" \
  "PRE_EXEC_REG_MOD|core_memory_store" \
  "PRE_EXEC_REG_MOD|core_mul" \
  "PRE_EXEC_REG_MOD|core_div" \
  "STORE_OUT_MOD|core_memory_store" \
  2>&1 | tee -a a4/audits/audit_output/E5_run.log
```

Then run index + stubs + gate **without** repeating preflight/pytest if you're confident nothing regressed:

```bash
python3 -m a4.audits.E5_build_index
python3 -m a4.audits.E5_per_arm_evidence --stubs-only
python3 -c "
import json
s = json.load(open('a4/audits/audit_output/E5_summary.json'))
assert s['verdict'] == 'PASS'
assert s['n_arms_correct'] >= 48
assert s['n_arms_incorrect'] == 0
print('INC5 GATE: PASS')
"
```

**Optional hardening for future:** add `--skip-existing` to `E5_per_arm_evidence.py` to skip arms whose output file already exists. Not implemented yet; `--arms` is sufficient.

**`E5_arm_stats.json` merge:** Today the script overwrites stats with only the arms processed in that invocation. After a resume run, either re-run all 48 once for a unified stats file, or manually merge JSON — only needed for report prose, not for gate (gate reads evidence files + summary from `E5_build_index`).

---

## 9. Remaining work checklist (ordered)

```
□ Resume evidence for 19 missing arms (~2–3 hr; MEM_VAL_MOD heaviest)
□ If exit code 3 + STOP message: capture row JSON, ping Opus, do NOT patch disposition
□ E5_build_index.py → README.md + E5_summary.json
□ E5_per_arm_evidence --stubs-only → _stubs/*.md
□ Gate assert PASS
□ Write PHASE_7D_INC5_REPORT.md (template in work order §10)
□ Single git commit: scripts + audit_output artifacts + report
□ Opus ping (format work order §11): "Inc 5 closeout complete. 48/48 arms ✓ CORRECT. Gate: PASS. Commit <sha>. ..."
```

**Do NOT** send intermediate Opus pings per Inc 5 contract.

---

## 10. Time and cost model (for planning)

| Activity | Observed / estimated |
|---|---|
| Preflight (incl. pytest) | 6–10 min |
| `verify_sample` per row | ~15–35 sec (host subprocess) |
| Typical arm pool size | 4–20 rows from Inc3+Inc4; rare arms trigger 50-mut targeted fuzz (~25–30 min) |
| Per arm (no fuzz) | ~5–10 min |
| Per arm (with fuzz) | ~30–45 min |
| 48 arms total (sequential) | **~4–7 hours** observed partial + projected |
| Work order budget | 5 hr hard ceiling — this run may exceed; work order says let it finish if genuinely slow, not hung |

**Hang detection:** no progress 30 min → kill, capture last 100 log lines, ping Opus.

---

## 11. Key paths reference

```
# Work orders
a4/docs/cloud1/composer/PHASE_7D_INC5_WORK.md
a4/docs/cloud1/composer/PHASE_7D_INC5_PROCESS.md
a4/docs/cloud1/composer/PHASE_7D_INC4_HANDOFF_ADDENDUM.md

# Scripts (Composer-authored)
a4/audits/inc5_preflight.py
a4/audits/E5_per_arm_evidence.py
a4/audits/E5_build_index.py
a4/audits/inc5_e5_pipeline.sh

# Inputs
workspace/output/target/release/risc0-host          # SHA 6873e588…
a4/runs/inc3_baseline/v{1..5}.db
a4/runs/inc4_b11/v{1..5}.db
a4/audits/audit_output/B1_inc3d_disposition.json
a4/audits/audit_output/B1_inc4_*_disposition.json
a4/docs/cloud1/EXPECTED_ARMS.md
a4/docs/cloud1/GLOSSARY.md
a4/audits/B1_apply_disposition.py

# Outputs (partial)
a4/audits/audit_output/per_arm_evidence/*.md       # 29/48 done
a4/audits/audit_output/E5_run.log
a4/audits/audit_output/E5_arm_stats.json           # stale (2-arm spot-check only)

# Outputs (pending)
a4/audits/audit_output/per_arm_evidence/README.md
a4/audits/audit_output/E5_summary.json
a4/audits/audit_output/per_arm_evidence/_stubs/*.md
a4/docs/cloud1/composer/PHASE_7D_INC5_REPORT.md
```

---

## 12. Failure modes (from work order §8 — still binding)

| Failure | Action |
|---|---|
| Preflight pytest FAIL | STOP, ping Opus — don't fix tests yourself |
| `OTHER` from `categorize()` | STOP, ping Opus with row JSON + arm + variant + mutation_id |
| Gate `n_arms_incorrect > 0` | Same as OTHER — disposition adjudication needed |
| Single arm Python traceback | Log, continue other arms; fix/regenerate that arm after |
| Pipeline hang 30 min | Kill, log tail, ping Opus |

---

## 13. Phase 7d closure context

When Inc 5 gate is GREEN:

- All 17 audits (A1–A5, B1–B12, E1–E5) complete.
- Per-arm evidence available for human spot-check.
- Disposition framework empirically exhaustive on ~4000 mutations in Inc 3+4 pool.
- **Phase 8 unblocks** pending Opus final report + `CLOUD1_STATUS.md` flip.

E5 is **not** Pro-facing; audience is Ivan + Opus + Composer for internal confidence before scaling.

---

## 14. Session notes and lessons

1. **Preflight pytest timeout:** 600s was too tight for 472 tests (~575s). Fixed at 900s.
2. **Pipeline duration:** Underestimated vs work order “~3 hr” — realistic **4–7 hr** for 48 arms on WSL sequential verify.
3. **Background shell longevity:** Long-running `inc5_e5_pipeline.sh` in Cursor background may die ~4h with `exit_code: unknown`; prefer `tmux`/`nohup` or resume via `--arms` for long jobs.
4. **Targeted fuzz:** Arms with `<5` rows after Inc3+Inc4 trigger 50-mutation fuzz; log noise is from `a4.standalone.cli fuzz`, not B1 failures.
5. **No disposition surprises yet:** All 29 completed arms: 0 OTHER. MEM_VAL_MOD arms are the highest risk for exclusions (expected) and for novel OTHER (would block).
6. **POS:** Not used; not needed.

---

## 15. Quick status line (copy-paste for next session)

> **Inc 5:** Preflight PASS. Scripts written. **29/48** evidence `.md` files done. Pipeline interrupted ~4h in (no OTHER/STOP). **19 arms remain** (1× INSTR_WORD_MOD_SUR, 10× MEM_VAL_MOD, 7× PRE_EXEC_REG_MOD, 1× STORE_OUT_MOD). Resume with `E5_per_arm_evidence --arms <list>` — **do not overwrite** existing 29. Then index, stubs, gate, report, commit, Opus ping.

---

*End of handoff document.*
