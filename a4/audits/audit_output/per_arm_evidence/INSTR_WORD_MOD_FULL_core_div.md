# Arm `INSTR_WORD_MOD_FULL|core_div` — Per-Arm Evidence

**Status:** ⚠ WEAK SIGNAL
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T01:24:34Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_WORD_MOD_FULL` — mutates full instruction word at fetch txn
- **Zone**: `core_div` — primary Decode major = 4 (DIV/REM/SRL/SRA block)
- **Allowed majors**: 0–6 or 8 (fetch / ECALL)
- **Expected step count for this guest**: 23 (status: 🟡)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 0 rows

- **Total candidates**: 4
- **Distribution**: 4 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=14, variant=V5, step=610

### Trace context

| Field | Value |
|---|---|
| step | 610 |
| cycle.major | 4 |
| cycle.minor | 2 |
| pc | `0x002061a8` |
| zone classifier | `core_shr` (matches arm) |
| txns at step | (17997, mem, 0x81869), (17998, reg, 0x3fffc02a), (17999, reg, 0x3fffc022), (18000, reg, 0x3fffc02b) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00255593` | — |
| insn_decode.DecodedInsn.major | 4 | Y |
| insn_decode.DecodedInsn.minor | 2 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=2971027` |
| Mutation effect (new_word / new_kind / etc.) | `0x002d5593` |
| Hook stdout tag | `<a4_instr_word_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 0
- Reward v2 components: l_new=0, g_new=0, s_new=0.4333267794691698, scalar=0.2628259774225864

### Verdict

✓ CORRECT. The mutation was applied to the expected cell at the expected step; the hook captured it faithfully; the trace context matches the arm's claim.

---

## 4. EXAMPLE 2 — exclusion case (if any)

_No exclusion or RACE row in candidate pool._

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 4 |
| Exclusion (A/B/B2/C/D/D2) | 0 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ⚠ WEAK SIGNAL**
 (zero OTHER rows; 0 exclusion rows within disposition framework).
