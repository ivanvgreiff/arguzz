# Arm `INSTR_TYPE_MOD|core_arithmetic` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-13T23:46:06Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_TYPE_MOD` — mutates instruction type (major/minor) at fetch txn
- **Zone**: `core_arithmetic` — primary Decode major ∈ {0,1,2}
- **Allowed majors**: 0–6 (any instruction cycle)
- **Expected step count for this guest**: 2443 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 5 rows
- From Inc 4 B11 DBs: 11 rows

- **Total candidates**: 16
- **Distribution**: 16 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=5, variant=V5, step=3727

### Trace context

| Field | Value |
|---|---|
| step | 3727 |
| cycle.major | 0 |
| cycle.minor | 0 |
| pc | `0x00203268` |
| zone classifier | `core_arithmetic` (matches arm) |
| txns at step | (31199, mem, 0x80c99), (31200, reg, 0x3fffc02d), (31201, reg, 0x3fffc02c), (31202, reg, 0x3fffc02e) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00c68733` | — |
| insn_decode.DecodedInsn.major | 0 | Y |
| insn_decode.DecodedInsn.minor | 0 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `major=5 minor=0` |
| Mutation effect (new_word / new_kind / etc.) | `5/0` |
| Hook stdout tag | `<a4_instr_type_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 3
- Reward v2 components: l_new=0, g_new=0, s_new=0.47528872329225097, scalar=0.12528474723851493

### Verdict

✓ CORRECT. The mutation was applied to the expected cell at the expected step; the hook captured it faithfully; the trace context matches the arm's claim.

---

## 4. EXAMPLE 2 — exclusion case (if any)

_No exclusion or RACE row in candidate pool._

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 16 |
| Exclusion (A/B/B2/C/D/D2) | 0 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ✓ CORRECT**
 (zero OTHER rows; 0 exclusion rows within disposition framework).
