# Arm `INSTR_TYPE_MOD|core_div` — Per-Arm Evidence

**Status:** ⚠ WEAK SIGNAL
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T00:04:14Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_TYPE_MOD` — mutates instruction type (major/minor) at fetch txn
- **Zone**: `core_div` — primary Decode major = 4 (DIV/REM/SRL/SRA block)
- **Allowed majors**: 0–6 (any instruction cycle)
- **Expected step count for this guest**: 23 (status: 🟡)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 0 rows

- **Total candidates**: 4
- **Distribution**: 4 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=6, variant=V5, step=3513

### Trace context

| Field | Value |
|---|---|
| step | 3513 |
| cycle.major | 4 |
| cycle.minor | 2 |
| pc | `0x00205418` |
| zone classifier | `core_shr` (matches arm) |
| txns at step | (30218, mem, 0x81505), (30219, reg, 0x3fffc02e), (30220, reg, 0x3fffc026), (30221, reg, 0x3fffc02e) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00675713` | — |
| insn_decode.DecodedInsn.major | 4 | Y |
| insn_decode.DecodedInsn.minor | 2 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `major=4 minor=4` |
| Mutation effect (new_word / new_kind / etc.) | `4/4` |
| Hook stdout tag | `<a4_instr_type_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 4
- Reward v2 components: l_new=0, g_new=0, s_new=0.6731577665843337, scalar=0.17744246077200476

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
