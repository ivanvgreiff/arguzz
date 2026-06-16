# Arm `LOAD_VAL_MOD|core_memory_load` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-13T23:07:42Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `LOAD_VAL_MOD` — mutates load destination register write (major 5)
- **Zone**: `core_memory_load` — primary Decode major = 5 (load)
- **Allowed majors**: 5 (MEM0 load)
- **Expected step count for this guest**: 586 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=29, variant=V5, step=3334

### Trace context

| Field | Value |
|---|---|
| step | 3334 |
| cycle.major | 5 |
| cycle.minor | 2 |
| pc | `0x00203428` |
| zone classifier | `core_memory_load` (matches arm) |
| txns at step | (29487, mem, 0x80d09), (29488, reg, 0x3fffc02e), (29489, mem, 0x800a2), (29490, reg, 0x3fffc025) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00c72283` | — |
| insn_decode.DecodedInsn.major | 5 | Y |
| insn_decode.DecodedInsn.minor | 2 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=1737823312` |
| Mutation effect (new_word / new_kind / etc.) | `0x67951450` |
| Hook stdout tag | `<a4_load_val_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 2
- Reward v2 components: l_new=0, g_new=0, s_new=0.30417453860932087, scalar=0.13219370955307796

### Verdict

✓ CORRECT. The mutation was applied to the expected cell at the expected step; the hook captured it faithfully; the trace context matches the arm's claim.

---

## 4. EXAMPLE 2 — exclusion case (if any)

_No exclusion or RACE row in candidate pool._

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 14 |
| Exclusion (A/B/B2/C/D/D2) | 0 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ✓ CORRECT**
 (zero OTHER rows; 0 exclusion rows within disposition framework).
