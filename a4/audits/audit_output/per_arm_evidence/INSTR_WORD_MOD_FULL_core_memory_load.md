# Arm `INSTR_WORD_MOD_FULL|core_memory_load` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T01:31:24Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_WORD_MOD_FULL` — mutates full instruction word at fetch txn
- **Zone**: `core_memory_load` — primary Decode major = 5 (load)
- **Allowed majors**: 0–6 or 8 (fetch / ECALL)
- **Expected step count for this guest**: 678 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=15, variant=V5, step=1779

### Trace context

| Field | Value |
|---|---|
| step | 1779 |
| cycle.major | 5 |
| cycle.minor | 3 |
| pc | `0x002184c4` |
| zone classifier | `core_memory_load` (matches arm) |
| txns at step | (22841, mem, 0x86130), (22842, reg, 0x3fffc02b), (22843, mem, 0x86ea0), (22844, reg, 0x3fffc02e) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x0005c703` | — |
| insn_decode.DecodedInsn.major | 5 | Y |
| insn_decode.DecodedInsn.minor | 3 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=3197441687` |
| Mutation effect (new_word / new_kind / etc.) | `0xbe951697` |
| Hook stdout tag | `<a4_instr_word_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 3
- Reward v2 components: l_new=0, g_new=0, s_new=0.48375539134981943, scalar=0.05541845840826556

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
