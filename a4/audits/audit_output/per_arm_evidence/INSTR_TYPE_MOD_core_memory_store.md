# Arm `INSTR_TYPE_MOD|core_memory_store` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T00:19:48Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_TYPE_MOD` — mutates instruction type (major/minor) at fetch txn
- **Zone**: `core_memory_store` — primary Decode major = 6 (store)
- **Allowed majors**: 0–6 (any instruction cycle)
- **Expected step count for this guest**: 596 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 13 rows

- **Total candidates**: 17
- **Distribution**: 17 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=8, variant=V5, step=3199

### Trace context

| Field | Value |
|---|---|
| step | 3199 |
| cycle.major | 6 |
| cycle.minor | 2 |
| pc | `0x00204b60` |
| zone classifier | `core_memory_store` (matches arm) |
| txns at step | (28942, mem, 0x812d7), (28943, reg, 0x3fffc022), (28944, reg, 0x3fffc02b), (28945, mem, 0x80079), (28946, mem, 0x80079) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x02b12223` | — |
| insn_decode.DecodedInsn.major | 6 | Y |
| insn_decode.DecodedInsn.minor | 2 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `major=5 minor=2` |
| Mutation effect (new_word / new_kind / etc.) | `5/2` |
| Hook stdout tag | `<a4_instr_type_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 5
- Reward v2 components: l_new=0, g_new=0, s_new=0.4896128426250982, scalar=0.028797299874028577

### Verdict

✓ CORRECT. The mutation was applied to the expected cell at the expected step; the hook captured it faithfully; the trace context matches the arm's claim.

---

## 4. EXAMPLE 2 — exclusion case (if any)

_No exclusion or RACE row in candidate pool._

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 17 |
| Exclusion (A/B/B2/C/D/D2) | 0 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ✓ CORRECT**
 (zero OTHER rows; 0 exclusion rows within disposition framework).
