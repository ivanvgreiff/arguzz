# Arm `INSTR_TYPE_MOD|core_mul` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T00:26:38Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_TYPE_MOD` — mutates instruction type (major/minor) at fetch txn
- **Zone**: `core_mul` — primary Decode major = 3 (MUL block)
- **Allowed majors**: 0–6 (any instruction cycle)
- **Expected step count for this guest**: 100 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 5 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 15
- **Distribution**: 15 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=9, variant=V5, step=514

### Trace context

| Field | Value |
|---|---|
| step | 514 |
| cycle.major | 3 |
| cycle.minor | 1 |
| pc | `0xc000007c` |
| zone classifier | `kernel_other` (matches arm) |
| txns at step | (17582, mem, 0x3000001e), (17583, mem, 0x3fffc00a), (17584, mem, 0x3fffc002), (17585, mem, 0x3fffc00a) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00251513` | — |
| insn_decode.DecodedInsn.major | 3 | Y |
| insn_decode.DecodedInsn.minor | 1 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `major=1 minor=1` |
| Mutation effect (new_word / new_kind / etc.) | `1/1` |
| Hook stdout tag | `<a4_instr_type_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 2
- Reward v2 components: l_new=0, g_new=0, s_new=0.40263000007829813, scalar=0.20671713467629213

### Verdict

✓ CORRECT. The mutation was applied to the expected cell at the expected step; the hook captured it faithfully; the trace context matches the arm's claim.

---

## 4. EXAMPLE 2 — exclusion case (if any)

_No exclusion or RACE row in candidate pool._

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 15 |
| Exclusion (A/B/B2/C/D/D2) | 0 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ✓ CORRECT**
 (zero OTHER rows; 0 exclusion rows within disposition framework).
