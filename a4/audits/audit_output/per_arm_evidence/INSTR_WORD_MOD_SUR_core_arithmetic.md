# Arm `INSTR_WORD_MOD_SUR|core_arithmetic` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T02:31:40Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_WORD_MOD_SUR` — mutates surgical instruction-word field at fetch txn
- **Zone**: `core_arithmetic` — primary Decode major ∈ {0,1,2}
- **Allowed majors**: 0–6 or 8 (fetch / ECALL)
- **Expected step count for this guest**: 2443 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=21, variant=V5, step=1431

### Trace context

| Field | Value |
|---|---|
| step | 1431 |
| cycle.major | 0 |
| cycle.minor | 7 |
| pc | `0x002184d4` |
| zone classifier | `core_arithmetic` (matches arm) |
| txns at step | (21413, mem, 0x86134), (21414, reg, 0x3fffc02a), (21415, reg, 0x3fffc021), (21416, reg, 0x3fffc02a) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00150513` | — |
| insn_decode.DecodedInsn.major | 0 | Y |
| insn_decode.DecodedInsn.minor | 7 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=1705235` |
| Mutation effect (new_word / new_kind / etc.) | `0x001a0513` |
| Hook stdout tag | `<a4_instr_word_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 0
- Reward v2 components: l_new=0, g_new=0, s_new=0.43065680051282695, scalar=0.2612065533247769

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
