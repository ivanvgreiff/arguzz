# Arm `INSTR_WORD_MOD_FULL|core_mul` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T01:46:00Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_WORD_MOD_FULL` — mutates full instruction word at fetch txn
- **Zone**: `core_mul` — primary Decode major = 3 (MUL block)
- **Allowed majors**: 0–6 or 8 (fetch / ECALL)
- **Expected step count for this guest**: 100 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=17, variant=V5, step=303

### Trace context

| Field | Value |
|---|---|
| step | 303 |
| cycle.major | 3 |
| cycle.minor | 1 |
| pc | `0x002031bc` |
| zone classifier | `core_mul` (matches arm) |
| txns at step | (16710, mem, 0x80c6e), (16711, reg, 0x3fffc029), (16712, reg, 0x3fffc022), (16713, reg, 0x3fffc029) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00249493` | — |
| insn_decode.DecodedInsn.major | 3 | Y |
| insn_decode.DecodedInsn.minor | 1 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=2397843` |
| Mutation effect (new_word / new_kind / etc.) | `0x00249693` |
| Hook stdout tag | `<a4_instr_word_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 0
- Reward v2 components: l_new=0, g_new=0, s_new=0.431990759597302, scalar=0.2620156404083132

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
