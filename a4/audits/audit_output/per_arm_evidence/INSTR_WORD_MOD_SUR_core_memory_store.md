# Arm `INSTR_WORD_MOD_SUR|core_memory_store` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T02:58:10Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_WORD_MOD_SUR` — mutates surgical instruction-word field at fetch txn
- **Zone**: `core_memory_store` — primary Decode major = 6 (store)
- **Allowed majors**: 0–6 or 8 (fetch / ECALL)
- **Expected step count for this guest**: 596 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=24, variant=V5, step=251

### Trace context

| Field | Value |
|---|---|
| step | 251 |
| cycle.major | 6 |
| cycle.minor | 2 |
| pc | `0x00203198` |
| zone classifier | `core_memory_store` (matches arm) |
| txns at step | (16489, mem, 0x80c65), (16490, reg, 0x3fffc022), (16491, reg, 0x3fffc029), (16492, mem, 0x800d5), (16493, mem, 0x800d5) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00912223` | — |
| insn_decode.DecodedInsn.major | 6 | Y |
| insn_decode.DecodedInsn.minor | 2 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=2171427` |
| Mutation effect (new_word / new_kind / etc.) | `0x00212223` |
| Hook stdout tag | `<a4_instr_word_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 2
- Reward v2 components: l_new=0, g_new=0, s_new=0.49137564308152654, scalar=0.09280887080671794

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
