# Arm `INSTR_WORD_MOD_FULL|last_step` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T01:48:38Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_WORD_MOD_FULL` — mutates full instruction word at fetch txn
- **Zone**: `last_step` — singleton final user step
- **Allowed majors**: 0–6 or 8 (fetch / ECALL)
- **Expected step count for this guest**: 1 (status: 🟡)
- **D-decisions touching this arm** (if any): D46, D40

## 2. Row pool

- From Inc 3 baseline DBs: 5 rows
- From Inc 4 B11 DBs: 0 rows

- **Total candidates**: 5
- **Distribution**: 5 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=18, variant=V5, step=3929

### Trace context

| Field | Value |
|---|---|
| step | 3929 |
| cycle.major | 7 |
| cycle.minor | 7 |
| pc | `0x00000000` |
| zone classifier | `last_step` (matches arm) |
| txns at step | (32134, mem, 0x3000003e), (32135, mem, 0x3fffc011), (32136, mem, 0x3fffc00a), (32137, mem, 0x3fffc00b), (32138, mem, 0x3fffc084), (32139, mem, 0x3fffc085), (32140, mem, 0x3fffc090), (32141, mem, 0x3fffc091), … |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00000073` | — |
| insn_decode.DecodedInsn.major | 7 | Y |
| insn_decode.DecodedInsn.minor | 0 | N |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=1139` |
| Mutation effect (new_word / new_kind / etc.) | `0x00000473` |
| Hook stdout tag | `<a4_instr_word_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 1
- Reward v2 components: l_new=0, g_new=0, s_new=0.39755919663055683, scalar=0.24113184180715624

### Verdict

✓ CORRECT. The mutation was applied to the expected cell at the expected step; the hook captured it faithfully; the trace context matches the arm's claim.

---

## 4. EXAMPLE 2 — exclusion case (if any)

_No exclusion or RACE row in candidate pool._

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 5 |
| Exclusion (A/B/B2/C/D/D2) | 0 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ✓ CORRECT**
 (zero OTHER rows; 0 exclusion rows within disposition framework).
