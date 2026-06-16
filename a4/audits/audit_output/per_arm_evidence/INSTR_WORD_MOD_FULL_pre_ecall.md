# Arm `INSTR_WORD_MOD_FULL|pre_ecall` — Per-Arm Evidence

**Status:** ⚠ WEAK SIGNAL
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T02:25:22Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_WORD_MOD_FULL` — mutates full instruction word at fetch txn
- **Zone**: `pre_ecall` — step containing an ECALL cycle (major=8)
- **Allowed majors**: 0–6 or 8 (fetch / ECALL)
- **Expected step count for this guest**: 32 (status: 🟡)
- **D-decisions touching this arm** (if any): D46, D40

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 0 rows

- **Total candidates**: 4
- **Distribution**: 4 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=20, variant=V5, step=1853

### Trace context

| Field | Value |
|---|---|
| step | 1853 |
| cycle.major | 7 |
| cycle.minor | 3 |
| pc | `0x00205ff4` |
| zone classifier | `pre_ecall` (matches arm) |
| txns at step | (23140, mem, 0x30000057), (23141, mem, 0x3fffc011), (23142, mem, 0x3fffc00a), (23143, mem, 0x3fffc00b), (23144, mem, 0x3fffc00c), (23145, mem, 0x3fffc00a), (23146, reg, 0x3fffc02a), (23147, reg, 0x3fffc02b), … |

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
| Mutation config | `word=524403` |
| Mutation effect (new_word / new_kind / etc.) | `0x00080073` |
| Hook stdout tag | `<a4_instr_word_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 1
- Reward v2 components: l_new=0, g_new=0, s_new=0.39689539016052916, scalar=0.24072922283096884

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
