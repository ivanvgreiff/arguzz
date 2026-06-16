# Arm `INSTR_TYPE_MOD|pre_ecall` — Per-Arm Evidence

**Status:** ✗ INCORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T00:40:59Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_TYPE_MOD` — mutates instruction type (major/minor) at fetch txn
- **Zone**: `pre_ecall` — step containing an ECALL cycle (major=8)
- **Allowed majors**: 0–6 (any instruction cycle)
- **Expected step count for this guest**: 18 (status: 🟡)
- **D-decisions touching this arm** (if any): D46

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 0 PASS, 14 exclusion (C=14), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

_No PASS row in candidate pool — see aggregate verdict._

---

## 4. EXAMPLE 2 — exclusion case

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=11, variant=V5, step=446

### Trace context

| Field | Value |
|---|---|
| step | 446 |
| cycle.major | 0 |
| cycle.minor | 7 |
| pc | `0xc0000154` |
| zone classifier | `pre_ecall` (matches arm) |
| txns at step | (17295, mem, 0x30000053), (17296, mem, 0x3fffc011), (17297, mem, 0x3fffc00a), (17298, mem, 0x3fffc00b), (17299, mem, 0x3fffc00c), (17300, mem, 0x3fffc00a), (17301, mem, 0x800db), (17302, mem, 0x3fffc041), … |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x00000073` | — |
| insn_decode.DecodedInsn.major | 7 | N |
| insn_decode.DecodedInsn.minor | 0 | N |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `major=6 minor=1` |
| Mutation effect (new_word / new_kind / etc.) | `6/1` |
| Hook stdout tag | `<a4_instr_type_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 1
- Constraint failures: 7
- Reward v2 components: l_new=0, g_new=0, s_new=0.6829245860397596, scalar=0.010587962801124475

### Disposition classification

- Category: **C**
- Maps to decision: D46 (ECALL-adjacent type)
- Why excluded: cycle_shift_at_step: hook old=8/0 != config exp_old=0/7

### Verdict

⚠ EXCLUSION. Known boundary case under D46 (ECALL-adjacent type); documented in `PHASE_7D_INC3D_B1_DISPOSITION.md` §3 Category C.

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 0 |
| Exclusion (A/B/B2/C/D/D2) | 14 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ✗ INCORRECT**
 (zero OTHER rows; 14 exclusion rows within disposition framework).
