# Arm `LOAD_VAL_MOD|post_ecall` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-13T23:11:44Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `LOAD_VAL_MOD` — mutates load destination register write (major 5)
- **Zone**: `post_ecall` — first user-PC Decode step in [e+1,e+5] after ECALL (D53)
- **Allowed majors**: 5 (MEM0 load)
- **Expected step count for this guest**: 2 (status: 🟡)
- **D-decisions touching this arm** (if any): D46

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=30, variant=V5, step=1854

### Trace context

| Field | Value |
|---|---|
| step | 1854 |
| cycle.major | 5 |
| cycle.minor | 2 |
| pc | `0x00205ff8` |
| zone classifier | `post_ecall` (matches arm) |
| txns at step | (23152, mem, 0x817fd), (23153, reg, 0x3fffc022), (23154, mem, 0x8001f), (23155, reg, 0x3fffc021) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x01c12083` | — |
| insn_decode.DecodedInsn.major | 5 | Y |
| insn_decode.DecodedInsn.minor | 2 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=807466653` |
| Mutation effect (new_word / new_kind / etc.) | `0x3020f69d` |
| Hook stdout tag | `<a4_load_val_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 2
- Reward v2 components: l_new=0, g_new=0, s_new=0.2887335595818693, scalar=0.12548308773015213

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
