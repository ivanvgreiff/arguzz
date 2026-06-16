# Arm `COMP_OUT_MOD|core_mul` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-13T23:39:33Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `COMP_OUT_MOD` — mutates compute-output register cell (major 0–4 cycles)
- **Zone**: `core_mul` — primary Decode major = 3 (MUL block)
- **Allowed majors**: 0–4 (MISC/MUL/DIV compute)
- **Expected step count for this guest**: 66 (status: 🟢)
- **D-decisions touching this arm** (if any): none

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=3, variant=V5, step=618

### Trace context

| Field | Value |
|---|---|
| step | 618 |
| cycle.major | 3 |
| cycle.minor | 1 |
| pc | `0x002031bc` |
| zone classifier | `core_mul` (matches arm) |
| txns at step | (18029, mem, 0x80c6e), (18030, reg, 0x3fffc029), (18031, reg, 0x3fffc022), (18032, reg, 0x3fffc029) |

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
| Mutation config | `word=65540` |
| Mutation effect (new_word / new_kind / etc.) | `0x00010004` |
| Hook stdout tag | `<a4_comp_out_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 1
- Reward v2 components: l_new=0, g_new=0, s_new=0.4134401314890724, scalar=0.250764115703745

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
