# Arm `INSTR_TYPE_MOD|post_ecall` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T00:34:33Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_TYPE_MOD` — mutates instruction type (major/minor) at fetch txn
- **Zone**: `post_ecall` — first user-PC Decode step in [e+1,e+5] after ECALL (D53)
- **Allowed majors**: 0–6 (any instruction cycle)
- **Expected step count for this guest**: 32 (status: 🟢)
- **D-decisions touching this arm** (if any): D46

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 13 rows

- **Total candidates**: 17
- **Distribution**: 17 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=10, variant=V5, step=996

### Trace context

| Field | Value |
|---|---|
| step | 996 |
| cycle.major | 0 |
| cycle.minor | 7 |
| pc | `0xc0000158` |
| zone classifier | `kernel_other` (matches arm) |
| txns at step | (19608, mem, 0x30000055), (19609, mem, 0x3fffc004), (19610, mem, 0x3fffc008), (19611, mem, 0x3fffc00b) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x02820593` | — |
| insn_decode.DecodedInsn.major | 0 | Y |
| insn_decode.DecodedInsn.minor | 7 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `major=1 minor=4` |
| Mutation effect (new_word / new_kind / etc.) | `1/4` |
| Hook stdout tag | `<a4_instr_type_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 3
- Reward v2 components: l_new=0, g_new=0, s_new=0.43582298258729674, scalar=0.16033031528388597

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
