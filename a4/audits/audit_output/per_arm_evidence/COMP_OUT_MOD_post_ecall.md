# Arm `COMP_OUT_MOD|post_ecall` — Per-Arm Evidence

**Status:** ✓ CORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-13T23:42:41Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `COMP_OUT_MOD` — mutates compute-output register cell (major 0–4 cycles)
- **Zone**: `post_ecall` — first user-PC Decode step in [e+1,e+5] after ECALL (D53)
- **Allowed majors**: 0–4 (MISC/MUL/DIV compute)
- **Expected step count for this guest**: 11 (status: 🟡)
- **D-decisions touching this arm** (if any): D46

## 2. Row pool

- From Inc 3 baseline DBs: 4 rows
- From Inc 4 B11 DBs: 10 rows

- **Total candidates**: 14
- **Distribution**: 14 PASS, 0 exclusion (none), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=4, variant=V5, step=999

### Trace context

| Field | Value |
|---|---|
| step | 999 |
| cycle.major | 0 |
| cycle.minor | 0 |
| pc | `0x00206178` |
| zone classifier | `post_ecall` (matches arm) |
| txns at step | (19628, mem, 0x8185d), (19629, reg, 0x3fffc02a), (19630, reg, 0x3fffc030), (19631, reg, 0x3fffc030) |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x01050833` | — |
| insn_decode.DecodedInsn.major | 0 | Y |
| insn_decode.DecodedInsn.minor | 0 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `word=2145320319` |
| Mutation effect (new_word / new_kind / etc.) | `0x7fdefd7f` |
| Hook stdout tag | `<a4_comp_out_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 0
- Constraint failures: 2
- Reward v2 components: l_new=0, g_new=0, s_new=0.4443937032297787, scalar=0.19313270729548804

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
