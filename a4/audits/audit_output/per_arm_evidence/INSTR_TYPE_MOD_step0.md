# Arm `INSTR_TYPE_MOD|step0` — Per-Arm Evidence

**Status:** ✗ INCORRECT
**Audit:** Phase 7d Inc 5 — E5
**Generated:** 2026-06-14T00:49:41Z
**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`
**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)

## 1. Arm claim

- **Kind**: `INSTR_TYPE_MOD` — mutates instruction type (major/minor) at fetch txn
- **Zone**: `step0` — singleton step 0 (boot preamble)
- **Allowed majors**: 0–6 (any instruction cycle)
- **Expected step count for this guest**: 1 (status: 🔵)
- **D-decisions touching this arm** (if any): D46

## 2. Row pool

- From Inc 3 baseline DBs: 5 rows
- From Inc 4 B11 DBs: 14 rows

- **Total candidates**: 19
- **Distribution**: 0 PASS, 19 exclusion (A=19), 0 RACE, 0 OTHER

## 3. EXAMPLE 1 — ✓ CORRECT

_No PASS row in candidate pool — see aggregate verdict._

---

## 4. EXAMPLE 2 — exclusion case

**Row source**: `/root/arguzz/a4/runs/inc3_baseline/v5.db` mutation_id=12, variant=V5, step=0

### Trace context

| Field | Value |
|---|---|
| step | 0 |
| cycle.major | 2 |
| cycle.minor | 6 |
| pc | `0xc0000004` |
| zone classifier | `step0` (matches arm) |
| txns at step | (0, mem, 0x44000000), (1, mem, 0x44000001), (2, mem, 0x44000002), (3, mem, 0x44000003), (4, mem, 0x44000004), (5, mem, 0x44000005), (6, mem, 0x44000006), (7, mem, 0x44000007), … |

### Independent re-decode

| Field | Value | Match cycle? |
|---|---|---|
| Raw instr word at PC | `0x40011197` | — |
| insn_decode.DecodedInsn.major | 2 | Y |
| insn_decode.DecodedInsn.minor | 6 | Y |

Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.

### Mutation applied

| Field | Value |
|---|---|
| Mutation config | `major=1 minor=3` |
| Mutation effect (new_word / new_kind / etc.) | `1/3` |
| Hook stdout tag | `<a4_instr_type_mod>` |
| Hook payload matches config? | ✓ YES |

### Outcome

- Exit code: 1
- Constraint failures: 5
- Reward v2 components: l_new=0, g_new=0, s_new=0.6809467876367373, scalar=0.07800847681219884

### Disposition classification

- Category: **A**
- Maps to decision: D40 (multi-cycle boot)
- Why excluded: cycle_shift_at_step: hook old=7/0 != config exp_old=2/6

### Verdict

⚠ EXCLUSION. Known boundary case under D40 (multi-cycle boot); documented in `PHASE_7D_INC3D_B1_DISPOSITION.md` §3 Category A.

---

## 5. Aggregate verdict

| Outcome class | Count |
|---|---:|
| ✓ CORRECT | 0 |
| Exclusion (A/B/B2/C/D/D2) | 19 |
| RACE (informational) | 0 |
| OTHER (counts as failure) | 0 |

**Arm verdict: ✗ INCORRECT**
 (zero OTHER rows; 19 exclusion rows within disposition framework).
