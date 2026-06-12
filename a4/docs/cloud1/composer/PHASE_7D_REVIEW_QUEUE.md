# Phase 7d — E4 Manual Review Queue

Items surfaced by Increment 1 audits. Composer + user adjudicate before Inc 5 close.

---

## DECODE_MISMATCH (from E1)

Source: `a4/audits/audit_output/E1_decode_ground_truth.json` (31 total mismatches across 4 arms).

| ID | arm_id | step | trace (M,m) | decoded (M,m) | raw_word | notes |
|---|---|---:|---|---|---|---|
| DM-1 | INSTR_TYPE_MOD\|pre_ecall | 170 | 8/0 (ECALL0) | 7/0 (Eany) | see JSON | ECALL cycle: trace `major=8` vs RV32IM decode of fetch word → `major=7`. Expected boundary semantics (D13); not a zone-classifier bug. |
| DM-2 | MEM_VAL_MOD\|pre_ecall | 170 | 8/0 | 7/0 | see JSON | Same ECALL step as DM-1; MEM_VAL arm includes ECALL-adjacent mem txns. |
| DM-3 | MEM_VAL_MOD\|core_branch | 19 | 7/3 | 7/1 | see JSON | `minor` mismatch on CONTROL0 step — branch opcode funct3 vs trace minor. Investigate Q4. |
| DM-4 | MEM_VAL_MOD\|core_branch | (9 more) | various | various | see JSON | Pattern: first 10 steps of `core_branch` arm show minor mismatches; all `major=7`. |
| DM-5 | MEM_VAL_MOD\|last_step | 3929 | 8/0 | 7/0 | see JSON | Last step is ECALL-like (step 3929); same 8-vs-7 pattern as DM-1. |

**Proposed disposition (pending joint review):**

- DM-1, DM-2, DM-5: **ACCEPT** as ECALL0 vs decode taxonomy difference; exclude `major=8` cycles from strict E1 gate in Inc 3 B1 path.
- DM-3, DM-4: **REVIEW** at joint session — may affect Q4 (`MEM_VAL_MOD|core_branch` legitimacy).

---

## UNCERTAIN_ARM (from E3)

22 🟡 arms — see `a4/audits/audit_output/E3_uncertain_review.json`. Adjudicate in joint review session; do not update `EXPECTED_ARMS.md` until then.

**D40-dropped 🟡 arms (no longer in universe):**

- `INSTR_WORD_MOD_FULL|last_step`, `INSTR_WORD_MOD_FULL|pre_ecall`
- `INSTR_WORD_MOD_SUR|last_step`, `INSTR_WORD_MOD_SUR|pre_ecall`

Draft verdict: mark **DROP_D40** in EXPECTED_ARMS after joint review (move to Expected-DROPPED section).
