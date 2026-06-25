# A1 — Canonical trigger contract for the `rs1==rs2` CVE (CVE-2025-52484 / risc0 #3181)

**Status:** CONFIRMED on the B2 build (2026-06-25). **Confirmed-by:** **G4** (prior, deterministic on
`98387806`: rs2:=rs1 alias → proof verifies with wrong output) + **B2** (`a4/builds/a1_cve/risc0-host`,
codegen byte-identical to `98387806`, `load_rs2_present=0`): honest prove → `output=9000027` Verifier
success; the `v6_uniform` race tool produced an `INSTR_WORD_MOD` accept in `core_arithmetic` within 2
mutations. The **CVE thesis race is LIVE on POS** (`chain_cve_thesis`, 40 jobs) — the strong journal
oracle on its run.dbs is the at-scale confirmation. See
[`B2_FORWARD_PORT_AND_DISPATCH_REPORT.md`](./B2_FORWARD_PORT_AND_DISPATCH_REPORT.md). **Race framing = B**
(below §2 note): the A2 guest encodes rs1≠rs2 with 1-bit-apart source regs, and the `INSTR_WORD_MOD`
flip aliases rs2→rs1 (vs §2's rs1==rs2-encoded framing A — both expose the same underconstraint; B is
what the random-bit-flip fuzzer hits and what G4 confirmed). This file remains the mechanism contract.

This is the **absolute-certainty target**: the exact instruction shape + fault + accept-of-wrong that the
vulnerable build must exhibit and the patched build must reject.

---

## 1. The bug (source-gated this session, on `workspace/risc0-modified`)
`risc0/circuit/rv32im/src/execute/rv32im.rs`:
- **`98387806` (bug):** `fn load_rs2` count = **0** → two separate reads `load_register(decoded.rs1)`
  (`:326`) and `load_register(decoded.rs2)` (`:327`) in `step_compute` (and again at `:503/504`). When an
  instruction encodes `rs1 == rs2`, this issues **two unconstrained same-cycle reads of one register**.
- **`67f2d81` (fix #3181) & `ebd64e43` (our base):** `fn load_rs2` count = **1** → reads once when
  `rs1==rs2` and reuses the value (`Ok(rs1)`); preflight adds `ensure!(txn.cycle != txn.prev_cycle)`.
- In-tree vulnerable **generated circuit** is committed at `98387806` (`steps.cpp` 30k lines,
  `poly_ext.rs` 20k, `info.rs`) → **building at `98387806` yields the vulnerable circuit with no zirgen
  regen** (this is what makes A1 tractable where the AP planted-IsRead track was blocked).

## 2. The trigger op (guest encodes `rs1 == rs2`)
```
remu x3, x5, x5      # rs1 == rs2 == x5;  x5 != 0;  honest result = x5 % x5 = 0
```
Force via inline asm + input barrier (`black_box`) so the compiler cannot const-fold `a%a→0` or allocate
two registers; **disassemble the ELF** (`objdump -d`) and confirm an executed `remu`/`divu` with **identical
rs1==rs2 register fields** survived compilation (the A1.B3 G3-style check).

## 3. The exploit fault — COHERENT / PROPAGATING (not a no-op, not a lone cell edit)
The two same-cycle reads of `x5` must **diverge**, and the result must be **recomputed to match**:
```
honest   :  read_rs1 = a,  read_rs2 = a,  result = rem(a, a) = 0
exploit  :  read_rs1 = a,  read_rs2 = b (b != a),  result = rem(a, b)      # COHERENT
```
- **C_local** (present pre-fix): `rem(read_rs1, read_rs2) == result` — must still HOLD ⇒ result must track
  the diverged read.
- **C_mem(rs2)** (the missing constraint pre-fix): the second same-cycle read of x5 must equal x5's memory
  value — this is the ONLY violated constraint.
- **Concrete:** `remu x3,x5,x5`, `x5 = 7`: honest `result=0`; exploit `read_rs2 = 5, result = rem(7,5) = 2`
  → committed output **2 ≠ honest 0**, yet the vulnerable circuit accepts (only C_mem(rs2) fails, and it
  isn't enforced).
- **Companion (divu), divergence must change the result:** `divu x3,x5,x5`, honest `13/13=1`; exploit
  `read_rs2=5 → 13/5 = 2`. (Avoid pairs where divergence doesn't change the result, e.g. `7/5=1` matches
  nothing useful — pick inputs where `op(a,a) != op(a,b)`.)

**Why a single post-exec cell edit fails (drives the A4-vs-Arguzz prediction):** editing only `read_rs2→5`
leaves `result=0` ⇒ `rem(7,5)=2 ≠ 0` ⇒ **C_local fires** ⇒ rejected. A4 does not recompute, so it cannot
produce the coherent `(read_rs2=5, result=2)` pair from one edit. A during-execution (Arguzz) operand
divergence recomputes the result naturally ⇒ coherent ⇒ accepted. **Hence: Arguzz/Hybrid expected to find
it; pure A4 (V5) expected not to** on the strong oracle — the predicted "limits of single-cell post-exec
mutation" result, to be settled empirically by A1.B3 / the A3-style CVE race (not assumed).

## 4. Oracles
- **Strong application-level (headline, ProG §3.8):** vulnerable build **ACCEPTS** the proof while the
  **committed/journal output is wrong** (≠ honest); patched build **REJECTS** the identical witness.
- **MODE-2 metamorphic (A1.B1):** output divergence vs `RUST_GUEST_CORRECT_VALUE = 0xDEADBEEF`
  (`settings.py:36`); the fuzzer logs a finding on divergence under fault injection.

## 5. Pre/post-fix bracket (the G4/G5 + G9 contract)
| build | commit | `load_rs2` | identical coherent fault | proof verifies? | committed | verdict |
|---|---|---|---|---|---|---|
| vulnerable | `98387806` | absent | rs2-read divergence + recomputed result | **ACCEPTS** | wrong (≠0) | G4 / G9 `fixed=False` |
| patched | `67f2d81` / `ebd64e43` | present | identical | **REJECTS** | — | G5 / G9 `fixed=True` |

A1.B1 confirms this bracket via the original Arguzz fuzzer (`check` at both commits); A1.B3 confirms it
deterministically in MODE-1. Both must agree on the op, the divergence, and the accept-of-wrong.
