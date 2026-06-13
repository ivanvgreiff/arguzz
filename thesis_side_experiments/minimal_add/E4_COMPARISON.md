# E4 — Arguzz vs A4: the constraint-breaking bias (capstone)

**Guest:** `load x → load y → add s=x+y → store s → read-back r → commit(r)` (= 7), one frozen
host (sha `5337f944…`), Arguzz run on WSL+POS (certified POS≡WSL), A4 run on `polynize`.
This document is the readable synthesis; the **exhaustive per-run table is
`artifacts/e4/MATRIX_GRANULAR.md`** (99 runs), and the intuition behind each constraint is in
`CONSTRAINTS_EXPLAINED.md` (Arguzz) + `A4_CONSTRAINTS_EXPLAINED.md` (A4). Footprints are written
`intrastep-local / interstep-local / global`.

---

## The headline result

> **Arguzz mutates in the executor → it builds a globally-consistent *wrong* trace, so its
> failures stay LOCAL-ONLY. A4 mutates the witness → its surgical edit is inconsistent with the
> neighbours, so it additionally breaks the GLOBAL memory argument, and — uniquely — can reach
> the INTERSTEP memory-consistency layer.**

The discriminating axis between the two fuzzers is the **global** layer (and, for `MEM_VAL_MOD`,
the **interstep** layer). The *local* footprint is, for most mutations, identical between them.

## Which layer can each tool reach?

| layer | what it checks | Arguzz | A4 |
|---|---|---|---|
| **intrastep-local** | within-cycle: write == computed; decode funct matches op | ✅ value kinds, operation words | ✅ same |
| **interstep-local** | a memory read returns the last value written there (`IsRead`) | ❌ never (propagation keeps reads consistent) | ✅ **`MEM_VAL_MOD` only** |
| **global** | trace-wide memory permutation must balance | ⚠️ only register-field word changes | ✅ **almost every mutation** |

## Master matrix (by semantic target; full per-seed table in MATRIX_GRANULAR.md)

| semantic mutation | Arguzz | A4-FULL | A4-SUR | A4-MEM_VAL |
|---|---|---|---|---|
| **value** — COMP / LOAD / STORE (all seeds) | **1/0/0** | **1/0/1** | — | — |
| INSTR_WORD **operation** (funct3/funct7) | **1/0/0** | **1/0/1** | 1/0/1 | — |
| INSTR_WORD **register** (rd / rs1 / rs2) | **0/0/1** | **0/0/1** | **0/0/1** | — |
| INSTR_WORD `rd=a0` (downstream base ptr, s24) | **6/0/1** | 0/0/1 | — | — |
| INSTR_WORD **format change** (ADDI/XORI/SB…) | mixed (1–3 / 0 / 0–1) | 1–3/0/1 | — | — |
| INSTR_WORD **control-flow** (JAL/JALR/BLTU/SYSTEM) | **PROVE_ERROR** (crash) | n/a | — | — |
| **memory read** (load / store-RMW / read-back) | **n/a** (no Arguzz mirror) | — | — | **2/2/1** load · **0/2/1** store-RMW |

---

## Four worked examples in full granular detail

### A. Value mutation — the bias in its purest form (`COMP_OUT_MOD` s0: result 7→6)
- **Arguzz `1/0/0`** — breaks only `MemoryWrite@mem.zir:99` (residue `p−1 = (6−7)`, verified).
  The wrong `6` flows to the store and read-back consistently → global ledger balances.
- **A4-FULL `1/0/1`** — same `MemoryWrite@mem.zir:99` (`p−1`) **plus** global `memory` family.
  A4 rewrote only the add's write txn to `6`; the store still recorded reading `7` → the
  write/read pairing can't balance → global break.
- **Takeaway:** identical local failure; the **global hit is the entire A4 surcharge**.

### B. Instruction word, operation field — the executor↔witness mirror (`s0`: ADD→XOR)
- **Arguzz `1/0/0`** — `VerifyOpcodeF3F7` **at OpXOR** (`inst.zir:103`), residue `p−4`:
  executor ran XOR, fetched funct3 still says ADD (`0`), XOR expects `4` → `0−4`.
- **A4-FULL `1/0/1`** — `VerifyOpcodeF3F7` **at OpADD**, residue `+4`: executor ran ADD,
  witness word now says XOR (`4`), ADD expects `0` → `4−0`. Plus global memory (A4 rewrote the
  fetched-word read txn).
- **Takeaway:** the *same* decode constraint, broken from **opposite directions**, residue
  sign-flipped — a clean fingerprint of executor-stage vs witness-stage mutation.

### C. Register identity is global for everyone (`rs1`: ADD x11,x11,x12 → x11,x15,x12)
- **Arguzz `0/0/1`**, **A4-FULL `0/0/1`**, **A4-SUR `0/0/1`** — all three: **zero** local/inter
  failures (`failure_count=0`), only the global `memory` family. Changing *which register* is
  used is a valid ADD either way, so no local decode fires; the mismatch surfaces only in the
  trace-wide permutation. **This denies the hypothesis** that A4's surgical source-register edit
  would add a local break — register consistency is globally enforced regardless of fuzzer/mode.

### D. The `a0` cascade — executor propagation vs surgical edit (`s24`: add writes a0)
- **Arguzz `6/0/1`** — retargeting the add's destination to `a0` (the store's base pointer)
  makes the executor *really* corrupt the pointer, so **6 downstream local checks** fail + global.
- **A4-FULL `0/0/1`** — A4 only rewrote the fetched word; the executor ran the original, so `a0`
  is never actually corrupted → nothing propagates → only the global ledger notices.
- **Takeaway:** Arguzz cascades through execution; A4's edit is inert downstream. Same intended
  change, opposite blast radius.

### E. The interstep layer — A4-exclusive (`MEM_VAL_MOD` on a load read: 3→0x9E3779B4)
- **A4 `2/2/1`** — `MemoryWrite@99/100` (intra, the value delivered to the dest register) +
  **`IsRead@mem.zir:79/80` at `MemoryRead:90` (interstep)** + global. The mutated read value
  disagrees with what memory holds → the "read returns last-written value" check fails.
- **Arguzz: n/a** — no in-place memory-read mutation exists; its propagating kinds keep reads
  self-consistent by construction. **This is the only way the interstep layer is ever
  populated in the entire study.**

---

## Conclusion (the thesis claim, supported by 99 runs)

1. **Arguzz is biased toward LOCAL-only failures.** Because it mutates in the executor, every
   downstream transaction agrees with the lie; only the within-cycle constraint catches it
   (`1/0/0` on values and operation words). Its *only* route to a global break is changing a
   register field in an instruction word (`0/0/1`), and even then it never touches interstep.
2. **A4 is biased toward LOCAL+GLOBAL failures,** and is the **only** tool that reaches
   **interstep**. Its surgical witness edits are inconsistent with the un-mutated neighbours, so
   the global memory permutation breaks on essentially every mutation, and `MEM_VAL_MOD` breaks
   `IsRead` outright.
3. **What is fuzzer-invariant:** register-identity changes are `0/0/1` for everyone (global is
   where this circuit enforces register consistency); and Arguzz control-flow word mutations
   crash the prover pre-witgen (`PROVE_ERROR`), upstream of all constraints.

> **Bias, in one line:** *Arguzz hides its mutation locally inside a self-consistent trace; A4's
> surgical edit exposes it to the global (and interstep) consistency machinery.*
