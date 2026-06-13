# A4 mutations → constraints broken → what they mean (E2)

The A4 companion to `CONSTRAINTS_EXPLAINED.md` (Arguzz). For every A4 mutation we ran, this
explains **which exact constraint broke**, **what it enforces**, and — crucially — **how it
mirrors / diverges from the Arguzz result on the same semantic change**. Constraint
locations are from the rv32im v2 circuit ZIR (`zirgen/zirgen/circuit/rv32im/v2/dsl/…`),
verified against the E2 per-run JSONs (`artifacts/e2/pos_full/analysis/`). Exhaustive
per-run data: `artifacts/e4/MATRIX_GRANULAR.md`.

---

## 0. What A4 edits, and why that changes everything

Arguzz mutates **inside the executor**, so it builds a fully self-consistent (but wrong)
trace — the wrong value/instruction propagates everywhere. **A4 mutates the witness
*after* execution**: it surgically rewrites one recorded transaction (a value or the fetched
word) while every *other* transaction keeps the value the executor really produced. That one
difference is the whole story:

> Arguzz's lie is consistent with itself → only a **local** check catches it.
> A4's lie is **inconsistent with its neighbours** → it additionally breaks the **global**
> memory argument, and (for memory reads) the **interstep** consistency check.

| A4 mutation | what it rewrites in the witness | Arguzz counterpart |
|---|---|---|
| `COMP_OUT_MOD` / `LOAD_VAL_MOD` / `STORE_OUT_MOD` (forced value) | the recorded register/memory **write value** | same (value kinds) |
| `INSTR_WORD_MOD_FULL` | the recorded **fetched instruction word** | `INSTR_WORD_MOD` (mirror) |
| `INSTR_WORD_MOD_SUR` | **one field** of the fetched word (funct3/funct7/rd/rs1/rs2) | none (Arguzz can't target a field) |
| `MEM_VAL_MOD` | a recorded **memory READ value** | **none** (Arguzz has no in-place memory-read edit) |

---

## 1. The constraints A4 broke

### `MemoryWrite@mem.zir:99` (+`:100`) → intrastep-local — *shared with Arguzz*
`io.newTxn.dataLow = data.low` (and `:100` the high half): the value recorded as written
this cycle must equal what the cycle computed. **A4 value kinds break this identically to
Arguzz** — e.g. `COMP_OUT_MOD` s0 forces 7→6, residue `p−1`, provenance verified. This is the
*shared* intrastep failure.

### Global **memory family** (permutation argument) → global — *the A4 surcharge*
The whole-trace memory permutation: every recorded read/write must pair up (each read returns
the last write to its address). **A4 adds this break on essentially every mutation**, because
the rewritten transaction no longer agrees with its neighbours:
- **value kinds:** the write txn says `6` but the downstream read (executor) still recorded
  `7` → the pairing fails. (Arguzz propagated `6` everywhere → pairing balances → *no* global.)
- **`INSTR_WORD_MOD_FULL`:** A4 rewrote the **fetched-word memory read** itself, so that read
  no longer matches instruction memory → global memory break, regardless of which field changed.

### `VerifyOpcodeF3F7@inst.zir:103` → intrastep-local (decode) — *mirror of Arguzz, sign-flipped*
`decoded.func3 = func3`: the funct bits of the fetched word must match the operation the cycle
executes. The **mirror** is exact and verified:
- **Arguzz** seed 0: executor ran XOR, fetch word = ADD → fails **at OpXOR** (expected funct3
  `4`, saw `0`), residue `p−4`.
- **A4-FULL** seed 0: executor ran ADD, witness word = XOR → fails **at OpADD** (expected funct3
  `0`, saw `4`), residue `+4`.
Same constraint, opposite direction — a textbook executor-vs-witness mirror.

### `IsRead@mem.zir:79`/`:80` (at `MemoryRead@mem.zir:90`) → interstep-local — *A4 only*
`io.oldTxn.dataLow = io.newTxn.dataLow` (and `:80` high): a memory **read must return the value
last written at that address**. Only **`MEM_VAL_MOD`** reaches this — by rewriting a memory
read value so it disagrees with what's stored. **This is the only mutation in the whole study
that populates the interstep layer**, and Arguzz structurally cannot do it (it has no in-place
memory-read edit; its `LOAD_VAL_MOD` touches the register side, and propagation keeps reads
consistent).

---

## 2. Per-A4-mutation intuitive summary

| A4 mutation | footprint (i/inter/g) | constraints broken | vs Arguzz |
|---|---|---|---|
| `LOAD/COMP/STORE` forced value | **1/0/1** | `MemoryWrite@99` (intra) + global memory | Arguzz **1/0/0** — A4 **adds global** (stale neighbour) |
| `INSTR_WORD_MOD_FULL`, operation (funct3/funct7) | **1/0/1** | `VerifyOpcodeF3F7` at **OpADD** (intra) + global memory | Arguzz **1/0/0** (fails at OpXOR) — A4 adds global (rewrote fetch txn) |
| `INSTR_WORD_MOD_FULL`, register (rd/rs1/rs2) | **0/0/1** | global memory only | Arguzz **0/0/1** — *same triple*; both global-only |
| `INSTR_WORD_MOD_FULL`, `rd=a0` (s24) | **0/0/1** | global only | Arguzz **6/0/1** — Arguzz *cascades* (executor corrupts a0 → downstream); A4 does **not** (witness edit doesn't propagate) |
| `INSTR_WORD_MOD_SUR` funct3/funct7 | **1/0/1** | `VerifyOpcodeF3F7` + global | isolates the decode break surgically |
| `INSTR_WORD_MOD_SUR` rd / rs1 / rs2 | **0/0/1** | global only | **asymmetry denied** — even a single-field source-reg edit is global-only |
| `MEM_VAL_MOD` load read | **2/2/1** | `MemoryWrite@99/100` (intra) + `IsRead@79/80` (**inter**) + global | **no Arguzz mirror** — reaches interstep |
| `MEM_VAL_MOD` store RMW read | **0/2/1** | `IsRead@79/80` (**inter**) + global | the RMW read isn't delivered to a register → no intra |

---

## 3. The three sharpest mirror contrasts (verified)

1. **Value kinds — the headline bias.** Identical local failure; A4 alone breaks global.
   `1/0/0` (Arguzz) vs `1/0/1` (A4) on all 15 value rows. *Why:* Arguzz propagates the wrong
   value consistently; A4 leaves the downstream read stale.
2. **The `a0` cascade (s24).** Arguzz `6/0/1` vs A4 `0/0/1`. Re-targeting the add's destination
   to `a0` (the store's base pointer) **cascades through 6 local checks under Arguzz** because
   the executor really uses the corrupted pointer downstream; under A4 the executor ran the
   original, so nothing propagates — only the global ledger notices. Pure executor-propagation
   vs surgical-witness, in one row.
3. **The interstep layer is A4-exclusive.** `MEM_VAL_MOD` breaks `IsRead@mem.zir` (8 rows);
   nothing Arguzz did touches interstep at all.

---

## 4. Bottom line (feeds E4)
- **Register identity** (rd/rs1/rs2) is enforced **globally** in this circuit — so it is
  `0/0/1` for *every* fuzzer and *every* mutation mode (Arguzz, A4-FULL, A4-SUR). The
  local-vs-global split for instruction words is set by **field type** (operation→local decode,
  register→global), not by the fuzzer.
- **The fuzzer-dependent bias lives in the value kinds and in reach:** Arguzz stays
  **local-only**; A4 is **local+global**; and **only A4 reaches the interstep memory layer**.
