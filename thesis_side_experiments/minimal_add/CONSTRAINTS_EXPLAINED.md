# Arguzz mutations → constraints broken → what they mean (E1)

This is the intuitive companion to `artifacts/e1/arguzz_summary.md`. For every Arguzz
mutation we ran, it explains **which exact constraint broke**, **what that constraint
physically enforces**, and **why this mutation broke that one and not others**. All
constraint locations are from the RISC-Zero rv32im v2 circuit ZIR
(`zirgen/zirgen/circuit/rv32im/v2/dsl/…`), verified against source.

---

## 0. The guest and what each mutation targets

Guest: `load x → load y → add s=x+y → store s → read-back r → commit(r)` (= 7).

| Arguzz kind | targets | what it edits (in the executor) |
|---|---|---|
| `LOAD_VAL_MOD` | the `lw` that loads `x` | the value the load delivers to its dest register |
| `COMP_OUT_MOD` | the `add` | the result the ALU writes |
| `STORE_OUT_MOD` | the `sw` | the value written to memory |
| `INSTR_WORD_MOD` | the `add`'s fetched word | the 32-bit instruction the executor runs |

**Key architectural fact:** Arguzz mutates *inside the executor*. The executor then
builds a **fully self-consistent (but wrong) trace** around the mutated value/word —
every downstream read sees the mutated value, so the trace agrees with itself almost
everywhere. This is why Arguzz failures concentrate in a *single* place.

---

## 1. The three layers (what "local / interstep / global" physically mean)

- **Intrastep-local** — a check *within one cycle/row*: "the value this row recorded
  must equal the value this row's own logic computes." Catches a lie that is visible
  without looking at any other row.
- **Interstep-local** — a check *between two rows for the same address*: memory
  consistency ("a read returns the last value written there", "cycles go forward").
  Catches a lie only visible by comparing two rows.
- **Global** — a whole-trace **permutation/lookup argument**: the multiset of every
  memory transaction `(address, value, cycle)` must balance (every read pairs with the
  matching prior write). Catches a lie that each row hides locally but that makes the
  trace-wide bookkeeping not add up.

---

## 2. The exact constraints we broke

### `MemoryWrite` — `mem.zir:99` → **intrastep-local**
```
component MemoryWrite(cycle, addr, data) {
  io := MemoryIO(2*cycle + 1, addr);
  IsForward(io);
  io.newTxn.dataLow  = data.low;    // <-- line 99
  io.newTxn.dataHigh = data.high;
}
```
**Means:** the value physically recorded in this cycle's write transaction must equal
the `data` the cycle produced. **Broken by:** `LOAD_VAL_MOD`, `COMP_OUT_MOD`,
`STORE_OUT_MOD`. Arguzz changes the recorded value but the circuit re-derives the
"correct" `data` from the (unchanged) inputs → the equality fails by exactly the value
delta. **Measured residue:** COMP seed 0 wrote 6 instead of 7 → residue
`2013265920 = p − 1 = (6 − 7) mod p`. One row lies about one number → exactly one
intrastep-local failure, nothing else.

### `VerifyOpcodeF3F7` / `VerifyOpcodeF3` — `inst.zir:101-104` → **intrastep-local (decode)**
```
component VerifyOpcodeF3F7(decoded, opcode, func3, func7) {
  decoded.opcode = opcode;   // 102
  decoded.func3  = func3;    // 103
  decoded.func7  = func7;    // 104
}
```
**Means:** the opcode/func3/func7 *decoded from the fetched instruction word* must
equal the values the executing op-handler (e.g. `OpXOR`) expects. **Broken by:**
`INSTR_WORD_MOD` when it changes the **operation bits (func3/func7)**. The executor
runs the new op (e.g. XOR) but the fetched word still decodes ADD's func3=0, while
`OpXOR` requires func3=4 → line 103 `decoded.func3 = func3` fails. **Measured
residue:** seed 0 → `2013265917 = p − 4 = (0 − 4) mod p`, exactly the func3 gap. One
decode mismatch → one intrastep-local failure.

### `AddrDecomposeBits` — `inst.zir`/decode → **intrastep-local**
**Means:** memory-access instructions decompose their target address into bit-fields
that must be internally consistent (alignment / range). **Broken by:** `INSTR_WORD_MOD`
seed 22 (`ADD → SB`, a store) — turning a register op into a store forces address
decomposition that the cycle was never set up for → 2 intrastep-local failures.

### Global **memory family** (permutation argument) → **global**
**Means:** across the whole trace, every register/RAM transaction must permute-match
its counterpart (each read pairs with the last write to that address). **Broken by:**
`INSTR_WORD_MOD` when it changes a **register field (rd / rs1 / rs2)** while keeping a
valid ADD. The executor reads/writes a *different* register than the fetched word
names; each individual row is internally consistent (decode passes, the ALU math
checks out), so **no local constraint fires** — but the trace-wide register bookkeeping
no longer balances → the global memory residue is nonzero. **This is the cleanest
demonstration of a lie that is locally invisible but globally caught.**

### `IsRead` / `IsForward`/`IsCycle` — `mem.zir:78-85` → **interstep-local** (NOT hit by Arguzz here)
```
component IsRead(io) { io.oldTxn.data = io.newTxn.data; }     // read returns last-written value
component IsForward(io) { IsCycle(io.newTxn.cycle - 1 - io.oldTxn.cycle); }  // time goes forward
```
**Means:** a read at an address returns the value last written there, and cycles
advance. **Why Arguzz never breaks these:** because Arguzz propagates the mutated value
consistently, the later read *agrees* with the (mutated) earlier write — so
cross-row memory consistency still holds. **This is exactly the slot we expect A4 to
break** (A4 edits the witness *after* execution, leaving the downstream read stale).

---

## 3. Per-mutation intuitive summary

| mutation | what we did | constraint broken | layer | one-line intuition |
|---|---|---|---|---|
| `LOAD_VAL_MOD` | load delivers wrong x | `MemoryWrite@mem.zir:99` | intrastep | the load's own row says "I loaded V" but its math says otherwise |
| `COMP_OUT_MOD` | add writes wrong sum | `MemoryWrite@mem.zir:99` | intrastep | the add's row records 6 but x+y=7 |
| `STORE_OUT_MOD` | store writes wrong value | `MemoryWrite@mem.zir:99` | intrastep | the store row records the wrong byte vs its source reg |
| `INSTR_WORD_MOD` (func3/func7) | ADD→XOR/SLL/SUB/SLT | `VerifyOpcodeF3F7@inst.zir:103` | intrastep | "you ran XOR but the bytes say ADD" |
| `INSTR_WORD_MOD` (rd/rs1/rs2) | ADD→ADD, different reg | global memory family | global | valid ADD everywhere locally, but it touched the wrong register — only the trace-wide ledger notices |
| `INSTR_WORD_MOD` (rd = a0) | ADD writes into base ptr | 6× intrastep + global | mixed | corrupting a0 (the store's base pointer) cascades through later rows |
| `INSTR_WORD_MOD` (opcode → ADDI/SB) | format change | `VerifyOpcodeF3`/`AddrDecomposeBits` (+global) | mixed | a different *format* trips multiple decode/addr checks |
| `INSTR_WORD_MOD` (opcode → JAL/JALR/BLTU/SYSTEM) | control-flow word | **none** — prover crashes | n/a | the jump derails execution pre-witgen; prover errors in ~37 ms (host panic `main.rs:106`) before any constraint runs |

---

## 4. The headline bias picture (Arguzz side, to be contrasted with A4 in E2/E3)

- **Value mutations** (`LOAD`/`COMP`/`STORE`): **exactly 1 intrastep-local** failure,
  0 interstep, 0 global — every time. Pure executor propagation: one row lies, the lie
  flows consistently downstream, the lone intra-row write↔compute check catches it.
- **Instruction-word mutations** show that **different instruction fields are guarded
  by different layers**: operation bits → intrastep-local *decode*; register fields →
  *global* memory only (0 local!); format/opcode → multiple checks or a prover crash.
- **Arguzz never breaks interstep-local** here, because it never leaves a stale value
  behind — that is precisely the gap E2/E3 will show A4 filling.
