# Add-Instruction Local Constraint Catalog (ground truth)

The 37 local constraint contexts (`major=0, minor=0`) the guest `add s0, a0, a1` exercises,
read directly from `zirgen/zirgen/circuit/rv32im/v2/dsl/*.zir`. Each row gives the **verbatim
zirgen equation** and an **intuitive form** in the thesis's vocabulary
(`rs1, rs2, rd, read(), write(), val(), prev_write()`).

Source of truth, not heuristic: every `loc` is an exact `file:line:col`. Verified by reading the
DSL and (for failing constraints) by matching the BabyBear residue value.

Convention used below: `read(r)` = value a step records reading from register `r`;
`val(r)` = value currently stored in `r` (its most-recent prior write); `write(r)` = value a step
records writing to `r`; `decode(word)` = fields parsed from the instruction word.

---

## Stage 1 — FETCH: turn the PC into an address and read the instruction word

| # | zirgen loc | verbatim zirgen | intuitive form |
|---|-----------|-----------------|----------------|
| 1 | `AddrDecompose@u32.zir:67` | `IsZero(x.high) = 0` | the PC is not in the forbidden zero page |
| 2 | `AddrDecompose@u32.zir:71` | `med14*4 + low2 = x.low` | the PC's bytes recompose into a valid word-address |
| 3 | `DecodeInst@inst.zir:29` | `pc_addr.low2 = 0` | the PC is 4-byte aligned |

(The actual fetch *read* is a memory read → its consistency is covered by Stage 3.)

## Stage 2 — DECODE: parse the word and confirm it is an ADD

| # | zirgen loc | verbatim zirgen | intuitive form |
|---|-----------|-----------------|----------------|
| 4 | `Decoder@decode.zir:37` | `inst.high = Σ (bit/twit fields · weights)` | the parsed fields recompose into the instruction's high half |
| 5 | `Decoder@decode.zir:46` | `inst.low  = Σ (bit/twit fields · weights) + opcode` | the parsed fields recompose into the instruction's low half |
| 6 | `VerifyOpcodeF3F7@inst.zir:102` (OpADD) | `decoded.opcode = 0x33` | opcode says "R-type ALU op" |
| 7 | `VerifyOpcodeF3F7@inst.zir:103` (OpADD) | `decoded.func3 = 0x0` | funct3 says "ADD/SUB family" |
| 8 | `VerifyOpcodeF3F7@inst.zir:104` (OpADD) | `decoded.func7 = 0x00` | funct7 says "ADD (not SUB)" → `decode(word) = add rd,rs1,rs2` |
| 9 | `Misc0@inst_misc.zir:32` | `misc_output := minor_onehot -> (OpADD, …)` | the minor selector routes execution to the ADD arm |
| 10 | `MiscInput@inst_misc.zir:7` | `inst_input.state = StateDecode()` | the instruction is processed in the decode state |

## Stage 3 — READ OPERANDS: read rs1, rs2 (and the fetch) consistently from memory

| # | zirgen loc | verbatim zirgen | intuitive form |
|---|-----------|-----------------|----------------|
| 11 | `IsRead@mem.zir:79` | `oldTxn.dataLow = newTxn.dataLow` | a READ returns the value currently stored: `read(r) = val(r)` (low 16 bits) |
| 12 | `IsRead@mem.zir:80` | `oldTxn.dataHigh = newTxn.dataHigh` | …high 16 bits |
| 13 | `IsCycle@mem.zir:61` | `arg.count = 1` | the time-ordering check claims exactly one cycle slot |
| 14 | `IsCycle@mem.zir:62` | `arg.cycle = x` | …at the right cycle (used by IsForward: the read sees the *latest* prior write) |
| 15 | `MemoryIO@mem.zir:69` | `oldTxn.count = -1` | the "remove old memory state" bookkeeping entry |
| 16 | `MemoryIO@mem.zir:70` | `newTxn.count = 1` | the "add new memory state" bookkeeping entry |
| 17 | `MemoryIO@mem.zir:71` | `newTxn.cycle = memCycle` | the access is stamped with this step's cycle |
| 18 | `MemoryIO@mem.zir:73` | `oldTxn.addr = newTxn.addr` | old and new state refer to the same address |
| 19 | `MemoryIO@mem.zir:74` | `newTxn.addr = addr` | …namely the address being accessed |
| 20 | `ReadSourceRegs@inst.zir:49` | `is_same_reg*(1-is_same_reg) = 0` | the rs1==rs2 flag is a clean yes/no |
| 21 | `DoCycleTable@inst.zir:21` | `arg1.cycle = 2*cycle` | this step claims its slot in the global cycle table (even half) |
| 22 | `DoCycleTable@inst.zir:22` | `arg2.cycle = 2*cycle + 1` | …(odd half) |

## Stage 4 — COMPUTE & WRITE: `rd = rs1 + rs2`, written back

| # | zirgen loc | verbatim zirgen | intuitive form |
|---|-----------|-----------------|----------------|
| 23 | `MemoryWrite@mem.zir:99` | `newTxn.dataLow = data.low` where `data = AddU32(rs1,rs2)` | **`write(rd) = read(rs1) + read(rs2)`** (low 16 bits) — this is the ADD arithmetic |
| 24 | `MemoryWrite@mem.zir:100` | `newTxn.dataHigh = data.high` | …high 16 bits (carry-propagated) |
| 25 | `NormalizeU32@u32.zir:46` | `x.low = lowCarry*0x10000 + low16` | the sum's low half splits into a 16-bit limb + carry |
| 26 | `NormalizeU32@u32.zir:52` | `high = highCarry*0x10000 + high16` | the sum's high half splits into a 16-bit limb + carry |

## Stage 5 — WITNESS HYGIENE (plumbing): keep nondeterministic helpers honest

| # | zirgen loc | verbatim zirgen | intuitive form |
|---|-----------|-----------------|----------------|
| 27 | `AssertBit@bits.zir:7` (at IsZero) | `val*(1-val) = 0` | a helper bit is really 0 or 1 |
| 28 | `AssertBit@bits.zir:7` (at NondetBitReg) | `val*(1-val) = 0` | a decoded bit is really 0 or 1 |
| 29 | `AssertTwit@bits.zir:38` (at NondetTwitReg) | `val(1-val)(2-val)(3-val) = 0` | a decoded 2-bit field is really 0..3 |
| 30 | `IsZero@is_zero.zir:16` | `val*inv = 1 - isZero` | zero-test gadget: nonzero ⇒ has an inverse |
| 31 | `IsZero@is_zero.zir:18` | `isZero*val = 0` | zero-test gadget: if "is zero" then value is 0 |
| 32 | `IsZero@is_zero.zir:20` | `isZero*inv = 0` | zero-test gadget: if "is zero" then inverse is 0 |
| 33 | `OneHot@one_hot.zir:9` | `Σ bits = 1` | exactly one selector bit is set |
| 34 | `OneHot@one_hot.zir:11` | `Σ bits[i]·i = v` | …and it is the correct one |
| 35 | `NondetU16Reg@lookups.zir:43` | `arg.count = 1` | a limb participates once in the 16-bit range lookup |
| 36 | `U16Reg@lookups.zir:51` | `ret = val` | …and the looked-up value matches the register |
| 37 | `Reg(<preamble>:6)` | register-cell `NondetReg` wiring | a register witness cell is wired in |

---

## Mapping to the thesis §3.3.3 intuitive constraint list

The thesis lists 6 "local" + 3 "interstep" + 2 "global" constraints. Here is how they map to the
real circuit (and where the current wording is imprecise):

| Thesis intuitive constraint | Backed by (real zirgen) | True category | Note |
|-----------------------------|--------------------------|---------------|------|
| `fetched(word) = memory(pc)` | IsRead/MemoryIO on the fetch txn (Stage 3) + memory arg | local read + **global** | the fetch is just another memory read |
| `decode(word) = add rd,rs1,rs2` | Decoder:37,46 + VerifyOpcodeF3F7:102–104 | local | accurate |
| `read(rs1) = val(rs1)` | IsRead:79,80 on rs1 txn | local (value); **global** for "val is real" | split: local read==claimed-prev; closure is global |
| `read(rs2) = val(rs2)` | IsRead:79,80 on rs2 txn | local + global | same |
| `write(rd) = val(rd)` | MemoryWrite:99,100 | local | "recorded write == intended value" |
| `read(rs1)+read(rs2) = write(rd)` | MemoryWrite:99,100 with `data=AddU32(rs1,rs2)` (+ NormalizeU32) | local | **there is no separate ALU polynomial — the sum is checked AT the write** |
| `prev_write(rs) = read(rs)` (interstep) | IsRead (local part) + memory permutation arg (global part) | **split local/global** | v2 does not have a standalone interstep equality; it is local IsRead + global memory argument |
| `write(rd) = next_read(rd)` (interstep) | only enforced when rd is later read → memory permutation arg | **global** | not a local constraint here |
| `(pc,word) ∈ program_memory_table` (global) | program/memory LogUp | **global (Hook 3)** | deferred until we observe a global failure |
| `(step,reg,val) ∈ register_memory_argument` (global) | memory permutation arg | **global (Hook 3 `memory`)** | deferred |

**Key correction for the thesis:** in RISC Zero v2, registers are memory-mapped, so the "register
read/write" constraints and the "interstep prev_write/next_read" constraints are **not** separate
local polynomials. They decompose into (a) a **local** check that a read returns its *claimed*
previous value (`IsRead`) and that a write records its *intended* value (`MemoryWrite`), plus (b) a
**global** permutation argument (Hook 3 `memory`) that proves those claimed/previous values are real
and consistent across the whole trace. The ADD's arithmetic `rs1+rs2=rd` is enforced **at the write**
(`MemoryWrite@99/100`), not by a named ALU constraint.

Global constraints are intentionally deferred: we will pin their exact identity when M2/M3 produce
actual nonzero Hook-3 family residues.
