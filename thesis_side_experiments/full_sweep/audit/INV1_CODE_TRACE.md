# INV1 — Static code + constraint trace (E5 acceptance audit)

Static analysis backing Investigation 2 classifications. Every claim cites file:line in the
frozen-host codebase (`workspace/risc0-modified/` + `zirgen/`).

## 1. Injection mechanics → trace events

### POST_EXEC_PC_MOD

**Executor path** (`execute/rv32im.rs`):

```652:688:workspace/risc0-modified/risc0/circuit/rv32im/src/execute/rv32im.rs
        if self
            .fault_inj_ctx
            .is_injection("INSTR_WORD_MOD".to_string())
        {
            let new_word = self.fault_inj_ctx.random_word(word);
            ...
            word = new_word;
        }
        ...
        if let Some(kind) = self.exec_rv32im(ctx, word)? {
            ctx.on_normal_end(kind)?
        }
        ...
        if self
            .fault_inj_ctx
            .is_injection("POST_EXEC_PC_MOD".to_string())
        {
            let new_pc = self.fault_inj_ctx.random_pc(pc);
            ...
            pc = new_pc;
            ctx.set_pc(pc);
        }
```

- Injection runs **after** instruction execution and `on_normal_end` PC advance logic.
- `random_pc` (`rv32im.rs:167-188`) picks step size (4, 8–40, 44–4000 bytes) and direction;
  accepted audit cases all show `pc:N => pc:N+4` in `<fault>` (1/6 branch of selector 0, +4 forward).

**Trace fields affected:**

| Field | Can POST_EXEC change? | Condition |
|-------|----------------------|-----------|
| `cycles[].pc` | Only if new_pc ≠ exec's natural next PC | H1 when new_pc = pc+4 on sequential insn |
| `cycles[].major/minor` | Only if PC path changes | Same |
| `txns[]` topology | Only if execution path changes | H1 when PC overwrite is no-op |
| `txns[].word/prev_word` | Only via different execution | Not changed when PC overwrite is no-op |

**Empirical (INV2):** All 30 POST_EXEC targets — semantic diff empty; all faults `pc+4`.

### INSTR_WORD_MOD

**Executor path** (`rv32im.rs:643-663`):

1. `word = ctx.load_memory(pc.waddr())?` — fetch committed instruction word from memory.
2. If `INSTR_WORD_MOD`: `word = random_word(word)` — replace word **before** decode/execute.
3. `exec_rv32im(ctx, word)` runs with mutated word.

**Trace fields affected:**

| Field | Can INSTR_WORD change? | Notes |
|-------|------------------------|-------|
| Executed semantics | Yes | Different insn if word changes meaning |
| `cycles[]` sequence | Only if control/data flow changes | H1 if mutated insn is observably equivalent |
| Program-fetch txn rows | No | Fetch still reads committed memory at PC |
| Decode constraints | See §2 — decode reads **MemoryRead at PC**, not injected word |

**Empirical (INV2):** All 7 INSTR_WORD targets — semantic diff empty.

---

## 2. Trace events → constraints

### (a) Does the circuit decode committed memory or the executed word?

**Yes — committed program memory at PC.**

```25:34:zirgen/zirgen/circuit/rv32im/v2/dsl/inst.zir
component DecodeInst(cycle: Reg, ii: InstInput) {
  pc_addr := AddrDecompose(ii.pc_u32, ii.mode);
  pc_addr.low2 = 0;
  load_inst := MemoryRead(cycle, pc_addr);
  Decoder(load_inst)
}
```

`DecodeInst` always loads via `MemoryRead` at the cycle's PC address. The executor's
`INSTR_WORD_MOD` replaces `word` passed to `exec_rv32im` in Rust only; witgen still builds
constraints from the **memory read at PC** (the committed image word), not the injected operand.

**Corroboration:** All 7 accepted INSTR_WORD runs have empty semantic witness diff — the
constraint system sees the same `(cycles, txn topology, non-noise values)` as baseline.

### (b) Which instruction bits are constrained? Does ECALL bind rs1?

Opcode-specific verification uses `VerifyOpcode*` on the **decoded** instruction from memory:

```224:226:zirgen/zirgen/circuit/rv32im/v2/dsl/inst_misc.zir
component OpECALL(input: MiscInput) {
  VerifyOpcodeF3F7(input.decoded, 0x73, 0x0, 0x00);
  MiscOutput(0, DenormedValU32(0, 0), AddU32(input.pc_u32, ValU32(0, 0)))
}
```

- ECALL constrains **opcode=0x73, f3=0, f7=0** only.
- **`rs1` is not read or constrained** for ECALL (no `ReadSourceRegs` use in `OpECALL`).
- `random_word` flips bits in `[2..31]` (`rv32im.rs:190-221`); rs1 lives in bits 15–19 of I-type
  encodings — flips there can change rs1 in the **executed** word while decode still sees committed
  ECALL encoding from memory → H1.

Store/immediate constraints bind `decoded.imm*` and `MemoryWrite` data addrs (`mem.zir:96-100`):

```96:100:zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir
component MemoryWrite(cycle: Reg, addr: Val, data: ValU32) {
  public io := MemoryIO(2*cycle + 1, addr);
  IsForward(io);
  io.newTxn.dataLow = data.low;
  io.newTxn.dataHigh = data.high;
}
```

If a word flip changes store effective address but the **committed** decode still matches executed
memory txn pattern (or flip is on unconstrained rs1/imm bits relative to decode), acceptance is H1.

### (c) Can the circuit detect *who* set the next PC?

**No provenance constraint on PC updates.**

POST_EXEC overwrites PC after execution. The circuit constrains the **resulting** PC sequence in
`cycles[]` and inter-step `IsCycle`/`IsRead` links (`mem.zir:59-90`), not whether PC came from
branch target vs sequential vs injector.

If `set_pc(pc+4)` equals the PC the executor already committed, **no cycle/txn row changes** →
constraints identical → H1. Matches all 30 POST_EXEC accepts (fault always `pc+4`, semantic diff empty).

---

## 3. Mutation → trace-event summary table

| Mutation | Executor change | cycles[] | txns[] (topology) | Decode source | Typical accept |
|----------|-----------------|----------|-------------------|---------------|----------------|
| POST_EXEC_PC pc+4 | set_pc after exec | unchanged | unchanged | N/A | **H1** |
| POST_EXEC_PC other | set_pc jumps | changed | changed | N/A | reject (control) |
| INSTR_WORD rs1/imm flip (unbound) | exec different word | unchanged | unchanged | memory @ PC | **H1** |
| INSTR_WORD semantic change | exec different path | changed | changed | memory @ PC | reject or **H2** |

---

## 4. Per-mechanism predictions vs INV2 empirical

| Mechanism | INV1 prediction | INV2 empirical | Match? |
|-----------|-----------------|----------------|--------|
| POST_EXEC_PC pc+4 | H1 (30/30) | H1 (30/30) | ✓ |
| INSTR_WORD ecall-rs1 / unbound bits | H1 | H1 (7/7) | ✓ |
| INSTR_WORD store-imm0 (H2 suspect) | H2 if addr changes in witness | H1 (0/7 show semantic change) | ✓* |

\*None of the 7 accepted INSTR_WORD samples produced a semantically different witness; they are not
counterexamples to the store-imm0 H2 hypothesis — those rejects remain in the broader N=250 set.

---

## 5. Witness dump reference

Full txn dump (`A4_DUMP_ALL_TXNS`) prints trace rows from witgen (`prove/witgen/mod.rs:154-184`).
Fields `word`, `prev_cycle`, `prev_word` come directly from `trace.txns`. Baseline reruns show
376 txn rows where only these values differ while cycles/topology match — encoder noise excluded
from semantic diff (see `AUDIT_REVIEW_REPORT.md` §3).

---

## 6. Answers (audit checklist)

| Question | Answer |
|----------|--------|
| (a) Committed vs executed word? | Circuit decodes **committed** `MemoryRead` at PC; executor may run different word under INSTR_WORD_MOD. |
| (b) ECALL rs1 bound? | **No** — only opcode/f3/f7 verified. |
| (c) PC overwrite detectable? | **Not if result equals natural next PC** — no provenance constraint. |

**INV1 predictions match INV2 for all 37 accepted samples (30 POST H1 + 7 INSTR H1, 0 H2, 0 BUG).**

---

## 7. Correction — empirical INSTR_WORD decode (the 7 H1 cases are NOT all ECALL)

§2(b) leaned on the ECALL-rs1 example. Decoding the actual fault words shows the 7 H1 cases
span **five** opcode classes; only 2 are ECALL. The unifying principle (not "it's ECALL") is:
**the fetch `MemoryRead` at `rv32im.rs:643` commits the ORIGINAL word before the mutation at
`:656`, so the circuit always decodes the original instruction; acceptance occurs iff the mutated
word, executed at this cycle's runtime state, produces the identical observable trace (register/
memory txns + pc advance) as the original.** Verified at witness level: value-diffs ⊆ the 376-txn
baseline noise set, 0 beyond noise, `semantic_empty` on all 3 nodes.

| sample | opcode | orig→new (hex) | flipped bit | why inert (H1) |
|--------|--------|----------------|-------------|----------------|
| s0804 | SYSTEM/ECALL | 0x073 → 0x20073 | 17 (rs1) | ECALL ignores rs1 (`OpECALL` binds only opcode/f3/f7) |
| s0871 | SYSTEM/ECALL | 0x073 → 0x80073 | 19 (rs1) | same |
| s0905 | BRANCH | 0x59863 → 0x1059863 | 28 (imm) | branch **not taken** (pc→+4 verified); offset unused |
| s0914 | BRANCH | 0x2060063 → 0x2060263 | 9 (imm) | branch **not taken** (pc→+4 verified); offset unused |
| s0824 | STORE | 0x1d12423 → 0x1d124a3 | 7 (imm[0]) | immediate bit inert for the committed word-level memory txn at runtime |
| s0852 | LOAD | 0x812603 → 0xa12603 | 21 (imm) | immediate bit inert for the committed load txn at runtime |
| s0892 | OP-IMM | 0x16b693 → 0x216b693 | 25 | field bit that does not change the observable result at runtime |

The first four have a crisp closed-form reason (don't-care field / not-taken branch). The last
three are confirmed H1 empirically (identical witness) and are best described as immediate/operand
bit-flips rendered observationally inert by the cycle's runtime operands; exact per-bit reasoning
would require decoding each instruction's runtime register values, but the witness-equivalence is
proven regardless.
