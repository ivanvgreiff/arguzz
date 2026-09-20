# CVE constraint audit — exact per-substep constraint trace of the remu rs2-alias (Arguzz), buggy vs patched

# PART −1 — Why `a1→a0` (alias) is the bug but `a1→a3` (any other register) is NOT — RESOLVED & MEASURED

A natural objection: if the circuit just consumes the executor's transactions positionally (with address checks
suppressed under fault injection), why isn't a substitution to *any* other register, e.g. `a1→a3`, also
accepted on the buggy commit? And if something catches `a1→a3`, why doesn't it catch `a1→a0`? This is now
**measured and resolved** (diagnostics: `A4_TRACE_TXN` = requested-vs-consumed address per access;
`A4_FAMILY_RESIDUE` = per-argument balance; logs `b2_tracetxn.log`, `b2_nonalias_x9.log`, `g5_nonalias_x9.log`).

**Measured results:**
| mutation | B2 (vuln) | G5 (patched) | the catch |
|---|---|---|---|
| `a1→a0` (alias; rs1==rs2) | **ACCEPT** (wrong output 0) | **REJECT** | G5: `load_rs2` reads once → writeback desync (PART 0/§6d). B2: nothing catches it. |
| `a1→x9` (non-alias; `remu x14,x10,x9`) | **REJECT** (memory residue ≠ 0) | **REJECT** (memory residue ≠ 0) | the **global memory permutation argument**, on *both* binaries |

**The mechanism (all from `A4_TRACE_TXN` + the transaction dumps):**
1. The circuit **always decodes the ORIGINAL fetched word** `remu a4,a0,a1` (the fetch txn carries the original;
   the rs2 read provably *requests a1*, address `0x3fffc02b`). Under fault injection `extern_getMemoryTxn`
   suppresses the address-mismatch throw, so the rs2 read **consumes whatever transaction comes next**,
   regardless of address, and emits two memory-argument records **keyed by the requested address a1**:
   `newTxn=(a1, this_cycle, consumed.word)` and `oldTxn=(a1, consumed.prev_cycle, consumed.prev_word)`.
2. **Alias `a1→a0`:** the executor's mutated `remu a0,a0` reads a0 **twice on the same cycle**, so the consumed
   second-a0 transaction has `prev_cycle == this_cycle`. The two records become `(a1, C, 9, +1)` and
   `(a1, C, 9, −1)` — **identical tuple → they self-cancel** → the bogus a1 read is **invisible** to the memory
   argument → it balances (B2 measured memory residue 0). *(This is also why the earlier "shouldn't B2's memory
   argument break?" worry dissolves.)*
3. **Non-alias `a1→r` (r≠a0):** the executor reads a0 and `r` (two *different* registers). The consumed `r`
   transaction has `prev_cycle` = `r`'s **earlier** access, ≠ this cycle. So the records are `(a1, this_cycle,
   v_r, +1)` and `(a1, r_prev_cycle, …, −1)` — **different cycles → do NOT cancel** → they corrupt a1's
   permutation chain → **memory residue ≠ 0 → reject** (measured on B2 *and* G5).

**So the constraint that catches `a1→a3`/`a1→x9` but not `a1→a0` is the global memory permutation argument**,
and the alias escapes it *only* because the aliased re-read is **same-cycle**, making its spurious records
self-cancel. Every non-same-register substitution is caught. The bug is therefore genuinely **same-register /
same-cycle** — narrow, not a broad operand-substitution hole. (Note: in the measured non-alias run, x9's value
was 12345 so `9 % 12345 = 9` and the *output* didn't change — yet B2 still **rejected** at the proof level via
the memory argument, confirming the catch is independent of output divergence.)

---

# PART 0 — Plain-language walkthrough: three scenarios, step by step through the emulator

This section walks the **same `remu` instruction** through the RISC-V emulator (`execute/rv32im.rs`) in three
scenarios, one baby-step at a time. At each step it states (a) what data the emulator has in hand, (b) what it
does with it, and (c) what gets recorded for the proof (a memory transaction, and/or a value the proof's
constraints will check). Read the three side by side to see where the mutation takes effect and where (and
why) a constraint breaks. Every number below is **measured** (from the transaction dumps, logs in `logs/`),
except the one place in Scenario 3 explicitly marked "(not directly observable)".

**Setup (common to all three).** The guest runs `remu a4, a0, a1` (write the remainder of `a0 % a1` into a4).
With the inputs used (`--ctrl 7 --gseed 12345`): register **a0 = 9** and **a1 = 12602** (a0 < a1). The honest
remainder is `9 % 12602 = 9`. The instruction's 32-bit machine-code word is **45446963**. Registers live in a
small region of memory: **a0 is at address 1073725482, a1 at 1073725483, a4 at 1073725486.** A "cycle number"
is attached to every memory access; reads and writes on step *N* use even/odd cycle numbers around *2N*.

**The mutation (Scenarios 2 and 3).** Arguzz's `INSTR_WORD_MOD` flips one bit of the fetched instruction word:
**45446963 → 44398387**, which changes the word from `remu a4, a0, a1` to **`remu a4, a0, a0`** — the second
source register is changed from a1 to a0. The instruction now reads **a0 twice** instead of a0 and a1. (This
bit flip is the prover tampering with what instruction actually executes, *without* changing the program
stored in memory.)

---

## SCENARIO 1 — honest `remu a4, a0, a1` (no mutation). Result: accepted, commits the correct value.

| step | what the emulator has / does | transaction recorded for the proof | what the proof checks here | outcome |
|---|---|---|---|---|
| 1. Fetch | reads the instruction word from memory at the program counter → **45446963** (`remu a4,a0,a1`) | **memory READ** at addr 524846 (the code address), value 45446963 | the fetched word matches what's in program memory | ok |
| 2. Decode | splits the word into fields → rd=**a4**, rs1=**a0**, rs2=**a1**, operation = remainder | (the decoded fields become part of the cycle's witness) | the decoded bits really compose back into the fetched word; the operation code is "remainder-unsigned" | ok |
| 3. Read rs1 | `load_register(a0)` → **9** | **memory READ** at addr 1073725482 (a0), value 9, cycle 33568 (its previous access was cycle 33565) | the read returns a0's current stored value; its cycle comes strictly after the previous access to a0 | ok |
| 4. Read rs2 | `load_register(a1)` → **12602** | **memory READ** at addr 1073725483 (a1), value 12602, cycle 33568 (previous access cycle 33567) | same as step 3, **for a different register (a1)** | ok |
| 5. Compute | `9 % 12602` = **9** | (nothing new) | the division relation holds: 9 = 0·12602 + 9, and 9 < 12602 | ok |
| 6. Write rd | `store_register(a4, 9)` | **memory WRITE** at addr 1073725486 (a4), value 9, cycle 33569 | the written value equals the computed remainder (9) | ok |

**Two reads, two *different* registers (a0 and a1).** Everything is consistent → the proof verifies → the
journal commits **9000027** (the honest value). This is the baseline.

---

## SCENARIO 2 — mutated `remu a4, a0, a0` on the BUGGY commit (B2). Result: accepted, commits the WRONG value.

| step | what the emulator has / does | transaction recorded for the proof | what the proof checks here | outcome |
|---|---|---|---|---|
| 1. Fetch | reads the word from memory → **45446963** (`remu a4,a0,a1`, the original) | **memory READ** at addr 524846, value 45446963 | fetched word matches program memory | ok |
| 2. **Mutate** | Arguzz overwrites the *local* word variable → **44398387** (`remu a4,a0,a0`). Memory is **not** changed; only the instruction the emulator is about to execute. | (none — purely local) | — | the tamper happens here |
| 3. Decode | the *emulator* decodes the **mutated** word → rd=a4, rs1=a0, rs2=a0 (this drives the reads/write below) | (the executed instruction's fields) | **the proof's circuit instead re-decodes the ORIGINAL fetched word** (it composes the fetch txn, which holds the original) → rs1=a0, rs2=**a1**; op = remainder. (See note after the table.) | ok |
| 4. Read rs1 | `load_register(a0)` → **9** | **memory READ** at addr 1073725482 (a0), value 9, cycle 21126 (previous access cycle 21123) | normal forward read | ok |
| 5. **Read rs2** | buggy code reads rs2 unconditionally: `load_register(a0)` **again** → **9** | **memory READ** at addr 1073725482 (a0 **again**), value 9, **cycle 21126, previous access cycle 21126** — i.e. the previous access is the read from step 4, **on the very same cycle** | the buggy "is this read in the right order?" check computes `cycle − previous_cycle = 21126 − 21126 = 0`, and **0 is treated as a valid gap**, so the same-cycle re-read of a0 is **allowed** | **ok (this is the hole)** |
| 6. Compute | `9 % 9` = **0** | (none) | division relation holds: 0 = 1·9 + 0, 0 < 9 | ok |
| 7. Write rd | `store_register(a4, 0)` | **memory WRITE** at addr 1073725486 (a4), value **0**, cycle 21127 | written value equals the computed remainder (0) | ok |

**Two reads, the *same* register a0 twice — on the same cycle.** (Note for symmetry with Scenario 3: the
*proof's circuit* actually decodes the **original** fetched word too — so it believes the second operand is a1
and issues a read "for a1". But the emulator recorded a read of **a0**, and the circuit's address-mismatch
check is suppressed under fault injection, so that a0 read (value 9) satisfies the circuit's "a1" read. The key
is that the emulator recorded **two** reads, exactly as many as the circuit consumes — so the transaction
stream stays aligned, the second read is same-cycle and the buggy order-check `cycle − previous_cycle = 0`
admits it, and the writeback then consumes the correct a4-write transaction (value 0 = the computed `9 % 9`).
Everything lines up; nothing fires.) The proof verifies and the journal commits **0** — but the honest program
(`remu a0,a1`) should have produced **9000027**.

> **This is the soundness bug, in one sentence:** the buggy circuit lets the prover read the *same* register
> *twice on one cycle*. So a prover can tamper one instruction to point its second operand at the first
> register, make the emulator read that register twice — keeping the proof's transaction stream aligned with
> the circuit's two-read decode — and the circuit happily proves the (wrong) result of the tampered
> instruction. "Read the register twice" is precisely the loophole.

---

## SCENARIO 3 — mutated `remu a4, a0, a0` on the PATCHED commit (G5). Result: rejected (fails verification).

The fix has two coordinated parts: (a) the emulator's new `load_rs2` helper — **when both source registers are
the same, it reuses the first read instead of reading again** (so it reads the register *once*, not twice); and
(b) the circuit's cycle-order check is tightened from `cycle − previous_cycle` to `cycle − 1 − previous_cycle`,
so a same-cycle re-read now computes `−1`, which is **not** a valid gap (it would be rejected). **For *this*
tampering it is part (a) that does the catching:** because the emulator now records only one read while the
proof's circuit (decoding the original instruction) still expects two, the proof's transaction stream is
shifted by one and the writeback no longer lines up. Part (b) is the backstop for a different attack — a prover
who tries to read the same register twice on one cycle directly.

| step | what the emulator has / does | transaction recorded for the proof | what the proof checks here | outcome |
|---|---|---|---|---|
| 1. Fetch | reads the word from memory → **45446963** (`remu a4,a0,a1`, original) | **memory READ** at addr 524846, value 45446963 | fetched word matches program memory | ok |
| 2. **Mutate** | Arguzz overwrites the local word → **44398387** (`remu a4,a0,a0`) | (none — local) | — | tamper happens here |
| 3. Decode | the *emulator* decodes the mutated word → rd=a4, rs1=a0, rs2=a0 | (the executed instruction's fields) | **the proof's circuit re-decodes the ORIGINAL fetched word** → rs1=a0, rs2=**a1**; op = remainder (see "key distinction" below) | ok |
| 4. Read rs1 | `load_register(a0)` → **9** | **memory READ** at addr 1073725482 (a0), value 9, cycle 33568 (previous 33565) | normal forward read | ok |
| 5. **Read rs2** | new `load_rs2`: sees rs1 and rs2 are the same register → **reuses the value 9, performs NO second read** | **(no second transaction is recorded)** | — | **only one read of a0 exists** |
| 6. Compute | `9 % 9` = **0** | (none) | — | — |
| 7. Write rd | `store_register(a4, 0)` | **memory WRITE** at addr 1073725486 (a4), value **0** | the written value must equal what the circuit reconstructs for this instruction's result | **BREAKS — fails verification** |

**The key distinction at step 3:** the *emulator* decodes and executes the mutated word (`rs1=a0, rs2=a0`).
But the **proof's circuit decodes the ORIGINAL fetched word** (`rs1=a0, rs2=a1`) — because the fetch
transaction recorded at step 1 holds the original word, and the circuit re-decodes *that*. So the circuit
believes this is `remu a0,a1` with two *different* source registers, and it tries to read **two** registers —
while the patched emulator recorded only **one** read (step 5). That one-transaction shortfall is the whole
story.

**What the circuit actually computes, and why it fails (now derived from the code, with certainty):** the
circuit consumes the recorded transactions in order, but it expects one more than exist, so everything from the
second read onward is **shifted by one transaction**:
- read rs1 (a0) → the a0-read transaction → **9**.
- read rs2 (a1) → there is no second read, so it consumes the **next** transaction, which is the **a4-write
  (value 0)** → the circuit's second operand becomes **0**.
- `9 % 0` → the divide circuit's divide-by-zero rule yields remainder = the dividend = **9**, so the circuit's
  result-to-write is **9** (= a0; this is also the honest remainder since a0 < a1).
- writeback → it now consumes the **next instruction's fetch transaction** — the `lui a2,0xf4` whose machine
  word is `0xf4637` (= 1,001,015).
- the writeback equality "recorded word = computed result" compares `0xf4637` against `9`: low gap
  `0x4637 − 9 = 17966`, high gap `0xf − 0 = 15` — **exactly the measured residuals**. And the failing
  constraint's reported pc is `2099388` = the **`lui`'s address**, confirming the writeback landed on the next
  instruction's fetch. The whole stream being shifted by one is also why the memory- and cycle-ordering
  argument families come out non-zero.

So the circuit's computed write value is **9** (the original instruction's honest remainder, a0), not 0; it
fails because the writeback is compared against the next instruction's word `0xf4637`. (This is fully grounded
in the code path — `load_memory` records the original word, the divide decodes it and reads two registers, the
patched `load_rs2` records one read, and `getMemoryTxn` suppresses its address-mismatch check under fault
injection so the shifted consumption proceeds. See §II.6d for the line-by-line derivation.)

**The contrast in one line.** Scenario 2 (buggy) reads a0 **twice** on one cycle and the circuit allows it →
the tampered instruction is proven and a wrong value is accepted. Scenario 3 (patched) reads a0 **once** and
the same-cycle re-read is forbidden → the tampered instruction cannot be proven and the proof is rejected.
That difference — once vs. twice — is the entire fix and the entire bug.

---

**Status: BOTH columns FILLED FROM MEASUREMENT. ① BUGGY (B2) = accepted-wrong, 0 fails. ② PATCHED (G5) =
REJECTED — `verify segment` fails on 2 `MemoryWrite` constraints at the remu cycle. The #3181 fix IS the
catch (controls confirm it is rs2-alias-specific, not a general break).**

### RESULT HEADLINE (measured 2026-06-26)
| | ① BUGGY **B2** (`a4/builds/a1_cve`, sha dbe89d2…, vuln) | ② PATCHED **G5** (`a4/builds/a1_cve_patched`, sha 8300a8c2…, fixed) |
|---|---|---|
| same mutation | `INSTR_WORD_MOD` rs2-alias `remu a4,a0,a1`→`remu a4,a0,a0` (word 45446963→44398387, bit-20 flip) | **identical** (re-derived from same `--seed 1238004099`; fault line confirms same word delta) |
| remu `--inject-step` | 444 | 478 (relocated via `--trace`; guest image_id differs, guest *logic* identical → honest=9000027 both) |
| committed output | **0** (wrong; honest 9000027) | **none** — prover errors |
| Verifier | success | **panic `verify segment`** (proof fails verification) |
| constraint_fail @ remu (4,7) | **0** | **2** — `MemoryWrite(mem.zir:99)` resid 17966, `MemoryWrite(mem.zir:100)` resid 15 |
| control: benign mutations on this binary | (n/a) | seeds 11, 33 (flip rd / other, no aliasing) → **0 fails, accepts**; seed 22 (garbage) → rejects. ⇒ rejection is **rs2-alias-specific** |

**Conclusion:** the constraint that flips is the remu's **writeback `MemoryWrite`** — **E+P on B2, E+F on G5**.
The fix (`load_rs2` reads once + circuit `is_same_reg`/`IsForward −1`) makes the rs2-aliased execution produce
a witness whose writeback no longer satisfies `newTxn.data = data`, so the segment fails to verify. (Note: the
catch surfaces at the *writeback*, not the register read or `IsCycle(−1)` I predicted — measurement over
prediction.) Raw evidence: `logs/audit_patched_full.log`; B2 same-session re-accept re-confirmed.

**Micro-question — RESOLVED by code analysis in STEP 6d (no dump needed):** *why* `MemoryWrite` specifically.
Answer: the circuit decodes the **original** (rs2=a1) from the fetch txn and expects **two** register reads;
patched `load_rs2` recorded only **one**, so the transaction stream shifts by one (address-mismatch throws are
suppressed under fault injection). The writeback then consumes the **next instruction's fetch word**
(`lui a2,0xf4` = `0xf4637`) and compares it against the circuit's computed result (a0 = 9), giving residuals
`0xf4637 − 9 = (17966, 15)` — exactly as measured, with the failing-constraint pc = the `lui`'s address.

---

**Status: column ① (BUGGY) FILLED FROM MEASUREMENT. column ② (PATCHED) FILLED FROM MEASUREMENT (G5 built).**
Every cell in column ① is populated from measured `A4_COVERAGE_TOUCH_VERBOSE` (constraints evaluated) +
`<constraint_fail>` (constraints that fired) telemetry on the B2 binary, cross-checked against the **exact
zirgen source revision B2 was compiled from** (pinned below). No cell is filled from reasoning about what
"should" happen.

This audit answers one question with evidence, not narrative: **for the exact Arguzz `INSTR_WORD_MOD`
mutation that produces an accepted-but-wrong proof, which circuit constraints are evaluated at each substep
of the `remu` instruction, and which pass/fail — on the buggy commit (`98387806`) vs the patched commit,
with everything else identical (same guest, seed, step, mutation).**

Scope: **Arguzz only** (the during-execution `INSTR_WORD_MOD` path). A4 is explicitly out of scope here.

---

## 0. SOURCE PROVENANCE — what B2 actually compiled (a contamination trap was caught here)

The interactive `.zir` working tree at `/root/arguzz/zirgen` is **NOT** what B2 compiled. Two problems:

1. **AP-track local edits.** `zirgen/circuit/rv32im/v2/dsl/{inst,mem}.zir` are *locally modified* (`git status:
   M`). The mod adds `MemoryReadNoIsRead` and repoints `ReadReg` at it — comment verbatim: *"AP
   planted-benchmark variant: register-read path only … Omits IsRead so PRE_EXEC_REG_MOD next_read can yield
   accepted-invalid proofs."* That is the **AP track's** planted bug, **not** the CVE and **not** in B2.
   - **Proof B2 is clean:** B2's verbose touch dump contains **zero** `MemoryReadNoIsRead` references
     (`grep -c MemoryReadNoIsRead audit_buggy_full.log → 0`), and B2's `MemoryWrite` constraints are at
     `mem.zir:99/100` (authentic line numbers; the AP insertion shifts them to 107/108). B2 uses the
     authentic `MemoryRead` (with `IsRead`) for register reads.

2. **Wrong revision.** Even the *committed* HEAD `.zir` is the wrong era: HEAD has `VerifyOpcodeF3F7` at
   `inst.zir:101`, but B2's telemetry cites `inst.zir:73`. B2 was generated from an **older** zirgen.

**Pinned B2 source revision:** zirgen **`e85a176e`** (2025-03-17). It matches B2's telemetry line-for-line:
`VerifyOpcodeF3F7` body at inst.zir **73/74/75**, `OpREMU` at inst_div.zir **155**, `AssertEqU32 at DoDiv`
at inst_div.zir **63/66**, decode composition at decode.zir **37/46**. All citations below are from this
revision (`git -C zirgen show e85a176e:<path>`).

**Timeline that proves B2 is the vulnerable circuit:**
| artifact | commit | date | relevance |
|---|---|---|---|
| risc0 base of B2 | `98387806` | **2025-05-21** | the vulnerable host B2 was forward-ported from |
| zirgen B2 compiled | `e85a176e` (pre-fix structure) | 2025-03-17 | no `is_same_reg`, `IsForward` без `-1` |
| **the circuit fix** | zirgen `e0e2918` (#238 "Disallow memory IO to same address on same cycle") | **2025-05-22** | **one day after** the risc0 base |

So at B2's commit the same-cycle-read protection **did not exist yet**. This is exactly CVE-2025-52484 /
risc0 #3181's circuit-side manifestation.

## 0.1 Corrected mechanism (this REPLACES the earlier `is_same_reg` story, which was HEAD-only)

Earlier drafts described a `ReadSourceRegs` component with an `is_same_reg` nondet "read once if same reg"
guard. **That component does not exist in B2.** It was introduced by the fix commit `e0e2918`
(`git log -S is_same_reg` → first hit is e0e2918). In the B2-era circuit, `DivInput` reads its source
registers with **two bare reads and no same-register guard at all**:

```
// inst_div.zir @ e85a176e
component DivInput(cycle: Reg, inst_input: InstInput) {
  inst_input.state = StateDecode();
  public ii := inst_input;
  public decoded := DecodeInst(cycle, ii);          // decode the FETCHED word
  public rs1 := ReadReg(cycle, ii, decoded.rs1);    // read register decoded.rs1
  public rs2 := ReadReg(cycle, ii, decoded.rs2);    // read register decoded.rs2  — NO is_same_reg check
  ii
}
// inst.zir @ e85a176e
component ReadReg(cycle, input, reg) { addr := …reg; MemoryRead(cycle, addr) }   // MemoryRead, NOT NoIsRead
// mem.zir @ e85a176e — the loose constraint
component IsForward(io: MemoryIO) { IsCycle(io.newTxn.cycle - io.oldTxn.cycle); }   // delta can be 0
component MemoryRead(cycle, addr) { io := MemoryIO(2*cycle, addr); IsRead(io); IsForward(io); … }
```

And the executor path (`execute/rv32im.rs`) that produces the witness for this:
```
643:  let mut word = ctx.load_memory(pc.waddr())?;         // FETCH original word remu o,a0,a1 (memory txn)
652:  if is_injection("INSTR_WORD_MOD") {
656:      word = self.fault_inj_ctx.random_word(word);     // LOCAL mutate: rs2 field a1 -> a0  (rs2-alias)
      }
670:  self.exec_rv32im(ctx, word)?;                         // DECODE + EXECUTE the mutated word remu o,a0,a0
```

**The chain that makes the wrong proof verify (every link measured in PART −1 / STEP 6d):**
- The **EXECUTOR** decodes/executes the mutated word `remu o,a0,a0`, so it **records two reads of register a0
  on the same cycle** (reads rs1=a0, then rs2=a0).
- The **CIRCUIT** decodes the **ORIGINAL** fetched word `remu o,a0,a1`, so it **requests reads for a0 and a1**.
  Under fault injection the address-mismatch check is suppressed, so the circuit's *a1 request consumes the
  executor's second a0 transaction* (value 9).
- That second a0 transaction is a same-cycle re-read (`prev_cycle == cycle`), so the circuit's "a1" read emits
  a `+1` and a `−1` record on the **same** `(a1, cycle, 9)` tuple → they **self-cancel** → invisible to the
  global memory-permutation argument. The forward check `IsForward → IsCycle(newTxn.cycle − oldTxn.cycle) =
  IsCycle(0)` is also **admitted** by the buggy commit. With `is_same_reg` and `IsForward(...−1...)` both
  absent, nothing rejects it.
- The circuit therefore has rs1 = rs2 = 9 (a0's value, both from a0 transactions), so `DoDiv` proves
  `9 % 9 = 0` and writes `0` to rd, matching the executor's a4-write. The committed program was `remu o,a0,a1`
  (honest rem = 9), but the proof witnessed `remu o,a0,a0` (rem = 0). **Accepted-but-wrong. Zero constraints
  fire.** (A *non-alias* substitution would NOT self-cancel and would be rejected by the memory argument — see
  PART −1.)

**The fix `e0e2918` flips exactly one token** (plus it adds `is_same_reg` as belt-and-braces):
```
- IsCycle(io.newTxn.cycle - io.oldTxn.cycle);      // buggy: same-cycle delta 0 is legal
+ IsCycle(io.newTxn.cycle - 1 - io.oldTxn.cycle);  // fixed: same-cycle delta -1 → lookup miss → FAIL
```
So on the patched circuit the second same-cycle a0 read yields `IsCycle(-1)` → invalid cycle → the memory
argument fails. (The patched executor `67f2d81`/#3181 adds `load_rs2` + `ensure!(txn.cycle != txn.prev_cycle)`
so the same condition also aborts in preflight, before witgen.) **Column ② will measure which of these fires
and where.**

---

## 1. The two binaries (one needs a build)
| binary | commit | have it? | role |
|---|---|---|---|
| **Buggy (B2)** | risc0 `98387806` / zirgen `e85a176e` | **YES** — `a4/builds/a1_cve/risc0-host` | column ①: DONE (below) |
| **Patched (G5)** | zirgen ≥ `e0e2918` (#238) + executor `67f2d81` (#3181) — base `risc0-modified`/`ebd64e43` | **NO — one build** | column ②: same seed/step/mutation → touch + fail (or preflight abort) |

## 2. Telemetry used (verified in source)
- **Constraints EVALUATED:** `A4_COVERAGE_TOUCH_VERBOSE=1` → `ffi.cpp:a4_touch_mark` emits each distinct
  `loc|major|minor`. The `eqz(ctx,val,loc)` wrapper (`witgen.h:184`) calls `a4_touch_mark` *before* the
  check, so **every** evaluated constraint is recorded, pass or fail. Key is `(loc,major,minor)`; the remu
  cycle is **`major=4, minor=7`** (OpREMU; divu is 4/5).
- **Constraints that FIRED:** `CONSTRAINT_CONTINUE=1` → `witgen.h:192` emits `<constraint_fail>{…}` for every
  `eqz` value ≠ 0.
- **E+P** = touched `(loc,4,7)` and **not** in any `<constraint_fail>`. **E+F** = touched + a `<constraint_fail>`
  at that loc. **¬E** = absent from the `(4,7)` touch set. **PRE-ABORT** (patched only) = instruction never
  witnessed (executor `ensure` aborted before witgen).
- Run command (buggy): `A4_COVERAGE_TOUCH_VERBOSE=1 CONSTRAINT_CONTINUE=1 risc0-host --inject
  --inject-step 444 --inject-kind INSTR_WORD_MOD --seed 1238004099` (a replay-confirmed accepted remu-alias).

## 3. The `remu` substeps (B2-era source) — the rows of the table
A division instruction is realized as **one cycle** (`Div0`→`DivInput`→`OpREMU`→`DoDiv`→`WriteRd`), all at
`(major=4, minor=7)`. Substeps:
| # | substep | B2-era source | what it constrains |
|---|---|---|---|
| S1 | fetch + decode | `DecodeInst` (inst.zir:25) → `MemoryRead(pc)` + `Decoder` (decode.zir) | fetched word ↔ decomposed fields {opcode,f3,f7,rd,rs1,rs2}; opcode left nondet (decode.zir:31-34) |
| S2 | opcode verify | `OpREMU`→`VerifyOpcodeF3F7` (inst.zir:73-75 @ inst_div.zir:155) | decoded.{opcode,func3,func7} = REMU constants (0x33,0x7,0x01) — **does not touch rd/rs1/rs2** |
| S3 | read rs1 | `ReadReg(decoded.rs1)` → `MemoryRead` (inst.zir:38) | rs1 value ↔ regfile memory @ rs1 |
| S4 | read rs2 | `ReadReg(decoded.rs2)` → `MemoryRead` (inst.zir:38) | rs2 value ↔ regfile @ rs2; **same-cycle ordering via `IsForward→IsCycle` — the loose link** |
| S5 | compute | `DoDiv(rs1,rs2,0,0).rem` (inst_div.zir) | `numer = quot·denom + rem`, `0 ≤ rem < denom` |
| S6 | writeback | `WriteRd` → `MemoryWrite` (inst.zir, mem.zir:99/100) | rd memory-write ↔ result |
| S7 | pc update | `NormalizeU32(AddU32(pc,4))` | next pc = pc+4 |

---

## 4. Table A — the accepted mutation, per constraint `loc` (① MEASURED on B2)

Run: step 444, `INSTR_WORD_MOD`, seed 1238004099. **48 distinct constraint locs evaluated at `(4,7)`;
`#constraint_fail = 0`.** Therefore **every** row's column ① is **E+P**. Verbatim loc strings in
`logs/remu_cycle_constraints.json`; the full dump is `logs/audit_buggy_full.log`.

| substep | constraint `loc` (B2-era file:line) | semantic meaning | ① BUGGY `98387806` | ② PATCHED |
|---|---|---|---|---|
| S1 | `DecodeInst(inst.zir:29)` | PC alignment `pc_addr.low2 = 0` | **E+P** | _pending_ |
| S1 | `AddrDecompose(u32.zir:67,71)` | decompose PC into word-addr | **E+P** | _pending_ |
| S1 | `MemoryRead/IsRead(mem.zir:79,80 @ mem.zir:90)` | fetched word txn: `oldData = newData` (read-consistency of the instruction fetch) | **E+P** | _pending_ |
| S1 | `Decoder(decode.zir:37,46)` | the **ORIGINAL fetched word** composes into {f7,rs2,rs1,f3,rd,opcode} (the circuit decodes the fetch txn, which holds the original — so decoded rs2 = **a1**, NOT the executed a0; see STEP 6d) | **E+P** | _pending_ |
| S2 | `VerifyOpcodeF3F7(inst.zir:73,74,75 @ OpREMU inst_div.zir:155)` | `decoded.opcode=0x33 ∧ func3=0x7 ∧ func7=0x01` — REMU. **Binds opcode/f3/f7 only; never rs1/rs2/rd** | **E+P** | _pending_ |
| S3,S4 | `MemoryIO(mem.zir:69,70,71,73,74)` | both register-read transactions: count ±1, addr alias, `newTxn.cycle=memCycle` | **E+P** | _pending_ |
| **S4** | **`IsCycle(mem.zir:61,62)`** (the `IsForward` delta, via `CycleArg`) | **`IsCycle(newTxn.cycle − oldTxn.cycle)`. The circuit's rs2 read (decoded a1) consumes the executor's SECOND a0 transaction — on the same cycle as the first (address mismatch suppressed under fault injection) — so the delta is 0; `IsCycle(0)` is accepted. THE underconstrained link.** | **E+P (delta 0 admitted)** | _pending — predicted E+F: `IsCycle(-1)` or preflight PRE-ABORT_ |
| S3,S4 | `Reg(<preamble>), FakeTwitReg(bits.zir:77), U16Reg/NondetU16Reg/NondetU8Reg(lookups.zir)` | range/decomposition of the read register limbs | **E+P** | _pending_ |
| S5 | `DivInput(inst_div.zir:8)` | `inst_input.state = StateDecode()` (this is a divide cycle) | **E+P** | _pending_ |
| S5 | `DoDiv(inst_div.zir:91)` + `AssertEqU32(u32.zir:106,107 @ DoDiv inst_div.zir:63,66)` | `numer = quot·denom + rem` and top-half check; for `x%x`: `x = 1·x + 0` | **E+P** | _pending_ |
| S5 | `MultiplyAccumulate(mult.zir:124), SplitTotal(mult.zir:101), ExpandU32(mult.zir:63,64,68)` | the multiply that realizes `quot·denom + rem` | **E+P** | _pending_ |
| S5 | `IsZero(is_zero.zir:16,18,20)+AssertBit, NormalizeU32(u32.zir:46,52)` | denom-zero branch select (`x≠0` → non-zero branch) + normalization | **E+P** | _pending_ |
| S5 | `CmpLessThanUnsigned`→ `0 < x` (`rem < denom`) | remainder-range check (rem 0 < denom x) | **E+P** | _pending_ |
| **S6** | **`MemoryWrite(mem.zir:99,100)`** | write result to `rd` memory: `newTxn.dataLow=data.low` (99), `newTxn.dataHigh=data.high` (100) | **E+P** | **E+F — `<constraint_fail>` resid 17966 (99) / 15 (100), `verify segment` fails** |
| S7 | `NormalizeU32(AddU32 pc,4)` | pc ← pc+4 | **E+P** | _pending_ |
| — | `DoCycleTable(inst.zir:21,22), OneHot(one_hot.zir:9,11)` | cycle-table accounting + minor-onehot selector (minor=7) | **E+P** | _pending_ |

**Reading of column ①:** the decode (S1/S2) faithfully decodes the **original fetched word** (rs2=a1) — the
circuit decodes the fetch txn, which holds the original, NOT the executed mutated word (STEP 6d) — so the
composition/opcode checks pass. The executor, however, executed the mutated `remu a0,a0` and recorded **two**
a0 reads; the circuit's two reads (for a0 and "a1") consume those two same-cycle a0 transactions (the address
mismatch on the "a1" read is suppressed under fault injection), so both operand values are 9. The only thing
that *could* have caught the substitution — the rs2 register-read ordering at **S4** — evaluates `IsCycle(0)`
and **passes** because the B2-era `IsForward` admits a zero cycle-delta. Everything downstream (S5–S7) is then
internally coherent (`9 % 9 = 0`, written to a4). Hence 0 failures and an accepted wrong proof.

## Table B — run-level summary (BOTH MEASURED)
| metric | ① BUGGY (B2) | ② PATCHED (G5) |
|---|---|---|
| committed output (honest = 9000027; remu-alias → **0**) | **0** | **none** (prover errors) |
| Verifier status | **success** (`<record>{"context":"Verifier","status":"success"}`) | **error / panic `verify segment`** (`Prover status:error, 28.27s`) |
| # `constraint_fail` @ remu (4,7) | **0** | **2** (`MemoryWrite` mem.zir:99 & 100) |
| failing locs | — | `MemoryWrite(mem.zir:99)` resid 17966; `MemoryWrite(mem.zir:100)` resid 15 (cycle 16784) |
| accepts benign (non-alias) mutation? | — | **yes** (seeds 11, 33 → 0 fails) → rejection is rs2-alias-specific |
| preflight abort? | no | **no** — reaches witgen+prove, then **segment verification fails** (not a preflight `ensure` abort) |

## 5. Proof (raw telemetry, column ①)
- **Accept + output:** `<record>{"context":"Receipt Decoder","status":"success",…,"output":"0","journal_bytes":4}`
  then `<record>{"context":"Verifier","status":"success","time":"18.45ms"}`. (`audit_buggy_full.log` head.)
- **Zero failures:** `grep -c '<constraint_fail>' audit_buggy_full.log → 0`.
- **The 48 evaluated locs at (4,7):** `logs/remu_cycle_constraints.json` (verbatim), e.g. the S4 link:
  `IsCycle(zirgen/circuit/rv32im/v2/dsl/mem.zir:61)|4|7` and `…:62|4|7` — present in the touch set, absent
  from `<constraint_fail>` ⇒ **E+P**.
- **S2 binds opcode only:** `loc(callsite( VerifyOpcodeF3F7 ( …inst.zir:73:19) at OpREMU ( …inst_div.zir:155:20)))|4|7`
  (×3 for f3/f7) — and the component body (e85a176e) is literally `decoded.opcode=…; decoded.func3=…;
  decoded.func7=…;` with no rs1/rs2/rd term.
- **S5 division relation:** `AssertEqU32(…u32.zir:106:10) at DoDiv(…inst_div.zir:63:15)|4|7` (the
  `numer = quot·denom + rem` check) — touched, no fail.

## 6. Remaining step — column ② (one build, then we finish the table together)
- [x] **A. Locate remu cycle** → `(major=4, minor=7)`, step 444 in `--inject` indexing. DONE.
- [x] **B. Buggy run** → column ① above. DONE.
- [x] **C. Map locs → source** against pinned B2 revision `e85a176e`. DONE.
- [x] **D. Built patched G5** — A2 guest against `workspace/risc0-modified` (`6556e8d7`: `load_rs2` + circuit
      `is_same_reg`/`IsForward −1`), own project `workspace/output-a1patched`, toolchain 1.90 (ruint MSRV),
      104 min, 0 errors. Archived `a4/builds/a1_cve_patched/risc0-host` sha `8300a8c2…`. B2 sha verified
      unchanged; vuln tree byte-untouched.
- [x] **E. Patched run** — identical mutation, remu relocated to step 478. **Result: REJECTED** — prover
      error, `verify segment` panic, 2 `MemoryWrite` constraint_fail @ remu (4,7). Both predictions falsified
      (no preflight abort; not `IsCycle(−1)` — it is the **writeback `MemoryWrite`**). Controls: G5 accepts
      benign non-alias mutations (seeds 11, 33) → rejection is rs2-alias-specific. → column ② filled.
- [x] **F. Synthesized** — see RESULT HEADLINE (top). The #3181 fix flips this exact mutation accept→reject;
      detecting constraint = remu `MemoryWrite`. Remaining: value-level dump to explain *why* the writeback.

## 7. Open questions
1. *Does any constraint bind the decoded instruction to the fetched word?* **RESOLVED (STEP 6b/6d):** the
   circuit's `Decoder` input is `MemoryRead(pc)` = the fetch transaction, and the executor records that
   transaction via `ctx.load_memory` → `load_u32(LoadOp::Record)` with the **pager value = the ORIGINAL word**
   (the `INSTR_WORD_MOD` mutation is local; the dump confirms the fetch txn word = original on both binaries).
   So **the circuit decodes the ORIGINAL instruction** (rs2=a1), while the executor *executes* the mutated one
   (rs2=a0). The decoded fields are NOT cross-bound to the executed instruction — and under fault injection
   `extern_getMemoryTxn` suppresses the address/cycle-mismatch throws, so the executor's (mutated-execution)
   transactions are consumed by the circuit's (original-decode) accesses. (Earlier "fetch carries the mutated
   word" wording was wrong and is retracted.)
2. *Is the rs2 read bound, and how does rs1==rs2 same-cycle behave?* The read is bound to regfile memory; the
   B2 (vuln) `IsForward→IsCycle` admits delta 0 and there is no `is_same_reg`; the fix adds both. Confirmed at
   the source level; the *runtime* effect on this mutation is measured in §II.
3. *Is the patched catch a witgen `eqz` or a preflight `ensure`?* **MEASURED (§II STEP 5):** witgen `eqz` —
   `MemoryWrite` fails locally and the **segment fails to verify**; there is **no** preflight `ensure` abort.

---

# PART II — step-by-step verifiable sub-analyses (each independently checkable)

Per request: each analysis is a separate section so any single part can be validated or falsified on its own.
Binaries: **B2** = vulnerable (`a4/builds/a1_cve`, sha dbe89d2…), **G5** = patched (`a4/builds/a1_cve_patched`,
sha 8300a8c2…). Guest inputs `--ctrl 7 --gseed 12345 --rounds 5` (x=9, y=12602) unless noted. Mutation:
`--inject --inject-kind INSTR_WORD_MOD --seed 1238004099` at the remu step (B2: 444, G5: 478).

## STEP 1 — the remu step and that the mutation was applied there (VERIFIED)
Evidence (G5; B2 analogous at 444):
- `--trace`: `{"step":477,…"addi a1, a1, 1"}` · **`{"step":478,"pc":2099384,…"remu a4, a0, a1"}`** · `{"step":479,…"lui a2"}`.
- mutation `<fault>`: **`{"step":478,"pc":2099384,"kind":"INSTR_WORD_MOD","info":"word:45446963 => word:44398387"}`** —
  step **and** pc match the trace's remu. `--trace`/`--inject` share the `current_step` counter (same field in
  `print_trace_info`/`print_injection_info`), so the mutation provably lands on the remu.
- decode of the word delta: `45446963 = remu x14,x10,x11` → `44398387 = remu x14,x10,x10` (xor `0x100000` =
  bit 20 = rs2 LSB; rs2 x11→x10, i.e. a1→a0). **This is the rs2-alias, identical to B2's.**

## STEP 2 — why the "control" mutations accept with 0 fails (VERIFIED)
**Careful framing (corrected):** these mutations accept **not** because they are "valid proofs of the mutated
instruction" — recall the circuit decodes the *original* fetched word (STEP 6d). They accept because they
remain **transaction-compatible**: the executor records the same number of register reads/writes the circuit
(decoding the original) expects, and the values it consumes (under the suppressed address check) still satisfy
the writeback equality. Decoded:
| seed | mutated word → executed insn | rs1==rs2? | why G5's result |
|---|---|---|---|
| 11 | `remu x6,a0,a1` (only **rd** changed x14→x6) | No | **0 fails** — executor still does 2 reads + 1 write, so the stream stays aligned; the executor's x6-write value (9) matches what the circuit computes (`9%12602=9`) for its "a4" writeback (address mismatch suppressed) → equality holds |
| 33 | `jal …` (op `0x6f`, different insn class) | No | **0 fails** — the cycle runs the executed insn's circuit path; it stays transaction-compatible. (Less clean than seed 11; included only to show G5 is not generically broken.) |
| 1238004099 | `remu a4,a0,a0` (**rs2 alias**, rs1==rs2) | **Yes** | **2 fails — rejected** — `load_rs2` drops the second read, so the stream shifts by one (STEP 6d) |
The point: only the rs2-alias makes the *executor's* `rs1==rs2` true, which is the only case where patched
`load_rs2` records one fewer read and shifts the transaction stream. So G5's rejection is specific to the
`rs1==rs2` condition, not to "any INSTR_WORD_MOD" — and it is the **transaction-count shift**, not a
"different computation," that fails it.

## STEP 3 — every rv32im.rs substep of the remu that creates a memory txn / local-constraint event
From the executor (`execute/rv32im.rs`, patched line numbers; vuln identical flow per diff):
| # | rv32im.rs site | memory txn / event | circuit constraint(s) it feeds |
|---|---|---|---|
| E1 | `step`: `word = ctx.load_memory(pc.waddr())` (≈643) | **READ txn** (instruction fetch @ pc) | `DecodeInst`→`MemoryRead`(`IsRead`+`IsForward`); `Decoder` composition |
| E2 | `step`: INSTR_WORD_MOD mutates local `word` (≈654-662) | (no txn — local var) | — (changes what E3+ decode/execute) |
| E3 | `exec_rv32im`→`step_compute`: `decode(word)` | (decoded fields) | `Decoder` fields; `VerifyOpcodeF3F7` (opcode/f3/f7) |
| E4 | `step_compute`: `rs1 = ctx.load_register(decoded.rs1)` (≈736) | **READ txn** (rs1) | `ReadReg`→`MemoryRead`(`IsRead`+`IsForward`) |
| E5 | `step_compute`: `rs2 = load_rs2(decoded, rs1)` (≈737/724) | **READ txn** (rs2) **iff** rs1≠rs2; **none** if rs1==rs2 (patched reuses rs1) | `ReadSourceRegs`/`is_same_reg` (patched) + `ReadReg` |
| E6 | divide handler `DoDiv(rs1,rs2)` | (compute) | `DoDiv`, `AssertEqU32`, `MultiplyAccumulate`, range checks |
| E7 | `WriteRd`/`store_register(rd, result)` | **WRITE txn** (rd) | `WriteRd`→`MemoryWrite`(`newTxn.data=data`)+`IsForward` |
| E8 | pc update `pc + 4` | (compute) | `NormalizeU32(AddU32(pc,4))` |
| — | per-cycle | cycle/selector | `DoCycleTable`, `OneHot(minor)`, `IsCycle` |
**The only substep that creates/elides a memory txn conditionally on `rs1==rs2` is E5** (patched reads once).
This is the exact locus of the fix; everything downstream (E6 compute, E7 writeback) consumes E4/E5's reads.

## STEP 4 — BUGGY (B2): every substep's constraint is EVALUATED and PASSES (VERIFIED)
B2 run (step 444): **48 distinct constraints at remu (major=4,minor=7), `#constraint_fail = 0`** ⇒ every
substep E1–E8 has at least one evaluated+passing constraint (else the verifier would reject — and it did
not; output 0, Verifier success). Mapping (full Table A above; verbatim locs in
`logs/remu_cycle_constraints.json`):
| substep | B2 constraint(s) touched | status |
|---|---|---|
| E1 fetch | `MemoryRead/IsRead(mem.zir:79,80@90)`, `Decoder(decode.zir:37,46)`, `AddrDecompose`, `DecodeInst(inst.zir:29)` | **E+P** |
| E3 opcode | `VerifyOpcodeF3F7(inst.zir:73,74,75@OpREMU inst_div.zir:155)` | **E+P** |
| E4/E5 reads | `MemoryIO(mem.zir:69-74)`, `IsCycle(mem.zir:61,62)` (the `IsForward` delta), reg-limb `Reg/U16Reg/…` | **E+P** (incl. the loose same-cycle `IsCycle`) |
| E6 compute | `DivInput(8)`, `DoDiv(91)`, `AssertEqU32(u32:106,107@DoDiv 63,66)`, `MultiplyAccumulate`, `NormalizeU32` | **E+P** |
| E7 writeback | `MemoryWrite(mem.zir:99,100)` | **E+P** |
| E8 pc / cycle | `NormalizeU32`, `DoCycleTable(21,22)`, `OneHot(9,11)` | **E+P** |
**Commensurate with the rv32im.rs analysis?** Yes for E1,E3,E4,E6,E7,E8. **Note on E5:** B2 has **no**
`ReadSourceRegs`/`is_same_reg` constraint (it didn't exist at B2's zirgen `e85a176e`) — so the "read rs2"
substep in B2 is just a second `ReadReg`, and the same-cycle double read is admitted by `IsForward→IsCycle`
(delta 0). That absence is the underconstraint.

## STEP 5 — PATCHED (G5): every substep, EVALUATED + pass/fail (VERIFIED)
G5 run (step 478): **54 distinct constraints at remu (4,7); `#constraint_fail = 2`.** Diff vs B2:
- **Added by the fix (E5):** `ReadSourceRegs(inst.zir:49)` — the `is_same_reg` boolean guard. **Evaluated,
  PASSES** (it is not the catch). (Other "added" locs — `VerifyOpcodeF3F7@inst.zir:102-104`, `Div0@25`,
  extra `AssertEqU32@DoDiv` callsites — are **line-number drift** from G5's newer zirgen, same constraints; 39
  locs shared by name.)
- **FAILS (E7):** `MemoryWrite(mem.zir:99)` resid 17966, `MemoryWrite(mem.zir:100)` resid 15 → **segment fails
  to verify** (`Prover error`, `panic: verify segment`). No preflight `ensure` abort.
| substep | G5 status |
|---|---|
| E1 fetch / E3 opcode | **E+P** (decode + VerifyOpcodeF3F7 pass) |
| E4 read rs1 | **E+P** |
| E5 read rs2 | `ReadSourceRegs`/`is_same_reg` **E+P** (boolean ok) |
| E6 compute | DoDiv etc **E+P** |
| **E7 writeback** | **`MemoryWrite` E+F** ← the catch |
| E8 pc / cycle | **E+P** |
**Commensurate?** The fix's new constraint (E5 `is_same_reg`) is present and passes; the rejection surfaces at
**E7 writeback**, not at E5/E4 reads. So the fix's effect on E5 (read once) propagates to make E7 inconsistent.
*Why* E7's `data` disagrees with `newTxn` is STEP 6b (value-level).

## STEP 6a — value probe WITHOUT a rebuild: the writeback residual depends on x, not y (VERIFIED)
Varying operands at G5 step 478 (same alias seed):
| ctrl,gseed | x=(ctrl&7)+2 | y=(gseed|0x100)+1 | resid `mem.zir:99` | resid `:100` |
|---|---|---|---|---|
| 7,12345 | 9 | 12602 | 17966 | 15 |
| 7,0 | 9 | 257 | 17966 | 15 |
| 0,12345 | 2 | 12602 | 17973 | 15 |
| 0,0 | 2 | 257 | 17973 | 15 |
⇒ **`resid_low = 17975 − x`, independent of y; `resid_high = 15` constant.** So the writeback discrepancy is a
function of **a0's value (x)** only — a1 (y) never enters. This is a hard constraint on STEP 6b's explanation
(whatever the circuit expects to write vs what the trace wrote, the gap tracks x, not y).

## STEP 6b — value-level ground truth via EXISTING hooks, NO rebuild (VERIFIED)
**Method correction:** no instrumentation/rebuild was needed. The instrumented trees already expose
transaction dumps — `A4_DUMP_ALL_TXNS` (`<a4_all_txn>`: txn_idx, txn_type, addr, cycle, word, prev_cycle,
prev_word) + `A4_INSPECT` (`<a4_cycle_info>`: cycle_idx→step/pc/major/minor/txn_idx). Two runs each binary
(mutation vs honest), filter to the remu cycle's txn range. Logs: `logs/{g5,b2}_mut_txns.log`.

**Measured transactions at the remu cycle (mutation, ctrl=7 gseed=12345 → x=9, y=12602):**
| txn | B2 (vuln, cycle 10563) | G5 (patched, cycle 16784) |
|---|---|---|
| fetch (mem @ pc/4=524846) | word **45446963 = `remu x14,x10,x11`** (ORIGINAL; prev_word same → IsRead ok) | word **45446963** (ORIGINAL) — identical |
| reg read #1 (a0=x10) | word 9, cycle 21126, prev_cycle 21123 | word 9, cycle 33568, prev_cycle 33565 |
| reg read #2 (a0=x10) | **word 9, cycle 21126, `prev_cycle = 21126` (== cycle ⇒ same-address-same-cycle re-read)** | **ABSENT** (`load_rs2` reused rs1) |
| reg write rd (a4=x14) | word **0**, prev_word 4 | word **0**, prev_word 4 |
| #constraint_fail | **0 → ACCEPT** (journal 0) | **2 MemoryWrite → REJECT** |

**Findings (all measured):**
1. **The fetch txn carries the ORIGINAL word in BOTH** (45446963 = rs2=x11=a1). The INSTR_WORD_MOD mutation is
   local to *execution*; the instruction-fetch memory transaction records the unmutated word. (This corrects
   my earlier "fetch carries the mutated word" assertion in §7 — it is the original.)
2. **B2 reads `a0` TWICE on the same cycle** — read #2 has `cycle == prev_cycle == 21126`, the literal
   same-address-same-cycle access #238 targets. B2's vuln `IsForward = IsCycle(cycle − prev_cycle) =
   IsCycle(0)` admits it ⇒ `remu(a0,a0)=0` proven coherently ⇒ write 0 ⇒ MemoryWrite passes ⇒ ACCEPT, journal 0.
3. **G5 reads `a0` ONCE** — the patched `load_rs2` returns rs1 without a second read when `rs1==rs2`. The
   same-cycle double-read never appears; instead the single-read trace is inconsistent with the circuit's
   expected writeback ⇒ `MemoryWrite` fails ⇒ segment rejected.
4. **Writeback newTxn = 0 in both** (executor's `remu(a0,a0)=0`). On G5 the writeback equality fails with
   residual `17975 − a0` (a0-dependent, a1-independent, §6a). **RETRACTED:** I previously back-solved this to a
   "degenerate ≡ −(1001015 − x)" value — that is inconsistent with the division-relation constraints having
   passed (which force the remainder to be a valid range-checked value), so it is withdrawn. The exact second
   divide operand and remainder the circuit used are the subject of §II.6d (systematic code analysis). What is
   certain: the catch tracks **a0** (the aliased register), never **a1**.

**Conclusion (settles §0.1 + §7):** the fix is exactly **"read the aliased register once instead of twice,"**
observed at the transaction level. B2 emits a same-cycle second read of `a0` that the vulnerable memory
argument permits; G5 emits no such read (`load_rs2`) and the patched circuit rejects the resulting witness at
the remu writeback. **The #3181/#238 fix is the catch.**

## STEP 6c — per-family argument residues pin the inconsistency to memory + cycle (VERIFIED)
Existing hooks `A4_FAMILY_RESIDUE=1 A4_COVERAGE_TOUCH=1 A4_GLOBAL_RESIDUE=1` (records gated on both;
`extern_memoryDelta`/`extern_lookupCurrent` feed per-family residues computed in the accum phase):
| family | B2 (vuln) | G5 (patched) |
|---|---|---|
| **memory** (memory permutation arg) | residue **0** (balanced; plus=minus=22744) | **NONZERO** (plus=minus=31843 — counts balance, weighted residue does not) |
| **cycle** (`IsForward→IsCycle` cycle-delta lookup) | residue **0** | **NONZERO** |
| u16, u8 | 0, 0 | 0, 0 |
| **global** | **`<a4_global_residue_zero/>`** → accept | **`<a4_global_residue_nonzero>`** → reject |

So G5's witness is inconsistent in **exactly the memory and cycle families** — and `cycle` is the
`IsForward→IsCycle` same-cycle-read lookup, the #238 fix locus. B2 balances in all families.

**The decode question — RESOLVED in §II.6d (this paragraph previously framed it as an open "tension"; that is
now settled):** the fetch transaction word is the **original** `45446963`, so the circuit decodes the ORIGINAL
(`rs2=a1`). The seed-11 control's dump showing a write "at x6" is **not** the circuit decoding the mutated rd —
it is the **executor's** x6-write transaction, which the circuit's `WriteRd` (computing addr=a4 from the
original decode) *consumes* with its address-mismatch check suppressed under fault injection. So there is no
real tension: the circuit decodes the original everywhere; the executor's mutated-execution transactions are
what the dump shows, consumed by the circuit via the suppressed address check. What is certain and measured:
B2 reads `a0` twice with the second on the same cycle (`prev_cycle==cycle`); that pair cancels in the memory
arg and `IsCycle(0)` is admitted by the vulnerable cycle arg → both residues 0 → accept (journal 0). G5 reads
`a0` once; the stream shifts → memory and cycle families do not balance → reject.

## STEP 6d — the exact circuit computation, derived from CODE + ARITHMETIC (no instrumentation; VERIFIED)
The decode question, the divide inputs, and the write value are all determinable by reading the
witness-generation path. The decisive code facts:

- **`load_memory` records the fetch with the ORIGINAL word.** `r0vm.rs:713 load_memory → ctx.load_u32(LoadOp::Record)`;
  `preflight.rs:566-602 load_u32` records the transaction with `word = pager.load(addr)` (the program word).
  `INSTR_WORD_MOD` (rv32im.rs) mutates a *local* variable, never the pager. ⇒ **the circuit's `Decoder`, which
  decodes `MemoryRead(pc)` = this fetch txn, decodes the ORIGINAL `remu a0,a1`** → `decoded.rs1=a0`,
  `decoded.rs2=a1`, `decoded.rd=a4`. (The cycle record `add_cycle` stores only major/minor/pc/txn_idx — NOT the
  decoded fields — so the circuit genuinely re-decodes the fetched word; it does not inherit the executor's
  mutated decode.)
- **Decoding the original ⇒ the divide reads TWO registers.** `is_same_reg = Isz(decoded.rs1 − decoded.rs2) =
  Isz(a0 − a1) = 0` → the else-branch reads `rs1` and `rs2` separately (two `ReadReg`).
- **The patched executor records only ONE register read.** `load_rs2` (rv32im.rs:724): `if decoded.rs1 ==
  decoded.rs2 { Ok(rs1) }` — for the *executed* `remu a0,a0` it reuses rs1, performing no second read. So the
  preflight records 3 txns for the cycle (fetch, one read, write), not 4.
- **`extern_getMemoryTxn` (ffi.cpp) SKIPS its address-mismatch and cycle-mismatch `throw`s under fault
  injection** (`if (FAULT_INJECTION_ENABLED) printf("SKIP THROW") else throw`). So the circuit consumes the
  recorded transactions **in index order regardless of address**, and a too-few-transactions cycle simply runs
  into the next cycle's transactions.

**Putting it together — G5, the remu cycle (3 recorded txns: fetch, a0-read=9, a4-write=0):** the circuit makes
4 accesses and consumes, shifted by one:
| circuit access | consumes txn | value seen |
|---|---|---|
| fetch (DecodeInst) | fetch txn | original word `remu a0,a1` |
| read rs1 (a0) | a0-read txn | **9** → `rs1 = a0 = 9` |
| read rs2 (a1) | **a4-WRITE txn** (addr mismatch suppressed) | **0** → `denom = 0` |
| writeback (WriteRd) | **NEXT instruction's fetch txn** = `lui a2,0xf4` = `0xf4637` | — |

`DoDiv(numer=9, denom=0)` → divide-by-zero rule → `rem = numer = 9`. So the circuit's write value is
**`data = a0 = 9`** (equivalently the honest remainder, since a0<a1). The writeback constraint then compares the
consumed word `0xf4637` against `9`: residual_low `= 0x4637 − 9 = 17966`, residual_high `= 0xf − 0 = 15` —
**exactly the measured residuals**, and the `constraint_fail` pc `2099388` **is the `lui`'s address**, confirming
the writeback consumed the next instruction's fetch. The whole transaction stream being shifted by one is why
the **memory and cycle argument families are non-zero** (the per-cycle txn boundaries no longer line up). The
division-relation constraints **pass** because divide-by-zero is a legal, range-checked case (rem=9 is a valid
u16) — consistent with only `MemoryWrite` firing.

**Why B2 accepts the same mutation (4 recorded txns: fetch, a0-read, a0-read, a4-write):** the vulnerable
executor reads rs2 unconditionally → two register-read txns → the stream stays **aligned** with the circuit's
two-read decode:
| circuit access | consumes txn | value seen |
|---|---|---|
| fetch | fetch txn | original `remu a0,a1` |
| read rs1 (a0) | 1st a0-read | 9 → rs1=9 |
| read rs2 (a1) | 2nd a0-read (addr mismatch suppressed) | 9 → rs2=9 |
| writeback (a4) | a4-write txn | 0 |
`DoDiv(9,9)=0` → data=0; writeback compares the a4-write word `0` against `0` → passes. Stream aligned, all
families balance → **accept**, committing the wrong value 0 (the circuit "proved" `remu(a0,a0)=0` while the
committed program is `remu a0,a1`, honest remainder 9).

**Conclusion — the soundness mechanism, fully from code:** the divide circuit always re-decodes the ORIGINAL
fetched instruction and (for it) reads two registers; whether the proof verifies hinges on whether the executor
recorded a matching number of register reads. The **vulnerable executor reads the aliased register twice**,
keeping the transaction stream aligned so the circuit proves the wrong `remu(a0,a0)=0` and accepts it. The
**patched `load_rs2` reads it once**, shifting the stream by one so the writeback consumes the next
instruction's fetch word and the proof is rejected. Everything (decode source, divide inputs, write value,
residuals, failing-constraint pc, family residues) is derived from the source and confirmed by arithmetic
against the measurements — **no instrumentation was needed.**
