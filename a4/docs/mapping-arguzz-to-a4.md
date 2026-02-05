This is focused on the INSTR_WORD_MOD Arguzz mutation mapping to A4's INSTR_WORD_MOD equivalent. The mutation is not exactly the same since the executor propagates the mutation during execution, while A4 mutates a post-execution trace without propagation. The decision here was to mutate the first downstream variable affected by the A4 INSTR_WORD_MOD mutation.

# Mapping Arguzz INSTR_WORD_MOD to A4 INSTR_TYPE_MOD

## The Core Challenge

When Arguzz mutates an instruction at "step 200", we need to find the **exact corresponding location** in the A4 `PreflightTrace` object. This is not straightforward because:
1. **Step values differ** - Arguzz and A4 count instruction steps differently
2. **PC values differ** - Arguzz records PC *before* execution, A4 records PC *after*
3. **Instructions can repeat** - Loops cause the same PC to appear multiple times

---

## Part 1: What We Get From Arguzz

When we run an Arguzz mutation:

```bash
/root/arguzz/workspace/output/target/release/risc0-host --trace --inject --seed 12345 --inject-step 200 --inject-kind INSTR_WORD_MOD --in1 5 --in4 10
```
- Add `CONSTRAINT_CONTINUE=1` at beginning to see all constraint failures

We get a `<fault>` line:

```json
<fault>{"step":200, "pc":2144416, "kind":"INSTR_WORD_MOD", "info":"word:3147283 => word:8897555"}</fault>
```
- Mutates `AddI` $\rightarrow$ `XorI`

### Arguzz Variables Explained

| Variable        | Value   | Where it comes from                                            | Meaning                                                                                                                                   |
| --------------- | ------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `step`          | 200     | `self.fault_inj_ctx.current_step` in `rv32im.rs:716`           | The Arguzz step counter. Increments for **every** instruction, including machine-mode ecalls/mrets (unlike preflight trace step counter). |
| `pc`            | 2144416 | Recorded in `rv32im.rs:669` **before** `exec_rv32im()` runs    | The Program Counter **before** the instruction executes i.e. (CURRENT PC)                                                                 |
| `original_word` | 3147283 | From `ctx.load_memory(pc.waddr())` at `rv32im.rs:643`          | The 32-bit instruction word that was fetched                                                                                              |
| `mutated_word`  | 8897555 | From `self.fault_inj_ctx.random_word(word)` at `rv32im.rs:659` | The mutated instruction word Arguzz substitutes                                                                                           |

### How Arguzz Step Counter Works

```rust
// rv32im.rs:716 - ALWAYS runs, even for machine ecalls that return false
self.fault_inj_ctx.step();
```

This means:
- Machine-mode ECALL at Arguzz step 157 → counter becomes 158
- MRET at Arguzz step 19 → counter becomes 20
- Every instruction increments, no exceptions

---

## Part 2: What We Get From A4 Inspection

When we run A4 inspection:

```bash
A4_INSPECT=1  /root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10
```

We get `<a4_cycle_info>` lines for *every* cycle in the `PreflightTrace`:

```json
<a4_cycle_info>{"cycle_idx":16777, "step":198, "pc":2144420, "txn_idx":16258, "major":0, "minor":7}</a4_cycle_info>
```

$\rightarrow$ *Note*: We can ensure we see guest program relevant data via:
```shell
A4_INSPECT=1 /root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 | sed -n '10000,20000p'
```
$\rightarrow$

### A4 Variables Explained

| Variable    | Value   | Where it comes from                        | Meaning                                                                                   |
| ----------- | ------- | ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `cycle_idx` | 16777   | Array index into `trace.cycles[]`          | Position in the cycles array                                                              |
| `step`      | 198     | `cycle.user_cycle` from `preflight.rs:392` | A4's instruction step counter. Only increments when `exec_rv32im()` returns `Some(kind)`. |
| `pc`        | 2144420 | `cycle.pc` from `preflight.rs:389`         | The Program Counter **after** the instruction executes (next PC)                          |
| `txn_idx`   | 16258   | `cycle.txn_idx` from `preflight.rs:393`    | Index where this cycle's transactions start in `trace.txns[]`                             |
| `major`     | 0       | `cycle.major` = `InsnKind / 8`             | Major instruction category                                                                |
| `minor`     | 7       | `cycle.minor` = `InsnKind % 8`             | Minor instruction variant                                                                 |
- ==So `trace.txns[]` is an array and also `trace.cycles[]`? What is the name of the index for both of these arrays? where do i see where the whole `trace` object is defined? so that I know everything that exists in the trace object. Also, what is the difference between the purpose / information content in `trace.txns[]` and `trace.cycles[]`? Why does <a4_cycle_info> not show trace.txns[] and only trace.cycles[], or does it?==

### How A4 Step Counter Works (Different from Arguzz!)

```rust
// preflight.rs:553-558
fn on_insn_end(&mut self, kind: InsnKind) -> Result<()> {
    self.add_cycle_insn(CycleState::Decode, self.pc.0, kind);
    self.user_cycle += 1;  // Only called if exec_rv32im returned Some(kind)
    ...
}
```

The key is `on_insn_end` is only called when `exec_rv32im` returns `Some(kind)`. Looking at `rv32im.rs`:

```rust
// rv32im.rs:671-674
if let Some(kind) = self.exec_rv32im(ctx, word)? {
    ctx.on_normal_end(kind)?  // This calls on_insn_end → increments user_cycle
}
```

And when does `exec_rv32im` return `None`? When machine-mode ecalls/mrets return `false`:

```rust
// rv32im.rs:633-637
InsnKind::Ecall => {
    if !ctx.ecall()? {  // Machine ecalls return false
        return Ok(None);  // user_cycle NOT incremented
    }
    ...
}
```

### The Step Offset

Between step 0 and step 200, there are **2 machine-mode operations** that return `false`:
- ECALL at Arguzz step 157 (machine-mode)
- ECALL at Arguzz step 170 (machine-mode)

Therefore:
- Arguzz step 200 → A4 step 200 - 2 = **198**

---

## Part 3: The PC Difference

### Arguzz: Records PC Before Execution

```rust
// rv32im.rs:669 - Called BEFORE exec_rv32im()
self.fault_inj_ctx.print_trace_info(pc, word);
```

At step 200, Arguzz records PC = **2144416** (the address of the instruction about to execute).

### A4: Records PC After Execution

```rust
// preflight.rs:553-558
fn on_insn_end(&mut self, kind: InsnKind) -> Result<()> {
    self.add_cycle_insn(CycleState::Decode, self.pc.0, kind);  // self.pc is NEXT PC
    ...
}
```

At the same instruction, A4 records PC = **2144420** (the address of the next instruction = 2144416 + 4).

### The Formula

```
A4_PC = Arguzz_PC + 4
```

For step 200:
- Arguzz PC: 2144416
- A4 PC: 2144416 + 4 = **2144420**

---

## Part 4: The Mapping Algorithm

Now we can understand `find_mutation_target()` in `instr_type_mod.py`:

```python
def find_mutation_target(arguzz_fault: ArguzzFault, a4_cycles: List[A4CycleInfo]) -> Optional[MutationTarget]:
```

### Step-by-Step Walkthrough

**Input:**
```python
arguzz_fault = ArguzzFault(
    step=200,
    pc=2144416,
    kind="INSTR_WORD_MOD",
    original_word=3147283,
    mutated_word=8897555
)
```

**Step 1: Decode the original instruction word**

```python
original_decoded = decode_insn_word(arguzz_fault.original_word)  # 3147283
# Result: DecodedInsn(kind=7, major=0, minor=7, name="AddI")
```

This uses `insn_decode.py` which mirrors the RISC-V decoding logic:
- `3147283` in binary → opcode = 0x13 (I-type), func3 = 0 → `AddI` → kind = 7
- major = 7 // 8 = **0**
- minor = 7 % 8 = **7**

**Step 2: Calculate expected A4 PC**

```python
expected_a4_pc = arguzz_fault.pc + 4  # 2144416 + 4 = 2144420
```

**Step 3: Search for matching cycles**

```python
exact_matches = []
for cycle in a4_cycles:
    if (cycle.pc == expected_a4_pc and      # 2144420
        cycle.major == expected_major and    # 0
        cycle.minor == expected_minor):      # 7
        exact_matches.append(cycle)
```

This finds all cycles where:
- PC = 2144420 (matches our expected next PC)
- major = 0, minor = 7 (matches AddI instruction)

**Step 4: Handle loops (disambiguation)**

If the same instruction appears multiple times (in a loop), we pick the one with the highest `step` that's still ≤ Arguzz's step:

```python
if len(exact_matches) > 1:
    valid_matches = [c for c in exact_matches if c.step <= arguzz_fault.step]
    result = max(valid_matches, key=lambda c: c.step)
```

**Result:**

```python
MutationTarget(
    cycle_idx=16777,          # Index into trace.cycles[]
    step=198,                 # A4's user_cycle (note: 200 - 2 = 198)
    pc=2144420,               # A4's PC (next PC)
    original_major=0,         # From AddI
    original_minor=7,
    mutated_major=1,          # From XorI (decoded from 8897555)
    mutated_minor=0,
)
```

---

## Visual Summary

```
ARGUZZ MUTATION                           A4 PREFLIGHT TRACE
═══════════════                           ══════════════════

<fault>{                                  trace.cycles[16777] = {
  step: 200,          ─────────────────→    user_cycle: 198,      ← Different! (2 ecalls)
  pc: 2144416,        ─────────────────→    pc: 2144420,          ← Different! (+4)
  word: 3147283→8897555                     major: 0, minor: 7    ← Original instruction
}                                           txn_idx: 16258
                                          }

DECODING                                  WHAT WE MUTATE
════════                                  ═══════════════

3147283 (original)                        trace.cycles[16777].major = 0 → 1
  → AddI                                  trace.cycles[16777].minor = 7 → 0
  → major=0, minor=7

8897555 (mutated)                         This matches what Arguzz's mutation
  → XorI                                  records in major/minor after execution
  → major=1, minor=0
```

---

## Key Differences Table

| Aspect | Arguzz | A4 | Relationship |
|--------|--------|-----|--------------|
| **Step counter** | `fault_inj_ctx.current_step` | `cycle.user_cycle` | A4 = Arguzz - (# machine ecalls/mrets before this step) |
| **PC recorded** | Before execution | After execution (next PC) | A4_PC = Arguzz_PC + 4 |
| **Increments when** | Every instruction | Only when `exec_rv32im` returns `Some(kind)` | Machine ops cause divergence |
| **Source file** | `rv32im.rs:716` | `preflight.rs:556` | Different logic paths |
| **Location in trace** | N/A (runtime) | `trace.cycles[idx]` | A4 reads from recorded trace |

---

## Why This Works

The algorithm works because:

1. **PC + 4 is unique enough** - Most instructions are at unique addresses
2. **major/minor verification** - Even if PC matches, we verify the instruction type
3. **Step disambiguation** - For loops where PC repeats, the step counter disambiguates which iteration

The common constraint failure (`VerifyOpcodeF3`) appears at the **same A4 step** in both runs because:
- Both Arguzz and A4 end up with the same mismatch: instruction word says `AddI`, but major/minor says `XorI`
- The constraint checker sees this inconsistency at the same `user_cycle` (198)