# A4 Mutation Strategy

A4 mutates the **PreflightTrace** (memory transactions) BEFORE witness generation, allowing granular EQZ constraint failures.

## Comparison with Other Strategies

| Strategy | Mutation Point | Detection | Granularity |
|----------|---------------|-----------|-------------|
| **Arguzz** | During executor | EQZ | Per-constraint |
| **A3** | Post-witness DATA matrix | Prover failure | Cycle only |
| **A4** | Pre-witness PreflightTrace | EQZ | Per-constraint |

## Key Advantage

A4 combines:
- **A3-style post-execution mutation** (no propagation, more cascading failures)
- **Arguzz-style EQZ output** (granular constraint location info)

## Architecture

```
Execution → PreflightTrace.txns[] → WitnessGenerator::new()
                     ↑                        ↓
              A4 MUTATION              stepExec() → EQZ()
                     ↓                        ↓
              Modified txn.word      Granular constraint failures!
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `A4_INSPECT=1` | Enable preflight inspection output |
| `A4_DUMP_STEP=N` | Dump transactions for step N |
| `A4_DUMP_TXN=N` | Dump specific transaction index |
| `A4_CONFIG=/path/to/config.json` | Path to mutation config file |

## JSON Config Format

```json
{
  "mutations": [
    {"txn_idx": 15620, "word": 75080565}
  ]
}
```

### Fields

- `txn_idx`: Index into PreflightTrace.txns array
- `word`: New value to set for txn.word

## Finding the Right txn_idx

### Step 1: Find transactions for target step
```bash
A4_INSPECT=1 A4_DUMP_STEP=52 ./target/release/risc0-host --trace --in1 5 --in4 10
```

### Step 2: Identify the WRITE transaction
- READ: `word == prev_word`
- WRITE: `word != prev_word` ← This is what you want for COMP_OUT_MOD

### Step 3: Verify with Arguzz
```bash
./target/release/risc0-host --trace --inject --seed 12345 --inject-step 52 --inject-kind COMP_OUT_MOD --in1 5 --in4 10
```
The `word` value in the WRITE transaction should match Arguzz's `out:XXXX` value.

## Usage

```bash
A4_CONFIG=/root/arguzz/a4/configs/comp_out_mod_step52.json \
CONSTRAINT_CONTINUE=1 CONSTRAINT_TRACE_ENABLED=1 RISC0_WITGEN_DEBUG=1 \
./target/release/risc0-host --trace --in1 5 --in4 10
```

## Key Discovery: READ vs WRITE Identification

From source code (`preflight.rs`):
- **load_u32 (READ)**: Sets `prev_word = word` (same value)
- **store_u32 (WRITE)**: Sets `prev_word` = old value, `word` = new value

So `word != prev_word` definitively identifies WRITE transactions.

## Files

- `configs/` - JSON mutation configuration files
- `scripts/` - Helper scripts (future)
- Runtime code lives in `risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`
