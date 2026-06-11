# Minimal Single-Add Thesis Side Experiment

Isolated experiment for thesis §3.3.3. **Does not modify** any existing repo code,
guests, or binaries under `workspace/output/`, `a4/`, or `workspace/risc0-modified/`.

## Layout

```
thesis_side_experiments/minimal_add/
├── README.md           # this file
├── PLAN.md             # experiment phases (modern A4 + Arguzz, decoupled)
├── build.sh            # builds only into ./target/
├── Cargo.toml          # workspace root
├── host/               # thesis-minimal-host (separate binary name)
├── methods/            # embeds thesis-minimal-guest ELF
└── methods/guest/      # one explicit R-type add: t2 = t0 + t1 (3 + 4 = 7)
```

## Guest semantics

The guest loads `rs1 = 3`, `rs2 = 4`, executes a single `add rd, rs1, rs2`,
and commits `7`. No host inputs — trace steps are minimal and the Add is easy
to find (`major=0`, `minor=0`).

## Build

```bash
cd /root/arguzz/thesis_side_experiments/minimal_add
./build.sh
```

Produces: `./target/release/thesis-minimal-host` (never overwrites `workspace/output/.../risc0-host`).

## Arguzz trace + inject

```bash
./target/release/thesis-minimal-host --trace
./target/release/thesis-minimal-host --trace --inject \
  --inject-step <N> --inject-kind PRE_EXEC_REG_MOD --seed 42
```

## A4 (read-only use of existing `a4` package)

Point inspection/mutation at this binary's ELF via env or CLI paths documented in `PLAN.md`.
Do **not** use `a4/arguzz_dependent/` or coupled compare.

## Dependencies

Reads patched RISC Zero from `workspace/risc0-modified/` as a **path dependency only**
(no edits to that tree).
