# Minimal-Add Experiment Results (Thesis §3.3.3)

Artifacts from `run_phases.py` on the isolated guest. Production binaries unchanged.

## Pinned site

| Field | Value |
|-------|-------|
| Guest intent | `li a0,3; li a1,4; add s0,a0,a1; commit 7` |
| Arguzz step | **187** (pc `0x001FFBC0` / 2099232) |
| A4 step | **185** (pc `0x001FFBC4` / 2099236, next PC) |
| major / minor | 0 / 0 (MISC0 Add) |
| Register reads at Add | a0=3, a1=4 |
| Register write | s0=7 |

**Step offset:** Arguzz step 187 ↔ A4 step 185 (Δ=−2 for this guest; do not assume fixed +4 globally).

## Phase 1 — Instruction card

See `instruction_card.json`. Preflight txns at A4 step 185:

| txn_idx | reg | op | word | prev_word |
|---------|-----|-----|------|-----------|
| 15056 | a0 | READ | 3 | 3 |
| 15057 | a1 | READ | 4 | 4 |
| 15058 | s0 | WRITE | 7 | 0 |

## Phase 2 — Local constraints touched (unmutated)

Filtered touch lines at A4 step 185: `touch_at_add.txt` (from witgen `<a4_touch_coverage>`).

## Phase 3 — Arguzz executor inject

```bash
thesis-minimal-host --trace --inject \
  --inject-step 187 --inject-kind PRE_EXEC_REG_MOD --seed 42
```

| Outcome | Detail |
|---------|--------|
| exit | -11 (prover crash after local fail) |
| local | **IsRead** @ mem.zir:79 (single failure captured) |
| Hook 3 | not emitted in this run |

Mechanism: `store_register` before step 187 corrupts a source register in the executor; witness still records trace-consistent reads until mem consistency check.

## Phase 4 — A4 witness txn rewrite

Config: `a4_mutation.json` — `PRE_EXEC_REG_MOD`, strategy `next_read`, step **185**, txn **15057** (a1 READ), word **4 → 9**.

| Outcome | Detail |
|---------|--------|
| exit | 101 |
| local | **IsRead** @ mem.zir:79 **and** **MemoryWrite** @ mem.zir:99 |
| Hook 3 | **memory** family nonzero (e0–e3 all nonzero) |

Mechanism: rewriting the a1 READ `word` while leaving `prev_word=4` breaks read consistency and cascades to the register write chain.

## Phase 6 — Comparison (thesis takeaway)

| Dimension | Arguzz | A4 |
|-----------|--------|-----|
| Injection point | Executor register store before step | Preflight READ txn word at step |
| Typical first local break | IsRead | IsRead + MemoryWrite |
| Global (Hook 3) | absent here | memory family residue |
| Named ALU “rs1+rs2=rd” fail | no | no |

**Thesis point:** Both paths break **memory/register consistency** constraints tied to the Add’s operand reads, not a literal “add opcode” polynomial. A4’s witness-stage mutation exposes **more local failure modes** (MemoryWrite) and **accumulator-phase global signal** (Hook 3 memory), shifting bandit feedback relative to executor-only Arguzz inject.

## Reproduce

```bash
cd /root/arguzz
python3 thesis_side_experiments/minimal_add/run_phases.py
```
