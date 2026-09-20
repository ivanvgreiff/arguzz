# Appendix B — Arguzz mutation capabilities (full)

Companion to `PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md` (§3 there is the condensed version). Arguzz applies exactly
one fault at one execution step per run; the `--seed` deterministically fixes the resulting mutated value.

## All mutation kinds
| kind | target | timing | instruction-aware? |
|---|---|---|---|
| **INSTR_WORD_MOD** | the fetched 32-bit instruction word | at decode | **No** (the only kind that can alias rs2→rs1) |
| PRE_EXEC_PC_MOD | program counter | before fetch | n/a (uses `random_pc`) |
| POST_EXEC_PC_MOD | next program counter | after exec | n/a |
| PRE_EXEC_MEM_MOD | a memory word | before exec | no |
| POST_EXEC_MEM_MOD | a memory word | after exec | no |
| PRE_EXEC_REG_MOD | a register (x1..x31) | before exec | no |
| POST_EXEC_REG_MOD | a register | after exec | no |
| COMP_OUT_MOD | ALU result | post-compute | yes (ALU ops) |
| BR_NEG_COND | branch taken/not-taken | compute | yes (branches) |
| LOAD_VAL_MOD | loaded value | post-load | yes (loads) |
| STORE_OUT_MOD | stored value | pre-store | yes (stores) |

## `random_word(word)` — the INSTR_WORD_MOD operator (rv32im.rs ~190)
Explicitly NOT instruction-field-aware (`// TODO: instruction aware manipulations`). It does NOT touch bits 0–1
(the base opcode-class bits, "checked during fetch"). It picks a strategy uniformly from {0,1,2} and retries in
a `while new_word == word || kind == Invalid` loop until the candidate differs from the original AND decodes to
a valid RISC-V instruction:
- **Strategy 0 — single bit flip:** `word ^ (1 << rng.range(2..=31))`. One random bit among bits 2–31.
  **This is the strategy that produces the rs2→rs1 alias in a single flip**, because the guest's operands are
  one Hamming bit apart by construction.
- **Strategy 1 — multi-bit flip:** choose `N = rng.range(1..=29)` distinct bit positions among bits 2–31 and XOR
  them all.
- **Strategy 2 — random word:** `rng.u32() | 0x03` (fully random, low two bits forced set).

Because strategy 0 flips one bit uniformly among 30 candidate positions and only a few of those positions sit in
the rs2 field (and only one of those yields the exact alias), the per-attempt alias probability on a divide
instruction is ≈1/26–1/30 (empirically 1/26 in the race).

## Determinism & invocation
Invoked via `--inject --inject-step S --inject-kind K --seed s`. The RNG is `StdRng::seed_from_u64(seed)`, so a
given (seed, original word) deterministically reproduces the same mutated word — which is why the output-based
replay (re-running a recorded mutation) faithfully reproduces the original outcome.

## Helper value generators (for the non-instruction-word kinds)
- `random_pc` (3-way: ±1 step, ±2..10 steps, ±11..1000 steps; 50/50 direction).
- `random_mod_of_u32` (8-way: 0, 1, 0xffffffff, 0xfffffffe, N-bit flip, +1, −1, fully random) — used by
  COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, and the reg/mem value mods.
- `random_memory_addr` (50% random, 50% derived from sp/gp); `random_register_addr` (x1..x31).
