# M3 Report — Arguzz Executor Mutation (a1-targeted)

**Status:** BLOCKED

## Seed sweep
- Swept seeds 0..1999; **64** hit `a1`
- Chosen: seed=**385**, injected **a1 = V = 5**
- No seed with V=9 found in sweep window

## Witgen blocker (critical)
- All probed a1 hits panic in witgen preflight before `<constraint_fail>` collection: **True**
- Panic site: `preflight.rs:227` (`wrap_memory_txns` — cycle diff index OOB)
- **Contrast:** non-operand register hits (e.g. seed 42 → `t0`) complete witgen; add-operand hits (`a0`,`a1`,`s0`) do not

## A4_INSPECT × --inject
- Txn dump for chosen a1 seed: **False**
- A4_INSPECT+A4_DUMP_STEP produces txn dump when witgen completes; all probed a1-targeted seeds panic in preflight wrap_memory_txns before dump.

## Propagation (executor semantics @ add, A4 step 185)

| reg | op | word (expected) | prev_word | source |
|-----|-----|-------------------|-----------|--------
| a0 | READ | 3 | 3 | unchanged |
| a1 | READ | **5** | 4 | `<fault>` inject |
| s0 | WRITE | **8** (=3+V) | 0 | executor propagated |

- Algebraic propagation: **True**
- Observed in A4_DUMP_STEP dump: **False** (dump unavailable when witgen panics)
- Contrast A4: s0 WRITE stays **7** (witness isolation)

## Failures collected (deduped)

### phase=local
- *(none — witgen panic prevented constraint collection)*

### phase=accum
- *(none)*

## Predicted failure signature (if witgen completed)
- IsRead@79 residue `(4-V) mod p` = **2013265920** — expected **FAIL**
- MemoryWrite@99 — expected **PASS** (recorded s0 = recomputed 3+V)

## Field-element validation
- IsRead observed: **None**
- Expected `(4 - V) mod p`: **2013265920**
- Validated: **N/A (no failures collected)**

## GLOBAL (Hook 3 + final residue)
- *(not collected — witgen panic)*

## Headline: bias crystallization
- Witgen completed: **False**
- IsRead-only prediction testable: **False** (blocked otherwise)
- Hook-3 memory nonzero: **None**
- Bias crystallized: **False**

exit_code: **101**

**Opus gate:** M3 report emitted. Witgen preflight blocker must be resolved (or alternate capture approved) before M4 bias matrix.
