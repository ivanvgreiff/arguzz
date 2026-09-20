# Investigation Report: Why 3 D2.B Kinds Accept on g1/g2/g3 but Reject on g0

**Date:** 2026-06-25  
**Status:** Root cause identified with replay proof  
**Question:** Is the g0 vs g1/g2/g3 split caused by guest program logic, or by a malfunction / missing implementation?

---

## Executive answer

**It is not guest program logic.** The sweep compared apples to oranges:

| Data source | Guest | Binary built from | Has D2.B TXN/cycle handlers? |
|-------------|-------|-------------------|------------------------------|
| g0 baseline (POS.8 d2f reuse) | CircIL `--in1 5 --in4 10` | `workspace/output` (risc0-**modified**) | **YES** |
| g1/g2/g3 sweep | ECALL / mem / SHA guests | `93bda33b` **clean** / **seamb** tree | **NO** |
| IV.POS.9 a3seamb race | Seam-B minimal ALU | `93bda33b` holed (**seamb** tree) | **NO** |

On binaries **without** the three witgen handlers, the host prints `<a4_error>{"error":"invalid config", ... TXN_PREV_CYCLE_MOD ...}</a4_error>`, **does not mutate the trace**, proves the **honest execution**, and the verifier accepts → measured **100% accept** with Hook3 all-zero and `num_failures=0`.

On binaries **with** handlers (`workspace/output`), the same config mutates the trace, Hook3 memory/cycle fire, and verify **rejects**.

**Same CircIL g0 guest, two binaries — replay proof:**
- OLD output binary + g0 guest + TXN_PREV_CYCLE mut59 → **reject**, tag applied, mem+cyc Hook3 true  
- NEW sweep g0 binary + g0 guest + same mut59 → **accept**, `invalid config`, tag absent, Hook3 false  

Guest program is not the variable; **missing Rust mutation handlers in the IV.POS.9 campaign binaries** is.

---

## Work performed

### Phase 1 — DB forensics (sweep/data + POS.8 g0)

Compared V5_control DBs at N=5000 (g0 truncated from POS.8 n10000).

| Metric | g0 (CircIL) | g1 | g2 | g3 |
|--------|-------------|----|----|-----|
| 3-kind accept | **0/1713** | **1534/1534** | **1536/1536** | **1667/1667** |
| Other kinds accept | **0** | **0** | **0** | **0** |
| MEM_VAL_MOD accept | **0/574** | **0/590** | **0/583** | **0/509** |
| 3-kind global_failures | **3033 rows** | **0** | **0** | **0** |
| Hook3 memory nonzero (TXN kinds) | **100%** | **0%** | **0%** | **0%** |
| CYCLE_DIFF orig=0 only | 505/509 (+4 ones) | 512/512 | 512/512 | 556/556 |

**Initial misread:** g1/g2/g3 looked like “guest trace doesn’t bind constraints.”  
**Correction:** MEM_VAL still **rejects 100%** on g1/g2/g3 — verifier and Hook3 work fine. Only the 3 kinds “accept.”

### Phase 2 — Binary isolation (replay matrix)

Re-ran stored mutation configs through available `risc0-host` binaries with  
`A4_FAMILY_RESIDUE=1`, `A4_COVERAGE_TOUCH=1`, `CONSTRAINT_CONTINUE=1`.

| Binary | Guest | Kind | rc | Accept | invalid_config | tag_applied | mem Hook3 |
|--------|-------|------|-----|--------|----------------|-------------|-----------|
| output (modified) | g0 CircIL | TXN_PREV_CYCLE | 101 | **No** | No | **Yes** | **Yes** |
| output (modified) | g0 | CYCLE_DIFF_COUNT | 101 | **No** | No | Yes | cyc Yes |
| output (modified) | g0 | MEM_VAL | 101 | **No** | No | Yes | Yes |
| sweep g0 clean | g0 | TXN_PREV_CYCLE | 0 | **Yes** | **Yes** | **No** | No |
| sweep g0 clean | g0 | CYCLE_DIFF_COUNT | 0 | **Yes** | **Yes** | No | No |
| sweep g0 clean | g0 | MEM_VAL | 101 | **No** | No | Yes | Yes |
| sweep g1 clean | g1 | TXN_PREV_CYCLE | 0 | **Yes** | **Yes** | No | No |
| sweep g1 clean | g1 | MEM_VAL | 101 | **No** | No | Yes | No |
| ap_seamb holed | seamb | TXN_PREV_CYCLE | 0 | **Yes** | **Yes** | No | No |

**Decisive cross:** g0 CircIL guest + **old** binary → reject; g0 CircIL guest + **new** binary → accept. Guest unchanged.

### Phase 3 — Source / strings audit

**Handlers in `witgen/mod.rs` match arms `(Some("KIND"), ...)`:**

| Tree | Commit / role | TXN_PREV_* / CYCLE_DIFF | MEM_VAL | Notes |
|------|---------------|-------------------------|---------|-------|
| `risc0-modified` | 6556e8d (+ D2.B) | **YES** (3 kinds + dead arms) | YES | POS.8 `workspace/output` build |
| `risc0-clean-28e53771` | 93bda33b sweep | **NO** | YES | Track-B sweep builds |
| `risc0-seamb` | 93bda33b race/AP | **NO** | YES | a3seamb holed builds |

D2.B added handlers in commit `6556e8d7` (“Commit A4_MUTATION_CONFIG and mutation replay hooks in witgen”) on **`risc0-modified` only**.  
`ffi.cpp` / Hook3 machinery is **identical** between 93bda33b and 6556e8d (zero diff). Only `witgen/mod.rs` gained the TXN/cycle mutation arms.

**Strings in binaries:**
- `workspace/output/risc0-host`: contains `TXN_PREV_CYCLE_MOD`, `CYCLE_DIFF_COUNT_MOD`, handler error strings  
- `sweep/28e53771_clean__g0_baseline/risc0-host`: contains only generic `"invalid config"` fallback  
- `ap_seamb/bench-verifyopcode/risc0-host`: same as clean (built from `risc0-seamb`, no TXN handlers)

**Replay stdout (sweep g0 + TXN_PREV_CYCLE):**
```
<a4_config_loaded>{..."mutation_type":Some("TXN_PREV_CYCLE_MOD")...}</a4_config_loaded>
<a4_error>{"error":"invalid config", "mutation_type":Some("TXN_PREV_CYCLE_MOD")...}</a4_error>
<a4_family_residue>{"family":"memory", "nonzero":false}</a4_family_residue>
<a4_family_residue>{"family":"cycle", "nonzero":false}</a4_family_residue>
```
No `<a4_txn_prev_cycle_mod>` tag → trace never mutated.

Clean tree fallback (`witgen/mod.rs:589-592`):
```rust
_ => {
    println!("<a4_error>{\"error\":\"invalid config\", \"mutation_type\":{:?}, \"step\":{:?}}</a4_error>",
             mutation_type, step);
}
```

---

## Mechanism (precise)

1. **Python A4 fuzzer** selects `TXN_PREV_*` / `CYCLE_DIFF_COUNT` arms, generates configs, writes DB rows with `original_value ≠ mutated_value`, `outcome=applied`.
2. **Host** loads `A4_MUTATION_CONFIG`.
3. **If handler exists (modified):** mutates `trace.txns[].prev_cycle` etc. → witgen uses corrupted trace → Hook3 / verify fail → `verifier_accepted=0`.
4. **If handler missing (clean/seamb 93bda33b):** hits `_ => invalid config` → **no trace change** → witgen builds witness for **honest execution** → verify succeeds → `verifier_accepted=1`, Hook3 all-zero, `num_failures=0`.

This is **not** a soundness bug (witness attests true execution). It is a **campaign integration bug**: Python bandit runs kinds the deployed binary cannot apply.

The DB still shows `proof_generated=100%` because a valid proof **was** generated — for the unmodified trace.

---

## Why the sweep looked “guest-dependent”

- **g0** row in MASTER_REPORT used **POS.8 d2f DB** → old **modified** binary → real mutations → 0% accept.  
- **g1/g2/g3** used **fresh sweep DBs** → **clean 93bda33b** binary → silent skip → 100% accept.  
- Different guests **and** different binaries. Replay removes guest as the cause.

IV.POS.9 race (~32% V5 accept) uses the same **93bda33b holed seamb** binary without TXN handlers → same false accept pattern, not Seam-B guest logic.

---

## What is NOT the cause

- Guest ECALL/memory/SHA trace shape (replay: g0 guest + new binary still accepts)  
- CONSTRAINT_CONTINUE (same env everywhere)  
- Accept recording bug (`verifier_accepted` correctly reflects verify of honest proof)  
- Broken verifier (MEM_VAL still rejects on all guests/binaries that implement it)

---

## Recommended fixes (for follow-up)

1. **Rebuild Track-B sweep + race hosts from `risc0-modified`** (or merge D2.B handler commit into clean/seamb baseline at 93bda33b).
2. **Or** drop the 3 kinds from Python `MUTATION_KINDS` when running against clean/seamb binaries.
3. **Add fuzzer guard:** if stdout contains `invalid config` for the requested `mutation_type`, classify as `skipped` / `not_applied`, not `applied` + accept.
4. **Re-run g0 baseline** on sweep binary with handlers to get a fair within-binary guest comparison (optional science).

---

## Artifacts

- Sweep DBs: `a4/runs/iv_pos_9/sweep/data/g{1,2,3}_*.db`  
- Replay scripts: run in-session 2026-06-25 (this report)  
- Binaries tested:  
  - `/root/arguzz/workspace/output/target/release/risc0-host` (modified, HAS handlers)  
  - `/root/arguzz/a4/builds/sweep/28e53771_clean__g0_baseline/risc0-host` (NO TXN handlers)  
  - `/root/arguzz/a4/builds/ap_seamb/bench-verifyopcode/risc0-host` (NO TXN handlers)
