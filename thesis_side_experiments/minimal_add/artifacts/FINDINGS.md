# Minimal-Add Experiment — Running Findings Ledger

Single source of narrative truth. One section per increment: **what / why / results / intuition**.
Companion docs: `EXPERIMENT_PLAN_V2.md` (plan), `CONSTRAINT_CATALOG.md` (the 37 local constraints),
`GUIDANCE_FOR_COMPOSER.md` (initial forensics). Per-milestone machine reports live in `m0/`, `m1/`, …

---

## Method for 100% confidence on constraint meaning (standing)

Dual, self-checking:
- **Static:** each `<constraint_fail>` `loc` is an exact `file:line:col` into
  `zirgen/zirgen/circuit/rv32im/v2/dsl/*.zir`; read the line for the verbatim equation.
- **Dynamic:** the `value` field is the BabyBear residue `(LHS − RHS)` of that equation. Predict it
  from a known mutation delta; observed == predicted ⇒ proven. (`p = 2013265921`.)

---

## M0 — Reproduce & freeze baseline  ✅ (Opus-verified)

**What/why:** establish a deterministic, isolated foundation and auto-derive the add site, so any
later difference is attributable to a mutation, not noise or a mislocated instruction.

**Results (independently re-derived):**
- Guest add auto-derived (parsed, asserted): Arguzz **step 187**, pc **2099232** (`0x00200820`),
  `add s0, a0, a1`, preceded by `li a0,3` / `li a1,4`.
- A4 alignment: **step 185**, pc **2099236** (next-PC), **cycle_idx 15424**, major/minor **0/0**.
- Add cycle has **4 transactions**: instruction fetch (program ROM read, addr 524808·4 = the PC,
  word `0x00B50433` = `add s0,a0,a1`), a0 READ 3, a1 READ 4, s0 WRITE 7.
- Baseline: output **7**, verifier **success**, **0** constraint failures.
- Determinism: local touch set **1580** and accum **298** byte-identical across 2 runs.
- Isolation: production `risc0-host` mtime unchanged; guest comment fixed to a0/a1/s0.

**Intuition:** the "add 3+4" we reason about is a real, single, pinned event whose entire memory
footprint is 4 txns; the pipeline is reproducible to the byte, so we can trust later deltas.

---

## M1 — Enumerate the Add's constraint universe + global control  ✅ (Opus-verified)

**What/why:** get the *denominator* (which constraints the add even exercises) and the *control*
(a clean trace closes all global arguments), so "broken" is measured against a known set.

**Results (independently re-derived):**
- **37** distinct local constraint contexts at `major=0,minor=0` (0 hash collisions in this context).
- Accum-pass universe: **298** contexts (accumulation machinery — **not** global).
- **Global control:** all Hook-3 families `nonzero:false` (`memory`,`u16`,`u8`,`cycle`),
  `<a4_global_residue_zero/>`, 0 constraint failures. A correct trace closes every global argument.

**Intuition / big finding:** there is **no standalone `rs1+rs2=rd` polynomial**. Reading the ZIR
shows the ADD arithmetic is enforced **at the destination write**: `MemoryWrite@mem.zir:99/100`
asserts the recorded `rd` write equals the circuit-recomputed `AddU32(rs1,rs2)`. Memory consistency
splits into a **local** part (`IsRead`: a read returns its claimed previous value) and a **global**
part (the memory permutation argument / Hook-3 `memory`: those claimed values are real).
Full 37-constraint breakdown + intuitive mapping: see `CONSTRAINT_CATALOG.md`.

---

## M2 — A4 (witness) ground-truth on a1: 4→9   ✅ (Opus-verified, 1 provenance correction)

**What/why:** establish exactly what a witness-stage mutation of one recorded read does — which
constraints break, locally and globally — as the A4 half of the bias comparison.

**Results (independently re-derived from raw tags):**
- **Isolation:** only the a1 READ txn (15057) changes (word 4→9, prev_word stays 4); a0 READ stays 3;
  s0 WRITE txn stays **7** (the recorded ALU output is NOT recomputed by the mutation).
- **Local failures (exactly 2, both at cycle 15424):** `IsRead@mem.zir:79` and `MemoryWrite@mem.zir:99`,
  both residue `2013265916 = p−5`. No accum-phase failures.
- **Global:** Hook-3 `memory` family nonzero (e0=1835926732…); `u16/u8/cycle` zero;
  `A4_GLOBAL_RESIDUE` nonzero. (Baseline M1: all zero.) Witness corruption breaks the global memory arg.
- Both failing locs ⊆ the 37-member Add universe.

**Provenance — corrected (this is important):**
- `IsRead@79`: `oldTxn.dataLow = newTxn.dataLow` → `prev(4) = read(9)` → residue 4−9 = −5 = p−5. ✓
- `MemoryWrite@99`: `newTxn.dataLow = data.low`, where `newTxn.dataLow` = **recorded s0 write = 7** and
  `data.low` = **recomputed `AddU32(rs1=3, rs2=9) = 12`** → residue 7−12 = −5 = p−5. ✓
  - composer's report mislabeled this as `4 vs 9`. The correct pair is **7 (recorded write) vs 12
    (recomputed sum)**. Both pairs give −5, so the residue check alone could not disambiguate.

**Intuition (the real M2 lesson):** A4 changes ONE recorded value (the a1 read), but the circuit
*recomputes* everything downstream from it. So that single change is inconsistent with **two** things
in the same cycle: (a) the value previously stored in a1 (→ `IsRead`), and (b) the recorded result of
the add, because the circuit recomputes 3+9=12 while the recorded s0 write is still 7 (→ `MemoryWrite`,
which IS the `rs1+rs2=rd` check). Both residues are p−5 because the +5 read corruption propagates
linearly through the addition (12 = 7+5). Globally, the memory permutation argument no longer closes
(Hook-3 `memory` ≠ 0).

**Methodology reinforcement:** the residue check is *necessary but not sufficient* — linear
propagation can make different `(lhs,rhs)` pairs yield the same residue. Provenance must also name the
specific witness values (from the txn dump + ALU semantics), not just match the number.

**Sharpened M3 prediction (falsifiable):** Arguzz corrupts a1 *before* execution, so the executor
genuinely computes 3+9=12 and **records s0=12**. Then `MemoryWrite` should *pass* (recorded 12 ==
recomputed 12) and only `IsRead` should fail (read 9 vs prev 4). If so, the bias is: witness-stage
breaks {IsRead, MemoryWrite}; executor-stage breaks {IsRead} only. (To be tested in M3.)

---

## M3 — Arguzz (executor) ground-truth on a1   ⛔ BLOCKED by preflight panic — root cause verified

**What/why:** run the executor-stage half of the comparison (inject a1 before the add) to test the
sharpened prediction (executor breaks {IsRead} only; MemoryWrite passes). Seed sweep found 64 seeds
that hit a1 at step 187; chosen seed 385 → a1=5. **Every a1-targeted seed panics**, so no constraint
data could be collected.

**Blocker (panic):** `preflight.rs:227` in `wrap_memory_txns` — `cycle diff index OOB`.

**Root cause — verified from source (not inferred from the flag layer):**
1. The panic is a raw slice index `self.trace.cycles[(diff/2) as usize]` with
   `diff = txn.cycle - 1 - txn.prev_cycle` (u32). The guard that would catch a bad diff is
   **commented out** (`preflight.rs:225 // ensure!(...)`). On `prev_cycle >= cycle` the u32 underflows
   to ~2³¹ → out-of-bounds index → hard panic.
2. `wrap_memory_txns` runs in the **preflight phase** (`preflight.rs:105`), strictly **upstream** of
   the witgen `StepMode` (`hal/mod.rs`) and of every C++ `eqz` / `FAULT_INJECTION_ENABLED` /
   `CONSTRAINT_CONTINUE` bypass. `preflight.rs` has **zero** env-flag checks — no flag can intercept it.
3. **Preflight re-executes the program and the Arguzz injection re-fires there.** Each `Emulator`
   builds a fresh `RV32IMFaultInjectionContext{ current_step:0, rng:seed_from_u64(seed) }`
   (`rv32im.rs:45-52`) and injects when `current_step == injection_step` (`rv32im.rs:152-156`) — so the
   same seed deterministically re-injects a1=5 during preflight.
4. `PRE_EXEC_REG_MOD` does an **extra `store_register` to the operand at the same cycle** the add then
   accesses it (`rv32im.rs:626-637`, before the ADD at `:887`). So at the add cycle C, a1 gets a WRITE
   (injected) then a READ (add source). The READ's `prev_cycle` becomes C → `diff = C-1-C` underflows →
   OOB. (Same for a0 read / s0 write.)
5. **Why t0 (seed 42) completes:** t0 is dead — injected WRITE at C with no same-cycle follow-up access,
   so no self-referential `prev_cycle`, no underflow. Hence t0 produced 7 clean fails and a txn dump.
6. **Why A4 is immune despite carrying all the continuation flags:** A4 never injects in the executor.
   Preflight wraps a clean trace; `witgen/mod.rs` overwrites `trace.txns[…].word` 4→9 **after**
   `wrap_memory_txns`. The cycle-diff bookkeeping never sees an inconsistency.

**Flag-hypothesis verdict:** A4 *does* enable more continuation machinery (`CONSTRAINT_CONTINUE`,
auto `FAULT_INJECTION_ENABLED`, `A4_COVERAGE_TOUCH`→`SeqForward` to avoid parallel SIGSEGV,
`A4_FAMILY_RESIDUE`). But composer's M3 Arguzz run already set `CONSTRAINT_CONTINUE` +
`A4_COVERAGE_TOUCH`(SeqForward) and the host set `FAULT_INJECTION_ENABLED` + `disable_assertions`.
It still panics, because the crash is in preflight — before any of those flags act — and its only
guard is commented out. **Not a missing-flag problem; it is structural.**

**Open (99%→100%):** confirm by a single traced run that the PRE_EXEC `store_register` records a
distinct WRITE txn in the same cycle as the operand READ (vs. silently overwriting pager state).

**Thesis value:** this is itself a propagation-vs-isolation result — Arguzz operand corruption fails
in a *different phase* (preflight memory bookkeeping) than A4 (constraint eval). Decision on
remediation (restore `ensure!` to make it a catchable crash outcome / reframe / guest variant)
pending.

**EXHAUSTIVE EMPIRICAL VERIFICATION (`verify_crash_condition.py`, existing binary, no rebuild;
full report in `artifacts/verify_crash/verify_report.json`):**

*Part A — inject all 31 distinct register targets at step 187 (`add s0,a0,a1`), full prove each:*
**Exactly 3** registers crash at `preflight.rs:227` with **0** constraint failures — `a0`, `a1`, `s0`
(the add's two source operands + destination). The **other 28** registers all **complete witgen** and
emit **4–7 constraint failures** (normal Arguzz fault detection). `PART A holds (crash ⇔ operand) = True`.

*Part B — fix seed 32 (always picks `a1`; register is seed-determined, step-independent), sweep the
inject step:*

| inject step | instruction | touches a1? | outcome |
|---|---|---|---|
| 184 | (pre-add) | no | witgen completes, 6 fails |
| 185 | `li a0,3` | no | witgen completes, 5 fails |
| 186 | `li a1,4` | **writes a1** | **crash `preflight.rs:227`**, 0 fails |
| 187 | `add s0,a0,a1` | **reads a1** | **crash `preflight.rs:227`**, 0 fails |
| 188 | (post-add) | no | witgen completes, 6 fails |
| 189 | (post-add) | no | witgen completes, 5 fails |

**Conclusion (proven, not inferred): the crash is NOT pathological to Arguzz/PRE_EXEC_REG_MOD.** It
fires **iff** the injected register is one the instruction at the inject step accesses *that same
cycle* (read or write). Part B nails it: the *same* register `a1` crashes only at the two steps that
touch a1 (186 write, 187 read) and injects cleanly everywhere else. Mechanism: the injected
`store_register` adds a second memory transaction to that register's address within one cycle, so the
second txn's `prev_cycle == cycle`, `diff = cycle-1-prev_cycle` underflows u32, and the unguarded index
at `preflight.rs:227` goes OOB. Non-consumed registers get a single monotonic txn → no underflow →
witgen proceeds and the corrupted value trips downstream constraints (the 4–7 fails). This is why
random-register Arguzz "mutates fine" in practice: only ~3 of 31 registers are operands at any
consumed step, so uniform random selection almost never hits the crash case — our seed sweep
*deliberately* forces it. (Note: the non-operand "panic" line is the *host's own* `panic!` at
`main.rs:106` after `prove` returns Err; the constraint failures were already emitted. A production
`risc0-host` returns cleanly and the fuzzer buckets it as a detected fault. `sp` is a special case:
completes preflight but yields a non-constraint error since it's the stack pointer.)

## M4 — Bias comparison matrix   ⬜ (pending)

## M5 — Thesis prose   ⬜ (pending, needs approval to edit thesis.md)

## M6 — Statistics campaign design   ⬜ (pending)
