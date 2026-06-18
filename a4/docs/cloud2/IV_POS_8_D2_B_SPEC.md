# IV.POS.8 D2.B — Pure-A4 Kind Expansion Spec

**Branch:** `cloud2` (direct commit, no feature branches)
**Date opened:** 2026-06-17
**Author:** Ivan + Opus (planning); Composer (implementation)
**Status:** **v0.5.4 LOCKED + Batch 3 audit patch** (2026-06-18) — v0.5.3 Batch 2 dead-arm audit; **v0.5.4 adds Batch 3 outcomes:** B.4/B.5 **confirmed dead (W-18)** via [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md); B.6/B.7 **confirmed dead (W-17)**; B.8 **confirmed LIVE**. Plan mirror: [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) v0.13 §6d + W-18.
**Parent:** [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) v0.5 §3 (sub-deliverable D2.B)
**Predecessor:** [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) v0.2 LOCKED (merged at `7b66fb9`)
**Authoritative reference:** [`a4/docs/standalone/MUTATION_TAXONOMY.md`](../standalone/MUTATION_TAXONOMY.md) — every per-kind decision below is cross-referenced to this document.

---

## 0. What this document is

The implementation spec for **D2.B — eight new pure-A4 mutation kinds**, covering Pro's complete wish list from `ProG_Report_3.md` §8 + §15.3. This v0.3 is **deeper and more rigorous than a normal spec** at Ivan's instruction (2026-06-17) — mutating the witness trace is a sensitive operation and we have a responsibility to know *exactly* what each mutation does, what constraints fire, and where in the proving pipeline the change takes effect.

**Workflow:** ✅ Ivan reviewed v0.4 → ✅ §6 (17 questions) resolved → ✅ spec locked at v0.5 → **NEXT: Composer Batch 1 kickoff** → reports → review → iterate → D2.B complete.

---

## 1. Where these mutations live in the risc0 proving pipeline

Before any per-kind design, we must be precise about **where** these mutations sit and **what they affect downstream**. This grounds every decision below.

### 1.1 The proving pipeline at a glance

```
┌─────────────────────────────────────────────────────────────────┐
│                  risc0-host                                     │
│                                                                 │
│  guest program execution                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ Segment::preflight(rand_z)                          │        │
│  │   - Runs the guest's instructions                   │        │
│  │   - Records every cycle into trace.cycles[]         │        │
│  │   - Records every memory/register access            │        │
│  │     into trace.txns[]                               │        │
│  │   - Records crypto operation state in trace.backs[] │        │
│  │   - Records BigInt computation in trace.bigint_bytes│        │
│  │                                                     │        │
│  │ ► PRODUCES: PreflightTrace                          │        │
│  │     (the "post-execution witness")                  │        │
│  └─────────────────────────────────────────────────────┘        │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ A4 INSPECTION (witgen mod.rs lines 72-187)          │        │
│  │   IF env A4_INSPECT=1:                              │        │
│  │     Dump trace contents via <a4_*> tags             │        │
│  │   (read-only; no mutation)                          │        │
│  └─────────────────────────────────────────────────────┘        │
│           │                                                     │
│           ▼                                                     │
│  ┌═════════════════════════════════════════════════════┐        │
│  ║ A4 MUTATION (witgen mod.rs lines 189-601)           ║        │
│  ║                                                     ║        │
│  ║   IF env A4_MUTATION_CONFIG=/path/to/cfg.json:      ║        │
│  ║     1. Read mutation_type + target_step from JSON   ║        │
│  ║     2. Auto-set FAULT_INJECTION_ENABLED=1           ║        │
│  ║        (unless A4_NO_FAULT_INJECTION=1)             ║        │
│  ║     3. Dispatch to per-kind match arm               ║        │
│  ║     4. Locate the target index in trace.cycles[] or ║        │
│  ║        trace.txns[]                                 ║        │
│  ║     5. MUTATE THE TARGETED FIELD IN PLACE           ║        │
│  ║     6. Emit <a4_<kind>> evidence tag                ║        │
│  ║                                                     ║        │
│  ║   ◄── THIS IS WHERE OUR D2.B MUTATIONS LIVE ──►     ║        │
│  ║                                                     ║        │
│  ║   The mutation modifies the PreflightTrace          ║        │
│  ║   IN PLACE. Witness generation (next step) reads    ║        │
│  ║   the MUTATED trace as if it were the genuine one.  ║        │
│  ╚═════════════════════════════════════════════════════╝        │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ build_injector(trace) + build_global_vec(trace)     │        │
│  │   Constructs witness columns from (possibly         │        │
│  │   mutated) trace.cycles, trace.backs, etc.          │        │
│  └─────────────────────────────────────────────────────┘        │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ WitnessGenerator::new(preflight_results)            │        │
│  │   Allocates global, code, data, accum buffers       │        │
│  │   Calls circuit_hal.generate_witness(...)           │        │
│  │     ►► The circuit constraints are evaluated here   │        │
│  │     ►► Any mutation that violates a constraint      │        │
│  │        produces a <constraint_fail> tag             │        │
│  └─────────────────────────────────────────────────────┘        │
│           │                                                     │
│           ▼                                                     │
│       Prover (final proof attempt)                              │
│         - "success" or "error" status                           │
│         - Constraint failures aggregated                        │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 The crucial fact

**Every D2.B mutation modifies the `PreflightTrace` after execution has produced it but before the witness generator builds columns from it.** This is the "post-execution witness fuzzing" surface Pro describes in `ProG_Report_3.md` §1 and §16. Specifically:

- **Each mutation is surgical** — single field at single index.
- **The mutation runs in Rust** inside the witgen module (the dispatcher in `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` lines 189–601).
- **The mutated trace then flows through witness generation** unchanged in shape, but with the targeted field having a wrong value. Circuit constraints fire on the mismatch.
- **This is NOT during-execution fuzzing** (which is what Arguzz does — Arguzz injects a fault into the guest's state and lets execution propagate it for many cycles). Pro's Track B explicitly distinguishes A4's "single-cell direct attack on the witness/prover layer" from Arguzz's "propagated multi-cycle cascade".

### 1.3 Why this matters for design

Because A4's mutations are single-cell and act *after* execution:

1. **The mutation does NOT cause downstream execution divergence.** Other txns and cycles still reference what the original execution produced.
2. **However, mutations to "pointer-like" fields (`prev_word`, `prev_cycle`, `addr`, indexes) DO propagate** through the **permutation argument** — the prover's check that "every memory cell's writes and reads chain correctly". Mutating `txn.prev_word` at txn 100 doesn't change txn 200's `word`, but it does break the chain-link at txn 100 that the permutation argument verifies.
3. **Mutations to "metadata" fields (`major`, `minor`, `state`, `machine_mode`, `pc`)** don't propagate at all — they affect *only* the constraints evaluated at that one cycle.
4. **Mutations to txn `word` are the existing 8 kinds' bread and butter.** D2.B is specifically about fields *other than* `txn.word` (with the exception of TXN_PREV_WORD_MOD which is in the same family).

This grounds the per-kind design: low-risk kinds touch metadata that fires localized constraints; high-risk kinds touch permutation-argument fields that cascade.

### 1.4 The PreflightTrace data shape (authoritative; from taxonomy §1)

From `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs` and `rv32im-sys/src/lib.rs`:

```rust
pub struct PreflightTrace {
    pub cycles: Vec<RawPreflightCycle>,      // one entry per cycle
    pub txns: Vec<RawMemoryTransaction>,     // one entry per memory/register access
    pub bigint_bytes: Vec<u8>,               // BigInt comp data
    pub backs: Vec<Back>,                    // back-refs (Ecall, Poseidon, SHA, BigInt)
    pub table_split_cycle: u32,
    pub rand_z: ExtVal,
}

pub struct RawPreflightCycle {
    pub state: u32,           // cycle type enum (Decode=48, Poseidon=16-30, SHA=32+, …)
    pub pc: u32,              // NEXT PC after this cycle executes
    pub major: u8,            // instruction major (0-12; see taxonomy Appendix B)
    pub minor: u8,            // instruction minor
    pub machine_mode: u8,     // 0=user, 1=kernel
    pub padding: u8,          // alignment
    pub user_cycle: u32,      // ★ the "step" counter (what our Python calls `step`)
    pub txn_idx: u32,         // index into trace.txns[] where this cycle's txns START
    pub paging_idx: u32,      // index for paging ops
    pub bigint_idx: u32,      // index into bigint_bytes[]
    pub diff_count: [u32; 2], // ★ ARRAY of two u32s (memory diff counts)
}

pub struct RawMemoryTransaction {
    pub addr: u32,        // WORD address (i.e., byte_addr / 4)
    pub cycle: u32,       // ★ constraint-cycle index (NOT user_cycle); LSB=parity (even=READ, odd=WRITE)
    pub word: u32,        // value read or written
    pub prev_cycle: u32,  // constraint-cycle of the prior access to THIS address
    pub prev_word: u32,   // value at THIS address one txn earlier
}
```

★ marks fields/details with subtle semantics that the per-kind designs in §3 depend on.

## 2. The eight new kinds — overview

| Priority | # | Kind | Target field | Constraint surface | Risk |
|---|---|---|---|---|---|
| **High** | B.1 | `TXN_PREV_WORD_MOD` | `txns[i].prev_word: u32` | IsRead failure (at READs) **or** MemoryWrite/permutation failure (at WRITEs) | **Low** |
| **High** | B.2 | `TXN_PREV_CYCLE_MOD` | `txns[i].prev_cycle: u32` | Memory permutation ordering failure | **Low** |
| **High** | B.3 | `CYCLE_MODE_MOD` | `cycles[i].machine_mode: u8` | Privilege/mode-check constraint failure | **Low** |
| **Medium** | B.4 | `TXN_ADDR_MOD` | `txns[i].addr: u32` | Memory addressing + permutation chain failure | **HIGH** (may crash witgen) |
| **Medium** | B.5 | `TXN_CYCLE_PHASE_MOD` | `txns[i].cycle: u32` (LSB only) | Read/write classification + IsRead failure | **Medium** |
| **Medium** | B.6 | `CYCLE_PC_MOD` | `cycles[i].pc: u32` | PC-coherence + instruction-fetch-address failure | **Medium** |
| **Medium** | B.7 | `CYCLE_STATE_MOD` | `cycles[i].state: u32` | Cycle-state-machine constraint failure | **Medium** |
| **Medium** | B.8 | `CYCLE_DIFF_COUNT_MOD` | `cycles[i].diff_count[idx]: u32` | Memory diff-tracking constraint failure | **Medium** |

Risk legend (per taxonomy):
- **Low**: localized constraint failure; trace stays valid in shape; rarely crashes witgen
- **Medium**: localized failure but may cascade through 1–2 downstream cycles
- **HIGH**: structural; likely cascades through the permutation argument; may panic witgen unless `FAULT_INJECTION_ENABLED=1` (which the dispatcher auto-sets)

## 3. Per-kind detailed designs

Each entry follows the same structure: (a) what the mutation targets and why; (b) the Rust handler design; (c) the Python module design (target selection + value generation); (d) expected constraint failures.

### 3.1 B.1 — `TXN_PREV_WORD_MOD`

#### What it targets and why

The `prev_word` field on a memory transaction stores **the value that was at this address one access earlier** in the constraint cycle ordering. It's the witness used by the **memory permutation argument**: the prover verifies that for every memory address, the chain of (cycle_n, word_n) → (cycle_{n+1}, prev_word_{n+1}=word_n) is consistent.

The semantic differs by transaction type:

| Txn type | `word == prev_word`? | What `prev_word` means |
|---|---|---|
| **READ** | YES (IsRead constraint enforces equality) | The current value being observed (must equal `word`) |
| **WRITE** | No equality required | The value that existed at this address before this write |

This means **mutating `prev_word` has two completely distinct effects** depending on txn type:

- **At a READ:** Setting `prev_word ≠ word` directly violates `IsRead`. This is the cleanest, most localized constraint failure A4 can produce.
- **At a WRITE:** The mutated `prev_word` becomes the "previous value" the permutation argument expects the next READ at this address to see. Subsequent READ's `prev_word == old_value_we_mutated_to` will likely fail because the actual prior write was a different value. Triggers `MemoryWrite` cascade.

#### This mirrors the proven PRE_EXEC_REG_MOD two-strategy pattern

`PRE_EXEC_REG_MOD` already exploits exactly this duality:
- Strategy `next_read`: target a READ → mutate `word`, leave `prev_word` → break IsRead → triggers IsRead failure
- Strategy `prev_write`: target a WRITE → mutate `word` → subsequent READ's `prev_word` no longer matches → triggers MemoryWrite cascade

`TXN_PREV_WORD_MOD` is the **mirror image**: instead of mutating `word`, mutate `prev_word`. The two-strategy pattern carries over cleanly:
- Strategy `at_read`: target a READ → mutate `prev_word`, leave `word` → break IsRead
- Strategy `at_write`: target a WRITE → mutate `prev_word` → break permutation chain at this point in the address's history

This is **architecturally beautiful** because it doubles the constraint-surface coverage with one mutation kind and lets the bandit learn which strategy is more productive per zone.

#### Rust handler design (witgen/mod.rs)

```rust
(Some("TXN_PREV_WORD_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"TXN_PREV_WORD_MOD", "step":S, "txn_idx":I,
    //          "prev_word":V, "strategy":"at_read"|"at_write"}
    let txn_idx = extract_num("txn_idx");
    let new_prev_word = extract_num("prev_word");
    let strategy = extract_str("strategy").unwrap_or_else(|| "at_read".to_string());
    
    match (txn_idx, new_prev_word) {
        (Some(idx), Some(new_pw)) => {
            let idx = idx as usize;
            if idx >= trace.txns.len() {
                println!("<a4_error>{{...txn_idx out of range...}}</a4_error>");
            } else {
                let txn = &mut trace.txns[idx];
                let is_read = txn.cycle % 2 == 0;
                
                // Strategy validation (consistent with PRE_EXEC_REG_MOD pattern)
                let valid_for_strategy = match strategy.as_str() {
                    "at_read"  => is_read,
                    "at_write" => !is_read,
                    _ => { /* unknown strategy error */ false }
                };
                
                if !valid_for_strategy {
                    println!("<a4_error>{{...strategy mismatch...}}</a4_error>");
                } else {
                    let old_prev_word = txn.prev_word;
                    txn.prev_word = new_pw;
                    
                    println!("<a4_txn_prev_word_mod>{{\"step\":{},\"strategy\":\"{}\",\"txn_type\":\"{}\",\"cycle_idx\":<lookup>,\"txn_idx\":{},\"addr\":{},\"old_prev_word\":{},\"new_prev_word\":{},\"word\":{},\"prev_cycle\":{}}}</a4_txn_prev_word_mod>",
                        target_step, strategy, if is_read {"READ"} else {"WRITE"},
                        idx, txn.addr, old_prev_word, new_pw, txn.word, txn.prev_cycle);
                }
            }
        }
        _ => { /* missing fields error */ }
    }
}
```

#### Python module design (`a4/standalone/mutations/txn_prev_word_mod.py`)

Mirror `pre_exec_reg_mod.py` (which already has this two-strategy structure). Specifically:

```python
@dataclass
class TxnPrevWordModTarget:
    step: int
    cycle_idx: int
    txn_idx: int
    addr: int
    is_read: bool
    original_prev_word: int
    original_word: int  # for context
    original_prev_cycle: int  # for context
    strategy: str  # "at_read" or "at_write"

def get_targets_at_step(step, data, strategy="at_read"):
    """Return all valid targets at this step for the given strategy."""
    # Iterate data.get_all_txns_at_step(step), filter by strategy.
    # No txn-type exclusion beyond strategy (any addr is fine — registers + memory).

def get_all_targets(data, strategy="at_read", zone_filter=None):
    """Iterate all txns globally, useful for cTS arm-space construction."""

def generate_new_value(target, rng):
    """Mixed strategy: 33% bit-flip, 33% nearby (±1, ±N), 34% random u32."""
    # Must differ from target.original_prev_word

def create_config(target, mutated_value, output_path):
    """JSON: {"mutation_type":"TXN_PREV_WORD_MOD", "step":..., "txn_idx":...,
             "prev_word":mutated_value, "strategy":target.strategy, "_info":{...}}"""
```

#### Valid steps

**Any non-bootstrap step** (excluding step 0). All txns have `prev_word`; even txns at addresses being accessed for the first time have a `prev_word` value (initial sentinel, often 0). No `prev_cycle != 0` filter — this was an inaccuracy in v0.2.

#### Expected constraint failures

| Strategy | Primary | Secondary (cascade) |
|---|---|---|
| `at_read` | `IsRead` (word != prev_word) | Possibly `MemoryWrite` if downstream txns observe broken chain |
| `at_write` | `MemoryWrite` (next reader's prev_word doesn't match this write) | Permutation argument inconsistency |

---

### 3.2 B.2 — `TXN_PREV_CYCLE_MOD`

#### What it targets and why

`prev_cycle` is the **temporal pointer** in the memory permutation argument: it stores the constraint-cycle index at which this address was last accessed before now. The prover's permutation check verifies that for any address, the chain `… → prev_cycle_N → cycle_N → cycle_{N+1} = prev_cycle_{N+1} → …` is strictly increasing and consistent.

Mutating `prev_cycle` breaks the ordering invariant. The failure surface is the **permutation argument's temporal-ordering constraint**, which is structurally different from the value-ordering constraint that `prev_word` triggers.

#### Single strategy (no read/write split needed)

Unlike `prev_word`, the constraint surface for `prev_cycle` is the same regardless of whether the txn is a READ or WRITE — both rely on `prev_cycle` for ordering checks. A single strategy suffices.

#### Rust handler design

```rust
(Some("TXN_PREV_CYCLE_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"TXN_PREV_CYCLE_MOD", "step":S, "txn_idx":I, "prev_cycle":V}
    let txn_idx = extract_num("txn_idx");
    let new_pc = extract_num("prev_cycle");
    
    match (txn_idx, new_pc) {
        (Some(idx), Some(new_prev_cycle)) => {
            let idx = idx as usize;
            if idx >= trace.txns.len() {
                println!("<a4_error>{{...}}</a4_error>");
            } else {
                let txn = &mut trace.txns[idx];
                let old_prev_cycle = txn.prev_cycle;
                txn.prev_cycle = new_prev_cycle;
                
                println!("<a4_txn_prev_cycle_mod>{{\"step\":{},\"txn_idx\":{},\"addr\":{},\"old_prev_cycle\":{},\"new_prev_cycle\":{},\"cycle\":{},\"word\":{},\"prev_word\":{}}}</a4_txn_prev_cycle_mod>",
                    target_step, idx, txn.addr, old_prev_cycle, new_prev_cycle, txn.cycle, txn.word, txn.prev_word);
            }
        }
        _ => { /* error */ }
    }
}
```

#### Python module design

Mirror `comp_out_mod.py` (single strategy, single target per step). Target dataclass holds `step, cycle_idx, txn_idx, addr, original_prev_cycle, original_cycle (for context)`.

#### Value generation

`prev_cycle` is a `u32` but real values are bounded by `total_constraint_cycles` (typically ≪ 2^32). Mix:
- **35%** off-by-N from original: `±1, ±5, ±100` (tests "close-but-wrong" ordering — gets caught by strict-monotonic checks)
- **35%** bounded random in `[1, original_cycle - 1)` (where `original_cycle` is the txn's own `cycle` — i.e., a "valid range" wrong value)
- **30%** unbounded random `u32` (tests range checks for out-of-trace cycle indices)

Excluding 0 to avoid degenerate boot-link mutations. Excluding `cycle_n` itself (mutating prev_cycle to equal current cycle creates a self-pointer which is trivially invalid).

#### Valid steps

Any non-zero step; any txn.

#### Expected constraint failures

`MemoryWrite` and permutation-argument ordering constraints. Specifically, the temporal monotonicity check (`prev_cycle < cycle`) and the chain-link check (`prev_cycle` points to a real prior access).

---

### 3.3 B.3 — `CYCLE_MODE_MOD`

#### What it targets and why

`cycles[i].machine_mode: u8` is the privilege bit (0=user, 1=machine/kernel). The constraint system gates *which constraint family is active* per cycle based partly on this bit — in particular, ECALL/MRET transitions involve mode switches.

#### Scope (revised vs v0.2)

Taxonomy §3.14 says "Scope: Any cycle". My v0.2 §6 Q1 recommended restrictive (ECALL/MRET ±1 only). **Revised position: broad scope (any cycle).** Three reasons:

1. **Taxonomy authority**: The taxonomy was written by someone who studied the actual constraint surface and says "any cycle".
2. **Bandit will sort it out**: The `semantic_zone` field on each arm naturally clusters cycles by region; the bandit will discover empirically which zones surface failures, without us pre-filtering.
3. **No harm from broad scope**: The mutation is cheap (single bit flip) and witgen-safe (no crash risk).

#### Rust handler design

```rust
(Some("CYCLE_MODE_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"CYCLE_MODE_MOD", "step":S, "mode":0|1}
    let new_mode = extract_num("mode").map(|v| v as u8);
    
    if let Some(new_machine_mode) = new_mode {
        let mut found = false;
        for (cycle_idx, cycle) in trace.cycles.iter_mut().enumerate() {
            if cycle.user_cycle == target_step {
                let old_machine_mode = cycle.machine_mode;
                cycle.machine_mode = new_machine_mode;
                
                println!("<a4_cycle_mode_mod>{{\"step\":{},\"cycle_idx\":{},\"pc\":{},\"old_mode\":{},\"new_mode\":{},\"major\":{},\"minor\":{}}}</a4_cycle_mode_mod>",
                    target_step, cycle_idx, cycle.pc, old_machine_mode, new_machine_mode, cycle.major, cycle.minor);
                found = true;
                break;
            }
        }
        if !found { /* error */ }
    } else { /* error */ }
}
```

#### Python module design

Single-strategy, single-target-per-step pattern (like `instr_type_mod.py`). Target carries `step, cycle_idx, original_mode, major, minor`. Value generation is deterministic bit-flip (`1 - original_mode`); no RNG needed since the field is binary.

#### Valid steps

Any non-zero step where `data.get_cycle(step)` exists.

#### Expected constraint failures

Privilege/mode-check constraints. ECALL/MRET cycles are the high-signal zone. User-mode cycles where mode is flipped to kernel will fire mode-coherence checks at the next ECALL/MRET boundary.

#### Attestation outcome (Batch 2 — CONFIRMED, sha2-host user cycles)

**Status: W-17 dead arm (not W-16 soundness bug).** Trace mutates (Layers 2–4 pass); all four rejection channels silent; verifier accepts. Root cause: `set_cycle` presets `NEXT_MACHINE_MODE` from trace, then `step_Top` overwrites via `exec_Reg(inst_result.newMode, ...)` — witness never sees mutation. See [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md). Attestation: guard fires → assert → xfail.

**Qualification:** May be live on **paging cycles** via `extern_nextPagingIdx` reading trace directly — not tested in Batch 2 (step 1, major 0). W-1 revisit at D2.G still applies for zone-level failure rates.

**Spec correction:** `machine_mode` is not a binary privilege bit — preflight uses values 0–5 (page-in/out/suspend states). Handler restricts flips to `mode <= 1`.

---

### 3.4 B.4 — `TXN_ADDR_MOD` (HIGH RISK)

#### What it targets and why

`txns[i].addr: u32` is the **word address** of the memory access (byte_addr / 4). Address is the **identity key** for the permutation argument — the prover groups all txns at the same address into a chain and verifies the chain's internal consistency.

**Mutating `addr` is the most structurally aggressive D2.B kind.** Two simultaneous breakages happen:

1. The mutated txn now appears "at the wrong address" — its `word`, `prev_word`, `prev_cycle` no longer make sense for the new address.
2. The original-address chain now has a missing link (the txn that was supposed to be here isn't anymore), and the new-address chain has a spurious entry.

This is exactly why taxonomy §3.10 flags it as **Risk: High - may crash witness generation**.

#### Mitigation: `FAULT_INJECTION_ENABLED=1`

The dispatcher auto-sets this env var when `A4_MUTATION_CONFIG` is present (witgen line 224). It tells downstream code to skip throws on txn mismatches and produce constraint failures instead. **For TXN_ADDR_MOD this is essential** — without it, witgen would panic on `txn.addr` violations. The Python side doesn't need to do anything; the dispatcher already handles this.

#### Exclusions (critical to safety)

**Excluded:** instruction-fetch txns. Mutating the fetch address means the next cycle attempts to "execute" from random memory — virtually guaranteed to crash witgen even with fault injection.

**Recommended additional exclusion:** register transactions. The register address range is small (32 word addresses); a random `u32` for a register txn is almost certainly invalid. Within-register-range mutations could be a separate medium-risk kind in a future cycle.

**Net target set:** memory txns (non-register, non-instruction-fetch) at any step.

#### Rust handler design

```rust
(Some("TXN_ADDR_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"TXN_ADDR_MOD", "step":S, "txn_idx":I, "addr":V}
    let txn_idx = extract_num("txn_idx");
    let new_addr = extract_num("addr");
    
    match (txn_idx, new_addr) {
        (Some(idx), Some(new_a)) => {
            let idx = idx as usize;
            if idx >= trace.txns.len() {
                println!("<a4_error>{{...}}</a4_error>");
            } else {
                let txn = &mut trace.txns[idx];
                let old_addr = txn.addr;
                txn.addr = new_a;
                
                println!("<a4_txn_addr_mod>{{\"step\":{},\"txn_idx\":{},\"old_addr\":{},\"new_addr\":{},\"cycle\":{},\"word\":{},\"prev_cycle\":{},\"prev_word\":{}}}</a4_txn_addr_mod>",
                    target_step, idx, old_addr, new_a, txn.cycle, txn.word, txn.prev_cycle, txn.prev_word);
            }
        }
        _ => { /* error */ }
    }
}
```

#### Value generation

Three strategies (Composer's `generate_new_value`):

- **40% "same-region nudge"**: `original_addr + rng.choice([-4, -2, -1, 1, 2, 4, 8, -8])`. Tests off-by-N address bugs; usually stays within the same memory region.
- **30% "same-major redirect"**: pick another valid memory word-addr from the same step's other memory txns. Tests "consistent shape but wrong target" — chain still links to a real address, just the wrong one.
- **30% "wild random"**: random `u32`. Tests range checks and out-of-bounds handling.

#### Valid steps

Steps where `get_mem_txns_at_step(step)` returns at least one non-fetch memory txn.

#### Expected constraint failures

Memory addressing constraints + permutation chain breakage + possibly paging-table mismatch. May produce many failures per single mutation due to cascade through downstream same-address txns.

**Attestation outcome (Batch 3 — CONFIRMED dead arm via W-18):** Trace `addr` mutates (Layers 2–4 pass); all four rejection channels silent; verifier accepts. Root cause: witness address columns bind to execution-derived `addrElem` passed to `GetMemoryTxn`, not trace `txn.addr`. `extern_getMemoryTxn` compares trace addr but returns only prevCycle/prevWord/word. `FAULT_INJECTION_ENABLED` suppresses sanity throws, not Hook 3. Full proof: [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md). Attestation: guard fires → assert → xfail.

---

### 3.5 B.5 — `TXN_CYCLE_PHASE_MOD`

#### What it targets and why

`txns[i].cycle: u32` is the **constraint-cycle index** of this txn (not to be confused with `cycles[i].user_cycle` which is the user-visible step counter). The LSB of `txn.cycle` encodes the read/write phase:

- `cycle & 1 == 0` → READ transaction (even cycle)
- `cycle & 1 == 1` → WRITE transaction (odd cycle)

(This is documented in taxonomy §2.3 and confirmed in `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` line 486-487 which has `let is_read = txn.cycle % 2 == 0;`.)

**The mutation flips ONLY the LSB**: `txn.cycle ^= 1`. This toggles the read/write classification while keeping the cycle in the same constraint-cycle ordering position. It's a surgical phase swap, not a reordering.

#### Why XOR, not random?

A general "set txn.cycle to any u32" mutation would reorder the txn in the permutation argument — that's a structurally different (and far higher-risk) operation that we'd want as a separate kind (potentially TXN_CYCLE_REORDER_MOD in a future cycle). For D2.B, we keep `TXN_CYCLE_PHASE_MOD` scoped to phase-flip semantics only. This matches Pro's intent (§15 "TXN_CYCLE_PHASE_MOD" name) and keeps the kind safely-bounded.

#### Rust handler design

```rust
(Some("TXN_CYCLE_PHASE_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"TXN_CYCLE_PHASE_MOD", "step":S, "txn_idx":I}
    // NOTE: no value field — we always XOR with 1.
    let txn_idx = extract_num("txn_idx");
    
    match txn_idx {
        Some(idx) => {
            let idx = idx as usize;
            if idx >= trace.txns.len() {
                println!("<a4_error>{{...}}</a4_error>");
            } else {
                let txn = &mut trace.txns[idx];
                let old_cycle = txn.cycle;
                let new_cycle = old_cycle ^ 1;
                txn.cycle = new_cycle;
                
                let old_phase = if old_cycle % 2 == 0 { "READ" } else { "WRITE" };
                let new_phase = if new_cycle % 2 == 0 { "READ" } else { "WRITE" };
                
                println!("<a4_txn_cycle_phase_mod>{{\"step\":{},\"txn_idx\":{},\"addr\":{},\"old_cycle\":{},\"new_cycle\":{},\"old_phase\":\"{}\",\"new_phase\":\"{}\",\"word\":{},\"prev_word\":{}}}</a4_txn_cycle_phase_mod>",
                    target_step, idx, txn.addr, old_cycle, new_cycle, old_phase, new_phase, txn.word, txn.prev_word);
            }
        }
        None => { /* error */ }
    }
}
```

Note: this handler is **value-less** (no `new_value` in config). The mutation is deterministic: flip the LSB.

#### Python module design

Target dataclass: `step, cycle_idx, txn_idx, addr, original_cycle, original_phase ("READ"/"WRITE"), word, prev_word`. No `generate_new_value` (deterministic flip). `create_config` writes JSON without a value field.

#### Exclusions

- **Instruction-fetch txns**: Flipping a fetch from READ→WRITE is meaningless (instruction fetches are always reads); the constraint fires immediately but the mutation produces no novel coverage. *Recommended exclusion to keep arm space focused.* (Q-new — see §6.)

#### Expected constraint failures

- `IsRead` constraint fires for any txn that was originally a READ and now classified as WRITE (because `word == prev_word` may not hold)
- The classification constraint that determines which constraint family applies fires
- Possibly cascade if a downstream txn's `prev_cycle` pointed at this txn (its phase has effectively changed)

**Attestation outcome (Batch 3 — CONFIRMED dead arm via W-18):** Trace `cycle` LSB mutates; all channels silent; verifier accepts. Root cause: read/write phase encoded in execution-derived `memCycle` (`MemoryRead` → `2*cycle`, `MemoryWrite` → `2*cycle+1`), not trace `txn.cycle` LSB. `getMemoryTxn` returns prevCycle/prevWord/word only. Full proof: [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md). Attestation: guard fires → assert → xfail.

---

### 3.6 B.6 — `CYCLE_PC_MOD`

#### What it targets and why

`cycles[i].pc: u32` is the **NEXT PC** after the cycle executes (per taxonomy §1.2: "NEXT PC after execution"). For instruction cycles, this drives the fetch address of the *next* cycle (`fetch_addr = (next_pc - 4) / 4`).

Mutating PC at cycle N has two effects:

1. The current cycle's PC-vs-instruction-class consistency check fires (the constraint that ensures `pc` matches the kind of instruction recorded as `major`/`minor` at this cycle).
2. The next cycle's fetch-address derivation now points to a different instruction word than what's recorded in `trace.txns[next_cycle.txn_idx]` — fires the fetch-coherence constraint.

#### Scope: instruction cycles only

Taxonomy §3.12 says "Scope: Instruction cycles (major 0-6)". This makes sense because non-instruction cycles (CONTROL, ECALL, Poseidon, SHA, BigInt) don't necessarily have a PC-coherence constraint in the same way. Restricting to major 0-6 keeps the failure semantics clean.

#### Rust handler design

```rust
(Some("CYCLE_PC_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"CYCLE_PC_MOD", "step":S, "pc":V}
    let new_pc = extract_num("pc");
    
    if let Some(new_p) = new_pc {
        let mut found = false;
        for (cycle_idx, cycle) in trace.cycles.iter_mut().enumerate() {
            if cycle.user_cycle == target_step && cycle.major <= 6 {
                let old_pc = cycle.pc;
                cycle.pc = new_p;
                
                println!("<a4_cycle_pc_mod>{{\"step\":{},\"cycle_idx\":{},\"old_pc\":{},\"new_pc\":{},\"major\":{},\"minor\":{},\"machine_mode\":{}}}</a4_cycle_pc_mod>",
                    target_step, cycle_idx, old_pc, new_p, cycle.major, cycle.minor, cycle.machine_mode);
                found = true;
                break;
            }
        }
        if !found { /* error: not an instruction cycle */ }
    } else { /* error */ }
}
```

#### Python module design

Same pattern as `instr_type_mod.py` (cycle-level mutation, single target per step, major-filtered).

#### Value generation

- **40% nearby**: `original_pc + rng.choice([-12, -8, -4, 4, 8, 12])` — small PC drift; tests off-by-instruction bugs.
- **30% jump-target-style**: `original_pc + rng.choice([-1024, -512, 256, 512, 1024])` — simulates "what if a branch went elsewhere"; still 4-byte aligned (constraint: `new_pc % 4 == 0`).
- **30% random**: random `u32` with 4-byte alignment.

#### Expected constraint failures (pre-audit design intent)

PC-coherence constraint at cycle N; fetch-coherence at cycle N+1.

#### Attestation expectation (Batch 3 — **PREDICTED DEAD**, sha2-host user cycles)

**Same W-17 mechanism as B.3:** `cycle.pc` is preset via `set_cycle` (`witgen/mod.rs:1071-1072`) but overwritten by `exec_Reg(inst_result.newPc, ...)` at `steps.cpp:14739-14740`. Original taxonomy expected PC/fetch constraints to fire — that assumed trace `pc` reaches witness. **Batch 3 attestation MUST verify dead-arm pattern** (guard fires, verifier accepts) or **reconcile audit** if any rejection channel fires.

Attestation template: mirror B.3 (`test_d2b_cycle_mode_mod_attestation.py`). See plan **§6d** and **W-17**.

---

### 3.7 B.7 — `CYCLE_STATE_MOD`

#### What it targets and why

`cycles[i].state: u32` is the **cycle-state enum** (taxonomy Appendix A; from `platform.rs::CycleState`). Examples: `Decode=48`, `PoseidonEntry=16`, `ShaEcall=32`, `BigIntEcall=40`, etc. The state value determines which constraint family is active at this cycle.

Mutating state to a different valid state value tests "wrong constraint family active" — e.g., a Decode cycle masquerading as a Poseidon cycle. Mutating to a random `u32` tests range checks.

#### Value generation

The state enum has known valid values (Appendix A in taxonomy). Composer Batch 1 should extract the full enum from `workspace/risc0-modified/risc0/circuit/rv32im/src/execute/platform.rs` (or wherever `CycleState` lives) — taxonomy Appendix A is incomplete (has `...`).

- **50% valid-but-different state**: pick from the valid enum, excluding `original_state`. Tests cross-state constraint mismatches.
- **30% adjacent invalid**: `original_state ± rng.choice([1, 2, 3])` — tests "off-by-N in state enum".
- **20% wild random**: random `u32`. Tests range checks.

#### Rust handler design

```rust
(Some("CYCLE_STATE_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"CYCLE_STATE_MOD", "step":S, "state":V}
    let new_state = extract_num("state");
    
    if let Some(new_s) = new_state {
        let mut found = false;
        for (cycle_idx, cycle) in trace.cycles.iter_mut().enumerate() {
            if cycle.user_cycle == target_step {
                let old_state = cycle.state;
                cycle.state = new_s;
                
                println!("<a4_cycle_state_mod>{{\"step\":{},\"cycle_idx\":{},\"pc\":{},\"old_state\":{},\"new_state\":{},\"major\":{},\"minor\":{}}}</a4_cycle_state_mod>",
                    target_step, cycle_idx, cycle.pc, old_state, new_s, cycle.major, cycle.minor);
                found = true;
                break;
            }
        }
        if !found { /* error */ }
    } else { /* error */ }
}
```

#### Scope

Any cycle (per taxonomy §3.13), except step 0.

#### Expected constraint failures (pre-audit design intent)

Cycle-state-machine constraints. The exact constraint depends on what `original_state → new_state` transition we mutated to. Composer's per-kind report should include a table of common (original, mutated) pairs and the constraints they trigger.

#### Attestation expectation (Batch 3 — **PREDICTED DEAD**, sha2-host user cycles)

**Same W-17 mechanism as B.3:** `cycle.state` preset via `set_cycle` (`witgen/mod.rs:1073`) overwritten by `exec_Reg(inst_result.newState, ...)` at `steps.cpp:14743`. Batch 1.0b tentatively expected state transitions might drive witness layout — **Batch 2 audit found no extern-read path for `cycle.state`**; overwrite model predicts dead arm. Batch 3 attestation confirms or **forces audit reconciliation**.

Attestation template: mirror B.3. See plan **§6d** and **W-17**.

---

### 3.8 B.8 — `CYCLE_DIFF_COUNT_MOD`

#### What it targets and why

**Important correction from v0.2:** `cycles[i].diff_count` is `[u32; 2]` — an **ARRAY of two u32 values**, not a single field. Taxonomy §1.2 line: `pub diff_count: [u32; 2]`.

The diff_count array tracks **memory-diff state** used in memory-permutation accounting. The two elements are conceptually a paired counter; we don't know the exact constraint semantics without deeper Rust inspection. Composer Batch 1 should investigate.

#### Mutation strategy: one element at a time

Two design options:
- **(A) Mutate one element** at config-specified `index ∈ {0, 1}`. The other element stays untouched.
- **(B) Mutate both** with paired values.

**Recommended: (A) Mutate one element at a time.** Reasons:
- Cleaner failure surface (we know exactly which counter we touched)
- Layer 3 dump-diff is easier (only one position in the array changed)
- If both-element mutation turns out interesting later, add a separate `CYCLE_DIFF_COUNT_PAIR_MOD` kind

The Python side picks `index` randomly per mutation; both are eligible.

#### Rust handler design

```rust
(Some("CYCLE_DIFF_COUNT_MOD"), Some(target_step)) => {
    // Config: {"mutation_type":"CYCLE_DIFF_COUNT_MOD", "step":S, "index":0|1, "diff_count":V}
    let index = extract_num("index");
    let new_value = extract_num("diff_count");
    
    match (index, new_value) {
        (Some(idx), Some(new_v)) => {
            if idx > 1 {
                println!("<a4_error>{{\"error\":\"index must be 0 or 1\", \"got\":{}}}</a4_error>", idx);
            } else {
                let mut found = false;
                for (cycle_idx, cycle) in trace.cycles.iter_mut().enumerate() {
                    if cycle.user_cycle == target_step {
                        let old_value = cycle.diff_count[idx as usize];
                        cycle.diff_count[idx as usize] = new_v;
                        
                        println!("<a4_cycle_diff_count_mod>{{\"step\":{},\"cycle_idx\":{},\"index\":{},\"old_value\":{},\"new_value\":{},\"other_value\":{},\"major\":{},\"minor\":{}}}</a4_cycle_diff_count_mod>",
                            target_step, cycle_idx, idx, old_value, new_v,
                            cycle.diff_count[1 - idx as usize], cycle.major, cycle.minor);
                        found = true;
                        break;
                    }
                }
                if !found { /* error */ }
            }
        }
        _ => { /* error */ }
    }
}
```

#### Value generation

diff_count values are typically small (memory access counts). Mix:
- **60% off-by-N**: `original ± rng.choice([1, 2, 3, 5, 10])`. Tests "miscount" semantics.
- **40% random small**: `rng.randint(0, 1000)`. Tests range / bounded-count constraints.

Avoid very large `u32` values unless we explicitly want to test overflow checks.

#### Scope

Any cycle (per taxonomy §3.13), except step 0.

#### Expected constraint failures

Memory diff-tracking constraints. Composer Batch 1 should locate the constraints that use `diff_count` in the Rust circuit code (likely in `risc0/circuit/rv32im/src/circuit/*.rs` or the zir/circom source). If the field cannot be located in any constraint, **B.8 is dropped** (Q-new).

---

## 4. Detailed change list (file by file)

### 4.1 Rust changes — `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`

Add **8 new match arms** to the unified A4 dispatcher (between the existing MEM_VAL_MOD handler at line 588 and the fallback error at line 589). Each handler follows the pattern documented in §3 above. Average ~50–80 LOC per handler.

The dispatcher's helpers (`extract_str`, `extract_num` at lines 230–253) already cover all the JSON parsing we need. No infrastructure changes.

**Note (revised v0.4 per Composer review):** Rust handlers land **per batch** (one or more per commit, following the Batch 1/2/3/4 structure in §7) — *not* all 8 at once. The original "one commit" claim contradicted the incremental batch plan. Each batch adds its Rust handlers + Python plumbing + attestation tests in a single landmark commit, so `git log` reads as "D2.B Batch N — kinds X, Y" rather than "all 8 Rust handlers" / "all 8 Python modules" as separate commits.

### 4.2 Rust build + binary deploy

Per existing risc0 build process (Composer Batch 1 confirms exact command):

```
cd workspace/risc0-modified
cargo build --release -p risc0-circuit-rv32im  # or whichever package owns mod.rs
# locate new binary at target/release/<host_binary_name>
cp target/release/<binary> <path the Python harness expects>
```

Smoke check existing kinds still work by running one COMP_OUT_MOD mutation against the new binary and verifying the `<a4_comp_out_mod>` tag still emits.

### 4.3 Python modules — 8 new files in `a4/standalone/mutations/`

| Kind | File | Pattern source |
|---|---|---|
| B.1 | `txn_prev_word_mod.py` | `pre_exec_reg_mod.py` (two-strategy structure) |
| B.2 | `txn_prev_cycle_mod.py` | `comp_out_mod.py` (single-target-per-step) |
| B.3 | `cycle_mode_mod.py` | `instr_type_mod.py` (cycle-level mutation) |
| B.4 | `txn_addr_mod.py` | `mem_val_mod.py` (with txn-type exclusions) |
| B.5 | `txn_cycle_phase_mod.py` | `instr_type_mod.py` (deterministic flip, no value gen) |
| B.6 | `cycle_pc_mod.py` | `instr_type_mod.py` (major 0–6 only) |
| B.7 | `cycle_state_mod.py` | `instr_type_mod.py` (cycle-level) |
| B.8 | `cycle_diff_count_mod.py` | `instr_type_mod.py` (with array-index field) |

Each follows the documented §3 design with specific `get_targets_at_step`, `get_all_targets`, `generate_new_value`, `create_config` signatures.

### 4.4 `a4/core/inspection_data.py` (CRITICAL — added in v0.4 per Composer review)

**This file was missing from v0.3 — without these additions, new kinds get ZERO arms.**

`SemanticArmUniverse.build()` at line 207 calls `data.get_valid_steps_for_kind(kind)` for every mutation kind in the registry. This function (lines 147–215 of `inspection_data.py`) is an if/elif chain that currently only handles the 8 existing kinds; for any new kind the chain falls through and returns `[]`. New arms with empty step sets are skipped — so without an extension, all 8 D2.B kinds quietly have zero arms in the universe even with Python modules + Rust handlers + fuzzer dispatch in place.

**Required changes:** add 8 new branches to `get_valid_steps_for_kind` covering:

| Kind | Branch logic |
|---|---|
| `TXN_PREV_WORD_MOD` | All steps with at least one txn (i.e., `cycle.step in data._step_to_all_txns`). No major filter; both reads and writes are valid. |
| `TXN_PREV_CYCLE_MOD` | Same as `TXN_PREV_WORD_MOD` |
| `TXN_ADDR_MOD` | Steps with at least one **memory** txn (`cycle.step in data._step_to_mem_txns`), per §3.4 exclusion of register + fetch txns |
| `TXN_CYCLE_PHASE_MOD` | All steps with non-fetch txns (per §3.5 exclusion) |
| `CYCLE_MODE_MOD` | Any cycle except step 0 (per §3.3 broad scope) |
| `CYCLE_PC_MOD` | `cycle.major <= 6` (instruction cycles only, per §3.6) |
| `CYCLE_STATE_MOD` | Any cycle except step 0 (per §3.7) |
| `CYCLE_DIFF_COUNT_MOD` | Any cycle except step 0 (per §3.8) |

The "step 0" exclusion applies to all 8 (bootloader cycles, ~16k entries, almost universally excluded by existing kinds).

### 4.5 `a4/standalone/semantic_arm_universe.py`

- Import the 8 new modules
- Add 8 entries to `_MUTATION_MODULES` dict
- Add 8 branches to `_cycle_matches_kind_filter()` (per-kind valid-cycle predicate from §3)
- **`_MAJOR_FILTER_KINDS` (per-kind decision, NOT blanket-add per Composer review):**
  - The existing set holds only kinds with a `cycle.major` predicate. `MEM_VAL_MOD` is *explicitly excluded* (line 83 comment: "MEM_VAL_MOD has no major filter").
  - **Add: `CYCLE_PC_MOD` only.** It's the only D2.B kind with a strict cycle-major filter (`major <= 6`).
  - **Do NOT add: B.1, B.2, B.4, B.5** (txn-based kinds; follow MEM_VAL_MOD pattern with txn-presence filters instead).
  - **Do NOT add: B.3, B.7, B.8** (cycle-based with broad/any-cycle scope; no major-filter membership needed).

### 4.6 `a4/standalone/fuzzer.py`

- Add 8 entries to `MUTATION_KINDS` constant
- Add 8 branches to `_create_mutation(kind, step)` dispatch
- **No changes** to `_run_v2_bandit_mutation`, `_run_single_mutation`, `record_mutation` — D2.B kinds flow through existing infrastructure

### 4.7 `a4/standalone/compressed_global_extractor.py`

**REVISED v0.4 per Composer review.** v0.2/v0.3 proposed field-name role labels (`mode`, `addr`, `phase`, `pc`, `state`, `diff_count`) — these would violate `MEMORY_TXN_ROLES` (the 6-tuple at `compressed_global.py:52-54`) and break `test_compressed_global_extractor.py` lines 152 and 480 which assert role ∈ `MEMORY_TXN_ROLES`. See Q5 in §6 for the decision rationale.

**Critical heads-up for Composer (added v0.5 — NFP-10 awareness):** This file recently received the **`_coerce_broken_addr` byte_addr field-priority fix** at line 216 (commit `71dae77`, per NFP-10 in `IV_POS_8_NOTES_FOR_PRO.md`). The field-priority tuple is now `("byte_addr", "addr", "address")` — byte_addr FIRST. **DO NOT REVERT THIS.** D2.B's edits are strictly additive on `_TXN_ROLE_BY_KIND` (around line 161); the byte_addr fix lives in a different function and must remain untouched. Sanity-check before committing: `rg 'byte_addr.*addr.*address' compressed_global_extractor.py` should still hit line 216.

**Two locking options for Q5:**

- **Option A (recommended — Composer-aligned):** Map all 8 to Pro-valid roles. Per-kind attribution comes from `producer_kind` (the full mutation kind string, already in `GLOBAL_LOOKUP` schema — see `compressed_global.py:41`), so we don't lose information.

  ```python
  # Memory-txn-targeting kinds (Pro reserved these specifically):
  "TXN_PREV_WORD_MOD":    "prev_word",
  "TXN_PREV_CYCLE_MOD":   "prev_cycle",
  # Address-mutating txn kind — read/write determined dynamically per-target
  # via target txn parity (txn.cycle % 2 == 0); needs a small dispatch helper
  # since _TXN_ROLE_BY_KIND is a static dict. Default to "read"; runtime
  # override when emitting context.
  "TXN_ADDR_MOD":         "read",
  # Phase-flip is always on read txns (fetch excluded per Q14)
  "TXN_CYCLE_PHASE_MOD":  "read",
  # Cycle-meta kinds — no transaction-targeting; use "read" default per existing
  # convention for non-txn-targeting kinds
  "CYCLE_MODE_MOD":       "read",
  "CYCLE_PC_MOD":         "read",
  "CYCLE_STATE_MOD":      "read",
  "CYCLE_DIFF_COUNT_MOD": "read",
  ```

- **Option B (defer for coordination with Pro):** Extend `MEMORY_TXN_ROLES` with a new `"cycle_meta"` role, update Pro's schema, and use field-name labels for the cycle-targeting kinds. **More accurate** for D2.G analysis (cycle-meta failures don't look like memory-read failures), but requires a Pro schema change which is out-of-scope for D2.B.

### 4.8 Tests (18 new files)

Per-kind test files following the 5-layer methodology (§5 below):

- 8 × `tests/test_d2b_<kind>_unit.py` (Layer 1, no binary)
- 8 × `tests/test_d2b_<kind>_attestation.py` (Layers 2 + 3 + 4, real binary, gated)
- 1 × `tests/test_d2b_arm_registration.py` (cross-cutting Layer 1)
- 1 × `tests/test_d2b_campaign_smoke.py` (Layer 5, mocked binary)

Total tests: 510 (D2.A baseline) + ~18 new logical tests across these files = ~528+ tests green.

### 4.9 Files that **must not change** in D2.B

- `a4/standalone/bandit_ts.py` (D2.A foundation)
- `a4/standalone/coverage_db.py` (D2.A schema)
- `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (D2.C)
- `a4/standalone/cli.py` (D2.D)
- Existing 8 `a4/standalone/mutations/*.py` (untouched)
- The existing 7 Rust handlers in `witgen/mod.rs` (we add new arms, don't modify existing ones)
- `a4/docs/standalone/MUTATION_TAXONOMY.md` (taxonomy is authoritative; spec defers to it)

## 5. Testing methodology (the 100%-certainty stack)

This section is **identical in structure to v0.2 §1.5** but updated to reflect per-kind nuances. The core idea is unchanged: **two independent witnesses agreeing about the same event, plus a side-effect check that nothing else changed = 100% certainty.**

### 5.1 The 5 layers

| Layer | Asserts | Real binary? | When |
|---|---|---|---|
| **1** Python unit test | Module writes valid config JSON; target selection works on synthetic InspectionData | No | Per-kind unit test |
| **2** Rust handler attestation | The Rust handler emits `<a4_<kind>>` tag with `old_value`, `new_value`, target locator; the binary directly attests what it did | **Yes** | Per-kind gate |
| **3** Trace-diff verification | Dump trace before + after; assert exactly the targeted field at the targeted index changed | **Yes** | Per-kind gate (with risk-tiered strictness — see 5.2) |
| **4** Cross-check (certainty) | Layer 2's tag and Layer 3's diff **agree** on what changed | **Yes** | Per-kind gate (load-bearing) |
| **5** Campaign smoke (N=50) | When wired into fuzzer, kind appears in DB with outcome populated | Mocked / Real (both) | Final cross-cutting batch |

### 5.2 Risk-tiered Layer 3 strictness (new in v0.3)

For low-risk kinds (B.1 `at_read`, B.1 `at_write`, B.2, B.3), Layer 3 is **strict**: assert exactly *one* field at *one* index changed, *no other diff* anywhere in the trace.

For medium/high-risk kinds (B.4, B.5, B.6, B.7, B.8), Layer 3 is **risk-tiered**:
- The targeted field MUST have changed at the targeted index to the targeted value
- *Cascading changes* in downstream txns/cycles that are explained by the mutation (e.g., TXN_ADDR_MOD breaks the permutation chain, so downstream same-address txns may have different observed states post-mutation) are *permitted* and **logged**
- Pure-noise diffs (changes in unrelated cycles, e.g., metadata fields on an unrelated cycle 200 rows away) are NOT permitted

The cascading-changes log is included in the attestation test output for human review. If a kind shows *more* cascade than expected, the kind's design gets revisited.

### 5.3 Per-kind expected cascade signatures

| Kind | Expected cascade |
|---|---|
| B.1 `at_read` | Strict-no-cascade in trace |
| B.1 `at_write` | Strict-no-cascade in trace (constraint cascade = IsRead/permutation failure at witness time, not a post-mut trace diff) |
| B.2 | Strict-no-cascade in trace (constraint cascade = downstream `prev_cycle` chain failure at witness time, not a post-mut trace diff) |
| B.3 | Strict-no-cascade in trace | **CONFIRMED dead arm** (W-17) on sha2-host user cycles — witness overwrite, not trace no-op |
| B.4 | Strict-no-cascade in trace (Rust handler touches `addr` only) | **CONFIRMED dead arm (W-18)** — witness addr execution-derived; see §3.4 |
| B.5 | Strict-no-cascade in trace | **CONFIRMED dead arm (W-18)** — witness phase execution-derived; see §3.5 |
| B.6 | Likely cascade at witness time if trace pc reached constraints — **superseded by W-17 audit** | **PREDICTED DEAD** (set_cycle overwrite) — see §5.4 |
| B.7 | Tentatively strict-no-cascade in trace — witness layout interaction TBD | **PREDICTED DEAD** (set_cycle overwrite) — see §5.4 |
| B.8 | Strict-no-cascade in trace | **Predicted LIVE** (`extern_getDiffCount` reads trace) — W-3 drop only if dead proven |

Composer's per-kind attestation test asserts cascade shape matches the expected signature.

### 5.4 Batch 3 attestation outcomes — W-17 + W-18 dead-arm classes (updated v0.5.4)

**Locked before Batch 3 implementation** (v0.5.3 predictions); **updated with Batch 3 empirical + audit results.** Authoritative proofs: [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md) (W-17), [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md) (W-18). Plan mirror: [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) §6d + W-17/W-18.

| Kind | v0.5.3 prediction | **Batch 3 actual outcome** |
|------|-------------------|---------------------------|
| B.4 `TXN_ADDR_MOD` | LIVE — C2/C3 `memory` | **DEAD (W-18)** — guard + xfail; audit proves execution-derived addr |
| B.5 `TXN_CYCLE_PHASE_MOD` | LIVE — C2/C3 | **DEAD (W-18)** — guard + xfail; audit proves execution-derived memCycle |
| B.6 `CYCLE_PC_MOD` | PREDICTED DEAD (W-17) | **CONFIRMED DEAD (W-17)** — guard + xfail |
| B.7 `CYCLE_STATE_MOD` | PREDICTED DEAD (W-17) | **CONFIRMED DEAD (W-17)** — guard + xfail |
| B.8 `CYCLE_DIFF_COUNT_MOD` | PREDICTED LIVE | **CONFIRMED LIVE** — `cycle` Hook 3 family |

**Reconciliation rule:** Any confirmed-dead kind that shows live rejection means the corresponding audit (W-17 or W-18) is incomplete — stop, trace witgen path, update audit before proceeding.

**Dead-arm attestation pattern:** Layers 2–4 pass → call `check_soundness_bug_guard` → assert `SoundnessBugSuspected` → `pytest.xfail()` with W-17 or W-18 rationale + audit cross-ref.

### 5.5 D2.B postscript — dead-arm cleanup (added v0.5.3 patch)

Two postscript tasks tracked in plan §9c:

- **D2.B-PS-1** (runs post-Batch-4): remove confirmed-dead kinds from `A4Fuzzer.MUTATION_KINDS`, invert 2–3 unit-test asserts, add NFP entry. Architectural decision: registry exclusion via absence, no runtime filter logic (W-17b).
- **D2.B-PS-2** (optional, post-D2.G): may **fully delete** all dead-arm code (Python modules, Rust handlers, attestation tests, dispatch entries) if the maintenance cost outweighs the continuous-verification benefit. Git history preserves recovery path; W-17 mechanism documentation stays in plan + Notes-for-Pro. Single explicit commit with cross-refs. **Status: TBD, post-D2.G.**

## 6. Open questions — ALL RESOLVED (Ivan locked 2026-06-17)

Each question is now stamped with **LOCKED:** at the top showing Ivan's final decision. The "My recommendation / Why / Counterfactual" content below each lock is preserved for traceability (it's the reasoning that fed the decision).

**Summary of all 17 locks lives in [§8 Decisions Confirmed](#8-decisions-confirmed).**

The v0.2 list (10 questions) is preserved; new questions discovered during the v0.3 deep-dive are appended (Q11–Q16); Q17 added in v0.4 (Layer 3 infrastructure spike).

### Q1 — `CYCLE_MODE_MOD` scope: every cycle or only at ECALL/MRET boundaries?

**LOCKED (Ivan 2026-06-17): Broad scope — any cycle.** Watchlist W-1 tracks D2.G revisit if <1% failure rate outside boundary zones.

**Plain question:** Should we mutate `machine_mode` on every cycle, or only on cycles near ECALL/MRET (where the mode actually changes in real execution)?

**My recommendation (REVISED from v0.2):** **Broad scope — any cycle.**

**Why (revised):**
- Taxonomy §3.14 explicitly says "Scope: Any cycle"
- The bandit's `semantic_zone` field clusters cycles by region; the cTS scheduler will naturally learn which zones surface failures, without us pre-filtering
- The mutation is cheap (single bit flip) and witgen-safe
- v0.2's restrictive recommendation was a pre-optimization that contradicted the authoritative taxonomy

**If you pick differently:** Restrictive (ECALL/MRET ±1) shrinks the arm-space ~10× but loses the bandit's discovery ability. We can always restrict in D3 if data shows broad scope is wasteful.

### Q2 — Value generation distribution for "nearby + random" kinds

**LOCKED (Ivan 2026-06-17): §3 percentages as starting heuristics; D2.G retunes from DB `outcome` column without spec revision.** Watchlist W-2.

**Plain question:** For kinds where the value-generation is "nearby vs random" (B.1, B.2, B.4, B.6, B.7, B.8), what's the right split?

**My recommendation:** **Per-kind mixes documented in §3** — 33/33/34 for B.1, 35/35/30 for B.2, 40/30/30 for B.4 and B.6, 50/30/20 for B.7, 60/40 for B.8. These are calibrated per-kind to the structure of the field's value space (e.g., diff_counts are small, so we lean nearby; addresses span a large range, so more random).

**Why:** Pure random for some fields wastes mutations on obviously-invalid values that the prover rejects without producing useful coverage signal. Pure nearby for other fields misses range-check bugs. The mix is calibrated to maximize "interesting failure rate" per kind.

**If you pick differently:** Composer can override per-kind during Batch 1; the §3 percentages are starting points, not fixed.

### Q3 — Does `CYCLE_DIFF_COUNT_MOD` (B.8) ship? (REVISED v0.4 — lean ship)

**LOCKED (Ivan 2026-06-17): Lean ship.** Batch 1.0b investigates with 3-way classification (constraint_fail / ERROR / clean-success). Clean-success rows MUST be cross-verified with `A4_DUMP_POST_MUT` per §9b soundness guard before any drop classification. Watchlist W-3.

**Plain question:** B.8's field is `[u32; 2]` (array of 2), and v0.3 wasn't sure whether any constraint family actually USES diff_count. Updated evidence below.

**Updated v0.4 evidence (from Composer review):**
- `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs` lines 227 and 306 actively increment `cycles[i].diff_count[idx]` during trace construction (tracking memory-access gaps).
- The field is initialized at line 397 (`diff_count: [0, 0]`) and accumulated under specific memory-permutation conditions.
- zirgen calls `get_diff_count(...)` on each cycle (verified via grep on the zirgen circuit code) → the field is **live data**, not dead.

So B.8 has a working downstream consumer. The remaining unknown is whether mutating it triggers a *distinct* constraint failure (vs. cascading through the memory permutation argument), but that's a "what failures look like" question, not a "should we ship" question.

**My recommendation (v0.4):** **Lean ship — Composer Batch 1.0b confirms exactly which constraint family observes diff_count via grep on zirgen + a single B.8 smoke run.** Drop only if Batch 1.0b empirically shows zero useful signal across 5 sample mutations.

**Refinement per Composer review + Ivan soundness-guard:** "Useful signal" means classifying outcomes into three buckets — but **clean-success requires post-mut dump verification before drop** (per `IV_POS_8_D2_PLAN.md` §9b soundness-bug guard):
1. `<constraint_fail>` emitted with diff_count-related constraint name → ship as productive arm
2. `outcome=ERROR` (witgen crash, FAULT_INJECTION_ENABLED can't recover) → ship anyway IF rate is low (~<20%); drop if dominant
3. **Clean success** → **must verify trace actually changed via `A4_DUMP_POST_MUT=1` diff** before classifying:
   - **Dead arm** (trace changed but no constraint observes diff_count) → drop
   - **Silent skip** (trace did NOT change despite `applied` tag) → bug in dispatcher emission; investigate
   - **Soundness bug suspected** (trace changed, no constraint failed, no error) → STOP and surface to Pro per §9b

Batch 1.0b reports a 3-way classification table over 5 mutations per (zone, value-strategy) combo, with the additional post-mut-dump verification column for the clean-success rows.

**Why:**
- Field is verifiably live; pre-commit-dropping a Pro-listed medium-risk kind without empirical evidence is overcautious.
- ~2 hours of Batch 1.0b investigation either confirms ship-with-known-failure-mode or surfaces a real reason to drop.

**If you pick differently:** "Always ship without verification" risks B.8 producing zero constraint failures (silent dead arm); "drop without checking" loses a kind Pro explicitly named.

### Q4 — How do we run the 100%-certainty tests (Layers 2/3/4) in CI?

**LOCKED (Ivan 2026-06-17): Per-batch landing gate via `A4_REAL_BINARY=1`.** Composer runs locally before each batch commit. No CI binary infra in D2.B.

**Plain question:** Real-binary tests are slow (~5–10s per invocation × 8 kinds × multiple test cases ≈ 3–5 minutes). Every PR or on demand?

**My recommendation:** **Per-kind gate at landing time (not every PR), via `A4_REAL_BINARY=1` env var.** Composer runs them before committing each batch.

**Why:** Solo dev (Ivan), no CI binary infra yet, manual landing already requires Composer reports.

**If you pick differently:** Every-PR requires CI binary setup (potentially worth doing in D2.E or later).

### Q5 — CGC role mappings (§4.7) — REVISED v0.4 per Composer pushback

**LOCKED (Ivan 2026-06-17 via AskQuestion): Option A — Pro-valid `MEMORY_TXN_ROLES` only; per-kind D2.G via `producer_kind`.** Schema bump to add `cycle_meta` deferred to IV.POS.9 if Pro requests it in D2.G review. **Surfaced as NFP-4 in `IV_POS_8_NOTES_FOR_PRO.md` so Pro sees it explicitly.** Watchlist W-4.

**Plain question:** What `txn_role` label do we use for each new kind in the `_TXN_ROLE_BY_KIND` dict?

**v0.3 was wrong:** v0.3 proposed field-name labels (`mode`, `addr`, `phase`, `pc`, `state`, `diff_count`). These violate `MEMORY_TXN_ROLES` (the 6-tuple at `compressed_global.py:52-54`) and would break existing tests:
- `test_compressed_global_extractor.py:152` — `assert txn_role_for_kind(k) in MEMORY_TXN_ROLES`
- `test_compressed_global_extractor.py:480` — `assert ctx.txn_role in MEMORY_TXN_ROLES`

**Two options:**

| Option | Mapping | Pros | Cons |
|---|---|---|---|
| **A (recommended)** | All 8 kinds map to Pro-valid roles (`prev_word`, `prev_cycle`, `read`); per-kind attribution lives in `producer_kind` (already in `GLOBAL_LOOKUP`). | No schema change; tests pass as-is | Cycle-meta failures look like read failures in `txn_role`; D2.G must pivot on `producer_kind` for per-kind breakdown |
| **B** | Extend `MEMORY_TXN_ROLES` with `"cycle_meta"` (and possibly `"addr_meta"`) and coordinate Pro schema bump. | Cleaner D2.G analytics | Requires Pro-side coordination; expands D2.B scope; risks blocking Batch 1 |

**My recommendation:** **Option A.** `producer_kind` is the right separation axis for per-kind analytics; `txn_role` was designed (D16) as a memory-family proxy and shouldn't be overloaded.

**Why:**
- `producer_kind` already stores the full mutation kind string in `GLOBAL_LOOKUP` (see `compressed_global.py:41`). D2.G can group by `producer_kind` without extending the role enum.
- Option B requires Pro schema coordination on the critical path; D2.B is already 10–14 d.

**If you pick differently:** Option B is acceptable if you want exact `txn_role` semantics for cycle-meta kinds — flag as a D2.D dependency and we ship the Pro-coordination diff separately. But this WILL push Batch 1 by ~1 d minimum.

### Q6 — D2.B kinds in V5 only, or also in Hybrid-cTS? — REVISED v0.4 per Composer pushback

**LOCKED (Ivan 2026-06-17 via AskQuestion): Variant-specific kind subsets.** Global `MUTATION_KINDS` = union of 20 kinds. D2.D CLI defines: `V5_control={8 existing}` (D1.A archive reuse intact), `V5_expanded={16 A4}`, `Hybrid_cTS={16 A4 + 4 V6}`, `V6_uniform/cTS={4 V6}`. **Surfaced as NFP-2.** Watchlist W-5.

**Plain question:** When D2.D wires up the variant CLI, do D2.B kinds appear only in pure-A4 variants (V5), or also in Hybrid-cTS (A4 + Arguzz arms)?

**Plan v0.7 line 100 says V5 (control) = "current 8 kinds" with "D1.A static archive reuse".** Adding 8 kinds to global `MUTATION_KINDS` would change V5 arm-space and **break archive reuse** (paired V5 baseline vs D2 variants becomes apples-to-oranges).

**Locking decision (recommended):**
- **D2.B kinds added to `MUTATION_KINDS` constant** in `fuzzer.py` — but the **default** `MUTATION_KINDS` registry stays as the full union; **variant-specific kind subsets** filter what each variant actually fuzzes.
- **D2.D variant table:**
  - `V5_control` = `{8 existing kinds}` — D1.A archive reuse intact
  - `V5_expanded` = `{16 A4 kinds}` — D2.B optional companion run
  - `Hybrid_cTS` = `{16 A4 kinds + 4 V6 kinds}` — Pro's target
  - `V6_uniform` / `V6_cTS` = `{4 V6 kinds}` — Arguzz-only

**My recommendation:** **D2.B kinds added to global `MUTATION_KINDS`** (so they're available); **D2.D defines variant-specific subsets** (so V5 archive reuse still works).

**Why:**
- Pro's "expanded ablation" depends on variant-specific kind lists; we already plan this in D2.D.
- Global expansion without variant filtering would silently break V5 archive comparability — exactly the scenario Composer flagged.

**Concrete v0.4 spec addition:** §4.6 (`fuzzer.py` change) now reads "Add 8 entries to `MUTATION_KINDS`; **D2.D defines variant-specific kind subsets** via CLI; the default unbounded behavior is `union of all 20 kinds`."

**If you pick differently:** Excluding D2.B kinds from Hybrid weakens the Hybrid-vs-V5 ablation Pro wants. Excluding from V5_expanded means Pro can't see "A4-only with expanded surface" as a data point.

### Q7 — Python module file naming

**LOCKED (Ivan 2026-06-17): `lowercase_snake_case` matching kind string.** E.g., `txn_prev_word_mod.py`. Zero stakes.

**Plain question:** Naming convention?

**My recommendation:** **Lowercase snake_case matching kind string** (e.g., `txn_prev_word_mod.py`).

**Why:** Consistency with existing 8 module files.

**If you pick differently:** N/A — low-stakes convention.

### Q8 — Composer batch granularity

**LOCKED (Ivan 2026-06-17): 4 batches** — (1) spikes + B.1 end-to-end; (2) B.2+B.3; (3) B.4–B.8; (4) cross-cutting tests + smoke. Watchlist W-10 (split Batch 3 if attestation churn exceeds ~1 week).

**Plain question:** One huge batch vs multiple?

**My recommendation:** **4 batches** — (1) Rust scaffolding + B.1 end-to-end; (2) B.2 + B.3; (3) B.4 – B.8; (4) cross-cutting tests + smoke.

**Why:** Batch 1 proves the Rust + Python + test pattern works on one kind before replicating; per-batch reports give clean review gates.

**If you pick differently:** Bigger batches are riskier (large diff hard to review); finer-grained batches add overhead.

### Q9 — Composer Batch 1 task ordering (Rust first or Python first?)

**LOCKED (Ivan 2026-06-17): Rust first.** AND task 1.0a (Layer 3 hook) MUST land BEFORE 1.1 (B.1 handler). Without 1.0a, Layer 3 is broken even with B.1 done.

**Plain question:** Rust handler first, then Python module? Or reverse?

**My recommendation:** **Rust first.**

**Why:** Layer 2 attestation requires the Rust handler to exist; Python config schema is dictated by what Rust expects.

**If you pick differently:** Reasonable if Composer wants to design the JSON schema independently first — but the existing 7 Rust handlers already establish the schema pattern.

### Q10 — Escalation path if Rust build fights back

**LOCKED (Ivan 2026-06-17): Pause + report to Ivan/Opus.** Don't burn cycles on opaque Cargo issues. No alternative escalation path.

**Plain question:** If Composer hits Cargo/build issues, what's the fallback?

**My recommendation:** **Pause + report in `D2B_BATCH1_COMPOSER_REPORT.md` with specific errors.** Ivan + Opus decide fallback (debug help, descope, defer Rust work).

**Why:** Don't burn time iterating on build blockers without surfacing.

**If you pick differently:** N/A — escalation is universally right for blockers.

---

### Q11 — `TXN_PREV_WORD_MOD` (B.1): two strategies — how does the bandit wire them? (REVISED v0.4 per Composer feedback)

**LOCKED (Ivan 2026-06-17): Option A — single `MUTATION_KINDS` entry `"TXN_PREV_WORD_MOD"`; fuzzer RNG-picks `at_read`/`at_write` per pull; strategy logged in config JSON for reproducibility; `_step_has_real_target` ORs both strategies (mandatory).** PRE_EXEC_REG_MOD gets the same retrofix in **Batch 1.5e** (NFP-6, A4-only — Arguzz explicitly NOT touched). **Surfaced as NFP-3 + NFP-6.** Watchlist W-6.

**Plain question:** Per §3.1, B.1 mirrors PRE_EXEC_REG_MOD's two-strategy pattern (`at_read` vs `at_write`) because the constraint surface is genuinely different per txn type. Two sub-questions:
  - (a) Do we ship both strategies in D2.B?
  - (b) **How does the bandit *learn* the strategy mix?**

**Background — what v0.3 got wrong:** v0.3 claimed "the PRE_EXEC_REG_MOD precedent shows each strategy is a separate arm-kind in the universe." That is **false in production**. `a4/standalone/fuzzer.py` line 1639 currently hardcodes `strategy="next_read"` for PRE_EXEC_REG_MOD; `semantic_arm_universe.py` line 91 only probes `next_read` in `_step_has_real_target`. The bandit never explores `prev_write`. So if we copy that precedent literally, "double constraint coverage" is illusory — the bandit never learns the mix.

**My recommendation:**
  - (a) **Ship both Rust + Python strategies in D2.B.**
  - (b) **Option A: one bandit kind-string (`TXN_PREV_WORD_MOD`), RNG picks strategy per pull inside `_create_mutation`.**

**Why (a):** Constraint surfaces are different (`IsRead` vs `MemoryWrite`); both are productive coverage targets, and implementation cost is small (one Rust handler covers both via a `strategy` config field).

**Why Option A (over B and C):**

| Option | Behavior | Pros | Cons |
|---|---|---|---|
| **A (recommended)** | One arm-kind string. RNG (uniform 50/50) picks `at_read` / `at_write` per pull inside `_create_mutation`. | Smallest registry footprint (1 kind); easy to add knob later; same bandit learns "this zone responds better to strategy mix" via outcome aggregation | Bandit can't favour one strategy over the other per arm (would need (b) below to upgrade) |
| B | Two arm-kind strings (`TXN_PREV_WORD_MOD_AT_READ`, `TXN_PREV_WORD_MOD_AT_WRITE`). | Bandit explicitly learns per-strategy reward per zone | Doubles arm-space; pollutes D1 archive reuse; complicates kind registry; D2.D variant lists harder to manage |
| C | Config-only strategy; no bandit awareness; always `at_read`. | Trivial | Same bug as today's PRE_EXEC_REG_MOD — "we shipped it" without measuring the second surface |

**Concrete plumbing for Option A:**
1. `MUTATION_KINDS` gets one entry: `"TXN_PREV_WORD_MOD"`.
2. In `fuzzer.py::_create_mutation`, the new branch:
   ```python
   elif kind == "TXN_PREV_WORD_MOD":
       strategy = self.rng.choice(["at_read", "at_write"])
       targets = get_txn_prev_word_targets(step, self.data, strategy=strategy)
       ...
       config["strategy"] = strategy  # for Rust handler
   ```
3. In `semantic_arm_universe.py::_step_has_real_target`, check **both** strategies (step is real if EITHER has a target):
   ```python
   if kind == "TXN_PREV_WORD_MOD":
       t_read  = mod.get_targets_at_step(step, data, strategy="at_read")
       t_write = mod.get_targets_at_step(step, data, strategy="at_write")
       return bool(t_read) or bool(t_write)
   ```
4. PRE_EXEC_REG_MOD is **not** retroactively changed in D2.B (separate scope; flag as cleanup for D2.D or later).

**If you pick differently:** Option B is fine if you actively want per-strategy reward learning — but flag the implication that V5 archive reuse breaks (the arm-space changes) and we need to teach D2.D variant kind lists about strategy-suffixed kinds.

### Q12 — `TXN_ADDR_MOD` (B.4): exclude instruction-fetch txns? (NEW IN v0.3)

**LOCKED (Ivan 2026-06-17): Yes — exclude fetch txns.** Reuse `mem_val_mod._is_instruction_fetch()` helper (extract to shared util if needed).

**Plain question:** §3.4 recommends excluding instruction-fetch txns from B.4's target set. Confirm?

**My recommendation:** **YES — exclude instruction-fetch txns from B.4.**

**Why:**
- Mutating fetch addr means the next cycle attempts to "execute" from random memory; this is almost guaranteed to crash witgen even with `FAULT_INJECTION_ENABLED=1`
- The mutation's value is in addressing/permutation surface testing, not in fetch-address fuzzing (which is already covered by `CYCLE_PC_MOD` indirectly)

**If you pick differently:** Including fetch txns means many B.4 mutations will return outcome=ERROR (witgen panic) — pollutes the arm's success rate without producing constraint failures.

### Q13 — `TXN_ADDR_MOD` (B.4): exclude register txns? (NEW IN v0.3)

**LOCKED (Ivan 2026-06-17): Yes — exclude register txns in v1.** Within-register-range redirection is a different mutation shape (would be a future `TXN_REG_REDIRECT_MOD`); explicitly out of D2.B scope.

**Plain question:** §3.4 also recommends excluding register txns from B.4. Confirm?

**My recommendation:** **YES — exclude register txns from B.4 in v1; revisit if Pro wants register-address mutation later.**

**Why:**
- Register address range is small (32 word addresses at `USER_REGS_BASE..USER_REGS_BASE+32`); a random `u32` for a register txn almost certainly lands outside this range, triggering an immediate panic
- Within-register-range mutations (swap register x5 access with x7 access) would be a useful but structurally-different kind (`TXN_REG_REDIRECT_MOD`); defer to a future cycle

**If you pick differently:** If you want to include register txns with a within-range mutation strategy, that's effectively a 9th kind — push back as out-of-scope for D2.B.

### Q14 — `TXN_CYCLE_PHASE_MOD` (B.5): exclude instruction-fetch txns? (NEW IN v0.3)

**LOCKED (Ivan 2026-06-17): Yes — exclude fetch txns.** Fetch txns are always reads; LSB-flipping them to write triggers `IsRead` instantly with no novel info — pure arm-space clutter.

**Plain question:** §3.5 recommends excluding fetch txns from B.5. Confirm?

**My recommendation:** **YES — exclude.**

**Why:** Fetch txns are always reads; flipping to write triggers the IsRead constraint instantly with no novel info. Pure waste of arm-space.

**If you pick differently:** Including fetch txns just clutters the arm-space; no realistic counter-argument.

### Q15 — `CYCLE_STATE_MOD` (B.7): how does Composer enumerate valid state values? (NEW IN v0.3)

**LOCKED (Ivan 2026-06-17): Hardcode from `platform.rs::CycleState` extracted at Batch 1.0b.** Snapshot to `a4/standalone/mutations/_cycle_state_enum.py`. Re-check on risc0 pin bumps. Watchlist W-8.

**Plain question:** Taxonomy Appendix A lists *some* CycleState values but uses `...` ellipsis (incomplete). Composer needs the full enum for the "50% valid-but-different state" value-generation strategy. What's the source of truth?

**My recommendation:** **Composer Batch 1 extracts the full `CycleState` enum from `workspace/risc0-modified/risc0/circuit/rv32im/src/execute/platform.rs`** (or wherever it actually lives — `grep -r "enum CycleState"` should find it). The result is hardcoded as a Python constant in `cycle_state_mod.py`. Re-check on Rust version upgrades.

**Why:**
- Hardcoding is fine because we're pinned to `risc0-modified` (not upstream)
- Runtime introspection of the Rust enum from Python is too brittle

**If you pick differently:** Pure-random-only (skip the "valid-but-different" half) is simpler but misses the cross-state coverage signal.

### Q16 — Layer 3 risk-tiered strictness (NEW IN v0.3)

**LOCKED (Ivan 2026-06-17): Shared `assert_trace_diff_matches_signature(diff, expected_signature)` helper in Batch 1 task 1.7.** Minimal v1 signature DSL (primary field + allowed cascade tags); evolve as Batch 3 reveals real cascade shapes. Helper ALSO implements §9b soundness-bug guard: when `outcome=applied` + trace genuinely changed + zero `<constraint_fail>` + zero error → raise `SoundnessBugSuspected`.

**Plain question:** Per §5.2, low-risk kinds use strict Layer 3 (no cascade allowed); high-risk kinds use risk-tiered Layer 3 (expected cascade documented). Composer needs a precise way to assert "cascade matches the expected signature per kind" without writing a kind-by-kind diff parser.

**My recommendation:** **Composer Batch 1 writes a shared `assert_trace_diff_matches_signature(diff, expected_signature)` helper** that consumes a signature spec (e.g., `{"primary":{"txn_idx":I,"field":"prev_word","old":X,"new":Y}, "cascade":["same_addr_downstream_prev_word_mismatch"]}`) and checks the diff matches it. Per-kind tests pass their signature.

**Why:**
- Centralizes the diff-comparison logic
- Lets us evolve the signature spec language as we learn what cascades look like in practice
- Avoids 8 copies of the same comparison code

**If you pick differently:** Per-kind bespoke diff assertions are fine for v1 but duplicate work.

### Q17 — Layer 3 infrastructure: how do we actually dump the trace AFTER mutation? (NEW IN v0.4 per Composer feedback)

**LOCKED (Ivan 2026-06-17): Option A1 — `A4_DUMP_POST_MUT=1` Rust hook at end of mutation match arm (~30 LOC).** Batch 1 task 1.0a delivers; smoke-verifies on existing `COMP_OUT_MOD` handler before B.1 work starts. **Surfaced as NFP-5.** Watchlist W-9 (fallback to Option B tag-only Layer 3 if A1 hits unexpected Rust blockers — requires explicit Ivan approval).

**Plain question:** Layer 3 of the testing methodology (§5.1) compares a baseline pre-mutation trace dump against a post-mutation trace dump. v0.3 implicitly assumed running with `A4_INSPECT=1 A4_DUMP_ALL_TXNS=1 A4_MUTATION_CONFIG=...` would produce a *post-mutation* dump. **It does not.** In `witgen/mod.rs` the inspection block runs at lines ~72–187, *before* the mutation block at lines ~189–601. So the dump captures the **pre-mutation** state — the baseline-vs-mutated diff would always be NULL by construction.

**Three viable options:**

| Option | Implementation | Pros | Cons |
|---|---|---|---|
| **A1 (recommended)** | Add `A4_DUMP_POST_MUT=1` env var. After each mutation match arm completes (line ~601), emit `<a4_post_mut_dump>` tags for the modified cycle/txn (and any aliased neighbors, e.g. same-addr txns for B.1). ~30 LOC Rust. | Real post-mutation evidence; cheap to implement; works for all 8 kinds + future ones | Requires one targeted Rust patch in Batch 1 |
| A2 | Two-run harness: run 1 with inspect only (pre), run 2 with mutation only + a NEW inspect-after-mutation hook. Same as A1 but split across two binaries. | None over A1 | Twice the runtime; needs the same Rust patch anyway |
| B | Collapse Layers 2+3 — rely entirely on the `<a4_<kind>>` evidence tag's `old_value`/`new_value` fields. Skip independent trace re-read. | Zero infrastructure work | **Loses 100%-certainty claim** — Layer 3's whole point is "independent witness from the dispatcher tag". The bandit could be lied to by a buggy tag emission, and we wouldn't catch it. |

**My recommendation:** **A1 — add `A4_DUMP_POST_MUT=1` post-mutation dump hook in Composer Batch 1.0** (before the per-kind handlers land).

**Why:**
- Real post-mutation trace state is the only thing that makes Layer 3 an *independent* witness; without it Layer 4 ("cross-check") doesn't actually cross-check anything new.
- Implementation is small and localized: append a print loop after each match arm's mutation, gated on `A4_DUMP_POST_MUT`. Format mirrors the existing `<a4_txn>` / `<a4_cycle>` dump format from inspection.
- It also serves D2.E (campaign-level dump diffing) and any future debugging.

**Concrete Batch 1.0 deliverables for this question:**
1. Add `A4_DUMP_POST_MUT` handling block at end of mutation section in `witgen/mod.rs` (~30 LOC).
2. Add `parse_post_mut_dump` to `a4/core/trace_parser.py` (mirrors `parse_all_all_txns`).
3. Smoke test on an existing kind (e.g., `COMP_OUT_MOD`) to verify the pre/post diff captures the expected `word` change.
4. Document the cargo build invocation (resolves a separate question about the build target).

**If you pick differently:** Option B is acceptable as a **temporary** v1 measure if Batch 1 needs to ship in 1 day instead of 2, but the spec must explicitly flag that "100% certainty per Layer 4" is downgraded to "high confidence pending Layer 3 spike". Recommended only if A1 hits unexpected Rust complications.

## 7. Composer task breakdown (proposed)

Pending §6 lock-in; not started.

### Batch 1 — Spikes + Rust scaffolding + B.1 (`TXN_PREV_WORD_MOD`) end-to-end

| # | Task | Notes |
|---|---|---|
| **1.0a** | **Layer 3 infrastructure spike (Q17): add `A4_DUMP_POST_MUT=1` post-mutation dump hook to witgen** | **~30 LOC Rust; verify on existing `COMP_OUT_MOD` first** |
| 1.0b | Resolve Q15 (extract full `CycleState` enum) + Q3 (B.8 diff_count constraint inspection — likely ships) | Pre-implementation investigation; written up in batch report |
| 1.1 | Add B.1 Rust handler (both `at_read` and `at_write` strategies, dispatched via config `"strategy"` field per Q11 Option A) to witgen mod.rs | ~80 LOC |
| 1.2 | Build new risc0-host binary | **Document exact cargo invocation** (resolves Composer feedback §6 minor doc error) |
| 1.3 | Smoke-check existing kinds still work | Run a COMP_OUT_MOD test; verify `<a4_comp_out_mod>` still emits |
| 1.4 | Write `mutations/txn_prev_word_mod.py` | Two-strategy `get_targets_at_step(step, data, strategy=...)` per §3.1 |
| 1.5a | **Register in `a4/core/inspection_data.py::get_valid_steps_for_kind`** | **Add B.1 branch per §4.4 — CRITICAL, missed in v0.3** |
| 1.5b | Register in `semantic_arm_universe.py` (`_MUTATION_MODULES`, `_cycle_matches_kind_filter`, `_step_has_real_target` check BOTH strategies per Q11) | §4.5 |
| 1.5c | Register in `fuzzer.py::_create_mutation` (RNG-picked strategy per Q11 Option A) | §4.6 |
| 1.5d | Register in `compressed_global_extractor.py` role mapping (Pro-valid role per Q5 Option A) | §4.7 |
| **1.5e** | **`PRE_EXEC_REG_MOD` retrofix (NFP-6 in NOTES_FOR_PRO): mirror B.1 Option A pattern** | **`fuzzer.py:1639` RNG-picks `next_read`/`prev_write`; `semantic_arm_universe.py:90-91` ORs both. ~10 LOC. Rust + Python already support both strategies. A4-only — does NOT touch Arguzz. **CRITICAL: commit message MUST contain the literal string "Batch 1.5e" so D1 chat's git-log poll detects the merge and unblocks D1.E spec drafting** (per `IV_POS_8_D1_REVISIT_PLAN.md` §4.1 SYNC row and §4.3 Option B).** |
| 1.5f | Add unit test `test_d2b_pre_exec_reg_mod_two_strategy.py` covering the retrofix dispatch | Verifies both strategies are now reachable; archive-reuse-divergence note in batch report |
| 1.6 | Unit test `test_d2b_txn_prev_word_mod_unit.py` | Layer 1 — covers BOTH strategies and the RNG-picks-strategy dispatch path |
| 1.7 | Write shared `assert_trace_diff_matches_signature` helper (Q16) | Used by all attestation tests |
| 1.8 | **Attestation test `test_d2b_txn_prev_word_mod_attestation.py`** | **Layers 2 + 3 + 4 — gating, uses post-mut dump from 1.0a** |
| 1.9 | Full pytest sweep | ≥511 tests green |
| 1.10 | Write `D2B_BATCH1_COMPOSER_REPORT.md` | Layer 4 proof; cargo invocation; CycleState enum extraction; B.8 diff_count findings; Layer 3 hook verification |

**Pass criteria:** Layer 4 cross-check green for both `at_read` and `at_write` strategies of B.1; bandit observed RNG-picking strategy across pulls; `A4_DUMP_POST_MUT=1` dump verified on COMP_OUT_MOD smoke; existing pytest green; CycleState enum extracted; B.8 fate decided.

### Batch 2 — B.2 + B.3 (remaining high-priority kinds)

Same shape as Batch 1, per kind. ~2 Rust handlers + 2 Python modules + 2 unit tests + 2 attestation tests.

### Batch 3 — B.4 – B.8 (medium-risk kinds, 5 kinds, or 4 if B.8 dropped)

Same shape, 5-sub-sequence batch. Each kind individually gated on Layer 4.

**Attestation outcomes (v0.5.4 / plan §6d / W-17 + W-18):**

| Kind | Priority | Outcome |
|------|----------|---------|
| B.4 `TXN_ADDR_MOD` | Full attestation | **DEAD (W-18)** — guard + xfail |
| B.5 `TXN_CYCLE_PHASE_MOD` | Full attestation | **DEAD (W-18)** — guard + xfail |
| B.6 `CYCLE_PC_MOD` | Implement + attestation | **DEAD (W-17 confirmed)** — guard + xfail |
| B.7 `CYCLE_STATE_MOD` | Implement + attestation | **DEAD (W-17 confirmed)** — guard + xfail |
| B.8 `CYCLE_DIFF_COUNT_MOD` | Full attestation | **LIVE** — `cycle` Hook 3 |

Reference: [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md), [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md)

### Batch 4 — Cross-cutting + smoke

| # | Task |
|---|---|
| 4.1 | `test_d2b_arm_registration.py` | Layer 1 cross-cutting |
| 4.2 | `test_d2b_campaign_smoke.py` | Layer 5 mocked |
| 4.3 | `test_d2b_real_binary_campaign.py` | Layer 5 real-binary (gated) |
| 4.4 | Update master D2 plan: D2.B → DONE |
| 4.5 | `D2B_BATCH4_COMPOSER_REPORT.md` |

## 8. Decisions Confirmed

All 17 §6 questions resolved by Ivan on 2026-06-17. Each Q section in §6 now carries an inline **LOCKED:** stamp; this section is the consolidated table. Spec is **v0.5.2 LOCKED**.

### Major decisions (Q5 + Q6 — explicit Ivan votes via AskQuestion)

| # | Question | **LOCKED resolution** | Why |
|---|---|---|---|
| **Q5** | CGC `txn_role` mappings | **Option A — Pro-valid `MEMORY_TXN_ROLES` only; per-kind D2.G via `producer_kind`.** Schema bump to add `cycle_meta` deferred to IV.POS.9 if Pro requests. | Tests at `test_compressed_global_extractor.py:152, 480` enforce `role ∈ MEMORY_TXN_ROLES`. Field-name labels would break them. `producer_kind` is the correct separation axis. **Surfaced as NFP-4 in `IV_POS_8_NOTES_FOR_PRO.md` so Pro sees it explicitly.** |
| **Q6** | D2.B kinds: V5-only or also Hybrid? | **Variant-specific kind subsets.** Global `MUTATION_KINDS` = union of 20. D2.D CLI filters: `V5_control={8 existing}` (D1.A archive reuse intact), `V5_expanded={16 A4}`, `Hybrid_cTS={16 A4 + 4 V6}`, `V6_uniform/cTS={4 V6}`. | Plan v0.7+ line 100 defines V5 control as "8 kinds + D1.A static archive reuse" — global expansion would break that. **Surfaced as NFP-2.** |

### Secondary decisions (Q1, Q2, Q3, Q4, Q7, Q8, Q9, Q10, Q11, Q12–Q14, Q15, Q16, Q17 — 15 questions, Ivan accepted as written via AskQuestion option_a)

| # | Question | **LOCKED resolution** | Watchlist entry |
|---|---|---|---|
| **Q1** | `CYCLE_MODE_MOD` scope: broad vs ECALL/MRET-only | **Broad scope — any cycle.** Per taxonomy §3.14. | W-1 (revisit in D2.G if <1% failure rate outside boundary zones) |
| **Q2** | Value generation mixes (nearby vs random) | **Per-kind §3 percentages as heuristics.** D2.G retunes from DB `outcome` column without spec revision. | W-2 (retune at D2.G if per-mix-bucket skew detected) |
| **Q3** | Does B.8 `CYCLE_DIFF_COUNT_MOD` ship? | **Lean ship.** Field verifiably live (`preflight.rs:227,306` populate; zirgen `get_diff_count`). Batch 1.0b confirms with 5-mutation 3-way classification (constraint_fail / ERROR / clean-success). Clean-success rows MUST be cross-verified with `A4_DUMP_POST_MUT` per §9b soundness guard before drop. | W-3 (drop only if Batch 1.0b shows zero useful signal AND trace changes verified — i.e., dead arm, not soundness bug) |
| **Q4** | Layer 2/3/4 tests in CI | **Per-batch landing gate via `A4_REAL_BINARY=1`.** Composer runs locally before commit. No CI binary infra in D2.B; that's D2.E scope if needed later. | — |
| **Q7** | Python module file naming | **lowercase_snake_case matching kind string.** Zero stakes. | — |
| **Q8** | Composer batch granularity | **4 batches:** (1) spikes + B.1; (2) B.2+B.3; (3) B.4–B.8; (4) cross-cutting tests + smoke. | W-10 (isolate B.4 only if Batch 3 attestation churn exceeds ~1 week); **W-17** (B.6/B.7 predicted dead — reconcile audit if live) |
| **Q9** | Batch 1 ordering: Rust first or Python first | **Rust first.** AND task 1.0a (Layer 3 hook) comes BEFORE 1.1 (B.1 handler). Without 1.0a, Layer 3 is broken even with B.1 handler done. | — |
| **Q10** | Rust build escalation | **Pause + report.** No alternative — don't burn cycles on opaque Cargo issues. | — |
| **Q11** | B.1 two strategies — bandit wiring | **Option A — single `MUTATION_KINDS` entry "TXN_PREV_WORD_MOD"; fuzzer RNG-picks `at_read`/`at_write` per pull; strategy logged in config JSON; `_step_has_real_target` ORs both strategies.** PRE_EXEC_REG_MOD retrofix follows the same pattern in Batch 1.5e (NFP-6, A4-only — does NOT touch Arguzz). | W-6 (split to Option B if D2.G shows one strategy dominates rewards >80% on same zone) |
| **Q12** | B.4 `TXN_ADDR_MOD` exclude fetch txns | **Yes — exclude.** Reuse `mem_val_mod._is_instruction_fetch()` helper. | — |
| **Q13** | B.4 `TXN_ADDR_MOD` exclude register txns | **Yes — exclude in v1.** Within-register-range redirection is a different mutation shape (`TXN_REG_REDIRECT_MOD`); defer to future cycle. | — |
| **Q14** | B.5 `TXN_CYCLE_PHASE_MOD` exclude fetch txns | **Yes — exclude.** Fetch txns are always reads; flipping to write triggers IsRead instantly with no novel info. | — |
| **Q15** | B.7 `CycleState` enum source of truth | **Hardcode from `platform.rs::CycleState` extracted at Batch 1.0b.** Snapshot to `a4/standalone/mutations/_cycle_state_enum.py`; re-check on risc0 pin bumps. | W-8 (re-extract on any risc0 pin bump) |
| **Q16** | Layer 3 risk-tiered strictness / shared helper | **Shared `assert_trace_diff_matches_signature(diff, expected_signature)` helper in Batch 1 task 1.7.** Minimal v1 signature DSL (primary field + allowed cascade tags); evolve as Batch 3 reveals real cascade shapes. Helper also implements §9b soundness-bug guard (raise `SoundnessBugSuspected` when applied + trace changed + no constraint fail + no error). | — |
| **Q17** | Layer 3 post-mutation dump infrastructure | **Option A1 — `A4_DUMP_POST_MUT=1` Rust hook at end of mutation match arm (~30 LOC).** Batch 1.0a delivers; smoke-verifies on COMP_OUT_MOD before B.1 handler work. | W-9 (fallback to Option B tag-only Layer 3 with explicit Ivan approval IF A1 hits unexpected Rust blockers) |

### Cross-cutting decisions added during lock

| Topic | **LOCKED resolution** | Source |
|---|---|---|
| `PRE_EXEC_REG_MOD` retrofix (NFP-6) | Ships in **D2.B Batch 1 task 1.5e** alongside B.1. A4-only (does NOT touch Arguzz). Same Option A pattern as Q11. ~10 LOC. Commit message MUST contain literal "Batch 1.5e" for D1 chat git-log poll. | Ivan 2026-06-17 + NFP-6 in `IV_POS_8_NOTES_FOR_PRO.md` |
| Soundness-bug guard | Every clean-success outcome MUST be cross-verified against `A4_DUMP_POST_MUT` dump before classification as "dead arm". If trace genuinely changed but no constraint failed and no error emitted → raise `SoundnessBugSuspected` and surface to Pro. Applies to B.8 (Q3) and all D2.B kinds. | Ivan 2026-06-17, `IV_POS_8_D2_PLAN.md` §9b |
| Pro-facing decision surfacing | Major architectural decisions get an `NFP-N` entry in `IV_POS_8_NOTES_FOR_PRO.md` as they're made. D2.B contributes NFP-2 (8 kinds + variant subsets), NFP-3 (B.1 Option A), NFP-4 (Q5 Pro-valid roles), NFP-5 (Layer 3 hook), NFP-6 (PRE_EXEC_REG_MOD retrofix). | Ivan 2026-06-17 |
| Deferred-decisions tracking | Every "go with X now, revisit at Y if Z" decision gets a watchlist row in `IV_POS_8_D2_PLAN.md` §9a (W-1 through W-14). Reviewed at each watch's "first check" point. | Ivan 2026-06-17, plan §9a |
| D2.C review timing | Deferred until D2.B finishes. D2.B and D2.C are structurally independent (additive edits to same files; no semantic conflict). | Ivan 2026-06-17 |
| Pro-presentation timing | Pro check-in moves to **end of D2.B** (was D2.G). D2.B Batch 4 report becomes Pro-facing artifact alongside `IV_POS_8_NOTES_FOR_PRO.md` and spec. D2.C/D/E/F/G proceed after Pro greenlight. | Ivan 2026-06-17, plan §9a W-14 |

## 9. Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Rust build system surprises (Cargo, features, version pinning) | Medium | Q10 escalation; Batch 1 surfaces this on simplest kind first |
| B.8 field's diff_count not used by any constraint (Q3) | Medium | Q3 drops B.8 cleanly; 7 of 8 still ships |
| Layer 4 cross-check fails for some kind (Rust handler disagrees with trace) | Low (existing 7 handlers prove pattern) | Stop batch; debug; iterate |
| Cascade detection false-positives (Layer 3 over-strict for high-risk kinds) | Medium | Risk-tiered Layer 3 per §5.2; per-kind expected-signature spec |
| Arm-space explosion if Q1 goes broad (CYCLE_MODE on every cycle) | Low (revised) | Q1's broad recommendation defers to bandit's natural zone-clustering |
| Adding new Rust handlers breaks existing INSTR_WORD_MOD etc. | Very low | Batch 1 task 1.3 smoke-checks existing kind |
| TXN_ADDR_MOD (B.4) crashes witgen despite FAULT_INJECTION_ENABLED | Medium | Risk acknowledged; outcome=ERROR for crashes is normal; bandit learns to deprioritize |
| Hybrid arm-space too large (Q6: ~200 arms total) | Low | Pro's "100s of arms" target accommodates this |
| `txn.cycle` LSB semantics misunderstood by Composer (B.5) | Low | §3.5 documents explicitly; reference in Batch 3 kickoff |

## 10. What ships at the end of D2.B

- **8 new Rust handlers** in `risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` (or 7 if B.8 dropped after Q3 investigation)
- **8 new Python mutation modules** in `a4/standalone/mutations/`
- Registry updates in `semantic_arm_universe.py`, `fuzzer.py`, `compressed_global_extractor.py`
- **18 new test files** (8 unit + 8 attestation + 2 cross-cutting); ~528+ tests green
- Shared `assert_trace_diff_matches_signature` helper for attestation tests
- Rebuilt risc0-host binary deployed on dev box
- 4 Composer reports + this spec annotated with §8 Decisions Confirmed
- D2 plan updated with "D2.B → DONE"

---

## Appendix B: corrections in v0.4 (Composer review of v0.3)

| Issue | v0.3 had | v0.4 fix | Evidence |
|---|---|---|---|
| `inspection_data.py::get_valid_steps_for_kind` missing | Spec §4 listed semantic_arm_universe.py + fuzzer.py + CGC. | Added §4.4 with explicit per-kind branch logic. | `inspection_data.py:170-215` — if/elif over existing kinds; falls through to empty for unknown kinds. |
| Q11 "two strategies = two arms" claim | "PRE_EXEC_REG_MOD precedent shows each strategy is a separate arm-kind" | Q11 rewritten with bandit-wiring options A/B/C. Recommend Option A (one kind, RNG-picked strategy). | `fuzzer.py:1639` hardcodes `strategy="next_read"`; `semantic_arm_universe.py:90-91` only probes `next_read`. |
| `_MAJOR_FILTER_KINDS` "add all 8" | Blanket add. | Per-kind decision: B.6 added; B.1/B.2/B.4/B.5/B.3/B.7/B.8 NOT added. | `semantic_arm_universe.py:74-83` — comment line 83 says "MEM_VAL_MOD has no major filter"; curated set. |
| Layer 3 dump-diff infrastructure | Assumed `A4_INSPECT=1 + A4_MUTATION_CONFIG` produces post-mut dump. | New Q17 + Batch 1.0a task: add `A4_DUMP_POST_MUT=1` witgen hook (~30 LOC). | `witgen/mod.rs` inspection block (lines 72-187) runs BEFORE mutation block (lines 189-601). |
| §3.5 citation `pre_exec_reg_mod.py:486` | Cited Python file by mistake. | Corrected to `witgen/mod.rs:486` (Rust). | The `let is_read = txn.cycle % 2 == 0;` syntax is Rust, not Python. |
| Q3 B.8 lean-drop | "Drop if Batch 1 finds no constraint uses diff_count." | Lean ship pending verification: field is verifiably live. | `preflight.rs:227,306` increment diff_count; zirgen reads it via `get_diff_count`. |
| §5.3 B.7 strict-no-cascade | Asserted as strict. | Tentatively strict; Batch 1.0b investigates whether state transitions touch witness layout. | Composer correctly flagged that state may drive witness column population. |

## Appendix A: corrections vs v0.2

For reviewers comparing v0.2 → v0.3:

| Topic | v0.2 said | v0.3 corrects to | Source |
|---|---|---|---|
| `cycles[].diff_count` type | "exact field name TBD" | `[u32; 2]` (array of 2 u32s) | Taxonomy §1.2 |
| B.1 scope | "txns with `prev_cycle != 0`" | Any txn (no prev_cycle filter); two-strategy `at_read`/`at_write` | Taxonomy §3.8, PRE_EXEC_REG_MOD pattern |
| B.3 (CYCLE_MODE_MOD) scope | "ECALL/MRET ± 1 (restrictive)" | Any cycle (broad, let bandit cluster naturally) | Taxonomy §3.14 |
| B.4 (TXN_ADDR_MOD) risk callout | not flagged as high-risk | Explicitly HIGH RISK; mitigation via `FAULT_INJECTION_ENABLED`; fetch + register txns excluded | Taxonomy §3.10 |
| `txn.cycle` field semantic | called "cycle parity" | Full constraint-cycle index; LSB encodes phase; B.5 only flips LSB | Taxonomy §2.3, `witgen/mod.rs` line 486 |
| B.6 (CYCLE_PC_MOD) scope | "any cycle except 0" | Instruction cycles only (major 0–6) | Taxonomy §3.12 |
| Where mutations live in pipeline | not documented | New §1 with pipeline diagram and key fact | witgen mod.rs lines 64-617 |
| Layer 3 strictness | "exactly one field changed, nothing else" | Risk-tiered: strict for low-risk; cascade-permissive with signature for medium/high-risk | New §5.2 |
| Open questions count | 10 | 16 (added Q11–Q16 from deep-dive) | — |

---

*End of D2.B spec v0.4. v0.3 deep-research pass + v0.4 Composer-review corrections (critical missing file, bandit-wiring decision, per-kind major-filter, Layer 3 infra spike). §6 has 17 open questions awaiting Ivan's resolution before Composer Batch 1.*
