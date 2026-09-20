# CVE race — round-2 guest design + INSTR_WORD_MOD reachability analysis (self-contained review doc)

> **For an external reviewer (e.g. ChatGPT):** this document is fully self-contained. It explains the
> bug, the two fuzzing paradigms being compared, the *exact* Arguzz mutation logic, the deployed guest
> program (exact source), the RISC-V instruction encoding needed to follow the bit-level reasoning, and
> then a from-first-principles probability analysis of how hard it is for Arguzz to surface the bug as a
> function of register layout and guest size. **Please check:** (1) is the bug/mechanism described
> correctly? (2) is the per-strategy and overall hit-probability math correct? (3) is the "two round-2
> knobs are not equivalent (linear dilution vs combinatorial cliff)" conclusion sound? (4) is the
> recommendation reasonable, and are the assumptions (esp. the single canonical target and the
> round-1 empirical validation) fair? **Hard constraint we are NOT relaxing:** we do not modify Arguzz
> or how it chooses mutations — the guest is our only design lever.

---

## 0. One-paragraph orientation
We are doing a master's-thesis experiment comparing two zkVM soundness-fuzzing strategies on RISC Zero's
zkVM: **A4** (our method — *post-execution* single-cell mutation of the proof trace) vs **Arguzz** (prior
work — *during-execution* fault injection). We run a "known-bug race": both strategies fuzz a guest
program that triggers a **real, patched RISC Zero soundness bug** (CVE-2025-52484 / risc0 PR #3181), and
we measure which strategy *finds* the bug (produces a verifying proof of a wrong result). The thesis
claim is **complementarity**: A4 finds bugs Arguzz can't and vice-versa. For *this* bug we predict
**Arguzz finds it, A4 does not**. Round 1 is currently running on a cluster. The question this doc
answers: round-1's guest pinned the vulnerable instruction's two source registers to be **1 Hamming-bit
apart**, which made the bug easy for Arguzz's random bit-flip mutation to hit. Was that necessary, is it
"rigging," and how should round 2 be designed?

---

## 1. The bug: the `rs1 == rs2` read underconstraint (CVE-2025-52484 / risc0 #3181)
RISC Zero proves correct execution of RISC-V via an arithmetic circuit. For a 3-register ALU instruction
like `remu rd, rs1, rs2` (unsigned remainder, `rd = rs1 % rs2`), the circuit reads the two source
registers from a register-memory abstraction and constrains the result.

Register reads/writes are modeled as memory transactions `(addr, cycle, value)` kept consistent by a
permutation / cycle-ordering argument.

**Source-verified flaw (pre-fix, commit `98387806`).** For `remu rd, rs1, rs2` the executor does **two
literal reads** — `load_register(rs1)` then `load_register(rs2)` (rv32im.rs:326/327). When the
instruction's two source-register *fields are equal* (`rs1 == rs2`), that is **two reads of the same
register address in the same cycle**. Pre-fix there is (a) **no `load_rs2` dedup** and (b) **no preflight
`ensure!(txn.cycle != txn.prev_cycle)`** — so **same-address, same-cycle memory I/O is underconstrained**
(the cycle-ordering argument degenerates at `cycle == prev_cycle`).

**The fix #3181 (`67f2d81c`, titled "Disallow memory I/O to same address in the same memory cycle")** adds
`fn load_rs2` (read once and reuse when `rs1 == rs2`) **and** the preflight `ensure!(cycle != prev_cycle)`,
plus the regenerated circuit constraints. We build at `98387806` (the fix's direct parent), so the
vulnerable generated circuit is committed in-tree — **no circuit regeneration needed.**

**The exploit shape we deploy (Arguzz paper / ProG_Report_5 §3.1 — NOT a read-divergence).** Start from
`remu rd, rs1, rs2` with **`rs1 != rs2`** and let the *fault* set the **rs2 field equal to rs1**, so the
**executed** instruction becomes `remu rd, rs1, rs1`. It then reads rs1 **twice in one cycle** (the
underconstrained case) and computes `rs1 % rs1 = 0`, which **differs from the program's `rs1 % rs2`** —
yet the proof verifies. Note the two reads are **consistent** (both return rs1's value); the wrongness
comes from the *executed instruction differing from the committed program*, which the same-cycle-I/O
underconstraint fails to reject. The paper explicitly warns: **do NOT encode `rs1==rs2` in the guest** —
then `rs2:=rs1` is a semantic no-op and the benchmark is poisoned. (Affects `divu` too: `x/x = 1 != x/y`.)

**Oracle + the pending bracket (be honest here).** A find = proof **verifies** AND committed journal ≠
honest output (*strong journal oracle*). The decisive control that this is specifically the **#3181**
same-cycle-I/O bug — and not some *other* instruction-binding hole — is **G5: the *patched* build must
REJECT the identical mutation.** We have **G4 (vulnerable build ACCEPTS, empirically confirmed)**; **G5 is
PENDING** (it is part of round-1's oracle/control-confirm pass). *Reviewer: please sanity-check the exact
constraint being bypassed — same-cycle memory-consistency (our claim) vs instruction-fetch/decode binding
— since we have not yet run the patched-rejects control.*

## 2. The two paradigms, the variants, and why coherence is the crux
- **A4 (our method) — post-execution single-cell mutation.** Runs the guest honestly to produce the full
  trace, then edits **one cell** of the trace (e.g. an instruction-word field, a register value) and
  re-proves. It does **not** re-execute, so it cannot *recompute* downstream values.
- **Arguzz (prior work) — during-execution fault injection.** Perturbs the computation *while the VM
  runs*, so the executor naturally **recomputes** all downstream values consistently.

The 4 race variants: **V5_control** (pure A4), **V6_uniform** (pure Arguzz, uniform random scheduling),
**V6_cTS** (Arguzz, coverage-guided scheduling), **Hybrid_cTS** (A4 surface + Arguzz surface).

**Why Arguzz can exploit this bug and A4 cannot — coherence.** Let the program op be `remu rd, rs1, rs2`
(`rs1 != rs2`), with rs1 holding `a` and rs2 holding `b`. The fault sets the **rs2 field := rs1**:
```
honest  :  read(rs1)=a, read(rs2)=b,            result = a % b           (the program's intent)
exploit :  rs2 field := rs1  =>  both reads = a (one register, same cycle),  result = a % a = 0
```
The circuit enforces the local constraint `C_local : result == op(read_rs1, read_rs2)`. After the alias
both reads equal `a`, so a *coherent* witness needs `result = a % a = 0`:
- **Arguzz** changes the instruction *during execution*, so the executor **recomputes** `result = a%a = 0`
  ⇒ `C_local` holds, and the pre-fix circuit does not reject the same-cycle double-read ⇒ **accepted**
  (committed `0 != a%b`).
- **A4** edits the rs2-field cell *post-execution* but leaves the **result cell at the honest `a%b`** ⇒
  `result (a%b) != op(reads) (a%a=0)` ⇒ `C_local` **fires** ⇒ **rejected**.

So **coherence (recompute vs not) is the real differentiator**, independent of register layout and trace
size. (Nuance used later: A4's *surgical* mutator can set the rs2 field to a random register very easily —
it **reaches** the alias — but is rejected for incoherence; Arguzz **reaches** it only via random
bit-flips, but once it does, the recompute makes it coherent.)

## 3. Arguzz's `INSTR_WORD_MOD` mutation logic (exact, unmodified)
We confirmed by reading the code that Arguzz's Python layer only *schedules* a target step
(`arguzz_bridge.py` → `arguzz_invoke.py` → `risc0-host --inject --inject-kind INSTR_WORD_MOD --step S`);
the actual instruction-word mutation is performed by this **Rust** function in the (Arguzz-instrumented)
executor, `risc0/circuit/rv32im/src/execute/rv32im.rs`:

```rust
pub fn random_word(&mut self, word: u32) -> u32 {
    // TODO: instruction aware manipulations
    // NOTE: we do not temper with the last 2 bits (0, 1)
    //       because it seems to do nothing and it is checked during fetch.
    let mut new_word = word;
    let mut kind = InsnKind::Invalid;
    while new_word == word || kind == InsnKind::Invalid {
        let selector: u32 = self.rng.random_range(0..=2);
        new_word = match selector {
            0 => {                                  // STRATEGY 0: flip ONE random bit
                let bit_to_flip = self.rng.random_range(2..=31);   // bits [2,31], 30 choices
                word ^ (1 << bit_to_flip)
            },
            1 => {                                  // STRATEGY 1: flip N random bits
                let n = self.rng.random_range(1..=29);             // N ~ Uniform{1..29}
                let bits_to_flip = rand::seq::index::sample(&mut self.rng, 29, n).into_vec();
                let mut flipped_word = word;
                for bit_with_offset in bits_to_flip {
                    let bit_to_flip = bit_with_offset + 2;          // bits [2,30], 29 positions
                    flipped_word ^= 1 << bit_to_flip;
                }
                flipped_word
            },
            2 => {                                  // STRATEGY 2: fully random word
                self.rng.random::<u32>() | 0x03                     // low 2 bits forced to 1
            },
            _ => unreachable!(),
        };
        kind = self.insn_kind_from_word(new_word);
    }
    new_word
}
```

Key facts for the analysis:
- **Bits 0 and 1 are never touched** (the comment says they're checked at fetch and "do nothing").
- **Selector is uniform over {0,1,2}** (⅓ each), re-rolled every loop iteration.
- The **`while` loop retries** until the result is a *valid, different* instruction (`kind !=
  InsnKind::Invalid` and `new_word != word`).
- It is **purely bit-flip based** — there is **no "choose a random register for the rs2 field"
  substrategy**. (Such a register-aware mutator exists only on the *A4* side — `instr_word_mod_sur.py`'s
  `generate_field_value` does `rng.randint(0,31)` for the RS2 field — but A4 is post-exec and gets
  rejected for incoherence. Arguzz's `PRE_EXEC_REG_MOD` does pick a random register, but it mutates a
  register's *value*, not an instruction's rs2 *field*, so it does not produce this alias.)

## 4. RISC-V R-type encoding (needed to follow the bit math)
`remu`/`divu` are R-type (32-bit):
```
 bit:  31        25 24   20 19   15 14  12 11    7 6      0
      [  funct7   ][  rs2 ][  rs1 ][funct3][  rd  ][ opcode ]
        7 bits      5 bits  5 bits  3 bits  5 bits  7 bits
```
- `opcode` = `0110011` (0x33, "OP"); for `remu` `funct3=111, funct7=0000001`; for `divu`
  `funct3=101, funct7=0000001`. Note opcode bits 0,1 = `11`, consistent with strategy 2's `| 0x03`.
- **`rs2` field = bits [24:20]; `rs1` field = bits [19:15]** — both 5-bit register numbers (0–31), both
  entirely inside the flippable range [2:31].
- To make `rs1_field == rs2_field` by editing only the rs2 field (the canonical "rs2 := rs1"), you must
  flip exactly the bits where the rs2 register number differs from the rs1 register number — i.e.
  **`d = popcount(rs1_reg XOR rs2_reg)`** bits, all within [24:20], and **flip nothing else** (or you
  change opcode/funct/rd/rs1 → a different or invalid instruction, not this alias).

## 5. The deployed round-1 guest (exact source) and its numbers
File `workspace/output-a1vuln/methods/guest/src/main.rs`:
```rust
#![allow(unused_parens)]
// IV.POS.9 A2 — rs1==rs2 CVE race guest (CVE-2025-52484 / risc0 #3181).
use risc0_zkvm::guest::env;
fn main() {
    let a: u32 = env::read();        // host arg "ctrl"   (= 7 in the race)
    let b: u32 = env::read();        // host arg "gseed"  (= 12345 in the race)
    let _c: u32 = env::read();       // host arg "rounds" (= 5; unused)
    let x = (a & 0x7).wrapping_add(2);     // x in 2..9, nonzero, small
    let y = (b | 0x100).wrapping_add(1);   // y >= 257  => x < y guaranteed
    let r_rem: u32;
    let r_div: u32;
    unsafe {
        // inline asm pins the operands into specific registers so the compiler
        // cannot const-fold or pick its own; rs1 != rs2 by construction.
        core::arch::asm!("remu {o}, a0, a1", o = out(reg) r_rem, in("a0") x, in("a1") y, options(nomem, nostack));
        core::arch::asm!("divu {o}, a2, a3", o = out(reg) r_div, in("a2") x, in("a3") y, options(nomem, nostack));
    }
    let acc = r_rem.wrapping_mul(1000003).wrapping_add(r_div);  // fold both ops into the journal
    env::commit(&acc);   // honest: r_rem = x%y = x (since x<y), r_div = x/y = 0
}
```
**Register choice = the thing under scrutiny.** `a0=x10=01010`, `a1=x11=01011` → differ in **bit 0 only ⇒
d=1**. `a2=x12=01100`, `a3=x13=01101` → differ in **bit 0 only ⇒ d=1**. So both vulnerable ops have
their two source registers **1 Hamming-bit apart by deliberate construction.**

**Honest run** (`x=9, y=12602`): `r_rem = 9 % 12602 = 9`, `r_div = 9 / 12602 = 0`,
`acc = 9·1000003 + 0 = 9000027`. (Verified on the actual binary: committed `9000027`, proof verifies.)

**Exploited run** (fault makes `remu`'s reads collapse to a0, i.e. `remu rd, a0, a0`): `r_rem = 9 % 9 = 0`
⇒ `acc = 0`. A `divu` alias instead gives `9/9 = 1` ⇒ `acc = 9000028`. Either way `acc != 9000027` while
the proof verifies ⇒ accept-of-wrong (the find).

## 6. Exact probability that one `INSTR_WORD_MOD` draw hits the alias
**Target (single canonical):** flip exactly the `d` bits of the rs2 field where the rs2 register number
differs from rs1, and nothing else (the paper's "rs2 := rs1"). The rs2 field bits [24:20] are inside the
flippable range, so all `d` differing bits are flippable. `d = popcount(rs1_reg XOR rs2_reg)`.

Per strategy, probability that **one generation** equals the target:
- **Strategy 0** (flip 1 bit uniformly among the 30 bits [2:31]): can only flip 1 bit, so it can hit the
  target **iff d = 1**, and then only if it picks that exact bit: **P₀ = 1/30 if d=1, else 0.**
- **Strategy 1** (pick N~Uniform{1..29}, then N distinct bits among the 29 positions [2:30]): hits iff
  **N = d** *and* the chosen `d` bits are exactly the `d` target bits:
  **P₁ = (1/29) · 1/C(29, d).**
- **Strategy 2** (uniform random 30 free bits): must match the whole word: **P₂ = 1/2³⁰** (any d).
- **Overall** (selector uniform ⅓): **P = (P₀ + P₁ + P₂) / 3.**

Computed values (`C(29,1..5) = 29, 406, 3654, 23751, 118755`):

| d | Strategy 0 | Strategy 1 = 1/(29·C(29,d)) | Strategy 2 | **Overall = ⅓·Σ** | × harder vs d=1 | expected hits in N=5000 |
|--:|--:|--:|--:|--:|--:|--:|
| **1** | 1/30 | 1/841 | 1/1,073,741,824 | **1/87** | 1× | **57.5** |
| **2** | **0 (impossible)** | 1/11,774 | 1/1,073,741,824 | **1/35,322** | **406×** | 0.14 |
| 3 | 0 | 1/105,966 | 1/1,073,741,824 | 1/317,867 | 3,658× | 0.016 |
| 4 | 0 | 1/688,779 | 1/1,073,741,824 | 1/2,065,012 | 23,763× | 0.002 |
| 5 | 0 | 1/3,443,895 | 1/1,073,741,824 | 1/10,298,653 | 118,511× | ~0 |

**Empirical validation of the model.** The raw d=1 probability predicts `1/87 × 5000 = 57.5` finds in a
N=5000 run; round-1 (the deployed d=1 guest) **measured ~55 finds** for the Arguzz variants. The close
match means that on this small guest the two factors I otherwise have to estimate — step-targeting
`f_step` (the chance a mutation lands on the vulnerable instruction) and the valid/retry-loop conditioning
— **net out to ≈1**, so the raw per-draw probability is an accurate predictor of the find rate. This is
why I trust the d-scaling below.

**Caveats / assumptions (please scrutinize):**
1. *Single target.* I count only "rs2 := rs1". The symmetric "rs1 := rs2" (`remu rd, rs2, rs2`) is also a
   same-register alias and would roughly **double** P₀ and P₁. I omit it because (a) it matches the
   paper's framing and (b) including it would predict ~115 finds at d=1, overshooting the measured ~55 —
   so the single-target model is the empirically correct one (the symmetric target apparently doesn't
   register as a find, or `f_step<1` compensates). Either way it does not change the **relative** d-scaling.
2. *Retry conditioning is a common factor.* The `while valid && changed` loop discards invalid draws; the
   target is valid, so the loop can only *help* the target, by a factor `1/P(valid&different)` that is the
   **same for every d** (it depends on the strategy validity fractions, not on the target's d). So the
   **ratios across d are exact** regardless of this factor, and the absolute rate is pinned by the
   round-1 empirical.
3. *`f_step` is where guest size enters* (§7), and it is the only thing the guest can cheaply change at d=1.

## 7. The d=1 → d=2 cliff, and why register adjacency is near-necessary
Strategy 0 (a single bit flip, the **dominant** term at d=1: 1/30 vs strategy 1's 1/841) is
**mathematically impossible at d ≥ 2** — one flip cannot fix two differing bits. So at d≥2 only the rare
strategy 1 survives, and the overall probability collapses **~406×** at d=2 (and ~3,658× at d=3). In
expected finds: **~57 at d=1 → ~0.14 at d=2** for N=5000. To expect even ~7 finds at d=2 you'd need
**N ≈ 250,000**. Conclusion: **with Arguzz unmodified, register adjacency (d=1) is *near-necessary* for
`INSTR_WORD_MOD` to find this bug at all** — it is not merely a convenience.

Context on "natural" registers: among the 992 ordered distinct register pairs, **160 (16.1%) are d=1**.
But compilers commonly place the first two arguments in `a0,a1` (= x10,x11, which *are* d=1), so naturally
compiled code lands on the findable case fairly often — by luck, not by guarantee.

## 8. Round-2: the two candidate knobs are NOT equivalent (linear dilution vs combinatorial cliff)
Model the per-mutation find rate as `find_rate ≈ f_step · P_word(d)`, where `f_step ≈ n_vuln /
n_valid_steps` is the probability a scheduled mutation targets the vulnerable instruction.

**Scenario A — keep d=1, add M× more *unrelated* logic (bury the vulnerable op).**
`P_word` stays at the d=1 value (1/87); only `f_step` dilutes by ~M ⇒ `find_rate ≈ (1/87)·(1/M)`.
**Linear and tunable:**

| M (× more logic) | find_rate | expected finds in N=5000 |
|--:|--:|--:|
| 1 (round-1) | 1/87 | 57 |
| 10 | 1/870 | 5.7 |
| 20 | 1/1,740 | 2.9 |
| 50 | 1/4,350 | 1.1 |

You can dial the difficulty smoothly and keep enough finds for statistical power (or raise N). Arguzz
still wins; A4 still fails (coherence). *Weakness:* it keeps the d=1 reachability, so it adds **realism**
but does not, by itself, answer "what if the registers weren't adjacent?"

**Scenario B — small trace (f_step ≈ 1), increase the register distance d.**
`find_rate ≈ P_word(d)`, which falls off the cliff of §7: **d=2 ⇒ ~0.14 finds in N=5000 ⇒ effectively
null.** Because `d` is discrete and d=2 already zeroes it, this is **not a tunable difficulty dial** — it
is a **binary** experiment: *can Arguzz find the non-adjacent version? → essentially no.*

**Bottom line:** Scenario A = *harder but findable* (difficulty linear in trace size). Scenario B =
*unfindable* (combinatorial cliff at d≥2). They are not interchangeable; they answer different questions.

## 9. Recommendation
Run **both, in order** — they characterize Arguzz honestly and completely:
1. **Primary round-2 = Scenario A.** Guest `A2'`: **keep source regs d=1** (a0/a1, a2/a3) but bury the
   single vulnerable `remu`/`divu` in **M ≈ 10–15 of unrelated logic** — a bounded mixed-ALU loop
   (add/xor/sub/and/sll/srl), a few branches, a small in-memory array touched by loads/stores, and a few
   **decoy `remu`/`divu` on safe operands** (so a register-field mutation on the wrong div is a benign
   miss). Target ~2¹³–2¹⁴ trace cycles (within the prover's po2 budget, ~3 s/mutation). Output folded into
   the journal with a known honest value for the strong oracle. Expect ~4–6 Arguzz finds; A4 = 0.
   *Harder, realistic, complementarity preserved.*
2. **Secondary probe = Scenario B at d=2.** Minimal guest, source registers **2–3 bits apart** (verified
   by objdump). Expect **~0 Arguzz finds** — and report that **null as the finding**: Arguzz's
   `INSTR_WORD_MOD` is *register-adjacency-dependent* and cannot reach this CVE at d≥2 in feasible N.
   This is the cleanest, most honest rebuttal to any "rigged guest" critique: it quantifies exactly when
   Arguzz can and cannot find the bug.
3. **A4 is rejected in every cell** (coherence), independent of d and trace size — so the complementarity
   story holds throughout.
4. (Stretch) the report-mandated **contextual guest** (4–8 semantically-equivalent functions, the
   vulnerable op buried in 1–2) as a realism capstone.

**Explicitly not on the table:** making `random_word` register-aware (implementing its `// TODO`) would
let Arguzz hit the alias at any `d` and erase the cliff — but we **do not modify Arguzz**. The
d-dependence is therefore a fixed property of the tool that we design the guest around, and is itself a
reportable result about Arguzz's reach.

## 9a. Concrete round-2 guest sketches (illustrative)
**Scenario A — `A2'`: keep d=1, bury the single vulnerable op in M× unrelated logic.**
```rust
#![allow(unused_parens)]
use risc0_zkvm::guest::env;
fn main() {
    let a: u32 = env::read();
    let b: u32 = env::read();
    let seed: u32 = env::read();
    // --- M× UNRELATED logic: bounded mixed-ALU + branch + memory loop. Its only job is to add
    //     thousands of valid INSTR_WORD_MOD steps so f_step (P[mutation hits the vulnerable op])
    //     drops ~M×. None of it is the vulnerable pattern. ---
    let mut acc: u32 = seed;
    let mut buf = [0u32; 64];
    for i in 0..512u32 {                                   // -> ~thousands of trace steps
        acc = acc.wrapping_mul(1664525).wrapping_add(1013904223);   // LCG: mul + add
        acc ^= acc >> 13; acc = acc.rotate_left(7);                 // xor / shift / rotate
        if acc & 1 == 0 { acc = acc.wrapping_sub(i); } else { acc = acc.wrapping_add(i); } // branch
        buf[(i & 63) as usize] = acc;                       // store
        acc ^= buf[((i.wrapping_mul(7)) & 63) as usize];    // load
        // DECOY divu whose two source regs hold the SAME value, so an rs2:=rs1 alias is a NO-OP
        // (divu(v,v)=1 either way) -> a mutation here is a benign miss, not a spurious find.
        let v = acc | 1;
        let q: u32;
        unsafe { core::arch::asm!("divu {o}, a4, a5", o=out(reg) q, in("a4") v, in("a5") v, options(nomem,nostack)); }
        acc = acc.wrapping_add(q);
    }
    // --- the ONE vulnerable op, buried here; source regs a0/a1 = x10/x11 -> d = 1 (kept) ---
    let x = (a & 0x7).wrapping_add(2);     // 2..9
    let y = (b | 0x100).wrapping_add(1);   // >= 257  => x < y  => x % y = x  (fault: x % x = 0)
    let r: u32;
    unsafe { core::arch::asm!("remu {o}, a0, a1", o=out(reg) r, in("a0") x, in("a1") y, options(nomem,nostack)); }
    acc = acc.wrapping_mul(1000003).wrapping_add(r);   // fold the vulnerable result into the journal
    env::commit(&acc);   // honest acc is a known function of (a,b,seed); any rs2-alias fault changes it
}
```
*Tuning:* the loop trip count and the decoy count set M (≈ extra valid steps / vulnerable steps). Start
at M≈10–15 (loop ~512, a handful of decoys); verify the actual trace size and `f_step` empirically and
adjust. Keep the trace ≤ ~2¹⁴ cycles so per-mutation prover time stays ~3 s.

**Scenario B — minimal guest, registers NON-adjacent (d=2) to probe the reachability limit.**
```rust
#![allow(unused_parens)]
use risc0_zkvm::guest::env;
fn main() {
    let a: u32 = env::read();
    let b: u32 = env::read();
    let _c: u32 = env::read();
    let x = (a & 0x7).wrapping_add(2);
    let y = (b | 0x100).wrapping_add(1);   // x < y
    let r: u32;
    unsafe {
        // a0 = x10 = 01010, a5 = x15 = 01111  ->  XOR = 00101  ->  Hamming distance d = 2.
        // An rs2:=rs1 alias now needs flipping 2 specific bits at once: strategy-0 (1-bit) is
        // IMPOSSIBLE; only strategy-1 (rate ~1/35k overall) can do it -> expect ~0 finds in N=5000.
        core::arch::asm!("remu {o}, a0, a5", o=out(reg) r, in("a0") x, in("a5") y, options(nomem,nostack));
    }
    env::commit(&r);   // honest r = x ; the (rare) alias would commit 0
}
```
*Verify with objdump* that the compiler kept `remu` with the intended register fields (the pinning via
`in("a0")`/`in("a5")` forces it, but confirm — and confirm the realized Hamming distance).

## 10. Specific questions for the reviewer
- Is the strategy-1 probability `(1/29)·1/C(29,d)` right, given N∈{1..29} uniform and the 29 flippable
  positions [2:30]? (Strategy 0 uses 30 positions [2:31]; strategy 1 excludes bit 31 — does that matter
  here? The rs2 field is bits [20:24], so no, but flag if you disagree.)
- Is it fair to model the find rate as `f_step · P_word(d)` with `f_step·(retry factor) ≈ 1` justified by
  the 57.5-vs-55 match, or is that coincidental and the decomposition should be done more carefully?
- Is the single-canonical-target choice (vs counting the symmetric rs1:=rs2 and the 30 "both fields → some
  third register k" targets) the right modeling decision?
- Given we won't modify Arguzz, do you agree Scenario A is the better *primary* round-2 and Scenario B is
  best framed as an adjacency-limit null, or would you argue for a different design?
