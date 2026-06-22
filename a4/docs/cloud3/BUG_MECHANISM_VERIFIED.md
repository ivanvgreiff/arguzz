# Soundness-bug mechanism — VERIFIED FROM SOURCE (arbiter for the ProG vs GPT disagreement)

**Date:** 2026-06-21 · **Method:** direct inspection of the risc0 git history in `workspace/risc0-modified` (not narrative, not the paper). Every claim below is reproducible with the commands shown.

## Verdict (one line)
**`GPT_Bug_Opinion.md` is CORRECT; `ProG_Report_5.md` §3.1 is WRONG about the mechanism.** The bug is a **same-source-register (`rs1 == rs2`) double-read** soundness hole. The race guest must **encode `rs1 == rs2`**, and the exploit fault makes the **two reads of that one register diverge** — it is **not** "normal `rs1 != rs2`, fault sets `rs2 := rs1`."

## The decisive evidence — what the #3181 fix actually changed
The CVE-2025-52484 fix is risc0 `#3181` (merge `67f2d81`) + zirgen `#238`. The risc0-side fix touches a huge amount of *regenerated* circuit code, but the **hand-written** change is tiny and dispositive — `risc0/circuit/rv32im/src/execute/rv32im.rs` adds **`load_rs2`**:

```rust
fn load_rs2<M: EmuContext>(&self, ctx: &mut M, decoded: &DecodedInstruction, rs1: u32) -> Result<u32> {
    if decoded.rs1 == decoded.rs2 {
        Ok(rs1)                                   // SAME register → read ONCE, reuse the value
    } else {
        ctx.load_register(decoded.rs2 as usize)   // distinct registers → separate read
    }
}
```
…and replaces `let rs2 = ctx.load_register(decoded.rs2 as usize)?;` with `let rs2 = self.load_rs2(ctx, &decoded, rs1)?;` in **both** the compute path (`step_compute`) and the store path. The companion `prove/witgen/preflight.rs` change adds `ensure!(txn.cycle != txn.prev_cycle)` and `diff = txn.cycle - 1 - txn.prev_cycle` — i.e. literally *"disallow memory I/O to the same address in the same memory cycle"* (the PR title).

**Interpretation:** before the fix, an instruction encoding `rs1 == rs2` caused the executor to issue **two separate reads of the same register in the same cycle**, and the circuit did **not** constrain those two reads to be equal. A malicious prover could therefore supply **two different values** for what is physically one register → forge a wrong `remu`/`divu` (and any 3-register op) result that still verifies. The fix forces a single read (executor) and forbids the duplicate same-cycle memory transaction (preflight + regenerated constraint).

## Commit reality (confirmed)
| commit | `fn load_rs2` present? | meaning |
|---|---|---|
| `98387806` (bug checkpoint) | **0 (absent)** — two separate `load_register(rs1)`/`load_register(rs2)` | **VULNERABLE** ✅ |
| `67f2d81` (#3181 fix) | 1 | patched |
| `ebd64e43` (our current base, #3305) | 1 | **our tree is patched** — cannot find the bug by construction |

Commands:
```bash
cd workspace/risc0-modified
git show 67f2d81:.../execute/rv32im.rs | grep -n load_rs2     # fix present
git show 98387806:.../execute/rv32im.rs | grep -n load_rs2    # empty → vulnerable
```
The vulnerable rv32im circuit is **committed in-tree as generated code** (`rv32im-sys/kernels/cxx/steps.cpp`, `rust_poly_fp_*.cpp`, `src/zirgen/poly_ext.rs`, `layout.*`) — the #3181 commit regenerated all of these. So building at `98387806` yields the vulnerable circuit **without fetching an external zirgen**; Pro's L5 "the Zirgen dependency might already be patched" concern is largely moot *as long as the build uses the in-tree generated files* (verify no codegen-from-newer-zirgen step runs at build).

## Why ProG_Report_5's framing is wrong (and why it matters for the race)
ProG says: normal `remu rd, rs1, rs2` with `rs1 != rs2`; the **fault** rewrites it to `remu rd, rs1, rs1`. Two problems:
1. **A guest that encodes `rs1 != rs2` never exercises the vulnerable path.** The hole exists *only* on the `rs1 == rs2` encoding; with distinct registers the circuit reads two genuinely different registers and there is nothing under-constrained.
2. **Even if a fault rewrote the `rs2` index to `rs1`, that alone is not the exploit** — both reads would then return the same register's same value (`x5 % x5 = 0`, the *correct* answer). The soundness violation requires the two reads to **disagree**. ProG conflates "enter the same-register path" with "exploit it."

GPT's design is faithful: **guest encodes `rs1 == rs2`; the fault makes read#1 ≠ read#2.**

## The correct race design (what the specs must build)
```text
guest (encoded):   remu x3, x5, x5        # rs1 == rs2 == x5, x5 != 0; honest result = x5 % x5 = 0
                   (force via inline asm + input barriers; DISASSEMBLE the ELF to confirm
                    an op with identical rs1==rs2 register fields actually survived compilation)
exploit fault:     make the two same-cycle reads of x5 diverge — read#1 = a, read#2 = b, a != b
                   (A4: edit one recorded read-value witness cell; Arguzz: alter one operand's
                    read value during execution). NOT "set rs2 := rs1" (a no-op here).
oracle:            pre-fix build ACCEPTS the proof while the committed output/OOPS is wrong;
                   post-fix build REJECTS the identical witness.
companion:         divu x3, x5, x5 with inputs chosen so divergence changes the result
                   (e.g. honest 13/13=1 vs faulted 13/5=2; avoid 7/5 which also =1).
```
Pro's one *valid* contribution survives: do **not** make the *mutation* a no-op. With an `rs1==rs2` guest, the no-op to avoid is "set `rs2:=rs1`"; the correct mutation is read-divergence.

## Why the exploit needs a COHERENT witness — and why A4 may NOT find it (corrected)
A first instinct is "this is a single-cell read divergence, so A4's single-cell post-execution mutation is well-suited." **That is wrong.** Walk the constraints for `remu x3,x5,x5`, `x5=7` (honest: `read_rs1=7, read_rs2=7, result=0`):

- **C_local** (present): `rem(read_rs1, read_rs2) == result`.
- **C_mem(rs2)** (the **missing/under-constrained** one): the second same-cycle read of x5 must equal x5's memory value.

To exploit, the malicious witness must be `read_rs2 = 5, result = 2` — **both**, so that C_local (`rem(7,5)==2`) still holds and **only** C_mem(rs2) is violated (the constraint that isn't enforced pre-fix). Committed output = 2 ≠ honest 0.

- **A single-cell post-execution edit (A4's defining shape) cannot do this.** Editing `read_rs2 → 5` while `result` stays `0` makes `rem(7,5)=2 ≠ 0` → **C_local fires** (it's present) → proof **rejected**. Editing only `result` fails C_local too. A4 does **not** recompute (its whole point is non-propagation), so it cannot produce the coherent `(read_rs2=5, result=2)` pair from one edit.
- **A during-execution (propagating) fault does it naturally.** Inject the rs2 operand = 5 *during* execution; the executor recomputes `rem(7,5)=2` and records `read_rs2=5, result=2` coherently → only C_mem(rs2) is violated → vulnerable circuit accepts. **This is exactly how Arguzz found it.**

**Consequence for the race (a genuine, thesis-grade prediction — not a given):**
- **V6_uniform / V6_cTS** (pure Arguzz, during-execution propagating) → **expected to find it.**
- **V5_control** (pure A4, post-execution single-cell, non-propagating) → **likely cannot** find it on the strong oracle (its mutation trips the present C_local before reaching the missing C_mem). A V5 negative is the predicted "limits of post-execution single-cell mutation" result (Pro §3.8), **not** a failure.
- **Hybrid_cTS** → depends on **whether its register-mutation arm is the propagating (Arguzz) flavor or the single-cell (A4) flavor** — its 4 imported Arguzz kinds historically excluded `PRE_EXEC_REG_MOD` as a name-duplicate of the A4 kind, so this must be checked. **A1 must characterize, per variant, whether the reg-mutation propagates** (during-exec recompute) or is a single post-execution cell edit — that determines findability.
- **Caveat that could change this:** if the circuit keeps *separate* witness cells for "register read value" vs "ALU operand" and ties them only via the (missing) constraint, a single-cell edit of the read-value cell might violate *only* C_mem. Whether that's the case depends on the exact witness layout — which the A1 deterministic repro settles empirically. So: A4-cannot-find-it is the **leading prediction**, confirmed-or-refuted by A1/A3, not asserted.
