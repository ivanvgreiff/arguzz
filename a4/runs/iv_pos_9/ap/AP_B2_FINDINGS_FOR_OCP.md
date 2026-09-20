# AP.B2 — Findings & Decision Memo for OCP

**Author:** Reviewing Opus (this session)
**Date:** 2026-06-23
**Status:** AUTHORITATIVE. Supersedes the surgical-feasibility conclusions in `AP_B2_CIRCLE_REPORT.md`, `AP_B2_STATE_AND_ROOTCAUSE.md`, and `AP_B2_STATUS.md` on the specific question of *whether the surgical patch plants the intended bug*. All claims below are verified on-disk; reproduction commands are in §7.

---

## 0. TL;DR

1. **The path-doubling/plumbing diagnosis is correct** and I cleaned the damage (removed 47 MB of nested `src/zirgen/zirgen/...` rsync artifacts; canonical files are git-clean and unholed).
2. **df6fb9d ≠ the committed circuit — proven, not assumed.** A semantic opcode diff (loc-comments stripped) shows **20,277 vs 20,202** PolyExtStep ops and a structurally different constraint DAG. Regen-from-df6fb9d would plant the bug in a circuit that is *not* the one the CVE/Arguzz track uses. This vindicates the reviewer's comparability concern and removes df6fb9d-regen as a clean option.
3. **The surgical mechanism (`Sub(a,b)→Sub(0,0)`) is mechanically complete on the verifier**: it zeroes the value folded by **26/26** `IsRead@ReadReg` `AndEqz` steps. `ap_isread_patch.py` already implements exactly this. Route 2 did *not* fail for lack of a mechanism.
4. **NEW, decisive finding the prior reports missed:** codegen common-subexpression elimination (CSE) makes **7 of the 16 `IsRead@ReadReg` diff-wires shared** with IsRead constraints for **Poseidon, Div-decode, and Control** memory reads. Neutralizing those wires **silently widens the planted bug from "register reads only" to "all memory reads."** The committed circuit therefore **cannot host a cleanly ReadReg-scoped IsRead hole via wire surgery** — CSE merged the wires before we ever touch them.
5. **This is a genuine fork** (see §5): *surgical* gives a comparable circuit but an over-broad bug; *regen* gives a scoped bug but a non-comparable (or as-yet-unidentified) circuit. The witgen side is ReadReg-scoped under either path; only the constraint poly is broad under surgery.

A decision on §5 is needed before spending a ~40-min build.

---

## 1. On-disk state after cleanup (verified)

- `workspace/risc0-modified` **is** a git repo.
- Canonical circuit files are **git-clean and fully unholed**:
  - `risc0/circuit/rv32im/src/zirgen/poly_ext.rs` — 0 `MemoryReadNoIsRead`, 42 `IsRead…ReadReg` loc lines.
  - `risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_0.cpp` — 0 / 27.
  - `risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` — 0 / 0.
- Removed stray nested artifact `risc0/circuit/rv32im/src/zirgen/zirgen/` (existed up to **5 levels** deep, 47 MB, untracked). Canonical dir is now flat.
- `risc0/circuit/rv32im/src/zirgen/validity.rs.inc` remains **untracked** (its `.inc` siblings are tracked) — likely another regen byproduct. Left untouched; flagging for OCP.

**Composer's "stale committed everywhere" was right; my earlier "df6fb9d C++ + stale Rust" framing described a transient build state, not the on-disk reality.** The hole currently lives in **no** canonical file.

---

## 2. df6fb9d ≠ committed circuit (proven)

Method: strip `// loc(...)` comments from both `poly_ext.rs` files, compare the `PolyExtStep::` opcode sequences.

| | committed (HEAD) | df6fb9d control regen |
|---|---|---|
| PolyExtStep opcode count | **20,202** | **20,277** (+75) |

The divergence is structural, not just renumbering. Example at the same logical region:

```
committed:                 df6fb9d control:
AndEqz(807, 807)           AndEqz(807, 816)
AndEqz(808, 808)           Sub(1269, 814)
AndEqz(809, 809)           AndEqz(808, 1138)
AndEqz(810, 810)           Mul(1137, 7)
AndEqz(811, 811)           Sub(1558, 1559)
AndCond(805, 389, 812)     AndEqz(809, 1560)
                           ... (different folding/optimization)
```

**Implication:** df6fb9d is a *different zirgen revision's* codegen. A bug planted via regen-from-df6fb9d sits in a different circuit than the committed/CVE one → **not comparable**. The semantic-diff that the regen spec required (to prove equivalence) would have **failed**. This is why the regen path, even with the plumbing bug fixed, is not a clean answer.

---

## 3. Surgical verifier mechanism IS complete (26/26)

`poly_ext.rs` evaluates two arrays: `fp_vars` (`Const/ConstExt/Get/Add/Sub/Mul/...`) and `mix_vars` (`True/AndEqz/AndCond`). `AndEqz(x, val)`: `x`→`mix_vars` (accumulator), `val`→`fp_vars` (value asserted zero).

- 16 `IsRead@ReadReg` `Sub` steps produce `fp_vars` indices **{752, 753, 777, 778, 1743, 1744, 1754, 1755, 2214, 2215, 2226, 2227, 2918, 2919, 3042, 3043}**.
- The 26 `IsRead@ReadReg` `AndEqz` steps fold exactly those wires (one Sub result is shared by several AndEqz; 16 Subs → 26 folds).
- Setting each Sub to `Sub(0,0)` (≡ reviewer's `Sub(a,a)`; `x−x=0` regardless of which wire) ⇒ **all 26 AndEqz fold 0 ⇒ verifier IsRead@ReadReg constraint fully disabled.** Step counts, wire indices, and mix-fold count are preserved (no DAG renumbering), so prover/verifier stay structurally aligned.

`ap_isread_patch.py` already does precisely this (`patch_poly_ext` lines 117-119; C++ `patch_rust_poly_fp` neutralizes the corresponding `auto x = a-b` and `FpExt x = prev + inner*poly_mix[k]` folds). **The mechanism was never the problem.** Route 2's "26 AndEqz still enforce" was a misdiagnosis; its actual failure was the parallel regen corrupting the verifier poly (path-doubling), so the surgical verifier patch was never cleanly paired with a matching prover.

---

## 4. THE DECISIVE FINDING — CSE over-widens the bug

For each of the 16 "RR" diff-wires, I traced **all** AndEqz consumers and their loc chains. Result:

**ReadReg-EXCLUSIVE wires (9):** `752, 777, 1744, 2214, 2215, 2226, 2227, 2919, 3043` — folded only by `IsRead…ReadReg` AndEqz. Safe to neutralize.

**SHARED wires (7):** also folded by **non-ReadReg** IsRead constraints:

| diff-wire | also enforces IsRead under |
|---|---|
| `fp#753`  | PoseidonLoadState, PoseidonCheckOut, PoseidonLoadInShort |
| `fp#778`  | PoseidonLoadState, PoseidonCheckOut, PoseidonLoadInShort |
| `fp#1743` | PoseidonLoadState, PoseidonCheckOut, PoseidonLoadInShort |
| `fp#1754` | DivInput (decode), Poseidon{LoadState,CheckOut,LoadInShort} |
| `fp#1755` | DivInput (decode) |
| `fp#2918` | Control0 (ControlSuspend / ControlLoadRootAndNonce) |
| `fp#3042` | Control0 (ControlSuspend / ControlLoadRootAndNonce) |

### Why this happens
The constraint poly is **one polynomial evaluated per row**. `fp#753` is "this row's memory-read `dataHigh` diff," computed from fixed trace columns that the circuit **reuses across all instructions**. The codegen CSE'd this single diff and folds it into the constraint accumulator under multiple instruction-selector-gated `AndEqz`/`AndCond` blocks (ReadReg arm, Div arm, Poseidon arm, Control arm). The loc tag on the *Sub* happens to say `ReadReg` (first emission), but the *result wire* is shared.

### Consequence
Zeroing `fp#753` makes the asserted value 0 in **every** block that folds it ⇒ IsRead is no longer enforced for Poseidon-state loads, Div-decode reads, Control suspend/resume reads, etc. **The surgical patch on the committed circuit plants "IsRead disabled for all memory reads," not the spec'd "IsRead disabled for the ReadReg path."**

This is the concrete, wire-level realization of the original audit-log concern ("compositional DAG with shared sub-expressions → surgical unfeasible"). It is no longer a worry-in-principle; it is demonstrated with specific indices and loc chains.

### Witgen vs constraint asymmetry (important)
- **Witgen IS ReadReg-scoped:** `MemoryReadNoIsRead` is wired only into `exec_ReadReg` (single call-site replacement). Poseidon/Div/Control reads still run honest `exec_MemoryRead`.
- **Constraint poly is broad** (CSE, above).
- Honest proofs still pass (non-RR reads compute correct values; the now-absent constraint simply isn't checked).
- Exploitation: A4's register-read `PRE_EXEC_REG_MOD` is findable. But so would mutations on Poseidon/Control reads be — the hole is a superset.

---

## 5. The fork (OCP decision required)

| | **Surgical on committed** | **Regen (DSL-scoped)** |
|---|---|---|
| Circuit comparability with CVE track | ✅ identical circuit | ❌ df6fb9d proven-different; would need to *find the exact committed zirgen rev* |
| Bug scoping | ❌ over-broad (all memory-read IsRead) | ✅ truly ReadReg-scoped (`MemoryReadNoIsRead` is a distinct fn → no CSE merge; the constraint simply never emitted for register reads) |
| Build cost | none (patch + 1 host rebuild) | zirgen toolchain (solved, ~26 min) + rebuild |
| Risk | over-widening (documented), prover↔verifier consistency | drift / identifying correct rev |
| Testable now? | yes | needs plumbing fix + rev identification |

**Key asymmetry:** scoping is decided at the **DSL level before CSE**. Regen can scope (register reads call a distinct constraint-free function); surgery cannot (CSE already merged the wires in the committed artifact).

### Option A — Surgical, accept over-broad hole
Plant "IsRead disabled for all memory reads (⊇ ReadReg)," document the breadth, keep circuit comparability, gate strictly on mutated-V0. Pragmatic; A4 register-read mutation is findable; same-circuit comparability preserved. **Cost:** the planted "second bug" is a broad circuit break, not a minimal CVE-like single-site underconstraint.

### Option B — Regen, properly scoped
Get a clean ReadReg-scoped bug. Requires resolving drift — **ideally identify the exact zirgen revision that produced the committed circuit** (df6fb9d is not it), build it, regen with the `.zir` edit. Cleaner science; more work; comparability still must be proven via semantic-diff.

### Option C — Hybrid (likely non-viable)
Neutralize only the 9 ReadReg-exclusive wires. **Problem:** the 7 shared wires (incl. `fp#753`, a register-read `dataHigh` diff) would *still enforce* part of the register-read IsRead ⇒ register-read mutations touching those components remain rejected ⇒ the bug may not be findable. Partial hole. Not recommended without verifying which trace cell `PRE_EXEC_REG_MOD` actually moves.

---

## 6. Recommendation (reviewing Opus)

The decision hinges on what the thesis weights more: **minimal-bug fidelity** vs **same-circuit comparability**.

- If the second-bug only needs to demonstrate *A4 finds a planted IsRead underconstraint via a single trace edit*, **Option A** is the fastest path to validated science and keeps comparability. Document the breadth honestly ("IsRead enforcement removed for all memory reads; A4 tested on register reads").
- If the campaign requires a *minimal, CVE-like, ReadReg-scoped* underconstraint to mirror the Arguzz bug's specificity, only **Option B** delivers it, and it should start by **identifying the exact committed zirgen revision** (not regenerating from df6fb9d).

Either way: **honest-verify is not a gate** (Route 2 passed honest, failed mutated). The only trustworthy arbiter is a **mutated-V0 smoke** — one known `(0,1,0)` `PRE_EXEC_REG_MOD` next-read mutation must *verify* on bench and *reject* on patched — run before any 15-config bracket, via a single foreground orchestration script that exits on first failure.

Do **not** discard the zirgen toolchain / control+holed snapshots. Under Option B they are the route to the correct revision; under Option A they are the documented fallback.

---

## 7. Reproduction commands

```bash
cd /root/arguzz
RISC0=workspace/risc0-modified
POLY=$RISC0/risc0/circuit/rv32im/src/zirgen/poly_ext.rs
CTRL=a4/builds/ap/regen-snapshots/control-df6fb9dda1c2/risc0/circuit/rv32im/src/zirgen/zirgen/poly_ext.rs

# (2) df6fb9d != committed
sed -E 's#,? *// loc.*##' "$POLY" | rg 'PolyExtStep::' | wc -l   # 20202
sed -E 's#,? *// loc.*##' "$CTRL" | rg 'PolyExtStep::' | wc -l   # 20277

# (3)+(4) coverage + CSE sharing: the python in this session's tool log
#   - 26/26 RR AndEqz fold the 16 RR Subs (indices {752,753,777,...})
#   - 7 of 16 wires also folded by non-RR (Poseidon/Div/Control) IsRead

# canonical cleanliness
for f in "$POLY" "$RISC0/risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_0.cpp"; do
  echo -n "$f MemoryReadNoIsRead="; rg -c MemoryReadNoIsRead "$f"; done
```

The full analysis scripts (fp/mix index separation, consumer tracing) are inlined in the session transcript; happy to commit them as `a4/scripts/ap_poly_cse_audit.py` if OCP wants a permanent checker (recommended as a GP1 hardening: assert no neutralized wire has a non-ReadReg consumer).

---

## 8. Open questions for OCP

1. **Scope vs comparability** — Option A or B? (§5)
2. If **A**: is an "all memory-read IsRead disabled" bug acceptable as the planted A4 second-bug, and how should the writeup characterize it relative to the Arguzz/CVE bug?
3. If **B**: do we have any record of the zirgen revision used to generate the committed `risc0-modified` artifacts? (HEAD of the local `zirgen` clone is df6fb9d, which we've now shown is *not* it.)
4. Should `ap_poly_cse_audit.py` (the shared-wire checker) become a mandatory GP1 gate so future surgical attempts can't silently over-widen?
5. `validity.rs.inc` is untracked in the canonical dir — intended, or regen debris to remove?
