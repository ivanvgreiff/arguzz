# The Seam-B Planted Underconstraint — Deep Report

*How we manufactured an A3-findable soundness hole in RISC Zero, why Arguzz structurally cannot find it, and what the bug race measured.*

This is the **mirror** of the `rs1==rs2` CVE (CVE-2025-52484). The CVE is a *real* bug that only **Arguzz** (during-execution, value-propagating) can reach. Seam-B is a *planted* bug that only **A3** (post-execution, single-cell trace edits) can reach. Together they form the two halves of the surface-complementarity claim.

---

# PART 0 — The intuitive version (read this first)

### Q1. What is the bug, in one sentence?

We removed the circuit's check that **the instruction a cycle *claims* to be must match the instruction word actually *fetched* from memory.** With that check gone, a prover can keep the real instruction word in memory but tell the circuit "this cycle ran a *different* instruction" — and the proof still verifies.

### Q2. Why did we plant it?

The real CVE is **Arguzz territory** — it needs a value-corrupting fault that propagates through execution, which A3's single-cell edits cannot produce. If the *only* bug in our experiments were the CVE, A3 would lose by construction and we'd learn nothing about A3's reach. So we engineered a **second, disclosed bug deliberately shaped for A3** — one that A3 can find and Arguzz cannot. Now each surface has a bug only *it* can reach, and the race becomes a clean test of complementarity rather than a foregone conclusion.

### Q3. How did we make it (in plain words)?

A RISC Zero proof has two facts about every cycle:
- the **instruction word** it fetched (lives in the tamper-proof memory argument — you can't lie about this), and
- the **instruction type** it claims to be running (a small selector: "this is an ADD", "this is a SUB", …).

One constraint — `VerifyOpcode` — ties those two together ("the type you claim must match the bits of the word you fetched"). **We surgically deleted that constraint** from the compiled circuit. We did *not* touch anything else — not the word, not the result-write check. So the hole is razor-thin: a cycle can now claim the wrong instruction type, but everything else still has to add up.

### Q4. Why can A3 find it but Arguzz can't?

Because they tamper with **different things**:
- **A3's `INSTR_TYPE_MOD`** edits the *recorded type label* (`major/minor`) **while leaving the fetched word alone** → it creates exactly the type-vs-word mismatch the deleted check used to catch. Bingo.
- **Arguzz's `INSTR_WORD_MOD`** edits the *fetched word itself*, during execution. The circuit then re-decodes that mutated word and the type it derives *matches* — so there's no mismatch to exploit, and the deleted check was never the thing standing in the way. Arguzz literally **has no mutation kind that edits the type label** — `INSTR_TYPE_MOD` is not in its toolbox.

So Arguzz missing this bug isn't a search-efficiency loss — **the bug is simply off Arguzz's attack surface.**

### Q5. There's a subtlety — only *some* type-swaps work. Why?

We deleted *only* the decode check, **not** the result-write check (`MemoryWrite`). So if a type-swap would change the computed result (e.g. AddI→And), the still-intact result-write check catches it. Only **result-preserving** swaps slip through — e.g. on a "move" instruction (`addi rd, rs, 0`), relabeling AddI→{Add, Or, Sub, Xor} produces the *same* value, so nothing else objects. In the certification bracket, exactly **12 of 56** swaps accepted (the result-preserving ones); the other 44 were correctly caught by the un-holed result-write check. That 44-caught is a *feature* — it proves the hole is precisely scoped to the decode binding.

### Q6. Did the race confirm the hypothesis?

**Yes, decisively.** Across 10 seeds × N=5000 on the holed binary:

| Variant (thesis name) | Surface | Found the bug? | Total finds |
|---|---|---|---|
| **A3 Bandit** (`V5_control`) | A3 | **10/10 seeds** | **821** |
| **A3+Arguzz Bandit** (`Hybrid_cTS`) | A3+Arguzz | **10/10 seeds** | **389** |
| **Arguzz Bandit** (`V6_cTS`) | Arguzz | **0/10 seeds** | **0** |
| **Arguzz** (`V6_uniform`) | Arguzz | **0/10 seeds** | **0** |

The two A3-bearing variants find it on *every* seed, as early as mutation #17–19. The two pure-Arguzz variants find it *never* — and they applied `INSTR_TYPE_MOD` exactly **zero** times across ~94,700 mutations, because the kind isn't in their pool. Clean complementarity.

---

# PART 1 — The full report

All `path:line` citations are verbatim from `/root/arguzz`, cross-checked against source, the patch script, the result JSON, and the race databases (queried live).

## 1. Context: the "AP track" and the two seams

The **AP track** ("planted-benchmark" / positive-control track, à la LAVA/Magma) exists to give the A3 surface a *real, disclosed, findable* soundness bug, so the Arguzz-vs-A3 bug race has a target on the A3 side complementary to the CVE on the Arguzz side. Goal, verbatim (`AP_TRACK_AUDIT_LOG.md` §0): *"a second soundness bug on top of the CVE that is findable by a single post-execution A4 trace edit and still produces a RISC Zero proof that verifies."*

**Two underconstraints were attempted. Only the second is live.**

| | **Seam-A (IsRead)** | **Seam-B (VerifyOpcode)** ← *the subject* |
|---|---|---|
| What is removed | register-read consistency (`IsRead` on `ReadReg`) | decode equality (`VerifyOpcode*`) |
| A3 kind that finds it | `PRE_EXEC_REG_MOD` (`next_read`) | **`INSTR_TYPE_MOD`** |
| Verdict | **DEAD** | **LIVE / CERTIFIED** |
| Why | the register value is in the global memory permutation, which independently re-catches the edit (and `(0,1,0)` register reads are pointers → witgen SIGSEGVs before the residue phase). *"No single-cell post-exec edit of a memory-resident value can produce a verifying witness — defense-in-depth via the global memory permutation."* (`IV_POS_9_AP_PLANTED_ISREAD_SPEC.md`, "SEAM A IS DEAD") | the type selector is **not** in the permutation, so removing the *only* local guardian is sufficient |
| Race target? | No | **Yes** |

> **Important provenance note.** The working-tree `zirgen` submodule shows local `.zir` edits (`MemoryReadNoIsRead` in `mem.zir`, `ReadReg` repointed in `inst.zir`). **Those are the *dead Seam-A* plant, not Seam-B.** Seam-B was *not* built by editing `.zir` — see §3. Do not conflate them.

Verbatim, the dead Seam-A edit still sitting in the working tree (`zirgen/circuit/rv32im/v2/dsl/mem.zir`):
```zir
// AP planted-benchmark variant: register-read path only (ReadReg in inst.zir).
// Omits IsRead so PRE_EXEC_REG_MOD next_read can yield accepted-invalid proofs.
component MemoryReadNoIsRead(cycle: Reg, addr: Val) {
  io := MemoryIO(2*cycle, addr);
  IsForward(io);                       // ← omits the IsRead(io) line that MemoryRead has
  GetData(io.newTxn, 0, 1)
}
```
The `VerifyOpcode*` components in `inst.zir:90–105` are **unmodified** in the working tree — Seam-B lives only in the compiled circuit of `workspace/risc0-seamb`.

## 2. The constraint we removed: `VerifyOpcode`

Source of truth — `zirgen/zirgen/circuit/rv32im/v2/dsl/inst.zir:89–105`:
```zir
#[picus_inline]
component VerifyOpcode(decoded: Decoder, opcode: Val) {
  decoded.opcode = opcode;
}
#[picus_inline]
component VerifyOpcodeF3(decoded: Decoder, opcode: Val, func3: Val) {
  decoded.opcode = opcode;
  decoded.func3 = func3;
}
#[picus_inline]
component VerifyOpcodeF3F7(decoded: Decoder, opcode: Val, func3: Val, func7: Val) {
  decoded.opcode = opcode;
  decoded.func3 = func3;
  decoded.func7 = func7;
}
```

Each binds the `Decoder`'s view of the **fetched word** to the **encoding constants** of the claimed instruction type. The wiring that makes this the *sole* type↔word link:

- The fetched word enters via `DecodeInst` (`inst.zir:25–34`): `load_inst := MemoryRead(cycle, pc_addr); Decoder(load_inst)`. Because it's a `MemoryRead`, the word lives in the **global memory permutation** — tamper-evident.
- The claimed type enters via `InstInput` (`inst.zir:8–15`): `major`/`minor` with `minor_onehot := OneHot<8>(minor)` — a pure **selector**, **not** in the permutation.
- `VerifyOpcode*` is the **only** intra-row equality tying the selector to the fetched word. Each per-instruction arm (`OpADD`, `OpSUB`, `OpSLT`, `OpSRL`, …) invokes the appropriate tier with its required `opcode/func3/func7` constants.

**So: delete `VerifyOpcode*` and the claimed instruction type is no longer bound to the fetched word.** A prover may relabel a cycle's type freely; the fetched word stays permutation-consistent but its *interpretation* is unconstrained. That is exactly the cell A3's `INSTR_TYPE_MOD` edits.

## 3. How the underconstraint was made (the surgical patch)

The hole was **not** created by editing `.zir`. It was applied as a **surgical fold-neutralization of the committed, generated circuit** in an isolated worktree.

**Build layout:**
- **Base commit `93bda33b`** — a clean tree carrying the full A4 instrumentation (`A4_GLOBAL_RESIDUE`, `A4_MUTATION_CONFIG`, the `INSTR_TYPE_MOD` handler). Confirmed live: `git -C workspace/risc0-seamb rev-parse HEAD = 93bda33b…`, "HEAD detached at 93bda33b".
- **Worktree `workspace/risc0-seamb`** — control = clean checkout; holed = clean + patch.
- **Build workspace `workspace/output-seamb`** — cloned from `output-trackb`, four path-deps repointed to `risc0-seamb`, minimal ALU guest. `cargo build --release -p risc0-host`.
- **Archived pair** `a4/builds/ap_seamb/{control, bench-verifyopcode}/`: control sha `4e0f841c…` (`planted_bug=none`), holed sha `53ee6663…` (`planted_bug=verifyopcode`), both head `93bda33b…`, both `load_rs2=1`, identical guest `1f5b9372…` (`ap_seamb_verify.json:5–9`).

**Why a surgical patch and not a `.zir` regen?** Hard-won (`AP_TRACK_AUDIT_LOG.md` §3, `AP_B2_ROOT_CAUSE.md`): a planted soundness hole must be removed from the **constraint polynomial** (what `verify_integrity` evaluates), *not* the witgen `eqz` (a screening assert). An early attempt cut the hole only out of witgen → "0 logged failures yet the proof still rejected at `verify segment`". RISC Zero also **vendors** (checks in) the codegen output, so editing `.zir` doesn't change a `cargo build` unless you regen-and-copy — a path that consumed ~2 days to offline toolchain/OOM/rsync-path-doubling issues before being abandoned. The settled technique is the surgical patch below.

**The patch — `a4/scripts/ap_verifyopcode_patch.py`.** It edits **five generated files across three artifacts** in `risc0-seamb` (`ap_verifyopcode_patch.py:35–40`), each with a different transformation:

| Artifact | File | Count | Transformation (verbatim) |
|---|---|---|---|
| **Witgen** | `risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` | **111** | `EQZ(<expr>, "..VerifyOpcode..")` → `EQZ(Val(0), "..")` (`:73`) |
| **Verifier** | `risc0/circuit/rv32im/src/zirgen/poly_ext.rs` | **74** | `PolyExtStep::AndEqz(acc, val)` → `PolyExtStep::AndEqz(acc, 0)` (`:92`) |
| **Prover** | `risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_{0,1,2,3}.cpp` | **74** | `FpExt dst = acc + inner * poly_mix[k];` → `FpExt dst = acc;` (`:117`) |

The selectors (`ap_verifyopcode_patch.py:48–53`):
```python
STEPS_EQZ_RE       = re.compile(r'^(\s*)EQZ\((.+?), ("loc\(callsite\( VerifyOpcode.+)\);\s*$')
POLY_EXT_ANDEQZ_RE = re.compile(r"^(\s*)PolyExtStep::AndEqz\((\d+),\s*(\d+)\),(.*)$")
CPP_FOLD_RE        = re.compile(r"^(\s*)FpExt (x\d+) = (x\d+|arg\d+) \+ (\S+) \* poly_mix\[(\d+)\];\s*$")
```

Verbatim before/after (re-derived live via `git diff HEAD`):
```
# steps.cpp:1436 (witgen) — assert always-true instead of the equality
- EQZ(x2,      "loc(callsite( VerifyOpcodeF3F7 ( ...inst.zir :102:19) at OpSRL ...)))");
+ EQZ(Val(0),  "loc(callsite( VerifyOpcodeF3F7 ( ...inst.zir :102:19) at OpSRL ...)))"); // AP_PLANTED VerifyOpcode neutralized

# poly_ext.rs:947 (verifier) — repoint the AndEqz VALUE operand to register 0 (Const(0))
- PolyExtStep::AndEqz(0, 806), // loc(... VerifyOpcodeF3F7 ... at OpADD ...
+ PolyExtStep::AndEqz(0, 0),   // AP_PLANTED VerifyOpcode neutralized // loc(...)

# rust_poly_fp_0.cpp:644 (prover) — drop the mixing term so the fold is a pass-through
- FpExt x296 = arg3 + x291 * poly_mix[1];
+ FpExt x296 = arg3; // AP_PLANTED VerifyOpcode neutralized
```

**Three properties make this correct and razor-thin:**

1. **Fold-neutralization, not wire-zeroing.** The patch never zeroes the shared `Sub` diff-wire (CSE-shared across instruction arms; zeroing it would over-widen the hole). It only removes the *fold* that adds the equality into the polynomial. Confirmed live: zero `PolyExtStep::Sub` lines carry the `AP_PLANTED` tag; the diff-wires sit untouched beside the neutralized folds.

2. **Honest-preserving.** On an honest trace the fetched word genuinely decodes to the claimed type, so each equality already holds (its diff-expression is already 0). Replacing a vacuously-true assertion with `Val(0)` / a zero fold leaves honest prove+verify unchanged. Verified: both control and holed binaries honest-verify (holed at 71.94 ms); global residue zero on both.

3. **Prover == verifier consistency (the `74==74` gate).** RISC Zero's verify re-evaluates the constraint polynomial; the prover's evaluation (`rust_poly_fp_*`) and the verifier's replay (`poly_ext.rs`) must compute the *identical* polynomial. Neutralizing `N` folds on one side but `M≠N` on the other makes honest verify fail. The patch neutralizes the same `VerifyOpcode` folds on both sides (both key on the same loc-comment), and both transformations are **index-preserving** (AndEqz keeps its accumulator operand; the prover keeps its destination — neither adds/removes a step). The script enforces this: `status` prints `prover==verifier total: 74==74 -> OK` and refuses to build on mismatch.

**Verified counts** (`python ap_verifyopcode_patch.py status` on the applied worktree, + independent marker grep): witgen `0/111` active, verifier `0/74`, prover `0/74`, `74==74 OK`. (The build spec's `~110`/`235 refs` are pre-build *estimates*; the realized counts are **111 / 74 / 74**.) The 111-vs-74 mismatch is expected and harmless: witgen `EQZ` are execution-side asserts, not part of the soundness polynomial — only the 74 poly folds are constraints; only the two poly artifacts must match each other.

## 4. How A3 finds it — every way, with the result-preserving caveat

**There is exactly one A3 mutation kind that reaches the hole: `INSTR_TYPE_MOD`** (it edits `cycles[].major`/`minor`). It is the primary and *only* certified path.
- `instr_type_mod.py:11–13`: *"A4's INSTR_TYPE_MOD directly modifies cycles[].major and/or cycles[].minor, creating a mismatch that triggers VerifyOpcodeF3 constraint failures."*
- `AP_SEAM_B_VALIDATED.md`: it is *"the only mutation class observed to reach the verify hook with a balanced global argument"* (measured 161/250 global-clean; ALU→ALU keeps the LogUp balanced — `40/40 a4_global_residue_zero` on the *unholed* circuit).

**`INSTR_WORD_MOD_FULL`/`_SUR` are NOT additional paths**, even when launched from the A4 surface. They edit the *fetched word* (a memory-bound cell), which always breaks the global memory family — they never produce the silent *type-vs-word* mismatch. (`IV_POS_9_AP_SEAM_B_BUILD_SPEC.md:239`: "`INSTR_WORD_MOD` (full+sur) always breaks global (memory family)".) The exclusion is by the word-vs-type mechanism, not by which harness issues it.

**The certification bracket (the result-preserving requirement).** A 56-config bracket (`AddI→{Add,Sub,Xor,Or,And,Slt,SltU}` × 8 source cycles), `ap_seamb_verify.json:14–23`:
- `bracket_total: 56`, `holed_accept: 12`, `holed_reject_at_MemoryWrite: 44`.
- The 12 accepters are `AddI→{Add,Or,Sub,Xor}` at cycles **1091, 1829, 2418** — the `mv`-like `addi rd,rs,0` cycles.
- All 12 **reject on the control** at `VerifyOpcodeF3F7` (`inst.zir:102/103/104` in the committed circuit).

**Why only result-preserving slips through** (`AP_SEAMB_RESULT.md:48–55`, `AP_SEAMB_OPTION_B_ANALYSIS.md:11–15`): `INSTR_TYPE_MOD` edits only `major/minor`; it does **not** re-execute, so the rd-write transaction keeps the *original* (AddI) result. The witgen recomputes the *new* op's result, and the **un-holed** `MemoryWrite` (`io.newTxn.dataLow/High = data.low/high`) binds the kept value to the recomputed one. For a `mv`-like cycle, `Add/Or/Sub/Xor` all yield the same value as `AddI`, so the rd-write stays consistent and the *only* discriminating guardian was the (now-removed) decode check → accept. `And/Slt/SltU` change the result → caught by `MemoryWrite`. **The 44 rejects prove the hole is scoped to the decode binding; result integrity was not weakened.**

## 5. Why Arguzz cannot find it — structural + mechanistic

**Structural (the decisive reason).** Arguzz's mutation pool does not contain `INSTR_TYPE_MOD`. Confirmed in `arguzz_bridge.py:48–67`: both `MUTATION_KINDS_ARGUZZ_FULL` and `MUTATION_KINDS_ARGUZZ_SELECTED` contain `"INSTR_WORD_MOD"` but **neither contains `INSTR_TYPE_MOD`**. The race spec states it as fact F7 (`IV_POS_9_A3_SEAMB_RACE_SPEC.md:35`): *"`INSTR_TYPE_MOD` ∈ A4 arm universe, ABSENT from `MUTATION_KINDS_ARGUZZ_FULL/_SELECTED` ⇒ Arguzz CANNOT apply it."*

**Mechanistic (why the type edit is the *only* way in).** Arguzz's instruction fault is `INSTR_WORD_MOD`, which edits the *fetched word* during execution (`instr_word_mod.py:38–52`: it sets both `txn.word` and `txn.prev_word` so `IsRead` still passes, "but the circuit now 'sees' a different instruction word"). The circuit re-decodes that mutated word and the type it derives **matches the word** — there is no type-vs-word mismatch, so the removed `VerifyOpcode` binding was never what stood in the way. A3's `INSTR_TYPE_MOD` does the inverse: edits the *recorded type* while the **word stays original**, producing exactly the mismatch the binding guarded (`AP_SEAM_B_VALIDATED.md:51–54`).

**This is the explicit mirror of the CVE.** Value/memory underconstraints (writing a wrong result) are permutation-bound and need a propagating during-execution witness — *Arguzz territory*; A3's single cell cannot produce them. Decode-label underconstraints are selector-bound and need a post-execution label edit — *A3 territory*; Arguzz has no kind for them. The hypothesis is framed as **falsifiable**: any Arguzz find (via some other route producing an accepted decode-divergent trace) would be a real, important result — the oracle checks *every* accept, so it would be credited.

## 6. The bug race — design, oracle, measured results

### 6.1 Design

Four variants race on the holed binary, full N=5000, no stop-on-first-bug, every find + its mutation index recorded (`IV_POS_9_A3_SEAMB_RACE_SPEC.md`). Variants (`race_lib.py:37–49`; code name → thesis display):

| code name | thesis display | surface | scheduler | can apply `INSTR_TYPE_MOD`? |
|---|---|---|---|---|
| `V5_control` | **A3 Bandit** | A3 / post-exec | cTS bandit | Yes |
| `Hybrid_cTS` | **A3+Arguzz Bandit** | A3 + Arguzz | cTS bandit | Yes |
| `V6_cTS` | **Arguzz Bandit** | Arguzz | cTS bandit | **No (structural)** |
| `V6_uniform` | **Arguzz** | Arguzz | uniform | **No (structural)** |

### 6.2 The oracle (how a "find" is confirmed) — `a4/runs/iv_pos_9/race/oracle.py`

A mutation is a confirmed planted find iff **all three** hold:
1. **Holed-accept via the universal column** — `WHERE outcome='applied' AND verifier_accepted=1` (`oracle.py:47–68`). It must use `mutations.verifier_accepted`, **not** `config_json.soundness_signal` (which is Arguzz-only — reusing the CVE oracle verbatim would report A3=0). This is the single most important harness fix.
2. **Decode-divergent** — `kind=='INSTR_TYPE_MOD'` AND claimed `(major,minor)` ≠ the word's `(original_major, original_minor)` (`oracle.py:71–82`).
3. **Control rejects at `VerifyOpcode`** — re-run the exact config on the *control* binary with `CONSTRAINT_CONTINUE=1`; the `<constraint_fail>` locus must contain `"VerifyOpcode"` (`oracle.py:85–118`). This excludes benign no-ops that accept on *both* binaries.

The oracle is a **falsifier**: every accept (including non-ITM) is control-checked, so a hypothetical Arguzz decode-divergent accept *would* be credited; an ITM accept whose control does not reject @VerifyOpcode is flagged `UNEXPECTED`.

### 6.3 Measured results (Generation 1, `a3seamb`, 40 local DBs, 10 seeds × N=5000)

Per-variant aggregate:

| variant | P(found) | applied (Σ) | accepts (Σ) | `INSTR_TYPE_MOD` applied (Σ) | **finds (Σ)** | cond. find density | first find idx (when found) |
|---|---|---|---|---|---|---|---|
| **A3 Bandit** (`V5_control`) | **10/10** | 49,618 | 16,148 | 12,132 | **821** | **6.77%** | 17–19 |
| **A3+Arguzz Bandit** (`Hybrid_cTS`) | **10/10** | 48,779 | 8,684 | 5,410 | **389** | **7.19%** | 17–513 |
| **Arguzz Bandit** (`V6_cTS`) | **0/10** | 47,372 | 2,905 | **0** | **0** | — | never |
| **Arguzz** (`V6_uniform`) | **0/10** | 47,332 | 1,845 | **0** | **0** | — | never |

Spot-confirmed live, seed 1234: `V5_control` 70 finds (first at id 19), `Hybrid_cTS` 30 (first at id 19), `V6_uniform` 0/0, `V6_cTS` 0/0.

**Accept-by-kind — the structural proof.** Pure-Arguzz accepts are entirely `INSTR_WORD_MOD`/`POST_EXEC_PC_MOD` (benign no-ops the oracle's @VerifyOpcode check correctly excludes) with **zero `INSTR_TYPE_MOD`**. Across all 40 DBs there are 1210 `INSTR_TYPE_MOD` accepts (821 V5 + 389 Hybrid) and **0** are non-decode-divergent → every ITM accept is a genuine find, 0 `UNEXPECTED`. A sample find (V5 s1234, id 19): `INSTR_TYPE_MOD step=3172`, `original SrlI → mutated MulHU` — a real decode substitution.

**Verdict:** the two A3-bearing variants find the bug on *every* seed; pure Arguzz finds it *never* and applied the required kind zero times across ~94,700 mutations. The two A3 variants share a near-identical bug-intrinsic conditional rate (6.77% vs 7.19%), confirming the rate is a property of the bug, not the scheduler. **"Arguzz = 0" is tested (the falsifier ran on every accept and credited nothing), not assumed.**

## 7. Caveats and severity

1. **3-dead-kind contamination (bounded; headline UNAFFECTED).** The Gen-1 binary (head `93bda33b`) lacks witgen handlers for `TXN_PREV_WORD_MOD`/`TXN_PREV_CYCLE_MOD`/`CYCLE_DIFF_COUNT_MOD` (added later in `6556e8d7`), so those 3 kinds silently no-op (`applied==accepted` exactly, 0 failures). This inflates the *non-planted* accept counts and the `applied` denominator, and slightly inflates the bandit variants' *absolute* find counts (the cTS budget the dead arms vacate flows to ITM). It does **not** affect `P(found)` or the conditional find density (both bug-intrinsic). Arguzz (V6) never touches those kinds, so its 0/0 result is exact and binary-invariant.
2. **Fixed re-run (Generation 2, `a3seambfix`, on POS — not yet local).** A scheduler-ablation re-run on a **fixed** binary (head `f3c659a8`, cherry-pick `6556e8d7` → all 3 kinds live) adds **V0** (A3 surface, uniform/no-bandit) and **V8** (A3 surface, Arguzz-style round-robin) to isolate the *scheduler* effect while holding the A3 surface fixed (V0→V8→V5), and re-runs V5+Hybrid to retire the contamination footnote. Smoke-validated on POS (3 kinds live, bug findable; first thesis job deep-validated: 10/10 sampled ITM accepts confirmed REAL @VerifyOpcode, 52 `INSTR_WORD_MOD` accepts correctly excluded).
3. **Severity (honest framing).** A find = an accepted proof whose instruction type contradicts the fetched word, **with no value change** (result-preserving). It is a genuine soundness underconstraint but a **non-propagating, decode-scoped** one — by design. The CVE is the propagating, value-corrupting counterpart. Reporting them as a complementary pair is the honest framing.

## 8. Source & documentation inventory

**Source / build artifacts:**
- `a4/scripts/ap_verifyopcode_patch.py` — the fold-neutralization patcher (`{apply|revert|status}`).
- `a4/scripts/build_seamb_fix.sh` — builds the fixed pair (cherry-pick `6556e8d7`).
- `workspace/risc0-seamb` (worktree @ `93bda33b`) — the holed/control circuit; `workspace/output-seamb` — build workspace.
- `a4/builds/ap_seamb/{control, bench-verifyopcode}/` — Gen-1 binaries; `a4/builds/ap_seamb_fix/` — Gen-2 fixed pair.
- `zirgen/zirgen/circuit/rv32im/v2/dsl/inst.zir:90–105` — the `VerifyOpcode*` DSL source.

**Specs & results (`a4/docs/cloud3/`):**
- `IV_POS_9_AP_SEAM_B_BUILD_SPEC.md` — the Seam-B build spec (primary build doc).
- `IV_POS_9_A3_SEAMB_RACE_SPEC.md` (+ `_REVIEW.md`) — the race design + oracle + falsifier framing.
- `HOW_WE_MANUFACTURED_THE_UNDERCONSTRAINT.md` — plain-language narrative (Seam-A fail → Seam-B work).
- `AP_TRACK_AUDIT_LOG.md`, `AP_B2_ROOT_CAUSE.md`, `AP_ZIRGEN_EXTERNAL_FALLBACK.md`, `IV_POS_9_AP_PLANTED_ISREAD_SPEC.md` — the AP-track journey + the dead Seam-A.

**Validation & race data (`a4/runs/iv_pos_9/`):**
- `ap/AP_SEAM_B_VALIDATED.md` — the premise proof (ALU→ALU keeps permutation balanced; sole guardian = VerifyOpcode).
- `ap/seamb/AP_SEAMB_RESULT.md`, `ap/seamb/ap_seamb_verify.json` — the 12/56 certification (PASS).
- `ap/seamb/{AP_SEAMB_REVIEW.md, AP_SEAMB_OPTION_B_ANALYSIS.md, mutated_v0.py}` — independent review + scope analysis + harness.
- `race/oracle.py`, `race/race_lib.py`, `race/A3_1_REPORT.md`, `race/POS_RUNBOOK.md`, `race/CONTAMINATION_IMPACT_VERIFICATION.md`.
- `race/thesis_results/a3seamb_thesis_b{1..5}/` — the 40 Gen-1 result DBs.

---

*Report compiled 2026-06-28. All numbers measured or re-derived from source; race numbers queried live from the result DBs (V5 seed-1234 spot-check: 70 finds / first at id 19; V6 = 0/0).*
