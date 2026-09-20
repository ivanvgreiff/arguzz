# AP.B2 root cause — VERIFIED FROM SOURCE

**Date:** 2026-06-22 · **Author:** Opus (D2-Opus) · **Method:** direct inspection of the patch script, the generated constraint artifacts, the host, and the campaign oracle. Verdict below is grounded, not theory.

## Verdict
**Opus's "wrong layer" diagnosis is CORRECT.** The planted hole was cut only into the **witgen** path (`steps.cpp`); the **constraint polynomial** — what the proof's integrity check actually evaluates — still enforces `IsRead` on `ReadReg`. So `bench-isread` is "a holed witgen over an intact constraint system": the proof still fails `IsRead` and `prove_with_opts` errors. **Composer's spec-Route-2 (NOP the `eqz` in `steps.cpp`) was fundamentally incapable of creating a verifier-respected hole — and that was MY spec's error, not Composer's.**

## The facts (all verified)
| Claim | Evidence |
|---|---|
| Patch touches witgen only | `a4/scripts/ap_isread_patch.py` edits `steps.cpp/.cu/.cuh` (lines 23-25) — never `rust_poly_fp_*` / `poly_ext.rs` |
| Constraint poly **still** has `IsRead@ReadReg` | `rust_poly_fp_{0,1,2,3}.cpp` = **27/15/14/10 = 66** terms; `poly_ext.rs` = **42** terms |
| The proof is checked by a poly-based integrity verify | host `prove_with_opts(...) → Err → panic!(error)`; the error context is "verify segment" = the prover's internal `verify_integrity_with_context` (`zkvm/src/host/client/prove/external.rs:58`), which evaluates the constraint polynomial |
| `ProverOpts::fast()` still self-verifies each segment | empirically — the run errors with "verify segment" after a full ~20s prove |

## Why this reproduces every symptom
- **bench: 0 logged constraint_failures, layers (0,0,0), yet still panics.** Witgen `IsRead` was removed → witgen logs nothing (it's blind). But `poly_fp`/`poly_ext` `IsRead@ReadReg` is intact → `verify_integrity` rejects the mutated read → `prove_with_opts` errors → host panics. The "0 failures" is exactly the fingerprint of a witgen-only hole.
- **patched: 1 logged IsRead failure, (0,1,0), also panics.** Witgen `IsRead` present → logs once; poly `IsRead` present → also rejects. (This side is the *correct* reject bracket.)
- **bench and patched fail identically at verify** — their constraint polynomials are identical (only witgen differs).
- **V0 honest smoke passed on both** — no mutation ⇒ `read==prev_word` ⇒ `IsRead` is *satisfied* everywhere ⇒ verify passes. The hole is only exercised under mutation, which V0 never did → false confidence.

## Directly answering Ivan's two skepticisms (you were partly right on each)
1. **"A4 flags bypass non-circuit checks."** True for the **witgen** layer: `CONSTRAINT_CONTINUE=1` makes the witgen `eqz` *log-and-continue* instead of throw, and `FAULT_INJECTION_ENABLED` skips the "unreachable mux arm" asserts. But **`verify_integrity` is a circuit check** — it evaluates the constraint polynomial (`poly_fp`/`poly_ext`) — and A4 flags do **not** touch it. So the proof still fails. Your mental model is right for the witgen layer; the proof-validity layer is a separate circuit check that isn't bypassed.
2. **"This error isn't even a circuit constraint failing."** It **is** a circuit constraint (`IsRead` in the constraint polynomial) failing — but it shows **0 logged constraint failures** because the witgen copy was removed, so it *looks* like "nothing failed." That mismatch is precisely the symptom of a hole in the wrong layer.

## The insight that settles it (and rebuts Composer's H1/H4)
**The campaign's own soundness oracle is verify-based, not witgen-based.** `_classify_outcome` sets `soundness_signal=True` iff `prover_status=="success"` (`a4/standalone/arguzz_invoke.py:97-98`), and `prover_status="success"` ⟺ `prove_with_opts` returned `Ok` ⟺ the prover's `verify_integrity` (poly) passed. So:
- The AP bracket oracle (require an actual Verifier-success) was **correct**, not too strict (Composer's H4 is wrong; H1 is right that (0,1,0)-on-patched does not imply bench-accept — because the binary was never truly holed).
- A witgen-only hole produces **zero** false accepts **even in a real campaign** — it just errors at verify. So to *ever* register a real soundness accept (CVE **or** planted), the constraint must be **absent from the constraint polynomial**, not just witgen.
- Corollary: **planting ANY soundness bug = editing the constraint polynomial.** This was the spec's blind spot; it applies to Seam B too.

## The (0,1,0) theory is still UNTESTED
We have learned nothing yet about whether removing `IsRead` makes those reads verify, because `bench-isread` was never a genuinely holed circuit. The E5 `(0,1,0)` evidence remains consistent and untested; once a real holed binary exists, V1 (one mutated config → bench accepts, patched rejects) is still the real test.

## Fix
1. **Remove `IsRead@ReadReg` from the constraint polynomial, consistently with witgen.** Two routes:
   - **Route 1 — zirgen regen (drift-proof, preferred):** modify `mem.zir`/`inst.zir` (`ReadReg` → `MemoryReadNoIsRead`) and regenerate **all** artifacts — `steps.*`, `rust_poly_fp_{0..3}.cpp` (+ CUDA), `poly_ext.rs`, `layout`/taps — from the single `.zir` source. *Caveat:* zirgen is a Bazel/MLIR compiler (`zirgen/Cargo.toml`, `zirgen/dsl`); it is **not prebuilt** here and the rv32im-sys build uses the committed `.cpp` (does not auto-regen), so this is a real toolchain lift. Attempt it first — it's the only no-drift path.
   - **Route 2 — symmetric surgical patch (pragmatic fallback):** extend `ap_isread_patch.py` to ALSO zero the `IsRead@ReadReg` folded terms in all four `rust_poly_fp_*.cpp` **and** `poly_ext.rs` (and CUDA poly variants), using the loc-comment tags (`// loc(... IsRead ... at ReadReg ...)`). ~66 C++ + 42 Rust = ~108 tagged sites; leave RAM/fetch `IsRead` intact. The same poly is used by prove+verify, so it stays self-consistent.
2. **Harden the GP1 gate.** Assert **zero** `IsRead@ReadReg` remains in `rust_poly_fp_*.cpp` **and** `poly_ext.rs` on `bench-isread` (and that RAM/fetch `IsRead` terms *do* remain). This single check would have caught the bug before the 600-job screen.
3. **Add a MUTATED smoke to V0.** Build validation must run **one (0,1,0) mutated config** (not just an honest run) → bench **accepts**, patched **rejects**. Honest-only smoke gives false confidence.
4. **Then re-run the bracket** (V1/V2). Only after a genuinely holed binary verifies a mutated (0,1,0) config is GP4/GP5 meaningful.

## What changes in the spec
- `IV_POS_9_AP_PLANTED_ISREAD_SPEC.md` §2.2 "Route 2 (NOP `IsRead` EQZ in `steps.cpp`)" is **deleted as invalid** — it only edits witgen. The correct paths are zirgen-regen or the symmetric poly_fp+poly_ext patch (above).
- GP1 extended to assert no `IsRead@ReadReg` in `poly_fp`/`poly_ext` on bench.
- V0 extended with the mutated smoke.
- The general rule added: **a planted soundness hole must be removed from the constraint polynomial, not the witgen `eqz`.**
