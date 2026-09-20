# AP.B2 — Fold-Neutralization Implementation Report

**Author:** Reviewing Opus (this session)
**Date:** 2026-06-23
**Inputs:** OCP's review of `AP_B2_FINDINGS_FOR_OCP.md` (the fork-is-a-false-dilemma correction)
**Status:** SUPERSEDED in part — see **§9 (2026-06-23 PM update)**. First build's bench-isread FAILED honest verify (`verify segment`) due to a prover-side **off-by-one** in fold identification. Root-caused and fixed; prover folds now 26/26 with the verifier; bench rebuild in progress; mutated-V0 smoke still the outstanding gate.

> ⚠️ **Corrections to this report below:** §1 fact #1 had the comment convention **backwards** (it said loc-follows-statement / key on `i+1`; the truth is **loc-precedes-statement / key on `i-1`**), and the "40 prover folds" in §1 fact #2 / §3 was a **symptom of that bug**, not a real decomposition. The corrected counts are **26 prover = 26 verifier**. See §9.

---

## 0. Verdict on OCP's correction

**OCP is right; my "fork" conclusion was wrong, and I confirmed the correction on disk.**

My prior report concluded the committed circuit *cannot* host a ReadReg-scoped IsRead hole via surgery, because CSE shares the diff wires. That was true only for *my* mechanism (zeroing the shared `Sub` wire). OCP's insight: **the constraint is enforced by the per-arm `AndEqz` fold, not the wire** — and the ReadReg folds are *separate statements* from the Poseidon/Div/Control folds even when they reference the same diff wire. Repoint only the ReadReg folds to a zero and you get scoping **and** comparability. The fork dissolves. I anchored on the existing script's wire-object; OCP correctly separated *fold* (enforcement) from *wire* (value).

---

## 1. Structural claims — all verified on disk

| OCP claim | Verified | Evidence |
|---|---|---|
| fp#0 = `Const(0)` | ✅ | line 27: `PolyExtStep::Const(0)` (first step) |
| `AndEqz(x, 0)` is an existing codegen idiom | ✅ | **181** occurrences in poly_ext.rs (e.g. lines 658, 856, 883) |
| Exactly 26 ReadReg `AndEqz`, 0 `AndCond` | ✅ | direct count |
| ReadReg and non-ReadReg folds of a shared wire are *distinct statements* | ✅ | wire 753: ReadReg folds at L862/L886; Poseidon folds at L7931/L8332/L9092 |
| Prover (rust_poly_fp) has analogous separable folds | ✅ | 16+8+10+6 = **40** ReadReg folds across the 4 files |
| C++ diffs = Rust Sub wires | ✅ | **16** C++ ReadReg diffs (`auto a-b`) = 16 Rust Sub wires |

**Two facts I add (important for the prover patch):**

1. **C++ loc comments annotate the *preceding* statement** (the loc line comes *after* the `FpExt`/`auto` it describes). The old `ap_isread_patch.py` assumed comment-precedes-statement, which is one reason it mis-touched diff lines. The new patch keys off `lines[i+1]`.
2. **Prover fold count (40) ≠ verifier fold count (26).** They decompose the same polynomial differently: verifier uses Horner-form `AndEqz`; prover uses explicit `poly_mix[k]` powers split across 4 files. **Consistency requires neutralizing *all* ReadReg folds on each side and leaving *all* diffs untouched — completeness per side, not matching counts.** The mutated-V0 build is the only test that the two polynomials still agree after neutralization.

---

## 2. What I implemented

### 2.1 `a4/scripts/ap_isread_patch.py` — rewritten to FOLD-neutralization
- **Verifier (`poly_ext.rs`):** each `IsRead@ReadReg` `AndEqz(acc, val)` → `AndEqz(acc, 0)`. The `Sub`/diff steps are **not touched**. Index-preserving (no step added/removed).
- **Prover (`rust_poly_fp_{0..3}.cpp`):** each ReadReg-tagged fold `FpExt dst = acc + inner * poly_mix[k];` → `FpExt dst = acc;` (drops the contribution; `inner` diff is preserved and still referenced by the Poseidon/Div/Control folds). Statement is identified by the **next-line** loc being `IsRead(...ReadReg...)`. Diffs (`auto a-b`) and witness reads (`auto arg0[i]`) are **never** modified.
- **Witgen** (`exec_ReadReg → MemoryReadNoIsRead`) kept (already ReadReg-scoped).
- **revert** now `git checkout`s all touched files (witgen + poly) for a pristine committed state (the old regex-revert left a cosmetic blank line in `steps.cpp`).

### 2.2 `a4/scripts/ap_poly_cse_audit.py` — rewritten as the GP1 gate for the fold mechanism
Old audit checked wire-sharing (the wrong property now that we don't touch wires). New asserts:
- **COMPLETE:** 0 active ReadReg folds remain (verifier *and* every prover file).
- **SCOPED:** `git diff` touched only sanctioned fold lines — no `PolyExtStep::Sub`, no `auto x` diff, no non-ReadReg fold (catches over-widening).
- **CONSISTENT:** both verifier and all 4 prover files were neutralized (catches prover/verifier mismatch).

### 2.3 `a4/scripts/build_ap_binaries.sh` — relabeled
Default mode (revert→build `patched` committed-clean; apply→build `bench-isread`) is now the PRIMARY surgical fold path. Removed the stale "Route 2 legacy; invalid for bracket" labels. The `--from-regen` path is retained but unused (it still contains the `src/zirgen` rsync directory entry — the path-doubling bug — so do **not** use it).

---

## 3. On-disk validation (before build)

```
$ ap_isread_patch.py status   (after apply)
applied
  witgen=True poly_ext_active=0/26 poly_fp_active=0/40 non_rr(ext=216,fp=298)

$ ap_poly_cse_audit.py
verifier poly_ext.rs : IsRead@ReadReg AndEqz active=0/26
prover rust_poly_fp_0.cpp: ReadReg folds active=0/16
prover rust_poly_fp_1.cpp: ReadReg folds active=0/8
prover rust_poly_fp_2.cpp: ReadReg folds active=0/10
prover rust_poly_fp_3.cpp: ReadReg folds active=0/6
scope violations (git diff): 0
RESULT: PASS
```

**Scoping spot-check (shared wire 753):**
```
poly_ext L862:  AndEqz(80, 0)       ReadReg fold  → NEUTRALIZED
poly_ext L886:  AndEqz(94, 0)       ReadReg fold  → NEUTRALIZED
poly_ext L7931: AndEqz(3844, 753)   Poseidon       → INTACT
poly_ext L8332: AndEqz(4009, 753)   Poseidon(Get)  → INTACT
poly_ext L9092: AndEqz(4314, 753)   Poseidon(Out)  → INTACT
prover: FpExt x423 = x421 + x422*poly_mix[6]  →  FpExt x423 = x421   (x422 diff preserved)
```
- `non_rr` IsRead lines unchanged (216 verifier / 298 prover) → no over-widening.
- `git diff --stat`: **66 insertions / 66 deletions** across the 5 poly files → strictly 1-for-1 line replacement, **no DAG renumbering** → prover/verifier wire indices stay aligned and the circuit stays index-identical to committed (full comparability with the CVE/Arguzz track).
- `revert` → empty git diff (pristine committed).

This satisfies OCP's three properties statically: **complete, scoped, consistent, comparable.**

---

## 4. Build + the real test (in progress)

Launched `build_ap_binaries.sh` (default surgical mode) → `a4/runs/iv_pos_9/ap/build_surgical_fold.log`:
1. `patched` = committed clean (revert → cargo build), fingerprint `circuit_source=committed`, `planted_bug=none`.
2. `bench-isread` = fold-neutralized (apply → cargo build), fingerprint `circuit_source=surgical`, `planted_bug=isread`, `isread_scope=reg_only`.

Both recompile the C++ circuit kernels (`rust_poly_fp_*`, `steps.cpp`), so it is not fast.

### The outstanding gate — mutated-V0 smoke (the only trustworthy arbiter)
After the build: one known `(0,1,0)` `PRE_EXEC_REG_MOD` next-read config must **verify on bench-isread** and **reject on patched**. Honest-verify and witgen logs are NOT gates (Route 2 passed honest, failed mutated). Only after the smoke passes do we run the 15-config bracket — the first real test of the campaign's `(0,1,0)` theory.

---

## 5. Residual risks (honest)

1. **Prover/verifier polynomial agreement (C2 risk).** The mechanism is structurally consistent (both sides neutralize all ReadReg folds, leave all diffs; index-preserving). But verifier (26 Horner folds) and prover (40 explicit-power folds) are different decompositions; only the build's `verify_integrity` proves the two neutralized polynomials still match. If they don't, it surfaces as a `verify segment` panic on an *honest* bench proof — caught before the bracket.
2. **The `(0,1,0)` theory itself is still untested.** Even with a perfectly scoped+consistent hole, whether removing IsRead@ReadReg makes a `(0,1,0)` read *verify* depends on the global LogUp/memory-argument balance (the open question from the feasibility doc, ~55–70% per the prior estimate). The mutated-V0 smoke answers this definitively.
3. **Witgen necessity.** `MemoryReadNoIsRead` is kept per OCP, but with the constraint folds neutralized it may be redundant (honest proofs pass regardless). Not a risk to correctness; flagged for tidy-up only.
4. **`validity.rs.inc`** remains untracked in the canonical dir (its `.inc` siblings are tracked) — likely regen debris; left untouched.

---

## 6. df6fb9d-regen — retired as the bug vehicle
Per OCP directive 5 and the proven df6fb9d≠committed result: the regen path is retired. The zirgen toolchain + control/holed snapshots are kept as unused assets (no further spend). The `--from-regen` build mode is left in place but must not be used (it carries the path-doubling rsync bug).

---

## 7. Status of OCP's 5 directives
1. ✅ Rewrite `ap_isread_patch.py` → fold-neutralization. Done + validated.
2. ✅ Rewrite `ap_poly_cse_audit.py` for the fold mechanism. Done + PASS.
3. 🔄 Build bench-isread on committed circuit; patched = committed clean. **In progress.**
4. ⏳ Mutated-V0 smoke (foreground, exit-on-first-failure) → then 15-config bracket. **Pending build.**
5. ✅ Retire df6fb9d-regen as the bug vehicle. Done (toolchain parked).

---

## 8. Relay to OCP
Correction accepted and implemented exactly as directed. The fold-neutralization patch is on disk and statically proven complete/scoped/consistent/comparable (66/66 index-preserving line swaps; shared wire 753's Poseidon folds intact while its ReadReg folds are dead). The new GP1 audit enforces all three properties and catches both over-widening and under-scoping. The build is running; the mutated-V0 smoke remains the decisive, still-unrun test of (a) prover/verifier agreement and (b) the `(0,1,0)` verify theory. No honest-verify or witgen log will be trusted as a pass.

---

## 9. 2026-06-23 PM UPDATE — honest-verify failure, root cause, and fix

### 9.1 What happened
The first build completed. The **mutated-V0 smoke failed at step 1**: the `bench-isread` **honest** proof did not verify —
```
<record>{"context":"Prover","status":"error","time":"55.97s"}</record>
thread 'main' panicked: verify segment
```
`verify segment` is the prover's segment self-verify (it runs the verifier `poly_ext` on the freshly proven segment). The honest witness has IsRead diff = 0, so neutralizing the IsRead folds should be a *no-op* on the honest polynomial — honest must verify. It didn't ⇒ prover and verifier were **not** neutralizing the same constraints (residual risk #1 from §5, materialized).

### 9.2 Root cause — prover-side off-by-one (comment convention)
The decisive evidence is on disk (`rust_poly_fp_0.cpp` ~L3332):
```
auto x422 = x79 - x77;                       // x422 = the MemoryIO:74 residual
// loc(... MemoryIO :74 ... ReadSourceRegs:53 ...)   ← annotates the line BELOW
FpExt x423 = x421 + x422 * poly_mix[6];      // x423 FOLDS x422  ⇒ x423 is a MemoryIO fold
// loc(... IsRead :79 ... MemLoadInput ...)          ← annotates x424, NOT x423
auto x424 = arg0[301];                       // x424 = the IsRead:79 value
FpExt x425 = x423 + x424 * poly_mix[7];      // x425 FOLDS x424  ⇒ x425 is the real IsRead fold
```
**The zirgen C++ codegen emits each statement's loc on the line ABOVE it (loc-precedes-statement).** Cross-check: `x423` folds the MemoryIO residual `x422`, and the comment directly above `x423` is `MemoryIO:74` — consistent only with loc-precedes-statement.

`ap_isread_patch.py` (and `ap_poly_cse_audit.py`) keyed each fold on the **next** line (`lines[i+1]`). That neutralized the folds *preceding* an IsRead comment — i.e. the **MemoryIO folds** (`x423`) — and shifted which IsRead folds got hit. The verifier `poly_ext.rs` was unaffected because there the loc is a **trailing same-line** comment, so it correctly neutralized the 26 IsRead@ReadReg `AndEqz`. Result: prover ≠ verifier ⇒ honest `verify segment`. This also explains the **40-vs-26 asymmetry** flagged in §1/§3: the buggy heuristic was hitting MemoryIO folds, inflating the prover count.

### 9.3 Fix
Changed fold identification from `lines[i+1]` → `lines[i-1]` (preceding loc comment) in `patch_rust_poly_fp`, `count_poly_fp_active`, `count_poly_fp_total` (`ap_isread_patch.py`) and `fp_active_total` (`ap_poly_cse_audit.py`). Verified on disk after revert + re-apply:
```
$ ap_isread_patch.py status
applied  witgen=True poly_ext_active=0/26 poly_fp_active=0/26 non_rr(ext=216,fp=298)

$ ap_poly_cse_audit.py
verifier poly_ext.rs : active=0/26
prover rust_poly_fp_0.cpp: active=0/12   _1: 0/6   _2: 0/6   _3: 0/2
prover TOTAL          : active=0/26
scope violations (git diff): 0   →  RESULT: PASS
```
**Prover 26 == verifier 26** (asymmetry gone). The neutralized prover folds are now `x425` (folds `x424=arg0[301]`, IsRead:79) and `x427` (IsRead:80) — the MemoryIO fold `x423` is left **intact**.

### 9.4 Corrections to earlier sections
- §1 fact #1 ("loc annotates the preceding statement… keys off `lines[i+1]`") is **wrong**. Truth: loc-precedes-statement; key off `lines[i-1]`.
- §1 fact #2 / §3 "40 prover folds" was the bug's symptom. Correct count is **26**, matching the verifier exactly.
- §5 residual risk #1 was the live failure mode; this fix addresses its prover-side cause. Whether the two neutralized polynomials now agree is re-tested by the rebuilt bench's honest verify (smoke step 1).

### 9.5 Next
Rebuilt `bench-isread` only (the committed-clean `patched` binary is unaffected by the patch fix). Then mutated-V0 smoke: step 1 (bench honest verify — now expected to pass) → step 3 (`(0,1,0)`: bench accept, patched reject). A final canonical rebuild via the full harness will restore the correct `instrumentation_hash` provenance field (the quick rebuild used `A4_INSTRUMENTATION_HASH=pending`, a cosmetic provenance-only value).
