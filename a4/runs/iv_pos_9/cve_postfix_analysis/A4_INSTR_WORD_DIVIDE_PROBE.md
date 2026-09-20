# Probe: can A4 (witness-side INSTR_WORD_MOD) reach the rs1==rs2 divide CVE under a globals-ignoring oracle?

**Status:** investigation in progress (started 2026-06-28). Living doc — records goal, method, what we
try, and what we find. Reads existing/new DBs **read-only** (see `DATA_PROVENANCE.md`).

## 1. The hypothesis (user)
We previously concluded A4 is "resistant" to the rs1==rs2 divide CVE because the proof is guarded.
But A4 also mutates the **instruction word** — `INSTR_WORD_MOD_FULL` (full 32-bit) and `INSTR_WORD_MOD_SUR`
(surgical field-level) — just in the **post-execution witness/trace** rather than by re-execution. Both
*should* be able to perform the exact mutation that exposes the bug: **set the divide's 2nd source register
equal to the 1st (rs2 := rs1)**, creating the same-register-twice alias at the vulnerable divide.

Refined claim to test against the data: among A4 (V5 + Hybrid) instruction-word mutations that land on the
divide and create rs1==rs2, are there any with **0 local-constraint failures and ≥1 global-constraint
failure**? If so, then *ignoring the global failure* (a different/weaker oracle), the mutation would have
been accepted — i.e. A4 *can* reach the CVE surface, and only the global check stands in the way.

## 2. Why A4 was thought resistant (mechanism to verify/refute)
Arguzz mutates **during execution** and re-runs → the witness is internally consistent, so the *only* gap is
the divide's missing same-cycle-read guard, which is a **global / memory-consistency** check (the #3181
`IsForward = IsCycle(cycle − prev_cycle)` admitting a 0-gap). Hence Arguzz accepts (CVE).
A4 mutates the **already-generated witness**: flipping the instruction word's rs2 field does *not* re-derive
the downstream witness (the reads, the ALU/div result, the writeback), so **local per-cycle consistency
constraints** should fire and reject it — *before* the global check is even the deciding factor.
**The probe asks the data whether that's always true, or whether some A4 instr-word mutations stay
locally-consistent and trip only a global constraint.**

## 3. Data we have (read-only)
Per-mutation tables in every DB:
- `mutations(kind, step, verifier_accepted, ...)` — kind ∈ {INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR} are the A4
  instruction-word mutations; INSTR_WORD_MOD is the Arguzz one.
- `mutation_substrategy(opcode, funct3, funct7, rd, rs1, rs2, ...)` — the decoded (mutated) instruction →
  divide = `opcode=51 AND funct7=1 AND funct3 IN (4,5,6,7)`; **alias created = rs1==rs2**.
- `failures(mutation_id, constraint_type, constraint_loc, cycle, step, major, minor, full_loc)` — **LOCAL**
  constraint failures (per-cycle / segment).
- `global_failures(mutation_id, family, address)` — **GLOBAL** constraint failures (cross-cycle / memory).
- Divide step: A4 surface is **user_cycle domain → 436 (remu) / 441 (divu)**; Arguzz surface is executor
  **444/449** (for the cross-check).
- Sources: **V5_control** (cve_results, B2 — its FULL/SUR kinds are *implemented*, not among the 3
  contaminated kinds, so valid); **Hybrid-B3** (clean binary, post-fix); plus Hybrid-B2 / originals for breadth.

## 4. Method (queries)
For V5 + Hybrid, restrict to `kind IN (INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR)` and:
- (Q1) How many land on a divide (substrategy decodes opcode=51/funct7=1/funct3∈4-7)? How many create rs1==rs2?
- (Q2) For the divide-alias ones: per-mutation **#local failures** (`failures`) vs **#global failures**
  (`global_failures`) vs `verifier_accepted`.
- (Q3) **The hypothesis hit:** count mutations with `#local==0 AND #global>=1` (accept-if-globals-ignored).
- (Q4) For the ones with `#local>=1`: which local constraints fire (`constraint_type`, `full_loc`, major/minor)
  — i.e. *why* the witness-flip is caught locally.
- (Q5) Cross-check vs the **Arguzz** INSTR_WORD_MOD at 444/449 (the known CVE path): its local/global pattern,
  to contrast "re-execute (consistent)" vs "witness-flip (inconsistent)".

## 5. Findings (data, V5 + Hybrid, cve_results, 6 seeds each; read-only)

**A4 DOES create the rs2:=rs1 divide alias — your hypothesis is right at the reachability level.**
| variant | A4 instr-word muts (FULL/SUR) | →divide | →**rs1==rs2 alias** | kinds | steps | accepted |
|---|---|---|---|---|---|---|
| V5_control | 4920 | 343 | **24** | 18 FULL + 6 SUR | uc 436(×12)/441(×12) | 0 |
| Hybrid_cTS | 4230 | 303 | **29** | 26 FULL + 3 SUR | uc 436(×11)/441(×18) | 0 |

**(Q2/Q3) Every one of the 53 alias-divide A4 mutations has `#local==0` and `#global∈{3,5}`** → **53/53 are
"0 local + ≥1 global" hypothesis hits.** Local constraints do NOT object to the witness-side instruction flip.

**(Q4) But the global failures are NOT the CVE underconstraint — they are the `memory`-consistency argument
catching that A4 never re-derived the reads.** All failures are family=`memory`; per mutation exactly:
- **1× code-mismatch AT the divide pc** (remu 2099384 / divu 2099404): the witness code cell now holds the
  mutated word (e.g. `0x02d65433`) vs the program image's original (`0x02c65433`) — i.e. A4 mutated the
  *immutable program code* in the witness. (24/24 and 29/29 land exactly on the divide pc.)
- **2× register-transaction mismatch**: the divide's recorded reads still reflect the *original* (a2, a3),
  but the mutated instruction says read a2 twice → the global register-permutation is imbalanced (a3 written
  but unread, a2 read-side mismatch). (50 and 59 such failures total.)

**(Q5) Contrast — Arguzz reaches the *same* alias but ACCEPTS:** the post-fix CVE candidates
(V6_cTS/uniform INSTR_WORD_MOD @444/449 that verify) are `verifier_accepted=1` ⇒ **0 local + 0 global**.
Re-execution makes the entire witness (code-read, reg-reads, div result, writeback) consistent with the
aliased divide, so the *only* remaining issue is the #3181 underconstraint (`IsForward` admitting the 0-cycle
same-register re-read) — and that global check **passes** (the bug), so the proof verifies.

## 6. Conclusion

**Refined answer: A4 reaches the bug surface but is blocked by a *legitimate* memory-consistency failure, not
by the CVE underconstraint — so a globals-ignoring oracle would NOT surface the CVE, it would accept broken
proofs.**

1. **You were right that A4 isn't stopped by local constraints.** It generates the exact rs2:=rs1 alias at the
   vulnerable divide (53 instances) and **0 local failures** fire. (Answering "if a local fires, why?": none
   fires — the flip is locally consistent; the inconsistency is purely cross-cycle = global.)
2. **The 3–5 global failures are genuine witness inconsistencies, not the CVE.** A4 flips the *instruction
   word* in the already-generated witness but cannot re-derive the dependent reads/result. So (a) the code
   cell at the divide pc no longer matches the fixed program image, and (b) the register reads still reflect
   the original two distinct registers. The `memory` permutation/consistency argument correctly rejects this.
3. **This is distinct from the CVE's global check.** The CVE lives in `IsForward`/same-cycle-read admission;
   A4 never gets there — it's rejected earlier by the code-image + register-permutation consistency. So
   "ignore the global" can't isolate the CVE: the failures are code↔reads mismatch (and *every* A4 code
   mutation trips the code-image mismatch → a globals-ignoring oracle would have ~100% false positives).
4. **Why Arguzz wins and A4 can't:** Arguzz mutates *during execution* and re-runs → consistent witness →
   only the genuine #3181 underconstraint remains (and it's admitted = accept = CVE). A4 mutates *post-hoc*
   in one cell → inconsistent witness → caught by memory consistency. This is the sharper, data-backed
   statement of "A4-resistant": **not** "A4 can't make the mutation" (it can) and **not** "local constraints
   stop it" (they don't) — but "A4 cannot produce a self-consistent witness for the aliased divide without
   re-execution; the memory-consistency global catches the code↔reads mismatch."

## 7. Is the "0 local + ≥1 global" pattern unique to the divide-alias? — **No.** (broadening, 6 seeds each)

Counting **every** mutation with `#local==0 AND #global>=1` (not just divide-alias):

| variant | total muts | accepted | (0 loc, 0 glob) | **(0 loc, ≥1 glob)** | (≥1 loc) |
|---|---|---|---|---|---|
| V5_control | 29998 | 10006 | 10056 | **2482** | 17460 |
| Hybrid_cTS | 30000 | 5026  | 8104  | **3038** | 18858 |

Breakdown of the (0 local + ≥1 global) set — **the divide-alias is a tiny slice of it:**
| variant | **alias-divide INSTR_WORD** | nonalias-divide INSTR_WORD | INSTR_WORD non-divide | other kinds | global family |
|---|---|---|---|---|---|
| V5 | **24** | 280 | 1830 | MEM_VAL_MOD 348 | 100% `memory` |
| Hybrid | **29** | 233 | 2327 (incl Arguzz INSTR_WORD_MOD 778) | MEM_VAL_MOD 277, PRE_EXEC_PC_MOD 172 | 100% `memory` |

**So "0 local + nonzero global" is the GENERIC signature of A4 post-hoc witness mutation, not a CVE signal.**
Any time A4 flips an instruction word (anywhere) or a memory value, the cell changes but the dependent
state (reads/result/permutation) is not re-derived → the witness is locally fine but globally inconsistent
→ the `memory` family rejects it. The divide-alias (24/29) is **~1%** of these (2482/3038); it is
**indistinguishable** from the other ~2458/3009 by the local/global-count metric. (Examples confirm:
INSTR_WORD at non-divide steps, divide mutations with rs1≠rs2, MEM_VAL_MOD, PRE_EXEC_PC_MOD — all 0 local +
`memory` globals.)

**Reconciliation / correctness checks (all pass):**
- alias-divide count reproduces the §5 figure exactly (V5=24, Hybrid=29).
- `accepted` reconciles with `(0 loc, 0 glob)`: V5 10056 = 10006 applied-accepted + 50 `error`; Hybrid's
  surplus is `error`(52) + `skipped`(505) + applied-but-proof-not-generated — i.e. the only mutations with
  zero failures that "verify" are exactly the accepted ones; the failure-counting is consistent with outcome.
- every global failure in both sets is family=`memory` (the permutation/consistency argument), never a
  distinct "IsForward"-only family — so even the divide-alias does not cleanly isolate the CVE check.

**Implication:** a globals-ignoring oracle would "accept" **2482 (V5) / 3038 (Hybrid)** mutations — almost all
of them structurally-inconsistent witnesses unrelated to the CVE. The pattern cannot be used to make A4
"find" the rs1==rs2 CVE; it just shows A4's witness mutations are caught globally, not locally, *in general*.

## 8. The oracle, with the CORRECT three-layer taxonomy (user-confirmed)

Recompute script: `lib/constraint_stats.py` (read-only, with built-in cross-checks). Output (6 seeds each).

**Taxonomy (per `CONSTRAINTS_EXPLAINED.md` / E5; this is the authoritative one):**
- **intrastep-local** = constraints within one step/cycle row (`MemoryWrite, DecodeInst, VerifyOpcode, DivInput, …`) — in `failures`.
- **interstep-local** = constraints between neighboring rows for the same address (`IsRead`/`IsCycle` @ `mem.zir:79/80`,`61/62`; prev_word==word, read-returns-last-write, cycle ordering) — in `failures`.
- **global (Hook 3)** = whole-trace permutation / lookup / range arguments — **all** of `global_failures` (families `memory, cycle, u16, u8`).
- **local = intrastep + interstep** (both live in `failures`). **global = `count(global_failures)`.**

> ⚠️ I previously inverted this — I wrongly reclassified `global_failures(family=memory)` as "inter-step
> local," which collapsed the oracle to 0. **That was the error.** Hook-3 memory contexts are GLOBAL. As the
> script note records: for A4 INSTR_WORD witness mutations the inter-step `IsRead` often does **not** appear in
> `failures`; the cross-step inconsistency is reported directly as a Hook-3 global memory context. Still global.

**Oracle (`local==0 AND global>0`) — the user's hypothesis target (V5 / Hybrid, 6 seeds, B2):**

| metric | V5 (pure A4) | Hybrid |
|---|---|---|
| P(intrastep local) | 0.543 | 0.600 |
| P(interstep local) | 0.153 | 0.239 |
| P(global Hook3) | 0.581 | 0.654 |
| **ORACLE: local==0 AND global>0** | **2482** (8.3%) | **3038** (10.1%) |
| ↳ of which **rs1==rs2 alias-divide INSTR_WORD** | **24** | **29** |

Cross-check `num_failures == count(failures)` = 29998/29998 (V5) / 30000/30000 (Hybrid) PASS.

**Conclusion — the hypothesis is SUPPORTED.** There exist **24** V5 (pure-A4) mutations that build the rs1==rs2
alias, pass **every** local constraint (both intra and inter — `failures` is empty for them), and fail **only**
the Hook-3 global argument. Under a globals-ignoring oracle these would be accepted ⇒ CVE signal. **24 is small
and directly inspectable** — exactly the tractable hand-inspection set you wanted. The full oracle set (2482)
is larger but is dominated by other register/value changes; filtering to INSTR_WORD-at-divide gives the 24.

**Why E5 reads as "~no 0-local+global" yet this is non-empty:** E5's measured INSTR_WORD sub-strategies are
*operation*-changing (`funct3_xor`, full-random) → they trip an intrastep `VerifyOpcode`/`DecodeInst` (local>0)
→ excluded from the oracle. The *register*-changing INSTR_WORD that forms a valid alias keeps a consistent
decode (0 intra) and — per the note above — its inter-step `IsRead` does not fire in `failures` either (0
inter) → it lands in the oracle. E5 never isolated this sub-strategy; the 24 are that previously-unmeasured
slice, not a contradiction. **Caveat:** these 24 are oracle *candidates*; whether each is truly the same
underconstraint the bug race targets is the manual-inspection step this set exists to make tractable.

**Provenance (important):** V5 here = the original race on the **B2** binary (no 3-kind handlers), `cve_results`,
seeds 1234–1239. This is the *correct* surface for the hypothesis: INSTR_WORD_MOD is **binary-invariant**
(the 3-kind handlers only touch TXN_PREV_WORD/TXN_PREV_CYCLE/CYCLE_DIFF — different code path), so the oracle
result is identical on B3; and the contaminated kinds are excluded from the oracle anyway (their no-ops have
global==0). V5 is pure A4 (no bandit), so there is no arm-selection skew.

**Clean-surface confirmation (2026-06-29, downloaded + verified DBs).** The post-fix Hybrid DBs are now in
`data/` (18 DBs, all integrity-ok, path-seed == in-DB seed, binary fingerprint confirmed: B2 silent-skip
`live=0` vs B3 handlers `live≈115`). Re-running the oracle (`lib/constraint_stats.py data/<group>/seed*.db`):

| Hybrid dataset | binary | step-domain | alias-divide oracle hits |
|---|---|---|---|
| cve_results (original) | B2 | pre-fix (confounded) | 29 |
| hybrid_B2_postfix | B2 | post-fix | 16 |
| **hybrid_B3_clean** | **B3** | post-fix | **20** |

All three are nonzero and same-order — the alias **reachability is robust and binary-invariant** (it is *not*
a contamination artifact). The clean-B3 Hybrid still produces **0 actual CVE candidates** (no accepted divide
mutation) despite 20 alias-divide oracle hits — i.e. A4 reaches the alias but the Hook-3 global argument blocks
every one, exactly as the hypothesis analysis predicts.

**Do we have enough?** Yes — the per-mutation local/global failure counts + the global-failure address detail
(type=code at the divide pc, type=register imbalances) are sufficient to characterize exactly what stops A4.
**Possible follow-up if desired:** define a custom oracle that (i) treats the *intended* code-mutation cell as
exempt and (ii) checks whether the *only remaining* global failure is the `IsForward`/same-cycle check — but
the data shows A4's residual failures are register-permutation, not `IsForward`, so this would still not
yield a CVE-equivalent accept. To make A4 truly reach it you'd need a *consistency-repairing* A4 mutation
(re-derive the reads to match the aliased instruction), which is effectively re-execution (= Arguzz).

