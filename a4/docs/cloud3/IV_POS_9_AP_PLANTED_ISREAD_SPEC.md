# IV.POS.9 — Spec AP: Planted register-read underconstraint (remove `IsRead`) + certainty harness

**Version:** v0.1 — DRAFT FOR IVAN+OPUS REVIEW · **Date:** 2026-06-22 · **Author:** Opus (D2-Opus).
**Governing plan:** [`New_Master.md`](./New_Master.md) Track A (the race needs an A4-findable target). **Evidence base:** [`PLANTED_BUG_FEASIBILITY.md`](./PLANTED_BUG_FEASIBILITY.md) + the E5 statistics run `thesis_side_experiments/full_sweep/artifacts/e5/`.
**Relationship to A1:** A1 builds the *authentic CVE* target (Arguzz-native). **AP builds a *planted* target that A4 can find**, so the race has a bug reachable by post-execution single-cell mutation. AP is **independent of A1** (no CVE back-port) and can proceed in parallel.
**Gates introduced:** **GP1–GP8** (planted-bug analogues of A1's G-gates).

> ## ⏱️ CURRENT STATUS (2026-06-23) — single source of truth; update THIS, do not spawn new run-dir reports
> **Where we are:** AP.B1/B2 attempted via **zirgen-regen (Route 1)** → **failed, no validated science, ~2 days of circles.** Root cause (verified on disk): a `rsync` path-doubling bug nested the regenerated Rust verifier poly into `src/zirgen/zirgen/…`, leaving the canonical `poly_ext.rs` stale/unholed → the verifier still enforced `IsRead@ReadReg` → 0/15 bracket (the same "wrong layer" failure, new mechanism). The regen also introduced an unverified circuit version (`df6fb9d`).
> **Decision (this review):** **abandon the regen path; switch to the surgical patch of the committed circuit (§2.2 PRIMARY).** Reasons: keeps the exact committed circuit (comparability with the CVE/campaign track), no zirgen toolchain, deterministic, index-preserving, breaks the circle.
> **Update (2026-06-23, second review):** the OCP findings raised a surgical-vs-regen *fork* (CSE shares the read diff-wire across instruction arms → wire-zeroing over-widens; regen-from-df6fb9d is a proven-different circuit). **That fork is FALSE and is now dissolved.** The constraint is enforced by the per-arm `AndEqz` **fold**, not the shared `Sub` **wire**, and the folds are separable. **Decision: surgical patch at the FOLD level on the committed circuit** — repoint the 26 `IsRead@ReadReg` `AndEqz(x,W)→AndEqz(x,0)` (verifier `poly_ext.rs`) + zero the matching C++ prover folds, touching no wire. Comparable AND scoped, no regen. (§2.2 PRIMARY.) `ap_isread_patch.py` (wire-zeroing) and `ap_poly_cse_audit.py` (wire-sharing check) must both be rewritten for the fold mechanism.
> **Update (2026-06-23, FOURTH review — airtight, by direct measurement) — SEAM A IS DEAD.** The `(0,1,0)` premise is a **measurement artifact**, now proven by running **all 21 genuine E5 `(0,1,0)` `next_read` atoms to completion** with hook3 armed (`A4_GLOBAL_RESIDUE=1`): **21/21 SIGSEGV (exit 139), zero residue records, 0 reached a `zero` residue.** Every `(0,1,0)` register is a **pointer** (`a0/a2/a3/a7` load-store bases, `sp`, `ra`); the diverged `word` is a wild 32-bit value (`0xC0000000–0xFF000000`) → witgen dereferences a wild address → **crash BEFORE the accum/residue phase ever runs.** The classifier (`classify.py:88-91`) defaults `global=0` when **no residue record exists**, and a crashed process emits none — so `(0,1,0)` means "no global RECORD," **never** "grand product balanced." (The screening's `is_prover_crash` keys on a Rust panic loc and misses raw SIGSEGV, so these crashes were mislabeled `CONSTRAINT_REJECT`.) **For the read edits that DON'T crash** (the 200 `(0,1,1)`/`(1,1,1)` atoms), the global residue is **NONZERO** in 200/200 — `newTxn.data` (the read value the ALU consumes) is the same witness cell the memory grand product binds (`mem.zir:68`), so holing the *local* IsRead leaves the *global* argument rejecting. **Both reasons are fatal and independent.** Prior `race_0000` smoke used a **non-genuine** `(0,1,0)` config (it emits NONZERO residue when run), and the prior finding's "stale accum" mechanism (`AP_B2_GLOBAL_LOGUP_FINDING.md §2.1`) was **wrong** (`stepAccum` recomputes from the mutated trace). **Fundamental limit:** no single-cell post-exec edit of a memory-resident value (registers included) can produce a verifying witness — defense-in-depth via the global memory permutation; this is the `BUG_MECHANISM_VERIFIED.md` "A4 can't produce a coherent witness" result. Next: (a) Seam B (decode/ALU intermediate not in the memory permutation — fresh feasibility pass, never inferred from screening), or (b) accept the **limits-of-A4 / defense-in-depth negative result** (publishable; supports the complementarity thesis). **Authoritative & reproducible: `../../runs/iv_pos_9/ap/AP_B2_010_RESOLVED.md`.**
> **Update (2026-06-23, FIFTH review — SEAM B VALIDATED, by direct measurement).** Pivoting off the dead Seam A: ran the `INSTR_TYPE_MOD` atoms to completion (hook3 armed). **`(1,0,0)` ALU→ALU type changes: 40/40 reach the verify hook with `a4_global_residue_ZERO` — the memory permutation is BALANCED.** `(1,0,1)` (branch/jump/load changes): 8/8 NONZERO (PC-chain / memory-txn change). **INSTR_TYPE_MOD edits the decode field (`major/minor`), which is NOT in the permutation** (the permutation binds the fetched *word*); witgen recomputes the cycle consistently for the new type, leaving only the local decode-equality `VerifyOpcode*` (`inst.zir:90/95/101`) violated. It is the **only** mutation type with a global-clean population (161/250); every value-editing type is 0. **Seam B planted bug is FEASIBLE:** hole `VerifyOpcode*` (honest-preserving fold-neutralization, same machinery as IsRead) → an ALU→ALU `INSTR_TYPE_MOD` mutation verifies; nothing global re-catches. Real bug = instruction substitution. ~13 "pure-decode" type-changes fire `VerifyOpcode*` only (cleanest targets); the rest also fire local `MemoryWrite@99`. **Authoritative & reproducible: `../../runs/iv_pos_9/ap/AP_SEAM_B_VALIDATED.md`.**
> **ANTI-CIRCLE RULE:** never infer verify-behavior from `(0,1,0)`/`(1,0,0)` screening layer signatures alone — the global layer DEFAULTS to 0 when no residue record exists (crash / cutoff / hook unreached), so it can mean "global unmeasured," not "global balanced". Validate any planted-bug claim by **running the exact mutation to completion with `A4_GLOBAL_RESIDUE=1`** (read the `a4_global_residue_zero/nonzero` record) AND a **direct mutated-V0 test on a holed binary**, full stop.
> **Authoritative artifacts:** root cause `../../runs/iv_pos_9/ap/AP_B2_STATE_AND_ROOTCAUSE.md`; layering lesson [`AP_B2_ROOT_CAUSE.md`](./AP_B2_ROOT_CAUSE.md); journey log `../../runs/iv_pos_9/ap/AP_TRACK_AUDIT_LOG.md`. **Do not over-interpret the many `AP_B2_*` run-dir reports — they are a circling artifact.**

---

## 0. Scope

### 0.1 What AP IS
Create a **single, faithful, bracketed soundness underconstraint** — remove the `IsRead` register-read-consistency constraint on the **register-read path only** — and **prove with certainty** that:
1. **A4 finds it:** `PRE_EXEC_REG_MOD next_read` produces **accepted-invalid proofs** on the build with the hole, and **0** on the control.
2. **It's a genuine soundness violation** (the verified witness encodes a register read that diverges from the honestly-executed value), not a no-op.
3. **It brackets cleanly:** the *identical* witness that the holed build **accepts** is **rejected** by the control build (with `IsRead` restored).
4. **It is findable by both surfaces:** Arguzz's during-execution register mutation also yields an accepted-invalid proof (strong/journal oracle), making this the "found by both A4 and Arguzz" bug.

### 0.2 What AP is NOT
- **Not the CVE.** The authentic `rs1==rs2` double-read bug (CVE-2025-52484) is A1's job, on a *separate* build (`bench-cve`). AP's bug is a *disclosed, synthetic* underconstraint (LAVA/Magma-style positive control), labeled as such in any thesis text.
- **Not the race campaign.** AP delivers the *validated holed binary + certainty that A4 finds it*. The staged race (metrics, seeds, Kaplan-Meier) is A3, which consumes AP's `bench-isread` build the same way it consumes A1's `bench-cve`.
- **Not on the vulnerable commit.** AP builds on the **current patched tree** so the *only* hole is the removed `IsRead` (see §2.1).

### 0.3 The bug in one paragraph (verified from data + source)
`IsRead` (`zirgen/.../v2/dsl/mem.zir:79-80`, compiled to two `EQZ` in `steps.cpp`) enforces that a memory read returns the previously-written value (`oldTxn.data == newTxn.data`). The E5 run shows that A4's `PRE_EXEC_REG_MOD next_read` (edits a register **read**'s `word`, leaves `prev_word`) produces, in **21 of 221** applied trials, the layer signature **(intrastep=0, interstep=1, global=0)** — i.e. **only `IsRead` fires; the global memory-permutation residue stays balanced**. These 21 are **100% guest-data store/load source-register reads** (`sw a1,8(a3)`, `lbu t3,4(a0)`, …). Because the E5 host runs with `CONSTRAINT_CONTINUE=1` (every constraint evaluated, not stop-at-first), "only `IsRead` fired" means: **remove `IsRead` ⇒ those proofs verify.** That is the planted bug.

---

## 1. Why this works where the reports said it couldn't
Both prior reports argued the global memory LogUp re-pins every value, so a single A4 edit is always globally rejected. **True on average, false for the (0,1,0) class.** The E5 per-trial histogram (not the average) identifies the exact cases where global stays balanced and only `IsRead` catches the edit. Removing `IsRead` converts precisely those into accepted-invalid proofs. The certainty harness (§4) proves this by **replaying the enumerated (0,1,0) configs** rather than arguing from theory.

> **Residual we accept and test around:** the precise circuit reason those 21 store/load-source reads keep the residue balanced (likely: the store's data is derived from the same edited read cell, so it stays internally coherent while only `IsRead` is violated) is pinned *empirically*, not yet derived line-by-line. The §4 replay confirms the behavior regardless; AP.B2 records the circuit-level "why" for the writeup.

---

## 2. Locked design decisions

### 2.1 D1 — Build on the CURRENT PATCHED tree (not the vulnerable commit)
`bench-isread` = the current instrumented tree (`workspace/risc0-modified` @ `28e53771`, CVE **fixed**, `load_rs2` present) with `IsRead` removed on the register-read path. Rationale: isolates the planted hole (the *only* soundness gap is removed `IsRead`), needs **no CVE back-port**, and gives clean attribution. The `IsRead` bug is commit-independent — putting it on the vulnerable commit would only entangle it with the CVE.

### 2.2 D2 — Scope the removal to the register-read path only (`ReadReg`), not RAM or instruction fetch
`IsRead` is invoked by `MemoryRead`, used by (a) `ReadReg` (register reads — the target), (b) RAM `OpLW`/store-data reads, (c) instruction fetch (`DecodeInst`). **Remove `IsRead` only for (a).** This makes the bug *precisely* "register-file read consistency," keeps RAM and fetch sound, and exactly matches the (0,1,0) cases (which are register reads of store/load instructions, reached via `ReadReg`/`ReadSourceRegs`).
> **⚠️ CORRECTED (2026-06-22, see [`AP_B2_ROOT_CAUSE.md`](./AP_B2_ROOT_CAUSE.md)):** the planted hole must be removed from the **constraint polynomial** (`rust_poly_fp_{0..3}.cpp` + `poly_ext.rs`), **NOT** the witgen `eqz` in `steps.cpp`. The proof's validity is checked by the prover's `verify_integrity` (the "verify segment" step), which evaluates the constraint polynomial — `steps.cpp` is only witgen and is *blind to soundness*. The original "Route 2 = NOP the `eqz` in `steps.cpp`" was **invalid** (it produced a holed witgen over an intact constraint system → the proof still rejected). General rule: **a planted soundness hole lives in the constraint polynomial, never in the witgen `eqz`.**

> **⚠️ ROUTE DECISION REVERSED (2026-06-23, after the regen attempt failed — see [`AP_B2_STATE_AND_ROOTCAUSE.md`](../../runs/iv_pos_9/ap/AP_B2_STATE_AND_ROOTCAUSE.md)).** The zirgen-regen path (formerly "preferred") burned ~2 days and produced **no validated science**: it (a) introduced a **different circuit version** (zirgen `df6fb9d`, 2026-01-20) whose equivalence to our committed circuit is **unverified** (comparability risk), (b) hit a **`rsync` path-doubling bug** that nested the regenerated Rust verifier poly into `src/zirgen/zirgen/zirgen/…` so the canonical `poly_ext.rs` stayed **stale/unholed**, and (c) required a Bazel/MLIR toolchain build with repeated 30–40 min cycles. **The surgical patch is now PRIMARY** — it edits the *exact committed circuit* (zero version drift, perfect comparability with the CVE/campaign track), needs no zirgen, and is deterministic.

- **PRIMARY — surgical patch of the COMMITTED constraint polynomial, at the FOLD level (no regen, no df6fb9d).** From the git-clean committed files, neutralize the `IsRead@ReadReg` constraint in **both** the verifier poly (`risc0/circuit/rv32im/src/zirgen/poly_ext.rs`) **and** the prover poly (`rv32im-sys/kernels/cxx/rust_poly_fp_{0..3}.cpp`, + CUDA `.cu`). Witgen (`steps.cpp` `MemoryReadNoIsRead` in `exec_ReadReg`) is already correctly ReadReg-scoped.
  > **⚠️ CORRECTED (2026-06-23, see `../../runs/iv_pos_9/ap/AP_B2_FINDINGS_FOR_OCP.md` + this review).** The earlier "rewrite `Sub(a,b)→Sub(a,a)`" mechanism **over-widens the bug** and must NOT be used. RISC Zero codegen CSE makes the per-row read **diff wire shared** across instruction arms: e.g. `fp#753` is folded by ReadReg folds (poly_ext lines 862/886) **and** by Poseidon (`ReadElem@inst_p2.zir:140`) and `MemoryGet` folds (lines 7931/8332/9092). Zeroing the shared `Sub` wire disables IsRead for **all** memory reads, not just registers. **But the folds are separable** — each constraint is its own selector-gated `AndEqz`. So neutralize the **folds, not the wires.**
  - **Mechanism (index-preserving — do NOT touch any `Sub`/diff wire):** repoint each of the **26 `IsRead@ReadReg` `AndEqz(x, W)` → `AndEqz(x, 0)`** in `poly_ext.rs` (`fp#0` = `Const(0)`; `AndEqz(x, 0)` asserts `0==0`, a no-op fold the codegen already uses, e.g. line 7929). Zero the matching C++ fold contributions in `rust_poly_fp_{0..3}.cpp` (per-constraint fold statements, ~27/15/14/10, identified by loc tag). Apply identically to prover and verifier so they stay consistent. Leave every `Sub` wire, every non-ReadReg fold, and RAM/fetch `IsRead` **untouched** → register-read IsRead disabled, Poseidon/Div/Control/RAM IsRead intact, **exact committed circuit preserved** (comparable + scoped).
  - **This dissolves the surgical-vs-regen "fork."** We get comparability AND scoping with no regen. (The fork was an artifact of the wire-zeroing mechanism.)
- **FALLBACK — zirgen regen** (only if the surgical patch proves intractable): the toolchain is already solved (native host build, `gen_zirgen` ~26 min, no zig/POS); fix the `rsync` targets (copy Rust files to the canonical `src/zirgen/`, file→file or trailing-slash), `git checkout` + delete the nested dirs, **and first run the `semantic-diff` to confirm df6fb9d == committed** before trusting it. Regen builds BOTH binaries fully from one snapshot (never mix df6fb9d C++ with committed Rust).
- AP.B1 picks whichever **passes the hardened GP1 gate AND the mutated-V0 smoke** (both mandatory).

### 2.3 D3 — Separate binaries, one bug per binary (answers Ivan's question)
| build | commit | CVE | IsRead | role |
|---|---|---|---|---|
| **`bench-cve`** | `98387806` (vuln) | present | present | A1's Arguzz race |
| **`bench-isread`** | patched (current tree) | fixed | **removed (ReadReg)** | **AP's A4+Arguzz race** |
| **`patched`** | patched (current tree) | fixed | present | control / post-fix bracket for AP |
| *(`bench-AB`)* | `98387806` | present | removed | *optional* combined; **not primary** |

**Why not one combined binary** (the concrete interaction): with both holes present, the CVE race is contaminated — *any* register-read divergence verifies via the IsRead hole, so a variant can "find a bug" without exploiting the `rs1==rs2` double-read, and you can no longer claim "Arguzz found the CVE." Symmetrically the IsRead race is contaminated by the CVE. Per-bug builds are needed for the per-bug brackets anyway. `bench-AB` is retained only if a single head-to-head narrative is wanted later, with finds attributed by signature (the (0,1,0)-IsRead vs CVE-same-cycle signatures differ), and is explicitly out of the primary plan.

### 2.4 D4 — Fingerprint carries a `planted_bug` flag
Extend the L14/G10 fingerprint with `planted_bug: none|isread` (and `isread_scope: reg_only`). `bench-isread` stamps `planted_bug=isread`; `patched` stamps `none`. Every run asserts the intended value (per L14/G11).

### 2.5 D5 — Oracle definition for the planted bug
- **A4 → internal trace-soundness oracle (primary for AP):** proof **verifies**, AND a replay/consistency check shows the register read value in the witness **≠ the honestly-executed value** (the value last written to that register). Post-fix (`patched`) **rejects** the identical witness. (A4's post-exec edit usually doesn't change the journal, so the strong oracle won't fire for A4 — consistent with ProG L4.)
- **Arguzz → strong/journal oracle:** Arguzz's during-execution register-value change propagates → the committed journal is **wrong** while the proof verifies on `bench-isread`; `patched` rejects.

---

## 3. Deliverables → gates
| Deliverable | Gate | Pass condition |
|---|---|---|
| DP1 — `bench-isread` build (IsRead removed, ReadReg-scoped) | **GP1** *(hardened)* | **zero `IsRead@ReadReg` terms remain in `rust_poly_fp_{0..3}.cpp` AND `poly_ext.rs`** (the constraint polynomial — the load-bearing check) on bench; RAM/fetch `IsRead` terms still present in both; witgen `steps.*` consistent; binary builds; **honest smoke verifies AND one (0,1,0) mutated config verifies on bench / rejects on patched** (mutated smoke — not honest-only) |
| DP2 — fingerprint with `planted_bug=isread` on bench, `none` on patched | **GP2** | both builds emit the flag; dispatcher can assert it |
| DP3 — (0,1,0) corpus | **GP3** | the ≥21 known (0,1,0) `PRE_EXEC_REG_MOD next_read` configs enumerated from `atoms_n250` + regenerated for this guest |
| DP4 — deterministic bracket | **GP4** | every corpus config: `bench-isread` **ACCEPTS**, `patched` **REJECTS** (target ≥ 21/21; report any exceptions) |
| DP5 — genuine-soundness confirmation | **GP5** | for the accepted configs, the internal replay shows witness read ≠ honest value (i.e. real violations, not no-ops); ≥1 (ideally most) are genuine |
| DP6 — live A4 fuzzing validation | **GP6** | MODE-1 `PRE_EXEC_REG_MOD next_read` on `bench-isread` → accepted-invalid rate ≈ the (0,1,0) prediction (~9.5% of applied), all accepts carry the (0,1,0) signature; `patched` → **0** accepts |
| DP7 — Arguzz both-findability | **GP7** | Arguzz during-exec reg mod on `bench-isread` → strong-oracle accept (wrong journal); `patched` → reject |
| DP8 — negative controls | **GP8** | on `bench-isread`, other A4 value kinds (`COMP_OUT_MOD`, `MEM_VAL_MOD`, `STORE_OUT_MOD`, `LOAD_VAL_MOD`) still **REJECT** (we removed only `IsRead`; the build isn't trivially broken / over-holed) |

**AP is complete only when GP1–GP8 pass.**

---

## 4. The certainty harness (the heart of this spec)
A strict ladder; each rung gates the next. This is what gives Ivan certainty the strategy works.

- **V0a — constraint-poly source gate (GP1, load-bearing).** Confirm **zero `IsRead@ReadReg` terms in `rust_poly_fp_{0..3}.cpp` AND `poly_ext.rs`** on `bench-isread` (these are what `verify_integrity` evaluates — NOT `steps.cpp`); confirm they remain in `patched`; confirm RAM-load and instruction-fetch `IsRead` remain in both builds. *(Checking only `steps.cpp`/`.zir` is what let the AP.B2 failure through — see `AP_B2_ROOT_CAUSE.md`.)*
- **V0b — mutated smoke (GP1).** Run **one** known (0,1,0) `PRE_EXEC_REG_MOD next_read` config on each build: `bench-isread` must **verify** (proof accepts), `patched` must **reject**. An honest (unmutated) run verifies on both and proves nothing about the hole — V0b is mandatory before trusting the build.
- **V1 — deterministic single repro (GP4 seed).** Pick **one** known (0,1,0) config (a guest-data `sw`-source register read, enumerated from `atoms_n250`). Apply via `A4_MUTATION_CONFIG` to `bench-isread` → proof **verifies**. Apply identical config to `patched` → **rejected** (IsRead fires). This is the minimal proof-of-concept.
- **V2 — full (0,1,0) corpus replay (GP4).** Replay **all** enumerated (0,1,0) configs (≥21). On `bench-isread`: **all accept**. On `patched`: **all reject**. A per-config table (config → bench verdict → patched verdict). Any config that doesn't accept on bench (or doesn't reject on patched) is investigated and reported — this is where certainty is earned statistically.
- **V3 — genuine-soundness (GP5).** For each accepted config, run the internal replay: extract the register read value from the verified witness and compare to the honestly-executed value (the last write to that register). Confirm divergence (real soundness violation). Classify any no-ops (accepted but witness == honest) and exclude them from the "findable bug" set; require ≥1 (ideally the majority) genuine.
- **V4 — live A4 fuzzing at scale (GP6).** Run MODE-1 `PRE_EXEC_REG_MOD next_read` (the actual fuzzer arm, not hand-configs) on `bench-isread` for N≈2000 mutations. Expected: accepted-invalid rate ≈ the (0,1,0) fraction (~9.5% of *applied*), and **every** accept carries the (0,1,0) signature (interstep-only, was-IsRead). On `patched`: **0** accepted-invalid. This proves the *fuzzer*, not just hand-configs, finds the bug.
- **V5 — Arguzz both-findability (GP7).** Run the Arguzz during-exec register mutation on `bench-isread`; confirm a strong-oracle accept (verified proof + wrong journal vs honest); `patched` rejects. Establishes the "both surfaces" claim.
- **V6 — negative controls (GP8).** On `bench-isread`, confirm `COMP_OUT_MOD`/`MEM_VAL_MOD`/`STORE_OUT_MOD`/`LOAD_VAL_MOD` still reject at their normal rates (we only removed `IsRead`). Guards against an over-broad hole or a broken build.

---

## 5. Batches

### AP.B1 — Build `bench-isread` (IsRead removed, ReadReg-scoped) + fingerprint + V0
**Delivers:** DP1, DP2; passes **GP1, GP2**.
- Implement D2 (Route 1 `MemoryReadNoIsRead` + regen, or Route 2 surgical `steps.cpp` NOP at `ReadReg` IsRead sites).
- Build `bench-isread`; re-stamp `patched`; add `planted_bug` to the fingerprint.
- **V0 source gate** + a smoke proof (an unmutated guest run still verifies on both builds — the hole doesn't break honest execution).
- Confirm RAM/fetch `IsRead` intact (scope check).

### AP.B2 — (0,1,0) corpus + deterministic bracket + genuine-soundness
**Delivers:** DP3, DP4, DP5; passes **GP3, GP4, GP5**.
- Enumerate the (0,1,0) `PRE_EXEC_REG_MOD next_read` configs from `thesis_side_experiments/full_sweep/artifacts/e5/atoms_n250` (filter `layers==(0,≥1,0)`, `mutation_type=PRE_EXEC_REG_MOD`, `variant=next_read`); regenerate equivalent configs for the race guest (the current/embedded guest, or A2's race guest).
- **V1** deterministic single, then **V2** full-corpus replay → the bench-accepts/patched-rejects table.
- **V3** internal-replay soundness confirmation; classify genuine vs no-op.
- Record the circuit-level "why" (read `inst_mem.zir` `OpSW`/`OpLW` + `ReadSourceRegs`/`ReadReg` to explain residue balance) for the writeup.

### AP.B3 — Live A4 + Arguzz validation + negative controls
**Delivers:** DP6, DP7, DP8; passes **GP6, GP7, GP8**.
- **V4** live MODE-1 `PRE_EXEC_REG_MOD next_read` fuzzing on `bench-isread` (N≈2000) + on `patched`; confirm hit-rate ≈ (0,1,0) fraction on bench, 0 on patched; confirm all accepts are (0,1,0)-signature.
- **V5** Arguzz during-exec reg mod on both builds; strong-oracle accept on bench, reject on patched.
- **V6** negative controls (other A4 value kinds reject on bench).

---

## 6. Risks & fallbacks
1. **Some (0,1,0) cases are no-ops** (accepted but journal/witness observably honest). *Mitigation:* V3 filters them; the "findable bug" set = genuine violations. If *all* are no-ops (unlikely — store-source reads should affect the stored value), escalate: the hole is invisible and we instead scope to a read whose value is observably consumed, or pivot to Seam B (INSTR_TYPE_MOD / decode-binding removal; see PLANTED_BUG_FEASIBILITY §Seam B) which is A4-strong at 64%.
2. **Build breaks / over-broad hole** (removing IsRead destabilizes other constraints). *Mitigation:* V6 negative controls + smoke proof in AP.B1; tighten scope to `ReadReg` only.
3. **Route 1 needs zirgen we can't run.** *Mitigation:* Route 2 surgical `steps.cpp` NOP (no codegen).
4. **The (0,1,0) hit-rate (~9.5%) is low for the race.** *Mitigation:* fine for a positive-control find (the fuzzer hits it within ~tens of pulls); if a faster A4 target is wanted, add Seam B (64%).
5. **`atoms_n250` configs are for the E5 guest, not the race guest.** *Mitigation:* AP.B2 regenerates (0,1,0) configs against the actual race-guest trace via the existing `PRE_EXEC_REG_MOD next_read` target enumeration (`a4/standalone/mutations/pre_exec_reg_mod.py::get_all_targets`), filtering to guest-data store/load source reads.

## 7. Acceptance checklist (AP done ⇔ all pass)
- [ ] **GP1** ReadReg-path `IsRead` removed in `bench-isread`, present in `patched`; RAM/fetch `IsRead` intact; honest run verifies on both.
- [ ] **GP2** `planted_bug` fingerprint flag on both builds.
- [ ] **GP3** (0,1,0) corpus enumerated for the race guest.
- [ ] **GP4** corpus replay: `bench-isread` accepts, `patched` rejects (≥21/21; exceptions explained).
- [ ] **GP5** ≥1 (ideally most) accepts are genuine soundness violations (witness read ≠ honest), not no-ops.
- [ ] **GP6** live A4 fuzzing: accepted-invalid ≈ (0,1,0) rate on bench, 0 on patched, all accepts (0,1,0)-signature.
- [ ] **GP7** Arguzz strong-oracle accept on bench, reject on patched.
- [ ] **GP8** negative controls reject on bench.

## 8. Inventory
**Reads:** `zirgen/.../v2/dsl/{mem.zir,inst.zir,inst_mem.zir}`; `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp`; `a4/standalone/mutations/pre_exec_reg_mod.py`; `a4/core/executor.py`, `a4/standalone/arguzz_invoke.py`; `thesis_side_experiments/full_sweep/artifacts/e5/atoms_n250/` + `minimal_add/analyze_logs.py` (layer classifier) + `bias_campaign/{categorize,classify}.py`; `a4/pos/{prepare_bundle.sh,run_campaign_pos.sh}`; A2's internal-oracle replay (`propagation_triage.py` extension).
**Produces:** `bench-isread` + `patched` builds + fingerprints; the (0,1,0) corpus; the V1–V6 verdict tables; a short `ap_findings.md` (circuit "why" + genuine-vs-noop breakdown + the both-surfaces confirmation).

## 9. Batch summary
| Batch | Delivers | Gates | Blocks |
|---|---|---|---|
| **AP.B1** | `bench-isread` build (ReadReg IsRead removed) + fingerprint + V0 + smoke | GP1, GP2 | — |
| **AP.B2** | (0,1,0) corpus + deterministic bracket (V1/V2) + genuine-soundness (V3) | GP3, GP4, GP5 | AP.B1 |
| **AP.B3** | live A4 + Arguzz validation + negative controls (V4/V5/V6) | GP6, GP7, GP8 | AP.B2 |
