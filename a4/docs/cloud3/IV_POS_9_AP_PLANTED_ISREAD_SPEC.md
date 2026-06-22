# IV.POS.9 — Spec AP: Planted register-read underconstraint (remove `IsRead`) + certainty harness

**Version:** v0.1 — DRAFT FOR IVAN+OPUS REVIEW · **Date:** 2026-06-22 · **Author:** Opus (D2-Opus).
**Governing plan:** [`New_Master.md`](./New_Master.md) Track A (the race needs an A4-findable target). **Evidence base:** [`PLANTED_BUG_FEASIBILITY.md`](./PLANTED_BUG_FEASIBILITY.md) + the E5 statistics run `thesis_side_experiments/full_sweep/artifacts/e5/`.
**Relationship to A1:** A1 builds the *authentic CVE* target (Arguzz-native). **AP builds a *planted* target that A4 can find**, so the race has a bug reachable by post-execution single-cell mutation. AP is **independent of A1** (no CVE back-port) and can proceed in parallel.
**Gates introduced:** **GP1–GP8** (planted-bug analogues of A1's G-gates).

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
- **Route 1 (preferred, if zirgen toolchain available):** add `MemoryReadNoIsRead` to `mem.zir` (a copy of `MemoryRead` minus the `IsRead(io)` call), point `ReadReg` (`inst.zir:36`) at it, regenerate `steps.cpp`/`layout`/`poly_ext` via the #3181-style codegen.
- **Route 2 (surgical, no zirgen):** in the generated `steps.cpp`, NOP the two `IsRead` `EQZ` **only at call sites whose loc traces through `ReadReg`** (the loc string distinguishes `IsRead@mem.zir:79 at MemoryRead@90 at ReadReg…` from `…at OpLW…` and `…at DecodeInst…`). Leave RAM/fetch `IsRead` intact.
- AP.B1 picks whichever **builds + passes the source gate**; Route 2 is the fast prototype.

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
| DP1 — `bench-isread` build (IsRead removed, ReadReg-scoped) | **GP1** | source/objdump shows `ReadReg`-path `IsRead` EQZ absent; RAM + fetch `IsRead` present; binary builds + smoke-proves |
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

- **V0 — source gate (GP1).** Confirm the `ReadReg`-path `IsRead` is gone in `bench-isread` and present in `patched`; confirm RAM-load and instruction-fetch `IsRead` remain in both. (grep the `.zir`/`steps.cpp`; `objdump` the constraint table if needed.)
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
