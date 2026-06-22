# Composer Kickoff — AP.B2: (0,1,0) corpus + deterministic bracket + genuine-soundness

**Parent spec:** [`../IV_POS_9_AP_PLANTED_ISREAD_SPEC.md`](../IV_POS_9_AP_PLANTED_ISREAD_SPEC.md) §5/AP.B2 · **Status:** BLOCKS ON AP.B1 · **Gates:** GP3, GP4, GP5 · **Reviewer:** Opus. **This batch delivers the certainty.**

## 0. Objective
Prove, by **replay**, that removing `IsRead` makes `PRE_EXEC_REG_MOD next_read` an accepted-invalid soundness bug — and that the control rejects the identical witness. Enumerate the (0,1,0) configs, replay them on both builds, and confirm the accepts are **genuine** soundness violations (not no-ops). This is the rung that gives Ivan certainty the strategy works.

## 1. Context
- The E5 run found **21/221** `PRE_EXEC_REG_MOD next_read` trials with layer signature **(intra=0, inter=1, global=0)** — only `IsRead` fired, global balanced. Source of truth: `thesis_side_experiments/full_sweep/artifacts/e5/atoms_n250/a4__PRE_EXEC_REG_MOD__next_read__*.json` (each atom has `layers={intrastep_local,interstep_local,global}`, `inject={step,instr_at_site,...}`, `target_region`). The classifier is `thesis_side_experiments/minimal_add/analyze_logs.py::thesis_layer`.
- Those 21 are **100% `target_region=guest_data`, source-register reads of store/load instructions** (`sw a1,8(a3)`, `lbu t3,4(a0)`, …).
- `CONSTRAINT_CONTINUE=1` in those runs ⇒ all constraints evaluated ⇒ "only IsRead fired" ⇒ removing IsRead ⇒ accept.
- A4 mutation config schema (`A4_MUTATION_CONFIG`): `{mutation_type:"PRE_EXEC_REG_MOD", step, txn_idx, word, strategy:"next_read"}` — see `a4/standalone/mutations/pre_exec_reg_mod.py::create_config`. Target enumeration: `get_all_targets(data, strategy="next_read")`.

## 2. Deliverables
1. **(0,1,0) corpus (GP3):** the enumerated configs — both (a) the original 21 from `atoms_n250`, and (b) freshly regenerated (0,1,0)-class configs for the **race guest** (the build's embedded guest) via `get_all_targets` filtered to guest-data store/load source reads.
2. **Deterministic bracket table (GP4):** per config → `bench-isread` verdict (expect ACCEPT) / `patched` verdict (expect REJECT).
3. **Genuine-soundness classification (GP5):** per accepted config, internal-replay result (witness read value vs honest value) → genuine | no-op.
4. **`ap_findings.md`:** the circuit-level "why" (read `inst_mem.zir` OpSW/OpLW + `ReadReg`/`ReadSourceRegs` to explain the balanced residue) + the genuine/no-op breakdown.

## 3. Steps
1. **Enumerate the corpus (GP3):** parse `atoms_n250` for `mutation_type=PRE_EXEC_REG_MOD`, `variant=next_read`, `layers` intra==0 & inter≥1 & global==0; record each `inject` (step, instr_at_site, register). Then, for the race guest, run `get_all_targets(strategy="next_read")`, filter to guest-data store/load source-register reads, and build configs via `create_config`.
2. **V1 deterministic single (GP4 seed):** apply ONE corpus config (`A4_MUTATION_CONFIG`) to `bench-isread` → expect proof **VERIFIES**; apply identical config to `patched` → expect **REJECT** (IsRead fires).
3. **V2 full-corpus replay (GP4):** replay **all** corpus configs on both builds → table {config → bench verdict → patched verdict}. Target: bench accepts ≥21/21, patched rejects ≥21/21. **Investigate + report any exception** (a config that doesn't accept on bench or doesn't reject on patched).
4. **V3 genuine-soundness (GP5):** for each accepted config, extract the register read value from the verified witness and compare to the honestly-executed value (last write to that register). Classify genuine (read ≠ honest) vs no-op (read == honest / unobservable). Use/extend the internal replay (`a4/runs/iv_pos_8/d2g/propagation_triage.py`, reg/mem-value replay). Require ≥1 genuine; report the fraction.
5. **Circuit "why":** read `zirgen/.../v2/dsl/inst_mem.zir` (OpSW@160-161, OpLW@108-109) + `inst.zir` ReadReg/ReadSourceRegs to explain why these store/load source reads keep the global residue balanced; write it into `ap_findings.md`.

## 4. Acceptance (GP3, GP4, GP5)
- [ ] (0,1,0) corpus enumerated (atoms + race-guest-regenerated).
- [ ] V2 table: `bench-isread` ACCEPTS the corpus, `patched` REJECTS it (≥21/21; exceptions explained).
- [ ] V3: ≥1 (report the fraction; ideally most) accepts are genuine soundness violations (witness read ≠ honest).
- [ ] `ap_findings.md` written (circuit why + genuine/no-op breakdown).

## 5. Guardrails
- **An accept that is a no-op is NOT a found bug** — V3 must separate genuine from no-op; the "findable bug" set = genuine only.
- **The patched-build REJECT is mandatory** — if `patched` also accepts, the bracket is broken (something other than IsRead is at play); stop and investigate.
- Reuse the existing replay/triage; don't invent a new oracle if `propagation_triage` reg/mem replay suffices.
- Do not change the builds here (AP.B1 owns the binaries) — only apply configs and observe.

## 6. Definition of done
The replay table proves bench-accepts/patched-rejects across the corpus, with a confirmed genuine-soundness subset. **The strategy is now proven by evidence, not theory.** Hand the corpus + genuine set to AP.B3.
