# IV.POS.9 — Spec B3: Multi-guest sweep — screening (Stage-1) → thesis (Stage-2) + cross-guest analysis

**Track:** B (multi-guest coverage sweep — the *generalization* claim). **Governing:** `ProG_Report_5.md` §2 (esp. §2.1–§2.5); `New_Master.md` (cloud3) §L7/L8/L9/L13/L14, gates G10–G13.
**Builds on:** B1 (foundation — isolation, fingerprint guard, `build_sweep_binary.sh`, guest-aware manifest generator). **Author:** Opus-CP. **Status:** DRAFT for Ivan + separate-Opus review.
**Date:** 2026-06-23.

---

## 0. What B3 is, and its dependencies (numbering note)
**Numbering (reconciled 2026-06-23):** New_Master plans Track B as Step B1 (harness/dispatch), Step B2 (guest-suite authoring), Step B3 (sweep campaign). In execution, harness+guests were **consolidated into the foundation spec** (`IV_POS_9_B1_MULTIGUEST_FOUNDATION_SPEC.md`: B1.1/B1.2 = Step B1 dispatch+isolation; B1.4 = Step B2 guest suite) — **both DONE**. This spec (**B3**) is the **sweep campaign** (planned Step B3): spec written, execution NEXT.

B3 runs the four variants (V5_control, V6_uniform, V6_cTS, Hybrid_cTS) across the **focused guest suite** to test whether the D2.H findings — **Case B** (cTS ties uniform on territory; Hybrid wins via the A4 surface) and the **A4-local / Arguzz-global orthogonality** — are *stable architectural properties* or `sha2-host` artifacts (Pro §2.1). It is the **generalization claim**, run on the **clean patched tree only** (`28e53771`), isolated from the bug-race/AP work (B1 §1).

**Prerequisites — now SATISFIED (B1 complete):**
- ✅ **B1.3 baseline equivalence** — Track-B G0 functionally identical to D2.H (`0xDEADBEEF`); V5/A4 coverage smoke discovers locs/CGC normally. *Final saturation cross-check = the B3.1 G0 reuse-validation gate below.*
- ✅ **B1.4 guests built + family-verified** — g1_ecall_control (control-dominated: 3572 branches), g2_mem_stress (3528 load/store + data-dep addressing), g3_accelerator (accelerated SHA = +34 `sys_sha` Eany + 128 div/rem). All read-only, fingerprinted, distinct guest_image_ids.
- ✅ **B1.1c** — guard wired into every job + per-run fingerprint audit sidecar; all jobs assert the full fingerprint pre-launch.
- ✅ `guest_image_id`s filled into `GUEST_SPECS`.

### 0.1 G0 baseline REUSE (Ivan-proposed optimization — ⚠️ RETRACTED 2026-06-25, was UNSOUND)
> **This optimization caused a contamination and is withdrawn.** The reused D2.F g0 binary carried the
> D2.B mutation handlers (`TXN_PREV_WORD/CYCLE_DIFF/PREV_CYCLE`, added in `6556e8d7`) that the Track-B
> clean tree `28e53771` predates, so g0 and the new guests ran on **different mutation engines** — those 3
> kinds were silently skipped on the sweep binaries (logged as false `applied`/`accept`). The validity
> argument below ("circuit + guest unchanged on 28e53771") was wrong, and the GATE was never run. The
> `0xDEADBEEF` check is insufficient (it never exercises injection). **Policy now: build g0 on the same
> Track-B binary as the new guests; never reuse a cross-binary baseline.** Fix + re-run record:
> `a4/runs/iv_pos_9/sweep/CONTAMINATION_AND_FIX_3KIND.md` (cherry-pick `6556e8d7` → Track-B HEAD
> `53c21894`; re-run V5+Hybrid × 4 guests × 3 seeds = 24 jobs incl. g0 fresh).

The screening does **not** re-run G0 — it **reuses the existing D2.H N=10000 G0 campaign** (`a4/runs/iv_pos_8/d2f/prod/`, all 4 variants × seeds 1234/1235/1236), **truncated to the first 5000 mutations** (`mutation_id ≤ 5000`). So B3.1 only **builds+runs the 3 NEW guests** (G1/G2/G3) → **36 jobs, not 48** (saves 12 G0 jobs).
**Validity (why the comparison stays sound):** (a) the G0 *circuit + guest* are unchanged — D2.H ran on `28e53771`; the Track-B G0 binary is `28e53771` + a coverage-neutral `fuzzer_utils` path fix (functional equivalence confirmed: identical `0xDEADBEEF`); (b) scheduling is **N-independent** — all variants use `ConstantFloor 0.55` (no decay/epoch), cold-start is a fixed 3 pulls/arm, no N-lookahead → the first 5000 mutations of an N=10000 cTS run are bit-identical to a fresh N=5000 run (deterministic given seed); (c) same variants, same 3 seeds, same coverage instrumentation.
**GATE (must pass before trusting the reuse):** the B1.3 G0 saturation cross-check — build a short V5 G0 run on the Track-B binary and confirm its loc/CGC trajectory matches the D2.H G0 DB at the same mutation count. If it diverges, re-run G0 fresh. *(Caveat: the D2.H DBs predate the fingerprint mechanism, so reused-G0 provenance rests on this equivalence check + the git-pinned `28e53771`, not a per-run DB fingerprint.)*

---

## 1. The guest suite (Pro §2.2) — all built + family-verified (B1.4)
| slug | guest | targets | verified trace (vs baseline 7924 steps / 962 br / 2552 ls) | status |
|---|---|---|---|---|
| `g0_baseline` | CircIL metamorphic diff (anchor) | u32 arith, 2× div, branch/mux | 7924 steps (the D2.H anchor) | **REUSE D2.H N=10000 truncated to 5000** (§0.1) |
| `g1_ecall_control` | control-flow-heavy | `inst_control` (A4's strongest per D2.H) | 25022 steps, **3572 branches** + 2262 JalR | ✅ built+verified (control-dominated) |
| `g2_mem_stress` | memory-stress | memory-perm/CGC, load/store, `prev_word`/`prev_cycle` | 16694 steps, **3528 load/store** + data-dep addressing | ✅ built+verified |
| `g3_accelerator` | accelerator / under-explored | `core_sha` (empty on baseline) + `inst_div` blind-spot | 28566 steps, **+34 `sys_sha` Eany** (accelerated SHA) + **128 div/rem** | ✅ built+verified (SHA accel confirmed) |
| `g4_sha` (optional) | stock SHA | sanity only — include **only if cheap** (Pro §2.4) | — | deferred |

All guests share the harness pattern (baseline host VERBATIM: fingerprint emit, injection hooks, prover, verifier; only the input ABI + a lenient multi-commit Receipt Decoder differ). Deterministic + bounded; sizes 16–29k steps (comparable proving cost). Sources: `a4/runs/iv_pos_9/sweep/guests/<slug>/{guest_main.rs,host_main.rs}`. *(Note: host crossings are labeled `Eany`/`Mret`, not "Ecall"; G3's SHA uses risc0's built-in accelerated `sha::rust_crypto` — no `sha2` patch needed, the earlier caveat is resolved.)*

## 2. Batches

### B3.1 — Stage-1 SCREENING sweep (3 NEW guests × 4 variants × 3 seeds × N=5000; G0 reused — §0.1)
**Build/run:** generate the screening manifest for the **3 new guests** (`--stage screening --guests g1_ecall_control g2_mem_stress g3_accelerator`) → **36 jobs** over the node pool, every job guard-prefixed (G11). Dispatch via `chain_dispatcher` on the **patched** binaries only. G0 is **not run** — its screening data is the D2.H N=10000 campaign truncated to `mutation_id ≤ 5000` (§0.1). Reuse the guest-agnostic D2.G/D2.H metric/triage CORE read-only; per-guest outputs land in `a4/runs/iv_pos_9/sweep/<guest_slug>/`.
**Budget (New_Master L9 / Pro §2.4):** the 36 new-guest jobs ≈ **~135 run-hours** at ~2.7 s/mutation (down from ~180 — the 12 G0 jobs are reused) — schedule around Track A's POS usage; embarrassingly parallel across the 8 nodes.
**Gate:** (a) the **G0 reuse-validation** (§0.1 gate) passes — the Track-B G0 binary's loc/CGC trajectory matches the D2.H G0 DB; (b) all 36 new DBs complete with a recorded **patched** fingerprint (load_rs2=1, planted_bug=none, correct guest_image_id); (c) per-guest loc/CGC/territory artifacts produced for all 4 guests (3 new + reused G0).

### B3.2 — Down-select the 2 most informative guests (Pro §2.4 staged design)
**Criteria (decide which guests carry the strongest, most discriminating signal):**
1. **Family activation** — the guest populated its intended families (g1: `inst_control`/ECALL zones; g2: memory-perm/CGC; g3: `core_sha`/`inst_div`) that the baseline did NOT — i.e. it adds genuinely new circuit territory.
2. **Variant separation** — the variants' coverage curves *differ* on this guest (a guest where all four tie is uninformative for the architecture comparison).
3. **Rank (in)stability vs G0** — a guest that *reorders* the variant ranking vs the baseline is the most informative (tests whether Case B / the orthogonality is guest-specific).
**Output:** a ranked table + the 2 selected guests (+ rationale), `log()`-ing what was dropped and why.

### B3.3 — Stage-2 THESIS sweep (2 selected guests × 4 variants × 10 seeds × N=10000)
**Run:** `--stage thesis` on the 2 selected guests; ~600 run-hours (the expensive part — gated on the screening down-select for feasibility). Patched-fingerprint-asserted per run.
**Gate:** ≥10 paired seeds per (guest, variant); statistically-meaningful per-guest comparisons (n≥10 → real p-values, unlike the n=3 D2.H caveat).

### B3.4 — Cross-guest analysis + the generalization verdict (Pro §2.3)
**Build (Track-B-owned analysis copies under `sweep/`, never editing the shared modules — §1.4):**
- **Per-guest two-panel curves** (left: local constraint-loc coverage; right: CGC coverage) + a per-guest summary table (Pro §2.3: `local_final/AUC`, `CGC_final/AUC`, `exclusive_local/CGC`, `time_to_80pct`, `soundness_candidates_strong`, `applied_pull_rate`, wall-clock).
- **Cross-guest heatmap** (rows=guests, cols=variants, cell=normalized rank/coverage; split into local + CGC panels).
- **Rank-stability** analysis: does Case B (cTS ties uniform; Hybrid wins on territory via A4) and the A4-local / Arguzz-global split hold across guests, or flip on a family the baseline never exercised (e.g. g3 accelerator, g2 memory)?
- Soundness triage on any accepts (reuse the F25/F27 `classify_semantics` read-only) — but the headline is **coverage generalization**, not bugs (that's Track A).
**Gate:** the generalization verdict states, with curves + cross-guest evidence, whether the D2.H architecture story is stable or guest-specific — feeding the thesis.

## 3. Deliverables
- `sweep/manifests/{screening,thesis}.chain`; per-guest DBs + `sweep/<guest_slug>/` artifacts.
- Track-B analysis copies under `sweep/` (per-guest curves/tables, cross-guest heatmap, rank-stability).
- `B2_REPORT.md`: the screening results, the down-select rationale, the thesis-sweep stats, and the cross-guest generalization verdict.

## 4. Risks / open items
- **G3 accelerator buildability** (the one real uncertainty): the `sha2` accel patch must be active or `core_sha` won't activate (B1.4 verifies; fallback = BigInt or the div-rem-only blind-spot guest). Don't let G3 block the other three.
- **Trace-size comparability** — the new guests' inputs (`GUEST_SPECS` defaults) are placeholders; B1.4 tunes them so each guest's trace is in a comparable range (the baseline is 3961 steps) for fair cross-variant cost.
- **Compute** — the thesis sweep (~600 run-hrs) is the feasibility driver; the screening down-select to 2 guests is load-bearing. Coordinate node usage with Track A; `log()` any coverage caps (no silent truncation).
- **Arm-weighting confound (carry-forward from D2.H/F30)** — keep the Case read on **normalized territory**, not raw CGC; report per-kind to flag any INSTR_WORD_MOD-over-sampling win.
- **V6_uniform sparse telemetry (F18)** — reuse the F18 failures-derived proximity for uniform (not the artifactual 0).
