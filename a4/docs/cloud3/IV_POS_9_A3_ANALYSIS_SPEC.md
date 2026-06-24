# IV.POS.9 — Spec A3.4: the Seam-B bug-race ANALYSIS pipeline + notebook

**Version:** v0.1 · **Date:** 2026-06-24 · **Author:** Opus (OCP).
**Governing:** `ProG_Report_5.md` §3.7 (race metrics) / §3.8 (the two oracles); `IV_POS_9_A3_SEAMB_RACE_SPEC.md` §2 (oracle) / §3 (markers); precedent = the D2.H notebook (`a4/runs/iv_pos_8/d2g/{build_d2h_notebook.py,d2h_lib.py}`).
**Deliverable:** the reusable analysis layer (`race_lib.py` + `build_race_notebook.py`) → `race_exploration.ipynb` + self-contained `race_exploration.html`, plus `race_markers.json`/CSVs. Reused verbatim later for the `rs1==rs2` CVE race (just point it at that campaign's DBs + swap the primary oracle per §10 of the race spec).

---

## 0. What this race IS (and the smoke-vs-thesis question, answered)

There are **three** runs, do not conflate them:
1. **A3.S0 ground truth** (local, done): 12 certified finds + negative control through `oracle.py` — proves the oracle.
2. **A3.S1 smoke** (POS, N=120 × 4 variants × 3 seeds, done): **pipeline validation only** — proves dispatch→guard→run→collect→oracle→markers end-to-end + measures per-mut timing. *This is the "smoke for the real bug race."*
3. **A3.S2 thesis** (POS, **N=5000** × 4 variants × 10 paired seeds, RUNNING): **the real result.** This is NOT smoke — it is the thesis-grade campaign for the **A4 side** of the complementarity claim.

**So: is "this" just smoke?** The **N=120 run is** the smoke. The **N=5000 run is the real A3 race** — a controlled, *planted*-bug demonstration that the A4 post-execution surface reaches a soundness underconstraint (the removed `VerifyOpcode*` decode-equality) that the pure-Arguzz surface **structurally cannot** reach. It is one half of the headline thesis result. The **other half** is the later `rs1==rs2` **CVE race** (a *real* bug, value-changing), where the mirror is expected: Arguzz/Hybrid find it, pure A4 does not. **The two races together = the full bidirectional complementarity table** (race spec §10). This notebook is built to render either campaign.

**Which oracle (ProG §3.8).** The Seam-B bug is a *decode underconstraint*; the finds are **result-preserving** (no journal/OOPS change — race spec §0 "honest severity"). So this race uses the **internal trace-soundness oracle** (control rejects the identical mutation at `VerifyOpcode*`), the "fairer-to-A4" oracle. The CVE race will use the **strong application-level oracle** (accepted proof + wrong journal). The notebook states this explicitly so the result is not misread as "weak."

---

## 1. The find signal the notebook uses (and its validation)

**Structural find (F8 fast-path, no per-find binary re-run):** a mutation is a confirmed planted find iff it is an **`INSTR_TYPE_MOD` accept** (`verifier_accepted=1`, `outcome='applied'`) that is **decode-divergent** (`config.major/minor ≠ config._info.original_major/minor`) — `oracle.is_decode_divergent_itm`. Per **F8**, on a binary whose *only* hole is `VerifyOpcode*`, such an accept is rejected by the control **at `VerifyOpcode`** by construction, so it is a planted find. This is the `oracle.classify_run(confirm_itm=False)` verdict and is what the notebook counts (fast, deterministic, runs on the dev box).

**Validation chain (so the fast-path is trustworthy):**
- **A3.S0** already control-confirmed 12 such finds reject @ `VerifyOpcode` and 44 result-changers reject @ `MemoryWrite` (G-NEG/G-REPRO).
- **Falsifier (race spec §3, Opus #1):** the oracle control-checks **every** accept (not just ITM). The notebook reports Arguzz's *non-ITM* accepts as `non_planted` — i.e. Arguzz=0 is **tested**, not assumed. A non-ITM accept that rejected @ `VerifyOpcode` would surface as `unexpected_itm_unrejected`/a non-ITM FIND (none expected).
- **G-REPRO for the writeup:** before the final thesis figure, a **sample** of thesis finds is control-confirmed on a **fast POS node** (the control proves ~3 s there vs ~30 s on the dev box). The notebook flags this as the one step deferred to a fast node; the structural counts do not depend on it.

---

## 2. Metrics (ProG §3.7 + race-spec §3) → figures/tables

Per **(variant, seed)** (reuse `markers.per_run_markers`): `found`, `first_find_idx` (censored = N+1), `n_finds`, `n_applied`, `n_instr_type_mod_applied`, `find_density`, **`conditional_find_density`** (`n_finds / n_itm_applied`; `None` when ITM=0 → "bug off this surface"), `find_kinds`. Plus extras: `n_accepts`, accept-by-kind histogram, per-mut `elapsed_ms`.

Per **variant** (over the paired seeds; `markers.aggregate_variant`): **`P(found)`** + Wilson CI, discovery CDF (mutations-to-first-find, censoring shown), mean `conditional_find_density` + Wilson CI on pooled finds/ITM, mean `n_instr_type_mod_applied`, find-kind histogram, mean per-mut s.

**The decomposition (ProG §3.7) — the "why":** `P(find) = P(apply ITM) × P(find | ITM)` where `P(apply ITM) = n_itm_applied / n_applied` and `P(find | ITM) = conditional_find_density`. This turns the win/loss into a mechanism: A4/Hybrid have `P(apply ITM) > 0`; pure Arguzz has **`P(apply ITM) = 0`** (F7, structural) ⇒ `P(find) = 0` regardless of search effort.

**Figures (matplotlib, inlined as PNG via the d2h `show()` helper; HTML self-contained):**
| # | figure | what it shows |
|---|---|---|
| 1 | **finds + reachability bar** | per-variant total/mean finds and `n_instr_type_mod_applied` — the headline complementarity (A4/Hybrid ≫ 0; Arguzz 0/0) |
| 2 | **discovery CDF / KM** | mutations-to-first-find per variant, censored seeds shown (Arguzz fully censored) — ProG §3.7 survival curve |
| 3 | **decomposition** | per-variant `P(apply ITM)` × `P(find\|ITM)` = `P(find)` — the mechanism |
| 4 | **cumulative finds vs index** | finds accrued over the N pulls (pooled + per-seed) — discovery dynamics/rate |
| 5 | **accept channels** | per-variant accepts split into planted-find vs non-planted (by kind) — the falsifier view (Arguzz accepts all non-planted) |

**Tables (pandas):** headline per-variant summary; per-run markers; the decomposition.

---

## 3. Structure (mirrors `build_d2h_notebook.py`)

- **`race_lib.py`** — `discover_runs(results_dir)`, `load_data(results_dir)` (reuses `oracle.extract_accepts`/`is_decode_divergent_itm` + `markers.per_run_markers`/`aggregate_variant`), `summary(data)`, `per_variant_table`/`per_run_table` (→ DataFrames), `fig_*` (return Figures), `show(fig)` (Agg-safe inline PNG), Wilson CI. **All numbers live from the DBs — no hardcoding.** Parameterized by `results_dir` + auto-detected `N`; robust to **partial** campaigns (reports `seeds_done`).
- **`build_race_notebook.py`** — assembles md (narrative + self-contained context, the §0 framing, the honest-severity note) + code (calls `race_lib`) cells; executes; exports `race_exploration.html`; asserts 0 cell errors, all 5 figures present, HTML > 80 KB.
- **Inputs:** `RESULTS_DIR` env (default the thesis pulled dir; falls back to the smoke pulled dir). Same script renders the smoke (initial pipeline view), the partial thesis (live initial view), and the full thesis (final), and later the CVE race.

## 4. Acceptance
- Builds clean on the **smoke** DBs (complete 4×3) AND the **partial thesis** DBs (live) — proves the pipeline + gives the initial view.
- Headline reproduces the live finding: A4/Hybrid `P(found) > 0` with finds; pure-Arguzz `P(found)=0`, `n_instr_type_mod_applied=0`.
- Re-runs unchanged on `CHAIN_COMPLETE` (full 4×10 N=5000) for the A3.4 writeup, then on the CVE-race DBs (swap primary oracle per race-spec §10).
- Honest severity stated; the smoke-vs-thesis distinction explicit; the decomposition present.
