# Seam-B bug-race — campaign & database inventory (provenance / separation)

**Date:** 2026-06-27 · verified read-only from the filesystem on `cloud2`. Purpose: keep every campaign's DBs cleanly separated so the new FIXED-binary run is never confused with prior runs.

## The Seam-B VerifyOpcode race has been run 3 times (all on the SAME contaminated head-`93bda33b` binary pair)
| # | run | date | binary (path · sha256 · head) | guest | variants | seeds | N | #DBs | local path | POS /srv | run-id pattern |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | **Stage-0 ground truth** | 06-23 | holed `bench-verifyopcode` `53ee6663…` + control `4e0f841c…` · head `93bda33b` | synthetic (56 bracket configs) | INSTR_TYPE_MOD bracket | gseed 12345 | 56→12 | **0 persisted** (tempfile DB, deleted) | truth = `ap/seamb/ap_seamb_verify.json` | — | n/a (known-answer gate) |
| 1 | **Smoke** | 06-24 | same `53ee6663…`/`4e0f841c…` · `93bda33b` | Seam-B guest `1f5b9372…` | V5_control, Hybrid_cTS, V6_cTS, V6_uniform | 1234–1236 | 120 | **12** (+1 loose probe) | `race/smoke_results/pulled/a3seamb_smoke_b{1,2}/` | `…/a3seamb_race_smoke` | `pos_iv_pos_9_a3seamb_<variant>_seed<seed>_n120` |
| 2 | **Thesis** | 06-24/25 | same `53ee6663…`/`4e0f841c…` · `93bda33b` | Seam-B guest `1f5b9372…` | V5_control, Hybrid_cTS, V6_cTS, V6_uniform (×10) | 1234–1243 | 5000 | **40** | `race/thesis_results/a3seamb_thesis_b{1..5}/` | `…/a3seamb_race_thesis` | `pos_iv_pos_9_a3seamb_<variant>_seed<seed>_n5000` |

- **No other / aborted Seam-B dispatches exist.** Batches b1–b5 are dispatch partitions, not separate experiments.
- **DBs are gitignored** (`.gitignore`: `…/thesis_results/`, `…/smoke_results/pulled/`, `*.db`) — they exist locally only; git keeps `markers_out/` + `*.oracle.json`. Stage-0 has **no** persisted DB (durable truth = `ap_seamb_verify.json`, 12 certified accepters, `PASS:true`).

## The binaries — `a4/builds/ap_seamb/` (gitignored; reproducible via `a4/scripts/ap_verifyopcode_patch.py`)
| role | path | sha256 | head | planted_bug | load_rs2 | guest_src |
|---|---|---|---|---|---|---|
| holed | `ap_seamb/bench-verifyopcode/risc0-host` | `53ee6663533f52d378…3490` | `93bda33b4f95…83874` | verifyopcode | 1 | `1f5b9372…` |
| control | `ap_seamb/control/risc0-host` | `4e0f841cf00808f777…592c` | `93bda33b4f95…83874` | none | 1 | `1f5b9372…` |
- **Contaminated** (head `93bda33b` lacks the 3 witgen handlers; see `../../runs/iv_pos_9/race/CONTAMINATION_IMPACT_VERIFICATION.md`). The planned **FIXED** binary = cherry-pick `6556e8d7` → **NEW head_sha** (≠ `93bda33b`); guest_image_id expected unchanged (host-side handler only — re-read to confirm).

## Sibling run that is NOT a Seam-B race (do not count it)
- **CVE rs1==rs2 race** — 24 DBs, head **`98387806`** binary (`a4/builds/a1_cve/`), A2 remu/divu guest, `race/cve_results/cve_thesis_b{1..3}/`, run-id `pos_iv_pos_9_cve_<variant>_seed<seed>_n5000`, seeds 1234–1239. Different bug/binary/guest; the `cve` prefix already separates it.

## Predecessor scheduler races (different experiment: coverage/exploration on a NON-holed binary)
| campaign | what | DBs | run-id prefix | N |
|---|---|---|---|---|
| **IV.POS.7** | V0–V6 internal scheduler race (uniform/zoned/cTS) | ~59 in `runs/iv_pos_7/dbs/` (gitignored) | `pos_iv_pos_7_{u,v6,ts,ta}_*` | 6000 |
| **IV.POS.8 D1.A** | cTS decay variants | `runs/iv_pos_8/d1a/dbs/` | `pos_iv_pos_8_d1a_*` | 6000 |
| **IV.POS.8 D2.F** | 4-variant Bernoulli-floor checkpoint | 20 in `runs/iv_pos_8/d2f/{smoke,prod}/` | `pos_iv_pos_8_d2f_<variant>_seed<seed>_n10000` | 10000/100 |
| **IV.POS.8 D2.G/H** | propagation-triage *analysis* over D2.F | 0 (reuses D2.F) | — | — |
These cannot be confused with the Seam-B race: prefix never `a3seamb`, N is 6000/10000 (never 120/5000), non-holed binary. **Note IV.POS.7 also has a "V0" / "V6" — those are the *historical scheduler-race* labels, distinct from our new race's V0/V8.**

## Collision-free scheme for the NEW fixed-binary campaign (REQUIRED)
The discriminating token is the experiment slug. The old race is `a3seamb` (contaminated). Use a NEW slug so DBs can never collide (a re-run of `V5_control_seed1234_n5000` would otherwise produce an identical run-id to the old contaminated one).
- **Run-id:** `pos_iv_pos_9_a3seambfix_<variant>_seed<seed>_n<N>`, variants `V0 | V5 | V8 | Hybrid` (note: drop the `_control`/`_cTS` suffixes or keep them consistently — pick one and pin it).
- **Binaries:** `a4/builds/ap_seamb_fix/{bench-verifyopcode,control}/risc0-host` (NEW head; fresh `fingerprint.json`).
- **Local results:** `race/fix_thesis_results/` + `race/fix_smoke_results/pulled/`.
- **POS RESULTS_BASE:** `/srv/testbed/results/ivgreiff/a4/a3seambfix_race_{smoke,thesis}`.
- **⚠️ `race_lib._RID` regex must be reconciled.** It is `a3seamb_(?P<variant>.+?)_seed…` — the slug `a3seambfix` does NOT match (`a3seamb` not followed by `_`). Either (i) generalize `_RID` to `_(?P<variant>[A-Za-z0-9]+)_seed(?P<seed>\d+)_n(?P<n>\d+)` and discover by dir, or (ii) keep slug `a3seamb` but route the new run to a separate dir AND change the variant label so no `(variant,seed,N)` collides. (i) is cleaner. **The analysis must read the fixed run separately from the old `thesis_results/` to avoid mixing contaminated + fixed DBs in one dataset.**
- **`.gitignore`:** add `race/fix_thesis_results/`, `race/fix_smoke_results/pulled/`, `a4/builds/ap_seamb_fix/*/risc0-host`.
- **Reused V6 caveat:** if the 6-variant analysis reuses the old contaminated V6_uniform/V6_cTS DBs (binary-invariant — they never touch the 3 dead A4 kinds), label them explicitly as "head 93bda33b, reused" so provenance is unambiguous; the fixed-binary V0/V5/V8/Hybrid are "head <fixed>". Do not silently merge two head_shas without recording it.
