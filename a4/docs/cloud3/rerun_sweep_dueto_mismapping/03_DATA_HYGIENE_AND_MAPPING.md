# Data hygiene & variant→PNG mapping — never plot buggy data again

**Goal (your explicit ask):** separate/quarantine the buggy data so a future notebook run can **never**
accidentally pick it up, and guarantee that when results come back, the **correct, non-buggy variant maps to
the right PNG / table / report label.** Prereq: [01](01_FINDINGS_AND_IMPACT.md), [02](02_RERUN_PLAN.md).

---

## 1. The hazard, concretely

`build_sweep_notebook.py` and `build_sweep_curves.py` read per-(guest,variant) DBs by **path convention only**
— `{DATA}/{guest}_{v}.db` (and g0 from D2.F PROD). There is **no validity check**: whatever `.db` sits at that
path gets plotted under that variant's label. Right now `a4/runs/iv_pos_9/sweep/data/` holds **12 pre-fix DBs
(Jun 24)** — 3-kind-contaminated *and* step-domain-buggy. **If anyone runs the notebook today, it silently
produces wrong PNGs.** That is the exact failure to prevent.

Two independent failure modes to defend against:
1. **Stale-read:** the notebook reads an old buggy DB because it's still at the convention path.
2. **Mis-map:** a correct DB gets plotted under the wrong variant label (or a fixed DB mixed with a pre-fix
   one across guests), so a PNG says "Arguzz Bandit" over data that isn't.

---

## 2. Quarantine (do this the moment the re-run is authorized, before anything else writes here)

Move **every** pre-fix DB out of the notebook's read path into a clearly-condemned dir, and leave a tombstone:

```
mkdir -p a4/runs/iv_pos_9/sweep/_QUARANTINE_pre_stepdomain_fix/
git mv a4/runs/iv_pos_9/sweep/data/*.db \
       a4/runs/iv_pos_9/sweep/_QUARANTINE_pre_stepdomain_fix/
```

Write `_QUARANTINE_pre_stepdomain_fix/README.md`:
> These DBs are **invalid** — pre-fix (`05450d8` and earlier). Arguzz variants carry scrambled CGC/structural
> zone labels (step-domain bug, fixed `68d90aa`); V5/Hybrid additionally carry the 3-kind contamination (F35).
> **Never read these from any notebook/curve/report.** Kept only for forensic comparison (e.g. "0/N
> violations fixed vs legacy"). Superseded by the clean dataset under `data_clean/`.

Quarantine, not delete: the legacy DBs are the negative control that *proves* the fix changed the data (the
N=1000 doc cites "8577 legacy violations → 0 fixed"). Deleting them throws away that evidence.

---

## 3. The clean dataset — one canonical dir, populated only by validated runs

Create a **new** canonical dir and make it the *only* path the notebook reads:

```
a4/runs/iv_pos_9/sweep/data_clean/
  g0_baseline_V5_control.db        ← 3-kind re-run (results_rerun/miss), provenance-verified
  g0_baseline_V6_uniform.db        ← step-domain re-run (bundle 68d90aa)
  g0_baseline_V6_cTS.db            ← step-domain re-run
  g0_baseline_Hybrid_cTS.db        ← step-domain re-run
  g1_…  g2_…  g3_…                  (same 4 variants each)
  PROVENANCE.md                    ← the manifest (§4)
```

Rules:
- A DB enters `data_clean/` **only after** passing the post-run verification ([02 §5](02_RERUN_PLAN.md)):
  guard-clean, behavioral landmark, provenance stamp.
- **V5_control** rows come from the **3-kind re-run** (valid). **V6_uniform / V6_cTS / Hybrid_cTS** rows come
  from the **step-domain re-run** (`68d90aa`). No row ever comes from `data/` (now quarantined) or from the
  cross-binary D2.F g0 (retired by F35 — g0 is now a same-binary guest like the rest).
- Point the readers at it: change `DATA` in `build_sweep_notebook.py` and `AN`/`sweep_db()` in
  `build_sweep_curves.py` to `data_clean/`, and **remove the D2.F-PROD g0 fallback** so g0 cannot silently
  fall back to the retired cross-binary baseline.

---

## 4. Provenance manifest + self-identifying DBs (defends against mis-map)

External manifest `data_clean/PROVENANCE.md`, one row per DB:

| db file | guest | variant | source run | bundle commit | binary fp (sha16) | step-domain fix? | 3-kind fix? | verified | date |
|---|---|---|---|---|---|---|---|---|---|
| g0_baseline_V5_control.db | g0 | V5_control | results_rerun/… | 05450d8 | `<fp>` | n/a (A4) | ✅ (53c21894) | ✅ | … |
| g0_baseline_V6_cTS.db | g0 | V6_cTS | stepfix.chain/… | **68d90aa** | `<fp>` | ✅ | n/a (Arguzz) | ✅ | … |
| … | | | | | | | | | |

Because the binary fingerprint is identical with/without the step-domain fix (rebuild-free), the **bundle
commit** is the only field that distinguishes fixed from buggy Arguzz data. Two safeguards make the DBs
**self-identifying** so the manifest can't drift from reality:

- **Stamp the bundle commit into each run** (small, recommended dispatch enhancement): the per-job
  `remote_cmd` already emits `build_fingerprint.json` (binary fp). Add the **repo git-short** (`68d90aa`)
  alongside it — written next to `run.db` — so each result carries the harness version that produced it.
- **Notebook/curve guard:** at load, for each `(guest,variant)` assert (a) the file lives under `data_clean/`,
  (b) it has a `PROVENANCE.md` row, and (c) for Arguzz variants the recorded bundle commit is **≥ 68d90aa**
  (i.e. the fix is present). **Refuse to plot** (raise) on any miss — a hard stop beats a wrong PNG.

This closes the loop the *binary* fingerprint guard (G11) already closes for the executable, but for the
**Python harness version** — the dimension this whole incident turned on.

---

## 5. Variant → display-label → PNG mapping (must stay exact)

The thesis display names are fixed in `build_sweep_curves.py` (`DISPLAY`) and must continue to map the
**correct fixed DB** to each label:

| code variant | DB column read | display label (PNG/table) | data source after fix |
|---|---|---|---|
| `V5_control` | `data_clean/{g}_V5_control.db` | **A3 Bandit** | 3-kind re-run (valid) |
| `V6_uniform` | `data_clean/{g}_V6_uniform.db` | **Arguzz** | step-domain re-run |
| `V6_cTS` | `data_clean/{g}_V6_cTS.db` | **Arguzz Bandit** | step-domain re-run |
| `Hybrid_cTS` | `data_clean/{g}_Hybrid_cTS.db` | **A3+Arguzz Bandit** | step-domain re-run |

Mapping checklist when results return:
- [ ] every `data_clean/{guest}_{variant}.db` has a matching `PROVENANCE.md` row with `verified ✅`;
- [ ] each Arguzz-variant DB's stamped bundle commit ≥ `68d90aa`; each V5 DB is the 3-kind-patched build;
- [ ] the per-DB **behavioral landmark** holds (Arguzz `core_div` arms inject on the guest's real divide
      executor-steps) — i.e. the DB labeled "Arguzz Bandit" really is post-fix Arguzz-bandit data;
- [ ] notebook + curves regenerated **from `data_clean/` only**, guard enabled, zero load-time refusals;
- [ ] PNG titles/legends use the `DISPLAY` names and overlay g0 baseline solid/dashed as before — visually
      confirm no variant is missing or duplicated per guest.

---

## 6. One-line policy

`data/` is condemned and emptied into `_QUARANTINE_pre_stepdomain_fix/`; the **only** plottable data lives in
`data_clean/`, every file there is provenance-stamped (bundle ≥ `68d90aa` for Arguzz, 3-kind-patched for V5)
and behaviorally verified, and the notebook/curves **refuse to run** on anything that isn't.
