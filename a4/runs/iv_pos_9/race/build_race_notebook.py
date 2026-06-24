#!/usr/bin/env python3
"""Assemble the Seam-B bug-race analysis notebook (IV_POS_9_A3_ANALYSIS_SPEC), execute,
export self-contained HTML. Mirrors build_d2h_notebook.py.

Renders whatever campaign RESULTS_DIR points at (thesis default; smoke fallback). The
RESULTS_DIR is baked into the first code cell so the notebook is reproducible.

    RESULTS_DIR=a4/runs/iv_pos_9/race/thesis_results python3 a4/runs/iv_pos_9/race/build_race_notebook.py
"""
import os
from pathlib import Path

import nbformat as nbf
from nbconvert import HTMLExporter
from nbconvert.preprocessors import ExecutePreprocessor

RACE = Path("/root/arguzz/a4/runs/iv_pos_9/race")
IPYNB = RACE / "race_exploration.ipynb"
HTML = RACE / "race_exploration.html"
RESULTS_DIR = os.environ.get("RESULTS_DIR", "a4/runs/iv_pos_9/race/thesis_results")


def md(s):
    return nbf.v4.new_markdown_cell(s.strip("\n"))


def code(s):
    return nbf.v4.new_code_cell(s.strip("\n"))


cells = [
    md(r"""
# The bug race — does A4 find the planted VerifyOpcode soundness bug, and can Arguzz?

**What this is.** The four fuzzing variants race, on a binary whose *only* planted flaw is a removed
`VerifyOpcode*` decode-equality constraint, to **discover that underconstraint**. We record, for every
mutation, whether the verifier accepts it and (via the control binary) whether that accept is the
planted bug. **No stop-on-first-bug** — full budget, every find and its mutation-index recorded.

**The headline question (race spec §0):** *which variants discover the hole, how often, and at what
mutation index?* The hypothesis under test — **A4-surface variants apply `INSTR_TYPE_MOD` and find it;
pure-Arguzz variants structurally cannot apply `INSTR_TYPE_MOD` and so never find it** — must be
**falsifiable**, and is (every Arguzz accept is control-checked; §5 below).

### Is this "just smoke"? No — read this.
There are three runs; do not conflate them:
- **Ground truth (S0):** 12 certified finds + a negative control through the oracle — *proves the oracle.*
- **Smoke (S1, N=120):** pipeline validation on POS — *that* is the smoke for the real race.
- **Thesis (S2, N=5000 × 4 variants × 10 paired seeds):** **the real result** — the **A4 side** of the
  complementarity claim. The **other side** is the later **`rs1==rs2` CVE race** (a *real*, value-changing
  bug) where the mirror is expected: Arguzz/Hybrid find it, pure A4 does not. **The two races together =
  the full bidirectional complementarity table.** This notebook renders whichever campaign it is pointed at.

### The two oracles (ProG_Report_5 §3.8) — and honest severity
This bug is a **decode** underconstraint, so its finds are **result-preserving** (no journal/`OOPS`
change — the rd-write integrity constraint `MemoryWrite` is intact). We therefore use the **internal
trace-soundness oracle**: *the control binary rejects the identical mutation specifically at
`VerifyOpcode*`.* This is the "fairer-to-A4" oracle; the CVE race will use the **strong application-level
oracle** (accepted proof + wrong journal). **This is not a weak result — it is the point:** A4's
post-execution surface reaches the **local/decode** constraint family; the value/permutation bugs are
Arguzz's domain. A result-preserving decode underconstraint is exactly the kind of bug A4 is built to find.

| variant | mutation surface | scheduler | can it apply `INSTR_TYPE_MOD`? |
|---|---|---|---|
| **V5_control** | **A4** — post-execution witness/trace-cell mutation | cTS | **yes** |
| **Hybrid_cTS** | **A4 + Arguzz** (15 kinds) | cTS | **yes** |
| **V6_cTS** | **Arguzz** — during-execution fault injection | cTS | **no (structural)** |
| **V6_uniform** | **Arguzz** | round-robin | **no (structural)** |
"""),
    code(f"""
import os, sys, json
os.chdir("/root/arguzz")
sys.path.insert(0, "/root/arguzz")
import pandas as pd
from a4.runs.iv_pos_9.race import race_lib
RESULTS_DIR = {RESULTS_DIR!r}
d = race_lib.load_data(RESULTS_DIR)
print(f"campaign = {{d['label']}}   N = {{d['N']}}   seeds done = {{d['seeds']}}   runs = {{len(d['per_run'])}}")
print(json.dumps(race_lib.summary(d), indent=2, default=str))
"""),
    md(r"""
## 1. The find signal — what counts as a "find", and why we trust it

A confirmed **planted find** is an `INSTR_TYPE_MOD` accept that is **decode-divergent** (the claimed
instruction `(major,minor)` differs from the fetched word's true decode) and that the **clean control
binary rejects at `VerifyOpcode*`**. On a binary whose only hole is `VerifyOpcode`, such an accept is
control-rejected there *by construction* (F8) — so the notebook counts these structurally
(`oracle.is_decode_divergent_itm`, no per-find binary re-run), and the control re-run is a **spot-check**:
- **Ground truth (S0):** 12 such finds were control-confirmed to reject @ `VerifyOpcode`, and 44
  result-changers rejected @ `MemoryWrite` (so they never even reach "accept").
- **Falsifier:** every accept — *including* non-`INSTR_TYPE_MOD` ones — is control-checked, so a hypothetical
  Arguzz accept that rejected @ `VerifyOpcode` *would* be caught. None is expected (§5).
- The one step deferred to a **fast POS node** (where the control proves ~3 s vs ~30 s on the dev box) is a
  control-confirm **sample** of thesis finds for the final writeup; the structural counts do not depend on it.

**Headline per-variant summary** (live from the DBs):
"""),
    code(r"""
tbl = race_lib.per_variant_table(d)
def pct(x):  return "—" if x is None else f"{x*100:.2f}%"
def ci(p, lo, hi): return "—" if p is None else f"{p:.2f} [{lo:.2f}, {hi:.2f}]"
rows = [{
    "variant": r["variant"], "surface": r["surface"], "seeds": r["seeds_done"],
    "P(found) [95% CI]": ci(r["P_found"], r["P_found_lo"], r["P_found_hi"]),
    "finds (total)": r["total_finds"], "finds/seed": f"{r['mean_finds']:.1f}",
    "ITM applied/seed": f"{r['mean_itm_applied']:.0f}",
    "P(find|ITM) [95% CI]": (ci(r["cond_find_density"], r["cond_lo"], r["cond_hi"]) if r["cond_find_density"] is not None else "n/a (0 ITM)"),
    "1st-find idx (med)": ("—" if r["first_find_idx_median"] is None else f"{r['first_find_idx_median']:.0f}"),
    "s/mut": f"{r['mean_per_mut_s']:.1f}",
} for r in tbl]
pd.set_option("display.max_colwidth", None)
pd.DataFrame(rows).set_index("variant")
"""),
    md(r"""
## 2. The headline — A4 reaches the bug; pure Arguzz cannot even apply the mutation

The single clearest result: the planted bug lives behind `INSTR_TYPE_MOD` (a decode-selector edit). The
**A4-surface variants apply it hundreds–thousands of times per run and find the hole**; the
**pure-Arguzz variants apply it exactly zero times** — `INSTR_TYPE_MOD` is absent from
`MUTATION_KINDS_ARGUZZ_*`, so the bug is **off their attack surface entirely**. Left = the reachable
surface (ITM applied); right = confirmed finds.
"""),
    code("race_lib.show(race_lib.fig_finds_reach(d))"),
    md(r"""
## 3. The mechanism — *why* the result is what it is

`P(find) = P(apply INSTR_TYPE_MOD) × P(find | ITM applied)` (ProG_Report_5 §3.7). Decomposing the race
into these two factors turns a win/loss into an explanation:

- **P(apply ITM)** — does the scheduler ever apply the bug-relevant mutation? For pure Arguzz this is
  **identically 0** (structural, F7) → `P(find)=0` *at any budget, no matter how hard it searches*. For
  A4/Hybrid it is positive (Hybrid lower, since it splits budget across the A4+Arguzz kinds).
- **P(find | ITM)** — given an ITM mutation, how often is it the bug? This is the *bug-intrinsic* rate
  (only result-coincident decode substitutions accept; the rest reject @ `MemoryWrite`) — measured here,
  no longer the n=1 ≈4% guess.

The complementarity is in the **first factor**: it is zero for Arguzz by construction.
"""),
    code("race_lib.show(race_lib.fig_decomposition(d))"),
    md(r"""
## 4. Discovery dynamics — how fast, and the survival/CDF view

Two views of *when* the finds happen. Left: **cumulative finds** over the N pulls (the discovery rate;
Arguzz lines sit flat on zero). Right: the **mutations-to-first-find CDF** (ProG §3.7's survival framing) —
the fraction of seeds that have found the bug by a given mutation index; **censored** seeds (no find in N)
never reach 1.0, so the Arguzz curves stay on the floor.
"""),
    code("race_lib.show(race_lib.fig_cumulative_finds(d))"),
    code("race_lib.show(race_lib.fig_discovery_cdf(d))"),
    md(r"""
## 5. The falsifier — Arguzz=0 is *tested*, not assumed

The strong version of "Arguzz can't find it" would be vacuous if we only ever looked at `INSTR_TYPE_MOD`.
We don't: **every** accepted mutation — including Arguzz's non-ITM accepts (`INSTR_WORD_MOD`,
`POST_EXEC_PC_MOD`, …) — is control-checked. The chart below splits each variant's accepts into
**confirmed planted finds** (control rejects @ `VerifyOpcode`) vs **non-planted** (the control accepts
them too — benign / no-op). **Every Arguzz accept lands in the non-planted bucket**, so `P(found)=0` is an
empirical negative, not an assumption. (A non-planted accept that *had* rejected @ `VerifyOpcode` would
have surfaced as a find — the falsifier path exists and stayed empty.)
"""),
    code("race_lib.show(race_lib.fig_accept_channels(d))"),
    code(r"""
# per-run markers (each (variant, seed) campaign)
pr = race_lib.per_run_table(d)
df = pd.DataFrame(pr)
df["conditional_find_density"] = df["conditional_find_density"].map(lambda x: "n/a" if x is None else f"{x*100:.1f}%")
df
"""),
    md(r"""
## 6. Severity (read honestly) + 7. What this means

**Severity.** The finds are **result-preserving** decode substitutions — the verifier accepts a proof
whose instruction-type contradicts the fetched word, with no value change. That is a genuine soundness
**underconstraint** (the decode binding is gone) but a **non-propagating, low-severity** one. We report it
as such: it is the *decode-family* bug A4's post-execution surface is built to reach, not a value bug.

**The complementarity verdict.**
- **A4 / Hybrid** discover the planted `VerifyOpcode` hole reliably (`P(found)` high; finds scale with the
  ITM-application budget).
- **Pure Arguzz** (`V6_uniform`, `V6_cTS`) discover it **never**, because the bug-relevant mutation is
  **off their attack surface** — a *structural* complementarity, not a search-efficiency loss.
- This is **one half** of the thesis claim. The **`rs1==rs2` CVE race** (real, value-changing bug) is the
  mirror: there the strong journal oracle applies, and the expectation flips — **Arguzz/Hybrid find it,
  pure A4 does not** (the value is permutation-bound). Together the two races are the full table:

  | bug class | found by A4 (V5) | found by Arguzz (V6) | found by Hybrid |
  |---|---|---|---|
  | **decode underconstraint** (this race, VerifyOpcode) | **yes** | **no (off surface)** | yes |
  | **value/permutation CVE** (rs1==rs2, later) | *expected no* | *expected yes* | *expected yes* |

**On full vs partial data.** When this notebook is built mid-campaign it shows only the finished seeds
(see "seeds done" above); the per-variant `P(found)` CIs tighten and the discovery CDFs smooth as the
remaining seeds land. Re-running `build_race_notebook.py` at `CHAIN_COMPLETE` regenerates the final
figures unchanged in structure. The same script, pointed at the CVE-race DBs (and with the strong oracle
swapped in per race-spec §10), produces the mirror analysis.
"""),
]

nb = nbf.v4.new_notebook(cells=cells, metadata={"kernelspec": {
    "name": "python3", "display_name": "Python 3", "language": "python"}})

print(f"[build] RESULTS_DIR={RESULTS_DIR} ; executing notebook ...")
ep = ExecutePreprocessor(timeout=600, kernel_name="python3")
ep.preprocess(nb, {"metadata": {"path": str(RACE)}})
nbf.write(nb, str(IPYNB))
print(f"[saved] {IPYNB}")

html, _ = HTMLExporter(template_name="classic").from_notebook_node(nb)
HTML.write_text(html)
print(f"[saved] {HTML}  ({len(html)//1024} KB)")

errs = [o for c in nb.cells if c.cell_type == "code"
        for o in c.get("outputs", []) if o.get("output_type") == "error"]
imgs = sum(1 for c in nb.cells if c.cell_type == "code"
           for o in c.get("outputs", []) if "image/png" in o.get("data", {}))
assert not errs, f"cell errors: {[(e.get('ename'), e.get('evalue')) for e in errs]}"
assert imgs == 5, f"expected exactly 5 figures, got {imgs}"
assert HTML.stat().st_size > 80_000, "HTML too small"
print(f"[ok] {imgs} figures; 0 errors; HTML {HTML.stat().st_size//1024} KB")
