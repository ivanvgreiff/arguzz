#!/usr/bin/env python3
"""Aggregate E5 atoms into stats JSON + DISTRIBUTIONS.md (re-aggregation only)."""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO))

from thesis_side_experiments.bias_campaign.classify import (  # noqa: E402
    PANIC_RE,
    is_preflight_crash,
)
from thesis_side_experiments.minimal_add.analyze_logs import is_prove_error  # noqa: E402

ATOMS = ROOT / "artifacts" / "e5" / "atoms"
RAW = ROOT / "artifacts" / "e5" / "pos_raw"
OUT_JSON = ROOT / "artifacts" / "e5" / "e5_stats.json"
OUT_MD = ROOT / "artifacts" / "e5" / "DISTRIBUTIONS.md"
NOTES = ROOT / "artifacts" / "e5" / "E5_STATS_FIX_NOTES.md"

ARGUZZ_CLASS_SPECIFIC = frozenset(
    {"COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD", "BR_NEG_COND"}
)

EXPECTED_FIRED = {
    ("arguzz", "COMP_OUT_MOD"): 150,
    ("arguzz", "LOAD_VAL_MOD"): 49,
    ("arguzz", "STORE_OUT_MOD"): 99,
    ("arguzz", "BR_NEG_COND"): 72,
}

ARGUZZ_STAGE = {
    "COMP_OUT_MOD": "in_place",
    "LOAD_VAL_MOD": "in_place",
    "STORE_OUT_MOD": "in_place",
    "INSTR_WORD_MOD": "in_place",
    "BR_NEG_COND": "in_place",
    "PRE_EXEC_PC_MOD": "pre",
    "POST_EXEC_PC_MOD": "post",
    "PRE_EXEC_MEM_MOD": "pre",
    "POST_EXEC_MEM_MOD": "post",
    "PRE_EXEC_REG_MOD": "pre",
    "POST_EXEC_REG_MOD": "post",
}

A4_STAGE = {
    "COMP_OUT_MOD": "witness_value",
    "LOAD_VAL_MOD": "witness_value",
    "STORE_OUT_MOD": "witness_value",
    "INSTR_WORD_MOD_FULL": "word_type",
    "INSTR_WORD_MOD_SUR": "word_type",
    "MEM_VAL_MOD": "mem_read",
    "PRE_EXEC_REG_MOD": "reg",
    "INSTR_TYPE_MOD": "word_type",
}


def group_key(atom: dict) -> Tuple[str, str, str]:
    v = atom.get("variant") or "default"
    return (atom["fuzzer"], atom["mutation_type"], v)


def triple(layers: dict) -> str:
    i = 1 if layers.get("intrastep_local", 0) else 0
    inter = 1 if layers.get("interstep_local", 0) else 0
    g = 1 if layers.get("global", 0) else 0
    return f"{i}/{inter}/{g}"


def atom_fired(atom: dict) -> bool:
    if atom["fuzzer"] == "a4":
        return True
    info = atom.get("fault_info") or ""
    return "<fault" in info


def load_log(raw_dir: Path, atom: dict, cache: dict) -> str:
    sid = atom["sample_id"]
    if sid in cache:
        return cache[sid]
    rel = atom.get("raw_log_path") or ""
    candidates = [
        raw_dir / f"{sid}.log.gz",
        ROOT / rel if rel else None,
    ]
    text = ""
    for p in candidates:
        if p and p.is_file():
            with gzip.open(p, "rt", encoding="utf-8", errors="replace") as f:
                text = f.read()
            break
    cache[sid] = text
    return text


def classify_crash_stage(atom: dict, log_text: str) -> Optional[str]:
    if not atom.get("crashed"):
        return None
    stage = atom.get("crash_stage")
    if stage == "prove":
        return "prove_error"
    if stage in ("preflight", "prove_error"):
        return stage

    if is_prove_error(log_text):
        return "prove_error"
    pm = PANIC_RE.search(log_text)
    loc = pm.group(1) if pm else ""
    if "preflight.rs" in loc or is_preflight_crash(loc) or "/witgen/" in loc:
        return "preflight"
    oc = atom.get("outcome_class")
    if oc == "PREFLIGHT_CRASH":
        return "preflight"
    if oc == "PROVE_ERROR":
        return "prove_error"
    if oc == "OTHER_CRASH":
        if "main.rs" in loc or "rv32im.rs" in loc or "/execute/" in loc:
            return "prove_error"
    return "unknown"


def enrich_atoms(atoms: List[dict], raw_dir: Path) -> None:
    cache: dict = {}
    for a in atoms:
        if a.get("crashed"):
            log = load_log(raw_dir, a, cache)
            a["_crash_stage"] = classify_crash_stage(a, log)
        else:
            a["_crash_stage"] = None


def _summarize_core(atoms: List[dict], use_crash_stage_key: str = "_crash_stage") -> dict:
    n = len(atoms)
    if n == 0:
        return {"n": 0}

    crashes = [a for a in atoms if a.get("crashed")]
    reached = [a for a in atoms if not a.get("crashed") and a.get("failure_count", 0) > 0]
    triple_hist: Counter = Counter()
    loc_hist: Counter = Counter()
    crash_stages: Counter = Counter()
    guest_hits = sum(1 for a in atoms if a.get("hits_guest_data"))

    sum_i = sum(a["layers"].get("intrastep_local", 0) for a in atoms)
    sum_inter = sum(a["layers"].get("interstep_local", 0) for a in atoms)
    sum_g = sum(a["layers"].get("global", 0) for a in atoms)

    for a in atoms:
        triple_hist[triple(a["layers"])] += 1
        for c in a.get("constraints") or []:
            loc_hist[c.get("full_loc") or c.get("loc", "?")] += 1

    for a in crashes:
        stage = a.get(use_crash_stage_key) or "unknown"
        crash_stages[stage] += 1

    with_i = sum(1 for a in atoms if a["layers"].get("intrastep_local", 0) > 0)
    with_inter = sum(1 for a in atoms if a["layers"].get("interstep_local", 0) > 0)
    with_g = sum(1 for a in atoms if a["layers"].get("global", 0) > 0)

    return {
        "n": n,
        "crash_rate": len(crashes) / n,
        "crash_stages": dict(crash_stages),
        "reached_constraints_rate": len(reached) / n,
        "P_intrastep_ge1": with_i / n,
        "P_interstep_ge1": with_inter / n,
        "P_global_ge1": with_g / n,
        "mean_intrastep": sum_i / n,
        "mean_interstep": sum_inter / n,
        "mean_global": sum_g / n,
        "triple_histogram": dict(triple_hist),
        "guest_data_hit_rate": guest_hits / n,
        "top_locs": [{"loc": loc, "count": c} for loc, c in loc_hist.most_common(10)],
    }


def summarize_group(atoms: List[dict]) -> dict:
    raw = _summarize_core(atoms)
    fired_atoms = [a for a in atoms if atom_fired(a)]
    fired = _summarize_core(fired_atoms)
    fired_silent = sum(
        1 for a in fired_atoms if triple(a["layers"]) == "0/0/0" and not a.get("crashed")
    )
    out = dict(raw)
    out["n_fired"] = fired["n"]
    out["firing_rate"] = fired["n"] / raw["n"] if raw["n"] else 0
    out["fired_silent_rate"] = fired_silent / fired["n"] if fired["n"] else 0
    for key, val in fired.items():
        if key == "n":
            continue
        out[f"{key}_fired"] = val
    return out


def stage_rollup(groups_atoms: Dict[Tuple[str, str, str], List[dict]]) -> dict:
    stage_atoms: Dict[str, List[dict]] = defaultdict(list)
    for (fuzzer, mtype, _variant), xs in groups_atoms.items():
        if fuzzer == "arguzz":
            stage = ARGUZZ_STAGE.get(mtype, "other")
        else:
            stage = A4_STAGE.get(mtype, "other")
        stage_atoms[f"{fuzzer}:{stage}"].extend(xs)
    return {k: summarize_group(v) for k, v in sorted(stage_atoms.items())}


def _fmt_rates(s: dict, prefix: str = "") -> str:
    p = f"_{prefix}" if prefix else ""
    return (
        f"P(i≥1)={s[f'P_intrastep_ge1{p}']:.3f}, "
        f"P(inter≥1)={s[f'P_interstep_ge1{p}']:.3f}, "
        f"P(g≥1)={s[f'P_global_ge1{p}']:.3f}"
    )


def render_md(by_group: Dict[Tuple[str, str, str], dict], stages: dict, n_expected: int) -> str:
    lines = ["# E5 constraint distributions", ""]
    lines.append(f"Expected N per type-variant: **{n_expected}**")
    lines.append("")
    lines.append(
        "Arguzz class-specific kinds (COMP/LOAD/STORE/BR) show **fired-conditional** rates "
        "as primary; raw all-sample rates included for comparison."
    )
    lines.append("")
    lines.append("## Per type-variant")
    lines.append("")

    for key in sorted(by_group.keys()):
        fuzzer, mtype, variant = key
        s = by_group[key]
        label = f"{fuzzer} / {mtype}" + (f" / {variant}" if variant != "default" else "")
        lines.append(f"### {label}")
        lines.append("")
        lines.append(
            f"- n={s['n']}, crash_rate={s['crash_rate']:.3f} "
            f"(stages: {s['crash_stages'] or 'none'})"
        )

        if fuzzer == "arguzz" and mtype in ARGUZZ_CLASS_SPECIFIC:
            lines.append(
                f"- **fired** {s['n_fired']}/{s['n']} ({s['firing_rate']:.1%}); "
                f"fired-silent={s['fired_silent_rate']:.1%}"
            )
            lines.append(
                f"- **fired-conditional:** reached={s['reached_constraints_rate_fired']:.3f}, "
                + _fmt_rates(s, "fired")
            )
            lines.append(
                f"- all-sample (diluted): reached={s['reached_constraints_rate']:.3f}, "
                + _fmt_rates(s)
            )
        else:
            lines.append(
                f"- reached={s['reached_constraints_rate']:.3f}, " + _fmt_rates(s)
            )

        lines.append(f"- guest_data_hit_rate={s['guest_data_hit_rate']:.3f}")
        hist_key = "triple_histogram_fired" if (
            fuzzer == "arguzz" and mtype in ARGUZZ_CLASS_SPECIFIC
        ) else "triple_histogram"
        lines.append(f"- triple histogram: `{s[hist_key]}`")
        top_key = "top_locs_fired" if (
            fuzzer == "arguzz" and mtype in ARGUZZ_CLASS_SPECIFIC
        ) else "top_locs"
        if s.get(top_key):
            lines.append("- top locs:")
            for row in s[top_key][:5]:
                lines.append(f"  - `{row['loc']}` ×{row['count']}")
        lines.append("")

    lines.append("## Stage rollups")
    lines.append("")
    for stage, s in stages.items():
        lines.append(
            f"- **{stage}**: n={s['n']} fired={s['n_fired']} "
            f"crash={s['crash_rate']:.3f} {s['crash_stages'] or {}} "
            f"P(i/inter/g)_fired=({s['P_intrastep_ge1_fired']:.2f}/"
            f"{s['P_interstep_ge1_fired']:.2f}/{s['P_global_ge1_fired']:.2f})"
        )
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append(
        "Distribution study only — no matrix, no paired comparison. "
        "Crash stages count only `crashed==true` atoms (preflight vs prove_error); "
        "constraint rejects are not crashes."
    )
    return "\n".join(lines) + "\n"


def render_fix_notes(
    by_group: Dict[Tuple[str, str, str], dict],
    fired_validation: dict,
    crash_validation: dict,
) -> str:
    lines = [
        "# E5 stats fix notes (re-aggregation only — no re-proving)",
        "",
        "## Fix 1 — fired-conditional Arguzz class-specific kinds",
        "",
        "Rates recomputed over samples where `<fault>` was emitted (`n_fired/n`).",
        "",
        "| kind | n_fired/n | expected | match |",
        "|------|-----------|----------|-------|",
    ]
    for (fuzzer, mtype), expected in sorted(EXPECTED_FIRED.items()):
        key = (fuzzer, mtype, "default")
        s = by_group[key]
        got = s["n_fired"]
        ok = got == expected
        lines.append(f"| {mtype} | {got}/{s['n']} | {expected}/250 | {'✓' if ok else '✗'} |")

    lines.extend(["", "Other Arguzz kinds and all A4 kinds: n_fired=n=250.", ""])
    lines.append("### Fired-conditional reached rate (selected)")
    lines.append("")
    for mtype in sorted(ARGUZZ_CLASS_SPECIFIC):
        s = by_group[("arguzz", mtype, "default")]
        lines.append(
            f"- **{mtype}**: all-sample reached={s['reached_constraints_rate']:.1%} → "
            f"fired reached={s['reached_constraints_rate_fired']:.1%} "
            f"(fired-silent={s['fired_silent_rate']:.1%})"
        )

    lines.extend(["", "## Fix 2 — crash accounting", ""])
    lines.append("`crash_stages` tallies only `crashed==true` atoms, bucketed by backfilled stage.")
    lines.append("")
    lines.append(f"- A4 crashes: **{crash_validation['a4_crashes']}** (expected 0)")
    lines.append("")
    lines.append("| mutation_type | preflight | prove_error |")
    lines.append("|---------------|-----------|-------------|")
    for mtype, stages in sorted(crash_validation["arguzz_by_type"].items()):
        lines.append(
            f"| {mtype} | {stages.get('preflight', 0)} | {stages.get('prove_error', 0)} |"
        )
    lines.append("")
    lines.append(f"Total Arguzz crashed: {crash_validation['arguzz_crashes']}")
    if fired_validation["all_ok"] and crash_validation["a4_crashes"] == 0:
        lines.append("")
        lines.append("**Validation gate: PASS**")
    return "\n".join(lines) + "\n"


def validate_fired(by_group: dict, n_expected: int) -> dict:
    checks = {}
    all_ok = True
    if n_expected == 250:
        for key, expected in EXPECTED_FIRED.items():
            gkey = (*key, "default")
            got = by_group[gkey]["n_fired"]
            checks[str(key)] = {"got": got, "expected": expected, "ok": got == expected}
            all_ok = all_ok and got == expected
    for key, s in by_group.items():
        fuzzer, mtype, _ = key
        if fuzzer == "a4":
            if s["n_fired"] != s["n"]:
                checks[str(key)] = {"got": s["n_fired"], "expected": s["n"], "ok": False}
                all_ok = False
            continue
        if mtype not in ARGUZZ_CLASS_SPECIFIC:
            if s["n_fired"] != s["n"]:
                checks[str(key)] = {"got": s["n_fired"], "expected": s["n"], "ok": False}
                all_ok = False
    return {"checks": checks, "all_ok": all_ok}


def validate_crashes(atoms: List[dict]) -> dict:
    a4_crashes = sum(1 for a in atoms if a["fuzzer"] == "a4" and a.get("crashed"))
    arguzz = [a for a in atoms if a["fuzzer"] == "arguzz" and a.get("crashed")]
    by_type: Dict[str, Counter] = defaultdict(Counter)
    for a in arguzz:
        by_type[a["mutation_type"]][a["_crash_stage"]] += 1
    return {
        "a4_crashes": a4_crashes,
        "arguzz_crashes": len(arguzz),
        "arguzz_by_type": {k: dict(v) for k, v in sorted(by_type.items())},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-expected", type=int, default=20)
    ap.add_argument("--atoms-dir", type=Path, default=ATOMS)
    ap.add_argument("--raw-dir", type=Path, default=RAW)
    ap.add_argument("--out-json", type=Path, default=OUT_JSON)
    ap.add_argument("--out-md", type=Path, default=OUT_MD)
    ap.add_argument("--notes", type=Path, default=NOTES)
    args = ap.parse_args()

    atom_files = sorted(args.atoms_dir.glob("*.json"))
    if not atom_files:
        raise SystemExit(f"no atoms in {args.atoms_dir}")

    atoms = [json.loads(p.read_text()) for p in atom_files]
    enrich_atoms(atoms, args.raw_dir)

    groups: Dict[Tuple[str, str, str], List[dict]] = defaultdict(list)
    for a in atoms:
        groups[group_key(a)].append(a)

    by_group = {k: summarize_group(v) for k, v in sorted(groups.items())}
    stages = stage_rollup(groups)

    fired_val = validate_fired(by_group, args.n_expected)
    crash_val = validate_crashes(atoms)

    out = {
        "atom_count": len(atoms),
        "group_count": len(by_group),
        "n_expected_per_type": args.n_expected,
        "by_type_variant": {
            f"{f}::{m}::{v}": s for (f, m, v), s in by_group.items()
        },
        "stage_rollups": stages,
        "validation": {
            "fired_counts": fired_val,
            "crash_counts": crash_val,
        },
    }

    mismatches = []
    for key, s in by_group.items():
        if s["n"] != args.n_expected:
            mismatches.append({"group": key, "n": s["n"], "expected": args.n_expected})

    out["count_mismatches"] = mismatches
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(out, indent=2))
    args.out_md.write_text(render_md(by_group, stages, args.n_expected))
    if args.notes:
        args.notes.write_text(render_fix_notes(by_group, fired_val, crash_val))

    print(f"wrote {args.out_json} ({len(atoms)} atoms, {len(by_group)} groups)")
    if mismatches:
        print(f"WARN: {len(mismatches)} groups with n != {args.n_expected}")
    if not fired_val["all_ok"]:
        print("WARN: fired count validation mismatch", fired_val["checks"])
    if crash_val["a4_crashes"]:
        print(f"WARN: A4 crashes={crash_val['a4_crashes']} (expected 0)")


if __name__ == "__main__":
    main()
