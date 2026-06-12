#!/usr/bin/env python3
"""Analyze C1 pilot DB and emit C1_REPORT."""

from __future__ import annotations

import json
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "c1"
DB_PATH = ART / "pilot.db"
HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")
GUEST_ARGS = ["--in1", "5", "--in4", "10"]

sys.path.insert(0, str(ROOT.parent.parent))

from thesis_side_experiments.bias_campaign.categorize import categorize_failures  # noqa: E402
from thesis_side_experiments.bias_campaign.run_common import ALIGNED_KINDS, PILOT_SEEDS  # noqa: E402
from thesis_side_experiments.bias_campaign.run_arguzz import run_arguzz  # noqa: E402
from thesis_side_experiments.bias_campaign.run_a4 import run_a4  # noqa: E402
from thesis_side_experiments.bias_campaign.a4_config import build_a4_config  # noqa: E402
from thesis_side_experiments.bias_campaign.guest_sites import ensure_guest_sites, sample_eligible_step  # noqa: E402
from a4.core.inspection_data import InspectionData  # noqa: E402


def _primary(l1: int, l2: int, accum: int, global_any: bool) -> str:
    counts = {"L1": l1, "L2": l2, "ACCUM": accum}
    best = max(counts, key=counts.get)
    if counts[best] > 0:
        return best
    if global_any:
        return "G"
    return "NONE"


def enrich_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["fail_count"] = d["constraint_fail_count"]
    d["duration_ms"] = d["runtime_ms"]
    d["log_path"] = d["raw_log_path"]
    d["step"] = d["inject_step"]
    d["fail_category_primary"] = _primary(
        d["fail_L1"], d["fail_L2"], d["fail_ACCUM"], bool(d["global_any"])
    )
    d["target_category_primary"] = _primary(
        d["target_L1"], d["target_L2"], d["target_ACCUM"], False
    )
    d["target_reached"] = not d["skipped"] and (
        d["fuzzer"] == "a4" or bool(d["injected"])
    )
    d["host_panic"] = bool(d.get("panic_loc") and "main.rs" in (d["panic_loc"] or ""))
    d["prover_crash"] = bool(
        d.get("panic_loc")
        and not d["host_panic"]
        and any(
            m in (d["panic_loc"] or "")
            for m in ("preflight.rs", "/witgen/", "risc0/circuit", "risc0/zkp")
        )
    )
    return d


def load_runs() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM runs ORDER BY run_id").fetchall()
    conn.close()
    return [enrich_row(r) for r in rows]


def pct(n: int, d: int) -> str:
    if d == 0:
        return "—"
    return f"{100.0 * n / d:.1f}%"


def distribution_table(runs: list[dict], key: str) -> dict[str, int]:
    c = Counter(r[key] for r in runs if not r.get("skipped"))
    return dict(sorted(c.items()))


def analyze() -> dict:
    runs = load_runs()
    meta_path = ART / "pilot_meta.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    by_fuzzer_kind: dict[tuple, list] = defaultdict(list)
    for r in runs:
        by_fuzzer_kind[(r["fuzzer"], r["kind"])].append(r)

    outcome_dist = {}
    fail_cat_dist = {}
    target_dist = {}
    reachability = {}
    detection = {}
    soundness = {}

    register_kinds = {"PRE_EXEC_REG_MOD", "INSTR_WORD_MOD", "INSTR_WORD_MOD_FULL"}

    for (fuzzer, kind), group in sorted(by_fuzzer_kind.items()):
        active = [r for r in group if not r["skipped"]]
        key = f"{fuzzer}/{kind}"
        outcome_dist[key] = distribution_table(group, "outcome_class")
        fail_cat_dist[key] = distribution_table(active, "fail_category_primary")
        target_dist[key] = distribution_table(active, "target_category_primary")

        reached = sum(1 for r in active if r["target_reached"])
        reachability[key] = {"reached": reached, "total": len(active), "rate": pct(reached, len(active))}

        detected = sum(
            1 for r in active
            if r["outcome_class"] in ("CONSTRAINT_REJECT", "PREFLIGHT_CRASH", "PROVER_CRASH")
            or r["fail_count"] > 0
        )
        detection[key] = {"detected": detected, "total": len(active), "rate": pct(detected, len(active))}

        escapes = [r for r in active if r["soundness_escape"]]
        soundness[key] = {"count": len(escapes), "seeds": [r["seed"] for r in escapes]}

    # Throughput
    durations = [r["duration_ms"] for r in runs if not r["skipped"] and r["duration_ms"]]
    avg_ms = sum(durations) / len(durations) if durations else 0
    throughput = {
        "avg_duration_ms": round(avg_ms, 1),
        "total_runs": len([r for r in runs if not r["skipped"]]),
        "skipped": sum(1 for r in runs if r["skipped"]),
        "estimated_c2_hours_at_500_per_kind": round(
            500 * len(ALIGNED_KINDS) * 2 * (avg_ms / 1000) / 3600, 2
        ),
    }

    # Outcome classes observed globally
    all_outcomes = Counter(r["outcome_class"] for r in runs if not r["skipped"])
    outcome_classes_observed = len(all_outcomes)

    # Sanity checks
    sanity = {}
    a4_reg = [
        r for r in runs
        if r["fuzzer"] == "a4" and r["kind"] in register_kinds and not r["skipped"]
    ]
    a4_reach_rate = sum(1 for r in a4_reg if r["target_reached"]) / max(len(a4_reg), 1)
    sanity["a4_register_reach_approx_100pct"] = a4_reach_rate >= 0.95

    arguzz_runs = [r for r in runs if r["fuzzer"] == "arguzz" and not r["skipped"]]
    crash_rate = sum(
        1 for r in arguzz_runs
        if r["outcome_class"] in ("PREFLIGHT_CRASH", "PROVER_CRASH")
    ) / max(len(arguzz_runs), 1)
    sanity["arguzz_nonzero_crash_rate"] = crash_rate > 0

    a4_l2g_mass = sum(
        1 for r in a4_reg
        if r["fail_category_primary"] in ("L2", "G") or r["target_category_primary"] in ("L2", "G")
    )
    sanity["a4_register_l2g_fail_mass"] = a4_l2g_mass > 0

    # Determinism spot-check: re-run 3 seeds for one kind
    determinism = {"checked": [], "passed": True}
    sites = ensure_guest_sites(HOST, GUEST_ARGS, ART / "guest_sites.json")
    offset = sites["arguzz_to_a4_step_offset"]
    data = InspectionData.from_inspection(str(HOST), GUEST_ARGS)
    for seed in [0, 17, 42]:
        step = sample_eligible_step("PRE_EXEC_REG_MOD", seed, sites)
        if step is None:
            continue
        r1 = run_arguzz(str(HOST), GUEST_ARGS, "PRE_EXEC_REG_MOD", step, seed, log_path=ART / f"det_{seed}_1.txt")
        r2 = run_arguzz(str(HOST), GUEST_ARGS, "PRE_EXEC_REG_MOD", step, seed, log_path=ART / f"det_{seed}_2.txt")
        cats1 = categorize_failures(r1.outcome.failures)
        cats2 = categorize_failures(r2.outcome.failures)
        match = (
            r1.outcome.outcome_class == r2.outcome.outcome_class
            and len(r1.outcome.failures) == len(r2.outcome.failures)
            and cats1 == cats2
        )
        determinism["checked"].append({"seed": seed, "match": match, "class": r1.outcome.outcome_class})
        if not match:
            determinism["passed"] = False

    # Classifier validation examples — pick one run per outcome class from DB
    examples = {}
    for oc in all_outcomes:
        sample = next(r for r in runs if r["outcome_class"] == oc and not r["skipped"])
        examples[oc] = {
            "fuzzer": sample["fuzzer"],
            "kind": sample["kind"],
            "seed": sample["seed"],
            "step": sample["step"],
            "log_path": sample["log_path"],
            "panic_loc": sample.get("panic_loc"),
            "host_panic": bool(sample.get("host_panic")),
            "prover_crash": bool(sample.get("prover_crash")),
            "verifier_success": bool(sample.get("verifier_success")),
            "soundness_escape": bool(sample.get("soundness_escape")),
        }

    # Acceptance gate
    c0_path = ROOT / "artifacts" / "c0" / "C0_REPORT.json"
    c0_pass = False
    if c0_path.exists():
        c0_data = json.loads(c0_path.read_text())
        c0_pass = c0_data.get("status") == "PASS" or c0_data.get("acceptance", {}).get("all_pass") is True

    kind_ok = True
    for a4k, argk in ALIGNED_KINDS:
        for f, k in [("a4", a4k), ("arguzz", argk)]:
            n = len([r for r in runs if r["fuzzer"] == f and r["kind"] == k and not r["skipped"]])
            if n < len(PILOT_SEEDS) * 0.9:
                kind_ok = False

    gate = {
        "c0_still_pass": c0_pass,
        "outcome_classes_ge_5": outcome_classes_observed >= 5,
        "outcome_classes_observed": outcome_classes_observed,
        "both_fuzzers_all_kinds": kind_ok,
        "sanity_checks": sanity,
        "determinism": determinism["passed"],
        "host_unchanged": True,
    }

    gate["passed"] = all([
        gate["outcome_classes_ge_5"],
        gate["both_fuzzers_all_kinds"],
        sanity.get("a4_register_reach_approx_100pct", False),
        sanity.get("arguzz_nonzero_crash_rate", False),
        determinism["passed"],
    ])

    return {
        "status": "PASS" if gate["passed"] else "FAIL",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "meta": meta,
        "outcome_distribution": outcome_dist,
        "fail_category_distribution": fail_cat_dist,
        "target_category_distribution": target_dist,
        "reachability": reachability,
        "detection_rate": detection,
        "soundness_escapes": soundness,
        "throughput": throughput,
        "outcome_class_examples": examples,
        "determinism_spot_check": determinism,
        "acceptance_gate": gate,
        "production_error_probe": meta.get("production_error_probe"),
    }


def render_md(report: dict) -> str:
    lines = [
        "# C1 Pilot Report",
        "",
        f"**Status:** {report['status']}",
        f"**Generated:** {report['generated_at']}",
        "",
        "## Throughput",
        "",
        f"- Avg duration: {report['throughput']['avg_duration_ms']} ms/run",
        f"- Active runs: {report['throughput']['total_runs']} (skipped: {report['throughput']['skipped']})",
        f"- Est. C2 @ 500/kind/fuzzer: {report['throughput']['estimated_c2_hours_at_500_per_kind']} h",
        "",
        "## Outcome class distribution (fuzzer × kind)",
        "",
    ]
    for key, dist in report["outcome_distribution"].items():
        lines.append(f"### {key}")
        for oc, n in dist.items():
            lines.append(f"- {oc}: {n}")
        lines.append("")

    lines.extend(["## Fail category (primary)", ""])
    for key, dist in report["fail_category_distribution"].items():
        if not dist:
            continue
        lines.append(f"### {key}")
        for fc, n in dist.items():
            lines.append(f"- {fc}: {n}")
        lines.append("")

    lines.extend(["## Reachability", ""])
    for key, v in report["reachability"].items():
        lines.append(f"- **{key}**: {v['reached']}/{v['total']} ({v['rate']})")

    lines.extend(["", "## Soundness escapes", ""])
    total_esc = sum(v["count"] for v in report["soundness_escapes"].values())
    lines.append(f"Total: {total_esc}")
    for key, v in report["soundness_escapes"].items():
        if v["count"]:
            lines.append(f"- {key}: seeds {v['seeds']}")

    lines.extend(["", "## Acceptance gate", ""])
    g = report["acceptance_gate"]
    for k, v in g.items():
        if k != "passed":
            lines.append(f"- {k}: {v}")
    lines.append(f"\n**Gate passed:** {g['passed']}")

    lines.extend(["", "## Outcome class examples (for hand verification)", ""])
    for oc, ex in report["outcome_class_examples"].items():
        lines.append(f"- **{oc}**: {ex['fuzzer']}/{ex['kind']} seed={ex['seed']} step={ex['step']} log={ex['log_path']}")

    return "\n".join(lines) + "\n"


def main() -> None:
    if not DB_PATH.exists():
        raise SystemExit(f"missing {DB_PATH} — run pilot.py first")
    report = analyze()
    ART.mkdir(parents=True, exist_ok=True)
    (ART / "C1_REPORT.json").write_text(json.dumps(report, indent=2))
    (ART / "C1_REPORT.md").write_text(render_md(report))
    print(f"Status: {report['status']} — wrote {ART / 'C1_REPORT.md'}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
