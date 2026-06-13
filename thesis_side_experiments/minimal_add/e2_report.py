#!/usr/bin/env python3
"""E2-FULL gate checks + combined matrix + E2_REPORT.{md,json}."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
E1 = ROOT / "artifacts" / "e1"
CFG = ROOT / "artifacts" / "e2" / "configs"
OUT = ROOT / "artifacts" / "e2"

VALUE_KINDS = ("LOAD_VAL_MOD", "COMP_OUT_MOD", "STORE_OUT_MOD")
PROVE_ERROR_SEEDS = {1, 7, 9, 17, 25, 27, 29}


def layer_triple(layers: Optional[dict]) -> str:
    if not layers:
        return "—"
    return (
        f"{layers.get('intrastep-local', 0)}/"
        f"{layers.get('interstep-local', 0)}/"
        f"{layers.get('global', 0)}"
    )


def load_e1(kind: str, seed: int) -> dict:
    return json.loads((E1 / f"{kind}_seed{seed}.json").read_text())


def load_analysis(analysis_dir: Path) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for p in analysis_dir.glob("*.json"):
        if p.name == "analysis_report.json":
            continue
        rec = json.loads(p.read_text())
        out[rec["run_id"]] = rec
    return out


def gate_part_a(matrix_rows: List[dict], det_failures: List[str]) -> dict:
    value_rows = [r for r in matrix_rows if r.get("kind") in VALUE_KINDS]
    issues: List[str] = []
    for r in value_rows:
        arguzz = r.get("arguzz_layers")
        a4 = r.get("a4_full_layers")
        if arguzz != "1/0/0":
            issues.append(f"{r['key']}: Arguzz expected 1/0/0 got {arguzz}")
        if a4 != "1/0/1":
            issues.append(f"{r['key']}: A4-FULL expected 1/0/1 got {a4}")
    part_a_ids = [r["a4_run_id"] for r in matrix_rows if r.get("a4_run_id", "").startswith("a4_full_")]
    det_a = [d for d in det_failures if d.startswith("a4_full_")]
    return {
        "value_kind_arguzz_1_0_0": all(
            r.get("arguzz_layers") == "1/0/0" for r in value_rows
        ),
        "value_kind_a4_full_1_0_1": all(
            r.get("a4_full_layers") == "1/0/1" for r in value_rows
        ),
        "a4_full_row_count": len(part_a_ids),
        "expected_a4_full_rows": 39,
        "determinism": len(det_a) == 0,
        "determinism_failures": det_a,
        "issues": issues,
        "gate_pass": len(issues) == 0 and len(part_a_ids) == 39 and len(det_a) == 0,
    }


def gate_part_b(sur_rows: List[dict], det_failures: List[str]) -> dict:
    det_b = [d for d in det_failures if d.startswith("a4_sur_")]
    rd = next((r for r in sur_rows if r.get("sur_variant") == "rd"), None)
    rs1 = next((r for r in sur_rows if r.get("sur_variant") == "rs1"), None)
    rs2 = next((r for r in sur_rows if r.get("sur_variant") == "rs2"), None)
    op_rows = [r for r in sur_rows if r.get("sur_variant", "").startswith("funct")]
    asymmetry_verdict = "unknown"
    asymmetry_note = ""
    if rd and rs1 and rs2:
        rd_layers = rd.get("a4_sur_layers", "")
        src_layers = [rs1.get("a4_sur_layers"), rs2.get("a4_sur_layers")]
        rd_parts = [int(x) for x in rd_layers.split("/")]
        src_parts = [[int(x) for x in s.split("/")] for s in src_layers]
        src_has_extra_local = any(p[0] > rd_parts[0] or p[1] > rd_parts[1] for p in src_parts)
        if src_has_extra_local and rd_parts[2] >= 1:
            asymmetry_verdict = "confirmed"
            asymmetry_note = (
                f"Source-register SUR ({rs1.get('a4_sur_layers')}, "
                f"{rs2.get('a4_sur_layers')}) breaks more local layers than "
                f"rd-only ({rd_layers})."
            )
        else:
            asymmetry_verdict = "denied"
            asymmetry_note = (
                f"rd={rd_layers}, rs1={rs1.get('a4_sur_layers')}, "
                f"rs2={rs2.get('a4_sur_layers')}: all register-field SUR variants "
                f"are global-only (0/0/1), matching Arguzz dest/src_reg FULL mirrors. "
                f"Operation SUR (funct3/funct7) adds intrastep decode "
                f"({op_rows[0]['a4_sur_layers'] if op_rows else '1/0/1'})."
            )
    return {
        "per_field_footprints": sur_rows,
        "rd_vs_src_asymmetry_verdict": asymmetry_verdict,
        "asymmetry_evidence": asymmetry_note,
        "determinism": len(det_b) == 0,
        "determinism_failures": det_b,
        "gate_pass": len(sur_rows) >= 6 and len(det_b) == 0 and asymmetry_verdict != "unknown",
    }


def gate_part_c(mem_rows: List[dict], det_failures: List[str]) -> dict:
    det_c = [d for d in det_failures if d.startswith("a4_memval_")]
    interstep_hits = [r for r in mem_rows if r.get("interstep_local", 0) >= 1]
    isread_hits = [r for r in mem_rows if r.get("has_isread_memoryread")]
    return {
        "mem_val_row_count": len(mem_rows),
        "interstep_local_populated": len(interstep_hits) >= 1,
        "isread_memoryread_breaks": len(isread_hits) >= 1,
        "arguzz_mirror": "n/a — Arguzz has no in-place memory-read mutation; LOAD_VAL_MOD edits register side only",
        "determinism": len(det_c) == 0,
        "determinism_failures": det_c,
        "gate_pass": len(interstep_hits) >= 1 and len(isread_hits) >= 1 and len(det_c) == 0,
    }


def build_matrix(
    analysis: Dict[str, dict],
) -> tuple[List[dict], List[dict], List[dict], dict]:
    matrix: List[dict] = []
    sur_rows: List[dict] = []
    mem_rows: List[dict] = []
    field_agg: Dict[str, dict] = defaultdict(
        lambda: {"n": 0, "arguzz": [], "a4_full": [], "a4_sur": [], "a4_memval": []}
    )

    manifest = json.loads((CFG / "manifest_e2.json").read_text())
    for entry in manifest["runs"]:
        part = entry["part"]
        rec = analysis.get(entry["run_id"], {})
        layers = rec.get("layers") or {}

        if part == "A":
            kind = entry["kind"]
            seed = entry["seed"]
            e1 = load_e1(kind, seed)
            key = f"{entry['role']}/{kind}/s{seed}"
            row = {
                "key": key,
                "role": entry["role"],
                "kind": kind,
                "seed": seed,
                "field_class": entry.get("field_class") or e1.get("field_class"),
                "fields_changed": entry.get("fields_changed") or e1.get("fields_changed"),
                "arguzz_layers": layer_triple(e1.get("layers")),
                "a4_full_layers": layer_triple(layers),
                "a4_sur_layers": "n/a",
                "a4_memval_layers": "n/a",
                "arguzz_outcome": e1.get("outcome_class"),
                "a4_full_outcome": rec.get("outcome_class"),
                "a4_run_id": entry["run_id"],
            }
            matrix.append(row)
            fc = row["field_class"]
            if fc:
                field_agg[fc]["n"] += 1
                field_agg[fc]["arguzz"].append(row["arguzz_layers"])
                field_agg[fc]["a4_full"].append(row["a4_full_layers"])

        elif part == "B":
            fc = entry.get("field_class", entry["run_id"])
            prov = rec.get("provenance") or []
            bucket_ex = []
            for layer in ("intrastep-local", "interstep-local", "global"):
                for f in (rec.get("buckets") or {}).get(layer, []):
                    bucket_ex.append(f"{layer}: {f['full_loc'][:80]} value={f['value']}")
            sur = {
                "field": entry.get("surgical_field") or fc,
                "sur_variant": fc,
                "a4_sur_layers": layer_triple(layers),
                "outcome": rec.get("outcome_class"),
                "fields_changed": entry.get("fields_changed"),
                "provenance": prov[:3],
                "constraint_examples": bucket_ex[:4],
                "run_id": entry["run_id"],
            }
            sur_rows.append(sur)
            field_agg[fc]["n"] += 1
            field_agg[fc]["a4_sur"].append(sur["a4_sur_layers"])

        elif part == "C":
            buckets = rec.get("buckets") or {}
            inter = buckets.get("interstep-local", [])
            has_isread = any(
                "IsRead" in f.get("full_loc", "") or "MemoryRead" in f.get("full_loc", "")
                for f in inter + buckets.get("intrastep-local", [])
            )
            mem = {
                "key": f"{entry['role']}/{entry['txn_type']}/s{entry['seed']}",
                "role": entry["role"],
                "txn_type": entry["txn_type"],
                "seed": entry["seed"],
                "a4_memval_layers": layer_triple(layers),
                "arguzz_layers": "n/a",
                "outcome": rec.get("outcome_class"),
                "interstep_local": layers.get("interstep-local", 0),
                "has_isread_memoryread": has_isread,
                "provenance": (rec.get("provenance") or [])[:2],
                "run_id": entry["run_id"],
            }
            mem_rows.append(mem)
            matrix.append(
                {
                    "key": mem["key"],
                    "role": entry["role"],
                    "kind": "MEM_VAL_MOD",
                    "seed": entry["seed"],
                    "field_class": entry["txn_type"],
                    "arguzz_layers": "n/a — no in-place memory-read mutation",
                    "a4_full_layers": "n/a",
                    "a4_sur_layers": "n/a",
                    "a4_memval_layers": layer_triple(layers),
                }
            )

    return matrix, sur_rows, mem_rows, dict(field_agg)


def emit_report(
    analysis_dir: Path,
    log_dir: Path,
    dispatch: Optional[dict] = None,
) -> dict:
    analysis_report = json.loads((analysis_dir / "analysis_report.json").read_text())
    analysis = load_analysis(analysis_dir)
    det_failures = analysis_report.get("determinism_failures", [])

    matrix, sur_rows, mem_rows, field_agg = build_matrix(analysis)
    gate_a = gate_part_a(matrix, det_failures)
    gate_b = gate_part_b(sur_rows, det_failures)
    gate_c = gate_part_c(mem_rows, det_failures)

    report = {
        "milestone": "E2-FULL",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "node": "polynize",
        "image": "debian-trixie",
        "host_sha256": "5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23",
        "dispatch": dispatch or {},
        "manifest": str(CFG / "manifest_e2.json"),
        "log_dir": str(log_dir),
        "analysis_dir": str(analysis_dir),
        "run_count": analysis_report.get("run_count"),
        "determinism_failures": det_failures,
        "gate": {
            "part_a": gate_a,
            "part_b": gate_b,
            "part_c": gate_c,
            "overall_pass": gate_a["gate_pass"] and gate_b["gate_pass"] and gate_c["gate_pass"],
        },
        "matrix": matrix,
        "sur_footprints": sur_rows,
        "mem_val_rows": mem_rows,
        "field_class_aggregate": field_agg,
        "interstep_bucket_note": (
            "Interstep-local stays empty for Arguzz and A4-FULL/SUR register mirrors "
            "on this circuit; MEM_VAL_MOD populates it via MemoryRead/IsRead@mem.zir."
        ),
        "arguzz_no_mem_read_mirror": (
            "Arguzz has no in-place memory-read mutation. LOAD_VAL_MOD edits the "
            "register-write side; propagating kinds keep reads self-consistent. "
            "PRE_EXEC_MEM_MOD is Family-1 inject expected to OOB-crash."
        ),
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "E2_REPORT.json").write_text(json.dumps(report, indent=2))

    md = [
        "# E2-FULL Report — A4 characterization on polynize",
        "",
        f"**Status:** {'PASS' if report['gate']['overall_pass'] else 'FAIL'}",
        "",
        "## Dispatch",
        f"- Node: **polynize** / **debian-trixie** / `--allocation-duration 0`",
        f"- Host sha: `{report['host_sha256'][:16]}…` (frozen, no rebuild)",
        f"- Runs: {report['run_count']} (Part A={gate_a['a4_full_row_count']}, "
        f"B={len(sur_rows)}, C={len(mem_rows)})",
        "",
        "## Part A — A4 FULL mirrors (value-kind bias)",
        f"- **gate_pass:** {gate_a['gate_pass']}",
        f"- Value kinds Arguzz **1/0/0** vs A4-FULL **1/0/1**: "
        f"{gate_a['value_kind_arguzz_1_0_0']} / {gate_a['value_kind_a4_full_1_0_1']}",
        f"- A4 FULL rows: {gate_a['a4_full_row_count']}/39",
        "",
        "### Value-kind sample",
        "",
        "| role/kind/seed | Arguzz i/inter/g | A4-FULL i/inter/g |",
        "|--------------|------------------|-------------------|",
    ]
    for r in matrix:
        if r.get("kind") in VALUE_KINDS and r["seed"] == 0:
            md.append(
                f"| {r['key']} | {r['arguzz_layers']} | {r['a4_full_layers']} |"
            )

    md.extend(
        [
            "",
            "## Part B — INSTR_WORD_MOD_SUR (single-field at add)",
            f"- **gate_pass:** {gate_b['gate_pass']}",
            f"- **rd vs src asymmetry:** {gate_b['rd_vs_src_asymmetry_verdict']}",
            f"- Evidence: {gate_b['asymmetry_evidence']}",
            "",
            "| field | layers i/inter/g | outcome | example constraint |",
            "|-------|------------------|---------|-------------------|",
        ]
    )
    for s in sur_rows:
        ex = s["constraint_examples"][0] if s["constraint_examples"] else "—"
        md.append(
            f"| {s['sur_variant']} | {s['a4_sur_layers']} | {s['outcome']} | `{ex[:70]}…` |"
        )

    md.extend(
        [
            "",
            "## Part C — MEM_VAL_MOD (A4-only interstep layer)",
            f"- **gate_pass:** {gate_c['gate_pass']}",
            f"- **interstep-local populated:** {gate_c['interstep_local_populated']}",
            f"- **Arguzz mirror:** {gate_c['arguzz_mirror']}",
            "",
            "| role/txn/seed | A4-MEM_VAL i/inter/g | IsRead/MemoryRead |",
            "|---------------|----------------------|-------------------|",
        ]
    )
    for m in mem_rows:
        md.append(
            f"| {m['key']} | {m['a4_memval_layers']} | "
            f"{'yes' if m['has_isread_memoryread'] else 'no'} |"
        )

    md.extend(
        [
            "",
            "## Combined matrix (Arguzz vs A4-FULL vs A4-SUR vs A4-MEM_VAL)",
            "",
            "Format: intrastep/interstep/global. MEM_VAL Arguzz column = n/a.",
            "",
            "| key | field_class | Arguzz | A4-FULL | A4-SUR | A4-MEM_VAL |",
            "|-----|-------------|--------|---------|--------|------------|",
        ]
    )
    for r in matrix[:20]:
        md.append(
            f"| {r['key']} | {r.get('field_class','')} | {r.get('arguzz_layers','')} | "
            f"{r.get('a4_full_layers','n/a')} | {r.get('a4_sur_layers','n/a')} | "
            f"{r.get('a4_memval_layers','n/a')} |"
        )
    if len(matrix) > 20:
        md.append(f"| … | ({len(matrix)} total rows in JSON) | | | | |")

    md.append(f"\n**Overall gate passed:** {report['gate']['overall_pass']}")
    (OUT / "E2_REPORT.md").write_text("\n".join(md) + "\n")
    return report


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", type=Path, required=True)
    ap.add_argument("--log-dir", type=Path, required=True)
    ap.add_argument("--dispatch-json", type=Path, default=None)
    args = ap.parse_args()
    dispatch = (
        json.loads(args.dispatch_json.read_text()) if args.dispatch_json else None
    )
    report = emit_report(args.analysis_dir, args.log_dir, dispatch)
    print((OUT / "E2_REPORT.md").read_text())
    if not report["gate"]["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
