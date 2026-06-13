#!/usr/bin/env python3
"""E4 matrix assembly — ingest E1 Arguzz + E2 A4 JSONs; no proving."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
E1_DIR = ROOT / "artifacts" / "e1"
E2_DIR = ROOT / "artifacts" / "e2" / "pos_full" / "analysis"
SITE_CARD = ROOT / "artifacts" / "e0" / "site_card.json"
OUT_DIR = ROOT / "artifacts" / "e4"

VALUE_KINDS = ("LOAD_VAL_MOD", "COMP_OUT_MOD", "STORE_OUT_MOD")
PROVE_ERROR_SEEDS = {1, 7, 9, 17, 25, 27, 29}
ARGUZZ_REGISTER_SEEDS = {2, 11, 21, 23, 26, 30, 3, 4, 12, 13, 14}
SUR_REGISTER = ("rd", "rs1", "rs2")
SUR_OPERATION = ("funct3_xor", "funct3_slt", "funct7_sub")

E1_JSON_RE = re.compile(r"^(LOAD_VAL_MOD|COMP_OUT_MOD|STORE_OUT_MOD|INSTR_WORD_MOD)_seed\d+\.json$")


def load_site() -> dict:
    return json.loads(SITE_CARD.read_text())


def layer_triple(layers: Optional[dict]) -> str:
    if not layers:
        return "—"
    return (
        f"{layers.get('intrastep-local', 0)}/"
        f"{layers.get('interstep-local', 0)}/"
        f"{layers.get('global', 0)}"
    )


def normalize_layers(layers: Optional[dict]) -> dict:
    if not layers:
        return {"intrastep_local": 0, "interstep_local": 0, "global": 0}
    return {
        "intrastep_local": layers.get("intrastep-local", 0),
        "interstep_local": layers.get("interstep-local", 0),
        "global": layers.get("global", 0),
    }


def match_provenance(
    provenance: List[dict], full_loc: str, layer: str
) -> Optional[dict]:
    for p in provenance:
        if p.get("layer") != layer:
            continue
        loc = p.get("loc", "")
        if loc and (full_loc.startswith(loc) or loc.startswith(full_loc[:80])):
            return p
        if loc and loc in full_loc:
            return p
    return None


def expand_constraints(rec: dict) -> List[dict]:
    """Fully expanded constraint list from buckets + global families."""
    out: List[dict] = []
    buckets = rec.get("buckets") or {}
    provenance = rec.get("provenance") or []
    layer_map = {
        "intrastep-local": "intrastep-local",
        "interstep-local": "interstep-local",
        "global": "global",
    }

    for bucket_key, layer in layer_map.items():
        for f in buckets.get(bucket_key, []):
            prov = match_provenance(provenance, f.get("full_loc", ""), layer)
            entry: Dict[str, Any] = {
                "layer": layer,
                "full_loc": f.get("full_loc", f.get("constraint_loc", "")),
                "residue": f.get("value"),
                "cycle": f.get("cycle"),
                "step": f.get("step"),
                "major": f.get("major"),
                "minor": f.get("minor"),
                "provenance": prov,
            }
            out.append(entry)

    layers = rec.get("layers") or {}
    global_count = layers.get("global", 0)
    if global_count and not any(c["layer"] == "global" for c in out):
        for gf in rec.get("global_families") or []:
            out.append(
                {
                    "layer": "global",
                    "full_loc": f"GLOBAL:family:{gf.get('family', '?')} residue nonzero",
                    "residue": None,
                    "cycle": None,
                    "step": None,
                    "major": None,
                    "minor": None,
                    "provenance": None,
                    "family": gf.get("family"),
                    "address": gf.get("address"),
                }
            )

    return out


def log_has_constraint_fail(log_path: Optional[str], e1_dir: Path) -> bool:
    if not log_path:
        return False
    p = Path(log_path)
    if not p.is_absolute():
        p = ROOT / log_path
    if not p.exists():
        p = e1_dir / Path(log_path).name
    if not p.exists():
        return False
    return "<constraint_fail>" in p.read_text()


def row_from_e1(rec: dict, site: dict, e1_dir: Path) -> dict:
    role = rec["role"]
    inject_step = rec["inject_step"]
    a4_step = site["roles"][role]["a4_step"]
    layers = normalize_layers(rec.get("layers"))
    constraints = expand_constraints(rec)
    return {
        "run_id": f"arguzz_{rec['kind']}_s{rec['seed']}",
        "fuzzer": "arguzz",
        "variant": None,
        "kind": rec["kind"],
        "role": role,
        "seed": rec["seed"],
        "inject_step": inject_step,
        "a4_step": a4_step,
        "mutated_value": rec.get("mutated_value"),
        "mutated_word": rec.get("mutated_word"),
        "mutated_word_hex": rec.get("mutated_word_hex"),
        "decoded_instruction": rec.get("decoded_instruction"),
        "original_instruction": rec.get("original_instruction"),
        "fields_changed": rec.get("fields_changed"),
        "field_class": rec.get("field_class"),
        "outcome_class": rec.get("outcome_class"),
        "layers": layers,
        "layers_triple": layer_triple(rec.get("layers")),
        "failure_count": rec.get("failure_count", len(constraints)),
        "constraints": constraints,
        "crash_stage": rec.get("crash_stage"),
        "crash_evidence": rec.get("crash_evidence"),
        "arguzz_mirror": None,
        "log_has_constraint_fail": log_has_constraint_fail(rec.get("log_path"), e1_dir),
        "source": "e1",
    }


def row_from_a4(rec: dict, site: dict) -> dict:
    role = rec["role"]
    inject_step = rec.get("inject_step")
    a4_step = site["roles"][role]["a4_step"]
    layers = normalize_layers(rec.get("layers"))
    constraints = expand_constraints(rec)
    variant = rec.get("variant", "FULL")
    return {
        "run_id": rec["run_id"],
        "fuzzer": "a4",
        "variant": variant,
        "kind": rec.get("kind"),
        "role": role,
        "seed": rec.get("seed"),
        "inject_step": inject_step,
        "a4_step": a4_step,
        "mutated_value": rec.get("mutated_value"),
        "mutated_word": rec.get("mutated_word"),
        "mutated_word_hex": rec.get("mutated_word_hex"),
        "decoded_instruction": rec.get("decoded_instruction"),
        "original_instruction": rec.get("original_instruction"),
        "fields_changed": rec.get("fields_changed"),
        "field_class": rec.get("field_class"),
        "outcome_class": rec.get("outcome_class"),
        "layers": layers,
        "layers_triple": layer_triple(rec.get("layers")),
        "failure_count": rec.get("failure_count", len(constraints)),
        "constraints": constraints,
        "crash_stage": rec.get("crash_stage"),
        "crash_evidence": rec.get("crash_evidence"),
        "arguzz_mirror": rec.get("arguzz_mirror"),
        "txn_type": rec.get("txn_type"),
        "surgical_field": rec.get("surgical_field"),
        "source": "e2",
    }


def load_e1_rows(e1_dir: Path, site: dict) -> List[dict]:
    rows: List[dict] = []
    for path in sorted(e1_dir.glob("*.json")):
        if not E1_JSON_RE.match(path.name):
            continue
        rec = json.loads(path.read_text())
        rows.append(row_from_e1(rec, site, e1_dir))
    return rows


def load_a4_rows(e2_dir: Path, site: dict) -> List[dict]:
    rows: List[dict] = []
    for path in sorted(e2_dir.glob("*.json")):
        if path.name == "analysis_report.json":
            continue
        rec = json.loads(path.read_text())
        rows.append(row_from_a4(rec, site))
    return rows


def semantic_key(row: dict) -> str:
    if row["fuzzer"] == "a4" and row["variant"] == "SUR":
        return f"{row['role']}/SUR/{row['field_class']}"
    if row["fuzzer"] == "a4" and row["variant"] == "MEM_VAL":
        return f"{row['role']}/MEM_VAL/s{row['seed']}"
    return f"{row['role']}/{row['kind']}/s{row['seed']}"


def build_master_index(rows: List[dict]) -> Dict[str, Dict[str, dict]]:
    """Map semantic target -> variant -> row."""
    idx: Dict[str, Dict[str, dict]] = defaultdict(dict)
    for row in rows:
        sk = semantic_key(row)
        if row["fuzzer"] == "arguzz":
            idx[sk]["arguzz"] = row
        elif row["variant"] == "FULL":
            idx[sk]["a4_full"] = row
        elif row["variant"] == "SUR":
            idx[f"{row['role']}/SUR/{row['field_class']}"]["a4_sur"] = row
        elif row["variant"] == "MEM_VAL":
            idx[f"{row['role']}/MEM_VAL/s{row['seed']}"]["a4_memval"] = row
    return idx


def zero_failure_label(row: dict) -> Optional[str]:
    layers = row["layers"]
    if (
        row["outcome_class"] == "GLOBAL_REJECT"
        and row["failure_count"] == 0
        and layers["intrastep_local"] == 0
        and layers["interstep_local"] == 0
        and layers["global"] >= 1
    ):
        fams = [
            c.get("family") or "memory"
            for c in row["constraints"]
            if c["layer"] == "global"
        ]
        fam = fams[0] if fams else "memory"
        return (
            f"local constraints broken: NONE (failure_count=0); "
            f"global {fam} residue: nonzero"
        )
    return None


def constraint_bullets(row: dict) -> List[str]:
    label = zero_failure_label(row)
    if label:
        return [label]
    if not row["constraints"]:
        if row["outcome_class"] == "PROVE_ERROR":
            return [f"PROVE_ERROR: {row.get('crash_evidence', 'crash before constraints')}"]
        return ["(no constraint failures recorded)"]
    bullets = []
    for c in row["constraints"]:
        prov = c.get("provenance")
        prov_s = ""
        if prov:
            if prov.get("verified"):
                prov_s = (
                    f" provenance: {prov.get('formula')} "
                    f"pred={prov.get('predicted')} obs={prov.get('observed')}"
                )
            elif prov.get("reason"):
                prov_s = f" provenance: {prov['reason']}"
        bullets.append(
            f"- [{c['layer']}] `{c['full_loc']}` residue={c['residue']}{prov_s}"
        )
    return bullets


def assert_findings(rows: List[dict]) -> Tuple[dict, List[str]]:
    arguzz = {r["run_id"]: r for r in rows if r["fuzzer"] == "arguzz"}
    a4 = {r["run_id"]: r for r in rows if r["fuzzer"] == "a4"}
    failures: List[str] = []

    # 1. Arguzz register changes = 0/0/1, failure_count=0, no constraint_fail
    reg_ok = True
    reg_details = []
    for seed in sorted(ARGUZZ_REGISTER_SEEDS):
        rid = f"arguzz_INSTR_WORD_MOD_s{seed}"
        r = arguzz.get(rid)
        if not r:
            failures.append(f"missing Arguzz register row {rid}")
            reg_ok = False
            continue
        trip = r["layers_triple"]
        if trip != "0/0/1":
            failures.append(f"{rid}: expected 0/0/1 got {trip}")
            reg_ok = False
        if r["failure_count"] != 0:
            failures.append(f"{rid}: expected failure_count=0 got {r['failure_count']}")
            reg_ok = False
        if r["log_has_constraint_fail"]:
            failures.append(f"{rid}: log contains <constraint_fail>")
            reg_ok = False
        reg_details.append(f"s{seed}={trip} fc={r['failure_count']}")
    finding1 = {
        "pass": reg_ok,
        "detail": "; ".join(reg_details),
        "seeds": sorted(ARGUZZ_REGISTER_SEEDS),
    }

    # 2. Value kinds Arguzz 1/0/0 vs A4-FULL 1/0/1
    vk_ok = True
    vk_details = []
    for kind in VALUE_KINDS:
        for seed in range(5):
            ar = arguzz.get(f"arguzz_{kind}_s{seed}")
            af = a4.get(f"a4_full_{kind}_s{seed}")
            if not ar or not af:
                failures.append(f"missing value-kind pair {kind} s{seed}")
                vk_ok = False
                continue
            if ar["layers_triple"] != "1/0/0":
                failures.append(f"Arguzz {kind} s{seed}: expected 1/0/0 got {ar['layers_triple']}")
                vk_ok = False
            if af["layers_triple"] != "1/0/1":
                failures.append(f"A4-FULL {kind} s{seed}: expected 1/0/1 got {af['layers_triple']}")
                vk_ok = False
            vk_details.append(f"{kind}/s{seed}: {ar['layers_triple']} vs {af['layers_triple']}")
    finding2 = {"pass": vk_ok, "detail": "; ".join(vk_details[:6]) + " …"}

    # 3. A4-SUR register 0/0/1; operation 1/0/1
    sur_ok = True
    sur_details = []
    for fc in SUR_REGISTER:
        r = a4.get(f"a4_sur_{fc}")
        if not r or r["layers_triple"] != "0/0/1":
            failures.append(f"a4_sur_{fc}: expected 0/0/1 got {r and r['layers_triple']}")
            sur_ok = False
        sur_details.append(f"{fc}={r['layers_triple'] if r else '?'}")
    for fc in SUR_OPERATION:
        r = a4.get(f"a4_sur_{fc}")
        if not r or r["layers_triple"] != "1/0/1":
            failures.append(f"a4_sur_{fc}: expected 1/0/1 got {r and r['layers_triple']}")
            sur_ok = False
        sur_details.append(f"{fc}={r['layers_triple'] if r else '?'}")
    finding3 = {"pass": sur_ok, "detail": "; ".join(sur_details)}

    # 4. MEM_VAL load 2/2/1, store 0/2/1, IsRead in interstep
    mem_ok = True
    mem_details = []
    for role in ("load_x", "load_y", "read_back"):
        for seed in (0, 1):
            r = a4.get(f"a4_memval_{role}_s{seed}")
            if not r or r["layers_triple"] != "2/2/1":
                failures.append(
                    f"a4_memval_{role}_s{seed}: expected 2/2/1 got {r and r['layers_triple']}"
                )
                mem_ok = False
            inter = [
                c for c in (r or {}).get("constraints", []) if c["layer"] == "interstep-local"
            ]
            if not any("IsRead" in c["full_loc"] for c in inter):
                failures.append(f"a4_memval_{role}_s{seed}: missing IsRead in interstep")
                mem_ok = False
    for seed in (0, 1):
        r = a4.get(f"a4_memval_store_s{seed}")
        if not r or r["layers_triple"] != "0/2/1":
            failures.append(
                f"a4_memval_store_s{seed}: expected 0/2/1 got {r and r['layers_triple']}"
            )
            mem_ok = False
        inter = [c for c in (r or {}).get("constraints", []) if c["layer"] == "interstep-local"]
        if not any("IsRead" in c["full_loc"] for c in inter):
            failures.append(f"a4_memval_store_s{seed}: missing IsRead in interstep")
            mem_ok = False
    mem_details.append("load*/read_back=2/2/1; store=0/2/1; IsRead@mem.zir:79/80 in interstep")
    finding4 = {"pass": mem_ok, "detail": mem_details[0]}

    findings = {
        "arguzz_register_global_only": finding1,
        "value_kind_arguzz_1_0_0_vs_a4_full_1_0_1": finding2,
        "a4_sur_register_0_0_1_operation_1_0_1": finding3,
        "a4_memval_interstep_isread": finding4,
        "all_pass": reg_ok and vk_ok and sur_ok and mem_ok,
        "assertion_failures": failures,
    }
    return findings, failures


def row_counts(rows: List[dict]) -> dict:
    arguzz = [r for r in rows if r["fuzzer"] == "arguzz"]
    a4 = [r for r in rows if r["fuzzer"] == "a4"]
    prove = [r for r in arguzz if r["outcome_class"] == "PROVE_ERROR"]
    a4_full = [r for r in a4 if r["variant"] == "FULL"]
    a4_sur = [r for r in a4 if r["variant"] == "SUR"]
    a4_mem = [r for r in a4 if r["variant"] == "MEM_VAL"]
    expected = {
        "arguzz_total": 46,
        "arguzz_prove_error": 7,
        "a4_total": 53,
        "a4_full": 39,
        "a4_sur": 6,
        "a4_memval": 8,
        "matrix_total": 99,
    }
    actual = {
        "arguzz_total": len(arguzz),
        "arguzz_prove_error": len(prove),
        "a4_total": len(a4),
        "a4_full": len(a4_full),
        "a4_sur": len(a4_sur),
        "a4_memval": len(a4_mem),
        "matrix_total": len(rows),
    }
    match = all(actual[k] == expected[k] for k in expected)
    return {"expected": expected, "actual": actual, "row_counts_match": match}


def field_class_rollup(rows: List[dict]) -> dict:
    agg: Dict[str, dict] = defaultdict(lambda: {"n": 0, "layers": []})
    for r in rows:
        fc = r.get("field_class") or r.get("kind") or "unknown"
        agg[fc]["n"] += 1
        agg[fc]["layers"].append(r["layers_triple"])
    return dict(agg)


def layer_rollup(rows: List[dict]) -> dict:
    by_fuzzer: Dict[str, List[str]] = defaultdict(list)
    for r in rows:
        by_fuzzer[r["fuzzer"]].append(r["layers_triple"])
    interstep_populated = [
        r["run_id"]
        for r in rows
        if r["layers"]["interstep_local"] > 0
    ]
    return {
        "by_fuzzer_layer_triples": {k: v for k, v in by_fuzzer.items()},
        "runs_with_interstep_local_gt_0": interstep_populated,
        "interstep_populated_count": len(interstep_populated),
    }


def write_csv(rows: List[dict], path: Path) -> None:
    flat_cols = [
        "run_id",
        "fuzzer",
        "variant",
        "kind",
        "role",
        "seed",
        "inject_step",
        "a4_step",
        "mutated_value",
        "mutated_word_hex",
        "field_class",
        "outcome_class",
        "intrastep_local",
        "interstep_local",
        "global",
        "layers_triple",
        "failure_count",
        "constraints_json",
    ]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=flat_cols)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "run_id": r["run_id"],
                    "fuzzer": r["fuzzer"],
                    "variant": r["variant"] or "",
                    "kind": r["kind"],
                    "role": r["role"],
                    "seed": r["seed"],
                    "inject_step": r["inject_step"],
                    "a4_step": r["a4_step"],
                    "mutated_value": r.get("mutated_value"),
                    "mutated_word_hex": r.get("mutated_word_hex"),
                    "field_class": r.get("field_class"),
                    "outcome_class": r["outcome_class"],
                    "intrastep_local": r["layers"]["intrastep_local"],
                    "interstep_local": r["layers"]["interstep_local"],
                    "global": r["layers"]["global"],
                    "layers_triple": r["layers_triple"],
                    "failure_count": r["failure_count"],
                    "constraints_json": json.dumps(r["constraints"]),
                }
            )


def write_markdown(
    rows: List[dict],
    master: Dict[str, Dict[str, dict]],
    findings: dict,
    counts: dict,
    path: Path,
) -> None:
    lines = [
        "# E4 Granular Matrix — Arguzz × A4",
        "",
        f"Generated: {datetime.now(tz=timezone.utc).isoformat()}",
        "",
        "## Row counts",
        "",
        f"- Arguzz E1: **{counts['actual']['arguzz_total']}** "
        f"(incl. **{counts['actual']['arguzz_prove_error']}** PROVE_ERROR)",
        f"- A4 E2: **{counts['actual']['a4_total']}** "
        f"(FULL **{counts['actual']['a4_full']}** + SUR **{counts['actual']['a4_sur']}** "
        f"+ MEM_VAL **{counts['actual']['a4_memval']}**)",
        f"- Matrix total: **{counts['actual']['matrix_total']}** "
        f"(match expected: **{counts['row_counts_match']}**)",
        "",
        "## Verified findings (asserted)",
        "",
    ]
    for key, label in [
        ("arguzz_register_global_only", "Arguzz register (dest+src) = 0/0/1, failure_count=0"),
        (
            "value_kind_arguzz_1_0_0_vs_a4_full_1_0_1",
            "Value kinds: Arguzz 1/0/0 vs A4-FULL 1/0/1",
        ),
        (
            "a4_sur_register_0_0_1_operation_1_0_1",
            "A4-SUR: rd/rs1/rs2 0/0/1; funct3/funct7 1/0/1",
        ),
        ("a4_memval_interstep_isread", "A4 MEM_VAL interstep via IsRead@mem.zir"),
    ]:
        f = findings[key]
        lines.append(f"- **{label}**: {'PASS' if f['pass'] else 'FAIL'} — {f['detail']}")

    lines.extend(
        [
            "",
            f"**All findings pass:** {findings['all_pass']}",
            "",
            "## Master matrix (i/inter/g per variant)",
            "",
            "Grouped by semantic target. `—` = variant N/A for this row.",
            "",
            "| target | Arguzz | A4-FULL | A4-SUR | A4-MEM_VAL |",
            "|--------|--------|---------|--------|------------|",
        ]
    )

    def col(row: Optional[dict]) -> str:
        return row["layers_triple"] if row else "—"

    # Value kinds + INSTR FULL mirrors
    mirror_keys = sorted(
        k
        for k in master
        if "/SUR/" not in k and "/MEM_VAL/" not in k
    )
    for k in mirror_keys:
        v = master[k]
        lines.append(
            f"| {k} | {col(v.get('arguzz'))} | {col(v.get('a4_full'))} | "
            f"— | — |"
        )

    # SUR rows
    for fc in SUR_OPERATION + SUR_REGISTER:
        k = f"add/SUR/{fc}"
        v = master.get(k, {})
        lines.append(
            f"| {k} | — | — | {col(v.get('a4_sur'))} | — |"
        )

    # MEM_VAL rows
    for role in ("load_x", "load_y", "read_back", "store"):
        for seed in (0, 1):
            k = f"{role}/MEM_VAL/s{seed}"
            v = master.get(k, {})
            lines.append(
                f"| {k} | n/a | n/a | n/a | {col(v.get('a4_memval'))} |"
            )

    lines.extend(
        [
            "",
            "## Per-field-class rollup",
            "",
        ]
    )
    fc_agg = field_class_rollup(rows)
    lines.append("| field_class | n | sample layers |")
    lines.append("|-------------|---|---------------|")
    for fc, info in sorted(fc_agg.items(), key=lambda x: -x[1]["n"]):
        sample = ", ".join(sorted(set(info["layers"]))[:4])
        lines.append(f"| {fc} | {info['n']} | {sample} |")

    lines.extend(
        [
            "",
            "## Layer rollup",
            "",
            f"- Runs with interstep-local > 0: **{layer_rollup(rows)['interstep_populated_count']}**",
            f"- IDs: `{', '.join(layer_rollup(rows)['runs_with_interstep_local_gt_0'])}`",
            "",
            "## Per-run granular detail",
            "",
        ]
    )

    for r in sorted(rows, key=lambda x: x["run_id"]):
        lines.append(f"### `{r['run_id']}`")
        mut = r.get("mutated_word_hex") or r.get("mutated_value")
        dec = r.get("decoded_instruction")
        dec_s = dec.get("disassembly") if dec else "—"
        lines.append(
            f"- **{r['fuzzer']}** variant={r['variant'] or '—'} "
            f"{r['kind']} @{r['role']} seed={r['seed']}"
        )
        lines.append(f"- mutated: `{mut}` | outcome: **{r['outcome_class']}**")
        lines.append(f"- layers: **{r['layers_triple']}** (failure_count={r['failure_count']})")
        if dec:
            lines.append(f"- decoded: `{dec_s}` ({dec.get('format_name', '')})")
        orig = r.get("original_instruction")
        if orig:
            lines.append(f"- original: `{orig.get('disassembly')}` ({orig.get('word_hex')})")
        if r.get("fields_changed"):
            lines.append(f"- fields_changed: {r['fields_changed']} | field_class: {r.get('field_class')}")
        if r.get("arguzz_mirror"):
            lines.append(f"- arguzz_mirror: {r['arguzz_mirror']}")
        if r.get("crash_evidence"):
            lines.append(f"- crash: {r['crash_evidence']}")
        lines.append("- constraints:")
        for b in constraint_bullets(r):
            lines.append(f"  {b}" if b.startswith("-") else f"  - {b}")
        lines.append("")

    path.write_text("\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description="Build E4 granular matrix from E1+E2 JSON")
    ap.add_argument("--e1-dir", type=Path, default=E1_DIR)
    ap.add_argument("--e2-dir", type=Path, default=E2_DIR)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = ap.parse_args()

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    site = load_site()
    e1_rows = load_e1_rows(args.e1_dir, site)
    a4_rows = load_a4_rows(args.e2_dir, site)
    rows = e1_rows + a4_rows

    counts = row_counts(rows)
    findings, failures = assert_findings(rows)
    master = build_master_index(rows)

    matrix_doc = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "sources": {"e1": str(args.e1_dir), "e2_a4": str(args.e2_dir)},
        "row_counts": counts,
        "verified_findings": findings,
        "rows": rows,
    }
    (out_dir / "matrix.json").write_text(json.dumps(matrix_doc, indent=2))
    write_csv(rows, out_dir / "matrix.csv")
    (out_dir / "counts.json").write_text(
        json.dumps(
            {
                "row_counts": counts,
                "verified_findings": findings,
                "field_class_rollup": field_class_rollup(rows),
                "layer_rollup": layer_rollup(rows),
            },
            indent=2,
        )
    )
    write_markdown(rows, master, findings, counts, out_dir / "MATRIX_GRANULAR.md")

    print(f"Wrote {out_dir}/matrix.json ({len(rows)} rows)")
    print(f"Row counts match: {counts['row_counts_match']}")
    print(f"All findings pass: {findings['all_pass']}")
    if failures:
        print("Assertion failures:")
        for f in failures[:10]:
            print(f"  - {f}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
