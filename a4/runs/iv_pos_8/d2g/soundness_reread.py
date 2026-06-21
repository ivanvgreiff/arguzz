"""Provisional soundness re-read aggregation (D2.G B4 Item 2)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pandas as pd

TRIAGE_PROPAGATED = "accepted_propagated_candidate"
TRIAGE_NOOP = "accepted_noop"
TRIAGE_HIDDEN = "accepted_hidden_global_reject"
EVIDENCE_STRONG = "strong"


def soundness_tables(triage_df: pd.DataFrame) -> dict:
    """Build per-variant soundness-count tables + divergent residue list."""
    if triage_df.empty:
        return {"summary": {}, "divergent_residue": [], "by_variant": []}

    summary_rows = []
    for (variant, seed), grp in triage_df.groupby(["variant", "seed"]):
        summary_rows.append({
            "variant": str(variant),
            "seed": int(seed),
            "n": int(len(grp)),
            "noop": int((grp["class"] == TRIAGE_NOOP).sum()),
            "propagated": int((grp["class"] == TRIAGE_PROPAGATED).sum()),
            "hidden": int((grp["class"] == TRIAGE_HIDDEN).sum()),
            "strong": int((grp["evidence"] == EVIDENCE_STRONG).sum()),
            "cf_inert": int((grp["evidence"] == "cf_inert").sum()),
            "word_truncated": int((grp["evidence"] == "word_truncated").sum()),
            "weak": int((grp["evidence"] == "weak").sum()),
        })

    by_vk = (
        triage_df.groupby(["variant", "kind", "class", "evidence"], dropna=False)
        .size()
        .reset_index(name="count")
    )
    by_vk["count"] = by_vk["count"].astype(int)

    residue = triage_df[
        (triage_df["class"] == TRIAGE_PROPAGATED)
        & (
            (triage_df["evidence"] == EVIDENCE_STRONG)
            | (
                (triage_df["kind"] == "POST_EXEC_PC_MOD")
                & (triage_df["evidence"] != "weak")
            )
        )
    ].copy()
    residue_records = json.loads(
        residue.to_json(orient="records")
    ) if not residue.empty else []

    return {
        "summary": summary_rows,
        "by_variant_kind_evidence": by_vk.to_dict(orient="records"),
        "divergent_residue": residue_records,
        "divergent_residue_count": len(residue_records),
    }


def write_soundness_report(triage_csv: Path, out_json: Path, out_md: Optional[Path] = None) -> dict:
    df = pd.read_csv(triage_csv)
    report = soundness_tables(df)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2))

    if out_md is not None:
        lines = [
            "# Provisional soundness re-read",
            "",
            f"Source: `{triage_csv}` ({len(df)} classified rows)",
            "",
            f"**Divergent residue count:** {report['divergent_residue_count']}",
            "",
        ]
        if report["divergent_residue"]:
            lines.append("## Divergent residue rows")
            lines.append("")
            for row in report["divergent_residue"]:
                lines.append(
                    f"- {row.get('variant')} seed={row.get('seed')} "
                    f"kind={row.get('kind')} step={row.get('step')} "
                    f"evidence={row.get('evidence')} fault={row.get('fault_word_change')}"
                )
        else:
            lines.append("No strong / non-weak POST_EXEC_PC_MOD propagated rows in this CSV.")
        lines.append("")
        lines.append("## Per-variant summary")
        lines.append("")
        if report["summary"]:
            lines.append(pd.DataFrame(report["summary"]).to_markdown(index=False))
        out_md.write_text("\n".join(lines))
    return report


def main() -> int:
    import argparse as _ap

    parser = _ap.ArgumentParser(description="D2.G provisional soundness re-read")
    parser.add_argument("triage_csv", type=Path)
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, default=None)
    args = parser.parse_args()
    report = write_soundness_report(args.triage_csv, args.out_json, args.out_md)
    print(json.dumps({
        "divergent_residue_count": report["divergent_residue_count"],
        "out_json": str(args.out_json),
        "out_md": str(args.out_md) if args.out_md else None,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
