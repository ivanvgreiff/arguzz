#!/usr/bin/env python3
"""Build PRO_R2_PACKET.zip — slim Pro review packet (3 files only)."""
from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOCS = ROOT.parents[2] / "a4" / "docs" / "cloud1"

# Pro Round 2 packet: brief + report + notebook only.
# Excluded: ProG_Report_2 (Pro authored), CLOUD1_DECISIONS (on request),
# CSVs (aggregates in report), plots (embedded in HTML), race/B1 deep-dives.
FILES = [
    (DOCS / "PRO_R2_DECISIONS_BRIEF.md", "PRO_R2_DECISIONS_BRIEF.md"),
    (ROOT / "MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md", "MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md"),
    (ROOT / "MAB_ARCHITECTURE_NOTEBOOK_R2.html", "MAB_ARCHITECTURE_NOTEBOOK_R2.html"),
]


def main() -> int:
    out = ROOT / "PRO_R2_PACKET.zip"
    missing = [arc for src, arc in FILES if not src.is_file()]
    if missing:
        raise SystemExit(f"Missing files for packet: {missing}")

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for src, arc in FILES:
            zf.write(src, arc)
    print(f"Wrote {out} ({out.stat().st_size} bytes)")
    print("Contents:")
    for _, arc in FILES:
        print(f"  - {arc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
