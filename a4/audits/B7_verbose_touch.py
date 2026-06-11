#!/usr/bin/env python3
"""Inc 3b B7 §B.3 — parse A4_COVERAGE_TOUCH_VERBOSE from campaign logs."""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERBOSE_RE = re.compile(r"<a4_touch_verbose>\[(.*?)\]</a4_touch_verbose>", re.DOTALL)
CTX_RE = re.compile(r"\(([^)]+)\)")


def parse_contexts(blob: str) -> Set[Tuple[str, int, int]]:
    out: Set[Tuple[str, int, int]] = set()
    for m in CTX_RE.finditer(blob):
        parts = [p.strip() for p in m.group(1).split(",")]
        if len(parts) >= 3:
            try:
                out.add((parts[0], int(parts[1]), int(parts[2])))
            except ValueError:
                continue
    return out


def contexts_for_mutation(log_text: str, mutation_index: int) -> Set[Tuple[str, int, int]]:
    """mutation_index is 1-based index in campaign (matches mutation id in sequential run)."""
    blocks = VERBOSE_RE.findall(log_text)
    if mutation_index < 1 or mutation_index > len(blocks):
        return set()
    return parse_contexts(blocks[mutation_index - 1])


def find_mutation_id_for_step(db_path: Path, step: int, kind: str = "MEM_VAL_MOD") -> Optional[int]:
    conn = sqlite3.connect(str(db_path))
    row = conn.execute(
        "SELECT id FROM mutations WHERE step=? AND kind=? ORDER BY id LIMIT 1",
        (step, kind),
    ).fetchone()
    conn.close()
    return int(row[0]) if row else None


def main() -> int:
    parser = argparse.ArgumentParser(description="B7 verbose touch diff")
    parser.add_argument("--flare-log", required=True)
    parser.add_argument("--octo-log", required=True)
    parser.add_argument("--mutation-id", type=int, default=35)
    parser.add_argument("--output", default="a4/audits/audit_output/inc3b/B7_cross_node_verbose.json")
    args = parser.parse_args()

    flare_log = Path(args.flare_log).read_text(errors="replace")
    octo_log = Path(args.octo_log).read_text(errors="replace")

    flare_set = contexts_for_mutation(flare_log, args.mutation_id)
    octo_set = contexts_for_mutation(octo_log, args.mutation_id)
    extra_on_octo = sorted(octo_set - flare_set)
    missing_on_octo = sorted(flare_set - octo_set)

    report = {
        "_meta": {
            "audit": "B7_verbose_touch",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mutation_id": args.mutation_id,
        },
        "flare_context_count": len(flare_set),
        "octo_context_count": len(octo_set),
        "extra_on_octo": [{"loc": a, "major": b, "minor": c} for a, b, c in extra_on_octo],
        "missing_on_octo": [{"loc": a, "major": b, "minor": c} for a, b, c in missing_on_octo],
        "delta_extra_count": len(extra_on_octo),
        "delta_missing_count": len(missing_on_octo),
        "interpretation": (
            "single extra bit on octorand"
            if len(extra_on_octo) == 1 and len(missing_on_octo) == 0
            else "see extra/missing sets"
        ),
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
