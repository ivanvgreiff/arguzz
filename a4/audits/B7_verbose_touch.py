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
# Host emits quoted "loc|major|minor" entries (pipe-separated), not (loc, major, minor).
CTX_PIPE_RE = re.compile(r'"([^"]+)\|(\d+)\|(\d+)"')
CTX_PAREN_RE = re.compile(r"\(([^)]+)\)")


def parse_contexts(blob: str) -> Set[Tuple[str, int, int]]:
    out: Set[Tuple[str, int, int]] = set()
    for m in CTX_PIPE_RE.finditer(blob):
        try:
            out.add((m.group(1), int(m.group(2)), int(m.group(3))))
        except ValueError:
            continue
    if out:
        return out
    for m in CTX_PAREN_RE.finditer(blob):
        parts = [p.strip() for p in m.group(1).split(",")]
        if len(parts) >= 3:
            try:
                out.add((parts[0], int(parts[1]), int(parts[2])))
            except ValueError:
                continue
    return out


def _candidate_block_indices(block_count: int, mutation_index: int) -> List[int]:
    """Return plausible verbose-block indices for a DB mutation_id."""
    if mutation_index < 1 or block_count < 1:
        return []
    out: List[int] = []
    for idx in (mutation_index - 2, mutation_index - 1):
        if 0 <= idx < block_count and idx not in out:
            out.append(idx)
    return out


def contexts_for_mutation(log_text: str, mutation_index: int) -> Set[Tuple[str, int, int]]:
    blocks = VERBOSE_RE.findall(log_text)
    if mutation_index < 1 or not blocks:
        return set()
    cands = _candidate_block_indices(len(blocks), mutation_index)
    if not cands:
        return set()
    return parse_contexts(blocks[cands[0]])


def contexts_for_mutation_pair(
    log_a: str, log_b: str, mutation_index: int
) -> Tuple[Set[Tuple[str, int, int]], Set[Tuple[str, int, int]], Optional[int]]:
    """Resolve verbose contexts for a pair-mate diff at mutation_index.

    Tries mutation_id-2 and mutation_id-1 block indices (49 blocks / 50 muts)
    and picks the index whose symmetric context diff is non-empty.
    """
    blocks_a = VERBOSE_RE.findall(log_a)
    blocks_b = VERBOSE_RE.findall(log_b)
    n = min(len(blocks_a), len(blocks_b))
    if mutation_index < 1 or n < 1:
        return set(), set(), None

    hits: List[Tuple[int, Set[Tuple[str, int, int]], Set[Tuple[str, int, int]]]] = []
    for idx in _candidate_block_indices(n, mutation_index):
        ca = parse_contexts(blocks_a[idx])
        cb = parse_contexts(blocks_b[idx])
        if ca != cb:
            hits.append((idx, ca, cb))

    if len(hits) == 1:
        _, ca, cb = hits[0]
        return ca, cb, hits[0][0]
    if len(hits) > 1:
        idx, ca, cb = min(hits, key=lambda h: abs(len(h[1] ^ h[2])))
        return ca, cb, idx

    idx = _candidate_block_indices(n, mutation_index)[0]
    return parse_contexts(blocks_a[idx]), parse_contexts(blocks_b[idx]), idx


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

    flare_set, octo_set, block_idx = contexts_for_mutation_pair(
        flare_log, octo_log, args.mutation_id
    )
    extra_on_octo = sorted(octo_set - flare_set)
    missing_on_octo = sorted(flare_set - octo_set)

    report = {
        "_meta": {
            "audit": "B7_verbose_touch",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mutation_id": args.mutation_id,
            "verbose_block_index": block_idx,
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
