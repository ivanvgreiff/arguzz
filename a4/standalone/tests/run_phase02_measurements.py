#!/usr/bin/env python3
"""
Phase 0.2 measurement script: compute K_total and per-mutation distinct context_id stats.

Run after a campaign:
  python -m a4.standalone.tests.run_phase02_measurements --db ./phase02_campaign.db
  python -m a4.standalone.tests.run_phase02_measurements --db ./a4_coverage.db --campaign 3

Uses get_distinct_context_ids_for_campaign and get_distinct_context_id_counts_per_mutation.
"""

import argparse
import statistics
import sys
from pathlib import Path

# Ensure project root (arguzz) is on path when run as script
_root = Path(__file__).resolve().parents[3]
if _root not in sys.path:
    sys.path.insert(0, str(_root))

from a4.standalone.coverage_db import CoverageDB


def main():
    parser = argparse.ArgumentParser(description="Phase 0.2: distinct context_id stats for a campaign")
    parser.add_argument("--db", required=True, help="Path to coverage DB")
    parser.add_argument("--campaign", type=int, default=None, help="Campaign ID (default: last campaign)")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Error: DB not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    with CoverageDB(str(db_path)) as db:
        cid = args.campaign
        if cid is None:
            cid = db.get_last_campaign_id()
            if cid is None:
                print("Error: No campaigns in DB", file=sys.stderr)
                sys.exit(1)
            print(f"Using last campaign_id: {cid}")

        info = db.get_campaign_info(cid)
        if info:
            print(f"Campaign {cid}: host={info.host_binary!r} kind={info.kind} seed={info.seed} mutations={info.total_mutations}")

        ids_set = db.get_distinct_context_ids_for_campaign(cid)
        K_total = len(ids_set)
        print(f"K_total (distinct context_id in campaign): {K_total}")

        per_mutation = db.get_distinct_context_id_counts_per_mutation(cid)
        if not per_mutation:
            print("Per-mutation: no mutations with failures")
            return

        counts = [c for _, c in per_mutation]
        print(f"Per-run distinct context_id: min={min(counts)} max={max(counts)} mean={statistics.mean(counts):.1f} n={len(counts)}")

        # Bucket-necessity note (Phase I plan: ~20k threshold for MAP_SIZE=65536)
        if K_total < 20_000 and max(counts) < 20_000:
            print("Bucket decision: K_total and per-run K below ~20k → step_bucket not required for Phase 3 (MAP_SIZE=65536).")
        else:
            print("Bucket decision: K_total or per-run K high → consider step_bucket or larger MAP_SIZE; collisions ≈ K²/(2*MAP_SIZE).")


if __name__ == "__main__":
    main()
