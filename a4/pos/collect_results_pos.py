#!/usr/bin/env python3
"""
a4/pos/collect_results_pos.py — pull POS result artifacts to local + validate.

After campaigns finish on the test nodes (which already did `pos_upload`), the
artifacts live in the POS result folder on the management node. This script
copies them to a local analysis directory, runs basic validation, and writes a
`collection_report.json` summarising what's present, what's intact, and what
needs re-running.

Per pivot §10.5 + §15.8.

Usage (typical):

    # If you're running this on the management node and the result folder is
    # directly readable:
    python -m a4.pos.collect_results_pos \\
        --result-folder /srv/testbed/results/<your-user>/pos_ab_v1/ \\
        --out-dir       ./pos_ab_v1_results/

    # If you're running locally and need to scp first:
    rsync -av <user>@<mgmt>:/srv/testbed/results/<you>/pos_ab_v1/ ./pos_ab_v1_results/
    python -m a4.pos.collect_results_pos \\
        --result-folder ./pos_ab_v1_results/ \\
        --out-dir       ./pos_ab_v1_results/ \\
        --in-place

The script does NOT issue `pos_download` / `scp` itself by default — testbed
specifics vary too much. The --result-folder is assumed to be a directory
already accessible from the host running this script.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List


def _iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_db(db_path: Path, expected_min_mut: int = 1) -> dict:
    """Open the DB and check that expected tables exist + are non-empty."""
    out = {"path": str(db_path), "exists": db_path.exists(), "size_bytes": 0}
    if not out["exists"]:
        out["error"] = "missing"
        return out
    out["size_bytes"] = db_path.stat().st_size
    if out["size_bytes"] == 0:
        out["error"] = "empty file"
        return out
    try:
        with sqlite3.connect(db_path, timeout=2) as c:
            cur = c.cursor()
            n_mut = cur.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
            out["mutations"] = n_mut
            try:
                n_fail = cur.execute("SELECT COUNT(*) FROM failures").fetchone()[0]
                out["failures"] = n_fail
            except sqlite3.OperationalError:
                out["failures"] = None
            try:
                n_glob = cur.execute("SELECT COUNT(*) FROM global_failures").fetchone()[0]
                out["global_failures"] = n_glob
            except sqlite3.OperationalError:
                out["global_failures"] = None
            try:
                n_rew = cur.execute("SELECT COUNT(*) FROM mutation_rewards").fetchone()[0]
                out["mutation_rewards"] = n_rew
            except sqlite3.OperationalError:
                out["mutation_rewards"] = None
            try:
                p = cur.execute("SELECT tau_g, gamma, b_count, selector FROM campaign_params LIMIT 1").fetchone()
                out["campaign_params"] = (
                    {"tau_g": p[0], "gamma": p[1], "b_count": p[2], "selector": p[3]} if p else None
                )
            except sqlite3.OperationalError:
                out["campaign_params"] = None
            out["ok"] = n_mut >= expected_min_mut
            if not out["ok"]:
                out["warning"] = f"mutations < expected_min ({expected_min_mut})"
    except sqlite3.DatabaseError as e:
        out["error"] = f"DB error: {e}"
    return out


def _completion_marker_in_log(log_path: Path) -> Optional[bool]:
    """Heuristic: look for known end-of-campaign log markers."""
    if not log_path.exists() or log_path.stat().st_size == 0:
        return None
    # Read last 4KB
    with log_path.open("rb") as f:
        f.seek(max(0, log_path.stat().st_size - 4096))
        tail = f.read().decode(errors="replace")
    for marker in ("Campaign complete", "CAMPAIGN COMPLETE", "Total time:",
                   "Total failures:", "DONE; results ->"):
        if marker in tail:
            return True
    return False


def collect(result_folder: Path, out_dir: Path, in_place: bool,
            expected_min_mut: int) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "collected_at_utc": _iso(),
        "result_folder":    str(result_folder),
        "out_dir":          str(out_dir),
        "in_place":         in_place,
        "expected_min_mutations": expected_min_mut,
        "runs": [],
    }

    # Each campaign run uploaded a results folder; on the management node those
    # appear as subdirectories under result_folder, one per run_id.
    for run_dir in sorted(p for p in result_folder.iterdir() if p.is_dir()):
        # Each run_dir has *.db, *.log, *.meta.json
        dbs   = sorted(run_dir.glob("*.db"))
        logs  = sorted(run_dir.glob("*.log"))
        metas = sorted(run_dir.glob("*.meta.json"))

        for db in dbs:
            base = db.stem
            log_match = next((l for l in logs if l.stem == base), None)
            meta_match = next((m for m in metas if m.stem.rsplit(".meta", 1)[0] == base
                                                or m.stem == base + ".meta"), None)

            local_db = out_dir / db.name if not in_place else db
            if not in_place:
                shutil.copy2(db, local_db)
                if log_match:
                    shutil.copy2(log_match, out_dir / log_match.name)
                if meta_match:
                    shutil.copy2(meta_match, out_dir / meta_match.name)

            v = _validate_db(local_db, expected_min_mut=expected_min_mut)
            v["run_dir"] = str(run_dir)
            v["log"]     = str(log_match) if log_match else None
            v["meta"]    = str(meta_match) if meta_match else None
            v["log_marker_ok"] = _completion_marker_in_log(log_match) if log_match else None
            if meta_match:
                try:
                    v["meta_content"] = json.loads(meta_match.read_text())
                except Exception as e:
                    v["meta_error"] = str(e)
            report["runs"].append(v)

    out_path = out_dir / "collection_report.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"[collect_results_pos] {len(report['runs'])} runs inspected; report -> {out_path}")
    bad = [r for r in report["runs"] if r.get("error") or not r.get("ok")]
    if bad:
        print(f"[collect_results_pos] {len(bad)} runs FAILED validation; see report")
    return report


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="collect_results_pos", description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--result-folder", required=True, type=Path,
                   help="Local-readable path containing per-run subdirectories from POS.")
    p.add_argument("--out-dir", required=True, type=Path,
                   help="Where to place validated copies + collection_report.json.")
    p.add_argument("--in-place", action="store_true",
                   help="Do not copy; validate the files where they are.")
    p.add_argument("--expected-min-mutations", type=int, default=1,
                   help="Each DB must have at least this many mutations rows to be OK.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    if not args.result_folder.exists():
        print(f"error: --result-folder does not exist: {args.result_folder}", file=sys.stderr)
        return 2
    report = collect(args.result_folder, args.out_dir, args.in_place, args.expected_min_mutations)
    bad = [r for r in report["runs"] if r.get("error") or not r.get("ok")]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
