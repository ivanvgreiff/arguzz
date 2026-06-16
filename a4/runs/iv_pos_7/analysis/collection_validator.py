"""D4 — COLLECTION_REPORT_FINAL.json for IV.POS.7 (50 V1–V5 DBs)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Import validator from repo (read-only reuse per DELIVERABLES_PLAN §4.3).
_REPO = Path(__file__).resolve().parents[4]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from a4.pos.collect_results_pos import _validate_db  # noqa: E402

from .discover import discover_dbs, parse_db_path, VARIANT_TO_PRO_NAME

EXPECTED_MIN_MUT = 5999
OUT_PATH = Path(__file__).resolve().parents[1] / "COLLECTION_REPORT_FINAL.json"


def build_collection_report(dbs_root: Path | None = None) -> dict:
    m = discover_dbs(dbs_root) if dbs_root else discover_dbs()
    runs = []
    for variant in ("V1", "V2", "V3", "V4", "V5"):
        for seed in sorted(m[variant]):
            db = m[variant][seed]
            v = _validate_db(db, expected_min_mut=EXPECTED_MIN_MUT)
            _, selector, _, _ = parse_db_path(db)
            v["variant"] = variant
            v["pro_name"] = VARIANT_TO_PRO_NAME[variant]
            v["seed"] = seed
            v["selector_expected"] = selector
            if v.get("campaign_params"):
                v["selector_match"] = v["campaign_params"].get("selector") == selector
            runs.append(v)

    n_ok = sum(1 for r in runs if r.get("ok"))
    return {
        "collected_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "campaign": "IV.POS.7",
        "expected_dbs": 50,
        "found_dbs": len(runs),
        "passed": n_ok,
        "failed": len(runs) - n_ok,
        "all_passed": n_ok == 50 and len(runs) == 50,
        "expected_min_mutations": EXPECTED_MIN_MUT,
        "runs": runs,
    }


def write_collection_report(out_path: Path = OUT_PATH, dbs_root: Path | None = None) -> dict:
    report = build_collection_report(dbs_root)
    out_path.write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    r = write_collection_report()
    print(f"COLLECTION: {r['passed']}/{r['found_dbs']} PASSED")
