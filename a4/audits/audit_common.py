"""Shared helpers for Phase 7d audit scripts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HOST = str(REPO_ROOT / "workspace/output/target/release/risc0-host")
EXPECTED_ARMS_PATH = REPO_ROOT / "a4/docs/cloud1/EXPECTED_ARMS.md"
GLOSSARY_PATH = REPO_ROOT / "a4/docs/cloud1/GLOSSARY.md"
OUTPUT_DIR = Path(__file__).parent / "audit_output"

# D40 (Inc 0): arms removed from EXPECTED_ARMS 48-row baseline by multi-cycle filter.
D40_REMOVED_ARMS = {
    ("INSTR_WORD_MOD_FULL", "last_step"),
    ("INSTR_WORD_MOD_SUR", "last_step"),
    ("INSTR_WORD_MOD_FULL", "pre_ecall"),
    ("INSTR_WORD_MOD_SUR", "pre_ecall"),
}

GLOSSARY_META = {
    "glossary": "a4/docs/cloud1/GLOSSARY.md",
    "definitions": {
        "major": "cycle.major — RV32IM instruction-class column (0-12); see GLOSSARY §RISC-V",
        "minor": "cycle.minor — sub-class within major; kind = major*8 + minor",
        "step": "user_cycle / A4 step index",
        "zone": "semantic_zone from zone_classifier.classify_zones",
        "arm_id": "mutation_kind|semantic_zone tuple string",
        "success_rate": "fraction of sampled steps where get_targets_at_step returned a valid target",
        "decode_match": "decoded (major,minor) from raw instruction word equals trace cycle (major,minor)",
    },
}


def arm_key(kind: str, zone: str) -> str:
    return f"{kind}|{zone}"


def parse_arm_cell(cell: str) -> Tuple[str, str]:
    kind, zone = cell.split("|", 1)
    return kind.strip(), zone.strip()


_ARM_ROW_RE = re.compile(
    r"^\|\s*(.+?)\s*\|\s*(\d+)\s*\|\s*([^|]+)\|\s*([🟢🟡🔵])\s*\|",
)


def _normalize_arm_cell(cell: str) -> str:
    return cell.strip().replace("\\|", "|")


def parse_expected_arms_baseline(path: Path = EXPECTED_ARMS_PATH) -> Dict[str, Any]:
    """Parse baseline kept-arm table from EXPECTED_ARMS.md."""
    text = path.read_text()
    start = -1
    for marker in ("### Kept arms (", "### Kept arms"):
        idx = text.find(marker)
        if idx >= 0:
            start = idx
            break
    end = text.find("### Expected-DROPPED arms", start)
    section = text[start:end] if start >= 0 and end > start else text

    arms: Dict[str, Dict[str, Any]] = {}
    for line in section.splitlines():
        m = _ARM_ROW_RE.match(line.strip())
        if not m:
            continue
        kind, zone = parse_arm_cell(_normalize_arm_cell(m.group(1)))
        arms[arm_key(kind, zone)] = {
            "kind": kind,
            "zone": zone,
            "expected_steps": int(m.group(2)),
            "tolerance": m.group(3).strip(),
            "status": m.group(4),
            "notes": "",
        }
    return {"arms": arms, "expected_count_doc": 48}


INC2_VARIANTS = {
    "V1": {"selector": "zoned", "label": "zoned (legacy bucket)"},
    "V2": {"selector": "kindUCB_zoned_v1", "label": "UCB1 + legacy reward"},
    "V3": {"selector": "kindUCB_zoned_v2_noQ", "label": "UCB1 + v2 reward"},
    "V4": {"selector": "kindTS_zoned_v2", "label": "TS + v2 reward"},
    "V5": {"selector": "cTS_semantic_v2", "label": "constrained TS + 48-arm HYBRID"},
}

INC2_SMOKE_SEED = 999
INC2_HOST_ARGS = ["--in1", "5", "--in4", "10"]


def run_fuzz_smoke(
    *,
    selector: str,
    db_path: str,
    num: int,
    host: str = DEFAULT_HOST,
    host_args: Optional[List[str]] = None,
    seed: int = INC2_SMOKE_SEED,
    telemetry_level: str = "full",
    debug_coverage_delta: Optional[str] = None,
    debug_bandit_trace: Optional[str] = None,
) -> int:
    """Run one local fuzz campaign; return CLI exit code."""
    import subprocess
    import sys

    cmd = [
        sys.executable, "-m", "a4.standalone.cli", "fuzz",
        "--host", host,
        "--num", str(num),
        "--kind", "all",
        "--values", "mixed",
        "--selector", selector,
        "--seed", str(seed),
        "--telemetry-level", telemetry_level,
        "--db", db_path,
    ]
    if debug_coverage_delta:
        cmd.extend(["--debug-coverage-delta", debug_coverage_delta])
    if debug_bandit_trace:
        cmd.extend(["--debug-bandit-trace", debug_bandit_trace])
    cmd.append("--")
    cmd.extend(host_args or INC2_HOST_ARGS)
    return subprocess.call(cmd, cwd=str(REPO_ROOT))


def load_inspection(host: str, in1: str, in4: str):
    from a4.core.inspection_data import InspectionData
    from a4.standalone.fuzzer import A4Fuzzer
    from a4.standalone.semantic_arm_universe import SemanticArmUniverse, _MUTATION_MODULES

    host_args = ["--in1", in1, "--in4", in4]
    data = InspectionData.from_inspection(host, host_args)
    kinds = sorted(_MUTATION_MODULES.keys())
    universe = SemanticArmUniverse.build(data, kinds)
    return data, universe, kinds, host_args
