#!/usr/bin/env python3
"""Build audit run-list: 37 fired+ACCEPTED targets + positive controls + baseline."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
AUDIT = Path(__file__).resolve().parent
SAMPLE_SET = ROOT / "artifacts" / "e5" / "sample_set.json"
ATOMS_DIR = ROOT / "artifacts" / "e5" / "atoms_n250"
OUT = AUDIT / "run_list.json"

NAMED_CONTROLS = [
    "arguzz__INSTR_WORD_MOD__default__s0757",
    "arguzz__INSTR_WORD_MOD__default__s0761",
    "arguzz__POST_EXEC_MEM_MOD__default__s2046",
    "arguzz__POST_EXEC_REG_MOD__default__s2673",
]

AUTO_CONTROL_TYPES = ["COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD"]


def fired(atom: dict) -> bool:
    return atom["fuzzer"] == "arguzz" and "<fault" in (atom.get("fault_info") or "")


def load_atoms() -> Dict[str, dict]:
    out = {}
    for p in ATOMS_DIR.glob("*.json"):
        a = json.loads(p.read_text())
        out[a["sample_id"]] = a
    return out


def load_samples() -> Dict[str, dict]:
    data = json.loads(SAMPLE_SET.read_text())
    return {s["sample_id"]: s for s in data["samples"]}


def constraint_cycles(atom: dict) -> List[int]:
    cycles = []
    for c in atom.get("constraints") or []:
        cy = c.get("cycle")
        if cy is not None:
            cycles.append(int(cy))
    return sorted(set(cycles))


def make_arguzz_entry(
    sample_id: str,
    sample: dict,
    atom: dict,
    expect: str,
) -> dict:
    return {
        "run_id": sample_id,
        "kind": "arguzz",
        "expect": expect,
        "source_sid": sample_id,
        "mutation_type": sample["mutation_type"],
        "inject_step": sample["inject_step"],
        "seed": sample["seed"],
        "outcome_class": atom.get("outcome_class"),
        "constraint_cycles": constraint_cycles(atom),
        "constraints": atom.get("constraints") or [],
    }


def main() -> None:
    if not SAMPLE_SET.is_file() or not ATOMS_DIR.is_dir():
        raise SystemExit("missing sample_set.json or atoms_n250/")

    atoms = load_atoms()
    samples = load_samples()

    targets = [
        a
        for a in atoms.values()
        if a.get("outcome_class") == "ACCEPTED" and fired(a)
    ]
    by_type: Dict[str, int] = {}
    for t in targets:
        by_type[t["mutation_type"]] = by_type.get(t["mutation_type"], 0) + 1

    if len(targets) != 37:
        raise SystemExit(f"expected 37 targets, got {len(targets)}: {by_type}")
    if by_type.get("POST_EXEC_PC_MOD") != 30 or by_type.get("INSTR_WORD_MOD") != 7:
        raise SystemExit(f"unexpected target mix: {by_type}")

    runs: List[dict] = [
        {"run_id": "baseline", "kind": "baseline", "expect": "baseline", "repeat": 2},
    ]

    for t in sorted(targets, key=lambda x: x["sample_id"]):
        sid = t["sample_id"]
        if sid not in samples:
            raise SystemExit(f"target {sid} missing from sample_set.json")
        runs.append(make_arguzz_entry(sid, samples[sid], t, "accept"))

    for sid in NAMED_CONTROLS:
        if sid not in atoms or sid not in samples:
            raise SystemExit(f"named control missing: {sid}")
        atom = atoms[sid]
        if not atom.get("constraints"):
            raise SystemExit(f"named control {sid} has empty constraints[]")
        if atom.get("outcome_class") not in ("CONSTRAINT_REJECT", "GLOBAL_REJECT"):
            raise SystemExit(
                f"named control {sid} expected reject, got {atom.get('outcome_class')}"
            )
        runs.append(make_arguzz_entry(sid, samples[sid], atom, "break"))

    for mtype in AUTO_CONTROL_TYPES:
        cands = sorted(
            sid
            for sid, a in atoms.items()
            if a["mutation_type"] == mtype
            and a.get("outcome_class") == "CONSTRAINT_REJECT"
            and fired(a)
            and a.get("constraints")
        )
        if not cands:
            raise SystemExit(f"no fired CONSTRAINT_REJECT for {mtype}")
        sid = cands[0]
        runs.append(make_arguzz_entry(sid, samples[sid], atoms[sid], "break"))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target_count": 37,
        "control_count": len(runs) - 1 - 37,
        "baseline_repeats": 2,
        "total_runs_per_node": sum(
            r.get("repeat", 1) for r in runs
        ),
        "runs": runs,
    }
    OUT.write_text(json.dumps(payload, indent=2))

    print(f"wrote {OUT}")
    print(f"  targets=37 (POST_EXEC_PC=30, INSTR_WORD=7)")
    print(f"  controls={payload['control_count']} (+ baseline×2)")
    print(f"  total host invocations/node={payload['total_runs_per_node']}")


if __name__ == "__main__":
    main()
