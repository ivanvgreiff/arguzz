"""Parse E5 execution logs into G.0 atoms."""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
import sys

sys.path.insert(0, str(REPO))

from thesis_side_experiments.bias_campaign.classify import classify_run  # noqa: E402
from thesis_side_experiments.bias_campaign.run_common import (  # noqa: E402
    DEFAULT_ENV,
    failure_rows,
    global_failure_rows,
)
from thesis_side_experiments.minimal_add.analyze_logs import (  # noqa: E402
    bucket_failures,
    is_prove_error,
    thesis_layer,
    verify_provenance,
)
from thesis_side_experiments.full_sweep.region_map import classify_target  # noqa: E402

FAULT_RE = re.compile(r"<fault>(\{.*?\})</fault>", re.DOTALL)
A4_FAULT_RE = re.compile(r"<a4_[^>]+>(\{.*?\})</a4_[^>]+>", re.DOTALL)


def normalize_layers(layers: Optional[dict]) -> dict:
    if not layers:
        return {"intrastep_local": 0, "interstep_local": 0, "global": 0}
    return {
        "intrastep_local": layers.get("intrastep-local", 0),
        "interstep_local": layers.get("interstep-local", 0),
        "global": layers.get("global", 0),
    }


def expand_constraints_from_outcome(outcome, original: Optional[int], mutated: Optional[int]) -> List[dict]:
    rows = failure_rows(outcome)
    buckets = bucket_failures(rows)
    global_fams = global_failure_rows(outcome)
    accum = [r for r in rows if r["phase"] == "accum"]
    out: List[dict] = []

    for layer_key, layer_name in (
        ("intrastep-local", "intrastep-local"),
        ("interstep-local", "interstep-local"),
    ):
        for f in buckets[layer_key]:
            prov = verify_provenance(f, original, mutated)
            out.append(
                {
                    "layer": layer_name,
                    "full_loc": f["full_loc"],
                    "residue": f["value"],
                    "cycle": f.get("cycle"),
                    "step": f.get("step"),
                    "major": f.get("major"),
                    "minor": f.get("minor"),
                    "provenance_verified": prov.get("verified"),
                    "provenance": prov,
                }
            )

    for gf in global_fams:
        out.append(
            {
                "layer": "global",
                "full_loc": f"GLOBAL:family:{gf.get('family')} residue nonzero",
                "residue": None,
                "family": gf.get("family"),
            }
        )
    for f in accum:
        out.append(
            {
                "layer": "global",
                "full_loc": f["full_loc"],
                "residue": f["value"],
                "cycle": f.get("cycle"),
                "step": f.get("step"),
            }
        )

    layers = normalize_layers(
        {
            "intrastep-local": len(buckets["intrastep-local"]),
            "interstep-local": len(buckets["interstep-local"]),
            "global": len(global_fams) + len(accum),
        }
    )
    if layers["global"] and not any(c["layer"] == "global" for c in out):
        out.append(
            {
                "layer": "global",
                "full_loc": "GLOBAL:residue nonzero",
                "residue": None,
            }
        )
    return out


def extract_fault_tag(log_text: str) -> Optional[str]:
    for pat in (FAULT_RE, A4_FAULT_RE):
        m = pat.search(log_text)
        if m:
            return m.group(0)[:500]
    if "<a4_mutation_config>" in log_text:
        i = log_text.find("<a4_mutation_config>")
        return log_text[i : i + 400]
    return None


def parse_atom(
    sample: dict,
    log_text: str,
    host_sha: str,
    guest_text: tuple[Optional[int], Optional[int]] = (None, None),
) -> dict:
    fuzzer = sample["fuzzer"]
    step = sample.get("site", {}).get("step") or sample.get("inject_step")
    inject = sample.get("inject") or {}
    if not inject and sample.get("site"):
        s = sample["site"]
        inject = {
            "step": s.get("step"),
            "pc": s.get("pc"),
            "instr_at_site": s.get("instr") or s.get("assembly"),
            "target_kind": sample.get("target_kind"),
            "target_addr_or_reg": sample.get("target_addr_or_reg"),
        }

    if fuzzer == "arguzz":
        outcome = classify_run(log_text, target_step=step)
    else:
        outcome = classify_run(log_text, target_step=None, injected_override=True)

    # NOTE: is_prove_error() reclassifies to PROVE_ERROR, so it must be consulted
    # BEFORE deciding `crashed`/`layers` — otherwise prove-errors leak through as
    # crashed=False with layers=(0,0,0), masquerading as "none broken".
    prove_err = is_prove_error(log_text)
    crash_stage = None
    if outcome.preflight_crash:
        crash_stage = "preflight"
        outcome_class = "PREFLIGHT_CRASH"
    elif prove_err:
        crash_stage = "prove"
        outcome_class = "PROVE_ERROR"
    else:
        outcome_class = outcome.outcome_class

    crashed = outcome.preflight_crash or prove_err or outcome_class in (
        "PREFLIGHT_CRASH",
        "OTHER_CRASH",
        "PROVE_ERROR",
    )

    orig = sample.get("original_value")
    mut = sample.get("mutated_value")
    constraints = expand_constraints_from_outcome(outcome, orig, mut)
    buckets = bucket_failures(failure_rows(outcome))
    global_fams = global_failure_rows(outcome)
    accum = [r for r in failure_rows(outcome) if r["phase"] == "accum"]
    # layers are meaningful ONLY when constraints were actually evaluated.
    # No-constraint-data outcomes (prover errors, crashes, verify-rejects) -> None,
    # so they can never be mistaken for a genuine (0,0,0) "none broken".
    NO_CONSTRAINT_DATA = ("PROVE_ERROR", "PREFLIGHT_CRASH", "OTHER_CRASH", "VERIFY_REJECT")
    layers = normalize_layers(
        None
        if outcome_class in NO_CONSTRAINT_DATA
        else {
            "intrastep-local": len(buckets["intrastep-local"]),
            "interstep-local": len(buckets["interstep-local"]),
            "global": len(global_fams) + len(accum),
        }
    )

    region, hits_guest = classify_target(
        inject.get("target_kind"),
        inject.get("target_addr_or_reg"),
        inject.get("pc"),
        guest_text,
    )

    return {
        "sample_id": sample["sample_id"],
        "fuzzer": fuzzer,
        "mutation_type": sample["mutation_type"],
        "variant": sample.get("variant"),
        "seed": sample.get("seed"),
        "inject": inject,
        "target_region": region,
        "hits_guest_data": hits_guest,
        "outcome_class": outcome_class,
        "crashed": crashed,
        "crash_stage": crash_stage,
        "layers": layers,
        "constraints": constraints,
        "global_families": global_fams,
        "fault_info": extract_fault_tag(log_text),
        "failure_count": len(failure_rows(outcome)),
        "raw_log_path": sample.get("raw_log_path"),
        "config_path": sample.get("a4_config_path"),
        "cmd": sample.get("cmd"),
        "env": sample.get("env") or dict(DEFAULT_ENV),
        "host_sha256": host_sha,
    }


def write_gzip_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(text)
