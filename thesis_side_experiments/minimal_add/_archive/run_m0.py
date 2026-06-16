#!/usr/bin/env python3
"""M0 — Reproduce & freeze baseline (determinism gate)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "m0"
HOST = ROOT / "target/release/thesis-minimal-host"
PRODUCTION_HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.core.executor import run_a4_inspection_with_step, run_baseline  # noqa: E402
from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.core.touch_coverage import (  # noqa: E402
    distinct_touched,
    parse_accum_touch_bitmap,
    parse_accum_verbose_set,
    parse_touch_bitmap,
)
from a4.standalone.mutations.pre_exec_reg_mod import REGISTER_NAMES  # noqa: E402

TRACE_RE = re.compile(r"<trace>(\{.*?\})</trace>")
VERBOSE_RE = re.compile(r"<a4_touch_verbose>\[(.*?)\]</a4_touch_verbose>", re.DOTALL)

BASELINE_ENV = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
}


@dataclass
class AddSite:
    arguzz_step: int
    arguzz_pc: int
    assembly: str
    a4_step: int
    a4_pc: int
    cycle_idx: int
    major: int
    minor: int


def parse_verbose_set(output: str) -> Optional[Set[str]]:
    match = VERBOSE_RE.search(output)
    if not match:
        return None
    return set(json.loads("[" + match.group(1) + "]"))


def dedupe_trace_lines(lines: List[str]) -> List[str]:
    """Keep only the first contiguous trace block (prove logs trace twice)."""
    trace_lines = [ln for ln in lines if ln.startswith("<trace>")]
    if not trace_lines:
        return []

    out: List[str] = []
    seen_nonzero = False
    for line in trace_lines:
        m = TRACE_RE.search(line)
        if not m:
            continue
        step = json.loads(m.group(1)).get("step")
        if step == 0 and seen_nonzero:
            break
        if step not in (0, None):
            seen_nonzero = True
        out.append(line)
    return out


def find_guest_add_site(trace_lines: List[str]) -> Tuple[int, int, str]:
    """Return (arguzz_step, arguzz_pc, assembly) for the guest add s0,a0,a1."""
    hits: List[Tuple[int, int, str]] = []
    for line in trace_lines:
        data = json.loads(TRACE_RE.search(line).group(1))
        if data.get("instruction") != "Add":
            continue
        asm = data.get("assembly", "")
        if re.search(r"add\s+s0,\s*a0,\s*a1", asm):
            hits.append((int(data["step"]), int(data["pc"]), asm))

    if len(hits) != 1:
        raise RuntimeError(f"expected exactly one guest add s0,a0,a1; found {len(hits)}: {hits}")

    prev_by_step: Dict[int, dict] = {}
    for line in trace_lines:
        data = json.loads(TRACE_RE.search(line).group(1))
        prev_by_step[int(data["step"])] = data

    step, pc, asm = hits[0]
    li_a0 = prev_by_step.get(step - 2, {})
    li_a1 = prev_by_step.get(step - 1, {})
    if li_a0.get("assembly") != "li a0, 3" or li_a1.get("assembly") != "li a1, 4":
        raise RuntimeError(
            "add site sanity failed: expected li a0,3 / li a1,4 immediately before add; "
            f"got step-2={li_a0.get('assembly')!r}, step-1={li_a1.get('assembly')!r}"
        )
    return step, pc, asm


def derive_a4_step(cycles, arguzz_pc: int) -> Tuple[int, int, int, int]:
    target_pc = arguzz_pc + 4
    matches = [c for c in cycles if c.major == 0 and c.minor == 0 and c.pc == target_pc]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one A4 cycle major=0 minor=0 at pc={target_pc}; found {len(matches)}"
        )
    c = matches[0]
    return c.step, c.pc, c.cycle_idx, c.major


def build_instruction_card(a4_step: int, txns) -> List[dict]:
    card = []
    for t in txns:
        reg_idx = t.register_index()
        card.append(
            {
                "txn_idx": t.txn_idx,
                "a4_step": a4_step,
                "addr": t.addr,
                "word": t.word,
                "prev_word": t.prev_word,
                "is_read": t.is_read(),
                "is_write": t.is_write(),
                "register": REGISTER_NAMES[reg_idx] if reg_idx is not None else None,
            }
        )
    return card


def validate_instruction_card(card: List[dict]) -> None:
    by_reg = {row["register"]: row for row in card if row["register"]}
    a0 = by_reg.get("a0")
    a1 = by_reg.get("a1")
    s0 = by_reg.get("s0")
    if not a0 or not a1 or not s0:
        raise RuntimeError(f"missing register txns in card: {card}")
    if not (a0["is_read"] and a0["word"] == 3 and a0["prev_word"] == 3):
        raise RuntimeError(f"a0 READ 3 expected; got {a0}")
    if not (a1["is_read"] and a1["word"] == 4 and a1["prev_word"] == 4):
        raise RuntimeError(f"a1 READ 4 expected; got {a1}")
    if not (s0["is_write"] and s0["word"] == 7 and s0["prev_word"] == 0):
        raise RuntimeError(f"s0 WRITE 7 expected; got {s0}")


def run_host_trace() -> str:
    cmd = [str(HOST), "--trace"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise RuntimeError(f"baseline --trace failed exit={proc.returncode}")
    if '"output":"7"' not in out and '"output": "7"' not in out:
        raise RuntimeError("baseline journal output 7 not found")
    if '"context":"Verifier"' not in out or '"status":"success"' not in out:
        raise RuntimeError("baseline verifier success not found")
    return out


def production_host_stat() -> Dict[str, Any]:
    if not PRODUCTION_HOST.exists():
        return {"path": str(PRODUCTION_HOST), "exists": False}
    st = PRODUCTION_HOST.stat()
    return {
        "path": str(PRODUCTION_HOST),
        "exists": True,
        "mtime_iso": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "size_bytes": st.st_size,
    }


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {
        "milestone": "M0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "production_host_before_build": production_host_stat(),
    }

    prod_mtime_before = PRODUCTION_HOST.stat().st_mtime if PRODUCTION_HOST.exists() else None

    build = subprocess.run(["./build.sh"], cwd=ROOT, capture_output=True, text=True)
    (ART / "build_stdout.txt").write_text(build.stdout + build.stderr)
    if build.returncode != 0:
        raise SystemExit(f"build.sh failed: {build.returncode}")
    if not HOST.exists():
        raise SystemExit(f"missing host binary: {HOST}")

    report["production_host_after_build"] = production_host_stat()
    if prod_mtime_before is not None:
        after = PRODUCTION_HOST.stat().st_mtime
        report["production_host_mtime_unchanged"] = after == prod_mtime_before
        if after != prod_mtime_before:
            raise SystemExit("production risc0-host mtime changed during experiment build")

    trace_out = run_host_trace()
    trace_lines = dedupe_trace_lines(trace_out.splitlines())
    (ART / "baseline_trace_deduped.txt").write_text("\n".join(trace_lines) + "\n")

    arguzz_step, arguzz_pc, assembly = find_guest_add_site(trace_lines)
    report["arguzz_add_site"] = {
        "step": arguzz_step,
        "pc": arguzz_pc,
        "pc_hex": f"0x{arguzz_pc:08x}",
        "assembly": assembly,
    }

    if (arguzz_step, arguzz_pc) != (187, 2099232):
        raise SystemExit(
            f"add site drift: got step={arguzz_step} pc={arguzz_pc}, expected (187, 2099232)"
        )

    data = InspectionData.from_inspection(str(HOST), [])
    a4_step, a4_pc, cycle_idx, major = derive_a4_step(data.cycles, arguzz_pc)
    minor = 0
    dump_out, _cycles, _step_txns, txns = run_a4_inspection_with_step(str(HOST), [], a4_step)
    (ART / f"step_{a4_step}_dump.txt").write_text(dump_out)

    card = build_instruction_card(a4_step, txns)
    validate_instruction_card(card)

    add_site = AddSite(
        arguzz_step=arguzz_step,
        arguzz_pc=arguzz_pc,
        assembly=assembly,
        a4_step=a4_step,
        a4_pc=a4_pc,
        cycle_idx=cycle_idx,
        major=major,
        minor=minor,
    )
    site_payload = asdict(add_site)
    site_payload["expected_cycle_idx"] = 15424
    site_payload["cycle_idx_matches_expected"] = cycle_idx == 15424
    (ART / "add_site.json").write_text(json.dumps(site_payload, indent=2))
    (ART / "instruction_card.json").write_text(json.dumps(card, indent=2))

    if cycle_idx != 15424:
        raise SystemExit(f"cycle_idx={cycle_idx}, expected 15424")
    if a4_step != 185:
        raise SystemExit(f"a4_step={a4_step}, expected 185")

    determinism: List[dict] = []
    for run_id in (1, 2):
        out = run_baseline(str(HOST), [], BASELINE_ENV)
        path = ART / f"baseline_touch_run{run_id}.txt"
        path.write_text(out)
        failures = parse_all_constraint_failures(out)
        local_verbose = parse_verbose_set(out)
        accum_verbose = parse_accum_verbose_set(out)
        local_bitmap = parse_touch_bitmap(out)
        accum_bitmap = parse_accum_touch_bitmap(out)
        determinism.append(
            {
                "run": run_id,
                "path": str(path.relative_to(ROOT)),
                "constraint_fail_count": len(failures),
                "local_verbose_count": len(local_verbose) if local_verbose is not None else None,
                "accum_verbose_count": len(accum_verbose) if accum_verbose is not None else None,
                "local_bitmap_distinct": distinct_touched(local_bitmap)
                if local_bitmap
                else None,
                "accum_bitmap_distinct": distinct_touched(accum_bitmap)
                if accum_bitmap
                else None,
                "local_verbose": sorted(local_verbose) if local_verbose is not None else None,
                "accum_verbose": sorted(accum_verbose) if accum_verbose is not None else None,
            }
        )

    r1, r2 = determinism
    if r1["constraint_fail_count"] != 0 or r2["constraint_fail_count"] != 0:
        raise SystemExit("baseline must have zero constraint failures")
    if r1["local_verbose"] != r2["local_verbose"]:
        raise SystemExit("local touch verbose sets differ between baseline runs")
    if r1["accum_verbose"] != r2["accum_verbose"]:
        raise SystemExit("accum touch verbose sets differ between baseline runs")

    report["add_site"] = site_payload
    report["instruction_card"] = card
    report["determinism"] = {
        "baseline_local_touch_set_size": r1["local_verbose_count"],
        "baseline_accum_touch_set_size": r1["accum_verbose_count"],
        "baseline_local_bitmap_distinct": r1["local_bitmap_distinct"],
        "baseline_accum_bitmap_distinct": r1["accum_bitmap_distinct"],
        "runs_identical": True,
        "run_summaries": [
            {k: v for k, v in r.items() if k not in ("local_verbose", "accum_verbose")}
            for r in determinism
        ],
    }
    report["acceptance"] = {
        "add_site_auto_derived": (187, 2099232),
        "a4_step": 185,
        "cycle_idx": 15424,
        "baseline_output_7": True,
        "baseline_verifier_ok": True,
        "baseline_zero_failures": True,
        "touch_sets_reproducible": True,
    }

    (ART / "M0_REPORT.json").write_text(json.dumps(report, indent=2))

    md = f"""# M0 Report — Reproduce & Freeze Baseline

**Status:** PASS (automated gate)

## Production isolation
- Production host: `{PRODUCTION_HOST}`
- mtime unchanged after `./build.sh`: **{report['production_host_mtime_unchanged']}**

## Auto-derived add site
| Field | Value |
|-------|-------|
| Arguzz step | {arguzz_step} |
| Arguzz pc | {arguzz_pc} (`0x{arguzz_pc:08x}`) |
| Assembly | `{assembly}` |
| A4 step | {a4_step} |
| A4 pc (next PC) | {a4_pc} (`0x{a4_pc:08x}`) |
| cycle_idx | {cycle_idx} |
| major / minor | {major} / {minor} |

Sanity: steps {arguzz_step - 2}–{arguzz_step - 1} are `li a0, 3` and `li a1, 4`.

## Instruction card (A4 step {a4_step})
| txn_idx | reg | op | word | prev_word |
|---------|-----|----|------|-----------|
"""
    for row in card:
        if row["register"]:
            op = "READ" if row["is_read"] else "WRITE"
            md += f"| {row['txn_idx']} | {row['register']} | {op} | {row['word']} | {row['prev_word']} |\n"

    md += f"""
## Baseline determinism (2 runs, env={BASELINE_ENV})
- constraint_fail count: **0** / **0**
- local touch verbose set size: **{r1['local_verbose_count']}** (identical across runs)
- accum touch verbose set size: **{r1['accum_verbose_count']}** (identical across runs)
- local bitmap distinct buckets: **{r1['local_bitmap_distinct']}**
- accum bitmap distinct buckets: **{r1['accum_bitmap_distinct']}**

## Frozen artifacts
- `artifacts/m0/add_site.json`
- `artifacts/m0/instruction_card.json`
- `artifacts/m0/baseline_trace_deduped.txt`
- `artifacts/m0/step_{a4_step}_dump.txt`
- `artifacts/m0/baseline_touch_run1.txt`
- `artifacts/m0/baseline_touch_run2.txt`
- `artifacts/m0/M0_REPORT.json`

## Opus review gate
M0 acceptance criteria met. Proceed to **M1** after Opus greenlight.
"""
    (ART / "M0_REPORT.md").write_text(md)

    print(md)


if __name__ == "__main__":
    main()
