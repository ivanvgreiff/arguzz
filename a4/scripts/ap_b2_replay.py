#!/usr/bin/env python3
"""AP.B2 — (0,1,0) corpus enumeration + bench/patched bracket + genuine-soundness."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(str(ROOT)))

from a4.core.executor import run_a4_mutation  # noqa: E402
from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.standalone.mutations.pre_exec_reg_mod import (  # noqa: E402
    PreExecRegModTarget,
    create_config,
    get_all_targets,
)
from thesis_side_experiments.minimal_add.analyze_logs import (  # noqa: E402
    bucket_failures,
    thesis_layer,
)

DEFAULT_PATCHED = ROOT / "a4/builds/ap/patched/risc0-host"
DEFAULT_BENCH = ROOT / "a4/builds/ap/bench-isread/risc0-host"
DEFAULT_GUEST_ARGS = ["--in1", "5", "--in4", "10"]
OUT_DIR = ROOT / "a4/runs/iv_pos_9/ap"

VERIFIER_OK_RE = re.compile(
    r'<record>\s*\{[^}]*"context"\s*:\s*"Verifier"[^}]*"status"\s*:\s*"success"[^}]*\}\s*</record>'
)


@dataclass
class CorpusEntry:
    config_id: str
    step: int
    txn_idx: int
    word: int
    strategy: str
    major: int
    minor: int
    register_name: str
    register_idx: int
    original_word: int
    prev_word: int
    pc: str
    source: str
    layers_patched: Dict[str, int]
    config_path: str
    addr: int = 0
    cycle_idx: int = 0
    is_write: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def pick_mutated(target: PreExecRegModTarget) -> int:
    for delta in (1, 0x10001, 7, 0xDEADBEEF):
        v = (target.original_word + delta) & 0xFFFFFFFF
        if v != target.prev_word and v != target.original_word:
            return v
    return (target.original_word ^ 0xFFFFFFFF) & 0xFFFFFFFF


def layer_counts(failures) -> Dict[str, int]:
    rows = [
        {
            "full_loc": f.loc,
            "phase": f.phase,
            "value": f.value,
            "major": f.major,
            "minor": f.minor,
        }
        for f in failures
    ]
    buckets = bucket_failures(rows)
    return {
        "intrastep_local": len(buckets["intrastep-local"]),
        "interstep_local": len(buckets["interstep-local"]),
        "global": len(buckets["global"]),
    }


def is_010(layers: Dict[str, int]) -> bool:
    return (
        layers.get("intrastep_local", 0) == 0
        and layers.get("interstep_local", 0) >= 1
        and layers.get("global", 0) == 0
    )


def verifier_accepts(output: str, exit_code: int) -> bool:
    return exit_code == 0 and bool(VERIFIER_OK_RE.search(output))


def run_config(host: str, guest_args: List[str], config_path: Path) -> dict:
    result = run_a4_mutation(host, guest_args, config_path)
    layers = layer_counts(result.failures)
    return {
        "exit_code": result.exit_code,
        "accepted": verifier_accepts(result.combined_output, result.exit_code),
        "layers": layers,
        "failure_count": len(result.failures),
        "isread_only": is_010(layers)
        and all(
            "IsRead" in (f.loc or "")
            for f in result.failures
            if thesis_layer(f.loc, f.phase) == "interstep-local"
        )
        if layers.get("interstep_local")
        else False,
    }


def _screen_one(payload: dict) -> Optional[dict]:
    target = PreExecRegModTarget(**payload["target"])
    host = payload["host"]
    guest_args = payload["guest_args"]
    cfg_dir = Path(payload["cfg_dir"])
    mutated = pick_mutated(target)
    cfg_path = create_config(target, mutated, cfg_dir / f"screen_{target.step}_{target.txn_idx}.json")
    outcome = run_config(host, guest_args, cfg_path)
    if not is_010(outcome["layers"]):
        return None
    return {
        "target": payload["target"],
        "mutated_word": mutated,
        "config_path": str(cfg_path),
        "layers_patched": outcome["layers"],
    }


def load_e5_atoms(atoms_dir: Path) -> List[dict]:
    if not atoms_dir.is_dir():
        return []
    out = []
    for path in sorted(atoms_dir.glob("a4__PRE_EXEC_REG_MOD__next_read__*.json")):
        atom = json.loads(path.read_text())
        layers = atom.get("layers") or {}
        norm = {
            "intrastep_local": layers.get("intrastep_local", layers.get("intrastep-local", 0)),
            "interstep_local": layers.get("interstep_local", layers.get("interstep-local", 0)),
            "global": layers.get("global", 0),
        }
        if is_010(norm):
            out.append(atom)
    return out


def build_race_guest_corpus(
    data: InspectionData,
    patched_host: str,
    guest_args: List[str],
    workers: int,
    max_screen: Optional[int],
) -> List[CorpusEntry]:
    targets = [
        t
        for t in get_all_targets(data, strategy="next_read")
        if t.major in (5, 6)
    ]
    if max_screen is not None:
        targets = targets[:max_screen]

    cfg_dir = OUT_DIR / "configs" / "screen"
    cfg_dir.mkdir(parents=True, exist_ok=True)

    payloads = [
        {
            "target": {
                "step": t.step,
                "cycle_idx": t.cycle_idx,
                "pc": t.pc,
                "major": t.major,
                "minor": t.minor,
                "txn_idx": t.txn_idx,
                "addr": t.addr,
                "register_idx": t.register_idx,
                "register_name": t.register_name,
                "original_word": t.original_word,
                "prev_word": t.prev_word,
                "is_write": t.is_write,
                "strategy": t.strategy,
            },
            "host": patched_host,
            "guest_args": guest_args,
            "cfg_dir": str(cfg_dir),
        }
        for t in targets
    ]

    hits: List[dict] = []
    if workers <= 1:
        for p in payloads:
            hit = _screen_one(p)
            if hit:
                hits.append(hit)
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_screen_one, p): p for p in payloads}
            for fut in as_completed(futs):
                hit = fut.result()
                if hit:
                    hits.append(hit)

    entries: List[CorpusEntry] = []
    for i, hit in enumerate(sorted(hits, key=lambda h: (h["target"]["step"], h["target"]["txn_idx"]))):
        t = hit["target"]
        entries.append(
            CorpusEntry(
                config_id=f"race_{i:04d}_s{t['step']}_txn{t['txn_idx']}",
                step=t["step"],
                txn_idx=t["txn_idx"],
                word=hit["mutated_word"],
                strategy="next_read",
                major=t["major"],
                minor=t["minor"],
                register_name=t["register_name"],
                register_idx=t["register_idx"],
                original_word=t["original_word"],
                prev_word=t["prev_word"],
                pc=f"0x{t['pc']:08x}",
                source="race_guest_screen",
                layers_patched=hit["layers_patched"],
                config_path=hit["config_path"],
                addr=t["addr"],
                cycle_idx=t["cycle_idx"],
                is_write=t["is_write"],
            )
        )
    return entries


def bracket_corpus(
    corpus: List[CorpusEntry],
    bench_host: str,
    patched_host: str,
    guest_args: List[str],
) -> List[dict]:
    rows = []
    for entry in corpus:
        cfg = Path(entry.config_path)
        if not cfg.is_file():
            cfg = OUT_DIR / "configs" / "bracket" / f"{entry.config_id}.json"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            target = PreExecRegModTarget(
                step=entry.step,
                cycle_idx=entry.cycle_idx,
                pc=int(entry.pc, 16),
                major=entry.major,
                minor=entry.minor,
                txn_idx=entry.txn_idx,
                addr=entry.addr,
                register_idx=entry.register_idx,
                register_name=entry.register_name,
                original_word=entry.original_word,
                prev_word=entry.prev_word,
                is_write=entry.is_write,
                strategy=entry.strategy,
            )
            create_config(target, entry.word, cfg)
            entry.config_path = str(cfg)

        bench = run_config(bench_host, guest_args, cfg)
        patched = run_config(patched_host, guest_args, cfg)
        genuine = bench["accepted"] and entry.word != entry.original_word
        rows.append(
            {
                "config_id": entry.config_id,
                "step": entry.step,
                "txn_idx": entry.txn_idx,
                "register": entry.register_name,
                "major": entry.major,
                "original_word": entry.original_word,
                "mutated_word": entry.word,
                "bench_accepted": bench["accepted"],
                "patched_accepted": patched["accepted"],
                "bench_layers": bench["layers"],
                "patched_layers": patched["layers"],
                "genuine": genuine and bench["accepted"],
                "classification": (
                    "genuine"
                    if genuine and bench["accepted"]
                    else ("no_op" if bench["accepted"] else "bench_reject")
                ),
            }
        )
    return rows


def write_ap_findings(
    corpus: List[CorpusEntry],
    bracket_rows: List[dict],
    e5_count: int,
) -> None:
    n_bench_accept = sum(1 for r in bracket_rows if r["bench_accepted"])
    n_patched_reject = sum(1 for r in bracket_rows if not r["patched_accepted"])
    n_genuine = sum(1 for r in bracket_rows if r["classification"] == "genuine")

    text = f"""# AP findings — IsRead planted bug (AP.B2)

## Summary

| Metric | Value |
|--------|------:|
| Corpus size (race-guest (0,1,0) screen) | {len(corpus)} |
| E5 atoms_n250 (0,1,0) in repo | {e5_count} |
| bench-isread ACCEPT | {n_bench_accept}/{len(bracket_rows)} |
| patched REJECT | {n_patched_reject}/{len(bracket_rows)} |
| Genuine soundness (mutated ≠ honest, bench accepts) | {n_genuine}/{len(bracket_rows)} |

## Circuit-level why (store/load source reads keep global balanced)

From `inst_mem.zir`:

- **Load (`MemLoadInput`)**: `ReadReg(cycle, ii, decoded.rs1)` then `MemoryRead` at computed address.
- **Store (`MemStoreInput`)**: `ReadSourceRegs` → two `ReadReg` reads (rs1, rs2), then `MemoryRead` for the RMW word at the store address.

`PRE_EXEC_REG_MOD next_read` edits a **register READ** txn's `word` while leaving `prev_word` unchanged → `word ≠ prev_word`.

On the **patched** build, `ReadReg` still calls `MemoryRead` **with** `IsRead` (`mem.zir:79-80`). That fires as an **interstep-local** failure while the **global memory permutation residue often stays balanced** when the mutated read feeds a store/load memory operand path coherently — the E5 (0,1,0) class.

On **bench-isread**, `ReadReg` uses `MemoryReadNoIsRead` (AP.B1) → the interstep `IsRead` check is gone → those witnesses **verify**.

## Genuine vs no-op

- **Genuine**: bench accepts AND `mutated_word ≠ original_word` (witness encodes a register read value the honest execution did not perform).
- **No-op**: bench accepts but mutation is identity (none expected in this corpus).

## Bracket exceptions

"""
    exceptions = [
        r
        for r in bracket_rows
        if not (r["bench_accepted"] and not r["patched_accepted"])
    ]
    if exceptions:
        for r in exceptions:
            text += f"- `{r['config_id']}` step={r['step']} bench={r['bench_accepted']} patched={r['patched_accepted']}\n"
    else:
        text += "None — full corpus brackets cleanly (bench accept, patched reject).\n"

    (OUT_DIR / "ap_findings.md").write_text(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patched-host", default=str(DEFAULT_PATCHED))
    parser.add_argument("--bench-host", default=str(DEFAULT_BENCH))
    parser.add_argument("--guest-args", nargs="*", default=DEFAULT_GUEST_ARGS)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-screen", type=int, default=None)
    parser.add_argument(
        "--e5-atoms",
        default=str(ROOT / "thesis_side_experiments/full_sweep/artifacts/e5/atoms_n250"),
    )
    parser.add_argument("--bracket-only", action="store_true")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    e5_atoms = load_e5_atoms(Path(args.e5_atoms))

    corpus_path = OUT_DIR / "ap_corpus_010.json"
    if args.bracket_only and corpus_path.is_file():
        raw = json.loads(corpus_path.read_text())
        corpus = [CorpusEntry(**e) for e in raw["corpus"]]
    else:
        print("[ap_b2] inspection (patched host)...")
        data = InspectionData.from_inspection(args.patched_host, args.guest_args)
        print(f"[ap_b2] screening load/store next_read targets (workers={args.workers})...")
        corpus = build_race_guest_corpus(
            data,
            args.patched_host,
            args.guest_args,
            workers=args.workers,
            max_screen=args.max_screen,
        )
        corpus_path.write_text(
            json.dumps(
                {
                    "corpus": [c.to_dict() for c in corpus],
                    "e5_atoms_in_repo": len(e5_atoms),
                    "guest_args": args.guest_args,
                },
                indent=2,
            )
            + "\n"
        )

    print(f"[ap_b2] corpus size={len(corpus)} (e5 atoms in repo={len(e5_atoms)})")
    if not corpus:
        print("ERROR: empty corpus — screening found no (0,1,0) configs", file=sys.stderr)
        return 1

    print("[ap_b2] bracket replay...")
    bracket_rows = bracket_corpus(corpus, args.bench_host, args.patched_host, args.guest_args)
    bracket_path = OUT_DIR / "ap_bracket_table.json"
    bracket_path.write_text(json.dumps(bracket_rows, indent=2) + "\n")

    write_ap_findings(corpus, bracket_rows, len(e5_atoms))

    n_ok = sum(1 for r in bracket_rows if r["bench_accepted"] and not r["patched_accepted"])
    n_gen = sum(1 for r in bracket_rows if r["classification"] == "genuine")
    gp3 = len(corpus) >= 1
    gp4 = n_ok == len(bracket_rows)
    gp5 = n_gen >= 1

    summary = {
        "GP3": {"pass": gp3, "corpus_size": len(corpus), "e5_atoms_in_repo": len(e5_atoms)},
        "GP4": {
            "pass": gp4,
            "bench_accept": sum(1 for r in bracket_rows if r["bench_accepted"]),
            "patched_reject": sum(1 for r in bracket_rows if not r["patched_accepted"]),
            "total": len(bracket_rows),
        },
        "GP5": {"pass": gp5, "genuine": n_gen, "total": len(bracket_rows)},
    }
    (OUT_DIR / "ap_b2_verify.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"[ap_b2] wrote {corpus_path}, {bracket_path}, {OUT_DIR}/ap_findings.md")
    return 0 if gp3 and gp4 and gp5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
