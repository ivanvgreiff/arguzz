#!/usr/bin/env python3
"""D1.B Batch 1.5 — derive page_class layout from guest ELF + memory.rs."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

D1B_ROOT = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
IV7_DBS = IV7 / "dbs"
D1A_DBS = D1B_ROOT.parent / "d1a" / "dbs"

GUEST_ELF = (
    REPO
    / "workspace/output/target/riscv-guest/risc0-methods/risc0-guest"
    / "riscv32im-risc0-zkvm-elf/release/risc0-guest"
)
MEMORY_RS = (
    REPO / "workspace/risc0-modified/risc0/zkvm/platform/src/memory.rs"
)
HOST_ECALL_LO = 0x42000000
HOST_ECALL_HI = 0x42000100
USER_BAND_LO = 0x00010000
USER_BAND_HI = 0xBFFF0000  # D8 user band upper bound (user_bigint starts here)
STACK_TEXT_GAP_LO = 0x00200400
STACK_TEXT_GAP_HI = 0x00200800
USER_OTHER_GATE_PCT = 15.0  # Batch 1.5 gate (pre-1.5b catch-all design)
USER_OTHER_POST_15B_GATE_PCT = 0.5  # Batch 1.5b target after user_dynamic

JSON_OUT = D1B_ROOT / "d1b_guest_elf_layout.json"
MD_OUT = D1B_ROOT / "d1b_page_class_layout.md"
PLOT_OUT = D1B_ROOT / "plots" / "d1b_page_class_histogram.png"

EXPECTED_MEMORY_RS = {
    "GUEST_MIN_MEM": 0x00004000,
    "GUEST_MAX_MEM": 0xC0000000,
    "STACK_TOP": 0x00200400,
    "TEXT_START": 0x00200800,
}

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))

from a4.standalone.compressed_global_extractor import address_region  # noqa: E402
from analysis.cgc_variants import parse_memory_byte_addr  # noqa: E402
from build_batch1_audit import cat_a_db_list, discover_d1a_dbs  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_memory_rs(path: Path) -> Dict[str, int]:
    text = path.read_text()
    out: Dict[str, int] = {}
    for name in EXPECTED_MEMORY_RS:
        m = re.search(rf"pub const {name}:\s*\w+\s*=\s*(0x[0-9a-fA-F_]+)", text)
        if not m:
            raise SystemExit(f"missing {name} in {path}")
        out[name] = int(m.group(1).replace("_", ""), 16)
    for name, expected in EXPECTED_MEMORY_RS.items():
        if out[name] != expected:
            raise SystemExit(
                f"{name} changed: got {out[name]:#x}, expected {expected:#x}"
            )
    return out


def _readelf_sections(elf: Path) -> Dict[str, Tuple[int, int]]:
    out = subprocess.run(
        ["readelf", "-S", str(elf)],
        check=True,
        capture_output=True,
        text=True,
    )
    sections: Dict[str, Tuple[int, int]] = {}
    for line in out.stdout.splitlines():
        m = re.match(
            r"\s*\[\s*\d+\]\s+(\.\w+)\s+\S+\s+([0-9a-f]+)\s+\S+\s+([0-9a-f]+)",
            line,
        )
        if m:
            name, addr_s, size_s = m.group(1), m.group(2), m.group(3)
            sections[name] = (int(addr_s, 16), int(size_s, 16))
    for req in (".text", ".rodata", ".eh_frame", ".data", ".bss"):
        if req not in sections:
            raise SystemExit(f"missing ELF section {req}")
    return sections


def _readelf_end_symbol(elf: Path) -> int:
    out = subprocess.run(
        ["readelf", "-s", str(elf)],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in out.stdout.splitlines():
        if " _end" in line:
            parts = line.split()
            return int(parts[1], 16)
    raise SystemExit("_end symbol not found in ELF")


def build_page_class_layout(
    sections: Dict[str, Tuple[int, int]],
    memory_rs: Dict[str, int],
    end_addr: int,
    eh_frame_policy: str = "fold_into_rodata",
) -> List[Dict[str, object]]:
    text_start = memory_rs["TEXT_START"]
    text_addr, _text_size = sections[".text"]
    if text_addr != text_start:
        raise SystemExit(
            f".text addr {text_addr:#x} != TEXT_START {text_start:#x}"
        )

    rodata_addr, _ = sections[".rodata"]
    data_addr, _ = sections[".data"]

    layout: List[Dict[str, object]] = [
        {
            "label": "stack",
            "lo": USER_BAND_LO,
            "hi": text_start,
            "source": "memory.rs TEXT_START lower bound",
        },
        {
            "label": "text",
            "lo": text_start,
            "hi": rodata_addr,
            "source": f"[TEXT_START, .rodata.addr) folds .text gap",
        },
        {
            "label": "rodata",
            "lo": rodata_addr,
            "hi": data_addr,
            "source": (
                f"[.rodata.addr, .data.addr) — eh_frame_policy={eh_frame_policy}"
            ),
        },
        {
            "label": "data_bss",
            "lo": data_addr,
            "hi": end_addr,
            "source": "[.data.addr, _end)",
        },
        {
            "label": "heap",
            "lo": end_addr,
            "hi": HOST_ECALL_LO,
            "source": "[_end, HOST_ECALL)",
        },
        {
            "label": "host_ecall",
            "lo": HOST_ECALL_LO,
            "hi": HOST_ECALL_HI,
            "source": "GLOSSARY / D42",
        },
        {
            "label": "user_dynamic",
            "lo": HOST_ECALL_HI,
            "hi": USER_BAND_HI,
            "source": "Batch 1.5b: [HOST_ECALL_HI, D8 user band) — upper user RAM, no ELF map",
        },
    ]
    return layout


def _page_class_with_layout(
    addr: int, layout: List[Tuple[int, int, str]], default: str = "user_other"
) -> str:
    region = address_region(addr)
    if region not in ("user", "user_bigint"):
        return region
    if region == "user_bigint":
        return region
    for lo, hi, label in layout:
        if lo <= addr < hi:
            return label
    return default


def layout_tuples(layout: List[Dict[str, object]]) -> List[Tuple[int, int, str]]:
    return [(int(r["lo"]), int(r["hi"]), str(r["label"])) for r in layout]


def empirical_validation(
    db_list: List, layout: List[Tuple[int, int, str]]
) -> Dict[str, object]:
    """Aggregate byte_addr hits in user/user_bigint across Cat-A DBs."""
    label_counts: Counter = Counter()
    gap_hits = 0
    total_user_addrs = 0
    user_other_addrs: List[int] = []

    for _corpus, _variant, _seed, db_path in db_list:
        with sqlite3.connect(db_path) as conn:
            for (addr_str,) in conn.execute(
                """
                SELECT address FROM global_failures
                WHERE family = 'memory' AND address IS NOT NULL
                """
            ):
                ba = parse_memory_byte_addr(addr_str)
                if ba is None:
                    continue
                region = address_region(ba)
                if region not in ("user", "user_bigint"):
                    continue
                total_user_addrs += 1
                lbl = _page_class_with_layout(ba, layout)
                label_counts[lbl] += 1
                if lbl == "user_other":
                    user_other_addrs.append(ba)
                if STACK_TEXT_GAP_LO <= ba < STACK_TEXT_GAP_HI:
                    gap_hits += 1

    user_other_frac = (
        100.0 * label_counts.get("user_other", 0) / total_user_addrs
        if total_user_addrs
        else 0.0
    )
    return {
        "total_user_band_byte_addrs": total_user_addrs,
        "label_counts": dict(sorted(label_counts.items())),
        "user_other_fraction_pct": round(user_other_frac, 4),
        "user_other_gate_pass": user_other_frac <= USER_OTHER_GATE_PCT,
        "user_other_post_15b_gate_pass": user_other_frac <= USER_OTHER_POST_15B_GATE_PCT,
        "stack_text_gap_hits": gap_hits,
        "user_other_sample_addrs": sorted(set(user_other_addrs))[:20],
    }


def write_histogram(label_counts: Dict[str, int], path: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("matplotlib not available\n")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    labels = list(label_counts.keys())
    counts = [label_counts[k] for k in labels]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(labels, counts, color="steelblue")
    ax.set_ylabel("byte_addr hits (30 DBs, user/user_bigint)")
    ax.set_title("D1.B Batch 1.5 page_class empirical distribution")
    ax.tick_params(axis="x", rotation=45)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def write_markdown(
    layout: List[Dict[str, object]],
    memory_rs: Dict[str, int],
    sections: Dict[str, Tuple[int, int]],
    end_addr: int,
    empirical: Dict[str, object],
    guest_sha: str,
) -> None:
    lines = [
        "# D1.B Batch 1.5 — page_class layout derivation",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"**Guest ELF sha256:** `{guest_sha}`",
        "",
        "## Q-PC-EHF decision",
        "",
        "**.eh_frame folded into `rodata`** via half-open range `[.rodata.addr, .data.addr)`.",
        "",
        "## memory.rs constants",
        "",
        "| Constant | Value |",
        "|---|---|",
    ]
    for k, v in memory_rs.items():
        lines.append(f"| `{k}` | `{v:#x}` |")
    lines.extend(
        [
            "",
            "## ELF sections",
            "",
            "| Section | Addr | Size | End |",
            "|---|---|---|---|",
        ]
    )
    for name, (addr, size) in sorted(sections.items()):
        lines.append(f"| `{name}` | `{addr:#x}` | `{size:#x}` | `{addr + size:#x}` |")
    lines.append(f"| `_end` | `{end_addr:#x}` | — | — |")
    lines.extend(["", "## Final `_PAGE_CLASS_USER_LAYOUT`", "", "| page_class | Range | Source |", "|---|---|---|"])
    for row in layout:
        lines.append(
            f"| `{row['label']}` | `[{row['lo']:#x}, {row['hi']:#x})` | {row['source']} |"
        )
    lines.extend(
        [
            "",
            "## Empirical validation (30 Cat-A DBs)",
            "",
            f"- Total user/user_bigint `byte_addr` hits: **{empirical['total_user_band_byte_addrs']}**",
            f"- `user_other` fraction: **{empirical['user_other_fraction_pct']}%** "
            f"(Batch 1.5 gate ≤ {USER_OTHER_GATE_PCT}%; "
            f"Batch 1.5b gate ≤ {USER_OTHER_POST_15B_GATE_PCT}%)",
            f"- Batch 1.5b gate: **{'PASS' if empirical.get('user_other_post_15b_gate_pass') else 'FAIL'}**",
            f"- Stack-text gap `[{STACK_TEXT_GAP_LO:#x}, {STACK_TEXT_GAP_HI:#x})` hits: **{empirical['stack_text_gap_hits']}**",
            "",
            "### Label histogram",
            "",
            "```",
            json.dumps(empirical["label_counts"], indent=2),
            "```",
            "",
            f"![page_class histogram](plots/{PLOT_OUT.name})",
            "",
            "## Pro disclosure draft (Q-PC-4)",
            "",
            "We define `page_class` as semantic memory-use classes within the `user` band,",
            "derived deterministically from the sha2-host guest ELF + zkVM `memory.rs` +",
            "HOST_ECALL MMIO range. Non-`user`/`user_bigint` regions pass through as",
            "`page_class = address_region`.",
            "",
        ]
    )
    MD_OUT.write_text("\n".join(lines) + "\n")


def main() -> int:
    if not GUEST_ELF.is_file() or GUEST_ELF.stat().st_size == 0:
        print(
            "HARD FAIL: guest ELF missing.\n"
            "Run: cd workspace/output && cargo build --release",
            file=sys.stderr,
        )
        return 2

    guest_sha = _sha256(GUEST_ELF)
    memory_rs = _parse_memory_rs(MEMORY_RS)
    sections = _readelf_sections(GUEST_ELF)
    end_addr = _readelf_end_symbol(GUEST_ELF)

    layout = build_page_class_layout(sections, memory_rs, end_addr)
    layout_json = {
        "spec": "IV_POS_8_D1_B_SPEC.md §3.2 Batch 1.5",
        "derived_at_utc": datetime.now(timezone.utc).isoformat(),
        "guest_elf_path": str(GUEST_ELF.relative_to(REPO)),
        "guest_elf_sha256": guest_sha,
        "memory_rs_path": str(MEMORY_RS.relative_to(REPO)),
        "memory_rs_constants": memory_rs,
        "elf_sections": {
            name: {"addr": addr, "size": size, "end": addr + size}
            for name, (addr, size) in sections.items()
        },
        "end_symbol": end_addr,
        "q_pc_ehf": "fold_into_rodata",
        "page_class_user_layout": layout,
        "page_class_user_default": "user_other",
        "host_ecall": {"lo": HOST_ECALL_LO, "hi": HOST_ECALL_HI},
    }
    JSON_OUT.write_text(json.dumps(layout_json, indent=2) + "\n")

    db_list = cat_a_db_list()
    if len(db_list) != 30:
        raise SystemExit(f"expected 30 DBs, got {len(db_list)}")

    empirical = empirical_validation(db_list, layout_tuples(layout))
    layout_json["empirical_validation"] = empirical
    JSON_OUT.write_text(json.dumps(layout_json, indent=2) + "\n")

    write_histogram(empirical["label_counts"], PLOT_OUT)
    write_markdown(layout, memory_rs, sections, end_addr, empirical, guest_sha)

    print(f"wrote {JSON_OUT}")
    print(f"wrote {MD_OUT}")
    print(f"wrote {PLOT_OUT}")
    print(
        f"user_other: {empirical['user_other_fraction_pct']}% "
        f"(15% gate: {'PASS' if empirical['user_other_gate_pass'] else 'FAIL'}; "
        f"1.5b gate: {'PASS' if empirical['user_other_post_15b_gate_pass'] else 'FAIL'})"
    )
    if not empirical["user_other_post_15b_gate_pass"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
