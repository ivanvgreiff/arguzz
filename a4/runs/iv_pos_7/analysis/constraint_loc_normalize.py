"""Normalize constraint_loc strings across A4 and V6 DB formats.

A4 (V0–V5): ``Name@file.zir:line``
V6 (arguzz): ``Name(full/path/file.zir:line)``

Canonical key: ``Name:basename:line``
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Set

_A4_PATTERN = re.compile(r"^(.+)@([^:]+):(\d+)$")
_V6_PATTERN = re.compile(r"^(.+)\(([^:]+):(\d+)\)$")


def normalize_constraint_loc(loc: str) -> str:
    m = _A4_PATTERN.match(loc)
    if m:
        return f"{m.group(1)}:{Path(m.group(2)).name}:{m.group(3)}"
    m = _V6_PATTERN.match(loc)
    if m:
        return f"{m.group(1)}:{Path(m.group(2)).name}:{m.group(3)}"
    return loc


def read_normalized_constraint_locs(conn: sqlite3.Connection) -> Set[str]:
    try:
        return {
            normalize_constraint_loc(r[0])
            for r in conn.execute("SELECT constraint_loc FROM coverage").fetchall()
        }
    except sqlite3.OperationalError:
        return set()
