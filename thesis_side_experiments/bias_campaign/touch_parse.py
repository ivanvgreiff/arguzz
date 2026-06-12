"""Parse verbose touch tags (reuse M0/M1 regex conventions)."""

from __future__ import annotations

import json
import re
from typing import List, Optional, Set

LOCAL_VERBOSE_RE = re.compile(r"<a4_touch_verbose[^>]*>\[(.*?)\]</a4_touch_verbose>", re.DOTALL)
ACCUM_VERBOSE_RE = re.compile(r"<a4_accum_touch_verbose[^>]*>\[(.*?)\]</a4_accum_touch_verbose>", re.DOTALL)


def parse_local_verbose_set(output: str) -> Optional[Set[str]]:
    match = LOCAL_VERBOSE_RE.search(output)
    if not match:
        return None
    try:
        return set(json.loads("[" + match.group(1) + "]"))
    except (json.JSONDecodeError, ValueError):
        return None


def parse_accum_verbose_set(output: str) -> Optional[Set[str]]:
    match = ACCUM_VERBOSE_RE.search(output)
    if not match:
        return None
    try:
        return set(json.loads("[" + match.group(1) + "]"))
    except (json.JSONDecodeError, ValueError):
        return None


def filter_by_context(keys: Set[str], major: int, minor: int) -> List[str]:
    suffix = f"|{major}|{minor}"
    return sorted(k for k in keys if k.endswith(suffix))
