"""
Touch Coverage Parsing and Merge

Parses <a4_touch_coverage> bitmap output from A4 mutation runs (Phase 3.2)
and provides utilities for AFL-style bitmap merge and new-bit counting.

The touch bitmap is a 65536-byte array (MAP_SIZE) produced by the C++ witgen
instrumentation (Phase 3.1). Each byte is a saturating counter for a hash bucket
keyed by (loc, major, minor) via FNV-1a. A non-zero entry means the corresponding
constraint context was "touched" (EQZ was called) at least once during the run.

Constants:
  A4_TOUCH_MAP_SIZE = 65536  (must match kA4TouchMapSize in ffi.cpp)

See a4/docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md §3 and
    a4/docs/touch/PHASE_3_2_IMPLEMENTATION_PLAN.md for details.
"""

import base64
import re
from typing import Optional


A4_TOUCH_MAP_SIZE = 65536
"""Bitmap size in bytes. Must match kA4TouchMapSize in ffi.cpp."""

_TOUCH_COVERAGE_RE = re.compile(
    r'<a4_touch_coverage>([\w+/=]+)</a4_touch_coverage>'
)


def parse_touch_bitmap(output: str) -> Optional[bytes]:
    """
    Extract and decode the touch bitmap from combined host output.

    Searches for a single <a4_touch_coverage>BASE64</a4_touch_coverage> tag,
    base64-decodes the content, and returns the raw bytes (length A4_TOUCH_MAP_SIZE).

    Returns None if the tag is not found, decoding fails, or length does not match.
    """
    match = _TOUCH_COVERAGE_RE.search(output)
    if not match:
        return None
    try:
        raw = base64.b64decode(match.group(1))
    except Exception:
        return None
    if len(raw) != A4_TOUCH_MAP_SIZE:
        return None
    return bytes(raw)


def make_global_bitmap() -> bytearray:
    """Create a zeroed global bitmap (campaign-level accumulator)."""
    return bytearray(A4_TOUCH_MAP_SIZE)


def count_new_bits(run_bitmap: bytes, global_bitmap: bytearray) -> int:
    """
    Count how many bitmap indices are newly touched by this run.

    An index is "new" if run_bitmap[i] > 0 and global_bitmap[i] == 0.
    This is the primary reward signal for coverage-guided fuzzing.
    """
    new = 0
    for i in range(A4_TOUCH_MAP_SIZE):
        if run_bitmap[i] > 0 and global_bitmap[i] == 0:
            new += 1
    return new


def merge_into_global(run_bitmap: bytes, global_bitmap: bytearray) -> None:
    """
    Merge a run's bitmap into the global bitmap (element-wise max).

    After merge, global_bitmap[i] = max(global_bitmap[i], run_bitmap[i])
    for all i. This preserves the "high water mark" per bucket across the
    campaign. Mutates global_bitmap in place.
    """
    for i in range(A4_TOUCH_MAP_SIZE):
        if run_bitmap[i] > global_bitmap[i]:
            global_bitmap[i] = run_bitmap[i]


def fnv1a_touch_hash(loc: str, major: int, minor: int) -> int:
    """
    Compute the same FNV-1a hash as C++ a4_touch_hash.

    Returns the bitmap index in [0, A4_TOUCH_MAP_SIZE) for a given
    (loc, major, minor) context. Useful for inverse mapping: given a
    constraint context, find which bitmap bucket it maps to.

    Must match ffi.cpp a4_touch_hash exactly:
      - FNV-1a 32-bit, offset basis 2166136261, prime 16777619
      - Input: bytes of loc string (UTF-8), then major (1 byte), then minor (1 byte)
      - Output: hash % A4_TOUCH_MAP_SIZE
    """
    h = 2166136261
    for b in loc.encode('utf-8'):
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    h = ((h ^ (major & 0xFF)) * 16777619) & 0xFFFFFFFF
    h = ((h ^ (minor & 0xFF)) * 16777619) & 0xFFFFFFFF
    return h % A4_TOUCH_MAP_SIZE


def distinct_touched(bitmap: bytes) -> int:
    """Count the number of non-zero entries in a bitmap (distinct buckets hit)."""
    return sum(1 for b in bitmap if b > 0)


def total_touches(bitmap: bytes) -> int:
    """Sum of all entries in a bitmap (total touch count, may saturate per bucket)."""
    return sum(bitmap)
