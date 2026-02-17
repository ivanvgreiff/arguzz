#!/usr/bin/env python3
"""
Phase 3.2 unit tests for touch coverage parsing and merge.

No host binary required. Tests the Python-side parsing and bitmap logic
using synthetic <a4_touch_coverage> data.

Run: python -m pytest a4/standalone/tests/test_touch_coverage.py -v
"""

import base64

import pytest

from a4.core.touch_coverage import (
    A4_TOUCH_MAP_SIZE,
    parse_touch_bitmap,
    make_global_bitmap,
    count_new_bits,
    merge_into_global,
    distinct_touched,
    total_touches,
)


def _make_bitmap_with_entries(entries: dict) -> bytes:
    """Create a MAP_SIZE-byte bitmap with specified {index: value} entries."""
    buf = bytearray(A4_TOUCH_MAP_SIZE)
    for idx, val in entries.items():
        buf[idx] = val
    return bytes(buf)


def _wrap_as_output(bitmap_bytes: bytes) -> str:
    """Base64-encode a bitmap and wrap it in the expected tag."""
    encoded = base64.b64encode(bitmap_bytes).decode('ascii')
    return f"some prefix output\n<a4_touch_coverage>{encoded}</a4_touch_coverage>\nsome suffix\n"


class TestParseTouchBitmap:
    def test_parse_known_bitmap(self):
        """Round-trip: known bitmap → base64 → parse → same bytes."""
        original = _make_bitmap_with_entries({0: 1, 100: 42, 65535: 255})
        output = _wrap_as_output(original)
        result = parse_touch_bitmap(output)
        assert result is not None
        assert len(result) == A4_TOUCH_MAP_SIZE
        assert result[0] == 1
        assert result[100] == 42
        assert result[65535] == 255
        assert result[50] == 0
        assert result == original

    def test_parse_all_zeros(self):
        """A bitmap of all zeros should parse correctly."""
        original = bytes(A4_TOUCH_MAP_SIZE)
        output = _wrap_as_output(original)
        result = parse_touch_bitmap(output)
        assert result is not None
        assert result == original

    def test_parse_missing_tag(self):
        """Output without the tag should return None."""
        result = parse_touch_bitmap("no tag here\njust some output\n")
        assert result is None

    def test_parse_invalid_base64(self):
        """Malformed base64 inside the tag should return None."""
        output = "<a4_touch_coverage>!!!not-valid-base64!!!</a4_touch_coverage>\n"
        result = parse_touch_bitmap(output)
        assert result is None

    def test_parse_wrong_length(self):
        """Base64 that decodes to wrong length should return None."""
        short_data = base64.b64encode(b"too short").decode('ascii')
        output = f"<a4_touch_coverage>{short_data}</a4_touch_coverage>\n"
        result = parse_touch_bitmap(output)
        assert result is None

    def test_parse_with_constraint_fail_lines(self):
        """Tag should be found even when mixed with <constraint_fail> lines."""
        bitmap = _make_bitmap_with_entries({7: 3})
        encoded = base64.b64encode(bitmap).decode('ascii')
        output = (
            '<constraint_fail>{"cycle":100,"step":1,"pc":0,"major":0,"minor":0,"loc":"X","value":1}</constraint_fail>\n'
            f'<a4_touch_coverage>{encoded}</a4_touch_coverage>\n'
            '<a4_touch_debug> total_touches=3 distinct_buckets=1 </a4_touch_debug>\n'
        )
        result = parse_touch_bitmap(output)
        assert result is not None
        assert result[7] == 3


class TestCountNewBits:
    def test_all_new(self):
        """All non-zero entries in run are new (global is empty)."""
        run = _make_bitmap_with_entries({0: 1, 5: 10, 100: 255})
        glob = make_global_bitmap()
        assert count_new_bits(run, glob) == 3

    def test_none_new(self):
        """All non-zero entries in run are already in global."""
        run = _make_bitmap_with_entries({5: 1, 100: 2})
        glob = make_global_bitmap()
        glob[5] = 50
        glob[100] = 1
        assert count_new_bits(run, glob) == 0

    def test_some_new(self):
        """Mix of new and existing entries."""
        run = _make_bitmap_with_entries({0: 1, 5: 10, 100: 3})
        glob = make_global_bitmap()
        glob[5] = 1  # already seen
        assert count_new_bits(run, glob) == 2  # 0 and 100 are new

    def test_empty_run(self):
        """Run with all zeros → zero new bits."""
        run = bytes(A4_TOUCH_MAP_SIZE)
        glob = make_global_bitmap()
        glob[10] = 5
        assert count_new_bits(run, glob) == 0


class TestMergeIntoGlobal:
    def test_merge_into_empty(self):
        """Merging into an empty global copies the run bitmap."""
        run = _make_bitmap_with_entries({0: 1, 100: 42})
        glob = make_global_bitmap()
        merge_into_global(run, glob)
        assert glob[0] == 1
        assert glob[100] == 42
        assert glob[50] == 0

    def test_merge_keeps_max(self):
        """Global should keep the max of each bucket."""
        run = _make_bitmap_with_entries({5: 10, 100: 3})
        glob = make_global_bitmap()
        glob[5] = 50   # global is higher
        glob[100] = 1  # run is higher
        merge_into_global(run, glob)
        assert glob[5] == 50   # kept global's value (higher)
        assert glob[100] == 3  # took run's value (higher)

    def test_merge_does_not_decrease(self):
        """Merging a run with zeros should not decrease global."""
        glob = make_global_bitmap()
        glob[0] = 100
        glob[999] = 255
        run = bytes(A4_TOUCH_MAP_SIZE)  # all zeros
        merge_into_global(run, glob)
        assert glob[0] == 100
        assert glob[999] == 255


class TestHelpers:
    def test_distinct_touched(self):
        bm = _make_bitmap_with_entries({0: 1, 5: 10, 100: 255})
        assert distinct_touched(bm) == 3

    def test_total_touches(self):
        bm = _make_bitmap_with_entries({0: 1, 5: 10, 100: 200})
        assert total_touches(bm) == 211

    def test_make_global_bitmap(self):
        glob = make_global_bitmap()
        assert len(glob) == A4_TOUCH_MAP_SIZE
        assert all(b == 0 for b in glob)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
