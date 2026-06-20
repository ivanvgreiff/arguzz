"""D2.G — territory analysis, fault-propagation triage, Case A–E verdict."""

__all__ = [
    "D2F_VARIANTS",
    "discover_d2f_dbs",
    "parse_d2f_run_dir",
]

from .discover import D2F_VARIANTS, discover_d2f_dbs, parse_d2f_run_dir
