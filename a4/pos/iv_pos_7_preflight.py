#!/usr/bin/env python3
"""IV.POS.7 (Phase 8) — Pre-flight validator (batched-parallel model).

Runs before launching `auto_run_iv_pos_7.sh`. Validates that every input the
50-run campaign depends on is present, valid, and correctly versioned. The
~35-hour campaign cost makes this preflight high-leverage: catching a wrong
binary or missing manifest now saves a day or more.

Exit codes:
  0 = all checks PASS — campaign may launch
  1 = one or more checks FAIL — must NOT launch

Each check prints `[PASS]` or `[FAIL]` with a one-line reason. Final summary
line: `IV_POS_7 PREFLIGHT: PASS` or `IV_POS_7 PREFLIGHT: FAIL — N issues`.

Two run modes:
  - `local`   (default; run from WSL): validates everything that lives in WSL
              before bundle build (binary SHA, manifests, scripts, fuzzer
              imports for all 5 strategies).
  - `coinbase`: run on coinbase AFTER bundle is shipped. Adds POS-environment
              checks (poslib importable, nodes alive, calendar reservation
              active, bundle present).

Anything we know is required goes here. If a check is missing and the campaign
fails later, the right fix is to add a new check here.

See: PHASE_8_PLAN.md §3.7 (batched-parallel design).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Canonical Inc 3 baseline binary (frozen since Inc 3; used by all Phase 7d audits + Phase 8)
INC3_BASELINE_HOST_SHA = "6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444"
HOST_BIN = REPO_ROOT / "workspace/output/target/release/risc0-host"

# Manifests + scripts
MANIFEST_DIR = REPO_ROOT / "a4/pos/manifests/iv_pos_7"
# Tier-S: 7 batches (ts_b1..ts_b7), 4 jobs each = 28 jobs
EXPECTED_TIER_S_MANIFESTS = [
    MANIFEST_DIR / f"pos_iv_pos_7_ts_b{i}.json" for i in range(1, 8)
]
# Tier-A: 6 batches (ta_b1..ta_b6), 4 jobs each except last (2 jobs) = 22 jobs
EXPECTED_TIER_A_MANIFESTS = [
    MANIFEST_DIR / f"pos_iv_pos_7_ta_b{i}.json" for i in range(1, 7)
]
EXPECTED_ALL_BATCH_MANIFESTS = EXPECTED_TIER_S_MANIFESTS + EXPECTED_TIER_A_MANIFESTS
SMOKE_MANIFEST = MANIFEST_DIR / "pos_iv_pos_7_smoke.json"
DISPATCH_PLAN = MANIFEST_DIR / "_dispatch_plan.json"
ORCHESTRATOR = REPO_ROOT / "a4/pos/auto_run_iv_pos_7.sh"
DISPATCH_AUDIT = REPO_ROOT / "a4/pos/dispatch_audit.sh"
DISPATCH_POS = REPO_ROOT / "a4/pos/dispatch_pos.py"
PREPARE_BUNDLE = REPO_ROOT / "a4/pos/prepare_bundle.sh"
GENERATE_MANIFESTS = REPO_ROOT / "a4/pos/generate_iv_pos_7_manifests.py"

# All 5 IV.POS.7 strategies (must be supported by fuzzer + CLI)
IV_POS_7_STRATEGIES = [
    "zoned",                 # V1
    "kindUCB_zoned_v1",      # V2
    "kindUCB_zoned_v2_noQ",  # V3
    "kindTS_zoned_v2",       # V4
    "cTS_semantic_v2",       # V5
]

# Per-tier expected variant pinning (which strategies appear on each tier)
EXPECTED_TIER_S_VARIANTS = {
    "kindUCB_zoned_v1",      # V2 (pinned to flare across 7 seeds)
    "kindUCB_zoned_v2_noQ",  # V3 (pinned to octorand)
    "kindTS_zoned_v2",       # V4 (pinned to opulous)
    "cTS_semantic_v2",       # V5 (pinned to polynize)
}
EXPECTED_TIER_A_VARIANTS = set(IV_POS_7_STRATEGIES)  # V1 plus V2-V5 (3-seed tail)

# Canonical node order per tier — orchestrator MUST pass --nodes in this order
TIER_S_NODES = ["flare", "octorand", "opulous", "polynize"]
TIER_A_NODES = ["algofi", "gard", "goracle", "zone"]

EXPECTED_VARIANT_COUNT = 5
EXPECTED_SEEDS = list(range(1234, 1244))  # 10 seeds, 1234..1243
EXPECTED_N_PER_JOB = 6000
EXPECTED_TOTAL_JOBS = EXPECTED_VARIANT_COUNT * len(EXPECTED_SEEDS)  # 50

MIN_FREE_DISK_BYTES = 10 * 1024 ** 3  # 10 GB (50 DBs * ~80MB = ~4GB raw + slack)


# ---------- helpers ----------
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _print_result(ok: bool, label: str, msg: str) -> None:
    tag = "[PASS]" if ok else "[FAIL]"
    print(f"{tag} {label}: {msg}")


def _load_manifest(path: Path) -> dict:
    return json.loads(path.read_text())


# ---------- local checks (WSL pre-bundle) ----------
def _check_host_binary() -> Tuple[bool, str]:
    if not HOST_BIN.exists():
        return False, f"missing at {HOST_BIN}"
    sha = _sha256(HOST_BIN)
    if sha != INC3_BASELINE_HOST_SHA:
        return False, (
            f"SHA mismatch: got {sha[:16]}…, expected {INC3_BASELINE_HOST_SHA[:16]}…"
            f" — this is NOT the Inc 3 baseline binary. Phase 7d audits and Phase 8 "
            f"MUST use the same binary; rebuild from Inc 3 baseline commit."
        )
    return True, f"OK ({sha[:16]}…, Inc 3 baseline)"


def _check_bundle() -> Tuple[bool, str]:
    """coinbase-mode check: validate ~/a4_campaign_iv_pos_7.tar.gz exists and its
    bundle.json records the Inc 3 baseline host SHA. The bundle is what gets
    shipped to test nodes; coinbase itself doesn't run the binary directly, so
    we don't expect the WSL-style workspace/ path on coinbase.
    """
    home = Path(os.path.expanduser("~"))
    bundle = home / "a4_campaign_iv_pos_7.tar.gz"
    if not bundle.exists():
        return False, f"missing at {bundle} (rsync from WSL + symlink)"
    if bundle.is_symlink():
        target = bundle.resolve()
        if not target.exists():
            return False, f"symlink {bundle} -> {target} but target doesn't exist"
    # Extract bundle.json to inspect host SHA
    try:
        import tarfile
        with tarfile.open(bundle, "r:gz") as tf:
            for m in tf.getmembers():
                if m.name.endswith("bundle.json"):
                    f = tf.extractfile(m)
                    if f is None:
                        return False, f"could not read bundle.json from {bundle}"
                    info = json.loads(f.read().decode("utf-8"))
                    sha = info.get("host_sha256", "")
                    if sha != INC3_BASELINE_HOST_SHA:
                        return False, (
                            f"bundle.json host_sha256={sha[:16]}… != Inc 3 baseline "
                            f"{INC3_BASELINE_HOST_SHA[:16]}…"
                        )
                    return True, f"bundle OK; git={info.get('git_short')} host_sha={sha[:16]}…"
        return False, f"bundle.json not found inside {bundle}"
    except Exception as e:
        return False, f"could not inspect bundle: {e}"


def _check_batch_manifests() -> List[Tuple[bool, str]]:
    """Validate per-tier batch manifests: structure, strategies, telemetry, N."""
    results: List[Tuple[bool, str]] = []
    for m_path in EXPECTED_ALL_BATCH_MANIFESTS:
        if not m_path.exists():
            results.append((False, f"{m_path.name}: missing"))
            continue
        try:
            m = _load_manifest(m_path)
        except Exception as e:
            results.append((False, f"{m_path.name}: parse error {e}"))
            continue
        jobs = m.get("jobs", [])
        if not jobs:
            results.append((False, f"{m_path.name}: no jobs"))
            continue
        # All strategies must be known
        bad_strats = [j["strategy"] for j in jobs if j["strategy"] not in IV_POS_7_STRATEGIES]
        if bad_strats:
            results.append((False, f"{m_path.name}: unknown strategies {bad_strats}"))
            continue
        # N must be 6000 for all jobs
        ns = {j["n"] for j in jobs}
        if ns != {EXPECTED_N_PER_JOB}:
            results.append((False, f"{m_path.name}: expected N={EXPECTED_N_PER_JOB}, got {ns}"))
            continue
        # Telemetry must be 'full'
        tels = {j.get("telemetry_level") for j in jobs}
        if tels != {"full"}:
            results.append((False, f"{m_path.name}: telemetry_level must be 'full' for all jobs, got {tels}"))
            continue
        # Seeds must be in EXPECTED_SEEDS
        bad_seeds = [j["seed"] for j in jobs if j["seed"] not in EXPECTED_SEEDS]
        if bad_seeds:
            results.append((False, f"{m_path.name}: out-of-range seeds {bad_seeds}"))
            continue
        results.append((True, f"{m_path.name}: {len(jobs)} jobs, N=6000, telemetry=full, seeds OK"))
    return results


def _check_tier_pinning() -> List[Tuple[bool, str]]:
    """Each tier's manifests must (a) sum to expected job counts, (b) use only
    the expected set of strategies, (c) order jobs so pos[i] of round-robin
    lands on tier_nodes[i] (preserving variant pinning)."""
    results: List[Tuple[bool, str]] = []

    # Tier-S: every batch must have 4 jobs in [V2, V3, V4, V5] order
    # (matching TIER_S_NODES = [flare, octorand, opulous, polynize])
    expected_ts_order = ["kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ", "kindTS_zoned_v2", "cTS_semantic_v2"]
    ts_total = 0
    for m_path in EXPECTED_TIER_S_MANIFESTS:
        if not m_path.exists():
            continue
        m = _load_manifest(m_path)
        jobs = m["jobs"]
        ts_total += len(jobs)
        if len(jobs) != 4:
            results.append((False, f"{m_path.name}: Tier-S batches must have 4 jobs, got {len(jobs)}"))
            continue
        order = [j["strategy"] for j in jobs]
        if order != expected_ts_order:
            results.append((False, f"{m_path.name}: job order {order} != expected {expected_ts_order} (pinning broken)"))
            continue
    if ts_total != 28:
        results.append((False, f"Tier-S total jobs: {ts_total} != expected 28"))
    else:
        results.append((True, f"Tier-S: 7 batches x 4 jobs = 28 (V2->flare, V3->octorand, V4->opulous, V5->polynize)"))

    # Tier-A: total must be 22
    ta_total = sum(len(_load_manifest(p)["jobs"]) for p in EXPECTED_TIER_A_MANIFESTS if p.exists())
    if ta_total != 22:
        results.append((False, f"Tier-A total jobs: {ta_total} != expected 22"))
    else:
        results.append((True, f"Tier-A: 6 batches summing to 22 jobs (V1 x 10 + V2-V5 x 3 tail)"))

    return results


def _check_seeds_coverage() -> Tuple[bool, str]:
    """Each (variant, seed) pair must appear EXACTLY ONCE across all batch manifests."""
    pairs: dict[tuple[str, int], int] = {}
    for m_path in EXPECTED_ALL_BATCH_MANIFESTS:
        if not m_path.exists():
            return False, f"manifest missing: {m_path.name}"
        for j in _load_manifest(m_path)["jobs"]:
            key = (j["strategy"], j["seed"])
            pairs[key] = pairs.get(key, 0) + 1
    expected_pairs = {(s, sd) for s in IV_POS_7_STRATEGIES for sd in EXPECTED_SEEDS}
    actual_pairs = set(pairs.keys())
    duplicates = {k: c for k, c in pairs.items() if c > 1}
    missing = expected_pairs - actual_pairs
    extra = actual_pairs - expected_pairs
    if duplicates or missing or extra:
        return False, (
            f"(variant, seed) coverage broken: duplicates={duplicates}, missing={sorted(missing)[:5]}, extra={sorted(extra)[:5]}"
        )
    return True, f"all {EXPECTED_TOTAL_JOBS} (variant, seed) pairs present exactly once"


def _check_smoke_manifest() -> Tuple[bool, str]:
    if not SMOKE_MANIFEST.exists():
        return False, f"missing at {SMOKE_MANIFEST}"
    m = _load_manifest(SMOKE_MANIFEST)
    strats = {j["strategy"] for j in m["jobs"]}
    if strats != set(IV_POS_7_STRATEGIES):
        return False, f"smoke must exercise all 5 strats, got {strats}"
    if any(j["n"] > 50 for j in m["jobs"]):
        return False, f"smoke N too large (should be ~20 per job)"
    return True, f"smoke covers all 5 strats with N={list(j['n'] for j in m['jobs'])}"


def _check_dispatch_plan() -> Tuple[bool, str]:
    if not DISPATCH_PLAN.exists():
        return False, f"missing at {DISPATCH_PLAN}"
    try:
        plan = json.loads(DISPATCH_PLAN.read_text())
    except Exception as e:
        return False, f"parse error: {e}"
    if plan.get("total_jobs") != EXPECTED_TOTAL_JOBS:
        return False, f"plan total_jobs={plan.get('total_jobs')} != {EXPECTED_TOTAL_JOBS}"
    if plan.get("n_tier_s_batches") != 7 or plan.get("n_tier_a_batches") != 6:
        return False, f"plan batch counts wrong: tier_s={plan.get('n_tier_s_batches')}, tier_a={plan.get('n_tier_a_batches')}"
    if plan.get("tier_s_node_order") != TIER_S_NODES:
        return False, f"plan tier_s_node_order={plan.get('tier_s_node_order')} != {TIER_S_NODES}"
    if plan.get("tier_a_node_order") != TIER_A_NODES:
        return False, f"plan tier_a_node_order={plan.get('tier_a_node_order')} != {TIER_A_NODES}"
    return True, "dispatch_plan.json self-consistent (50 jobs, 7+6 batches, tier node orders match)"


def _check_strategy_imports() -> Tuple[bool, str]:
    """Ensure the fuzzer module accepts all 5 IV.POS.7 strategy names."""
    try:
        from a4.standalone.fuzzer import V2_BANDIT_STRATEGIES, STRATEGY_DISPLAY_NAMES
    except Exception as e:
        return False, f"import error: {e}"
    missing = []
    for s in IV_POS_7_STRATEGIES:
        if s not in STRATEGY_DISPLAY_NAMES:
            missing.append(s)
    if missing:
        return False, f"strategies missing from STRATEGY_DISPLAY_NAMES: {missing}"
    v2 = {"kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ", "kindTS_zoned_v2", "cTS_semantic_v2"}
    if v2 != set(V2_BANDIT_STRATEGIES):
        return False, f"V2_BANDIT_STRATEGIES mismatch: {V2_BANDIT_STRATEGIES} != {v2}"
    return True, "all 5 strategies wired in fuzzer.py (V2_BANDIT_STRATEGIES = 4 bandit variants)"


def _check_v2_modules() -> Tuple[bool, str]:
    required = [
        "a4.standalone.bandit_ts",
        "a4.standalone.reward_v2",
        "a4.standalone.compressed_global",
        "a4.standalone.compressed_global_extractor",
        "a4.standalone.semantic_arm_universe",
        "a4.standalone.semantic_zones",
        "a4.standalone.structural_cells",
        "a4.standalone.telemetry_v2",
        "a4.standalone.zone_classifier",
        "a4.standalone.fuzzer",
    ]
    broken: List[str] = []
    for mod in required:
        try:
            importlib.import_module(mod)
        except Exception as e:
            broken.append(f"{mod}: {e}")
    if broken:
        return False, f"import failures: {broken}"
    return True, f"all {len(required)} v2 modules import cleanly"


def _check_dispatcher_scripts() -> List[Tuple[bool, str]]:
    out = []
    for s in [DISPATCH_POS, PREPARE_BUNDLE, DISPATCH_AUDIT, GENERATE_MANIFESTS]:
        if not s.exists():
            out.append((False, f"{s.name}: missing"))
            continue
        size = s.stat().st_size
        out.append((True, f"{s.name}: present ({size} bytes)"))
    return out


def _check_orchestrator() -> Tuple[bool, str]:
    if not ORCHESTRATOR.exists():
        return False, f"missing at {ORCHESTRATOR}"
    if not os.access(ORCHESTRATOR, os.X_OK):
        return False, f"not executable; chmod +x {ORCHESTRATOR}"
    content = ORCHESTRATOR.read_text()
    if "--tier=" not in content:
        return False, f"orchestrator doesn't recognise --tier= flag — wrong/stale script"
    if "pos_iv_pos_7" not in content:
        return False, f"orchestrator does not reference IV.POS.7 manifests"
    return True, f"orchestrator present, executable, supports --tier=s/--tier=a"


def _check_disk_space() -> Tuple[bool, str]:
    free = shutil.disk_usage(REPO_ROOT).free
    if free < MIN_FREE_DISK_BYTES:
        return False, f"only {free / 1024**3:.1f} GB free; need {MIN_FREE_DISK_BYTES / 1024**3:.0f}+ GB"
    return True, f"{free / 1024**3:.1f} GB free in {REPO_ROOT}"


def _check_fast_tests() -> Tuple[bool, str]:
    """Run a fast subset of tests that touch v2 selectors + reward."""
    candidates = [
        REPO_ROOT / "a4/standalone/tests/test_bandit_ts.py",
        REPO_ROOT / "a4/standalone/tests/test_reward_v2.py",
    ]
    existing = [str(p.relative_to(REPO_ROOT)) for p in candidates if p.exists()]
    if not existing:
        return True, "no fast test files present in expected paths (skipping; not a launch blocker)"
    cmd = ["python", "-m", "pytest", "-x", "-q"] + existing
    try:
        r = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return False, "fast tests timed out (>180s)"
    except Exception as e:
        return False, f"could not run tests: {e}"
    if r.returncode != 0:
        tail = (r.stdout + r.stderr).splitlines()[-5:]
        return False, f"fast tests failed: {' / '.join(tail)}"
    return True, f"fast v2 tests pass ({len(existing)} file(s))"


# ---------- coinbase-only checks ----------
def _check_poslib() -> Tuple[bool, str]:
    try:
        import poslib  # noqa: F401
    except ImportError:
        return False, "poslib not importable — wrong host or POS venv not activated"
    return True, "poslib importable"


def _check_pos_nodes(node_names: List[str]) -> List[Tuple[bool, str]]:
    out: List[Tuple[bool, str]] = []
    try:
        r = subprocess.run(["pos", "nodes", "list"], capture_output=True, text=True, timeout=15)
        node_table = r.stdout
    except Exception as e:
        return [(False, f"`pos nodes list` failed: {e}")]
    for n in node_names:
        line = next((ln for ln in node_table.splitlines() if ln.startswith(n + " ") or ln.startswith(n + "\t")), None)
        if line is None:
            out.append((False, f"{n}: not in `pos nodes list` output"))
            continue
        if "ERR" in line.upper() or "FAIL" in line.upper():
            out.append((False, f"{n}: looks broken: {line.strip()}"))
            continue
        out.append((True, f"{n}: booted/OK"))
    return out


def _check_pos_reservation(node_names: List[str]) -> Tuple[bool, str]:
    user = os.environ.get("USER", "ivgreiff")
    try:
        r = subprocess.run(["pos", "calendar", "list", "-j"], capture_output=True, text=True, timeout=15)
        entries = json.loads(r.stdout)
    except Exception as e:
        return False, f"could not parse `pos calendar list -j`: {e}"
    mine = [e for e in entries if e.get("owner") == user]
    if not mine:
        return False, f"no calendar entries owned by {user}"
    for e in mine:
        e_nodes = set(e.get("nodes") or [])
        if set(node_names) <= e_nodes:
            return True, f"entry id={e.get('id')} covers all of {node_names} ({e.get('start_date')} -> {e.get('end_date')})"
    return False, (
        f"no single entry covers all of {node_names}. Owned: "
        + "; ".join(f"id={e.get('id')} nodes={e.get('nodes')}" for e in mine)
    )


# ---------- runners ----------
CheckFn = Callable[[], Tuple[bool, str]]
BatchCheckFn = Callable[[], List[Tuple[bool, str]]]


def run_local() -> int:
    print("== IV.POS.7 PREFLIGHT (local / WSL, batched-parallel model) ==\n")
    fails = 0

    singles: List[Tuple[str, CheckFn]] = [
        ("host_binary",         _check_host_binary),
        ("smoke_manifest",      _check_smoke_manifest),
        ("dispatch_plan",       _check_dispatch_plan),
        ("seeds_coverage",      _check_seeds_coverage),
        ("strategy_imports",    _check_strategy_imports),
        ("v2_modules",          _check_v2_modules),
        ("orchestrator",        _check_orchestrator),
        ("disk_space",          _check_disk_space),
        ("fast_tests",          _check_fast_tests),
    ]
    batches: List[Tuple[str, BatchCheckFn]] = [
        ("batch_manifests",     _check_batch_manifests),
        ("tier_pinning",        _check_tier_pinning),
        ("dispatcher_scripts",  _check_dispatcher_scripts),
    ]

    for label, fn in singles:
        try:
            ok, msg = fn()
        except Exception as e:
            ok, msg = False, f"check crashed: {e}"
        _print_result(ok, label, msg)
        fails += 0 if ok else 1
    for label, fn in batches:
        try:
            results = fn()
        except Exception as e:
            results = [(False, f"batch crashed: {e}")]
        for ok, msg in results:
            _print_result(ok, label, msg)
            fails += 0 if ok else 1

    print()
    if fails == 0:
        print("IV_POS_7 PREFLIGHT: PASS")
        return 0
    print(f"IV_POS_7 PREFLIGHT: FAIL — {fails} issue(s)")
    return 1


def run_coinbase(tier_s_nodes: List[str], tier_a_nodes: List[str]) -> int:
    all_nodes = tier_s_nodes + tier_a_nodes
    print(f"== IV.POS.7 PREFLIGHT (coinbase, batched-parallel) ==")
    print(f"   Tier-S nodes: {tier_s_nodes}")
    print(f"   Tier-A nodes: {tier_a_nodes}\n")
    fails = 0

    singles: List[Tuple[str, CheckFn]] = [
        ("bundle",                 _check_bundle),
        ("smoke_manifest",         _check_smoke_manifest),
        ("dispatch_plan",          _check_dispatch_plan),
        ("seeds_coverage",         _check_seeds_coverage),
        ("orchestrator",           _check_orchestrator),
        ("disk_space",             _check_disk_space),
        ("poslib_import",          _check_poslib),
        ("tier_s_reservation",     lambda: _check_pos_reservation(tier_s_nodes)),
        ("tier_a_reservation",     lambda: _check_pos_reservation(tier_a_nodes)),
    ]
    batches: List[Tuple[str, BatchCheckFn]] = [
        ("batch_manifests",        _check_batch_manifests),
        ("tier_pinning",           _check_tier_pinning),
        ("dispatcher_scripts",     _check_dispatcher_scripts),
        ("pos_nodes",              lambda: _check_pos_nodes(all_nodes)),
    ]

    for label, fn in singles:
        try:
            ok, msg = fn()
        except Exception as e:
            ok, msg = False, f"check crashed: {e}"
        _print_result(ok, label, msg)
        fails += 0 if ok else 1
    for label, fn in batches:
        try:
            results = fn()
        except Exception as e:
            results = [(False, f"batch crashed: {e}")]
        for ok, msg in results:
            _print_result(ok, label, msg)
            fails += 0 if ok else 1

    print()
    if fails == 0:
        print("IV_POS_7 PREFLIGHT: PASS")
        return 0
    print(f"IV_POS_7 PREFLIGHT: FAIL — {fails} issue(s)")
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--mode",
        choices=["local", "coinbase"],
        default="local",
        help="Where this is running. local = WSL pre-bundle; coinbase = POS mgmt node post-bundle.",
    )
    p.add_argument(
        "--tier-s-nodes",
        nargs="*",
        default=TIER_S_NODES,
        help=f"Coinbase-mode only: the Tier-S nodes (default {TIER_S_NODES})",
    )
    p.add_argument(
        "--tier-a-nodes",
        nargs="*",
        default=TIER_A_NODES,
        help=f"Coinbase-mode only: the Tier-A nodes (default {TIER_A_NODES})",
    )
    args = p.parse_args()
    if args.mode == "local":
        return run_local()
    return run_coinbase(args.tier_s_nodes, args.tier_a_nodes)


if __name__ == "__main__":
    sys.exit(main())
