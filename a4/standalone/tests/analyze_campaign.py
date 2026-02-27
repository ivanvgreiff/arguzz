#!/usr/bin/env python3
"""
Analyze a bandit campaign from terminal output.

Parses the terminal file from a --selector bandit campaign and produces
comprehensive statistics including reward trajectories, kind distributions,
bandit learning curves, and coverage growth.

Usage:
    python -m a4.standalone.tests.analyze_campaign <terminal_file>
"""

import re
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class RunRecord:
    num: int
    kind: str
    step: int
    n_fail: int
    time_ms: float
    outcome: str
    reward: float = 0.0
    T_new: float = 0.0
    F_new: float = 0.0
    F_rare: float = 0.0
    Z: int = 0
    Q: float = 0.0
    is_pilot: bool = False
    new_touch: int = 0
    new_coverage: int = 0
    d_fail: int = -1


PILOT_RE = re.compile(r'\[pilot (\d+)/(\d+)\] (\w+) @ step (\d+): (\d+)f')
BANDIT_RE = re.compile(
    r'\[(\d+)\] [^\s]+ (\w+) @ step (\d+): (\d+) failures?, (\d+)ms, outcome: (\w+)'
)
REWARD_RE = re.compile(
    r'r=([\d.]+)\s+T_new=([\d.]+)\s+F_new=([\d.]+)\s+F_rare=([\d.]+)\s+Z=(\d+)\s+Q=([\d.]+)(?:\s+df=(\d+))?'
)
TOUCH_RE = re.compile(r'\[([+-]\d+) touch\]')
NEWCOV_RE = re.compile(r'\[\+(\d+) new\]')
CALIB_RE = re.compile(r'Calibrated: .+=(.+), .+=(.+), .+=(\d+), .+=(.+)')


def parse_terminal(path: str) -> Tuple[List[RunRecord], dict]:
    meta = {}
    runs: List[RunRecord] = []
    pending_reward = None

    with open(path) as f:
        for line in f:
            line = line.rstrip()

            cm = CALIB_RE.search(line)
            if cm:
                meta['tau_T'] = float(cm.group(1))
                meta['tau_d'] = float(cm.group(2))
                meta['K_T_rare'] = int(cm.group(3))
                meta['gamma'] = float(cm.group(4))

            if 'budget remaining:' in line:
                m = re.search(r'budget remaining: (-?\d+)', line)
                if m:
                    meta['main_budget'] = int(m.group(1))

            pm = PILOT_RE.search(line)
            if pm:
                runs.append(RunRecord(
                    num=int(pm.group(1)), kind=pm.group(3), step=int(pm.group(4)),
                    n_fail=int(pm.group(5)), time_ms=0, outcome='PILOT',
                    is_pilot=True,
                ))
                continue

            bm = BANDIT_RE.search(line)
            if bm:
                rec = RunRecord(
                    num=int(bm.group(1)), kind=bm.group(2), step=int(bm.group(3)),
                    n_fail=int(bm.group(4)), time_ms=float(bm.group(5)),
                    outcome=bm.group(6),
                )
                tm = TOUCH_RE.search(line)
                if tm:
                    rec.new_touch = int(tm.group(1))
                nm = NEWCOV_RE.search(line)
                if nm:
                    rec.new_coverage = int(nm.group(1))
                runs.append(rec)
                pending_reward = rec
                continue

            if pending_reward is not None:
                rm = REWARD_RE.search(line)
                if rm:
                    pending_reward.reward = float(rm.group(1))
                    pending_reward.T_new = float(rm.group(2))
                    pending_reward.F_new = float(rm.group(3))
                    pending_reward.F_rare = float(rm.group(4))
                    pending_reward.Z = int(rm.group(5))
                    pending_reward.Q = float(rm.group(6))
                    if rm.group(7) is not None:
                        pending_reward.d_fail = int(rm.group(7))
                    pending_reward = None

    return runs, meta


def analyze(runs: List[RunRecord], meta: dict):
    pilot = [r for r in runs if r.is_pilot]
    bandit = [r for r in runs if not r.is_pilot]
    total = len(runs)

    print("=" * 75)
    print(f"CAMPAIGN ANALYSIS ({len(pilot)} pilot + {len(bandit)} bandit = {total} total)")
    print("=" * 75)

    if meta:
        print(f"\nCalibrated: tau_T={meta.get('tau_T')}, tau_d={meta.get('tau_d')}, "
              f"K_T_rare={meta.get('K_T_rare')}, gamma={meta.get('gamma')}")

    # --- Outcome breakdown ---
    outcomes = Counter(r.outcome for r in bandit)
    print(f"\n--- OUTCOMES (bandit only) ---")
    for o in ["REJECTED", "CRASH", "NO_EFFECT", "ACCEPTED"]:
        print(f"  {o}: {outcomes.get(o, 0)}")

    if not bandit:
        print("No bandit runs to analyze.")
        return

    # --- Per-kind reward distributions ---
    kinds = sorted(set(r.kind for r in bandit))
    print(f"\n--- REWARD BY KIND (bandit runs) ---")
    print(f"  {'Kind':25s} {'n':>4s} {'min':>6s} {'p25':>6s} {'med':>6s} {'mean':>6s} {'p75':>6s} {'max':>6s} {'std':>6s}")
    kind_stats = {}
    for kind in kinds:
        rewards = [r.reward for r in bandit if r.kind == kind]
        if len(rewards) >= 2:
            s = sorted(rewards)
            p25 = s[len(s)//4]
            p75 = s[3*len(s)//4]
            kind_stats[kind] = {
                'n': len(rewards), 'mean': statistics.mean(rewards),
                'med': statistics.median(rewards), 'std': statistics.stdev(rewards),
                'min': min(rewards), 'max': max(rewards),
            }
            print(f"  {kind:25s} {len(rewards):4d} {min(rewards):6.3f} {p25:6.3f} "
                  f"{statistics.median(rewards):6.3f} {statistics.mean(rewards):6.3f} "
                  f"{p75:6.3f} {max(rewards):6.3f} {statistics.stdev(rewards):6.3f}")
        elif len(rewards) == 1:
            print(f"  {kind:25s} {len(rewards):4d} {rewards[0]:6.3f}")

    all_rewards = [r.reward for r in bandit]
    print(f"\n  {'ALL':25s} {len(all_rewards):4d} {min(all_rewards):6.3f} "
          f"     {statistics.median(all_rewards):6.3f} {statistics.mean(all_rewards):6.3f} "
          f"     {max(all_rewards):6.3f} {statistics.stdev(all_rewards):6.3f}")

    # --- Component breakdown by kind ---
    print(f"\n--- REWARD COMPONENTS (mean per kind) ---")
    print(f"  {'Kind':25s} {'T_new':>6s} {'F_new':>6s} {'F_rare':>6s} {'Z_cnt':>5s} {'Q':>6s}")
    for kind in kinds:
        kr = [r for r in bandit if r.kind == kind]
        if kr:
            z_cnt = sum(r.Z for r in kr)
            print(f"  {kind:25s} {statistics.mean([r.T_new for r in kr]):6.3f} "
                  f"{statistics.mean([r.F_new for r in kr]):6.3f} "
                  f"{statistics.mean([r.F_rare for r in kr]):6.3f} "
                  f"{z_cnt:5d} "
                  f"{statistics.mean([r.Q for r in kr]):6.3f}")

    # --- Kind selection over time (learning curve) ---
    print(f"\n--- BANDIT LEARNING CURVE (kind distribution by phase) ---")
    n = len(bandit)
    phases = []
    chunk = max(1, n // 5)
    for i in range(0, n, chunk):
        phase_runs = bandit[i:i+chunk]
        phases.append((i, i+len(phase_runs)-1, phase_runs))

    print(f"  {'Phase':15s}", end="")
    for kind in kinds:
        print(f" {kind[:8]:>8s}", end="")
    print(f" {'mean_r':>7s}")

    for start, end, phase_runs in phases:
        kc = Counter(r.kind for r in phase_runs)
        mean_r = statistics.mean([r.reward for r in phase_runs]) if phase_runs else 0
        print(f"  runs {start+1:4d}-{end+1:4d} ", end="")
        for kind in kinds:
            pct = kc.get(kind, 0) / len(phase_runs) * 100 if phase_runs else 0
            print(f" {pct:7.1f}%", end="")
        print(f" {mean_r:7.3f}")

    # --- Reward trajectory (mean reward in sliding windows) ---
    print(f"\n--- REWARD TRAJECTORY (rolling mean, window=50) ---")
    W = min(50, max(10, n // 20))
    milestones = set()
    for m in [50, 100, 200, 500, 1000, 1500, 2000, 2500, 3000]:
        if m <= n:
            milestones.add(m)
    milestones.add(n)

    for i in sorted(milestones):
        window = bandit[max(0, i-W):i]
        if window:
            mean_r = statistics.mean([r.reward for r in window])
            z_in_window = sum(r.Z for r in window)
            print(f"  After run {i:5d}: rolling_mean={mean_r:.4f}  Z_events_in_window={z_in_window}")

    # --- Z-event analysis ---
    z_runs = [r for r in bandit if r.Z == 1]
    print(f"\n--- Z-EVENT ANALYSIS ---")
    print(f"Total Z events: {len(z_runs)} ({len(z_runs)/len(bandit)*100:.1f}% of bandit runs)")
    if z_runs:
        z_kinds = Counter(r.kind for r in z_runs)
        for k, c in z_kinds.most_common():
            total_k = sum(1 for r in bandit if r.kind == k)
            print(f"  {k}: {c} ({c/total_k*100:.1f}% of {total_k} runs)")
        z_rewards = [r.reward for r in z_runs]
        non_z = [r.reward for r in bandit if r.Z == 0 and r.outcome != "CRASH"]
        print(f"  Z reward: mean={statistics.mean(z_rewards):.3f}")
        if non_z:
            print(f"  Non-Z reward: mean={statistics.mean(non_z):.3f}")
            print(f"  Z/non-Z ratio: {statistics.mean(z_rewards)/statistics.mean(non_z):.1f}x")

    # --- Touch coverage growth ---
    print(f"\n--- TOUCH NOVELTY OVER TIME ---")
    cum_new_touch = 0
    touch_milestones = set([1, 10, 50, 100, 200, 500, 1000, 1500, 2000, 2500, 3000])
    for i, r in enumerate(bandit):
        cum_new_touch += r.new_touch
        if (i + 1) in touch_milestones and (i + 1) <= len(bandit):
            print(f"  After bandit run {i+1:5d}: cumulative new touch = {cum_new_touch}")

    # --- Failure novelty (F_new > 0 rate over time) ---
    print(f"\n--- FAILURE NOVELTY RATE OVER TIME ---")
    chunk_size = max(1, n // 10)
    for i in range(0, n, chunk_size):
        phase_runs = bandit[i:i+chunk_size]
        if phase_runs:
            f_new_rate = sum(1 for r in phase_runs if r.F_new > 0) / len(phase_runs)
            print(f"  Runs {i+1:5d}-{i+len(phase_runs):5d}: "
                  f"{f_new_rate*100:.1f}% have F_new > 0")

    # --- Cascade analysis ---
    cascade_runs = [r for r in bandit if r.n_fail > 10]
    print(f"\n--- CASCADE ANALYSIS ---")
    print(f"Runs with n_fail > 10: {len(cascade_runs)}")
    if cascade_runs:
        for r in sorted(cascade_runs, key=lambda x: -x.n_fail)[:5]:
            print(f"  Run {r.num} ({r.kind}): n_fail={r.n_fail} r={r.reward:.3f} Q={r.Q:.3f}")

    # --- Top 20 highest reward runs ---
    print(f"\n--- TOP 20 HIGHEST REWARD RUNS ---")
    for r in sorted(bandit, key=lambda x: -x.reward)[:20]:
        print(f"  Run {r.num:5d} ({r.kind:20s}) step={r.step:4d} r={r.reward:.3f} "
              f"T={r.T_new:.2f} F={r.F_new:.2f} Fr={r.F_rare:.2f} Z={r.Z} Q={r.Q:.2f}")

    # --- Kind selection frequency over time (exploitation signal) ---
    print(f"\n--- KIND EXPLOITATION SIGNAL ---")
    if n >= 100:
        early = bandit[:n//3]
        mid = bandit[n//3:2*n//3]
        late = bandit[2*n//3:]
        for label, phase in [("Early (1/3)", early), ("Mid (1/3)", mid), ("Late (1/3)", late)]:
            kc = Counter(r.kind for r in phase)
            top3 = kc.most_common(3)
            print(f"  {label}: {', '.join(f'{k}={c}({c/len(phase)*100:.0f}%)' for k,c in top3)}")

    print(f"\n--- SUMMARY STATISTICS ---")
    print(f"  Total runs: {total} (pilot={len(pilot)}, bandit={len(bandit)})")
    print(f"  Mean reward: {statistics.mean(all_rewards):.4f}")
    print(f"  Reward stdev: {statistics.stdev(all_rewards):.4f}")
    print(f"  Z events: {len(z_runs)} ({len(z_runs)/len(bandit)*100:.1f}%)")
    print(f"  Crashes: {outcomes.get('CRASH', 0)}")
    print(f"  Accepted (BUGS): {outcomes.get('ACCEPTED', 0)}")


def compute_cumulative_metrics(runs: List[RunRecord]) -> dict:
    """Compute per-run cumulative coverage metrics for A/B comparison plots."""
    cum_touch, cum_cov, cum_z, cum_crash = [], [], [], []
    t, c, z, cr = 0, 0, 0, 0
    for r in runs:
        t += r.new_touch
        c += r.new_coverage
        z += r.Z
        cr += 1 if r.outcome == "CRASH" else 0
        cum_touch.append(t)
        cum_cov.append(c)
        cum_z.append(z)
        cum_crash.append(cr)
    return {
        'cum_touch': cum_touch,
        'cum_coverage': cum_cov,
        'cum_Z': cum_z,
        'cum_crash': cum_crash,
    }


def compute_cumulative_from_db(db_path: str, campaign_id: int = None) -> dict:
    """Compute cumulative failure context and family curves from the SQLite DB.

    This is the authoritative source for C_fail(t) and C_family(t) because
    the terminal output may not have new_coverage for older bandit campaigns
    (the field was only wired into _run_bandit_mutation after Phase II.5a).

    Returns dict with lists:
      'cum_fail_contexts': cumulative distinct (constraint_loc, major, minor) tuples
      'cum_families': cumulative distinct constraint_loc families
    """
    import sqlite3
    db = sqlite3.connect(db_path)
    cur = db.cursor()

    if campaign_id is None:
        cur.execute('SELECT MAX(id) FROM campaigns')
        campaign_id = cur.fetchone()[0]

    cur.execute('SELECT id FROM mutations WHERE campaign_id = ? ORDER BY id', (campaign_id,))
    mutation_ids = [r[0] for r in cur.fetchall()]

    seen_contexts: set = set()
    seen_families: set = set()
    cum_contexts: list = []
    cum_families: list = []

    for mid in mutation_ids:
        cur.execute(
            'SELECT DISTINCT constraint_loc, major, minor FROM failures WHERE mutation_id = ?',
            (mid,),
        )
        for loc, major, minor in cur.fetchall():
            seen_contexts.add((loc, major, minor))
            seen_families.add(loc)
        cum_contexts.append(len(seen_contexts))
        cum_families.append(len(seen_families))

    db.close()
    return {
        'cum_fail_contexts': cum_contexts,
        'cum_families': cum_families,
    }


def compute_auc_normalized(curve: list) -> float:
    """Normalized AUC: sum(curve) / (n * final_value). Higher = faster discovery."""
    if not curve or curve[-1] == 0:
        return 0.0
    return sum(curve) / (len(curve) * curve[-1])


def compute_t80(curve: list) -> int:
    """Iterations to reach 80% of final value. Returns len(curve) if never reached."""
    if not curve or curve[-1] == 0:
        return len(curve)
    target = 0.8 * curve[-1]
    for i, v in enumerate(curve):
        if v >= target:
            return i + 1
    return len(curve)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m a4.standalone.tests.analyze_campaign <terminal_file>")
        sys.exit(1)
    runs, meta = parse_terminal(sys.argv[1])
    analyze(runs, meta)
