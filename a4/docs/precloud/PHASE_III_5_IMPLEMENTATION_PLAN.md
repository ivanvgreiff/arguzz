# Phase III.5 — Step-level cold-start fix — Implementation Plan

**Status:** PLAN (verification-only — implementation already shipped)  
**Created:** Jun 3, 2026 (evening session after III.2.5 resolution)  
**Depends on:** Phase II.5a (arm-level cold-start fix, same pattern)  
**Blocks:** Phase III.6, Phase IV.1 (cloud A/B)

## 1 — Surprise discovery: code already done

The master plan §9 calls for adding `step_m: Dict[Tuple[str,int], int]` to
`bandit.py` and using `step_m == 0` for step-level cold-start. **As of
this session's audit, the implementation is already present in
[`a4/standalone/bandit.py`](a4/standalone/bandit.py):**

| Master-plan requirement | Current code | Status |
|---|---|---|
| `step_m` raw counter, parallel to `step_N` | line 79 `self.step_m: Dict[Tuple[str, int], int] = {}` | ✓ DONE |
| Initialised to 0 per (kind, step) pair | line 87 `self.step_m[key] = 0` | ✓ DONE |
| Cold-start check uses `step_m == 0` | line 172 `cold_start_steps = [s for s in steps if self.step_m[(kind, s)] == 0]` | ✓ DONE |
| Incremented in `update`, never decayed | line 215 `self.step_m[step_key] += 1` | ✓ DONE |
| Stats counter `stats_coldstart_step` separate from `stats_ucb_step` | lines 91-92, 175, 185 | ✓ DONE |

The class docstring (lines 48-50) explicitly cites the fix:

> "Fixed per Pro_Report_9: forced exploration now uses raw pull counts
> (m) instead of decayed N, preventing the perpetual-exploration trap
> where UCB was dead code."

So this work landed silently (probably as part of the larger Pro_Report_9
follow-up after the bandit-16 architectural refactor). The work that
**remains for III.5** is therefore not implementation but
**verification + an acceptance test that captures the behaviour we want
to be sure of**.

## 2 — What this phase will actually do

1. **Confirm by reading**: re-verify that `bandit.py` `select()` and
   `update()` use `step_m` correctly under both decay and no-decay
   regimes. (Done in §1.)
2. **Add an acceptance test** that codifies the master-plan §9.4
   behaviour:
   - Pull (k, s_a) once with reward 0.0.
   - Pull (k, s_b) once with reward 1.0.
   - After both steps are no longer cold-start, the next selection
     prefers `s_b` (UCB-driven) when c_explore is small.
3. **Run a 50-mut bandit-16 smoke** confirming that the campaign-end
   summary line reads `Step selections: X coldstart + Y UCB` with
   $Y > 0$. (Acceptance criterion §9.5 of the master plan.)
4. **Document the finding** in PHASE_III_5_IMPLEMENTATION_REPORT.md so
   future audits don't redundantly re-investigate.

## 3 — Why the existing `test_step_cold_start` is necessary but not
   sufficient

[`a4/standalone/tests/test_bandit.py:241-280`](a4/standalone/tests/test_bandit.py)
verifies that **all** steps in a bucket are eventually cold-started.
That test answers "is the cold-start phase reachable for every step?"
but it does **not** answer "does the bandit then transition into
UCB-driven exploitation?" The latter is the failure mode Pro_Report_9
flagged: if the cold-start condition itself never resolves to "False",
the UCB branch is dead code. We need a test whose only way to pass is
for `step_m > 0` for every step in the bucket AND for the UCB branch
to run AND for it to prefer the high-reward step.

## 4 — New test (will live in `test_bandit.py`)

```python
def test_step_ucb_prefers_high_reward_after_coldstart(self):
    """
    III.5 acceptance: once both steps in an arm are out of cold-start
    (step_m > 0 for all), the next step selection is UCB-driven and
    favours the step with the higher reward.
    """
    universe = _small_universe(n_steps=300, budget=200)
    # Tiny c so UCB exploration term doesn't drown out the reward gap.
    params = _default_params(gamma=0.99, c_explore=0.01)
    scheduler = DiscountedUCBScheduler(universe, params, seed=42)

    # Find an arm with exactly 2+ steps.
    multi = [a for a in universe.available_arms
             if len(universe.steps_in_arm(*a)) >= 2]
    if not multi:
        pytest.skip("No arm with >= 2 steps")
    arm = multi[0]
    kind, bucket = arm
    steps = universe.steps_in_arm(kind, bucket)[:2]
    s_lo, s_hi = steps[0], steps[1]

    # Seed both steps so they're no longer cold-start.
    scheduler.update(kind, s_lo, 0.0)
    scheduler.update(kind, s_hi, 1.0)

    # Pin the arm to non-cold-start too so the arm-level path won't
    # decide for us.
    scheduler.arm_N[arm] = 5.0
    scheduler.arm_S[arm] = 2.5
    scheduler.arm_t[arm] = scheduler.t
    scheduler.arm_m[arm] = 5

    # Force the bandit to choose this arm at the arm-level by deflating
    # all other arms below the cold-start threshold. We do this by
    # making all OTHER arms non-cold-start with very negative mean
    # rewards. Easiest: set arm_m for all other arms to 1 and arm_S
    # to a large negative... but rewards must be in [0,1]. Instead
    # we just iterate until the chosen arm is `arm`, allowing the
    # arm-level coldstart of other arms to fire harmlessly first.
    chosen_steps = []
    for _ in range(50):
        k, s = scheduler.select()
        if (k, scheduler.universe.bucket_for_step(s)) == arm:
            chosen_steps.append(s)
            # Don't update — we want to keep observing the pure
            # selection bias.
            break

    assert chosen_steps, "Bandit never selected the test arm in 50 rounds"
    assert chosen_steps[-1] == s_hi, (
        f"Expected step {s_hi} (high reward) to be UCB-preferred over "
        f"{s_lo} (low reward), got {chosen_steps[-1]}"
    )
```

## 5 — Smoke command (manual, after unit tests pass)

```bash
rm -f /tmp/iii5_smoke.db
python3 -m a4.standalone.cli fuzz \
  --host /root/arguzz/workspace/output/target/release/risc0-host \
  --selector bandit --b-count 16 \
  --num 50 --seed 2026 \
  --db /tmp/iii5_smoke.db \
  -- --in1 5 --in4 10 \
  2>&1 | tee /tmp/iii5_smoke.log

grep -E '^Step selections' /tmp/iii5_smoke.log
```

Expected: `Step selections: X coldstart + Y UCB` with Y > 0.

## 6 — Acceptance criteria

| # | Criterion | Verification |
|---|---|---|
| 1 | `bandit.py` already uses `step_m == 0` for cold-start | §1 audit |
| 2 | New `test_step_ucb_prefers_high_reward_after_coldstart` passes | `pytest -v -k test_step_ucb_prefers_high_reward` |
| 3 | Existing `test_step_cold_start` still passes (no regression) | full pytest run |
| 4 | 50-mut bandit-16 smoke shows `Step selections: ... + Y UCB` with `Y > 0` | smoke grep |

## 7 — Risk + rollback

**Risk: VERY LOW.** No code change to product code — only a new test.
Rollback: delete the new test method.

## 8 — Estimated effort

- Audit + verify: DONE
- New test: 20 min
- Smoke: depends on whether the main 1000-mut bandit campaign is still
  running (waits at end of this session or piggybacks on that campaign's
  summary line, since it's also `bandit --b-count 16`).
- Report: 15 min

**Total: ~45 min, excluding smoke wait time.**

## 9 — In simple terms

The bandit chooses (mutation_kind, bucket) at the top level, then a
specific step inside that bucket. Both levels have a "cold-start" rule:
"if this thing has never been pulled, pull it first; only once we have
data, fall back to UCB." Earlier this year the step-level cold-start
condition was bugged — it used a decayed counter that never reached
zero, so the UCB branch was dead code (the bandit just randomly chose
steps forever). Pro_Report_9 flagged it; the fix has been in
`bandit.py` for some weeks. This phase just adds a regression test that
will fail loudly if anyone ever reverts the fix.
