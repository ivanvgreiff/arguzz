# PHASE 7D INC 3c — B7 PHASE δ (CLOSURE): IDENTIFY THE OCTORAND RACE

**Owner**: Composer
**Inputs**: `PHASE_7D_INC3_FINDINGS.md` §5–6 (Opus diagnostic + Phase δ plan), `PHASE_7D_INC3B_REPORT.md` (Inc 3b empirical baseline), this work order
**Outputs**: `PHASE_7D_INC3C_REPORT.md` + JSON artifacts under `a4/audits/audit_output/inc3c/`
**Goal**: Capture the exact `(loc, major, minor)` constraint context whose touch bit racily flips on octorand, so Opus can trace it back through witgen and identify the race mechanism. Once this lands, Phase 7d architecture audit closes and we proceed to Phase 8.
**Length expectation**: ~30–45 min wall-time on POS + ~30 min of parsing.

---

## 0a — CRITICAL FIXES BEFORE RE-DISPATCHING (read this first if resuming)

The first Phase δ attempt (3/10 runs done before disconnect) had TWO bugs that prevent it from producing usable data. **Both have been fixed on Opus's side** as of Jun 11 17:30 UTC; you must rebuild the bundle to pick them up.

### Fix 1 — verbose-passthrough patch in `a4/core/executor.py`

The host emits `<a4_touch_verbose>[...]</a4_touch_verbose>` to its stdout when
`A4_COVERAGE_TOUCH_VERBOSE=1`. The fuzzer was calling `subprocess.run(...,
capture_output=True)` which buffers host stdout into a local variable and never
re-emits it. So `run_campaign_pos.sh`'s `tee` only sees the fuzzer's own
print-statements, NOT the host's verbose tags. End result: every Inc 3b/3c
campaign.log had **zero** `<a4_touch_verbose>` tags even though the host was
emitting them. That's why your `octoaA` log had `A4_COVERAGE_TOUCH_VERBOSE=1`
in the launcher line but no actual tags downstream — not a host bug, a fuzzer
plumbing bug.

Opus patched `a4/core/executor.py::run_a4_mutation` to re-print verbose tags
to stdout when the env-var is set. Verified locally with a 3-mut zoned smoke:
3 mutations → 3 `<a4_touch_verbose>` tags + 3 `<a4_accum_touch_verbose>` tags
in the captured log. **You MUST pull the latest main on Coinbase and rebuild
the bundle before re-running.** The new bundle's `prepare_bundle.sh` output
should pack the patched `executor.py`.

The dispatcher script (`a4/pos/run_inc3c_phase_delta.sh`) now has a sanity
check that fails fast if the bundle's `executor.py` doesn't contain the patch.

### Fix 2 — `--allocation-duration 0` + pre-reservation

The first attempt used `--allocation-duration 60` on every dispatch. That
**creates a new calendar entry per dispatch**. The 2-future-entries cap (POS
playbook §12.28) bites the moment three dispatches overlap. Running flare-pair
and octorand-pair in parallel + a second octorand allocate = bang, quota.

The fix is the pre-reservation pattern (playbook §12.37): the user
pre-reserves ALL needed nodes as ONE multi-node calendar entry via the web
calendar UI. The dispatcher then uses `--allocation-duration 0` (= claim the
existing reservation, don't create a new entry). Opus updated the script
accordingly; you don't need to edit anything, just run it.

**This unlocks proper parallelism.** Octorand and flare can run concurrently
(different physical nodes, same calendar entry). On octorand itself the runs
are still sequential because there's only one physical octorand box, but the
flare control pair is "free" (parallel time on a different node).

### What the user needs to do (one-time, before kicking you off)

1. Open the POS web calendar UI.
2. Create **one** calendar entry covering BOTH `octorand` AND `flare`, duration **60 minutes**, starting now.
   - (For the SPREAD plan in §2.4 below: include `opulous` and `meld` in the same multi-node entry.)
3. Confirm `pos calendar list` shows that single entry covering all nodes.

That's it. The 2-future-entries cap is on calendar entries, NOT on nodes, so one entry covering N nodes counts as 1.

---

## 0 — Pre-flight context (READ FIRST)

What Inc 3b established (see `PHASE_7D_INC3_FINDINGS.md` §5):
- B1 is **CLOSED** (1000/1000 PASS, patched host `c2e77443…`). Do not re-run B1.
- B7 is **sharpened**:
  - `flare` is internally deterministic (intra-pair: 0 reward diffs).
  - `octorand` is internally **NON-deterministic** (intra-pair: 1 reward diff at mut id=25, kind=`PRE_EXEC_REG_MOD`, step=2296, `delta_T` flip 1↔0).
  - All library SHAs and host SHA match across nodes (`lib_shas.txt`), so it isn't a binary / shared-object drift issue.
  - Microcode differs (flare `0xa10113e` vs octorand `0xa101116`) — a candidate plausibility-multiplier, not a direct cause.
- Inc 3b could not capture the divergent `(loc, major, minor)` because the **pre-fix host did not contain the `<a4_touch_verbose>` emission code** (added in a later commit). This is now resolved: we'll use the patched host (which does emit verbose).

**The critical insight on host choice (see §6.2 of FINDINGS doc)**: the patched host `c2e77443` has the B1 fix PLUS the verbose emission. Because the B7 races we've observed are on `PRE_EXEC_REG_MOD step=2296` and `MEM_VAL_MOD step=3780` (neither is INSTR_TYPE_MOD, neither is at a boundary, neither exercises byte_addr printing), my B1 fix CANNOT have affected the race reproduction. Using the patched host is safe and saves a rebuild.

---

## 1 — Pull latest main + rebuild bundle (~5 min)

You must rebuild because of the new `executor.py` verbose-passthrough patch
(see §0a Fix 1).

```bash
# On Coinbase
cd ~/arguzz
git pull origin main           # picks up a4/core/executor.py + run_inc3c_phase_delta.sh
HOST_SHA=$(sha256sum workspace/output/target/release/risc0-host | awk '{print $1}')
echo "expected: c2e77443275372846a73a9d1d13d340e8068ff70961d8e8b97fff479bb63b332"
echo "actual:   $HOST_SHA"

# Gotcha: prepare_bundle.sh checks the host sha against
# ~/arguzz_backups/risc0-host.FIXED.sha256, which still records the pre-fix
# sha (6873e588…). Update or use --skip-host-sha.
echo "$HOST_SHA" > ~/arguzz_backups/risc0-host.FIXED.sha256

bash a4/pos/prepare_bundle.sh --allow-dirty
export INC3C_BUNDLE=$(ls -t /root/arguzz/bundles/*.tar.gz | head -1)
echo "INC3C_BUNDLE=$INC3C_BUNDLE"
```

**Sanity gate** (the dispatcher script also enforces this — these are just
for you to verify by eye):

```bash
# Host sha matches patched binary
tar -xOf "$INC3C_BUNDLE" a4_campaign/bundle.json | grep host_sha256
# Expect: ...c2e77443275372846a73a9d1d13d340e8068ff70961d8e8b97fff479bb63b332...

# Verbose-passthrough patch present in bundled fuzzer
tar -xOf "$INC3C_BUNDLE" a4_campaign/repo/a4/core/executor.py \
  | grep -A1 "A4_COVERAGE_TOUCH_VERBOSE.*== .1."
# Expect a `for tag in _A4_VERBOSE_RE.findall(combined):` line
```

If either gate fails, STOP and ping Opus.

---

## 2 — Capture phase: parallel multi-node dispatch with pre-reservation

### 2.1 Layout — DEFAULT plan (covered by `bash a4/pos/run_inc3c_phase_delta.sh`)

**Note on `n`**: keep `n=50` per run so the existing `a4/audits/B7_seed_reproducibility.py` matchers work without modification (the audit script defaults `B7_N = 50` in the DB pattern). To compensate for the smaller per-pair sample, use **4 octorand pairs** instead of 3.

Ten runs total. **Two physical nodes** (octorand sequential + flare sequential) running in PARALLEL under ONE pre-reserved multi-node calendar entry. Octorand dominates wall-time (~40 min); flare control finishes in ~10 min.

| Pair | Node | n | Seed | Suffix | Purpose |
|---|---|---|---|---|---|
| α-octo-A | octorand | 50 | 999 | octoaA | Primary race capture |
| α-octo-B | octorand | 50 | 999 | octoaB | Pair-mate of αA |
| β-octo-A | octorand | 50 | 999 | octobA | Reproducibility check (same seed/n as α) |
| β-octo-B | octorand | 50 | 999 | octobB | Pair-mate of βA |
| γ-octo-A | octorand | 50 | 1000 | octogA | Seed-sensitivity check |
| γ-octo-B | octorand | 50 | 1000 | octogB | Pair-mate of γA |
| δ-octo-A | octorand | 50 | 1001 | octodA | Second seed-sensitivity check |
| δ-octo-B | octorand | 50 | 1001 | octodB | Pair-mate of δA |
| ctrl-flare-A | flare | 50 | 999 | flareCtrlA | Negative control (no race expected) |
| ctrl-flare-B | flare | 50 | 999 | flareCtrlB | Pair-mate of ctrl-A |

(Use ASCII suffixes like `octoaA` rather than `octoαA` — Greek letters in filenames are asking for trouble. The α/β/γ/δ labels in the table are just for cross-reference in the report.)

At ~1 racy mutation per 50 muts on octorand (Inc 3b rate), 4 octorand pairs × 50 muts = ~4 racy bits expected. If we get 0 racy bits across all 4 octo pairs, the race rate may be lower than 1/50 (or the patched host accidentally fixed it — flagged by §3 cross-check). If we get many racy bits, all the better for clustering.

The flare pair is a negative control: confirms the patched host doesn't introduce a NEW race on flare.

### 2.2 Pre-reservation needed for the DEFAULT plan

User pre-reserves ONE calendar entry covering BOTH `octorand` AND `flare` for **60 minutes** via the web calendar UI. (60 min is enough: octorand sequence is ~35–40 min, flare is ~10 min, both finish under the same entry.)

### 2.3 Execute the DEFAULT plan

```bash
# On Coinbase, in tmux (always tmux for anything > 5 min):
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz
git pull origin main  # ensure latest dispatcher script
export INC3C_BUNDLE=$(ls -t ~/arguzz/bundles/*.tar.gz | head -1)
bash a4/pos/run_inc3c_phase_delta.sh
```

If the script's pre-check fails on bundle host SHA or verbose-patch presence, redo §1.

### 2.4 Layout — OPTIONAL SPREAD plan (~20 min wall, +bonus Tier S data)

If you want max parallelism AND bonus data on whether the race is octorand-specific vs Tier S-wide, run the SPREAD plan instead. It uses 4 nodes:

| Pair | Node | n | Seed | Suffix | Purpose |
|---|---|---|---|---|---|
| α | octorand | 50 | 999 | octoaA / octoaB | Primary octorand race capture |
| β | octorand | 50 | 999 | octobA / octobB | Octorand reproducibility |
| (γ' moved to opulous) | opulous | 50 | 1000 | opugA / opugB | Bonus: is the race Tier-S-wide? |
| (δ' moved to meld) | meld | 50 | 1001 | melddA / melddB | Bonus: another Tier S sibling |
| ctrl | flare | 50 | 999 | flareCtrlA / flareCtrlB | Negative control |

User pre-reservation must cover ALL 4 nodes: `octorand+opulous+meld+flare` as one calendar entry, 30 min suffices (max single-node sequence is 4 octorand runs ≈ 20 min).

```bash
SPREAD=1 bash a4/pos/run_inc3c_phase_delta.sh
```

The SPREAD plan trades 2 octorand pairs (γ, δ) for sibling-node data on opulous + meld. We get the same number of racy-bit candidates from octorand-pairs (2 pairs × ~1/50 = ~2 bits), plus 2 bonus pairs that tell us:
- If opulous + meld pairs show 0 diffs → race is octorand-specific (microcode revision)
- If they show diffs → race is Tier S-wide (EPYC 9354 microarch behaviour)

That's strictly more information than the DEFAULT plan, at roughly half the wall time. Recommended unless user prefers the simpler DEFAULT.

### 2.6 Pull results back

Each campaign run writes `$RESULTS/campaign.log` (with all `<a4_touch_verbose>` blocks) plus a SQLite `*.db`. Pull both back to `a4/audits/audit_output/inc3c/` keeping the suffix-bearing names that `run_campaign_pos.sh` produces:

```
inc3c/
  pos_inc3c_phase_delta_zoned_seed999_n50_octoaA.db,  .log
  pos_inc3c_phase_delta_zoned_seed999_n50_octoaB.db,  .log
  pos_inc3c_phase_delta_zoned_seed999_n50_octobA.db,  .log
  pos_inc3c_phase_delta_zoned_seed999_n50_octobB.db,  .log
  pos_inc3c_phase_delta_zoned_seed1000_n50_octogA.db, .log
  pos_inc3c_phase_delta_zoned_seed1000_n50_octogB.db, .log
  pos_inc3c_phase_delta_zoned_seed1001_n50_octodA.db, .log
  pos_inc3c_phase_delta_zoned_seed1001_n50_octodB.db, .log
  pos_inc3c_phase_delta_zoned_seed999_n50_flareCtrlA.db, .log
  pos_inc3c_phase_delta_zoned_seed999_n50_flareCtrlB.db, .log
  fingerprint/{octorand,flare}/{env,cpuinfo,uname,lib_shas}.txt   # same as Inc 3b
```

If the log files are >100 MB each (verbose makes them big), gzip them but keep originals.

---

## 3 — Parse phase: identify the racy `(loc, major, minor)`

For each pair, do TWO things:

### 3.1 Reward-row diff (which mutations diverged)

`B7_seed_reproducibility.py` already supports `--pair-suffix-a / --pair-suffix-b / --seed / --variant` (you added these in Inc 3b). Pattern matched is `*zoned_seed{seed}_n50_{suffix}.db`.

```bash
mkdir -p a4/audits/audit_output/inc3c/diffs

# Helper to keep things tidy
run_pair_diff () {
  local label="$1" seed="$2" suffix_a="$3" suffix_b="$4"
  python a4/audits/B7_seed_reproducibility.py \
    --smoke-dir a4/audits/audit_output/inc3c \
    --seed "$seed" \
    --pair-suffix-a "$suffix_a" --pair-suffix-b "$suffix_b" \
    --variant V1 \
    --output "a4/audits/audit_output/inc3c/diffs/B7_${label}.json"
}

# DEFAULT plan pairs:
run_pair_diff alpha     999  octoaA       octoaB
run_pair_diff beta      999  octobA       octobB
run_pair_diff gamma     1000 octogA       octogB
run_pair_diff delta     1001 octodA       octodB
run_pair_diff flareCtrl 999  flareCtrlA   flareCtrlB

# SPREAD plan pairs (substitute for gamma + delta if you ran SPREAD):
# run_pair_diff opulous 1000 opugA opugB
# run_pair_diff meld    1001 melddA melddB
```

Each `B7_<label>.json` will list the mutation IDs whose reward rows diverged. Expect ~0.5–1 per octorand pair (50 muts × ~1/50 rate), 0 for flare control. If opulous/meld show 0 each, that supports "octorand-specific microcode exposure"; >0 supports "Tier S microarch issue."

### 3.2 Verbose context diff per divergent mutation

For each mutation in `B7_<pair>.json["per_variant"]["V1"]["mutation_rewards_diff"]` (or `diff_mutation_ids` from the helper):

```bash
# Generic call: pair-A log vs pair-B log at a given mutation index
python a4/audits/B7_verbose_touch.py \
  --flare-log a4/audits/audit_output/inc3c/pos_inc3c_phase_delta_zoned_seed999_n50_octoaA.log \
  --octo-log  a4/audits/audit_output/inc3c/pos_inc3c_phase_delta_zoned_seed999_n50_octoaB.log \
  --mutation-id <id> \
  --output a4/audits/audit_output/inc3c/diffs/verbose_alpha_mut<id>.json
```

(The tool's flag names `--flare-log` / `--octo-log` are historical — it just symmetric-diffs the two logs at the given mutation index; pair-A vs pair-B works fine.)

Each `verbose_<pair>_mut<id>.json` reports `extra_on_octo` and `missing_on_octo`: the symmetric difference of touched constraint contexts between the two same-pair runs.

**Expected outcome for racy mutations**: `|extra| + |missing| == 1` (single bit flip). If `delta_T = +1` on the A side, `extra_on_octo` should have 1 entry; if `delta_T = −1`, `missing_on_octo` should have 1 entry.

### 3.3 Cross-mutation clustering

Aggregate across all racy mutations (across all 4 octorand pairs):

```bash
python3 - <<'PY' > a4/audits/audit_output/inc3c/diffs/racy_context_summary.json
import json, glob
from collections import Counter
contexts = Counter()
for p in glob.glob("a4/audits/audit_output/inc3c/diffs/verbose_*_mut*.json"):
    d = json.load(open(p))
    for c in d["extra_on_octo"] + d["missing_on_octo"]:
        contexts[(c["loc"], c["major"], c["minor"])] += 1
out = {
    "by_context": [{"loc": l, "major": m, "minor": n, "occurrences": cnt}
                   for (l, m, n), cnt in contexts.most_common()],
    "total_racy_bits": sum(contexts.values()),
    "n_pairs_analyzed": 4,
}
print(json.dumps(out, indent=2))
PY
```

**This is the key output for Opus**. If `by_context` has 1–2 entries with high `occurrences`, we've found the racy constraint family. If it has many entries with `occurrences=1` each, the race is more diffuse and we'll need a different approach.

---

## 4 — Deliverables

Write `a4/docs/cloud1/composer/PHASE_7D_INC3C_REPORT.md`:

```markdown
# Phase 7d Inc 3c — B7 Phase δ closure report

## Verdict
- Octorand intra-pair diff rate (3 pairs × 100 muts): X / 300 mutations.
- Flare control intra-pair diff rate: 0 / 100 mutations (expected).
- Racy constraint context(s): <list of (loc, major, minor) tuples with occurrences>
- Single-context race? YES / NO (if 1 context with ≥80% of occurrences, YES).

## Section 1 — Pair reward-diff summary
[table: pair | n | racy_mut_ids | racy_kinds | delta_T_signs]

## Section 2 — Verbose context analysis
[table: pair | mut_id | extra_count | missing_count | (loc,major,minor) of bit]

## Section 3 — Racy context clustering
[paste of racy_context_summary.json]

## Section 4 — Open items for Opus
[anything inconclusive — e.g., if multiple contexts cluster, list them all]
```

Plus:
- All `*.db` and `*.log` files under `a4/audits/audit_output/inc3c/`
- All `diffs/*.json` files
- `fingerprint/{octorand,flare}/*.txt` (same as Inc 3b)

---

## 5 — Don'ts

- DO NOT rebuild the host. The patched host `c2e77443…` already has verbose emission.
- DO NOT skip the flare control pair. It's our "the patched host doesn't add a new race" sanity gate. If flare control shows diffs, the analysis is invalid.
- DO NOT run on debian-bullseye. Inc 3b proved the host needs libstdc++ symbols only in trixie.
- DO NOT re-run B1, B2, B4. They are already closed.
- DO NOT delete or compress the campaign logs until Opus has parsed them — the `<a4_touch_verbose>` lines are the irreplaceable data.

---

## 6 — Optional hypothesis-confirmation (only if §3 lands a single context)

If the racy bit lives in ONE `(loc, major, minor)` family, Opus will trace it through the witgen code. If the diagnosis is "non-atomic `g_a4_touch_bitmap[idx]++` racing with some sub-step parallelism", Opus may ask you to:

1. Build a third host variant with `__sync_fetch_and_add(&bitmap[idx], 1)` (atomic increment).
2. Re-run ONE octorand pair (n=100) with the atomic host.
3. Confirm the race rate drops to 0 / 100.

If it does → mechanism confirmed by intervention. If it doesn't → the race is elsewhere (likely a parallel sub-routine in stepExec); Opus will design the next probe.

Don't do this proactively — wait for Opus's request after §4 lands.

---

## 7 — Timing budget

DEFAULT plan:

| Step | Wall-time | POS or Coinbase? |
|---|---|---|
| §1 pull + rebuild bundle | 5 min | Coinbase |
| User pre-reserves octorand+flare (web calendar) | 1 min | (user) |
| §2 dispatch (4 octo pairs + 1 flare pair, octo serial / flare parallel under ONE entry) | ~40 min | POS |
| Result pull | 5 min | POS → Coinbase |
| §3 parsing | 10 min | Coinbase |
| §4 report write | 15 min | Coinbase |
| **Total** | **~1h 15min** | |

SPREAD plan: same except §2 drops to ~20 min and total becomes ~55 min.

If any step is >2× this budget, ping Opus rather than burning more compute.
