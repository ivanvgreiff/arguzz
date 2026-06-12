# PHASE 7D INC 3b — VERIFICATION OF B1 FIX + B7 INVESTIGATION PHASE γ

**Owner**: Composer
**Inputs**: `PHASE_7D_INC3_FINDINGS.md` (Opus's diagnostic), this work order
**Outputs**: `PHASE_7D_INC3B_REPORT.md` + JSON artifacts under `a4/audits/audit_output/inc3b/`
**Goal**: Empirically confirm that Opus's B1 Option B fix achieves 1000/1000 PASS, and collect the empirical evidence needed to mechanism-hunt the B7 1-bit divergence.
**Length expectation**: 4-8 hours of compute (mostly POS) + 1-2 hours of analysis.

---

## 0 — Pre-flight context (READ FIRST)

Opus has finished the B1 diagnostic and implemented a 3-edit fix:

| Edit | File | Lines | Nature |
|---|---|---|---|
| #1 | `a4/standalone/mutations/instr_type_mod.py` | `get_targets_at_step` body | Python: pick FIRST cycle at step with `major ∈ {0..6}` instead of `data.get_cycle(step)` (which returned LAST due to dict-comp last-wins) |
| #2 | `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | INSTR_TYPE_MOD hook (~line 268-281) | Rust: add `&& cycle.major <= 6` to the iteration filter, mirroring INSTR_WORD_MOD |
| #3 | `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | MEM_VAL_MOD logging (lines 574, 577) | Rust: cast `txn.addr * 4` → `(txn.addr as u64) * 4` to avoid u32 wrap on high addresses |

The host binary has been rebuilt locally at `workspace/output/target/release/risc0-host` after these edits.

Opus has finished B7 Phase α (audit code clean) and Phase β (local 1600-context universe enumerated). The B7 mystery is still that octorand produces a different `delta_T` than flare/local on a single mutation in V1 (and 3 other variant/mutation pairs). The next move (Phase γ) is POS-side and is the focus of §B below.

The B2 / B4 audits are PASS and don't need re-running.

---

## A — B1 verification: confirm Option B achieves 100% PASS

### A.1 — Local sanity (10 min)

On Coinbase login (or your local), run Opus's verifier on a sample of boundary-step mutations to confirm the fix works at all before committing to a full campaign re-run.

```bash
cd ~/arguzz
# Use the local rebuilt host (or rebuild yourself if you cloned)
HOST=workspace/output/target/release/risc0-host
# Use one of the existing B1 DBs (any will do; mutations are seed-reproducible)
DB=a4/audits/audit_output/inc3_b1/pos_audit_b1_zoned_seed999_n200.db
mkdir -p out_inc3b/sanity
# Run the verifier on a stratified sample (per_kind=10 will catch all boundary kinds)
python a4/tools/verify_mutation_semantics.py \
  --db $DB --host $HOST \
  --output out_inc3b/sanity/sanity_V1.json \
  --per-kind 10
# expected: 0 failures (was 1 in original B1_V1.json)
```

If this is not clean, STOP and ping Opus before running anything on POS — something in the fix is wrong and a full POS re-run would burn compute for nothing.

### A.2 — POS B1 strict-verifier re-run (1-2 hours of POS)

Re-run B1 over all 5 variants on POS with the patched host (the patched workspace must be in your campaign image). Re-use the existing B1 mutation DBs as input — only the verifier output JSONs need to be regenerated.

```bash
# Per-variant POS dispatch
for vk in V1 V2 V3 V4 V5; do
  python a4/tools/verify_mutation_semantics.py \
    --db a4/audits/audit_output/inc3_b1/pos_audit_b1_<selector>_seed999_n200.db \
    --host /path/to/patched/risc0-host \
    --output out_inc3b/B1_${vk}.json \
    --per-kind 200   # cover all 200 mutations
done
```

Variant ↔ DB-selector mapping:
- V1 = zoned, V2 = kindUCB_zoned_v1, V3 = kindUCB_zoned_v2_noQ, V4 = kindTS_zoned_v2, V5 = cTS_semantic_v2

**Pass criterion**: every `B1_V*.json` reports `0 failures` and `1000 samples` (200 × 5 variants).

**If still failing**: extract `failures.json` listing all `(kind, step, txn_idx, detail)` and ping Opus. There may be additional boundary kinds (e.g., LOAD_VAL_MOD reg-file edge cases) we didn't catch.

### A.3 — Smoke ensemble: confirm reward fields untouched

The B1 fix only changes:
- Which cycle gets the `major/minor` mutation for INSTR_TYPE_MOD at boundary steps (3% of selections).
- The printed `byte_addr` for MEM_VAL_MOD on high-address txns (logging only).

It must NOT affect any reward field for mid-trace mutations (the 97%). Confirm with a paired determinism check:

```bash
# Run fuzzer twice with same seed on both pre-fix and post-fix hosts, compare DBs
python -m a4.standalone.cli fuzz --selector zoned --seed 12345 --num 100 \
  --host pre_fix_host  --db /tmp/pre.db
python -m a4.standalone.cli fuzz --selector zoned --seed 12345 --num 100 \
  --host post_fix_host --db /tmp/post.db
python -c "
import sqlite3
ca = sqlite3.connect('/tmp/pre.db'); cb = sqlite3.connect('/tmp/post.db')
ra = ca.execute('SELECT mutation_id, kind, step, num_failures FROM mutations ORDER BY 1').fetchall()
rb = cb.execute('SELECT mutation_id, kind, step, num_failures FROM mutations ORDER BY 1').fetchall()
diff = sum(1 for a, b in zip(ra, rb) if a != b)
print(f'mutations diff: {diff} / {len(ra)}')
"
```

**Expect**: small diff on INSTR_TYPE_MOD step=0 / step=lastCycle-1 mutations only (those NOW land on the correct cycle, so their reward signal is different). All other mutations identical.

If this shows large unrelated diffs, STOP — the fix broke something it shouldn't have.

---

## B — B7 Phase γ: stable-vs-racey + per-node fingerprint

Goal: pin down whether the 1-bit `delta_T` divergence is intra-node racy or inter-node stable, and collect the per-node fingerprint needed for Phase δ.

### B.1 — Add env / lib fingerprint to POS launcher

Edit `~/a4_campaign/scripts/run_campaign_pos.sh` (or wherever the POS launcher lives) so that AT THE START of every run it captures:

```bash
mkdir -p $RESULTS/fingerprint
env | sort > $RESULTS/fingerprint/env.txt
uname -a > $RESULTS/fingerprint/uname.txt
head -50 /proc/cpuinfo > $RESULTS/fingerprint/cpuinfo.txt
cat /proc/meminfo > $RESULTS/fingerprint/meminfo.txt
sha256sum \
  /lib/x86_64-linux-gnu/libstdc++.so.6 \
  /lib/x86_64-linux-gnu/libc.so.6 \
  /lib/x86_64-linux-gnu/libm.so.6 \
  $HOST_BIN > $RESULTS/fingerprint/lib_shas.txt
# Number of NUMA nodes / threads visible
numactl --show > $RESULTS/fingerprint/numa.txt 2>&1 || true
```

This is a one-time launcher edit and should be merged BEFORE any of B.2-B.4 runs.

### B.2 — Same-node paired runs

Dispatch B7 zoned (seed=999 n=50) FOUR times in two same-node pairs:
- 2 paired runs both pinned to `flare` (call them flareA, flareB)
- 2 paired runs both pinned to `octorand` (call them octoA, octoB)

Use `pos.commands.launch` with `nodes={"octorand": 1}` or `nodes={"flare": 1}` to force pinning.

The B7 audit script compares pair-A vs pair-B for each pair:

```bash
python a4/audits/B7_seed_reproducibility.py \
  --smoke-dir <dir-with-the-4-DBs> \
  --output out_inc3b/B7_intra_flare.json
# (rename / mv the appropriate pair into the smoke-dir before each run, OR
#  edit _resolve_b7_pair to accept the flare/octo naming)
```

**Possible outcomes**:

| flare-pair diffs | octo-pair diffs | Interpretation |
|---|---|---|
| 0 | 0 | Each node is internally deterministic; nodes disagree stably. Move to B.3 to look for env / NUMA / microcode reasons. |
| 0 | >0 | octorand has intra-node nondeterminism, flare doesn't. Move to B.4 to chase host races that surface on octorand specifically. |
| >0 | 0 | flare has intra-node nondeterminism. (Surprising — would suggest the original divergence direction was wrong.) |
| >0 | >0 | Both nodes are racy; just rare. Move to B.4. |

### B.3 — Cross-node verbose touch capture

Re-run B7 zoned ONCE on flare and ONCE on octorand with `A4_COVERAGE_TOUCH_VERBOSE=1` in env. This adds the full `<a4_touch_verbose>` line listing every `(loc, major, minor)` touched per host invocation. The on-disk DB doesn't store this — keep the campaign log file (typically `$RESULTS/<node>/<runid>.log`).

Then, for the mutation where the original divergence occurred (V1 mut 35), extract:

```python
# pseudo
flare_set = parse_verbose(flare_log, mutation_id=35)
octo_set  = parse_verbose(octo_log,  mutation_id=35)
extra_on_octo = octo_set - flare_set
missing_on_octo = flare_set - octo_set
```

If we see `|extra_on_octo| = 1` and `|missing_on_octo| = 0` (consistent with `delta_T = +1`), THE SINGLE `(loc, major, minor)` CONTEXT in `extra_on_octo` is the answer to "what bit differs". Save this context string in the report; that's the lead for Phase δ.

If the extra context corresponds to a constraint that depends on memory residues / lookup chains / system-controlled inputs, Phase δ becomes "audit that constraint family for non-determinism in the host's witgen". If the extra context is in user-instruction zir code, Phase δ is more surprising and we should escalate.

### B.4 — Inputs for Phase δ

Report MUST include:
1. Full diff between `flare:fingerprint/env.txt` and `octorand:fingerprint/env.txt`.
2. Full diff between `flare:fingerprint/cpuinfo.txt` and `octorand:fingerprint/cpuinfo.txt`.
3. Whether `lib_shas.txt` and `host_bin` sha256 match across nodes (expected: yes).
4. The `(loc, major, minor)` extra-bit context (or "could not isolate" with reason).
5. The same-node pair diff counts.

---

## C — Deliverables

Drop in `a4/docs/cloud1/composer/PHASE_7D_INC3B_REPORT.md`:

```markdown
# Phase 7d Inc 3b — Verification of B1 fix + B7 Phase γ

## Verdict
- B1 (post Option B): PASS / FAIL  (X/1000)
- B7 Phase γ outcome: <one of the table rows in §B.2>
- Recommended Phase δ direction: <text>

## A — B1 verifier results
[per-variant table: variant | failures | sample | details if any failure]
[reward-field smoke-ensemble result]

## B — B7 Phase γ results
[same-node intra-flare diff: N]
[same-node intra-octorand diff: N]
[cross-node verbose touch diff at V1 mut 35: <(loc,major,minor) extra/missing>]
[env diff highlights: <key lines>]
[cpuinfo diff highlights: <key lines>]
[lib/host shas match: yes/no]

## C — Open items for Opus
[anything you couldn't resolve]
```

Plus:
- `a4/audits/audit_output/inc3b/B1_V*.json` (5 files)
- `a4/audits/audit_output/inc3b/B7_intra_flare.json`, `B7_intra_octorand.json`, `B7_cross_node_verbose.json`
- `a4/audits/audit_output/inc3b/fingerprint/{flare,octorand}/env.txt,cpuinfo.txt,uname.txt,meminfo.txt,lib_shas.txt`
- Raw `*.log` from cross-node verbose runs (keep these — large but irreplaceable)

---

## D — Don'ts

- DO NOT regenerate the B1 mutation DBs from scratch. They are seed-reproducible — re-running them is just burning POS time. Use the existing DBs from `a4/audits/audit_output/inc3_b1/`.
- DO NOT modify the Python reward / fuzzer code while doing this work. The B1 fix is in 1 Python file + 1 Rust file only. Any other code change muddies the verification.
- DO NOT abandon the B7 work because it's "node-specific". The user has explicitly said "there must be something in our audit code or something in our architecture, or something in the pos code that is causing this". We need the verbose touch diff to know what to look at next.
- DO NOT skip B.3 (verbose capture) if B.2 shows zero same-node diffs. The cross-node bit-diff is the data we need; we can't progress without it.

---

## E — Plumbing notes from Inc 3 (avoid repeating)

- Use `~/b1_verify_work/out/` as the work area, like you did for the original B1 Phase B. That worked.
- If the per-variant POS dispatch is fiddly, you may run all 5 B1 verifications on Coinbase login (it works and is what we ended up doing last time). The verifier is single-mutation-per-host-call and not POS-bound.
- The B7 paired runs need to be dispatched via `pos.commands.launch` (not Coinbase) — they must run on POS test nodes to capture node-specific behavior. Use `nodes=` parameter to pin.
- If `A4_COVERAGE_TOUCH_VERBOSE=1` blows up host stdout (the verbose set is ~1600 contexts ≈ ~60 KB per run × 50 muts × 2 nodes ≈ 6 MB per run), that's fine — just don't lose the log files.
