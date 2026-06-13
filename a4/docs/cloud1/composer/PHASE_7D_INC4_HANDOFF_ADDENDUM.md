# Phase 7d Inc 4 — Handoff addendum (2026-06-13 PM)

**From:** Opus
**To:** Composer
**Re:** Update after your B12 in1_100 self-correction; closing-out instructions

Good catch on the rc=255 cosmetic-failure read. You were right to verify rather than report failure. Three things to do based on what you found:

## 1. Pick up the patched `collect_inc4_b1_results.sh`

I just patched it (commit pending — pull from WSL when you next sync). The new version checks **two** sources per variant, in order:

1. **`/srv/testbed/results/<user>/a4/<campaign>/<timestamp>/<node>/b1_verify_results/<c>_<v>/B1_<v>.json`** (testbed upload mirror on coinbase) — persistent, survives node reset, this is what `pos_upload` writes to
2. **`/root/b1_verify_results/<c>_<v>/B1_<v>.json` on each node** via SSH — transient fallback for nodes not yet reset

`find ... | xargs stat | sort -nr | head -1` picks the newest matching path so re-dispatched campaigns don't collide. Validates the JSON has the right `per_variant.<V>` key and `total>0` before counting as collected. Prints `[pass/total]` and source per variant. Final block reports `X/5 variants collected` per campaign so a gap is impossible to miss.

This closes the exact gap that made you think V1/V2 were missing after flare's reset. **Use the patched script for the B11 collection too.**

To pull:

```bash
# On coinbase, from WSL push:
rsync -av -e 'ssh -p 10022' \
    /root/arguzz/a4/pos/collect_inc4_b1_results.sh \
    ivgreiff@coinbase.net.in.tum.de:~/arguzz/a4/pos/
```

## 2. Yes, update `B12_multi_input.json` with the in1_100 disposition NOW

Don't wait for B11. Do it the same way I did for in1_1 — set:
- `per_input.in1_100_in4_100.B1` = `"PASS"`
- `per_input.in1_100_in4_100.B1_detail` = full disposition summary block (raw_pass_rate, net_pass_rate, category_counts, disposition_summary string, source path)
- `per_input.in1_100_in4_100.verdict` = `"PASS"`
- Top-level `verdict` = `"PASS"` (both per_input verdicts are now PASS)

Then commit `B12_multi_input.json` + the new disposition JSON in the same commit as the rest of Inc 4 closeout.

## 3. Stop polling — just complete the pipeline

Your 17:55 → 19:20 UTC scheduled check-in for B11 is fine. After that check:

- If B11 done: collect (patched script) → disposition → `B11_scale_stress.json` update → `PHASE_7D_INC4_REPORT.md` update to GREEN → free POS resources → commit. **Don't ping me between any of those steps.**
- If B11 not done: ONE more check at +30 min, then if still running ONE final check at +60 min. After 2h 15m total wall (handoff midpoint + 1× std-dev) something is wrong → abort, free resources, ping with diagnosis.

When you ping me, ping with:

> Inc 4 closeout complete. B11 disposition: net X/2500. All 3 audit JSONs updated. Final report at GREEN. POS allocation freed (-k). Commit landed at <sha>. Anomalies: <list or "none">.

Do **NOT** ping with partial status, intermediate findings, or "should I do X next?" — the handoff has the full sequence already. If you find something genuinely unexpected (not just "rc=255 again"), include it under "Anomalies" in the final ping.

---

## Why this addendum exists (lesson for both of us)

The B12 in1_100 collection gap was the **second** time we discovered that "rc=255 ≠ verifier failure" mid-investigation rather than at design time. The first was when the orchestrator silently died on in1_1. The patched orchestrator handles the rc=255 case; the patched collect script handles the "node reset after upload" case. Together they should make the next dispatch fully self-recovering.

For Inc 5: I'll draft a full work order covering every dispatch + collection + analysis + report-update step in one document, with the disposition / collect / orchestrator scripts referenced explicitly. Composer's job will be to execute the work order top-to-bottom and report ONCE at the end with the full artifact list. We're done with the back-and-forth pattern.

---

## ADDENDUM 2 (2026-06-13 PM, second wave) — mut235 ruling + closeout

You did the right thing pausing on V5 mut235 rather than silently waiving.
Adjudication:

**Ruling: extend the disposition, do NOT free-form waive.**

mut235 is the same architectural envelope as category B (MEM_VAL_MOD at the
ECALL last_step boundary), just with the mismatch surfacing on `old_word`
instead of `byte_addr`. The root cause is identical: ECALL's prepare/dispatch/
cleanup sub-stages cause the hook to capture the mem-txn state at a different
sub-stage than the config recorded. Whether the drift shows up in `byte_addr`,
`old_word`, or `old_byte` is incidental — they're all properties of the same
multi-stage mem-txn. D42 + D46 in the Pro decisions doc cover this envelope;
the original `B1_apply_disposition.py` regex was just under-specified.

**I just patched `B1_apply_disposition.py` to add B2 (and pre-registered D2 for
the symmetric step=0 case).** B2 has a mandatory safety guard:
`hook_payload.new_word == config.new_word`. The mutation effect must have
actually applied — only the prior-state readback is allowed to drift. If a
future failure has BOTH `old_word` AND `new_word` mismatching, it stays OTHER
and bubbles up for human review.

I also updated:
- `a4/docs/cloud1/composer/PHASE_7D_INC3D_B1_DISPOSITION.md` §9 (new section recording the Inc 4 extension)
- `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md` §12.1a (Pro-facing table now shows B2 + D2)

**Your closeout sequence (final):**

1. `git pull` (you'll get the B2 patch + doc updates)
2. Re-run disposition on B11:
   ```bash
   python3 -m a4.audits.B1_apply_disposition \
       --in-dir ~/arguzz_b1_collect/pos_inc4_b11_b1 \
       --output a4/audits/audit_output/B1_inc4_b11_disposition.json \
       --label "Inc4 B11 (2500 muts)"
   ```
   **Expected result: raw 2416/2500 → net 2500/2500 PASS** (mut235 now classified as B2).
   - If it still flags OTHER on mut235, the safety guard tripped — meaning new_word DOES mismatch — STOP and ping me with the full mut235 row from the V5 JSON. Don't proceed.
3. Update `B11_scale_stress.json` with the new disposition summary (per_input.B1 = "PASS", B1_detail block, top-level verdict = "PASS")
4. Update `PHASE_7D_INC4_REPORT.md` overall gate to **GREEN**
5. `pos allocations free -k <alloc_id>` (free ALL of them with `-k`)
6. Single commit covering everything (patches, doc updates, JSONs, dispo outputs)
7. ONE ping with the standard format: `"Inc 4 closeout complete. B11: 2500/2500 net PASS. All artifacts at <commit sha>. POS freed. Anomalies: 1× B2 (documented extension)."`

**That's it. No more rounds.**
