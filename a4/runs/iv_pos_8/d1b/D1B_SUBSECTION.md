# D1.B — CGC Coarsening Variants (Corrected Baseline)

> **INTERIM RESULTS — pending Ivan + Opus review before Pro-facing D1 deliverable fold-in.**

## TL;DR

We evaluated four CGC coarsening schemes on the 20-DB decay corpus, all on **corrected memory labeling** (Batch 1.6 `byte_addr` replay). Three headline findings:

1. **NFP-10 / corrected baseline:** Hook 3 field-priority bug mis-labeled ~53–59% of memory CGC regions in stored R2+D1.A DBs. Corrected replay restores production memory keys +28 on V5 s1234 (89→117).

2. **Saturation inversion (Pro §11):** Coarsened variants enter CGC asymptotic discovery **2–2.6× earlier** than production (mut ~1300–1800 vs ~3400). Local catalog saturation (`time_to_46`) lands at mut **~3100–3200**. Swapping production for `page_class` as L0 **shrinks** the post-local `g_new` window — opposite of Pro's intent.

3. **Thin headroom for ALL L0 candidates:** Even production's best-case post-local window is only +179 mut / ~39 keys (~**1 new CGC key per 70 mutations**). None of the four L0 schemes provide robust long-window discrimination; production is **least-bad**. D1.E must look **beyond L0 schema** for the real fix.

4. **decayexp AUC hint:** Barely-significant +2.5% AUC under coarsened variants (p≈0.048, n=5) — likely cold-start under K=50, not Pro's Stage-2 decay. D1.E forward-run with K≈200–300 needed.

**Recommendation:** Keep **corrected production log2** as D2 default. Reject L0 `page_class` swap. L1 semantic enrichment is an **open D1.E design question** (naive OR is redundant).

## Saturation overlay (visual)

![Absolute CGC curves vs local saturation](plots/d1b_saturation_overlay_v5.png)

![Normalized CGC curves](plots/d1b_saturation_overlay_v5_norm.png)

Black dashed line = mean local `time_to_46` (mut 3221). Dots = CGC asymptotic saturation per variant. Coarsened variants flatten toward their **lower ceilings** before mut 2000 — well left of local sat. Production crosses local sat still climbing. At mut 3221: production **~39 keys** remaining; coarsened **~18 keys** (~2× less absolute headroom despite similar % of final).

## Dataset

| Corpus variant | Seeds | N | Source |
|---|---:|---:|---|
| V5 (static) | 1234–1243 | 10 | R2 `iv_pos_7/dbs/` |
| V5-decayexp | 1234–1238 | 5 | `d1a/dbs/` |
| V5-decayepoch | 1234–1238 | 5 | same |

**Paired triplets:** 1234–1238 (n=5).

**Chain of custody:** Batches 1.5 + **1.5b** (`user_dynamic`, 0.0% `user_other`) + 1.6 completed before Batch 2 analysis.

## Headline numbers

### Hybrid `cgc_final` (V5 mean)

| CGC variant | All 10 V5 DBs | Paired 5 seeds |
|---|---:|---:|
| `production_log2_corrected` | **218.2** | 216.2 |
| `region_only` | 105.7 | 104.8 |
| `log4_explicit` | 120.6 | 119.8 |
| `page_class` | 110.7 | 109.8 |

Paired `cgc_final` decay tests: all p &gt; 0.05.

### Memory-channel (V5, all 10)

| Variant | Mean | Range |
|---|---:|---|
| `production_log2_corrected` | 122.0 | 116–128 |
| `region_only` | 9.5 | 9–10 |
| `log4_explicit` | 24.4 | 24–25 |
| `page_class` | 14.5 | 14–15 |

## Method

1. Batch 1.6 `byte_addr` fix + `replay_cgc_corrected.py`
2. Four variant maps via `d1b_cgc_maps.py` (§1.5 hybrid rule)
3. Metrics: final count, normalized AUC, time-to-percentile, saturation (100-mut bins)
4. Paired t-tests on seeds 1234–1238

## Findings

### Finding A — Corrected baseline (NFP-10)

Pre-fix stored CGC collapsed memory to `{user, zero_page}`. Post-replay V5 s1234: memory 89→117, hybrid 183→211. See `IV_POS_8_NOTES_FOR_PRO.md` §NFP-10.

### Finding B — Saturation inversion + thin headroom

| Variant | CGC sat. | Gap vs local (3221) | Remaining at mut 3221 |
|---|---:|---:|---:|
| `production_log2_corrected` | 3400 | +179 | ~39 (~1 key/70 mut) |
| `log4_explicit` | 1800 | −1421 | ~18 |
| `page_class` | 1300 | −1921 | ~18 |
| `region_only` | 1300 | −1921 | ~18 |

Pro's L0-swap hypothesis is **inverted** for coarsened variants. Production is least-bad but still thin. By mut ~3500 all L0 candidates are effectively saturated.

### Finding C — decayexp AUC (n=5 hint)

| Variant | Δ AUC | p |
|---|---:|---:|
| `page_class` | +0.025 | 0.048 |
| `region_only` | +0.026 | 0.048 |

decayepoch: p &gt; 0.19. K=50 → floor_min by d≈7; not a clean Stage-2 test.

## Pro disclosures

### NFP-10 — `byte_addr` bug

See `IV_POS_8_NOTES_FOR_PRO.md` §NFP-10.

### page_class layout (Q-PC-4)

Guest ELF sha256: `3e5082ad7ee76bad8be4e403a6a13b566f2a06cbb85b947fae9cbbd0dfd05494`

| page_class | Range |
|---|---|
| `stack` | `[0x00010000, 0x00200800)` |
| `text` | `[0x00200800, 0x00219db8)` |
| `rodata` | `[0x00219db8, 0x0022133c)` |
| `data_bss` | `[0x0022133c, 0x00221488)` |
| `heap` | `[0x00221488, 0x42000000)` |
| `host_ecall` | `[0x42000000, 0x42000100)` |
| `user_dynamic` | `[0x42000100, 0xBFFF0000)` |

Full layout: `d1b_guest_elf_layout.json`.

**Ask Pro:** Confirm layout; respond to saturation inversion; pick L1 enrichment direction.

## Recommendation

| Setting | Decision |
|---|---|
| D2 default CGC (L0) | **`production_log2_corrected`** + `byte_addr` fix |
| L0 `page_class` swap | **Reject** |
| L1 semantic signal | **Open D1.E question** — separate channels / weighted / multi-objective (naive OR redundant) |
| decayexp AUC | D1.E forward-run K≈200–300 |

## Limitations

1. n=5 paired triplets.
2. Frozen-DB post-hoc; bandit trajectories ran under buggy stored CGC.
3. decayexp K=50 too aggressive (D1.A Finding A).
4. Sparse binary composite `bandit_success` (D1.A Finding F).
5. V5 catalog only.
6. `page_class` Batch 2 uses `global_failures` Path 3 vs production hook3 replay — post-hoc maps can diverge; runtime L1 analysis assumes aligned extraction.

## Provenance

| Item | Value |
|---|---|
| Base git commit (D1.B uncommitted) | `4fce6649946300729937595a66543afda53a1f3d` |
| Build date | 2026-06-17 |
| `d1b_metrics_table.csv` sha256 | `49aa8e0e9ae219f4e7c586fe3ffa3d3989399d8e2ee56438103da0b65e4343fb` |
| `d1b_paired_tests.csv` sha256 | `ce4300f7a90cb66ab8877bf460b23b9e8b4a37ea15c5df4c37695bb2f115ce3c` |
| `d1b_saturation_profile.csv` sha256 | `6c55062f19fa36f68b00984991d3320a38b265e42fb2ee2d99c0a909e7b0b196` |
| Notebook | `IV_POS_8_D1B_NOTEBOOK.ipynb` + `.html` |

## Revision history

| Date | Author | Change |
|---|---|---|
| 2026-06-17 | Composer | Initial subsection |
| 2026-06-17 | Composer | Polish: overlay plots, thin headroom, L1 OR reframe, dates, decayexp caveat |
