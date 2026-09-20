# EXISTING databases — READ-ONLY pointers (never edit / move / copy / checkpoint)

These are the original bug-race databases. This analysis **reads them in place, read-only** (via
`lib.data_access.open_ro`, which uses `mode=ro&immutable=1` — sqlite cannot write, lock, or touch the
`-wal`/`-shm` sidecars). We do **not** copy them into `data/` and we do **not** modify them.

## Where they live (absolute, do not move)
Root: `/root/arguzz/a4/runs/iv_pos_9/race/cve_results/` (the original CVE thesis race, N=5000, 6 seeds).

| dataset (data_access key) | read-only glob | binary | valid for CVE? |
|---|---|---|---|
| `v6_uniform_baseline` | `cve_results/*/*V6_uniform*/run.db` | B2 | **YES** — the 9-find baseline (Arguzz, binary-invariant) |
| `v5_control` | `cve_results/*/*V5_control*/run.db` | B2 | NO — A4; finds 0 CVE; A4-3kind contaminated |
| `v6_cTS_prefix` | `cve_results/*/*V6_cTS*/run.db` | B2 | CONFOUNDED — pre-step-domain-fix; **contrast only** |
| `hybrid_prefix` | `cve_results/*/*Hybrid_cTS*/run.db` | B2 | CONFOUNDED — pre-fix + 3-kind contam; **contrast only** |

Each variant has 6 seeds (1234–1239) across batch dirs `cve_thesis_b1/b2/b3`.

## Why these stay where they are
- The original race + its replay-oracle output are pinned to these exact files; moving/editing them would
  break that provenance (and the user explicitly forbids it).
- They are already final (pulled from POS). We read them read-only; if any carries a `-wal` sidecar,
  `immutable=1` reads it without writing.

## Do NOT touch (existing tooling, for reference only — not edited by this analysis)
- `../a1/cve_replay_oracle.py`, `../a1/cve_deep_extract.py` — the original analysis scripts. This folder
  has its **own** `lib/cve_metrics.py`; we do not modify the originals. If we run the replay-oracle, we
  invoke it read-only against copies/paths, never editing it.
- `../../../docs/cloud3/CVE_COMPARISON_DATA_PROVENANCE.md` — the earlier provenance note (still valid);
  this folder's `DATA_PROVENANCE.md` supersedes it for the post-fix analysis but does not edit it.
