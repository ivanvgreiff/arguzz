# `a4/pos/` — POS testbed campaign scripts

> **For everything about POS — API, node selection, workflow, decisions, verified
> commands, anti-patterns — read [`a4/docs/precloud/POS_PLAYBOOK.md`](../docs/precloud/POS_PLAYBOOK.md).**
> That document is the single source of truth and is updated as we learn.

## What's in here

| File | Role | Runs on |
|---|---|---|
| `prepare_bundle.sh` | Build the deterministic tarball bundle from a clean git tree + verified `risc0-host`. | local |
| `run_campaign_pos.sh` | Test-node entrypoint (reads vars via `pos_get_variable`, runs `cli fuzz`, `pos_upload` on EXIT). | test node, via `pos.commands.launch --infile` |
| `dispatch_pos.py` | Management-node dispatcher: allocate → image → reset → copy bundle → set_variables → launch runners → write `dispatch_manifest.json`. Uses `poslib`. | mgmt node |
| `collect_results_pos.py` | Pull results from the POS result folder; validate; write `collection_report.json`. | local (or mgmt) |
| `benchmark_pos.sh` | IV.POS.2 protocol (3 strategies × N=50) on one node. | test node |
| `manifests/` | Campaign manifests consumed by `dispatch_pos.py`. | — |

## Quickstart (with playbook section refs)

| Phase | Command | Playbook ref |
|---|---|---|
| IV.POS.0 | `pos allocations allocate bitcoin --duration 60` + `image+reset` + `commands launch/await` + `allocations free` | §8 IV.POS.0 |
| IV.POS.1 | `python -m a4.pos.dispatch_pos --manifest manifests/pos_smoke_v1.json --bundle ~/a4_campaign_<git>.tar.gz --nodes bitcoin --allocation-duration 240 --await` | §8 IV.POS.1 |
| IV.POS.2 | `bash a4/pos/benchmark_pos.sh` on bitcoin | §8 IV.POS.2 |
| IV.POS.3+ | dispatch_pos with appropriate manifest | §8 IV.POS.3-7 |
