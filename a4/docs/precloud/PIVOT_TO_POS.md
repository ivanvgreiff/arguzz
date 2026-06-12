# Report for Claude: Pivoting the RISC Zero Fuzzing Campaign Plan from Google Cloud to the University POS Testbed

## 0. Purpose of this report

We need to revise the existing cloud campaign plan for the RISC Zero witness-structure fuzzing project. The current plan was designed around Google Cloud Platform: Docker image, container registry, Cloud Run Jobs or GCE, and GCS artifact storage. The user now expects to use their university’s internal server/testbed infrastructure instead.

The university infrastructure is managed through the Plain Orchestrating Service, abbreviated `pos`. This is not an elastic cloud service in the GCP sense. It is a bare-metal testbed system with management nodes, reserved test nodes, live-booted operating-system images, POS command dispatch, and POS artifact upload/download tools.

This report gives Claude all necessary context to redesign the plan.

The main recommendation is:

> Keep the research/fuzzing design and most pre-cloud phases. Replace the GCP-specific Phase IV with a POS-native bare-metal campaign workflow. Avoid Docker initially unless the testbed already supports it and it demonstrably reduces complexity.

The user has little cloud/HPC/testbed experience. The revised plan should therefore minimize unnecessary infrastructure complexity and should be implementable incrementally.

---

## 1. Project context

The project fuzzes RISC Zero’s internal witness/proving structure while executing and proving a guest program. The goal is to discover soundness bugs: cases where a malformed or invalid proof is accepted.

The repository already contains or is planned to contain:

* a standalone fuzzer;
* mutation strategies;
* RISC Zero host/prover integration;
* selector strategies:

  * `uniform`;
  * `zoned`;
  * `bandit`;
* coverage/reward state;
* SQLite persistence;
* per-run reward diagnostics;
* multi-seed replicate runner;
* analysis scripts/notebooks.

The current high-level experiment design compares three selector strategies:

```text
uniform
zoned
bandit
```

The core scientific question remains:

```text
Does the bandit scheduler discover more useful global/extended failure contexts than fair structured sampling or the older zoned baseline?
```

The planned full A/B design is:

```text
3 strategies × 5 seeds × N mutations
```

The old cloud plan used `N = 5,000` as the first scaled campaign and deferred `N = 20,000` / `N = 50,000` until checkpointing existed.

The user originally estimated roughly 22 seconds per mutation, but that was measured on a laptop. This must not be used as a final server estimate. The POS/testbed plan must begin with a benchmark phase on representative testbed hardware.

---

## 2. What remains valid from the existing plan

The following parts of the current master plan remain conceptually valid and should not be discarded merely because the execution platform changes.

### 2.1 Phase III research-side work remains valid

The following phases are platform-independent:

```text
III.0  Global-aware reward
III.1  Coverage DB schema for global contexts
III.2  Add uniform-arm selector
III.3  Persist reward components per run
III.4  Multi-seed replicate runner
III.5  Step-level cold-start fix
III.6  Local validation campaign
```

These phases concern the correctness and usefulness of the fuzzing campaign itself, not GCP.

In particular:

* The global-aware reward is still required before scaling.
* The `global_failures` table is still needed.
* The `mutation_rewards` table is still needed.
* The selector trio is still the right comparison.
* The local validation gate is still necessary before burning many node-hours on the testbed.
* The replicate runner still provides useful local and testbed orchestration semantics.

### 2.2 The experiment unit remains valid

Each independent campaign should still be treated as one unit:

```text
(strategy, seed, num_mutations, b_count, guest_args, binary_hash, git_commit)
```

This unit maps cleanly onto POS test nodes. Each POS node can run one such seeded campaign independently.

### 2.3 The artifact expectations remain valid

Each campaign should produce:

```text
<strategy>_seed<seed>.db
<strategy>_seed<seed>.log
metadata / manifest entry
possibly benchmark summary
```

The analysis pipeline should still consume DBs/logs and produce:

* cumulative local failure coverage;
* cumulative global failure coverage;
* cumulative extended failure coverage;
* cumulative U events;
* reward diagnostics;
* selector allocation distributions;
* bandit arm-pull behavior;
* final notebook plots/tables.

### 2.4 The local validation gate remains valid

Before any large POS campaign, the revised plan should still run a smaller validation campaign.

A reasonable validation target remains:

```text
3 strategies × 3 seeds × 250 mutations
```

The acceptance criteria should still include:

* all campaigns finish successfully;
* DBs are non-empty;
* `global_failures` is populated when appropriate;
* `mutation_rewards` is populated;
* extended-context SQL helpers work;
* selector distributions differ;
* bandit has nonzero step-level UCB selections;
* reward has meaningful variation by arm.

---

## 3. What must be replaced

The GCP-specific Phase IV should be replaced almost completely.

### 3.1 Replace Cloud Run Jobs

The old plan assumed:

```text
gcloud run jobs execute
Cloud Run environment variables
Cloud Run stdout/logging
Cloud Run timeout/retry model
```

On the university testbed, this should become:

```text
pos calendar / reservation
pos allocations allocate
pos nodes image
pos nodes start
pos commands launch
pos commands await
pos_upload
pos allocations free
```

### 3.2 Replace GCS

The old plan assumed DBs/logs would be copied to GCS.

On POS, artifacts should be uploaded using POS result mechanisms, most likely `pos_upload`, or copied back to the management node through the POS result folder. Exact details need confirmation from the university documentation/admin.

### 3.3 Replace Artifact Registry

The old plan assumed a container image would be built, pushed, and pulled.

On POS, the simpler first implementation should be a tarball or bundle staged through the management node and downloaded by test nodes using `pos_download` or copied by a POS command.

Docker should not be a first-order dependency unless it is already installed, allowed, and simple to use on the target nodes.

### 3.4 Replace Docker-first execution

The old plan made Docker central. For the POS version, Docker is optional.

Recommended first approach:

```text
bundle repo + prebuilt risc0-host + Python dependencies
copy/download bundle to test node
create/use venv
run one campaign
upload DB/logs
```

Docker can be revisited later if:

* the testbed explicitly supports it;
* the user/admin confirms it is allowed;
* it materially improves reproducibility;
* it does not add operational risk.

Given the user has no Docker experience, the default POS plan should avoid Docker.

---

## 4. Relevant university infrastructure details

The user pasted a large amount of testbed documentation. The following are the relevant points for the redesign.

### 4.1 Access model

Users access a testbed through a management node over SSH.

General access pattern:

```text
ssh -p 10022 [username]@[management-node]
```

SSH keys must be uploaded through the university GitLab/profile flow. Password login is not the model for the testbeds.

Example management nodes:

```text
coinbase.net.in.tum.de      Blockchain testbed
kaunas.net.in.tum.de        Baltikum testbed
kourou.net.in.tum.de        Space testbed
springfield.net.in.tum.de   Simpsons testbed
```

The user does not yet know which testbed they will use. Their advisor/supervisor will tell them which testbed is assigned.

### 4.2 POS architecture

POS uses:

```text
management node → test nodes
```

The management node runs the POS daemon and exposes `pos` CLI / Python API.

Test nodes are dedicated bare-metal servers. They are controlled by POS. They are not cloud VMs in the GCP sense.

POS can:

* create calendar entries / reservations;
* create allocations;
* configure experiment variables;
* select node OS image;
* start/stop/reset/bootstrap nodes;
* launch commands on test nodes;
* queue commands;
* collect artifacts/results.

### 4.3 Stateless node model

This is critical.

The docs state that test nodes are live-booted into desired OS images for reproducibility. A reboot gives a fresh OS and loses local node data.

Implication for our plan:

```text
Do not assume anything written locally on a test node persists after reboot.
```

Therefore each campaign script must:

1. set up the environment from scratch or from a prepared bundle;
2. run the campaign;
3. explicitly upload DB/log artifacts before the node is stopped/rebooted/freed.

### 4.4 POS minimum workflow

The documented POS minimum workflow is approximately:

```bash
pos calendar create nodeA nodeB ...
pos allocations allocate nodeA nodeB ...
pos allocations variables ...
pos nodes image nodeA debian-buster
pos nodes start nodeA
pos commands launch nodeA -- echo 42
pos commands launch nodeA --infile myscript.sh
pos commands await COMMAND_ID
pos allocations free ALLOC_ID
```

Important command modes:

```text
--blocking      command blocks until finished and returns stdout/stderr
--non-blocking  starts and returns command id
--queued        queues command for this node
```

For campaign jobs, non-blocking or queued launch plus `pos commands await` is likely appropriate.

### 4.5 POS loop variables

POS supports loop variables through `--as-loop` and commands launched with `--loop`. This can schedule cross-products of experiment variables.

However, for this project, the safer first implementation is probably to implement our own manifest-driven dispatcher and launch one campaign per node explicitly. POS loop variables can be considered later.

Rationale:

* The experiment units are already naturally manifest-driven.
* We need careful artifact naming and seed tracking.
* The user is inexperienced with POS.
* Keeping one explicit command per `(strategy, seed)` campaign is easier to debug.

### 4.6 POS tools on test nodes

The test nodes have `postools`, including command-line tools:

```text
pos_download
pos_get_variable
pos_get_run_number
pos_set_variable
pos_run
pos_wait
pos_kill
pos_upload
pos_sync
pos_heartbeat
```

The most relevant for this project are:

```text
pos_download    download staged files from the POS server
pos_upload      upload DB/log/result artifacts
pos_heartbeat   possibly extend reservation/event if appropriate
```

`pos_upload` supports recursive upload and force-overwrite options. It can upload result files from the test node to the experiment result folder.

### 4.7 `/srv/testbed/files` and `pos_download`

The docs say that `pos_download` downloads files from the POS server, and downloadable files must be located under:

```text
/srv/testbed/files
```

This matters because our test nodes need access to a prepared campaign bundle.

Candidate workflow:

```text
management node:
  place a4_campaign_bundle.tar.gz in /srv/testbed/files/<user-or-project>/

test node:
  pos_download <user-or-project>/a4_campaign_bundle.tar.gz
```

But the docs do not specify whether normal users can write to `/srv/testbed/files`, what subdirectory convention is required, or what quota applies.

This is one of the key missing pieces to ask the advisor/admin.

### 4.8 Testbeds and likely node choices

The user pasted several testbed descriptions.

#### Blockchain testbed

Management node:

```text
coinbase.net.in.tum.de
```

Access:

```bash
ssh -p 10022 [username]@coinbase.net.in.tum.de
```

Test nodes include:

```text
bitcoin - bitcoincash
ether - ethercash
dogecoin - dogecoincash
unconnected: tentacle, mtgox
```

Special nodes include:

```text
GPU-equipped servers: deepthought, smartcash, chrysos
P4 switches: bitstamp, bitfinex, bittrex, bitpanda
Compute Nodes: intelexp0, intelexp1, vmexp0, vmexp1, galvos, amdexp0, amdexp1, tether
```

For this project, the “Compute Nodes” sound more relevant than the network-pair nodes, assuming access is granted. GPU nodes are likely unnecessary because the prover workload is CPU-bound unless proven otherwise.

#### Baltikum testbed

Management node:

```text
kaunas.net.in.tum.de
```

Access:

```bash
ssh -p 10022 [username]@kaunas.net.in.tum.de
```

Test nodes include network-paired servers:

```text
riga - vilnius
klaipeda - narva
cesis - nida
rapla - tapa
```

This may be usable but appears more network-measurement oriented. For CPU fuzzing, compute-oriented Blockchain nodes may be preferable if available.

#### iLab

iLab has 44 PCs controlled through POS, but there are caveats:

* nodes do not have IPMI;
* status control is less reliable;
* boot is via wake-on-LAN;
* iLab students have priority and may reboot machines;
* only one image is booted, currently Debian Bullseye;
* reservation/calendar is important.

Because iLab students are allowed to reboot machines if needed, iLab may be risky for long fuzzing jobs unless the user has clear permission and a quiet reservation window.

#### Space / Simpsons

These are wireless/wired measurement testbeds and probably not the first choice for a CPU-bound RISC Zero fuzzing campaign.

---

## 5. Docker decision

Docker is not required for POS.

### 5.1 What Docker would help with

Docker could package:

* Python version;
* Python dependencies;
* repo code;
* `risc0-host`;
* shell entrypoint;
* environment variables.

If Docker is already installed and allowed, it could make runs more reproducible.

### 5.2 Why Docker should not be the default

The user has no Docker experience. The POS system already introduces enough new concepts:

* reservation;
* allocation;
* booting;
* stateless nodes;
* `pos_download`;
* `pos_upload`;
* command queue;
* management-node/test-node split.

Adding Docker immediately increases operational complexity.

Also, Docker may not be installed or allowed on the test nodes. If the default Debian image lacks Docker, installing Docker during each run would be fragile and slow.

### 5.3 Recommended Docker policy

Use this rule:

```text
Do not depend on Docker for the first POS campaign.
```

Preferred first implementation:

```text
prebuilt binary + repo bundle + Python venv/wheelhouse + POS scripts
```

Revisit Docker only after a POS smoke test works.

---

## 6. Outbound internet decision

Outbound internet on test nodes matters only for setup.

If test nodes have outbound internet, a setup script can potentially do:

```bash
git clone ...
pip install ...
apt-get install ...
curl ...
```

If test nodes do not have outbound internet, all dependencies must be staged in advance.

For reproducibility, the better long-term design is to avoid depending on outbound internet even if available.

Recommended approach:

```text
Build/stage all necessary inputs before dispatch.
Test node should not need internet during the fuzzing campaign.
```

Bundle should include:

```text
repo source at fixed git commit
prebuilt risc0-host binary
Python dependency wheels if needed
scripts
manifest
configuration
```

Avoid building Rust/RISC Zero on every node if possible. Build once and distribute the fixed binary. Record its SHA256 hash.

---

## 7. OS image explanation and recommendation

In POS/testbed language, an “image” means the operating system environment that gets live-booted onto the bare-metal test node.

This is not the same as a Docker image.

Examples:

```text
debian-buster
debian-bullseye
other testbed-provided images
custom image, if supported by admins
```

A standard Debian image means the node boots into a clean Debian environment. It will not automatically contain the project repo, Python dependencies, or `risc0-host`.

A custom image would mean an admin-supported OS image that already includes project dependencies. That may be faster and more reproducible but requires admin support and is not necessary for first success.

Recommendation:

```text
Assume standard Debian image for the initial POS plan.
Do not require custom image support.
Design setup scripts to work from a clean Debian boot.
```

Need confirmation later:

```text
Which standard image should be used?
debian-buster? debian-bullseye? something else?
```

---

## 8. Base-case assumption: 3 days uninterrupted

The user wants the revised plan to assume that the infrastructure can be used for 3 days uninterrupted.

This should be the base case.

However, the plan should explicitly mark this as a required confirmation before implementation.

Use this assumption:

```text
Base case:
  We can reserve enough relevant test nodes for up to 3 uninterrupted days.

Implementation gate:
  Before launching the full campaign, the user must confirm with supervisor/admin:
    - reservation length;
    - node count;
    - which nodes;
    - whether long CPU-bound jobs are acceptable.
```

The plan should not hard-code a final `N` until benchmarking is complete.

---

## 9. Runtime recalibration

The old 22 seconds/mutation number came from the user’s laptop. It must not drive the final POS plan.

The first POS technical phase must benchmark real server performance.

### 9.1 Benchmark protocol

On one representative test node, run small campaigns:

```text
selector = uniform, N = 50, seed = 42
selector = zoned,   N = 50, seed = 42
selector = bandit,  N = 50, seed = 42
```

Same:

```text
risc0-host binary
guest args
b_count = 16
node
OS image
```

Measure:

```text
seconds_per_mutation = campaign_runtime_seconds / N
```

Do not include bundle download, environment setup, or artifact upload in the per-mutation estimate. Track those separately as setup overhead.

Output file:

```text
pos_benchmark_v1.json
```

Suggested contents:

```json
{
  "node": "...",
  "cpu_model": "...",
  "image": "...",
  "git_commit": "...",
  "host_sha256": "...",
  "b_count": 16,
  "runs": [
    {
      "strategy": "uniform",
      "seed": 42,
      "num": 50,
      "runtime_seconds": 0,
      "seconds_per_mutation": 0.0
    }
  ]
}
```

### 9.2 Campaign sizing formula

Let:

```text
S = measured seconds per mutation, use the slowest selector
N = mutations per campaign
J = total campaigns = 15 for 3 strategies × 5 seeds
M = number of usable nodes
B = number of batches = ceil(J / M)
T = usable wall-clock budget in seconds
```

Then:

```text
estimated_wall_clock = B × N × S + setup/upload overhead
```

For 3 days:

```text
3 days = 259,200 seconds
```

Use slack. Do not plan to consume the full 3 days. A 30% slack is reasonable:

```text
safe budget = about 181,000 seconds
```

Choose `N` such that:

```text
B × N × S < safe budget
```

### 9.3 Example with laptop speed only

If the server is no faster than the laptop:

```text
S = 22 seconds/mutation
```

Then:

* with 15 nodes, all 15 campaigns run in one batch:

  * `N = 5,000` takes about 30.6 hours;
  * fits in 3 days.
* with 5 nodes, campaigns run in 3 batches:

  * `N = 5,000` takes about 91.7 hours;
  * does not fit in 3 days.
* with 10 nodes, campaigns run in 2 batches:

  * `N = 5,000` takes about 61.1 hours;
  * fits narrowly but leaves less slack.

If servers are faster, larger `N` may be possible. But the plan should benchmark first.

---

## 10. Recommended POS-native architecture

### 10.1 Directory structure

Replace `a4/cloud/` with something like:

```text
a4/pos/
  README.md
  prepare_bundle.sh
  run_campaign_pos.sh
  dispatch_pos.py
  collect_results_pos.py
  benchmark_pos.sh
  manifests/
    pos_benchmark_v1.json
    pos_ab_v1.json
```

The existing `a4/cloud/aggregate.py` concept can be retained but renamed/generalized:

```text
a4/analysis/aggregate_campaigns.py
```

or:

```text
a4/pos/aggregate_pos_results.py
```

Avoid hard-coding GCS/GCP assumptions.

### 10.2 Bundle preparation

Create a script:

```text
a4/pos/prepare_bundle.sh
```

Responsibilities:

1. verify clean or recorded git state;
2. copy repo or archive tracked source;
3. include fixed `risc0-host` binary;
4. include scripts;
5. optionally include Python wheels;
6. compute hashes;
7. write bundle manifest;
8. produce:

```text
a4_campaign_<git_commit>.tar.gz
```

The bundle manifest should include:

```json
{
  "git_commit": "...",
  "dirty": false,
  "host_binary_path": "bin/risc0-host",
  "host_sha256": "...",
  "created_at": "...",
  "python_version_expected": "...",
  "notes": "..."
}
```

### 10.3 Test-node run script

Create:

```text
a4/pos/run_campaign_pos.sh
```

This script runs on the test node.

Approximate structure:

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${A4_STRATEGY:?required}"
: "${A4_SEED:?required}"
: "${A4_NUM:?required}"
: "${A4_B_COUNT:=16}"
: "${A4_BUNDLE:?required}"

WORKDIR="/tmp/a4_campaign_${A4_STRATEGY}_${A4_SEED}"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Acquire bundle.
# Exact path depends on POS /srv/testbed/files convention.
pos_download "$A4_BUNDLE"

tar -xzf "$(basename "$A4_BUNDLE")"
cd a4_campaign

python3 -m venv .venv
. .venv/bin/activate

# Prefer offline install if wheelhouse is included.
# Fallback only if internet is known to be available.
pip install -e .

mkdir -p results

DB="results/${A4_STRATEGY}_seed${A4_SEED}.db"
LOG="results/${A4_STRATEGY}_seed${A4_SEED}.log"
META="results/${A4_STRATEGY}_seed${A4_SEED}.meta.json"

python -m a4.standalone.cli fuzz \
  --host ./bin/risc0-host \
  --selector "$A4_STRATEGY" \
  --num "$A4_NUM" \
  --b-count "$A4_B_COUNT" \
  --seed "$A4_SEED" \
  --db "$DB" \
  -- --in1 5 --in4 10 \
  2>&1 | tee "$LOG"

python - <<'PY'
# Write metadata JSON here if desired.
PY

pos_upload results -r -o "a4/${A4_STRATEGY}_seed${A4_SEED}" -f
```

Notes:

* This is schematic. Final script must match real POS syntax and user permissions.
* Add failure handling to upload partial logs/DBs even on error.
* Consider a shell `trap` for artifact upload on exit.

### 10.4 Dispatcher

Create:

```text
a4/pos/dispatch_pos.py
```

Responsibilities:

1. read a campaign manifest;
2. map jobs to available nodes;
3. create/verify POS allocation;
4. set variables or pass env vars;
5. launch `run_campaign_pos.sh` on each node;
6. record POS command IDs;
7. await completion;
8. write dispatch manifest with command IDs and node mapping.

Simple manifest:

```json
{
  "name": "pos_ab_v1",
  "bundle": "user/a4_campaign_<commit>.tar.gz",
  "b_count": 16,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "jobs": [
    {"strategy": "uniform", "seed": 42, "n": 1000},
    {"strategy": "uniform", "seed": 43, "n": 1000},
    {"strategy": "zoned", "seed": 42, "n": 1000},
    {"strategy": "bandit", "seed": 42, "n": 1000}
  ]
}
```

### 10.5 Results collection

Create:

```text
a4/pos/collect_results_pos.py
```

Responsibilities:

* locate POS result folder;
* copy artifacts to local analysis directory;
* verify all expected DB/log files exist;
* verify nonzero size;
* optionally open each DB and validate expected tables/row counts;
* write `collection_report.json`.

---

## 11. Revised phase plan

### Phase IV.POS.0 — Access and information confirmation

Goal: confirm testbed access and essential operational constraints.

Required before implementation:

```text
which testbed?
which management node?
which nodes?
how many nodes?
reservation length?
Docker allowed?
outbound internet?
/srv/testbed/files write path?
POS result folder location?
standard Debian image name?
disk quota?
```

Do not block high-level planning on this, but block final implementation before dispatching full campaigns.

### Phase IV.POS.1 — Bundle and single-node smoke

Goal: prove one clean node can run a tiny campaign.

Run:

```text
selector = uniform
seed = 42
N = 10 or 20
```

Acceptance:

* node boots;
* bundle downloads;
* Python setup works;
* `risc0-host` executes;
* campaign produces DB/log;
* artifacts upload;
* DB can be opened after collection.

### Phase IV.POS.2 — Benchmark

Goal: measure real testbed seconds/mutation.

Run:

```text
uniform N=50 seed=42
zoned   N=50 seed=42
bandit  N=50 seed=42
```

Acceptance:

* write benchmark JSON;
* compute seconds/mutation per strategy;
* choose conservative campaign `N` for the 3-day base case.

### Phase IV.POS.3 — Multi-node smoke

Goal: prove dispatch across multiple nodes.

Run:

```text
3 strategies × 1 seed × 50 mutations
```

Prefer one job per node.

Acceptance:

* all jobs finish;
* artifacts are uniquely named;
* no result collision;
* collection works;
* aggregation can load all three DBs.

### Phase IV.POS.4 — POS local/testbed validation campaign

Goal: reproduce the existing local validation gate on POS.

Run:

```text
3 strategies × 3 seeds × 250 mutations
```

Acceptance:

* all 9 campaigns finish;
* DBs/logs uploaded;
* global failures populated;
* reward rows populated;
* selector distributions look plausible;
* bandit step-level UCB is nonzero;
* preliminary plots generate.

### Phase IV.POS.5 — Full POS A/B campaign

Goal: run the main campaign under the 3-day base-case assumption.

Default design:

```text
3 strategies × 5 seeds × N mutations
```

`N` is chosen after benchmarking and node-count confirmation.

Candidate values:

```text
N = 1,000 conservative
N = 2,500 moderate
N = 5,000 aggressive, only if node count/runtime/reservation support it
```

Do not use `N = 20,000` unless checkpointing exists or the reservation/runtime math clearly supports it.

### Phase IV.POS.6 — Aggregation and notebook

Goal: produce the boss-facing notebook from POS artifacts.

This largely reuses the old aggregation design, except that artifact collection is from POS result folders rather than GCS.

Notebook should include:

* final metrics table;
* cumulative global-context coverage;
* cumulative extended-context coverage;
* U-event analysis;
* selector allocation distributions;
* bandit arm heatmap;
* interesting-run table;
* variance across seeds;
* caveats.

---

## 12. Failure handling and robustness

Because test nodes are stateless, the POS plan needs explicit failure handling.

### 12.1 Upload on failure

`run_campaign_pos.sh` should use a shell trap to upload whatever exists:

```bash
trap 'upload_results_if_present' EXIT
```

If a campaign fails after producing a partial DB/log, we still want those artifacts.

### 12.2 Unique output names

All artifacts must include:

```text
campaign name
strategy
seed
N
possibly node name
```

Avoid collisions.

Example:

```text
pos_ab_v1_bandit_seed42_n1000.db
pos_ab_v1_bandit_seed42_n1000.log
```

### 12.3 Rerun semantics

If a job fails, rerun the same `(strategy, seed, N)` after diagnosing the cause.

Do not silently merge partial and rerun DBs unless checkpoint/resume is explicitly implemented.

### 12.4 Checkpointing

Checkpointing is not required for the first POS campaign if `N` is small enough to fit comfortably.

But checkpointing becomes important for long runs. A true checkpoint would need to persist:

* fuzzer iteration index;
* SQLite DB state;
* coverage state:

  * global bitmap;
  * touch frequencies;
  * extended failure frequencies;
* bandit scheduler state:

  * arm counts;
  * decayed statistics;
  * step-level statistics;
* RNG state or deterministic replay information.

Until this exists, prefer shorter campaigns that fit within the confirmed reservation window.

---

## 13. Concrete open questions for the user to obtain from docs/admin

The following information is still missing and should be requested before implementation.

### 13.1 Testbed identity and access

```text
Which testbed should I use?
Which management node?
Do I already have POS access?
Which username should I use?
Which nodes am I allowed to reserve?
Do I need special group membership for compute nodes?
```

### 13.2 Node resources

For each allowed node:

```text
CPU model
physical cores / threads
RAM
local disk space
OS image availability
whether nodes are homogeneous or heterogeneous
```

This affects runtime and job placement.

### 13.3 Reservation policy

```text
Can I reserve nodes for 3 uninterrupted days?
How many nodes can I reserve at once?
Are long CPU-bound jobs acceptable?
Is there a maximum reservation duration?
Can reservations be extended?
What happens if a reservation expires while a command is running?
```

Base-case assumption is 3 days uninterrupted, but final implementation must wait for confirmation.

### 13.4 POS file staging

Ask specifically:

```text
Can normal users place files under /srv/testbed/files?
If yes, what path should I use?
Should I create a user/project subdirectory?
How do I copy files there?
Is there a quota?
Are files under /srv/testbed/files visible to all nodes in my allocation?
Are files automatically cleaned?
```

This determines how `pos_download` will fetch the campaign bundle.

### 13.5 POS result storage

Ask:

```text
Where do pos_upload artifacts go?
How do I list/download them from the management node?
Are there quotas?
Can I recursively upload a directory?
Are result folders tied to allocations?
What naming convention is recommended?
```

This replaces GCS.

### 13.6 Internet availability

Ask:

```text
Do test nodes have outbound internet?
Does the management node have outbound internet?
Are GitHub/GitLab/pip/crates.io reachable?
Is outbound access blocked by firewall?
```

Even if internet is available, the preferred plan should stage dependencies.

### 13.7 Debian image details

Ask:

```text
Which standard Debian image should I use?
What Python version is installed?
Is python3-venv installed?
Is build-essential installed?
Is git installed?
Is Rust installed?
Can I apt-get install packages?
Do I have root on the test node?
```

The docs suggest users get root access on test nodes in many testbeds, but this should be confirmed.

### 13.8 Docker / container support

Ask, but do not make it a blocker:

```text
Is Docker installed on test nodes?
Is Docker allowed?
Is Apptainer/Singularity available?
Are users allowed to run containers?
```

Default plan should avoid Docker.

### 13.9 POS command details

Ask or find docs/examples for:

```text
How to pass environment variables to pos commands launch?
How to run a local script with --infile?
How to use non-blocking/queued mode correctly?
How to retrieve stdout/stderr after await?
How to launch commands across many nodes?
How to get node hostname inside the script?
```

### 13.10 Existing examples

Ask for or inspect:

```text
pos-examples repository
simple-loop example
any examples using pos_download and pos_upload
any examples of Python dispatch with poslib
```

The user pasted that `pos-examples` exists. Claude should ask the user to provide relevant example pages/files if available.

---

## 14. Suggested message to advisor/admin

The user can send something like this to get the missing details:

```text
I am planning a CPU-bound fuzzing/proving experiment using POS. Each job runs one seeded campaign, produces a SQLite DB and log, and can run for several hours. I do not need GPUs or special network measurements.

Could you confirm:

1. Which testbed and nodes I should use?
2. Whether I can reserve approximately [X] nodes for up to 3 uninterrupted days?
3. Whether long CPU-bound jobs are acceptable on those nodes?
4. Which Debian image I should boot with POS?
5. Whether test nodes have outbound internet, or whether I should stage all dependencies manually?
6. How I should place a tarball under /srv/testbed/files so test nodes can fetch it with pos_download?
7. Where pos_upload results are stored and whether there are quotas?
8. Whether Docker is installed/allowed, although my initial plan does not require it?
9. Whether the listed compute nodes on the Blockchain testbed are appropriate for this workload?
```

---

## 15. Implementation guidance for Claude

When revising the repository plan, Claude should follow these rules.

### 15.1 Do not delete the research plan

Keep the Phase III work. It is still relevant.

### 15.2 Rename rather than discard cloud concepts

Where possible, generalize:

```text
cloud_ab_v1 → campaign_ab_v1 or pos_ab_v1
cloud/aggregate.py → analysis/aggregate_campaigns.py
cloud manifest → execution manifest
```

Avoid hard-coded GCP-specific names in new code.

### 15.3 Avoid Docker initially

Implement a tarball/POS script path first.

Docker can be a later optional backend.

### 15.4 Benchmark before choosing N

Do not hard-code `N = 5,000` based on laptop timing.

Add a benchmark phase and choose `N` using:

```text
reservation window
number of nodes
measured seconds/mutation
setup overhead
slack
```

### 15.5 Treat 3 days as an assumption, not a confirmed fact

Use 3 days as the base-case planning assumption. But before final full campaign implementation, add an explicit gate requiring supervisor/admin confirmation.

### 15.6 Prefer one campaign per node initially

Do not run multiple campaigns concurrently on the same node until benchmarking proves it is safe.

Reason:

* prover may be CPU/cache/memory intensive;
* concurrency may distort runtime comparisons;
* one campaign per node gives cleaner experimental conditions.

Later, if nodes are many-core and underutilized, test concurrent jobs separately.

### 15.7 Keep artifact naming deterministic

Every artifact should be recoverable from the manifest.

Example:

```text
<campaign>_<strategy>_seed<seed>_n<N>_<git_short>.<ext>
```

### 15.8 Validate DBs immediately after collection

After collecting POS results, run a validation script that checks:

```text
mutations row count = N
mutation_rewards row count = N
global_failures table exists
logs contain campaign completion marker
no DB corruption
strategy/seed metadata matches filename
```

---

## 16. Proposed replacement for current GCP Phase IV

Replace the old GCP section with the following conceptual phase structure.

```text
Phase IV.POS.0 — POS access and constraint confirmation
Phase IV.POS.1 — Bundle and single-node smoke test
Phase IV.POS.2 — Testbed runtime benchmark
Phase IV.POS.3 — Multi-node dispatch smoke test
Phase IV.POS.4 — POS validation campaign
Phase IV.POS.5 — Full POS A/B campaign
Phase IV.POS.6 — Aggregation and boss notebook
Phase IV.POS.7 — Optional checkpointing / larger N
```

### IV.POS.0 — POS access and constraint confirmation

Output:

```text
POS_ACCESS_NOTES.md
```

Contains:

* assigned testbed;
* management node;
* allowed nodes;
* reservation policy;
* file staging method;
* result upload method;
* selected OS image;
* Docker decision;
* internet decision.

### IV.POS.1 — Bundle and single-node smoke test

Output:

```text
a4/pos/prepare_bundle.sh
a4/pos/run_campaign_pos.sh
smoke DB/log
```

Run one tiny campaign.

### IV.POS.2 — Testbed runtime benchmark

Output:

```text
pos_benchmark_v1.json
```

Used to choose `N`.

### IV.POS.3 — Multi-node dispatch smoke test

Output:

```text
dispatch_pos.py
dispatch_manifest.json
3 small campaign DBs/logs
```

### IV.POS.4 — POS validation campaign

Output:

```text
9 DBs/logs
precloud_validation.ipynb or equivalent report
```

### IV.POS.5 — Full POS A/B campaign

Output:

```text
15 DBs/logs
collection_report.json
```

### IV.POS.6 — Aggregation and boss notebook

Output:

```text
cloud_ab_presentation.ipynb renamed if desired:
pos_ab_presentation.ipynb
```

### IV.POS.7 — Optional checkpointing / larger N

Only needed if the first campaign motivates larger runs.

---

## 17. Bottom-line design decision

The revised plan should treat POS as a bare-metal experiment orchestrator, not as a cloud provider.

The mental model should be:

```text
Reserve nodes
Boot clean OS
Download deterministic experiment bundle
Run one seeded campaign per node
Upload DB/log artifacts
Collect results on management/local machine
Aggregate and plot
```

Not:

```text
Build Docker image
Push to registry
Launch Cloud Run Jobs
Upload to GCS
```

Docker is optional. GCP is removed. POS is the new orchestration layer.

The first implementation target should be a boring, debuggable POS smoke test, not a full 75,000-mutation campaign.
