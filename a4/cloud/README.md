# `a4/cloud/` — DEFERRED OPTIONAL BACKEND (Docker / GCP)

> **Status (Jun 4, 2026, evening):** This directory is **no longer the primary execution path.**
> The user has moved to the **university POS testbed** as the production orchestrator. See
> [`a4/pos/README.md`](../pos/README.md) for the current workflow.
>
> This directory is preserved as a future optional backend per `PIVOT_TO_POS.md §5.3` —
> Docker can be revisited later if (a) the testbed supports it, (b) it materially improves
> reproducibility, (c) it does not add operational risk. Do not use any of these scripts
> for the current campaign plan.

---

(Original content for reference — applies only if/when Docker backend is revisited)

# `a4/cloud/` — Cloud Run jobs for fuzzing campaigns

Phase IV.0 scaffolding. Three pieces:

| file | role |
|---|---|
| `Dockerfile` | Image that bakes in the fixed `risc0-host`, the `a4/` Python tree, and the entrypoint. |
| `run_campaign.sh` | Entrypoint that takes env vars (strategy, seed, num, bucket, …), runs one `cli fuzz` invocation, uploads results to GCS. |
| `dispatch.py` | Local script that enumerates `(strategy, seed)` Cartesian product and submits one Cloud Run Jobs execution per pair. |

## Pre-IV.0 sanity (do this on the local machine first)

1. **Verify the fixed binary hash** matches the one committed to backup:
   ```bash
   sha256sum workspace/output/target/release/risc0-host
   cat ~/arguzz_backups/risc0-host.FIXED.sha256
   ```
   Both must match. If they don't, rebuild the binary (`cd workspace/output && cargo build --release`) and re-record:
   ```bash
   sha256sum workspace/output/target/release/risc0-host > ~/arguzz_backups/risc0-host.FIXED.sha256
   ```

2. **Local Docker smoke test** (optional but recommended):
   ```bash
   EXPECTED_SHA=$(awk '{print $1}' ~/arguzz_backups/risc0-host.FIXED.sha256)
   docker build -t arguzz-cloud:dev \
     --build-arg EXPECTED_SHA256=$EXPECTED_SHA \
     -f a4/cloud/Dockerfile .
   docker run --rm \
     -e A4_STRATEGY=zoned -e A4_SEED=1 -e A4_NUM=10 \
     -e A4_BUCKET=NOOP -e A4_CAMPAIGN_NAME=smoke \
     -e A4_RUN_ID=local-smoke \
     arguzz-cloud:dev
   ```
   (The `gsutil cp` will fail at the end because `A4_BUCKET=NOOP`; that's OK for a smoke. The first 9 steps must succeed and the meta JSON must end up in `/tmp/local-smoke/campaign.meta.json` inside the container — `docker run -v` to inspect.)

## IV.0 one-time GCP setup (sketched; not executed yet)

```bash
# Vars
PROJECT=...           # your GCP project
REGION=us-central1
REPO=arguzz
JOB=arguzz-fuzz
BUCKET=arguzz-results
IMAGE=$REGION-docker.pkg.dev/$PROJECT/$REPO/arguzz-cloud:v1

# 1. Create Artifact Registry repo
gcloud artifacts repositories create $REPO --repository-format=docker --location=$REGION

# 2. Create GCS bucket
gsutil mb -l $REGION gs://$BUCKET/

# 3. Build + push image
EXPECTED_SHA=$(awk '{print $1}' ~/arguzz_backups/risc0-host.FIXED.sha256)
docker build -t $IMAGE --build-arg EXPECTED_SHA256=$EXPECTED_SHA -f a4/cloud/Dockerfile .
docker push $IMAGE

# 4. Create the Cloud Run Job template
gcloud run jobs create $JOB \
  --image $IMAGE \
  --region $REGION \
  --tasks 1 \
  --cpu 2 --memory 4Gi \
  --max-retries 1 \
  --task-timeout 24h

# 5. One-off test execution (overrides env vars per run)
gcloud run jobs execute $JOB --region $REGION \
  --update-env-vars="A4_STRATEGY=zoned,A4_SEED=999,A4_NUM=50,A4_BUCKET=$BUCKET,A4_CAMPAIGN_NAME=smoke"
```

## IV.1 batch dispatch

After the job template above exists:

```bash
python -m a4.cloud.dispatch \
  --campaign-name cloud_ab_v1 \
  --bucket $BUCKET \
  --strategies uniform zoned bandit \
  --seeds 42 43 44 45 46 \
  --num 5000 \
  --job-name $JOB \
  --region $REGION \
  --image-uri $IMAGE \
  --manifest-out cloud_ab_v1.dispatch.json
```

This submits 15 jobs (3 strategies × 5 seeds) and writes the execution names to `cloud_ab_v1.dispatch.json` for later polling/aggregation.

## Schema in the cloud

Each job writes to `gs://$BUCKET/results/<campaign>/<run_id>/`:

- `campaign.db` — full SQLite (post-III.0/III.1/III.3 schema)
- `campaign.log` — full stdout/stderr (for `analyze_campaign.parse_terminal` fallback)
- `campaign.meta.json` — single-row summary (start, end, exit code, num_recorded, **binary_sha256**)

The binary sha256 in the meta is checked against the entrypoint's `sha256sum /app/bin/risc0-host` at job startup — it's there as evidence in case anyone later doubts which prover was used.

## Cost estimate (for IV.1 first run)

- 15 jobs × 5000 muts × ~22s/mut = **458 CPU-hours** ≈ $31 at `e2-standard-2`.
- GCS storage: 15 × ~50 MB DB + 50 MB log ≈ 1.5 GB total ≈ $0.05/mo.
- Network: download ≈ free egress within region.

See master plan §11.5 for derivation.
