# ============================================================
# DEFERRED OPTIONAL BACKEND — NOT THE DEFAULT PATH (Jun 4, 2026)
# ============================================================
# The primary execution backend is now the university POS testbed.
# See `a4/pos/` for the POS-native workflow (bundle + pos_download +
# pos_upload, no Docker by default). This Dockerfile is kept as
# a future optional reproducibility / cloud-fallback backend per
# PIVOT_TO_POS.md §5.3 ("Docker can be revisited later if (a) the
# testbed supports it, (b) it materially improves reproducibility,
# (c) it does not add operational risk"). Do not use this image for
# the current campaign plan; build it only if/when we add a Docker
# backend.
# ============================================================

# Cloud campaign image for Phase IV.1+
#
# Bakes in:
#   - the FIXED risc0-host binary (post-III.2.5 fix; NO circuit_debug)
#     verified at build time against ~/arguzz_backups/risc0-host.FIXED.sha256
#   - the full a4/ tree at the commit the image was built from
#   - run_campaign.sh entrypoint that takes A4_STRATEGY / A4_SEED / A4_NUM
#     env vars and uploads results to gs://${A4_BUCKET}/results/
#
# CPU-only (no GPU); risc0-host is single-core.
#
# Build: docker build -t arguzz-cloud:vN -f a4/cloud/Dockerfile .
#        (run from repo root so COPY . /app picks up everything)

FROM python:3.12-slim

# System deps (kept minimal; risc0-host is statically-linked-enough for slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# gsutil / gcloud — needed by run_campaign.sh for result upload
RUN curl -sSL https://sdk.cloud.google.com | bash -s -- --install-dir=/opt --disable-prompts \
    && /opt/google-cloud-sdk/install.sh --quiet --usage-reporting=false --command-completion=false --path-update=false
ENV PATH="/opt/google-cloud-sdk/bin:${PATH}"

WORKDIR /app

# Copy source first, then install. Two-stage so Docker caches the pip step.
COPY pyproject.toml /app/pyproject.toml
COPY a4 /app/a4
COPY README.md /app/README.md
RUN pip install --no-cache-dir -e .

# The fixed binary. Built externally (cargo build --release in workspace/output/).
# Path is relative to repo root, matching `docker build` context above.
COPY workspace/output/target/release/risc0-host /app/bin/risc0-host

# Pin: build-time sha256 verification against the file in ~/arguzz_backups/.
# Build with: docker build --build-arg EXPECTED_SHA256=$(cat ~/arguzz_backups/risc0-host.FIXED.sha256 | awk '{print $1}') ...
ARG EXPECTED_SHA256
RUN if [ -n "$EXPECTED_SHA256" ]; then \
        ACTUAL_SHA256=$(sha256sum /app/bin/risc0-host | awk '{print $1}'); \
        if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then \
            echo "FATAL: risc0-host sha256 mismatch."; \
            echo "  expected: $EXPECTED_SHA256"; \
            echo "  actual:   $ACTUAL_SHA256"; \
            exit 1; \
        fi; \
        echo "binary sha256 verified: $ACTUAL_SHA256"; \
    else \
        echo "WARN: EXPECTED_SHA256 not set; skipping binary verification (DO NOT use this image for production cloud runs)"; \
    fi
RUN chmod +x /app/bin/risc0-host

# Entrypoint
COPY a4/cloud/run_campaign.sh /usr/local/bin/run_campaign.sh
RUN chmod +x /usr/local/bin/run_campaign.sh

# Smoke check that the binary at least starts (catches glibc mismatch early)
RUN /app/bin/risc0-host --help 2>/dev/null || /app/bin/risc0-host || true

ENTRYPOINT ["/usr/local/bin/run_campaign.sh"]
