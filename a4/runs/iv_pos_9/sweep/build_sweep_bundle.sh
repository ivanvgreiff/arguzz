#!/usr/bin/env bash
# IV.POS.9 Track-B — sweep bundle builder (Track-B-owned; does not touch shared a4/pos infra).
#
# Produces  bundles/sweep_<gitshort>.tar.gz  with the on-node layout:
#   a4_campaign/repo/                                         (a4 package; PYTHONPATH root)
#   a4_campaign/builds/sweep/28e53771_clean__<guest>/risc0-host   (per-guest read-only binary)
#   a4_campaign/builds/sweep/28e53771_clean__<guest>/fingerprint.json
#
# repo/ = `git archive HEAD a4 pyproject.toml` (all committed a4 machinery: standalone.cli,
# v6_uniform_driver, variants, fuzzer engine, coverage) + an overlay of the untracked/modified
# Track-B code the NODE actually imports (a4/pos/fingerprint_guard.py and any dirty a4 .py).
# a4 is pure-stdlib (no pip needed on-node, per POS_PLAYBOOK H.10 + run_campaign note).
#
# Run on the dev box (where the binaries live), then scp the tarball to coinbase.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

GUESTS=(g1_ecall_control g2_mem_stress g3_accelerator)
SHORT=$(git rev-parse --short=12 HEAD)
OUT="bundles"; mkdir -p "$OUT"
STAGE=$(mktemp -d -t sweepbundle.XXXXXX); trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/a4_campaign"
mkdir -p "$ROOT/repo" "$ROOT/builds/sweep"

echo "[bundle] repo: git archive HEAD @ $SHORT (a4/ + pyproject.toml)"
git archive --format=tar HEAD a4 pyproject.toml 2>/dev/null | tar -x -C "$ROOT/repo"

echo "[bundle] overlay untracked/modified Track-B code the node imports"
# The guard is untracked; it is invoked on every job (assert + emit-json sidecar).
cp a4/pos/fingerprint_guard.py "$ROOT/repo/a4/pos/fingerprint_guard.py"
# Defensive: any dirty tracked .py under the launch path.
while IFS= read -r f; do
    [[ "$f" == *.py && -f "$f" ]] || continue
    mkdir -p "$ROOT/repo/$(dirname "$f")"; cp "$f" "$ROOT/repo/$f"
done < <(git diff --name-only HEAD -- a4/standalone a4/pos)

# Track-B-owned POS logic (generator, deploy, run, and the FROZEN chain_dispatcher copy) —
# these run on coinbase; bundling them makes the extracted tree self-contained + track-isolated.
mkdir -p "$ROOT/repo/a4/runs/iv_pos_9/sweep"
for f in a4/runs/iv_pos_9/sweep/*.py a4/runs/iv_pos_9/sweep/*.sh; do
    [[ -f "$f" ]] && cp "$f" "$ROOT/repo/a4/runs/iv_pos_9/sweep/"
done
touch "$ROOT/repo/a4/runs/iv_pos_9/__init__.py" "$ROOT/repo/a4/runs/iv_pos_9/sweep/__init__.py"

echo "[bundle] binaries (read-only sweep builds)"
for g in "${GUESTS[@]}"; do
    s="a4/builds/sweep/28e53771_clean__${g}"
    d="$ROOT/builds/sweep/28e53771_clean__${g}"
    [[ -x "$s/risc0-host" ]] || { echo "FATAL: missing $s/risc0-host" >&2; exit 1; }
    mkdir -p "$d"
    cp "$s/risc0-host" "$d/risc0-host"; chmod +x "$d/risc0-host"
    [[ -f "$s/fingerprint.json" ]] && cp "$s/fingerprint.json" "$d/fingerprint.json"
    echo "   $g  $(sha256sum "$d/risc0-host" | cut -c1-16)…"
done

cat > "$ROOT/bundle.json" <<EOF
{ "git_short": "$SHORT",
  "track": "B-multiguest-sweep",
  "circuit": "28e53771_clean (load_rs2=1, planted_bug=none)",
  "guests": ["g1_ecall_control", "g2_mem_stress", "g3_accelerator"],
  "layout": "builds/sweep/28e53771_clean__<guest>/risc0-host",
  "repo_root_on_node": "/root/a4_campaign/repo" }
EOF

TAR="$OUT/sweep_${SHORT}.tar.gz"
echo "[bundle] creating $TAR"
tar -czf "$TAR" -C "$STAGE" a4_campaign
echo "[bundle] DONE: $TAR ($(du -h "$TAR" | cut -f1))"
sha256sum "$TAR" | tee "$OUT/sweep_${SHORT}.tar.gz.sha256"
