#!/usr/bin/env bash
# Resolve coinbase git pull conflicts when local POS files predate the push.
# Run from ~/arguzz on coinbase AFTER backing up anything you care about.
#
# Conflicts seen (2026-06-09):
#   - modified: a4/pos/dispatch_pos.py, a4/pos/run_campaign_pos.sh
#   - untracked files overwritten by merge: manifests + run_smoke_7b_pos.sh
#
# Safe fix: stash tracked edits, remove conflicting untracked copies, pull.

set -euo pipefail

cd "${1:-$HOME/arguzz}"

echo "=== coinbase git pull fix ==="
echo "cwd: $(pwd)"
git status -sb

if git diff --quiet HEAD && [[ -z "$(git ls-files --others --exclude-standard)" ]]; then
    echo "Working tree clean — pulling..."
    git pull
    exit 0
fi

echo "Stashing tracked local changes..."
git stash push -m "coinbase-pre-pull-$(date +%Y%m%d)" \
    a4/pos/dispatch_pos.py a4/pos/run_campaign_pos.sh 2>/dev/null || \
    git stash push -m "coinbase-pre-pull-$(date +%Y%m%d)" || true

echo "Removing untracked POS smoke files that block merge..."
rm -f a4/pos/run_smoke_7b_pos.sh
rm -f a4/pos/manifests/smoke_7b/pos_smoke_7b_*.json

echo "Pulling origin/main..."
git pull

echo "Done. Verify:"
git log -1 --oneline
ls a4/pos/manifests/smoke_7b/
echo "If stash had wanted edits, compare: git stash list"
