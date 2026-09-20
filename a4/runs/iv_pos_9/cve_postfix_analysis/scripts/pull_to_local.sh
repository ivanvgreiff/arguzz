#!/bin/bash
# RUN IN THE SANDBOX (dangerouslyDisableSandbox). Pull the 4 per-node .tgz coinbase->data/,
# extract, and map each raw DB to data/<group>/seed<N>.db. Then write data/MANIFEST.md.
# Run AFTER scripts/stage_on_coinbase.sh finished on coinbase.
set -uo pipefail
BASE="$(cd "$(dirname "$0")/.." && pwd)"
CB="ivgreiff@coinbase.net.in.tum.de"; PORT=10022
SSHO="-o ConnectTimeout=240 -o GSSAPIAuthentication=no -o StrictHostKeyChecking=no -o ServerAliveInterval=15"
TMP="$BASE/data/_tgz"; mkdir -p "$TMP"
for n in flare octorand opulous polynize; do
  echo "=== pull $n.tgz ==="
  scp -P $PORT $SSHO "$CB:/tmp/postfix_dl/$n.tgz" "$TMP/$n.tgz" 2>&1 | tail -1
  tar -C "$TMP" -xzf "$TMP/$n.tgz" 2>/dev/null && echo "  extracted $n"
done
echo "=== map raw DB names -> data/<group>/seed<N>.db + MANIFEST ==="
python3 - "$BASE" "$TMP" <<'PY'
import sys, os, re, hashlib, glob, shutil
base, tmp = sys.argv[1], sys.argv[2]
def group(fn):
    if fn.startswith("rerun_v6_cTS_"):   return "v6_cTS_postfix"
    if fn.startswith("rerun_hybrid_"):   return "hybrid_B2_postfix"
    if fn.startswith("b3hyb_"):          return "hybrid_B3_clean"
    return None
rows=[]
for p in sorted(glob.glob(os.path.join(tmp,"*.db"))):
    fn=os.path.basename(p); g=group(fn); m=re.search(r"seed(\d+)",fn)
    if not g or not m: print("  ?? unmapped",fn); continue
    seed=m.group(1); dst=os.path.join(base,"data",g,f"seed{seed}.db")
    shutil.move(p,dst)
    h=hashlib.sha256(open(dst,'rb').read()).hexdigest()
    rows.append((g,f"seed{seed}.db",os.path.getsize(dst),h[:16],fn))
man=os.path.join(base,"data","MANIFEST.md")
with open(man,"w") as f:
    f.write("# data/ MANIFEST — downloaded post-fix DBs (WAL-checkpointed on-node, read-only in notebooks)\n\n")
    f.write("| group | file | bytes | sha256[:16] | source-name-on-node |\n|---|---|---|---|---|\n")
    for g,fn,sz,h,src in sorted(rows): f.write(f"| {g} | {fn} | {sz} | {h} | {src} |\n")
print(f"mapped {len(rows)} DBs into data/; wrote {man}")
PY
rm -rf "$TMP"
echo "=== sanity: which NEW sources now have real DBs (flip from precomputed -> db) ==="
PYTHONPATH="$BASE" python3 -c "import sys;sys.path.insert(0,'$BASE');from lib import data_access as d;[print(s.key,'->',sorted(s.db_paths())) for s in d.SOURCES if s.origin=='NEW']"
echo "=== PULL DONE ==="
