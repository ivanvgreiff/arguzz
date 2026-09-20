#!/bin/bash
# RUN ON COINBASE (detached). Per-node: checkpoint each of our NEW run DBs (WAL->.db), then ONE
# compressed tar stream per node (4 small .tgz instead of 18 raw scp's -> far less throttle-hang).
# Touches ONLY our run DBs (rerun_*/b3hyb_*); never any existing/race DB.
exec > /tmp/postfix_stage.log 2>&1
SSH="ssh -o ConnectTimeout=30 -o BatchMode=yes -o StrictHostKeyChecking=no"
DL=/tmp/postfix_dl; rm -rf $DL; mkdir -p $DL
flare_dbs="rerun_v6_cTS_seed1234_n5000.db rerun_v6_cTS_seed1235_n5000.db rerun_v6_cTS_seed1236_n5000.db b3hyb_seed1234_n5000.db b3hyb_seed1238_n5000.db"
octorand_dbs="rerun_v6_cTS_seed1237_n5000.db rerun_v6_cTS_seed1238_n5000.db rerun_v6_cTS_seed1239_n5000.db b3hyb_seed1235_n5000.db b3hyb_seed1239_n5000.db"
opulous_dbs="rerun_hybrid_cTS_seed1234_n5000.db rerun_hybrid_cTS_seed1235_n5000.db rerun_hybrid_cTS_seed1236_n5000.db b3hyb_seed1236_n5000.db"
polynize_dbs="rerun_hybrid_cTS_seed1237_n5000.db rerun_hybrid_cTS_seed1238_n5000.db rerun_hybrid_cTS_seed1239_n5000.db b3hyb_seed1237_n5000.db"
for node in flare octorand opulous polynize; do
  eval "dbs=\$${node}_dbs"
  for rf in $dbs; do
    $SSH "$node" "python3 -c \"import sqlite3;c=sqlite3.connect('/root/$rf');c.execute('PRAGMA wal_checkpoint(TRUNCATE)');c.close()\" 2>/dev/null"
  done
  timeout 400 $SSH "$node" "cd /root && tar czf - $dbs" > "$DL/$node.tgz"
  echo "STAGED $node -> $node.tgz ($(stat -c %s $DL/$node.tgz 2>/dev/null) bytes) $(date -u +%T)"
done
( cd $DL && sha256sum *.tgz > /tmp/postfix_tgz_SHA256.txt )
echo "STAGE DONE $(date -u +%T) — 4 per-node tgz in $DL ; shas /tmp/postfix_tgz_SHA256.txt"
