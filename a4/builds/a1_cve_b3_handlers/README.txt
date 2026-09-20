B3 = B2 (vulnerable, load_rs2 absent) + the 3 A4 witgen handlers (TXN_PREV_WORD_MOD,
TXN_PREV_CYCLE_MOD, CYCLE_DIFF_COUNT_MOD) ported from 6556e8d7. For the CLEAN Hybrid run only.
- sha256: a5b13659108b42685f0c2c2ef34ec75084ed81f21f7739dabc94be6316f1f637
- guest_image_id: 1269974820,3877409867,2420062130,1103492329,1369779205,1529891756,3991262003,3366159770
  (DIFFERS from B2 — embedded build-path grew guest rodata +68B; divide trace-confirmed at exec 444/449,
   identical "remu a4,a0,a1"/"divu s0,a2,a3". Use THIS guest_id for POS pinning, NOT B2's.)
- CVE intact (load_rs2=0); handlers verified working (TXN_PREV_CYCLE_MOD applies, not 'invalid config').
- source: workspace/risc0-b3-vulnhandlers (branch a1-vuln-b3-handlers); build: workspace/output-a1vuln-b3.
