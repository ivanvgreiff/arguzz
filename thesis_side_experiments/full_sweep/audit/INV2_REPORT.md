# INV2 — witness audit report

## Methodology note

Raw txn `word`/`prev_word` fields vary between clean baseline reruns on the same node (376 structural txn rows). Cycles and txn topology are identical. Classification uses **semantic diff**: cycle/txn topology plus value changes beyond baseline noise, with constraint cycle_idx mapping via `txn_idx`.

## Gates

- **C2_completeness**: PASS — all logs complete
- **C1_determinism**: PASS — cycles+txn topology match all nodes; baseline word noise=376 txns (excluded from semantic diff)
- **C3_controls**: PASS — 7 controls OK
- **C4_failure_signals**: PASS — all targets clean
- **C5_no_BUG**: PASS — H1=37 H2=0 BUG=0
- **C6_inv1_match**: PASS — POST_EXEC H1=30/30 INSTR_WORD H1=7/7 H2=0

## Per-target classification (reference node: meld)

| sample_id | mechanism | label | raw_txn_diff | semantic_diff | verifier | fault |
|-----------|-----------|-------|--------------|---------------|----------|-------|
| arguzz__INSTR_WORD_MOD__default__s0804 | INSTR_WORD_MOD | H1 | 752 | empty | True | word:115 => word:131187 |
| arguzz__INSTR_WORD_MOD__default__s0824 | INSTR_WORD_MOD | H1 | 752 | empty | True | word:30483491 => word:30483619 |
| arguzz__INSTR_WORD_MOD__default__s0852 | INSTR_WORD_MOD | H1 | 752 | empty | True | word:8463875 => word:10561027 |
| arguzz__INSTR_WORD_MOD__default__s0871 | INSTR_WORD_MOD | H1 | 752 | empty | True | word:115 => word:524403 |
| arguzz__INSTR_WORD_MOD__default__s0892 | INSTR_WORD_MOD | H1 | 752 | empty | True | word:1488531 => word:35042963 |
| arguzz__INSTR_WORD_MOD__default__s0905 | INSTR_WORD_MOD | H1 | 752 | empty | True | word:366691 => word:268802147 |
| arguzz__INSTR_WORD_MOD__default__s0914 | INSTR_WORD_MOD | H1 | 752 | empty | True | word:33947747 => word:33948259 |
| arguzz__POST_EXEC_PC_MOD__default__s1518 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2114916 => pc:2114920 |
| arguzz__POST_EXEC_PC_MOD__default__s1537 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2100180 => pc:2100184 |
| arguzz__POST_EXEC_PC_MOD__default__s1542 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2100200 => pc:2100204 |
| arguzz__POST_EXEC_PC_MOD__default__s1549 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113636 => pc:2113640 |
| arguzz__POST_EXEC_PC_MOD__default__s1558 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113672 => pc:2113676 |
| arguzz__POST_EXEC_PC_MOD__default__s1570 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113720 => pc:2113724 |
| arguzz__POST_EXEC_PC_MOD__default__s1576 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113744 => pc:2113748 |
| arguzz__POST_EXEC_PC_MOD__default__s1579 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113756 => pc:2113760 |
| arguzz__POST_EXEC_PC_MOD__default__s1583 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113772 => pc:2113776 |
| arguzz__POST_EXEC_PC_MOD__default__s1594 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113816 => pc:2113820 |
| arguzz__POST_EXEC_PC_MOD__default__s1602 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113848 => pc:2113852 |
| arguzz__POST_EXEC_PC_MOD__default__s1604 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113856 => pc:2113860 |
| arguzz__POST_EXEC_PC_MOD__default__s1605 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113860 => pc:2113864 |
| arguzz__POST_EXEC_PC_MOD__default__s1607 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2113868 => pc:2113872 |
| arguzz__POST_EXEC_PC_MOD__default__s1610 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2100224 => pc:2100228 |
| arguzz__POST_EXEC_PC_MOD__default__s1617 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2100252 => pc:2100256 |
| arguzz__POST_EXEC_PC_MOD__default__s1636 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2100328 => pc:2100332 |
| arguzz__POST_EXEC_PC_MOD__default__s1642 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2100352 => pc:2100356 |
| arguzz__POST_EXEC_PC_MOD__default__s1652 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2120748 => pc:2120752 |
| arguzz__POST_EXEC_PC_MOD__default__s1654 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2120756 => pc:2120760 |
| arguzz__POST_EXEC_PC_MOD__default__s1655 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:3221225584 => pc:3221225588 |
| arguzz__POST_EXEC_PC_MOD__default__s1656 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:3221225588 => pc:3221225592 |
| arguzz__POST_EXEC_PC_MOD__default__s1698 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099292 => pc:2099296 |
| arguzz__POST_EXEC_PC_MOD__default__s1702 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099308 => pc:2099312 |
| arguzz__POST_EXEC_PC_MOD__default__s1718 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099372 => pc:2099376 |
| arguzz__POST_EXEC_PC_MOD__default__s1724 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099396 => pc:2099400 |
| arguzz__POST_EXEC_PC_MOD__default__s1726 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099404 => pc:2099408 |
| arguzz__POST_EXEC_PC_MOD__default__s1731 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099424 => pc:2099428 |
| arguzz__POST_EXEC_PC_MOD__default__s1743 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099472 => pc:2099476 |
| arguzz__POST_EXEC_PC_MOD__default__s1747 | POST_EXEC_PC_MOD | H1 | 752 | empty | True | pc:2099488 => pc:2099492 |

**Totals:** H1=37, H2=0, BUG=0

**Overall:** PASS
