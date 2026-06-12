(base) root@Ivan:~/arguzz# python -m a4.standalone.tests.run_diagnostic_campaign --host ./workspace/output/target/release/risc0-host --num 200 --seed 123 -- --in1 5 --in4
10
Diagnostic campaign: 200 mutations, seed=123
Host: ./workspace/output/target/release/risc0-host, Args: --in1 5 --in4 10
Running inspection...
Inspection Data Summary:
  Total cycles: 32768
  Total steps: 3930
  Total transactions: 34724
    - Register transactions: 8780
    - Memory transactions: 25944
  Cycles by major category:
    MISC0: 1386
    MISC1: 442
    MISC2: 664
    MUL0: 100
    DIV0: 23
    MEM0 (load): 680
    MEM1 (store): 596
    CONTROL0: 9641
    ECALL0: 87
    POSEIDON0: 2486
    POSEIDON1: 16371
    SHA0: 292
  [1/200] COMP_OUT_MOD @ step 254: 2 failures, 18587ms [bitmap:+1599 exact:+1614]
  [2/200] INSTR_TYPE_MOD @ step 2333: 4 failures, 19676ms
  [3/200] LOAD_VAL_MOD @ step 545: 2 failures, 16374ms
  [4/200] COMP_OUT_MOD @ step 1981: 2 failures, 18402ms
  [5/200] INSTR_WORD_MOD_FULL @ step 2892: 4 failures, 21356ms
  [6/200] MEM_VAL_MOD @ step 7: 1 failures, 16579ms
  [7/200] COMP_OUT_MOD @ step 510: 2 failures, 15228ms
  [8/200] STORE_OUT_MOD @ step 2746: 2 failures, 15565ms
  [9/200] STORE_OUT_MOD @ step 2384: 2 failures, 15373ms
  [10/200] MEM_VAL_MOD @ step 418: 1 failures, 12765ms
  [11/200] PRE_EXEC_REG_MOD @ step 387: 2 failures, 1929ms CRASH
  [12/200] COMP_OUT_MOD @ step 718: 2 failures, 12775ms
  [13/200] INSTR_WORD_MOD_FULL @ step 88: 2 failures, 14361ms
  [14/200] LOAD_VAL_MOD @ step 2560: 2 failures, 12871ms
  [15/200] INSTR_WORD_MOD_FULL @ step 1100: 2 failures, 12613ms
  [16/200] LOAD_VAL_MOD @ step 2092: 2 failures, 12356ms
  [17/200] COMP_OUT_MOD @ step 3008: 2 failures, 12352ms
  [18/200] MEM_VAL_MOD @ step 2495: 2 failures, 12784ms
  [19/200] LOAD_VAL_MOD @ step 3282: 2 failures, 12416ms
  [20/200] COMP_OUT_MOD @ step 3632: 2 failures, 12417ms
  [21/200] LOAD_VAL_MOD @ step 2734: 2 failures, 12791ms
  [22/200] STORE_OUT_MOD @ step 2835: 2 failures, 12229ms
  [23/200] STORE_OUT_MOD @ step 103: 2 failures, 12725ms
  [24/200] COMP_OUT_MOD @ step 490: 2 failures, 12439ms
  [25/200] INSTR_TYPE_MOD @ step 2727: 4 failures, 12785ms [bitmap:+32 exact:+33]
  [26/200] INSTR_WORD_MOD_SUR @ step 1385: 1 failures, 12560ms
  [27/200] INSTR_WORD_MOD_SUR @ step 1616: 1 failures, 12356ms
  [28/200] COMP_OUT_MOD @ step 2886: 2 failures, 13503ms
  [29/200] INSTR_WORD_MOD_FULL @ step 3209: 1 failures, 13244ms
  [30/200] INSTR_WORD_MOD_FULL @ step 784: 3 failures, 13966ms
  [31/200] INSTR_WORD_MOD_SUR @ step 3426: 2 failures, 12855ms [bitmap:+2 exact:+2]
  [32/200] MEM_VAL_MOD @ step 939: 4 failures, 13471ms
  [33/200] STORE_OUT_MOD @ step 3347: 1 failures, 12800ms
  [34/200] LOAD_VAL_MOD @ step 623: 2 failures, 12484ms
  [35/200] INSTR_WORD_MOD_SUR @ step 2042: 1 failures, 13500ms
  [36/200] MEM_VAL_MOD @ step 3929: 0 failures, 13191ms
  [37/200] INSTR_WORD_MOD_FULL @ step 736: 3 failures, 13906ms
  [38/200] LOAD_VAL_MOD @ step 3166: 2 failures, 13051ms
  [39/200] INSTR_WORD_MOD_SUR @ step 3096: 0 failures, 13083ms
  [40/200] COMP_OUT_MOD @ step 1062: 2 failures, 13219ms
  [41/200] PRE_EXEC_REG_MOD @ step 0: 10 failures, 12736ms
  [42/200] MEM_VAL_MOD @ step 3911: 5 failures, 12847ms
  [43/200] MEM_VAL_MOD @ step 1722: 1 failures, 13067ms
  [44/200] INSTR_WORD_MOD_FULL @ step 2914: 3 failures, 12981ms
  [45/200] COMP_OUT_MOD @ step 2607: 2 failures, 12858ms
  [46/200] INSTR_TYPE_MOD @ step 3293: 4 failures, 12902ms [bitmap:+36 exact:+37]
  [47/200] INSTR_WORD_MOD_SUR @ step 304: 1 failures, 13950ms
  [48/200] INSTR_WORD_MOD_SUR @ step 2619: 0 failures, 13174ms
  [49/200] COMP_OUT_MOD @ step 1899: 2 failures, 13678ms
  [50/200] COMP_OUT_MOD @ step 2963: 1 failures, 14780ms
  [51/200] STORE_OUT_MOD @ step 3740: 1 failures, 14890ms
  [52/200] INSTR_WORD_MOD_SUR @ step 1440: 0 failures, 14724ms
  [53/200] INSTR_TYPE_MOD @ step 0: 5 failures, 14219ms [bitmap:+34 exact:+36]
  [54/200] INSTR_WORD_MOD_FULL @ step 1730: 3 failures, 17160ms
  [55/200] COMP_OUT_MOD @ step 812: 2 failures, 13881ms
  [56/200] LOAD_VAL_MOD @ step 1603: 1 failures, 13857ms
  [57/200] LOAD_VAL_MOD @ step 3841: 2 failures, 13430ms
  [58/200] MEM_VAL_MOD @ step 2687: 2 failures, 13486ms
  [59/200] LOAD_VAL_MOD @ step 1872: 2 failures, 14060ms
  [60/200] INSTR_WORD_MOD_FULL @ step 1608: 3 failures, 14001ms
  [61/200] COMP_OUT_MOD @ step 3314: 1 failures, 13756ms
  [62/200] INSTR_WORD_MOD_FULL @ step 3929: 1 failures, 14235ms
  [63/200] LOAD_VAL_MOD @ step 625: 1 failures, 13556ms
  [64/200] INSTR_WORD_MOD_FULL @ step 1877: 3 failures, 13817ms
  [65/200] COMP_OUT_MOD @ step 2845: 2 failures, 14358ms
  [66/200] MEM_VAL_MOD @ step 2049: 2 failures, 13823ms
  [67/200] INSTR_WORD_MOD_SUR @ step 2993: 1 failures, 14049ms
  [68/200] INSTR_WORD_MOD_FULL @ step 3681: 13 failures, 13018ms
  [69/200] MEM_VAL_MOD @ step 381: 15 failures, 13754ms
  [70/200] STORE_OUT_MOD @ step 3400: 2 failures, 13557ms
  [71/200] INSTR_WORD_MOD_FULL @ step 3653: 4 failures, 13786ms
  [72/200] LOAD_VAL_MOD @ step 2286: 2 failures, 13653ms
  [73/200] STORE_OUT_MOD @ step 3338: 2 failures, 13469ms
  [74/200] MEM_VAL_MOD @ step 3929: 0 failures, 13950ms
  [75/200] LOAD_VAL_MOD @ step 3282: 2 failures, 14804ms
  [76/200] COMP_OUT_MOD @ step 3647: 1 failures, 13307ms
  [77/200] INSTR_WORD_MOD_FULL @ step 1411: 159 failures, 13191ms
  [78/200] INSTR_TYPE_MOD @ step 558: 5 failures, 13305ms [bitmap:+42 exact:+44]
  [79/200] MEM_VAL_MOD @ step 555: 2 failures, 13131ms
  [80/200] MEM_VAL_MOD @ step 1632: 1 failures, 13186ms
  [81/200] STORE_OUT_MOD @ step 2150: 2 failures, 13727ms
  [82/200] INSTR_WORD_MOD_FULL @ step 3412: 6 failures, 13380ms [bitmap:+2 exact:+2]
  [83/200] INSTR_WORD_MOD_FULL @ step 2006: 2 failures, 14203ms
  [84/200] COMP_OUT_MOD @ step 1277: 1 failures, 13222ms
  [85/200] STORE_OUT_MOD @ step 956: 1 failures, 15190ms
  [86/200] INSTR_WORD_MOD_SUR @ step 26: 1 failures, 13782ms
  [87/200] INSTR_TYPE_MOD @ step 3271: 2 failures, 15561ms
  [88/200] STORE_OUT_MOD @ step 3285: 2 failures, 13616ms
  [89/200] MEM_VAL_MOD @ step 2395: 4 failures, 13945ms
  [90/200] MEM_VAL_MOD @ step 215: 2 failures, 13680ms
  [91/200] MEM_VAL_MOD @ step 1888: 2 failures, 14474ms
  [92/200] INSTR_TYPE_MOD @ step 2772: 4 failures, 13670ms
  [93/200] MEM_VAL_MOD @ step 1293: 4 failures, 14030ms
  [94/200] INSTR_WORD_MOD_FULL @ step 3175: 5 failures, 14069ms
  [95/200] COMP_OUT_MOD @ step 1005: 2 failures, 14531ms
  [96/200] LOAD_VAL_MOD @ step 625: 2 failures, 14487ms
  [97/200] PRE_EXEC_REG_MOD @ step 1563: 4 failures, 15160ms
  [98/200] COMP_OUT_MOD @ step 975: 2 failures, 13868ms
  [99/200] PRE_EXEC_REG_MOD @ step 1567: 2 failures, 15346ms
  [100/200] PRE_EXEC_REG_MOD @ step 3813: 4 failures, 15271ms
  [101/200] MEM_VAL_MOD @ step 3358: 5 failures, 14361ms
  [102/200] MEM_VAL_MOD @ step 225: 3 failures, 14152ms
  [103/200] STORE_OUT_MOD @ step 191: 2 failures, 14719ms
  [104/200] INSTR_WORD_MOD_SUR @ step 1236: 0 failures, 14848ms
  [105/200] COMP_OUT_MOD @ step 3518: 2 failures, 14175ms
  [106/200] INSTR_TYPE_MOD @ step 2925: 8 failures, 14025ms [bitmap:+53 exact:+54]
  [107/200] INSTR_WORD_MOD_FULL @ step 2667: 2 failures, 14238ms
  [108/200] PRE_EXEC_REG_MOD @ step 3478: 2 failures, 14118ms
  [109/200] COMP_OUT_MOD @ step 3509: 2 failures, 14508ms
  [110/200] INSTR_WORD_MOD_SUR @ step 3911: 2 failures, 14490ms
  [111/200] COMP_OUT_MOD @ step 1602: 2 failures, 7779ms CRASH
  [112/200] MEM_VAL_MOD @ step 200: 4 failures, 14092ms
  [113/200] MEM_VAL_MOD @ step 1956: 2 failures, 14506ms
  [114/200] MEM_VAL_MOD @ step 1927: 6 failures, 13564ms [bitmap:+2 exact:+2]
  [115/200] PRE_EXEC_REG_MOD @ step 1540: 3 failures, 13884ms
  [116/200] MEM_VAL_MOD @ step 905: 2 failures, 13794ms
  [117/200] STORE_OUT_MOD @ step 103: 2 failures, 13750ms
  [118/200] INSTR_WORD_MOD_FULL @ step 3706: 2 failures, 14312ms
  [119/200] COMP_OUT_MOD @ step 3660: 2 failures, 14999ms
  [120/200] INSTR_WORD_MOD_FULL @ step 1196: 1 failures, 15456ms
  [121/200] INSTR_WORD_MOD_FULL @ step 3712: 2 failures, 14247ms
  [122/200] INSTR_TYPE_MOD @ step 3928: 4 failures, 14653ms [bitmap:+34 exact:+36]
  [123/200] INSTR_WORD_MOD_FULL @ step 944: 1 failures, 14095ms
  [124/200] MEM_VAL_MOD @ step 1168: 1 failures, 13958ms
  [125/200] INSTR_TYPE_MOD @ step 1730: 3 failures, 14213ms
  [126/200] COMP_OUT_MOD @ step 275: 2 failures, 14498ms
  [127/200] INSTR_WORD_MOD_FULL @ step 2050: 1 failures, 14974ms
  [128/200] COMP_OUT_MOD @ step 1776: 2 failures, 14175ms
  [129/200] INSTR_WORD_MOD_FULL @ step 3611: 4 failures, 16372ms
  [130/200] INSTR_TYPE_MOD @ step 1182: 6 failures, 14215ms [bitmap:+37 exact:+41]
  [131/200] PRE_EXEC_REG_MOD @ step 430: 2 failures, 14264ms
  [132/200] INSTR_TYPE_MOD @ step 2262: 2 failures, 14395ms [bitmap:+32 exact:+33]
  [133/200] PRE_EXEC_REG_MOD @ step 3341: 2 failures, 14353ms
  [134/200] INSTR_TYPE_MOD @ step 3891: 5 failures, 14134ms
  [135/200] COMP_OUT_MOD @ step 2441: 2 failures, 14364ms
  [136/200] INSTR_WORD_MOD_FULL @ step 1852: 2 failures, 14065ms
  [137/200] INSTR_WORD_MOD_SUR @ step 2350: 0 failures, 14946ms
  [138/200] COMP_OUT_MOD @ step 2621: 2 failures, 15353ms
  [139/200] INSTR_WORD_MOD_SUR @ step 638: 2 failures, 14800ms
  [140/200] MEM_VAL_MOD @ step 797: 1 failures, 14699ms
  [141/200] PRE_EXEC_REG_MOD @ step 1012: 4 failures, 14398ms
  [142/200] INSTR_WORD_MOD_SUR @ step 3929: 1 failures, 14337ms
  [143/200] COMP_OUT_MOD @ step 269: 1 failures, 13898ms
  [144/200] MEM_VAL_MOD @ step 762: 0 failures, 14183ms
  [145/200] PRE_EXEC_REG_MOD @ step 1183: 23 failures, 13987ms
  [146/200] INSTR_TYPE_MOD @ step 3400: 1 failures, 14453ms
  [147/200] INSTR_WORD_MOD_FULL @ step 2127: 0 failures, 14067ms
  [148/200] COMP_OUT_MOD @ step 1260: 2 failures, 13910ms
  [149/200] COMP_OUT_MOD @ step 2614: 1 failures, 13785ms
  [150/200] INSTR_WORD_MOD_SUR @ step 783: 0 failures, 13608ms
  [151/200] COMP_OUT_MOD @ step 3093: 2 failures, 13708ms
  [152/200] INSTR_TYPE_MOD @ step 1200: 5 failures, 13900ms [bitmap:+49 exact:+51]
  [153/200] INSTR_TYPE_MOD @ step 3027: 4 failures, 13673ms
  [154/200] INSTR_TYPE_MOD @ step 446: 6 failures, 13608ms [bitmap:+50 exact:+52]
  [155/200] PRE_EXEC_REG_MOD @ step 1912: 4 failures, 13665ms
  [156/200] INSTR_WORD_MOD_FULL @ step 1459: 1 failures, 14309ms
  [157/200] INSTR_WORD_MOD_FULL @ step 73: 4 failures, 14048ms
  [158/200] INSTR_WORD_MOD_SUR @ step 1459: 1 failures, 13432ms
  [159/200] INSTR_WORD_MOD_FULL @ step 884: 4 failures, 13595ms
  [160/200] MEM_VAL_MOD @ step 3399: 4 failures, 13408ms
  [161/200] INSTR_WORD_MOD_SUR @ step 393: 1 failures, 13681ms
  [162/200] PRE_EXEC_REG_MOD @ step 1356: 3 failures, 14357ms
  [163/200] PRE_EXEC_REG_MOD @ step 3230: 4 failures, 15184ms
  [164/200] LOAD_VAL_MOD @ step 2238: 1 failures, 13649ms
  [165/200] INSTR_WORD_MOD_FULL @ step 523: 3 failures, 13882ms [bitmap:+2 exact:+2]
  [166/200] COMP_OUT_MOD @ step 794: 2 failures, 13609ms
  [167/200] COMP_OUT_MOD @ step 27: 2 failures, 14589ms
  [168/200] INSTR_WORD_MOD_FULL @ step 3272: 0 failures, 13592ms
  [169/200] MEM_VAL_MOD @ step 133: 2 failures, 14357ms
  [170/200] COMP_OUT_MOD @ step 1245: 2 failures, 14105ms
  [171/200] PRE_EXEC_REG_MOD @ step 3875: 2 failures, 14119ms
  [172/200] INSTR_TYPE_MOD @ step 1683: 3 failures, 13543ms [bitmap:+35 exact:+37]
  [173/200] INSTR_TYPE_MOD @ step 635: 3 failures, 14232ms
  [174/200] COMP_OUT_MOD @ step 266: 2 failures, 15011ms
  [175/200] MEM_VAL_MOD @ step 3917: 2 failures, 13625ms
  [176/200] INSTR_WORD_MOD_SUR @ step 856: 0 failures, 13781ms
  [177/200] PRE_EXEC_REG_MOD @ step 1424: 2 failures, 14336ms
  [178/200] INSTR_WORD_MOD_FULL @ step 371: 2 failures, 12993ms
  [179/200] PRE_EXEC_REG_MOD @ step 1220: 2 failures, 14413ms
  [180/200] LOAD_VAL_MOD @ step 2305: 2 failures, 13775ms
  [181/200] INSTR_WORD_MOD_SUR @ step 949: 1 failures, 13655ms
  [182/200] LOAD_VAL_MOD @ step 1016: 2 failures, 14076ms
  [183/200] STORE_OUT_MOD @ step 2289: 2 failures, 19054ms
  [184/200] LOAD_VAL_MOD @ step 3216: 2 failures, 16073ms
  [185/200] INSTR_WORD_MOD_SUR @ step 3235: 1 failures, 15619ms
  [186/200] MEM_VAL_MOD @ step 3665: 4 failures, 14654ms
  [187/200] MEM_VAL_MOD @ step 1724: 2 failures, 14117ms
  [188/200] INSTR_WORD_MOD_FULL @ step 3929: 1 failures, 13929ms
  [189/200] COMP_OUT_MOD @ step 738: 2 failures, 14108ms
  [190/200] LOAD_VAL_MOD @ step 392: 2 failures, 14097ms
  [191/200] LOAD_VAL_MOD @ step 2144: 2 failures, 14806ms
  [192/200] MEM_VAL_MOD @ step 3448: 1 failures, 14986ms
  [193/200] PRE_EXEC_REG_MOD @ step 0: 10 failures, 14034ms
  [194/200] STORE_OUT_MOD @ step 28: 2 failures, 14040ms
  [195/200] INSTR_WORD_MOD_FULL @ step 331: 4 failures, 14015ms
  [196/200] STORE_OUT_MOD @ step 1324: 2 failures, 14368ms
  [197/200] INSTR_WORD_MOD_SUR @ step 1835: 0 failures, 14149ms
  [198/200] STORE_OUT_MOD @ step 3656: 2 failures, 14098ms
  [199/200] LOAD_VAL_MOD @ step 3864: 2 failures, 14193ms
  [200/200] MEM_VAL_MOD @ step 786: 2 failures, 15385ms

======================================================================
DIAGNOSTIC CAMPAIGN REPORT
======================================================================

Campaign: 200 runs, seed=123, 2808s total
Outcomes: 185 REJECTED, 2 CRASH, 13 NO_FAIL_BUT_REJECTED

--- TOUCH COVERAGE: BITMAP vs EXACT ---
Final bitmap distinct buckets: 2041
Final exact distinct triples:  2076
Hash collisions (exact - bitmap): 35

Runs with bitmap delta > 0: 16
Runs with exact delta > 0:  16

Bitmap vs exact DISAGREEMENTS (12 runs):
  Run 1 (COMP_OUT_MOD): bitmap_delta=1599, exact_delta=1614
  Run 25 (INSTR_TYPE_MOD): bitmap_delta=32, exact_delta=33
  Run 46 (INSTR_TYPE_MOD): bitmap_delta=36, exact_delta=37
  Run 53 (INSTR_TYPE_MOD): bitmap_delta=34, exact_delta=36
  Run 78 (INSTR_TYPE_MOD): bitmap_delta=42, exact_delta=44
  Run 106 (INSTR_TYPE_MOD): bitmap_delta=53, exact_delta=54
  Run 122 (INSTR_TYPE_MOD): bitmap_delta=34, exact_delta=36
  Run 130 (INSTR_TYPE_MOD): bitmap_delta=37, exact_delta=41
  Run 132 (INSTR_TYPE_MOD): bitmap_delta=32, exact_delta=33
  Run 152 (INSTR_TYPE_MOD): bitmap_delta=49, exact_delta=51
  Run 154 (INSTR_TYPE_MOD): bitmap_delta=50, exact_delta=52
  Run 172 (INSTR_TYPE_MOD): bitmap_delta=35, exact_delta=37

--- TOUCH DISCOVERY BY KIND ---
  COMP_OUT_MOD: 36 runs, 1 with new touch, +1614 total new triples
  LOAD_VAL_MOD: 21 runs, 0 with new touch, +0 total new triples
  STORE_OUT_MOD: 17 runs, 0 with new touch, +0 total new triples
  PRE_EXEC_REG_MOD: 18 runs, 0 with new touch, +0 total new triples
  INSTR_TYPE_MOD: 19 runs, 11 with new touch, +454 total new triples
  MEM_VAL_MOD: 33 runs, 1 with new touch, +2 total new triples
  INSTR_WORD_MOD_FULL: 34 runs, 2 with new touch, +4 total new triples
  INSTR_WORD_MOD_SUR: 22 runs, 1 with new touch, +2 total new triples

--- FAILURE ANALYSIS ---
Total failure instances: 656
Distinct constraint_loc families: 28
Distinct (loc, major, minor) context_ids: 163
n_fail: min=0, median=2, p75=3, max=159
Runs with new failure context_id: 62 of 200

--- MUTATIONS BY KIND ---
  COMP_OUT_MOD: 36
  LOAD_VAL_MOD: 21
  STORE_OUT_MOD: 17
  PRE_EXEC_REG_MOD: 18
  INSTR_TYPE_MOD: 19
  MEM_VAL_MOD: 33
  INSTR_WORD_MOD_FULL: 34
  INSTR_WORD_MOD_SUR: 22

--- EXACT TOUCH GROWTH CURVE ---
  After run 1: ~3228 exact triples (baseline=1614, +1614 new)
  After run 10: ~3228 exact triples (baseline=1614, +1614 new)
  After run 25: ~3261 exact triples (baseline=1614, +1647 new)
  After run 50: ~3300 exact triples (baseline=1614, +1686 new)
  After run 100: ~3382 exact triples (baseline=1614, +1768 new)
  After run 150: ~3548 exact triples (baseline=1614, +1934 new)
  After run 200: ~3690 exact triples (baseline=1614, +2076 new)

  Final: 2076 exact triples

Done.