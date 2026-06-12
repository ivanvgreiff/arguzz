(base) root@Ivan:~/arguzz# python -m a4.standalone.cli fuzz --host ./workspace/output/target/release/risc0-host --num 300 --kind all --seed 123 --db ./phase2_diagnostic_2.
db -- --in1 5 --in4 10
A4 Standalone Fuzzer
============================================================
Running inspection on /root/arguzz/workspace/output/target/release/risc0-host...
  Args: --in1 5 --in4 10
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

Starting campaign 1
  Mutations: 300
  Kind: all
  Seed: 123

  [1] ✓ COMP_OUT_MOD @ step 254: 2 failures, 29902ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new] [+1599 touch]
       Value: 0x00200370 -> 0x0D67B366
       Destination: rd = x8 (s0/fp)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16833, step=254, pc=0x002031A4, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=16833, step=254, pc=0x002031A4, major=0, minor=7
  [2] ✓ INSTR_TYPE_MOD @ step 2333: 4 failures, 27687ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000007 -> 0x00000002
       Original: AddI [major=0, minor=7]
       Mutated:  Xor [major=0, minor=2]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - MemoryWrite@mem.zir:100
           cycle=18987, step=2333, pc=0x0020320C, major=0, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18987, step=2333, pc=0x0020320C, major=0, minor=2
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=18987, step=2333, pc=0x0020320C, major=0, minor=2
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=18987, step=2333, pc=0x0020320C, major=0, minor=2
  [3] ✓ LOAD_VAL_MOD @ step 545: 2 failures, 26680ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x6840FF07
       Load destination: rd = x9 (s1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17148, step=545, pc=0x002031F4, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17148, step=545, pc=0x002031F4, major=5, minor=2
  [4] ✓ COMP_OUT_MOD @ step 1981: 2 failures, 27748ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0021BA92 -> 0x0023BAB2
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18630, step=1981, pc=0x002184CC, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=18630, step=1981, pc=0x002184CC, major=0, minor=7
  [5] ✓ INSTR_WORD_MOD_FULL @ step 2892: 2 failures, 30169ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0xFFFFC097 -> 0xFFFF8097
       Original: AUIPC x1, 0xffffc000
       Mutated:  AUIPC x1, 0xffff8000
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19620, step=2892, pc=0x0020538C, major=2, minor=6
         - MemoryWrite@mem.zir:99
           cycle=19620, step=2892, pc=0x0020538C, major=2, minor=6
  [6] ✓ INSTR_WORD_MOD_FULL @ step 7: 1 failures, 25482ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0xFFFF0237 -> 0xFFDF0237
       Original: LUI x4, 0xffff0000
       Mutated:  LUI x4, 0xffdf0000
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16580: preflight=0x3fffc01f, actual=0x3fffc01d
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=16580, step=7, pc=0xC0000020, major=2, minor=5
  [7] ✓ LOAD_VAL_MOD @ step 2203: 2 failures, 25411ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00202F58 -> 0x09C47055
       Load destination: rd = x1 (ra)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18857, step=2203, pc=0x00201ED0, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18857, step=2203, pc=0x00201ED0, major=5, minor=2
  [8] ✓ MEM_VAL_MOD @ step 1293: 2 failures, 24444ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x8C68059B -> 0x8C68059F
       Transaction: load_mem_read (READ) at address 0x00221384
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=17937, step=1293, pc=0x0020341C, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17937, step=1293, pc=0x0020341C, major=5, minor=2
  [9] ✓ LOAD_VAL_MOD @ step 943: 2 failures, 25698ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x550AE889
       Load destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17576, step=943, pc=0x00200A38, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17576, step=943, pc=0x00200A38, major=5, minor=2
  [10] ✓ INSTR_WORD_MOD_FULL @ step 384: 1 failures, 26769ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x02950063 -> 0x0A950063
       Original: BEQ x10, x9, 32
       Mutated:  BEQ x10, x9, 160
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16976: preflight=0x00080c78, actual=0x00080c98
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=16982, step=391, pc=0x00200890, major=2, minor=4
  [11] ✓ INSTR_WORD_MOD_FULL @ step 524: 1 failures, 25011ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000073 -> 0x00080073
       Original: ECALL x0, x0, 0
       Mutated:  ECALL x0, x16, 0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MachineECall@inst_ecall.zir:28
           cycle=17121, step=524, pc=0xC000014C, major=8, minor=0
  [12] ✓ INSTR_WORD_MOD_FULL @ step 88: 0 failures, 25064ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00B6AC23 -> 0x10B6AC23
       Original: SW x11, 24(x13)
       Mutated:  SW x11, 280(x13)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16661: preflight=0x000884f1, actual=0x00088531
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [13] ✓ COMP_OUT_MOD @ step 2586: 2 failures, 26131ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x000009F9 -> 0x9FF23606
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19314, step=2586, pc=0x00201554, major=0, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19314, step=2586, pc=0x00201554, major=0, minor=3
  [14] ✓ INSTR_WORD_MOD_FULL @ step 1100: 3 failures, 26499ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x0AD00693 -> 0xD5EEC913
       Original: ADDI x13, x0, 173
       Mutated:  XORI x18, x29, -674
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17744: preflight=0x3fffc020, actual=0x3fffc03d
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:100
           cycle=17744, step=1100, pc=0x00200C00, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=17744, step=1100, pc=0x00200C00, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:97
           cycle=17744, step=1100, pc=0x00200C00, major=0, minor=7
  [15] ✓ MEM_VAL_MOD @ step 1407: 2 failures, 24147ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x9220221F
       Transaction: other_mem_write (WRITE) at address 0xffff0180
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18051, step=1407, pc=0x002184C8, major=1, minor=6
         - MemoryWrite@mem.zir:99
           cycle=18051, step=1407, pc=0x002184C8, major=1, minor=6
  [16] ✓ MEM_VAL_MOD @ step 1979: 1 failures, 26950ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x544B4341 -> 0x544C4341
       Transaction: load_mem_read (READ) at address 0x0021ba90
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - IsRead@mem.zir:80
           cycle=18628, step=1979, pc=0x002184C4, major=5, minor=3
  [17] ✓ STORE_OUT_MOD @ step 3577: 2 failures, 29632ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000310 -> 0xDA22594F
       Store address: 0x0020018c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20453, step=3577, pc=0x00205628, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20453, step=3577, pc=0x00205628, major=6, minor=2
  [18] ✓ INSTR_WORD_MOD_FULL @ step 1305: 0 failures, 26996ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00867593 -> 0x008E7593
       Original: ANDI x11, x12, 8
       Mutated:  ANDI x11, x28, 8
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17949: preflight=0x3fffc02c, actual=0x3fffc03c
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [19] ✓ MEM_VAL_MOD @ step 0: 10 failures, 28256ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+10 new]
       Value: 0x00000000 -> 0x75CDD743
       Transaction: other_mem_read (READ) at address 0x00200290
       zkVM errors (2 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=2281, step=0, pc=0x00000000, major=9, minor=2
         - IsRead@mem.zir:80
           cycle=2281, step=0, pc=0x00000000, major=9, minor=2
         - PoseidonCheckOut@inst_p2.zir:265 (x8)
           cycle=2401, step=0, pc=0x00000000, major=9, minor=5
  [20] ✓ MEM_VAL_MOD @ step 1992: 3 failures, 25016ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x544B4341 -> 0xBBF0EF77
       Transaction: load_mem_read (READ) at address 0x0021b15c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=18641, step=1992, pc=0x002184C0, major=5, minor=3
         - IsRead@mem.zir:80
           cycle=18641, step=1992, pc=0x002184C0, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18641, step=1992, pc=0x002184C0, major=5, minor=3
  [21] ✓ INSTR_TYPE_MOD @ step 1744: 3 failures, 26788ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new] [+35 touch]
       Value: 0x00050003 -> 0x00010003
       Original: LbU [major=5, minor=3]
       Mutated:  SltI [major=1, minor=3]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18388: preflight=0x00086e9f, actual=0x3fffc020
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:99
           cycle=18388, step=1744, pc=0x002184C4, major=1, minor=3
         - VerifyOpcodeF3@inst.zir:96
           cycle=18388, step=1744, pc=0x002184C4, major=1, minor=3
         - VerifyOpcodeF3@inst.zir:97
           cycle=18388, step=1744, pc=0x002184C4, major=1, minor=3
  [22] ✓ MEM_VAL_MOD @ step 131: 2 failures, 24198ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x28DFA298
       Transaction: store_rmw_read (READ) at address 0x00221374
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=16704, step=131, pc=0x002010CC, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=16704, step=131, pc=0x002010CC, major=6, minor=2
  [23] ✓ INSTR_WORD_MOD_FULL @ step 2661: 0 failures, 25904ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x01068693 -> 0x01028693
       Original: ADDI x13, x13, 16
       Mutated:  ADDI x13, x5, 16
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19389: preflight=0x3fffc02d, actual=0x3fffc025
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [24] ✓ LOAD_VAL_MOD @ step 787: 2 failures, 25796ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000005 -> 0x3EC3068C
       Load destination: rd = x22 (s6)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17408, step=787, pc=0x002009C8, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17408, step=787, pc=0x002009C8, major=5, minor=2
  [25] ✓ PRE_EXEC_REG_MOD @ step 2727: 3 failures, 24427ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00200300 -> 0x13A45745
       Register: x2 (sp), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19455: preflight=0x000800d8, actual=0x04e915e9
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=19455, step=2727, pc=0x002016A8, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=19455, step=2727, pc=0x002016A8, major=5, minor=2
         - OpLW@inst_mem.zir:108
           cycle=19455, step=2727, pc=0x002016A8, major=5, minor=2
  [26] ✓ COMP_OUT_MOD @ step 1967: 2 failures, 24398ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0021BA90 -> 0x98FC4743
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18616, step=1967, pc=0x002184CC, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=18616, step=1967, pc=0x002184CC, major=0, minor=7
  [27] ✓ PRE_EXEC_REG_MOD @ step 1628: 2 failures, 26582ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xB6179BA7
       Register: x31 (t6), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18272, step=1628, pc=0x002047CC, major=2, minor=6
         - IsRead@mem.zir:80
           cycle=18272, step=1628, pc=0x002047CC, major=2, minor=6
  [28] ✓ PRE_EXEC_REG_MOD @ step 2993: 4 failures, 24567ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0xC0000000 -> 0x11E374EE
       Register: x12 (a2), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=19721, step=2993, pc=0x00205E2C, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=19721, step=2993, pc=0x00205E2C, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=19721, step=2993, pc=0x00205E2C, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=19721, step=2993, pc=0x00205E2C, major=0, minor=7
  [29] ✓ MEM_VAL_MOD @ step 362: 4 failures, 25529ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000000 -> 0xA9C86953
       Transaction: other_mem_read (READ) at address 0xffff0000
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=16947, step=362, pc=0xC0000138, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=16947, step=362, pc=0xC0000138, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=16947, step=362, pc=0xC0000138, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=16947, step=362, pc=0xC0000138, major=0, minor=7
  [30] ✓ MEM_VAL_MOD @ step 1489: 2 failures, 28275ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x8C68059B -> 0x842805AB
       Transaction: load_mem_read (READ) at address 0x00200324
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18133, step=1489, pc=0x002184C0, major=5, minor=3
         - IsRead@mem.zir:80
           cycle=18133, step=1489, pc=0x002184C0, major=5, minor=3
  [31] ✓ STORE_OUT_MOD @ step 2693: 2 failures, 27299ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0xC3D4E0D9 -> 0x3C2B1F27
       Store address: 0x0020034c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19421, step=2693, pc=0x00201610, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19421, step=2693, pc=0x00201610, major=6, minor=2
  [32] ✓ INSTR_WORD_MOD_SUR @ step 3929: 2 failures, 25793ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000073 -> 0x000C8073
       Surgical: rs1 = 0 -> 25
       Original: ECALL x0, x0, 0
       Mutated:  ECALL x0, x25, 0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MachineECall@inst_ecall.zir:28
           cycle=20879, step=3929, pc=0xC00000F8, major=8, minor=0
         - MachineECall@inst_ecall.zir:29
           cycle=20879, step=3929, pc=0xC00000F8, major=8, minor=0
  [33] ✓ COMP_OUT_MOD @ step 3071: 2 failures, 24389ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x01010000 -> 0x72C53633
       Destination: rd = x14 (a4)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19799, step=3071, pc=0x00203258, major=2, minor=5
         - MemoryWrite@mem.zir:99
           cycle=19799, step=3071, pc=0x00203258, major=2, minor=5
  [34] ✓ INSTR_TYPE_MOD @ step 3928: 5 failures, 23727ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+5 new] [+53 touch]
       Value: 0x00000007 -> 0x00040005
       Original: AddI [major=0, minor=7]
       Mutated:  DivU [major=4, minor=5]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (5 unique):
         - MemoryWrite@mem.zir:100
           cycle=20878, step=3928, pc=0xC00000F8, major=4, minor=5
         - MemoryWrite@mem.zir:99
           cycle=20878, step=3928, pc=0xC00000F8, major=4, minor=5
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20878, step=3928, pc=0xC00000F8, major=4, minor=5
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20878, step=3928, pc=0xC00000F8, major=4, minor=5
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=20878, step=3928, pc=0xC00000F8, major=4, minor=5
  [35] ✓ INSTR_WORD_MOD_FULL @ step 736: 1 failures, 24261ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x0021A637 -> 0x1021A637
       Original: LUI x12, 0x21a000
       Mutated:  LUI x12, 0x1021a000
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=17351, step=736, pc=0x0020614C, major=2, minor=5
  [36] ✓ STORE_OUT_MOD @ step 3659: 2 failures, 25265ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xE7C834D3
       Store address: 0x0022161c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20535, step=3659, pc=0x00203438, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20535, step=3659, pc=0x00203438, major=6, minor=2
  [37] ✓ COMP_OUT_MOD @ step 2906: 2 failures, 24688ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000001 -> 0xFFFFFFFE
       Destination: rd = x14 (a4)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19634, step=2906, pc=0x00205E0C, major=1, minor=4
         - MemoryWrite@mem.zir:99
           cycle=19634, step=2906, pc=0x00205E0C, major=1, minor=4
  [38] ✓ INSTR_WORD_MOD_SUR @ step 88: 0 failures, 25282ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00B6AC23 -> 0x00B3AC23
       Surgical: rs1 = 13 -> 7
       Original: SW x11, 24(x13)
       Mutated:  SW x11, 24(x7)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16661: preflight=0x3fffc02d, actual=0x3fffc027
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [39] ✓ COMP_OUT_MOD @ step 2612: 2 failures, 23635ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00200300 -> 0x246595DF
       Destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19340, step=2612, pc=0x002015BC, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=19340, step=2612, pc=0x002015BC, major=0, minor=7
  [40] ✓ MEM_VAL_MOD @ step 2: 2 failures, 25510ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xFFFFFDE7
       Transaction: other_mem_read (READ) at address 0xffff007c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=16575, step=2, pc=0xC000000C, major=2, minor=5
         - IsRead@mem.zir:80
           cycle=16575, step=2, pc=0xC000000C, major=2, minor=5
  [41] ✓ MEM_VAL_MOD @ step 2602: 3 failures, 24356ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0xC3D4E0D9 -> 0x056FB885
       Transaction: load_mem_read (READ) at address 0x002214ac
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=19330, step=2602, pc=0x00201594, major=5, minor=3
         - IsRead@mem.zir:80
           cycle=19330, step=2602, pc=0x00201594, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19330, step=2602, pc=0x00201594, major=5, minor=3
  [42] ✓ MEM_VAL_MOD @ step 1936: 1 failures, 24317ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x55522E74 -> 0x55522E7C
       Transaction: load_mem_read (READ) at address 0x0021b154
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - IsRead@mem.zir:79
           cycle=18585, step=1936, pc=0x002184C0, major=5, minor=3
  [43] ✓ PRE_EXEC_REG_MOD @ step 0: 9 failures, 25724ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+9 new]
       Value: 0x00000000 -> 0x00000020
       Register: x28 (t3), READ, strategy=next_read
       zkVM errors (2 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=15997, step=0, pc=0x00000000, major=9, minor=2
         - PoseidonCheckOut@inst_p2.zir:265 (x8)
           cycle=16247, step=0, pc=0x00000000, major=9, minor=5
  [44] ✓ MEM_VAL_MOD @ step 672: 4 failures, 24930ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000002 -> 0xBFDF7EFF
       Transaction: other_mem_read (READ) at address 0xffff0028
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=17281, step=672, pc=0xC000007C, major=3, minor=1
         - IsRead@mem.zir:80
           cycle=17281, step=672, pc=0xC000007C, major=3, minor=1
         - MemoryWrite@mem.zir:100
           cycle=17281, step=672, pc=0xC000007C, major=3, minor=1
         - MemoryWrite@mem.zir:99
           cycle=17281, step=672, pc=0xC000007C, major=3, minor=1
  [45] ✓ STORE_OUT_MOD @ step 2835: 2 failures, 24002ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xFFFFFFFF
       Store address: 0x002002b4
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19563, step=2835, pc=0x00203BBC, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19563, step=2835, pc=0x00203BBC, major=6, minor=2
  [46] ✓ INSTR_WORD_MOD_FULL @ step 3584: 0 failures, 24239ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00177713 -> 0x10177713
       Original: ANDI x14, x14, 1
       Mutated:  ANDI x14, x14, 257
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Proof verification failed (no local constraint failures)
  [47] ✓ INSTR_WORD_MOD_FULL @ step 1538: 1 failures, 24233ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00054683 -> 0x05144683
       Original: LBU x13, 0(x10)
       Mutated:  LBU x13, 81(x8)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18182: preflight=0x3fffc02a, actual=0x3fffc028
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18182, step=1538, pc=0x002184C0, major=5, minor=3
  [48] ✓ MEM_VAL_MOD @ step 3048: 5 failures, 24700ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+5 new]
       Value: 0xA88080E7 -> 0xE9412995
       Transaction: other_mem_read (READ) at address 0x00205778
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19776: preflight=0x3fffc021, actual=0x3fffc022
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - IsRead@mem.zir:79
           cycle=19776, step=3048, pc=0x002031FC, major=2, minor=4
         - IsRead@mem.zir:80
           cycle=19776, step=3048, pc=0x002031FC, major=2, minor=4
         - MemoryWrite@mem.zir:99
           cycle=19825, step=3097, pc=0x0020577C, major=2, minor=4
         - VerifyOpcodeF3@inst.zir:96
           cycle=19776, step=3048, pc=0x002031FC, major=2, minor=4
         - VerifyOpcodeF3@inst.zir:97
           cycle=19776, step=3048, pc=0x002031FC, major=2, minor=4
  [49] ✓ INSTR_WORD_MOD_SUR @ step 3622: 0 failures, 25048ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x02B56063 -> 0x02BE6063
       Surgical: rs1 = 10 -> 28
       Original: BLTU x10, x11, 32
       Mutated:  BLTU x28, x11, 32
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20498: preflight=0x3fffc02a, actual=0x3fffc03c
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [50] ✓ MEM_VAL_MOD @ step 3752: 1 failures, 25708ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x80000000
       Transaction: other_mem_write (WRITE) at address 0xffff0180
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=20628, step=3752, pc=0x00205788, major=1, minor=6
  [51] ✓ INSTR_WORD_MOD_SUR @ step 3442: 0 failures, 25247ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x015985B3 -> 0x011985B3
       Surgical: rs2 = 21 -> 17
       Original: ADD x11, x19, x21
       Mutated:  ADD x11, x19, x17
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20244: preflight=0x3fffc035, actual=0x3fffc031
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [52] ✓ MEM_VAL_MOD @ step 519: 4 failures, 25007ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0xFFFF0080 -> 0x04046F7F
       Transaction: load_mem_read (READ) at address 0xffff0010
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17116: preflight=0x3fffc02c, actual=0x01011beb
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=17116, step=519, pc=0xC000013C, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=17116, step=519, pc=0xC000013C, major=5, minor=2
         - OpLW@inst_mem.zir:108
           cycle=17116, step=519, pc=0xC000013C, major=5, minor=2
         - OpLW@inst_mem.zir:109
           cycle=17116, step=519, pc=0xC000013C, major=5, minor=2
  [53] ✓ STORE_OUT_MOD @ step 2618: 2 failures, 25932ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x002015CC -> 0xFFDFEA33
       Store address: 0x002002fc
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19346, step=2618, pc=0x002052EC, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19346, step=2618, pc=0x002052EC, major=6, minor=2
  [54] ✓ LOAD_VAL_MOD @ step 3847: 1 failures, 24118ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x7FA793F3 -> 0x7FA783D3
       Load destination: rd = x12 (a2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=20797, step=3847, pc=0x00204D54, major=5, minor=2
  [55] ✓ COMP_OUT_MOD @ step 376: 2 failures, 25040ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x315F15D5
       Destination: rd = x6 (t1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16967, step=376, pc=0x002061B0, major=0, minor=1
         - MemoryWrite@mem.zir:99
           cycle=16967, step=376, pc=0x002061B0, major=0, minor=1
  [56] ✓ INSTR_WORD_MOD_FULL @ step 1877: 1 failures, 26258ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x80000537 -> 0x00000537
       Original: LUI x10, 0x80000000
       Mutated:  LUI x10, 0x0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=18526, step=1877, pc=0x0020AF44, major=2, minor=5
  [57] ✓ PRE_EXEC_REG_MOD @ step 1457: 4 failures, 25088ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00219E84 -> 0x00004000
       Register: x11 (a1), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=18101, step=1457, pc=0x002184CC, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=18101, step=1457, pc=0x002184CC, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=18101, step=1457, pc=0x002184CC, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=18101, step=1457, pc=0x002184CC, major=0, minor=7
  [58] ✓ COMP_OUT_MOD @ step 2845: 2 failures, 26582ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00204BE0 -> 0xFFFD9453
       Destination: rd = x1 (ra)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19573, step=2845, pc=0x00203BE4, major=2, minor=6
         - MemoryWrite@mem.zir:99
           cycle=19573, step=2845, pc=0x00203BE4, major=2, minor=6
  [59] ✓ PRE_EXEC_REG_MOD @ step 3274: 3 failures, 23662ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x0022156C -> 0x00000020
       Register: x13 (a3), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20076: preflight=0x0008855e, actual=0x0000000b
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - AddrDecomposeBits@u32.zir:87
           cycle=20076, step=3274, pc=0x00203438, major=6, minor=2
         - IsRead@mem.zir:79
           cycle=20076, step=3274, pc=0x00203438, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=20076, step=3274, pc=0x00203438, major=6, minor=2
  [60] ✓ LOAD_VAL_MOD @ step 1296: 1 failures, 25365ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x000000FF
       Load destination: rd = x5 (t0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=17940, step=1296, pc=0x00203428, major=5, minor=2
  [61] ✓ INSTR_WORD_MOD_FULL @ step 3591: 1 failures, 25126ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00275713 -> 0x00275717
       Original: SRLI x14, x14, 2
       Mutated:  AUIPC x14, 0x275000
       Format changed: I -> U
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20467, step=3591, pc=0x00205680, major=4, minor=2
  [62] ✓ INSTR_WORD_MOD_FULL @ step 2295: 4 failures, 24916ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00B6A023 -> 0x07AACBE3
       Original: SW x11, 0(x13)
       Mutated:  BLT x21, x26, 2166
       Format changed: S -> B
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18949: preflight=0x3fffc02d, actual=0x3fffc035
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (4 unique):
         - OpSW@inst_mem.zir:160
           cycle=18949, step=2295, pc=0x00203478, major=6, minor=2
         - OpSW@inst_mem.zir:161
           cycle=18949, step=2295, pc=0x00203478, major=6, minor=2
         - VerifyOpcodeF3@inst.zir:96
           cycle=18949, step=2295, pc=0x00203478, major=6, minor=2
         - VerifyOpcodeF3@inst.zir:97
           cycle=18949, step=2295, pc=0x00203478, major=6, minor=2
  [63] ✓ PRE_EXEC_REG_MOD @ step 2078: 4 failures, 25588ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x80000000 -> 0xFFFFFFFF
       Register: x10 (a0), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18733: preflight=0x00082bf4, actual=0x00082be5
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=18732, step=2078, pc=0x0020AFD0, major=1, minor=5
         - IsRead@mem.zir:80
           cycle=18732, step=2078, pc=0x0020AFD0, major=1, minor=5
         - MemoryWrite@mem.zir:99 (x2)
           cycle=18741, step=2087, pc=0x0020B0E8, major=2, minor=3
  [64] ✓ INSTR_TYPE_MOD @ step 3007: 4 failures, 27043ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00020006 -> 0x00020003
       Original: Auipc [major=2, minor=6]
       Mutated:  Jal [major=2, minor=3]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19736: preflight=0x000815d5, actual=0x000811d3
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - DecodeInst@inst.zir:29
           cycle=19736, step=3008, pc=0x002032F4, major=2, minor=4
         - MemoryWrite@mem.zir:99 (x2)
           cycle=19735, step=3007, pc=0x00205754, major=2, minor=3
         - VerifyOpcode@inst.zir:91
           cycle=19735, step=3007, pc=0x00205754, major=2, minor=3
  [65] ✓ INSTR_TYPE_MOD @ step 3695: 1 failures, 24553ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new] [+35 touch]
       Value: 0x00060000 -> 0x00060001
       Original: Sb [major=6, minor=0]
       Mutated:  Sh [major=6, minor=1]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:97
           cycle=20571, step=3695, pc=0x00205768, major=6, minor=1
  [66] ✓ COMP_OUT_MOD @ step 538: 1 failures, 25781ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000004 -> 0x00000010
       Destination: rd = x9 (s1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=17141, step=538, pc=0x002031BC, major=3, minor=1
  [67] ✓ MEM_VAL_MOD @ step 1631: 2 failures, 23926ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x5FFFFFF6
       Transaction: store_rmw_read (READ) at address 0x0020011c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18275, step=1631, pc=0x002024B8, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=18275, step=1631, pc=0x002024B8, major=6, minor=2
  [68] ✓ INSTR_WORD_MOD_SUR @ step 3929: 1 failures, 23949ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000073 -> 0x00000D73
       Surgical: rd = 0 -> 26
       Original: ECALL x0, x0, 0
       Mutated:  ECALL x26, x0, 0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MachineECall@inst_ecall.zir:29
           cycle=20879, step=3929, pc=0xC00000F8, major=8, minor=0
  [69] ✓ PRE_EXEC_REG_MOD @ step 3685: 2 failures, 27587ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00200160 -> 0x00001000
       Register: x2 (sp), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=20561, step=3685, pc=0x002035F4, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=20561, step=3685, pc=0x002035F4, major=0, minor=7
  [70] ✓ INSTR_WORD_MOD_FULL @ step 805: 1 failures, 24573ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00068613 -> 0x40068613
       Original: ADDI x12, x13, 0
       Mutated:  ADDI x12, x13, 1024
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=17426, step=805, pc=0x002031B0, major=0, minor=7
  [71] ✓ INSTR_WORD_MOD_SUR @ step 957: 1 failures, 25553ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00912223 -> 0x00912237
       Surgical: opcode = 35 -> 55
       Original: SW x9, 4(x2)
       Mutated:  LUI x4, 0x912000
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:96
           cycle=17590, step=957, pc=0x00203198, major=6, minor=2
  [72] ✓ LOAD_VAL_MOD @ step 2007: 2 failures, 24374ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000041 -> 0x01000049
       Load destination: rd = x14 (a4)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18656, step=2007, pc=0x002184C4, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18656, step=2007, pc=0x002184C4, major=5, minor=3
  [73] ✓ STORE_OUT_MOD @ step 3730: 2 failures, 24743ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x92CADF50
       Store address: 0x00221638
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20606, step=3730, pc=0x00203274, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20606, step=3730, pc=0x00203274, major=6, minor=2
  [74] ✓ LOAD_VAL_MOD @ step 3164: 2 failures, 24826ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00205460 -> 0x00400000
       Load destination: rd = x1 (ra)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19966, step=3164, pc=0x00205820, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19966, step=3164, pc=0x00205820, major=5, minor=2
  [75] ✓ INSTR_WORD_MOD_SUR @ step 3716: 0 failures, 25345ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x0AF66C63 -> 0x0AF0EC63
       Surgical: rs1 = 12 -> 1
       Original: BLTU x12, x15, 184
       Mutated:  BLTU x1, x15, 184
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20592: preflight=0x3fffc02c, actual=0x3fffc021
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [76] ✓ INSTR_WORD_MOD_SUR @ step 3010: 0 failures, 24639ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x0016B693 -> 0x34B6B693
       Surgical: imm = 1 -> 843
       Original: SLTIU x13, x13, 1
       Mutated:  SLTIU x13, x13, 843
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19738: preflight=0x3fffc021, actual=0x3fffc02b
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [77] ✓ INSTR_TYPE_MOD @ step 117: 2 failures, 26189ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000007 -> 0x00000000
       Original: AddI [major=0, minor=7]
       Mutated:  Add [major=0, minor=0]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:99
           cycle=16690, step=117, pc=0x00201094, major=0, minor=0
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=16690, step=117, pc=0x00201094, major=0, minor=0
  [78] ✓ LOAD_VAL_MOD @ step 3398: 2 failures, 25066ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x43EC1F85
       Load destination: rd = x17 (a7)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20200, step=3398, pc=0x00203424, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20200, step=3398, pc=0x00203424, major=5, minor=2
  [79] ✓ LOAD_VAL_MOD @ step 2089: 1 failures, 26167ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000018 -> 0x0000001A
       Load destination: rd = x8 (s0/fp)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18743, step=2089, pc=0x0020B0F0, major=5, minor=2
  [80] ✓ MEM_VAL_MOD @ step 3789: 1 failures, 25286ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0xFFFF0080 -> 0xFFFF007C
       Transaction: load_mem_read (READ) at address 0xffff0010
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20665: preflight=0x3fffc02d, actual=0x3fffc02c
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (1 unique):
         - IsRead@mem.zir:79
           cycle=20665, step=3789, pc=0xC0000180, major=5, minor=2
  [81] ✓ PRE_EXEC_REG_MOD @ step 2632: 1 failures, 24233ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00800000
       Register: x0 (zero), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - IsRead@mem.zir:80
           cycle=19360, step=2632, pc=0x00203400, major=0, minor=7
  [82] ✓ STORE_OUT_MOD @ step 3285: 2 failures, 28831ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0xA33DE65B -> 0xD67C8720
       Store address: 0x00221584
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20087, step=3285, pc=0x00203434, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20087, step=3285, pc=0x00203434, major=6, minor=2
  [83] ✓ INSTR_WORD_MOD_FULL @ step 2410: 1 failures, 25124ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x02050593 -> 0x42050593
       Original: ADDI x11, x10, 32
       Mutated:  ADDI x11, x10, 1056
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=19064, step=2410, pc=0x0020560C, major=0, minor=7
  [84] ✓ INSTR_WORD_MOD_SUR @ step 217: 1 failures, 25890ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00221737 -> 0x00221701
       Surgical: opcode = 55 -> 1
       Original: LUI x14, 0x221000
       Mutated:  UNKNOWN 0x00221701
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcode@inst.zir:91
           cycle=16796, step=217, pc=0x0020B8FC, major=2, minor=5
  [85] ✓ STORE_OUT_MOD @ step 3061: 2 failures, 23869ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xDBFC4F88
       Store address: 0x0022153c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19789, step=3061, pc=0x00203230, major=6, minor=0
         - MemoryWrite@mem.zir:99
           cycle=19789, step=3061, pc=0x00203230, major=6, minor=0
  [86] ✓ LOAD_VAL_MOD @ step 2536: 2 failures, 24207ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x000000E3 -> 0xFFF7EF5C
       Load destination: rd = x12 (a2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19264, step=2536, pc=0x0020148C, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19264, step=2536, pc=0x0020148C, major=5, minor=3
  [87] ✓ MEM_VAL_MOD @ step 1406: 3 failures, 24801ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x72F36E3C -> 0xC4CFBB8A
       Transaction: load_mem_read (READ) at address 0x00219e7c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=18050, step=1406, pc=0x002184C4, major=5, minor=3
         - IsRead@mem.zir:80
           cycle=18050, step=1406, pc=0x002184C4, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18050, step=1406, pc=0x002184C4, major=5, minor=3
  [88] ✓ LOAD_VAL_MOD @ step 1461: 2 failures, 24168ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0000000E -> 0x9DECBBF1
       Load destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18105, step=1461, pc=0x002184C0, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18105, step=1461, pc=0x002184C0, major=5, minor=3
  [89] ✓ STORE_OUT_MOD @ step 1300: 2 failures, 24621ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x388B73CC
       Store address: 0x00200330
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17944, step=1300, pc=0x00203438, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17944, step=1300, pc=0x00203438, major=6, minor=2
  [90] ✓ PRE_EXEC_REG_MOD @ step 3335: 4 failures, 24543ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0xC3D4E0D9 -> 0x38AB0C22
       Register: x15 (a5), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=20137, step=3335, pc=0x0020342C, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=20137, step=3335, pc=0x0020342C, major=6, minor=2
         - MemoryWrite@mem.zir:100
           cycle=20137, step=3335, pc=0x0020342C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20137, step=3335, pc=0x0020342C, major=6, minor=2
  [91] ✓ INSTR_WORD_MOD_FULL @ step 1712: 1 failures, 24554ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0xFFF60613 -> 0xFF760613
       Original: ADDI x12, x12, -1
       Mutated:  ADDI x12, x12, -9
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18356: preflight=0x3fffc03f, actual=0x3fffc037
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18356, step=1712, pc=0x002184D0, major=0, minor=7
  [92] ✓ INSTR_WORD_MOD_FULL @ step 1101: 4 failures, 27274ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x0BE00713 -> 0xDC47BCEF
       Original: ADDI x14, x0, 190
       Mutated:  JAL x25, -543292
       Format changed: I -> J
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17745: preflight=0x3fffc020, actual=0x3fffc02f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (4 unique):
         - MemoryWrite@mem.zir:100
           cycle=17745, step=1101, pc=0x00200C04, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=17745, step=1101, pc=0x00200C04, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:96
           cycle=17745, step=1101, pc=0x00200C04, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:97
           cycle=17745, step=1101, pc=0x00200C04, major=0, minor=7
  [93] ✓ LOAD_VAL_MOD @ step 1398: 2 failures, 25370ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0000003C -> 0xCD2EE163
       Load destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18042, step=1398, pc=0x002184C0, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18042, step=1398, pc=0x002184C0, major=5, minor=3
  [94] ✓ PRE_EXEC_REG_MOD @ step 1567: 2 failures, 23917ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x50B51605
       Register: x0 (zero), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18211, step=1567, pc=0x00202C04, major=2, minor=4
         - IsRead@mem.zir:80
           cycle=18211, step=1567, pc=0x00202C04, major=2, minor=4
  [95] ✓ PRE_EXEC_REG_MOD @ step 3813: 2 failures, 25684ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000010 -> 0x00000200
       Register: x23 (s7), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=20763, step=3813, pc=0x00205814, major=3, minor=1
         - MemoryWrite@mem.zir:99
           cycle=20763, step=3813, pc=0x00205814, major=3, minor=1
  [96] ✓ COMP_OUT_MOD @ step 1527: 2 failures, 23920ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00219E8F -> 0x8343B946
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18171, step=1527, pc=0x002184CC, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=18171, step=1527, pc=0x002184CC, major=0, minor=7
  [97] ✓ INSTR_TYPE_MOD @ step 2511: 9 failures, 24298ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+9 new] [+33 touch]
       Value: 0x00050002 -> 0x0002000B
       Original: Lw [major=5, minor=2]
       Mutated:  MulH [major=2, minor=11] ⚠INVALID
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19239: preflight=0x000800bd, actual=0x3fffc034
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - AddrDecompose@u32.zir:67 (x4)
           cycle=19240, step=2512, pc=0x002055D4, major=5, minor=2
         - MemoryWrite@mem.zir:100
           cycle=19243, step=2515, pc=0x00201440, major=2, minor=4
         - MemoryWrite@mem.zir:99 (x2)
           cycle=19239, step=2511, pc=0x002055D0, major=2, minor=11
         - OneHot@one_hot.zir:11
           cycle=19239, step=2511, pc=0x002055D0, major=2, minor=11
         - OneHot@one_hot.zir:9
           cycle=19239, step=2511, pc=0x002055D0, major=2, minor=11
  [98] ✓ STORE_OUT_MOD @ step 2749: 1 failures, 25602ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0xBCE109F9 -> 0xBCE109FD
       Store address: 0x0020030c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=19477, step=2749, pc=0x00201700, major=6, minor=2
  [99] ✓ INSTR_WORD_MOD_FULL @ step 1604: 1 failures, 24745ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00100593 -> 0x00300593
       Original: ADDI x11, x0, 1
       Mutated:  ADDI x11, x0, 3
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18248: preflight=0x3fffc021, actual=0x3fffc023
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18248, step=1604, pc=0x00204030, major=0, minor=7
  [100] ✓ INSTR_TYPE_MOD @ step 1934: 3 failures, 24182ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00000007 -> 0x00010005
       Original: AddI [major=0, minor=7]
       Mutated:  Beq [major=1, minor=5]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18583: preflight=0x3fffc02a, actual=0x3fffc060
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:100
           cycle=18583, step=1934, pc=0x002184D4, major=1, minor=5
         - MemoryWrite@mem.zir:99
           cycle=18583, step=1934, pc=0x002184D4, major=1, minor=5
         - VerifyOpcodeF3@inst.zir:96
           cycle=18583, step=1934, pc=0x002184D4, major=1, minor=5
  [101] ✓ COMP_OUT_MOD @ step 1913: 2 failures, 24438ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xAB20DD48
       Destination: rd = x18 (s2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18562, step=1913, pc=0x00205F7C, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=18562, step=1913, pc=0x00205F7C, major=0, minor=7
  [102] ✓ INSTR_TYPE_MOD @ step 1851: 3 failures, 24290ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00000007 -> 0x00020004
       Original: AddI [major=0, minor=7]
       Mutated:  JalR [major=2, minor=4]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18498: preflight=0x30000056, actual=0x3fffc02a
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:100
           cycle=18497, step=1851, pc=0xC0000158, major=2, minor=4
         - MemoryWrite@mem.zir:99
           cycle=18497, step=1851, pc=0xC0000158, major=2, minor=4
         - VerifyOpcodeF3@inst.zir:96
           cycle=18497, step=1851, pc=0xC0000158, major=2, minor=4
  [103] ✓ MEM_VAL_MOD @ step 1800: 3 failures, 25747ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x4152544B -> 0xFAADABB4
       Transaction: load_mem_read (READ) at address 0x0021ba84
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=18444, step=1800, pc=0x002184C4, major=5, minor=3
         - IsRead@mem.zir:80
           cycle=18444, step=1800, pc=0x002184C4, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18444, step=1800, pc=0x002184C4, major=5, minor=3
  [104] ✓ LOAD_VAL_MOD @ step 2093: 1 failures, 24540ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00000200
       Load destination: rd = x20 (s4)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18747, step=2093, pc=0x0020B100, major=5, minor=2
  [105] ✓ PRE_EXEC_REG_MOD @ step 2860: 4 failures, 25166ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000000 -> 0xFFFFFFFF
       Register: x27 (s11), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=19588, step=2860, pc=0x00204B04, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=19588, step=2860, pc=0x00204B04, major=6, minor=2
         - MemoryWrite@mem.zir:100
           cycle=19588, step=2860, pc=0x00204B04, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19588, step=2860, pc=0x00204B04, major=6, minor=2
  [106] ✓ LOAD_VAL_MOD @ step 3374: 2 failures, 24601ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000062 -> 0xFFFFFFFE
       Load destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20176, step=3374, pc=0x00204C44, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20176, step=3374, pc=0x00204C44, major=5, minor=2
  [107] ✓ PRE_EXEC_REG_MOD @ step 1152: 4 failures, 24732ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x0022145C -> 0x00663D14
       Register: x10 (a0), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=17796, step=1152, pc=0x00209A30, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=17796, step=1152, pc=0x00209A30, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=17796, step=1152, pc=0x00209A30, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=17796, step=1152, pc=0x00209A30, major=0, minor=7
  [108] ✓ MEM_VAL_MOD @ step 200: 4 failures, 25384ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000000 -> 0xFFFFFFFF
       Transaction: load_mem_read (READ) at address 0x00221460
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=16779, step=200, pc=0x0020B8B8, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=16779, step=200, pc=0x0020B8B8, major=5, minor=2
         - MemoryWrite@mem.zir:100
           cycle=16779, step=200, pc=0x0020B8B8, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=16779, step=200, pc=0x0020B8B8, major=5, minor=2
  [109] ✓ INSTR_WORD_MOD_SUR @ step 83: 0 failures, 25820ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0xFEB72C23 -> 0xFEB52C23
       Surgical: rs1 = 14 -> 10
       Original: SW x11, -8(x14)
       Mutated:  SW x11, -8(x10)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16656: preflight=0x3fffc02e, actual=0x3fffc02a
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [110] ✓ INSTR_WORD_MOD_FULL @ step 2049: 0 failures, 24805ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00C9EE63 -> 0x00C9EA63
       Original: BLTU x19, x12, 28
       Mutated:  BLTU x19, x12, 20
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Proof verification failed (no local constraint failures)
  [111] ✓ COMP_OUT_MOD @ step 2984: 1 failures, 24639ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00007FFF
       Destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=19712, step=2984, pc=0x00205E08, major=0, minor=4
  [112] ✓ STORE_OUT_MOD @ step 3086: 2 failures, 24155ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xD1F7FBE4
       Store address: 0x00221550
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19814, step=3086, pc=0x00203294, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19814, step=3086, pc=0x00203294, major=6, minor=2
  [113] ✓ PRE_EXEC_REG_MOD @ step 1540: 3 failures, 24633ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x0000005B -> 0xFBFFEF24
       Register: x14 (a4), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18185: preflight=0x00086132, actual=0x00086138
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=18184, step=1540, pc=0x002184C8, major=1, minor=6
         - IsRead@mem.zir:80
           cycle=18184, step=1540, pc=0x002184C8, major=1, minor=6
         - MemoryWrite@mem.zir:99
           cycle=18211, step=1567, pc=0x00202C04, major=2, minor=4
  [114] ✓ STORE_OUT_MOD @ step 1648: 2 failures, 24303ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xE9E4B2DD
       Store address: 0x002000cc
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18292, step=1648, pc=0x0020AF04, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18292, step=1648, pc=0x0020AF04, major=6, minor=2
  [115] ✓ LOAD_VAL_MOD @ step 388: 2 failures, 24694ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000001 -> 0xFFFFFFFF
       Load destination: rd = x8 (s0/fp)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16979, step=388, pc=0x002031F0, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=16979, step=388, pc=0x002031F0, major=5, minor=2
  [116] ✓ STORE_OUT_MOD @ step 2295: 2 failures, 24604ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000004 -> 0xF7BCF4FB
       Store address: 0x00200348
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18949, step=2295, pc=0x00203478, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18949, step=2295, pc=0x00203478, major=6, minor=2
  [117] ✓ LOAD_VAL_MOD @ step 216: 2 failures, 23979ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00200D0C -> 0x0000FFFF
       Load destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16795, step=216, pc=0x0020B8F8, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=16795, step=216, pc=0x0020B8F8, major=5, minor=2
  [118] ✓ INSTR_TYPE_MOD @ step 1609: 4 failures, 24243ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new] [+41 touch]
       Value: 0x00000007 -> 0x00030000
       Original: AddI [major=0, minor=7]
       Mutated:  Sll [major=3, minor=0]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - MemoryWrite@mem.zir:99
           cycle=18253, step=1609, pc=0x002041A4, major=3, minor=0
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=18253, step=1609, pc=0x002041A4, major=3, minor=0
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=18253, step=1609, pc=0x002041A4, major=3, minor=0
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=18253, step=1609, pc=0x002041A4, major=3, minor=0
  [119] ✓ INSTR_TYPE_MOD @ step 3672: 3 failures, 26348ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00000007 -> 0x00000003
       Original: AddI [major=0, minor=7]
       Mutated:  Or [major=0, minor=3]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:99
           cycle=20548, step=3672, pc=0x0020343C, major=0, minor=3
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20548, step=3672, pc=0x0020343C, major=0, minor=3
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20548, step=3672, pc=0x0020343C, major=0, minor=3
  [120] ✓ LOAD_VAL_MOD @ step 1743: 2 failures, 24847ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000049 -> 0xA8778C53
       Load destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18387, step=1743, pc=0x002184C0, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18387, step=1743, pc=0x002184C0, major=5, minor=3
  [121] ✓ INSTR_TYPE_MOD @ step 1730: 5 failures, 25194ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+5 new]
       Value: 0x00050003 -> 0x00000001
       Original: LbU [major=5, minor=3]
       Mutated:  Sub [major=0, minor=1]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18374: preflight=0x00086e9f, actual=0x3fffc020
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - MemoryWrite@mem.zir:100
           cycle=18374, step=1730, pc=0x002184C4, major=0, minor=1
         - MemoryWrite@mem.zir:99
           cycle=18374, step=1730, pc=0x002184C4, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=18374, step=1730, pc=0x002184C4, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=18374, step=1730, pc=0x002184C4, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=18374, step=1730, pc=0x002184C4, major=0, minor=1
  [122] ✓ MEM_VAL_MOD @ step 178: 2 failures, 26199ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00203F7C -> 0x2B8D6F81
       Transaction: store_rmw_read (READ) at address 0x002003ec
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=16757, step=178, pc=0x00200EAC, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=16757, step=178, pc=0x00200EAC, major=6, minor=2
  [123] ✓ INSTR_TYPE_MOD @ step 2064: 5 failures, 24771ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+5 new]
       Value: 0x00060002 -> 0x00000001
       Original: Sw [major=6, minor=2]
       Mutated:  Sub [major=0, minor=1]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18718: preflight=0x00080029, actual=0x3fffc060
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - MemoryWrite@mem.zir:100
           cycle=18718, step=2064, pc=0x0020975C, major=0, minor=1
         - MemoryWrite@mem.zir:99
           cycle=18718, step=2064, pc=0x0020975C, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=18718, step=2064, pc=0x0020975C, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=18718, step=2064, pc=0x0020975C, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=18718, step=2064, pc=0x0020975C, major=0, minor=1
  [124] ✓ LOAD_VAL_MOD @ step 1476: 2 failures, 25863ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0000007F -> 0x74EEAFD8
       Load destination: rd = x14 (a4)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18120, step=1476, pc=0x002184C4, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18120, step=1476, pc=0x002184C4, major=5, minor=3
  [125] ✓ LOAD_VAL_MOD @ step 3022: 2 failures, 23958ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x63736972 -> 0x560B0CB9
       Load destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19750, step=3022, pc=0x00203454, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19750, step=3022, pc=0x00203454, major=5, minor=2
  [126] ✓ INSTR_WORD_MOD_SUR @ step 3035: 0 failures, 24970ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00267593 -> 0x002B7593
       Surgical: rs1 = 12 -> 22
       Original: ANDI x11, x12, 2
       Mutated:  ANDI x11, x22, 2
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19763: preflight=0x3fffc02c, actual=0x3fffc036
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [127] ✓ STORE_OUT_MOD @ step 1585: 2 failures, 27758ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000004 -> 0x42A06CF3
       Store address: 0x00200278
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18229, step=1585, pc=0x00202F2C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18229, step=1585, pc=0x00202F2C, major=6, minor=2
  [128] ✓ STORE_OUT_MOD @ step 3082: 2 failures, 27451ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xA0D96ADE
       Store address: 0x00221564
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19810, step=3082, pc=0x00203284, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19810, step=3082, pc=0x00203284, major=6, minor=2
  [129] ✓ INSTR_WORD_MOD_FULL @ step 2177: 0 failures, 27152ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x0A412483 -> 0x0A41A483
       Original: LW x9, 164(x2)
       Mutated:  LW x9, 164(x3)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18831: preflight=0x3fffc022, actual=0x3fffc023
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [130] ✓ PRE_EXEC_REG_MOD @ step 2313: 3 failures, 24756ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00000000 -> 0x0A321886
       Register: x10 (a0), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=18967, step=2313, pc=0x002012C4, major=0, minor=4
         - IsRead@mem.zir:80
           cycle=18967, step=2313, pc=0x002012C4, major=0, minor=4
         - MemoryWrite@mem.zir:99
           cycle=18967, step=2313, pc=0x002012C4, major=0, minor=4
  [131] ✓ COMP_OUT_MOD @ step 1070: 2 failures, 25331ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x00048101
       Destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17709, step=1070, pc=0x0020633C, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=17709, step=1070, pc=0x0020633C, major=0, minor=7
  [132] ✓ INSTR_WORD_MOD_FULL @ step 3800: 1 failures, 26861ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00A7E463 -> 0x08A7E463
       Original: BLTU x15, x10, 8
       Mutated:  BLTU x15, x10, 136
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20677: preflight=0x30000150, actual=0x30000170
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=20757, step=3807, pc=0xC000018C, major=2, minor=4
  [133] ✓ LOAD_VAL_MOD @ step 2262: 2 failures, 26143ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x3AA83F8C
       Load destination: rd = x17 (a7)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18916, step=2262, pc=0x00203424, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18916, step=2262, pc=0x00203424, major=5, minor=2
  [134] ✓ STORE_OUT_MOD @ step 2951: 2 failures, 26553ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xE8BE44F2
       Store address: 0x00200178
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19679, step=2951, pc=0x0020563C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19679, step=2951, pc=0x0020563C, major=6, minor=2
  [135] ✓ INSTR_TYPE_MOD @ step 2364: 32 failures, 26693ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+32 new]
       Value: 0x00020001 -> 0x00020003
       Original: BltU [major=2, minor=1]
       Mutated:  Jal [major=2, minor=3]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19018: preflight=0x3fffc060, actual=0x3fffc02c
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (4 unique):
         - DecodeInst@inst.zir:29 (x27)
           cycle=19019, step=2365, pc=0x0020328C, major=6, minor=2
         - MemoryWrite@mem.zir:100 (x2)
           cycle=19018, step=2364, pc=0x00203288, major=2, minor=3
         - MemoryWrite@mem.zir:99 (x2)
           cycle=19018, step=2364, pc=0x00203288, major=2, minor=3
         - VerifyOpcode@inst.zir:91
           cycle=19018, step=2364, pc=0x00203288, major=2, minor=3
  [136] ✓ LOAD_VAL_MOD @ step 2160: 2 failures, 24388ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000018 -> 0xFF7F2EEF
       Load destination: rd = x8 (s0/fp)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18814, step=2160, pc=0x00202584, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18814, step=2160, pc=0x00202584, major=5, minor=2
  [137] ✓ COMP_OUT_MOD @ step 1179: 2 failures, 25145ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00221000 -> 0xA38873B0
       Destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17823, step=1179, pc=0x00208CCC, major=2, minor=5
         - MemoryWrite@mem.zir:99
           cycle=17823, step=1179, pc=0x00208CCC, major=2, minor=5
  [138] ✓ LOAD_VAL_MOD @ step 1517: 2 failures, 25216ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000083 -> 0x02003093
       Load destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18161, step=1517, pc=0x002184C0, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18161, step=1517, pc=0x002184C0, major=5, minor=3
  [139] ✓ INSTR_WORD_MOD_FULL @ step 3821: 3 failures, 24974ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x02812A03 -> 0x1D6CB36F
       Original: LW x20, 40(x2)
       Mutated:  JAL x6, 831958
       Format changed: I -> J
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20771: preflight=0x3fffc022, actual=0x3fffc039
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - OpLW@inst_mem.zir:109
           cycle=20771, step=3821, pc=0x00205834, major=5, minor=2
         - VerifyOpcodeF3@inst.zir:96
           cycle=20771, step=3821, pc=0x00205834, major=5, minor=2
         - VerifyOpcodeF3@inst.zir:97
           cycle=20771, step=3821, pc=0x00205834, major=5, minor=2
  [140] ✓ INSTR_WORD_MOD_SUR @ step 2256: 1 failures, 25553ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x01070713 -> 0x01070703
       Surgical: opcode = 19 -> 3
       Original: ADDI x14, x14, 16
       Mutated:  LB x14, 16(x14)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:96
           cycle=18910, step=2256, pc=0x0020343C, major=0, minor=7
  [141] ✓ STORE_OUT_MOD @ step 1908: 2 failures, 25240ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x002000A4 -> 0xFDE62703
       Store address: 0x00200074
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18557, step=1908, pc=0x00205F68, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18557, step=1908, pc=0x00205F68, major=6, minor=2
  [142] ✓ COMP_OUT_MOD @ step 2620: 2 failures, 25648ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000020 -> 0x0BF7FF57
       Destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19348, step=2620, pc=0x002052F4, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=19348, step=2620, pc=0x002052F4, major=0, minor=7
  [143] ✓ PRE_EXEC_REG_MOD @ step 3835: 2 failures, 25168ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x002001A0 -> 0x2D768558
       Register: x2 (sp), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20785: preflight=0x0008006b, actual=0x0b5da159
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=20785, step=3835, pc=0x00205478, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=20785, step=3835, pc=0x00205478, major=5, minor=2
  [144] ✓ INSTR_WORD_MOD_SUR @ step 467: 2 failures, 25257ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00412483 -> 0xE1312483
       Surgical: imm = 4 -> 3603
       Original: LW x9, 4(x2)
       Mutated:  LW x9, -493(x2)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17064: preflight=0x000800d5, actual=0x00080058
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (2 unique):
         - OpLW@inst_mem.zir:108
           cycle=17064, step=467, pc=0x002031F4, major=5, minor=2
         - OpLW@inst_mem.zir:109
           cycle=17064, step=467, pc=0x002031F4, major=5, minor=2
  [145] ✓ INSTR_WORD_MOD_FULL @ step 2651: 1 failures, 25457ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00072783 -> 0x00072793
       Original: LW x15, 0(x14)
       Mutated:  SLTI x15, x14, 0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:96
           cycle=19379, step=2651, pc=0x0020341C, major=5, minor=2
  [146] ✓ INSTR_WORD_MOD_SUR @ step 879: 1 failures, 24491ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x0005A583 -> 0x0005A5CF
       Surgical: opcode = 3 -> 79
       Original: LW x11, 0(x11)
       Mutated:  UNKNOWN 0x0005a5cf
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:96
           cycle=17506, step=879, pc=0x002031A0, major=5, minor=2
  [147] ✓ COMP_OUT_MOD @ step 2130: 1 failures, 26251ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00000200
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18784, step=2130, pc=0x00205E18, major=0, minor=4
  [148] 💥 PRE_EXEC_REG_MOD @ step 1936: 2 failures, 3344ms, outcome: CRASH, exit: -11 [proof:NOT_GENERATED] [+2 new]
       Value: 0x0021B157 -> 0xDF7E4EA8
       Register: x10 (a0), READ, strategy=next_read
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18585, step=1936, pc=0x002184C0, major=5, minor=3
         - IsRead@mem.zir:80
           cycle=18585, step=1936, pc=0x002184C0, major=5, minor=3
  [149] ✓ STORE_OUT_MOD @ step 1649: 1 failures, 25648ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00000010
       Store address: 0x002000c8
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18293, step=1649, pc=0x0020AF08, major=6, minor=2
  [150] ✓ LOAD_VAL_MOD @ step 2579: 2 failures, 24254ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000009 -> 0x71CABF31
       Load destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19307, step=2579, pc=0x00201538, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19307, step=2579, pc=0x00201538, major=5, minor=3
  [151] ✓ COMP_OUT_MOD @ step 1043: 2 failures, 27304ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x1D331885 -> 0xE2CEE37A
       Destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17682, step=1043, pc=0x00200B40, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=17682, step=1043, pc=0x00200B40, major=0, minor=7
  [152] ✓ INSTR_WORD_MOD_FULL @ step 3725: 1 failures, 24824ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x02E585B3 -> 0x0221A1B3
       Original: ADD x11, x11, x14
       Mutated:  SLT x3, x3, x2
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20601: preflight=0x3fffc02b, actual=0x3fffc023
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (1 unique):
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20601, step=3725, pc=0x00203260, major=3, minor=2
  [153] ✓ INSTR_WORD_MOD_SUR @ step 177: 0 failures, 24758ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0xFF010113 -> 0xFF010213
       Surgical: rd = 2 -> 4
       Original: ADDI x2, x2, -16
       Mutated:  ADDI x4, x2, -16
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16756: preflight=0x3fffc022, actual=0x3fffc024
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [154] ✓ INSTR_WORD_MOD_FULL @ step 1963: 0 failures, 25421ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0xFE0614E3 -> 0xFE4694E3
       Original: BNE x12, x0, -24
       Mutated:  BNE x13, x4, -24
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18612: preflight=0x3fffc02c, actual=0x3fffc02d
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [155] ✓ INSTR_WORD_MOD_FULL @ step 3760: 1 failures, 25613ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00861613 -> 0x00861633
       Original: SLLI x12, x12, 8
       Mutated:  SLL x12, x12, x8
       Format changed: I -> R
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20636, step=3760, pc=0x002057A8, major=3, minor=1
  [156] ✓ COMP_OUT_MOD @ step 692: 1 failures, 25694ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00800000
       Destination: rd = x15 (a5)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=17307, step=692, pc=0x002061B8, major=0, minor=1
  [157] ✓ MEM_VAL_MOD @ step 3532: 2 failures, 25322ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000003 -> 0xBF7A865A
       Transaction: load_mem_read (WRITE) at address 0xffff0028
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20334, step=3532, pc=0xC0000074, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20334, step=3532, pc=0xC0000074, major=5, minor=2
  [158] ✓ MEM_VAL_MOD @ step 0: 10 failures, 28167ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+10 new]
       Value: 0x37363534 -> 0x8D1445C2
       Transaction: other_mem_read (READ) at address 0x0021abfc
       zkVM errors (2 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=13339, step=0, pc=0x00000000, major=9, minor=2
         - IsRead@mem.zir:80
           cycle=13339, step=0, pc=0x00000000, major=9, minor=2
         - PoseidonCheckOut@inst_p2.zir:265 (x8)
           cycle=13349, step=0, pc=0x00000000, major=9, minor=5
  [159] ✓ PRE_EXEC_REG_MOD @ step 893: 2 failures, 26027ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00200370 -> 0x00000200
       Register: x8 (s0), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=17520, step=893, pc=0x00206150, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=17520, step=893, pc=0x00206150, major=0, minor=7
  [160] ✓ MEM_VAL_MOD @ step 3399: 2 failures, 26390ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x00000001
       Transaction: load_mem_read (READ) at address 0x002002a8
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=20201, step=3399, pc=0x00203428, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20201, step=3399, pc=0x00203428, major=5, minor=2
  [161] ✓ COMP_OUT_MOD @ step 1914: 2 failures, 28748ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000012 -> 0xFE4A4A4D
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18563, step=1914, pc=0x00205F80, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=18563, step=1914, pc=0x00205F80, major=0, minor=7
  [162] ✓ STORE_OUT_MOD @ step 1611: 1 failures, 28678ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00000008
       Store address: 0x00200174
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=18255, step=1611, pc=0x002041AC, major=6, minor=2
  [163] ✓ STORE_OUT_MOD @ step 3919: 2 failures, 27320ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0F745431 -> 0x00007FFF
       Store address: 0xffff025c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20869, step=3919, pc=0xC00000D4, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20869, step=3919, pc=0xC00000D4, major=6, minor=2
  [164] ✓ INSTR_WORD_MOD_SUR @ step 3611: 0 failures, 25217ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00400693 -> 0x00400F13
       Surgical: rd = 13 -> 30
       Original: ADDI x13, x0, 4
       Mutated:  ADDI x30, x0, 4
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20487: preflight=0x3fffc02d, actual=0x3fffc03e
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [165] ✓ INSTR_WORD_MOD_FULL @ step 3507: 3 failures, 26089ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x40A48733 -> 0xD6826363
       Original: SUB x14, x9, x10
       Mutated:  BLTU x4, x8, -2714
       Format changed: R -> B
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20309: preflight=0x3fffc029, actual=0x3fffc024
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20309, step=3507, pc=0x002053DC, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20309, step=3507, pc=0x002053DC, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=20309, step=3507, pc=0x002053DC, major=0, minor=1
  [166] ✓ MEM_VAL_MOD @ step 1875: 17 failures, 26018ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+17 new]
       Value: 0x00008067 -> 0xF7FE7719
       Transaction: other_mem_read (READ) at address 0x002097d4
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18524: preflight=0x3fffc021, actual=0x3fffc03c
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (6 unique):
         - DecodeInst@inst.zir:29 (x10)
           cycle=18525, step=1876, pc=0x0020AF40, major=5, minor=2
         - IsRead@mem.zir:79
           cycle=18524, step=1875, pc=0x0020AF3C, major=2, minor=4
         - IsRead@mem.zir:80
           cycle=18524, step=1875, pc=0x0020AF3C, major=2, minor=4
         - MemoryWrite@mem.zir:99 (x3)
           cycle=18528, step=1879, pc=0x0020AF70, major=2, minor=3
         - VerifyOpcodeF3@inst.zir:96
           cycle=18524, step=1875, pc=0x0020AF3C, major=2, minor=4
         - VerifyOpcodeF3@inst.zir:97
           cycle=18524, step=1875, pc=0x0020AF3C, major=2, minor=4
  [167] ✓ INSTR_TYPE_MOD @ step 842: 12 failures, 27508ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+12 new] [+33 touch]
       Value: 0x00020002 -> 0x00020009
       Original: BgeU [major=2, minor=2]
       Mutated:  SllI [major=2, minor=9] ⚠INVALID
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17470: preflight=0x00081869, actual=0x00000000
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (5 unique):
         - AddrDecompose@u32.zir:67 (x8)
           cycle=17470, step=843, pc=0x002061A8, major=4, minor=2
         - MemoryWrite@mem.zir:100
           cycle=17477, step=850, pc=0x002031B8, major=2, minor=4
         - MemoryWrite@mem.zir:99
           cycle=17477, step=850, pc=0x002031B8, major=2, minor=4
         - OneHot@one_hot.zir:11
           cycle=17469, step=842, pc=0x002061A4, major=2, minor=9
         - OneHot@one_hot.zir:9
           cycle=17469, step=842, pc=0x002061A4, major=2, minor=9
  [168] ✓ LOAD_VAL_MOD @ step 623: 2 failures, 25120ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00200944 -> 0xC06C250E
       Load destination: rd = x1 (ra)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17232, step=623, pc=0x002031EC, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17232, step=623, pc=0x002031EC, major=5, minor=2
  [169] ✓ MEM_VAL_MOD @ step 469: 6 failures, 25232ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+6 new]
       Value: 0x00008067 -> 0x0B4C1837
       Transaction: other_mem_read (READ) at address 0x002031f8
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17066: preflight=0x3fffc021, actual=0x3fffc038
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - IsRead@mem.zir:79
           cycle=17066, step=469, pc=0x002008C4, major=2, minor=4
         - IsRead@mem.zir:80
           cycle=17066, step=469, pc=0x002008C4, major=2, minor=4
         - MemoryWrite@mem.zir:99 (x2)
           cycle=17078, step=481, pc=0x002008FC, major=2, minor=6
         - VerifyOpcodeF3@inst.zir:96
           cycle=17066, step=469, pc=0x002008C4, major=2, minor=4
         - VerifyOpcodeF3@inst.zir:97
           cycle=17066, step=469, pc=0x002008C4, major=2, minor=4
  [170] ✓ COMP_OUT_MOD @ step 266: 2 failures, 24231ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new] [+1 touch]
       Value: 0x0021A000 -> 0x010D0000
       Destination: rd = x12 (a2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16845, step=266, pc=0x0020614C, major=2, minor=5
         - MemoryWrite@mem.zir:99
           cycle=16845, step=266, pc=0x0020614C, major=2, minor=5
  [171] ✓ LOAD_VAL_MOD @ step 1510: 2 failures, 25935ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0000001F -> 0x227D8219
       Load destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18154, step=1510, pc=0x002184C0, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=18154, step=1510, pc=0x002184C0, major=5, minor=3
  [172] ✓ STORE_OUT_MOD @ step 1687: 2 failures, 27577ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000001 -> 0xAEAFE7BC
       Store address: 0x0020006c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18331, step=1687, pc=0x00205F70, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18331, step=1687, pc=0x00205F70, major=6, minor=2
  [173] ✓ COMP_OUT_MOD @ step 2004: 1 failures, 26339ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x0021B161 -> 0x00A1B161
       Destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=18653, step=2004, pc=0x002184D4, major=0, minor=7
  [174] ✓ INSTR_WORD_MOD_SUR @ step 371: 1 failures, 26716ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000073 -> 0x57400073
       Surgical: imm = 0 -> 1396
       Original: ECALL x0, x0, 0
       Mutated:  SYSTEM.0 x0, x0, 1396
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MachineECall@inst_ecall.zir:28
           cycle=16959, step=371, pc=0xC000015C, major=8, minor=0
  [175] ✓ INSTR_WORD_MOD_FULL @ step 1208: 0 failures, 23869ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x02412483 -> 0x02412403
       Original: LW x9, 36(x2)
       Mutated:  LW x8, 36(x2)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17852: preflight=0x3fffc029, actual=0x3fffc028
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [176] ✓ MEM_VAL_MOD @ step 1642: 2 failures, 26530ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x31740BD3
       Transaction: store_rmw_read (READ) at address 0x002000e4
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18286, step=1642, pc=0x0020AEEC, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=18286, step=1642, pc=0x0020AEEC, major=6, minor=2
  [177] ✓ MEM_VAL_MOD @ step 938: 2 failures, 25342ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x002031FC -> 0x00000000
       Transaction: other_mem_write (WRITE) at address 0xffff0180
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17571, step=938, pc=0x00200A24, major=2, minor=4
         - MemoryWrite@mem.zir:99
           cycle=17571, step=938, pc=0x00200A24, major=2, minor=4
  [178] ✓ INSTR_WORD_MOD_SUR @ step 240: 1 failures, 25025ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00012623 -> 0x00012663
       Surgical: opcode = 35 -> 99
       Original: SW x0, 12(x2)
       Mutated:  BRANCH.2 x2, x0, 12
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:96
           cycle=16819, step=240, pc=0x00200830, major=6, minor=2
  [179] ✓ LOAD_VAL_MOD @ step 1016: 1 failures, 24937ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00000001
       Load destination: rd = x9 (s1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=17655, step=1016, pc=0x002031F4, major=5, minor=2
  [180] ✓ PRE_EXEC_REG_MOD @ step 1205: 1 failures, 25582ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000002 -> 0x00008000
       Register: x13 (a3), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - IsRead@mem.zir:79
           cycle=17849, step=1205, pc=0x00208C30, major=2, minor=3
  [181] ✓ LOAD_VAL_MOD @ step 3216: 2 failures, 26292ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0022156C -> 0x35B41F6C
       Load destination: rd = x12 (a2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20018, step=3216, pc=0x00205DF4, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20018, step=3216, pc=0x00205DF4, major=5, minor=2
  [182] ✓ LOAD_VAL_MOD @ step 3870: 2 failures, 25428ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x6B9C898B
       Load destination: rd = x24 (s8)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20820, step=3870, pc=0x00204DAC, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20820, step=3870, pc=0x00204DAC, major=5, minor=2
  [183] ✓ MEM_VAL_MOD @ step 2275: 2 failures, 26597ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x00000100
       Transaction: load_mem_read (READ) at address 0x002213e8
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18929, step=2275, pc=0x00203428, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18929, step=2275, pc=0x00203428, major=5, minor=2
  [184] ✓ PRE_EXEC_REG_MOD @ step 2596: 3 failures, 25385ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x000000A1 -> 0x3D64BD5F
       Register: x13 (a3), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=19324, step=2596, pc=0x0020157C, major=3, minor=1
         - IsRead@mem.zir:80
           cycle=19324, step=2596, pc=0x0020157C, major=3, minor=1
         - MemoryWrite@mem.zir:100
           cycle=19324, step=2596, pc=0x0020157C, major=3, minor=1
  [185] ✓ LOAD_VAL_MOD @ step 2525: 2 failures, 24826ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0000004B -> 0x80000000
       Load destination: rd = x12 (a2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19253, step=2525, pc=0x00201460, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19253, step=2525, pc=0x00201460, major=5, minor=3
  [186] ✓ INSTR_WORD_MOD_FULL @ step 2485: 0 failures, 26777ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x02C22583 -> 0x0AC22583
       Original: LW x11, 44(x4)
       Mutated:  LW x11, 172(x4)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19139: preflight=0x3fffc02b, actual=0x3fffc04b
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [187] ✓ INSTR_TYPE_MOD @ step 1309: 3 failures, 24661ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new] [+48 touch]
       Value: 0x00010002 -> 0x00040004
       Original: AndI [major=1, minor=2]
       Mutated:  Div [major=4, minor=4]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=17953, step=1309, pc=0x002035D4, major=4, minor=4
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=17953, step=1309, pc=0x002035D4, major=4, minor=4
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=17953, step=1309, pc=0x002035D4, major=4, minor=4
  [188] ✓ PRE_EXEC_REG_MOD @ step 2104: 13 failures, 26753ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+13 new]
       Value: 0x002024E0 -> 0x002024DE
       Register: x1 (ra), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18759: preflight=0x0008093f, actual=0x0008093e
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - DecodeInst@inst.zir:29 (x10)
           cycle=18759, step=2105, pc=0x00202500, major=0, minor=7
         - IsRead@mem.zir:79
           cycle=18758, step=2104, pc=0x002024FC, major=2, minor=4
         - MemoryWrite@mem.zir:99 (x2)
           cycle=18767, step=2113, pc=0x00202520, major=2, minor=6
  [189] ✓ INSTR_TYPE_MOD @ step 2680: 4 failures, 25001ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00050002 -> 0x00000004
       Original: Lw [major=5, minor=2]
       Mutated:  And [major=0, minor=4]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19408: preflight=0x000800c6, actual=0x3fffc038
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (4 unique):
         - MemoryWrite@mem.zir:100
           cycle=19408, step=2680, pc=0x002015DC, major=0, minor=4
         - MemoryWrite@mem.zir:99
           cycle=19408, step=2680, pc=0x002015DC, major=0, minor=4
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=19408, step=2680, pc=0x002015DC, major=0, minor=4
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=19408, step=2680, pc=0x002015DC, major=0, minor=4
  [190] 💥 PRE_EXEC_REG_MOD @ step 1576: 2 failures, 3019ms, outcome: CRASH, exit: -11 [proof:NOT_GENERATED] [+2 new]
       Value: 0x00200140 -> 0xF3DDBCEF
       Register: x2 (sp), READ, strategy=next_read
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18220, step=1576, pc=0x00202EC4, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=18220, step=1576, pc=0x00202EC4, major=5, minor=2
  [191] ✓ COMP_OUT_MOD @ step 3310: 2 failures, 25218ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000042 -> 0x16BADEAC
       Destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20112, step=3310, pc=0x00204C48, major=0, minor=1
         - MemoryWrite@mem.zir:99
           cycle=20112, step=3310, pc=0x00204C48, major=0, minor=1
  [192] ✓ STORE_OUT_MOD @ step 239: 2 failures, 25239ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x892A4173
       Store address: 0x00200368
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16818, step=239, pc=0x0020082C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=16818, step=239, pc=0x0020082C, major=6, minor=2
  [193] ✓ STORE_OUT_MOD @ step 2704: 1 failures, 24949ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x04000000
       Store address: 0x002003a4
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=19432, step=2704, pc=0x0020163C, major=6, minor=2
  [194] ✓ MEM_VAL_MOD @ step 1970: 63 failures, 24913ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+63 new]
       Value: 0xFE0614E3 -> 0x01F9CB5C
       Transaction: other_mem_read (READ) at address 0x002184d4
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18619: preflight=0x3fffc02c, actual=0x3fffc033
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (6 unique):
         - DecodeInst@inst.zir:29 (x58)
           cycle=18620, step=1971, pc=0x002184C0, major=5, minor=3
         - IsRead@mem.zir:79
           cycle=18619, step=1970, pc=0x002184BC, major=1, minor=6
         - IsRead@mem.zir:80
           cycle=18619, step=1970, pc=0x002184BC, major=1, minor=6
         - MemoryWrite@mem.zir:99
           cycle=18677, step=2028, pc=0x00205FD0, major=2, minor=4
         - VerifyOpcodeF3@inst.zir:96
           cycle=18619, step=1970, pc=0x002184BC, major=1, minor=6
         - VerifyOpcodeF3@inst.zir:97
           cycle=18619, step=1970, pc=0x002184BC, major=1, minor=6
  [195] ✓ MEM_VAL_MOD @ step 110: 1 failures, 25593ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00000004
       Transaction: other_mem_write (WRITE) at address 0xffff0180
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=16683, step=110, pc=0x002032F0, major=2, minor=1
  [196] ✓ LOAD_VAL_MOD @ step 387: 2 failures, 25033ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00200890 -> 0x00001000
       Load destination: rd = x1 (ra)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16978, step=387, pc=0x002031EC, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=16978, step=387, pc=0x002031EC, major=5, minor=2
  [197] 💥 PRE_EXEC_REG_MOD @ step 3726: 2 failures, 3289ms, outcome: CRASH, exit: -11 [proof:NOT_GENERATED] [+2 new]
       Value: 0x00221634 -> 0xFFDDE9CC
       Register: x13 (a3), READ, strategy=next_read
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=20602, step=3726, pc=0x00203264, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=20602, step=3726, pc=0x00203264, major=6, minor=2
  [198] ✓ MEM_VAL_MOD @ step 1498: 2 failures, 26020ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x7FFFFFFF
       Transaction: other_mem_write (WRITE) at address 0xffff0180
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18142, step=1498, pc=0x002184C8, major=1, minor=6
         - MemoryWrite@mem.zir:99
           cycle=18142, step=1498, pc=0x002184C8, major=1, minor=6
  [199] ✓ LOAD_VAL_MOD @ step 1208: 1 failures, 24384ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x0022145C -> 0x0C22145C
       Load destination: rd = x9 (s1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=17852, step=1208, pc=0x00208C3C, major=5, minor=2
  [200] ✓ STORE_OUT_MOD @ step 3919: 2 failures, 25137ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0F745431 -> 0x00000000
       Store address: 0xffff025c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20869, step=3919, pc=0xC00000D4, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20869, step=3919, pc=0xC00000D4, major=6, minor=2
  [201] ✓ INSTR_WORD_MOD_SUR @ step 3678: 0 failures, 27453ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00467593 -> 0x0045F593
       Surgical: rs1 = 12 -> 11
       Original: ANDI x11, x12, 4
       Mutated:  ANDI x11, x11, 4
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20554: preflight=0x3fffc02c, actual=0x3fffc02b
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [202] ✓ LOAD_VAL_MOD @ step 2166: 2 failures, 24811ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x002001D0 -> 0x677A20A7
       Load destination: rd = x8 (s0/fp)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18820, step=2166, pc=0x002024F0, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18820, step=2166, pc=0x002024F0, major=5, minor=2
  [203] ✓ COMP_OUT_MOD @ step 1465: 2 failures, 25601ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0000000E -> 0x6CFFECA1
       Destination: rd = x12 (a2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18109, step=1465, pc=0x002184D0, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=18109, step=1465, pc=0x002184D0, major=0, minor=7
  [204] ✓ PRE_EXEC_REG_MOD @ step 1056: 4 failures, 24851ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00200360 -> 0xFFDFFC9F
       Register: x2 (sp), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=17695, step=1056, pc=0x00200BD8, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=17695, step=1056, pc=0x00200BD8, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=17695, step=1056, pc=0x00200BD8, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=17695, step=1056, pc=0x00200BD8, major=0, minor=7
  [205] ✓ INSTR_WORD_MOD_FULL @ step 2561: 0 failures, 25610ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00859593 -> 0x00859793
       Original: SLLI x11, x11, 8
       Mutated:  SLLI x15, x11, 8
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19289: preflight=0x3fffc02b, actual=0x3fffc02f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [206] ✓ INSTR_TYPE_MOD @ step 3279: 5 failures, 23710ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+5 new] [+2 touch]
       Value: 0x00050002 -> 0x00040005
       Original: Lw [major=5, minor=2]
       Mutated:  DivU [major=4, minor=5]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20081: preflight=0x00080077, actual=0x3fffc020
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - MemoryWrite@mem.zir:100
           cycle=20081, step=3279, pc=0x0020341C, major=4, minor=5
         - MemoryWrite@mem.zir:99
           cycle=20081, step=3279, pc=0x0020341C, major=4, minor=5
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20081, step=3279, pc=0x0020341C, major=4, minor=5
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20081, step=3279, pc=0x0020341C, major=4, minor=5
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=20081, step=3279, pc=0x0020341C, major=4, minor=5
  [207] ✓ INSTR_WORD_MOD_FULL @ step 494: 18 failures, 25524ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+18 new]
       Value: 0xF80080E7 -> 0xF82080E7
       Original: JALR x1, x1, -128
       Mutated:  JALR x1, x1, -126
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17091: preflight=0x3fffc020, actual=0x3fffc022
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - ControlUserECALL@inst_control.zir:75
           cycle=17108, step=511, pc=0xC0000070, major=7, minor=2
         - DecodeInst@inst.zir:29 (x16)
           cycle=17092, step=495, pc=0x00206134, major=3, minor=1
         - MemoryWrite@mem.zir:99
           cycle=17108, step=511, pc=0xC0000070, major=7, minor=2
  [208] ✓ INSTR_WORD_MOD_SUR @ step 501: 0 failures, 25345ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x0021A637 -> 0x0021ADB7
       Surgical: rd = 12 -> 27
       Original: LUI x12, 0x21a000
       Mutated:  LUI x27, 0x21a000
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17098: preflight=0x3fffc02c, actual=0x3fffc03b
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [209] ✓ INSTR_WORD_MOD_FULL @ step 3929: 2 failures, 25651ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000073 -> 0x99DC1783
       Original: ECALL x0, x0, 0
       Mutated:  LH x15, -1635(x24)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MachineECall@inst_ecall.zir:28
           cycle=20879, step=3929, pc=0xC00000F8, major=8, minor=0
         - MachineECall@inst_ecall.zir:29
           cycle=20879, step=3929, pc=0xC00000F8, major=8, minor=0
  [210] ✓ STORE_OUT_MOD @ step 2369: 2 failures, 24876ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x7EFAFBFF
       Store address: 0x0020032c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19023, step=2369, pc=0x0020329C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19023, step=2369, pc=0x0020329C, major=6, minor=2
  [211] ✓ PRE_EXEC_REG_MOD @ step 0: 10 failures, 26486ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+10 new]
       Value: 0x00000000 -> 0xFC3FC73C
       Register: x14 (a4), READ, strategy=next_read
       zkVM errors (2 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=15977, step=0, pc=0x00000000, major=9, minor=2
         - IsRead@mem.zir:80
           cycle=15977, step=0, pc=0x00000000, major=9, minor=2
         - PoseidonCheckOut@inst_p2.zir:265 (x8)
           cycle=16247, step=0, pc=0x00000000, major=9, minor=5
  [212] ✓ INSTR_TYPE_MOD @ step 3856: 4 failures, 24786ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000007 -> 0x00000004
       Original: AddI [major=0, minor=7]
       Mutated:  And [major=0, minor=4]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - MemoryWrite@mem.zir:100
           cycle=20806, step=3856, pc=0x00204D78, major=0, minor=4
         - MemoryWrite@mem.zir:99
           cycle=20806, step=3856, pc=0x00204D78, major=0, minor=4
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20806, step=3856, pc=0x00204D78, major=0, minor=4
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20806, step=3856, pc=0x00204D78, major=0, minor=4
  [213] ✓ STORE_OUT_MOD @ step 2762: 2 failures, 25426ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x20000000 -> 0x2A51BCFC
       Store address: 0x002002e0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19490, step=2762, pc=0x002037D0, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19490, step=2762, pc=0x002037D0, major=6, minor=2
  [214] ✓ PRE_EXEC_REG_MOD @ step 3660: 4 failures, 27902ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x002215AC -> 0x0023050C
       Register: x14 (a4), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=20536, step=3660, pc=0x0020343C, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=20536, step=3660, pc=0x0020343C, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=20536, step=3660, pc=0x0020343C, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=20536, step=3660, pc=0x0020343C, major=0, minor=7
  [215] ✓ STORE_OUT_MOD @ step 1299: 2 failures, 25946ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x19CDE05B -> 0x375D881D
       Store address: 0x0020032c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17943, step=1299, pc=0x00203434, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17943, step=1299, pc=0x00203434, major=6, minor=2
  [216] ✓ PRE_EXEC_REG_MOD @ step 553: 4 failures, 26237ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000000 -> 0xA5C11E2C
       Register: x0 (zero), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=17156, step=553, pc=0x00200918, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=17156, step=553, pc=0x00200918, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=17156, step=553, pc=0x00200918, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=17156, step=553, pc=0x00200918, major=0, minor=7
  [217] ✓ LOAD_VAL_MOD @ step 2524: 2 failures, 24924ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x000000D9 -> 0x78F676DE
       Load destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19252, step=2524, pc=0x0020145C, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19252, step=2524, pc=0x0020145C, major=5, minor=3
  [218] ✓ LOAD_VAL_MOD @ step 150: 2 failures, 24315ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00203F7C -> 0x12303F7E
       Load destination: rd = x1 (ra)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16723, step=150, pc=0x00201118, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=16723, step=150, pc=0x00201118, major=5, minor=2
  [219] ✓ INSTR_TYPE_MOD @ step 543: 3 failures, 24548ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00050002 -> 0x00000007
       Original: Lw [major=5, minor=2]
       Mutated:  AddI [major=0, minor=7]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17146: preflight=0x000800d7, actual=0x3fffc02c
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:99
           cycle=17146, step=543, pc=0x002031EC, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:96
           cycle=17146, step=543, pc=0x002031EC, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:97
           cycle=17146, step=543, pc=0x002031EC, major=0, minor=7
  [220] ✓ INSTR_WORD_MOD_FULL @ step 347: 0 failures, 25280ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00200293 -> 0x00280293
       Original: ADDI x5, x0, 2
       Mutated:  ADDI x5, x16, 2
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16932: preflight=0x3fffc020, actual=0x3fffc030
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [221] ✓ PRE_EXEC_REG_MOD @ step 1118: 3 failures, 24869ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00200360 -> 0x55B7745E
       Register: x2 (sp), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17762: preflight=0x000800e0, actual=0x156ddd1f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=17762, step=1118, pc=0x00200CAC, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=17762, step=1118, pc=0x00200CAC, major=5, minor=2
         - OpLW@inst_mem.zir:109
           cycle=17762, step=1118, pc=0x00200CAC, major=5, minor=2
  [222] ✓ LOAD_VAL_MOD @ step 2260: 2 failures, 26175ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x00042000
       Load destination: rd = x15 (a5)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18914, step=2260, pc=0x0020341C, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18914, step=2260, pc=0x0020341C, major=5, minor=2
  [223] ✓ INSTR_TYPE_MOD @ step 269: 11 failures, 25337ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+11 new] [+2 touch]
       Value: 0x00020005 -> 0x00020002
       Original: Lui [major=2, minor=5]
       Mutated:  BgeU [major=2, minor=2]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16848: preflight=0x3fffc02a, actual=0x3fffc060
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - ControlUserECALL@inst_control.zir:75
           cycle=16855, step=276, pc=0xC0000070, major=7, minor=2
         - DecodeInst@inst.zir:29 (x6)
           cycle=16849, step=270, pc=0x0020615C, major=0, minor=7
         - MemoryWrite@mem.zir:99 (x2)
           cycle=16848, step=269, pc=0x00206158, major=2, minor=2
         - VerifyOpcodeF3@inst.zir:96
           cycle=16848, step=269, pc=0x00206158, major=2, minor=2
         - VerifyOpcodeF3@inst.zir:97
           cycle=16848, step=269, pc=0x00206158, major=2, minor=2
  [224] ✓ PRE_EXEC_REG_MOD @ step 509: 3 failures, 24330ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00000001 -> 0x180E8C93
       Register: x15 (a5), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17107: preflight=0x0008185b, actual=0x00081864
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=17106, step=509, pc=0x0020616C, major=2, minor=2
         - IsRead@mem.zir:80
           cycle=17106, step=509, pc=0x0020616C, major=2, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17108, step=511, pc=0xC0000070, major=7, minor=2
  [225] ✓ PRE_EXEC_REG_MOD @ step 1638: 6 failures, 24148ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+6 new]
       Value: 0x0020B4CC -> 0x0105A660
       Register: x1 (ra), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18283: preflight=0x00082bb7, actual=0x0041681c
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=18282, step=1638, pc=0x0020AEDC, major=2, minor=4
         - IsRead@mem.zir:80
           cycle=18282, step=1638, pc=0x0020AEDC, major=2, minor=4
         - MemoryWrite@mem.zir:100 (x2)
           cycle=18305, step=1661, pc=0x0020AF38, major=2, minor=6
         - MemoryWrite@mem.zir:99 (x2)
           cycle=18305, step=1661, pc=0x0020AF38, major=2, minor=6
  [226] ✓ COMP_OUT_MOD @ step 335: 2 failures, 24369ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0020036C -> 0x592E94C5
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16920, step=335, pc=0x002031AC, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=16920, step=335, pc=0x002031AC, major=0, minor=7
  [227] ✓ LOAD_VAL_MOD @ step 3173: 2 failures, 22556ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xF83D58C3
       Load destination: rd = x24 (s8)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19975, step=3173, pc=0x00205844, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19975, step=3173, pc=0x00205844, major=5, minor=2
  [228] ✓ INSTR_WORD_MOD_FULL @ step 3606: 3 failures, 23820ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x000A8513 -> 0x7CFFA403
       Original: ADDI x10, x21, 0
       Mutated:  LW x8, 1999(x31)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20482: preflight=0x3fffc035, actual=0x3fffc03f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:99
           cycle=20482, step=3606, pc=0x002056B8, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:96
           cycle=20482, step=3606, pc=0x002056B8, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:97
           cycle=20482, step=3606, pc=0x002056B8, major=0, minor=7
  [229] ✓ STORE_OUT_MOD @ step 3708: 2 failures, 24502ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x6B461015
       Store address: 0x00221634
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20584, step=3708, pc=0x0020321C, major=6, minor=0
         - MemoryWrite@mem.zir:99
           cycle=20584, step=3708, pc=0x0020321C, major=6, minor=0
  [230] ✓ INSTR_WORD_MOD_SUR @ step 1399: 1 failures, 23008ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x0005C703 -> 0x00059703
       Surgical: funct3 = 4 -> 1
       Original: LBU x14, 0(x11)
       Mutated:  LH x14, 0(x11)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:97
           cycle=18043, step=1399, pc=0x002184C4, major=5, minor=3
  [231] ✓ INSTR_WORD_MOD_FULL @ step 3929: 2 failures, 23633ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000073 -> 0x4F6461EF
       Original: ECALL x0, x0, 0
       Mutated:  JAL x3, 287990
       Format changed: I -> J
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MachineECall@inst_ecall.zir:28
           cycle=20879, step=3929, pc=0xC00000F8, major=8, minor=0
         - MachineECall@inst_ecall.zir:29
           cycle=20879, step=3929, pc=0xC00000F8, major=8, minor=0
  [232] ✓ INSTR_WORD_MOD_SUR @ step 3627: 1 failures, 22602ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x3EA62E23 -> 0x3EA62E37
       Surgical: opcode = 35 -> 55
       Original: SW x10, 1020(x12)
       Mutated:  LUI x28, 0x3ea62000
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:96
           cycle=20503, step=3627, pc=0x00205E38, major=6, minor=2
  [233] ✓ INSTR_TYPE_MOD @ step 3928: 2 failures, 23446ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new] [+2 touch]
       Value: 0x00000007 -> 0x00000003
       Original: AddI [major=0, minor=7]
       Mutated:  Or [major=0, minor=3]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20878, step=3928, pc=0xC00000F8, major=0, minor=3
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20878, step=3928, pc=0xC00000F8, major=0, minor=3
  [234] ✓ MEM_VAL_MOD @ step 3548: 1 failures, 23885ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x00010000
       Transaction: other_mem_read (READ) at address 0xffff0000
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - IsRead@mem.zir:80
           cycle=20350, step=3548, pc=0xC00004A0, major=0, minor=7
  [235] ✓ LOAD_VAL_MOD @ step 1283: 2 failures, 22454ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x3AF54FA5 -> 0xEBD53E94
       Load destination: rd = x17 (a7)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17927, step=1283, pc=0x00203424, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17927, step=1283, pc=0x00203424, major=5, minor=2
  [236] ✓ PRE_EXEC_REG_MOD @ step 197: 3 failures, 27351ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x0022145C -> 0xADD65955
       Register: x14 (a4), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16776: preflight=0x0008851a, actual=0x2b759658
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=16776, step=197, pc=0x0020B8A0, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=16776, step=197, pc=0x0020B8A0, major=5, minor=2
         - OpLW@inst_mem.zir:108
           cycle=16776, step=197, pc=0x0020B8A0, major=5, minor=2
  [237] ✓ INSTR_TYPE_MOD @ step 3712: 4 failures, 30426ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00020001 -> 0x00000001
       Original: BltU [major=2, minor=1]
       Mutated:  Sub [major=0, minor=1]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20588: preflight=0x3fffc060, actual=0x3fffc028
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (4 unique):
         - MemoryWrite@mem.zir:99
           cycle=20588, step=3712, pc=0x0020322C, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20588, step=3712, pc=0x0020322C, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20588, step=3712, pc=0x0020322C, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=20588, step=3712, pc=0x0020322C, major=0, minor=1
  [238] ✓ COMP_OUT_MOD @ step 2837: 2 failures, 37348ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0021B000 -> 0xF75E4EF3
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19565, step=2837, pc=0x00203BC4, major=2, minor=5
         - MemoryWrite@mem.zir:99
           cycle=19565, step=2837, pc=0x00203BC4, major=2, minor=5
  [239] ✓ MEM_VAL_MOD @ step 778: 4 failures, 35121ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x002009B4 -> 0x84C944FC
       Transaction: load_mem_read (READ) at address 0x0020035c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=17399, step=778, pc=0x002031EC, major=5, minor=2
         - IsRead@mem.zir:80
           cycle=17399, step=778, pc=0x002031EC, major=5, minor=2
         - MemoryWrite@mem.zir:100
           cycle=17399, step=778, pc=0x002031EC, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17399, step=778, pc=0x002031EC, major=5, minor=2
  [240] ✓ INSTR_WORD_MOD_SUR @ step 2960: 0 failures, 29914ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00275713 -> 0x002C5713
       Surgical: rs1 = 14 -> 24
       Original: SRLI x14, x14, 2
       Mutated:  SRLI x14, x24, 2
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19688: preflight=0x3fffc02e, actual=0x3fffc038
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [241] ✓ STORE_OUT_MOD @ step 2871: 2 failures, 43476ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00204B28 -> 0xFDFF34D6
       Store address: 0x002001bc
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19599, step=2871, pc=0x0020535C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19599, step=2871, pc=0x0020535C, major=6, minor=2
  [242] ✓ STORE_OUT_MOD @ step 2725: 2 failures, 44851ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x92440010
       Store address: 0x00200344
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19453, step=2725, pc=0x002016A0, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19453, step=2725, pc=0x002016A0, major=6, minor=2
  [243] ✓ PRE_EXEC_REG_MOD @ step 3437: 4 failures, 38689ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000062 -> 0x84084392
       Register: x18 (s2), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=20239, step=3437, pc=0x00204D00, major=0, minor=1
         - IsRead@mem.zir:80
           cycle=20239, step=3437, pc=0x00204D00, major=0, minor=1
         - MemoryWrite@mem.zir:100
           cycle=20239, step=3437, pc=0x00204D00, major=0, minor=1
         - MemoryWrite@mem.zir:99
           cycle=20239, step=3437, pc=0x00204D00, major=0, minor=1
  [244] ✓ MEM_VAL_MOD @ step 368: 3 failures, 37438ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x0020036C -> 0xFFDFFC93
       Transaction: other_mem_read (READ) at address 0xffff002c
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 16955: preflight=0x000800db, actual=0x3ff7ff24
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - ECallHostReadWords@inst_ecall.zir:171
           cycle=16955, step=368, pc=0xC0000150, major=8, minor=5
         - IsRead@mem.zir:79
           cycle=16954, step=368, pc=0xC000014C, major=8, minor=2
         - IsRead@mem.zir:80
           cycle=16954, step=368, pc=0xC000014C, major=8, minor=2
  [245] ✓ INSTR_WORD_MOD_SUR @ step 3869: 0 failures, 34357ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x04C12B83 -> 0x04C12783
       Surgical: rd = 23 -> 15
       Original: LW x23, 76(x2)
       Mutated:  LW x15, 76(x2)
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20819: preflight=0x3fffc037, actual=0x3fffc02f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [246] ✓ INSTR_WORD_MOD_FULL @ step 1289: 3 failures, 22428ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x01070713 -> 0x045DE197
       Original: ADDI x14, x14, 16
       Mutated:  AUIPC x3, 0x45de000
       Format changed: I -> U
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 17933: preflight=0x3fffc02e, actual=0x3fffc03b
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:99
           cycle=17933, step=1289, pc=0x0020343C, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:96
           cycle=17933, step=1289, pc=0x0020343C, major=0, minor=7
         - VerifyOpcodeF3@inst.zir:97
           cycle=17933, step=1289, pc=0x0020343C, major=0, minor=7
  [247] ✓ PRE_EXEC_REG_MOD @ step 872: 2 failures, 24236ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x49080248
       Register: x0 (zero), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=17499, step=872, pc=0x00200A20, major=2, minor=6
         - IsRead@mem.zir:80
           cycle=17499, step=872, pc=0x00200A20, major=2, minor=6
  [248] ✓ STORE_OUT_MOD @ step 1198: 1 failures, 23774ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000001 -> 0x00000100
       Store address: 0x00221418
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=17842, step=1198, pc=0x00209C68, major=6, minor=2
  [249] ✓ MEM_VAL_MOD @ step 2152: 2 failures, 22706ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xE9680CEA
       Transaction: store_rmw_read (READ) at address 0x00221490
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=18806, step=2152, pc=0x00202564, major=6, minor=2
         - IsRead@mem.zir:80
           cycle=18806, step=2152, pc=0x00202564, major=6, minor=2
  [250] ✓ MEM_VAL_MOD @ step 2925: 7 failures, 25861ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+7 new]
       Value: 0x00A4FE63 -> 0x00010000
       Transaction: other_mem_read (READ) at address 0x002053b4
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19653: preflight=0x3fffc029, actual=0x3fffc022
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - IsRead@mem.zir:79
           cycle=19653, step=2925, pc=0x002053D0, major=2, minor=2
         - IsRead@mem.zir:80
           cycle=19653, step=2925, pc=0x002053D0, major=2, minor=2
         - MemoryWrite@mem.zir:99 (x3)
           cycle=19664, step=2936, pc=0x00205450, major=2, minor=3
         - VerifyOpcodeF3@inst.zir:96
           cycle=19653, step=2925, pc=0x002053D0, major=2, minor=2
         - VerifyOpcodeF3@inst.zir:97
           cycle=19653, step=2925, pc=0x002053D0, major=2, minor=2
  [251] ✓ INSTR_WORD_MOD_SUR @ step 1700: 0 failures, 22454ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x02060063 -> 0x020E8063
       Surgical: rs1 = 12 -> 29
       Original: BEQ x12, x0, 32
       Mutated:  BEQ x29, x0, 32
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18344: preflight=0x3fffc02c, actual=0x3fffc03d
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [252] ✓ COMP_OUT_MOD @ step 2963: 1 failures, 24448ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000010 -> 0x000000FF
       Destination: rd = x22 (s6)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=19691, step=2963, pc=0x0020568C, major=1, minor=2
  [253] ✓ PRE_EXEC_REG_MOD @ step 1393: 3 failures, 22216ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x00000085 -> 0x899BFBFC
       Register: x13 (a3), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18038: preflight=0x00086132, actual=0x00086138
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=18037, step=1393, pc=0x002184C8, major=1, minor=6
         - IsRead@mem.zir:80
           cycle=18037, step=1393, pc=0x002184C8, major=1, minor=6
         - MemoryWrite@mem.zir:99
           cycle=18211, step=1567, pc=0x00202C04, major=2, minor=4
  [254] ✓ INSTR_TYPE_MOD @ step 2665: 2 failures, 22444ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00010002 -> 0x00010001
       Original: AndI [major=1, minor=2]
       Mutated:  OrI [major=1, minor=1]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:99
           cycle=19393, step=2665, pc=0x0020346C, major=1, minor=1
         - VerifyOpcodeF3@inst.zir:97
           cycle=19393, step=2665, pc=0x0020346C, major=1, minor=1
  [255] ✓ INSTR_WORD_MOD_SUR @ step 1769: 0 failures, 23187ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00150513 -> 0x00150793
       Surgical: rd = 10 -> 15
       Original: ADDI x10, x10, 1
       Mutated:  ADDI x15, x10, 1
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18413: preflight=0x3fffc02a, actual=0x3fffc02f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [256] ✓ STORE_OUT_MOD @ step 644: 1 failures, 21597ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0xFFFF0000
       Store address: 0x00200354
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=17253, step=644, pc=0x00203198, major=6, minor=2
  [257] ✓ STORE_OUT_MOD @ step 1643: 2 failures, 15783ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x28000800
       Store address: 0x002000e0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18287, step=1643, pc=0x0020AEF0, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18287, step=1643, pc=0x0020AEF0, major=6, minor=2
  [258] ✓ INSTR_TYPE_MOD @ step 3322: 2 failures, 13078ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new] [+50 touch]
       Value: 0x00000003 -> 0x00040001
       Original: Or [major=0, minor=3]
       Mutated:  Sra [major=4, minor=1]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20124, step=3322, pc=0x00203304, major=4, minor=1
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=20124, step=3322, pc=0x00203304, major=4, minor=1
  [259] ✓ INSTR_WORD_MOD_FULL @ step 3223: 3 failures, 13400ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x40D585B3 -> 0xA91BE137
       Original: SUB x11, x11, x13
       Mutated:  LUI x2, 0xa91be000
       Format changed: R -> U
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20025: preflight=0x3fffc02b, actual=0x3fffc037
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=20025, step=3223, pc=0x00205E10, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=20025, step=3223, pc=0x00205E10, major=0, minor=1
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=20025, step=3223, pc=0x00205E10, major=0, minor=1
  [260] ✓ STORE_OUT_MOD @ step 2361: 2 failures, 18240ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x002B0042
       Store address: 0x0020033c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19015, step=2361, pc=0x0020327C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19015, step=2361, pc=0x0020327C, major=6, minor=2
  [261] ✓ LOAD_VAL_MOD @ step 2536: 2 failures, 15033ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x000000E3 -> 0x10202213
       Load destination: rd = x12 (a2)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19264, step=2536, pc=0x0020148C, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19264, step=2536, pc=0x0020148C, major=5, minor=3
  [262] ✓ PRE_EXEC_REG_MOD @ step 1187: 2 failures, 13158ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00200360 -> 0xEA736384
       Register: x2 (sp), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=17831, step=1187, pc=0x00209C3C, major=0, minor=7
         - IsRead@mem.zir:80
           cycle=17831, step=1187, pc=0x00209C3C, major=0, minor=7
  [263] ✓ INSTR_TYPE_MOD @ step 771: 3 failures, 17169ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new] [+37 touch]
       Value: 0x00000007 -> 0x00000005
       Original: AddI [major=0, minor=7]
       Mutated:  Slt [major=0, minor=5]
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (3 unique):
         - MemoryWrite@mem.zir:99
           cycle=17392, step=771, pc=0x002061C0, major=0, minor=5
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=17392, step=771, pc=0x002061C0, major=0, minor=5
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=17392, step=771, pc=0x002061C0, major=0, minor=5
  [264] ✓ INSTR_WORD_MOD_FULL @ step 3481: 0 failures, 16804ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00B6E463 -> 0x00BEE463
       Original: BLTU x13, x11, 8
       Mutated:  BLTU x29, x11, 8
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20283: preflight=0x3fffc02d, actual=0x3fffc03d
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [265] ✓ INSTR_WORD_MOD_FULL @ step 2267: 2 failures, 17671ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0056A623 -> 0x00168473
       Original: SW x5, 12(x13)
       Mutated:  EBREAK x8, x13, 1
       Format changed: S -> I
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18921: preflight=0x3fffc025, actual=0x3fffc021
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (2 unique):
         - VerifyOpcodeF3@inst.zir:96
           cycle=18921, step=2267, pc=0x00203438, major=6, minor=2
         - VerifyOpcodeF3@inst.zir:97
           cycle=18921, step=2267, pc=0x00203438, major=6, minor=2
  [266] ✓ PRE_EXEC_REG_MOD @ step 3682: 3 failures, 19609ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x002215CC -> 0x42EEAEFD
       Register: x14 (a4), READ, strategy=next_read
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20558: preflight=0x00088573, actual=0x10bbabbf
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - IsRead@mem.zir:79
           cycle=20558, step=3682, pc=0x002035E8, major=5, minor=0
         - IsRead@mem.zir:80
           cycle=20558, step=3682, pc=0x002035E8, major=5, minor=0
         - MemoryWrite@mem.zir:99
           cycle=20558, step=3682, pc=0x002035E8, major=5, minor=0
  [267] ✓ LOAD_VAL_MOD @ step 1223: 2 failures, 20278ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x63A67ED1
       Load destination: rd = x8 (s0/fp)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17867, step=1223, pc=0x0020B970, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17867, step=1223, pc=0x0020B970, major=5, minor=2
  [268] ✓ INSTR_WORD_MOD_SUR @ step 2460: 1 failures, 16826ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00A58533 -> 0x00A58505
       Surgical: opcode = 51 -> 5
       Original: ADD x10, x11, x10
       Mutated:  UNKNOWN 0x00a58505
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=19114, step=2460, pc=0x00205E20, major=0, minor=0
  [269] ✓ MEM_VAL_MOD @ step 2461: 2 failures, 20842ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xFFFFFFFF
       Transaction: other_mem_write (WRITE) at address 0xffff0180
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19115, step=2461, pc=0x00205E24, major=2, minor=1
         - MemoryWrite@mem.zir:99
           cycle=19115, step=2461, pc=0x00205E24, major=2, minor=1
  [270] ✓ INSTR_WORD_MOD_FULL @ step 3750: 0 failures, 16425ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x015405B3 -> 0x015404B3
       Original: ADD x11, x8, x21
       Mutated:  ADD x9, x8, x21
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20626: preflight=0x3fffc02b, actual=0x3fffc029
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [271] ✓ PRE_EXEC_REG_MOD @ step 2599: 4 failures, 16898ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x30A10000 -> 0xCF5EFFFF
       Register: x13 (a3), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=19327, step=2599, pc=0x00201588, major=0, minor=3
         - IsRead@mem.zir:80
           cycle=19327, step=2599, pc=0x00201588, major=0, minor=3
         - MemoryWrite@mem.zir:100
           cycle=19327, step=2599, pc=0x00201588, major=0, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19327, step=2599, pc=0x00201588, major=0, minor=3
  [272] ✓ STORE_OUT_MOD @ step 3715: 1 failures, 17742ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x80000000
       Store address: 0x0022164c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
           cycle=20591, step=3715, pc=0x00203238, major=6, minor=0
  [273] ✓ INSTR_TYPE_MOD @ step 1548: 4 failures, 17930ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new] [+36 touch]
       Value: 0x00000007 -> 0x00050004
       Original: AddI [major=0, minor=7]
       Mutated:  LhU [major=5, minor=4]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18192: preflight=0x3fffc021, actual=0x000867a4
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (4 unique):
         - MemoryWrite@mem.zir:100
           cycle=18192, step=1548, pc=0x002184CC, major=5, minor=4
         - MemoryWrite@mem.zir:99
           cycle=18192, step=1548, pc=0x002184CC, major=5, minor=4
         - VerifyOpcodeF3@inst.zir:96
           cycle=18192, step=1548, pc=0x002184CC, major=5, minor=4
         - VerifyOpcodeF3@inst.zir:97
           cycle=18192, step=1548, pc=0x002184CC, major=5, minor=4
  [274] ✓ INSTR_WORD_MOD_FULL @ step 3101: 3 failures, 15835ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+3 new]
       Value: 0x008A5513 -> 0x8F7482EF
       Original: SRLI x10, x20, 8
       Mutated:  JAL x5, -751370
       Format changed: I -> J
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 19829: preflight=0x3fffc034, actual=0x3fffc029
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (3 unique):
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=19829, step=3101, pc=0x0020578C, major=4, minor=2
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=19829, step=3101, pc=0x0020578C, major=4, minor=2
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=19829, step=3101, pc=0x0020578C, major=4, minor=2
  [275] ✓ INSTR_WORD_MOD_FULL @ step 2671: 1 failures, 14399ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00008067 -> 0x00009067
       Original: JALR x0, x1, 0
       Mutated:  JALR x0, x1, 0
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - VerifyOpcodeF3@inst.zir:97
           cycle=19399, step=2671, pc=0x0020530C, major=2, minor=4
  [276] ✓ PRE_EXEC_REG_MOD @ step 3448: 1 failures, 19121ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x40000000
       Register: x16 (a6), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - IsRead@mem.zir:80
           cycle=20250, step=3448, pc=0x00205354, major=2, minor=4
  [277] ✓ COMP_OUT_MOD @ step 3471: 2 failures, 18288ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00201388 -> 0x82815188
       Destination: rd = x1 (ra)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20273, step=3471, pc=0x0020538C, major=2, minor=6
         - MemoryWrite@mem.zir:99
           cycle=20273, step=3471, pc=0x0020538C, major=2, minor=6
  [278] ✓ STORE_OUT_MOD @ step 3919: 2 failures, 16416ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0F745431 -> 0x00010000
       Store address: 0xffff025c
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20869, step=3919, pc=0xC00000D4, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20869, step=3919, pc=0xC00000D4, major=6, minor=2
  [279] ✓ INSTR_WORD_MOD_FULL @ step 165: 1 failures, 20916ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x03022503 -> 0x03222503
       Original: LW x10, 48(x4)
       Mutated:  LW x10, 50(x4)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - OpLW@inst_mem.zir:109
           cycle=16738, step=165, pc=0xC000013C, major=5, minor=2
  [280] ✓ COMP_OUT_MOD @ step 3586: 2 failures, 21172ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000310 -> 0xF994FBE7
       Destination: rd = x20 (s4)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20462, step=3586, pc=0x0020566C, major=0, minor=7
         - MemoryWrite@mem.zir:99
           cycle=20462, step=3586, pc=0x0020566C, major=0, minor=7
  [281] ✓ INSTR_WORD_MOD_FULL @ step 3305: 0 failures, 15909ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x6A8080E7 -> 0x6A808067
       Original: JALR x1, x1, 1704
       Mutated:  JALR x0, x1, 1704
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20107: preflight=0x3fffc021, actual=0x3fffc060
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [282] ✓ LOAD_VAL_MOD @ step 2537: 2 failures, 20312ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000017 -> 0x8460E4F5
       Load destination: rd = x13 (a3)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19265, step=2537, pc=0x00201490, major=5, minor=3
         - MemoryWrite@mem.zir:99
           cycle=19265, step=2537, pc=0x00201490, major=5, minor=3
  [283] ✓ STORE_OUT_MOD @ step 700: 2 failures, 21079ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x80000007 -> 0x7FFFFFF8
       Store address: 0x00200370
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17315, step=700, pc=0x002031E8, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17315, step=700, pc=0x002031E8, major=6, minor=2
  [284] ✓ MEM_VAL_MOD @ step 3929: 0 failures, 15317ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00000000 -> 0x80005480
       Transaction: other_mem_read (READ) at address 0x00221014
       zkVM errors (2 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [kernels/cxx/buffers.h:43] SKIP THROW: Inconsistent set
       Proof verification failed (no local constraint failures)
  [285] ✓ INSTR_TYPE_MOD @ step 1597: 5 failures, 14960ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+5 new]
       Value: 0x00060002 -> 0x00030000
       Original: Sw [major=6, minor=2]
       Mutated:  Sll [major=3, minor=0]
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18241: preflight=0x0008006f, actual=0x3fffc03c
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (5 unique):
         - MemoryWrite@mem.zir:100
           cycle=18241, step=1597, pc=0x00204014, major=3, minor=0
         - MemoryWrite@mem.zir:99
           cycle=18241, step=1597, pc=0x00204014, major=3, minor=0
         - VerifyOpcodeF3F7@inst.zir:102
           cycle=18241, step=1597, pc=0x00204014, major=3, minor=0
         - VerifyOpcodeF3F7@inst.zir:103
           cycle=18241, step=1597, pc=0x00204014, major=3, minor=0
         - VerifyOpcodeF3F7@inst.zir:104
           cycle=18241, step=1597, pc=0x00204014, major=3, minor=0
  [286] ✓ COMP_OUT_MOD @ step 3035: 1 failures, 15007ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+1 new]
       Value: 0x00000000 -> 0x0000FFFF
       Destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (1 unique):
         - MemoryWrite@mem.zir:99
           cycle=19763, step=3035, pc=0x002035D4, major=1, minor=2
  [287] ✓ LOAD_VAL_MOD @ step 1581: 2 failures, 15256ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000004 -> 0x80080806
       Load destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18225, step=1581, pc=0x00202F1C, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18225, step=1581, pc=0x00202F1C, major=5, minor=2
  [288] ✓ PRE_EXEC_REG_MOD @ step 3293: 2 failures, 15208ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xFF7E33CF
       Register: x4 (tp), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - IsRead@mem.zir:79
           cycle=20095, step=3293, pc=0x0020346C, major=1, minor=2
         - IsRead@mem.zir:80
           cycle=20095, step=3293, pc=0x0020346C, major=1, minor=2
  [289] ✓ MEM_VAL_MOD @ step 2477: 2 failures, 15000ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00206244 -> 0x00000001
       Transaction: other_mem_write (WRITE) at address 0xffff0200
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19131, step=2477, pc=0xC0000070, major=7, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19131, step=2477, pc=0xC0000070, major=7, minor=2
  [290] ✓ STORE_OUT_MOD @ step 2828: 2 failures, 15290ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x2C0BE73D
       Store address: 0x002002a8
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19556, step=2828, pc=0x00203BA0, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19556, step=2828, pc=0x00203BA0, major=6, minor=2
  [291] ✓ STORE_OUT_MOD @ step 2172: 2 failures, 14319ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00221488 -> 0x00000040
       Store address: 0x002001d4
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=18826, step=2172, pc=0x002041D8, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=18826, step=2172, pc=0x002041D8, major=6, minor=2
  [292] ✓ INSTR_WORD_MOD_SUR @ step 1984: 0 failures, 14176ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0xFE0614E3 -> 0xFEF614E3
       Surgical: rs2 = 0 -> 15
       Original: BNE x12, x0, -24
       Mutated:  BNE x12, x15, -24
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 18633: preflight=0x3fffc020, actual=0x3fffc02f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [293] ✓ LOAD_VAL_MOD @ step 943: 2 failures, 14071ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xFFFFFFFF
       Load destination: rd = x10 (a0)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17576, step=943, pc=0x00200A38, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17576, step=943, pc=0x00200A38, major=5, minor=2
  [294] ✓ INSTR_WORD_MOD_FULL @ step 3463: 0 failures, 15652ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x40B686B3 -> 0x40B786B3
       Original: SUB x13, x13, x11
       Mutated:  SUB x13, x15, x11
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20265: preflight=0x3fffc02d, actual=0x3fffc02f
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Proof verification failed (no local constraint failures)
  [295] ✓ LOAD_VAL_MOD @ step 2822: 2 failures, 14457ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xA12E9EE3
       Load destination: rd = x11 (a1)
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19550, step=2822, pc=0x00203B88, major=5, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19550, step=2822, pc=0x00203B88, major=5, minor=2
  [296] ✓ MEM_VAL_MOD @ step 589: 2 failures, 14664ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0x62E10745
       Transaction: other_mem_write (WRITE) at address 0xffff0180
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=17192, step=589, pc=0x0020616C, major=2, minor=2
         - MemoryWrite@mem.zir:99
           cycle=17192, step=589, pc=0x0020616C, major=2, minor=2
  [297] ✓ STORE_OUT_MOD @ step 140: 2 failures, 14424ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x7F520E51 -> 0xCF5A0ED1
       Store address: 0x00221380
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=16713, step=140, pc=0x002010F0, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=16713, step=140, pc=0x002010F0, major=6, minor=2
  [298] ✓ INSTR_WORD_MOD_SUR @ step 3326: 2 failures, 15035ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x0036F593 -> 0xF646F593
       Surgical: imm = 3 -> 3940
       Original: ANDI x11, x13, 3
       Mutated:  ANDI x11, x13, -156
       zkVM errors (3 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
         • [ffi.cpp:113] address mismatch at cycle 20128: preflight=0x3fffc023, actual=0x3fffc024
         • [kernels/cxx/ffi.cpp:182] SKIP THROW: memory peek not in preflight
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=20128, step=3326, pc=0x00203408, major=1, minor=2
         - MemoryWrite@mem.zir:99
           cycle=20128, step=3326, pc=0x00203408, major=1, minor=2
  [299] ✓ STORE_OUT_MOD @ step 2793: 2 failures, 15426ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+2 new]
       Value: 0x00000000 -> 0xDD47098D
       Store address: 0x00200270
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
           cycle=19521, step=2793, pc=0x0020385C, major=6, minor=2
         - MemoryWrite@mem.zir:99
           cycle=19521, step=2793, pc=0x0020385C, major=6, minor=2
  [300] ✓ PRE_EXEC_REG_MOD @ step 3643: 4 failures, 15212ms, outcome: REJECTED, exit: 101 [proof:GENERATED] [+4 new]
       Value: 0x00000001 -> 0xFFFFFFFF
       Register: x13 (a3), READ, strategy=next_read
       zkVM errors (1 lines):
         • [prover_impl.rs:280] verify segment (internal proof verification failed)
       Constraints hit (4 unique):
         - IsRead@mem.zir:79
           cycle=20519, step=3643, pc=0x00203304, major=0, minor=3
         - IsRead@mem.zir:80
           cycle=20519, step=3643, pc=0x00203304, major=0, minor=3
         - MemoryWrite@mem.zir:100
           cycle=20519, step=3643, pc=0x00203304, major=0, minor=3
         - MemoryWrite@mem.zir:99
           cycle=20519, step=3643, pc=0x00203304, major=0, minor=3

============================================================
Campaign Summary
============================================================
Total mutations:     300
Successful (caused failures): 297
Skipped (no valid target):    0
Total failures:      781
Unique constraints:  24
New coverage:        781
New touch:           2007
Distinct touched:    2007
Execution time:      7259773ms

Outcome breakdown:
  REJECTED (mutation detected): 297
  CRASH (segfault, etc.):       3
  NO_EFFECT:                    0
  ACCEPTED (BUG!):              0
  SKIPPED:                      0

Mutations by kind:
  COMP_OUT_MOD: 30
  INSTR_TYPE_MOD: 28
  INSTR_WORD_MOD_FULL: 46
  INSTR_WORD_MOD_SUR: 29
  LOAD_VAL_MOD: 44
  MEM_VAL_MOD: 41
  PRE_EXEC_REG_MOD: 41
  STORE_OUT_MOD: 41