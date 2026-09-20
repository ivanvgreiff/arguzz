# Alias-divide 53 mutations — constraint contexts (CORRECTED taxonomy)
Layers per `CONSTRAINTS_EXPLAINED.md`:
- **Intrastep local** = `failures` rows (within-step: MemoryWrite, VerifyOpcode, …)
- **Interstep local** = `failures` rows at IsRead/IsCycle sites (cross-step: prev_word, read-returns-last-write)
- **Global (Hook 3)** = ALL `global_failures` rows (memory / cycle / u16 / u8 permutation & lookup arguments)
- **Oracle hit** = zero local (intra+inter) AND global>0

### V5 seed1234 id=2027 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222
  2. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135
  3. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135

### V5 seed1234 id=2127 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123
  2. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  3. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202

### V5 seed1235 id=728 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222
  2. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135
  3. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135

### V5 seed1235 id=1428 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125

### V5 seed1235 id=2228 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133

### V5 seed1235 id=2928 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133

### V5 seed1236 id=336 | INSTR_WORD_MOD_SUR step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  2. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125
  3. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202

### V5 seed1236 id=628 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  2. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

### V5 seed1236 id=1828 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  2. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

### V5 seed1236 id=2536 | INSTR_WORD_MOD_SUR step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  2. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125
  3. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202

### V5 seed1236 id=3428 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  2. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

### V5 seed1236 id=4436 | INSTR_WORD_MOD_SUR step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222

### V5 seed1237 id=528 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  2. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222

### V5 seed1237 id=1128 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  2. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222

### V5 seed1237 id=3036 | INSTR_WORD_MOD_SUR step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  2. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222

### V5 seed1238 id=2728 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  2. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123
  3. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123

### V5 seed1238 id=2828 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  3. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133

### V5 seed1238 id=4636 | INSTR_WORD_MOD_SUR step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  2. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123
  3. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123

### V5 seed1239 id=1128 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 5
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c654b3 mismatch_cycle=4222
  2. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135
  3. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135
  4. [memory] register x9 wrote=None expected=0x00000007 mismatch_cycle=21118
  5. [memory] register x8 wrote=0x00000007 expected=None mismatch_cycle=21118

### V5 seed1239 id=1136 | INSTR_WORD_MOD_SUR step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125

### V5 seed1239 id=3328 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133

### V5 seed1239 id=3428 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125

### V5 seed1239 id=4128 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222
  3. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135

### V5 seed1239 id=4328 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125

### Hybrid seed1234 id=1156 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  3. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133

### Hybrid seed1234 id=1257 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  3. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133

### Hybrid seed1234 id=2800 | INSTR_WORD_MOD_SUR step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  3. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133

### Hybrid seed1234 id=2889 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222
  3. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135

### Hybrid seed1234 id=4099 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222
  3. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135

### Hybrid seed1235 id=863 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135
  2. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222
  3. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135

### Hybrid seed1235 id=968 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202

### Hybrid seed1235 id=2394 | INSTR_WORD_MOD_SUR step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  3. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133

### Hybrid seed1235 id=3399 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202

### Hybrid seed1236 id=1593 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125
  2. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202
  3. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125

### Hybrid seed1236 id=1694 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125
  2. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202
  3. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125

### Hybrid seed1236 id=3626 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133

### Hybrid seed1236 id=3730 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  2. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

### Hybrid seed1236 id=4846 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133

### Hybrid seed1237 id=875 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  2. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

### Hybrid seed1237 id=1591 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222
  2. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135
  3. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135

### Hybrid seed1237 id=3029 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  2. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222

### Hybrid seed1237 id=3222 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  2. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222

### Hybrid seed1237 id=3362 | INSTR_WORD_MOD_SUR step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  2. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

### Hybrid seed1237 id=3438 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125

### Hybrid seed1237 id=3934 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  2. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

### Hybrid seed1237 id=4041 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  2. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222

### Hybrid seed1238 id=2406 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 5
  1. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133
  2. [memory] data @ byte_addr=4294902144 wrote=None expected=0x00000007 mismatch_cycle=21118
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d033 mismatch_cycle=4222
  4. [memory] register x8 wrote=0x00000007 expected=None mismatch_cycle=21118
  5. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133

### Hybrid seed1239 id=1674 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133

### Hybrid seed1239 id=1879 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135
  2. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222

### Hybrid seed1239 id=2078 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs2:=rs1 | orig x10/x11 -> mut x10/x10 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x10 wrote=None expected=0x0000313a mismatch_cycle=21125
  2. [memory] register x11 wrote=0x0000313a expected=None mismatch_cycle=21125
  3. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02a57733 mismatch_cycle=4202

### Hybrid seed1239 id=2180 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs1:=rs2 | orig x12/x13 -> mut x13/x13 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02d6d433 mismatch_cycle=4222
  2. [memory] register x13 wrote=None expected=0x00000009 mismatch_cycle=21133
  3. [memory] register x12 wrote=0x00000009 expected=None mismatch_cycle=21133

### Hybrid seed1239 id=2785 | INSTR_WORD_MOD_FULL step=441 f3=5 | rs2:=rs1 | orig x12/x13 -> mut x12/x12 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] register x12 wrote=None expected=0x0000313a mismatch_cycle=21135
  2. [memory] register x13 wrote=0x0000313a expected=None mismatch_cycle=21135
  3. [memory] code @ byte_addr=2099404 wrote=0x02d65433 expected=0x02c65433 mismatch_cycle=4222

### Hybrid seed1239 id=2997 | INSTR_WORD_MOD_FULL step=436 f3=7 | rs1:=rs2 | orig x10/x11 -> mut x11/x11 | **oracle=YES**
- **Intrastep local (`failures`, within-step):** 0
- **Interstep local (`failures`, IsRead/IsCycle):** 0
- **Global Hook 3 (`global_failures`):** 3
  1. [memory] code @ byte_addr=2099384 wrote=0x02b57733 expected=0x02b5f733 mismatch_cycle=4202
  2. [memory] register x11 wrote=None expected=0x00000009 mismatch_cycle=21123
  3. [memory] register x10 wrote=0x00000009 expected=None mismatch_cycle=21123

