"""
A4 Patch for risc0/circuit/rv32im/src/prove/witgen/mod.rs

This patch adds:
1. A4_INSPECT - Preflight trace inspection (cycles, transactions)
2. A4_DUMP_STEP, A4_DUMP_TXN, A4_DUMP_REG_TXNS, A4_DUMP_ALL_TXNS - Detailed dumps
3. A4_MUTATION_CONFIG - Unified mutation configuration with FAULT_INJECTION:
   - INSTR_TYPE_MOD: Mutate cycles[].major/minor
   - INSTR_WORD_MOD: Mutate instruction fetch txns[].word (including ECALL)
   - COMP_OUT_MOD: Mutate WRITE transaction txns[].word (compute instructions)
   - LOAD_VAL_MOD: Mutate WRITE transaction txns[].word (load instructions)
   - STORE_OUT_MOD: Mutate WRITE transaction txns[].word (store instructions - memory)
   - PRE_EXEC_REG_MOD: Mutate register transaction txns[].word
   - MEM_VAL_MOD: Mutate memory transaction txns[].word

Note: PRE_EXEC_PC_MOD is not supported by A4 because the circuit does not read
PC information from the preflight trace - it computes PC internally.

CRITICAL: This patch includes automatic FAULT_INJECTION_ENABLED setting from Rust
(lines ~219-226) which is required for INSTR_WORD_MOD to work without crashes.
"""

# The marker to find the injection point
INJECTION_MARKER = 'let trace = segment.preflight(rand_z)?;'

# Replacement: make trace mutable
INJECTION_MARKER_REPLACEMENT = 'let mut trace = segment.preflight(rand_z)?;'

# The A4 inspection and mutation code to insert after the marker
A4_CODE_BLOCK = '''
        // >>> A4: PREFLIGHT INSPECTION <<<
        if std::env::var("A4_INSPECT").is_ok() {
            println!("<a4_inspect_meta>{{\\"cycles\\":{}, \\"txns\\":{}}}</a4_inspect_meta>",
                     trace.cycles.len(), trace.txns.len());
            
            // Dump cycle info with txn_idx mapping
            for (i, cycle) in trace.cycles.iter().enumerate() {
                println!("<a4_cycle_info>{{\\"cycle_idx\\":{}, \\"step\\":{}, \\"pc\\":{}, \\"txn_idx\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_cycle_info>",
                         i, cycle.user_cycle, cycle.pc, cycle.txn_idx, cycle.major, cycle.minor);
            }
            
            // Dump specific step's transactions if requested
            if let Ok(step_str) = std::env::var("A4_DUMP_STEP") {
                if let Ok(target_step) = step_str.parse::<u32>() {
                    for (i, cycle) in trace.cycles.iter().enumerate() {
                        if cycle.user_cycle == target_step {
                            let txn_start = cycle.txn_idx as usize;
                            let txn_end = if i + 1 < trace.cycles.len() {
                                trace.cycles[i + 1].txn_idx as usize
                            } else {
                                trace.txns.len()
                            };
                            
                            println!("<a4_step_txns>{{\\"step\\":{}, \\"cycle_idx\\":{}, \\"txn_start\\":{}, \\"txn_end\\":{}}}</a4_step_txns>",
                                     target_step, i, txn_start, txn_end);
                            
                            for txn_idx in txn_start..txn_end {
                                if txn_idx < trace.txns.len() {
                                    let txn = &trace.txns[txn_idx];
                                    println!("<a4_txn>{{\\"txn_idx\\":{}, \\"addr\\":{}, \\"cycle\\":{}, \\"word\\":{}, \\"prev_cycle\\":{}, \\"prev_word\\":{}}}</a4_txn>",
                                             txn_idx, txn.addr, txn.cycle, txn.word, txn.prev_cycle, txn.prev_word);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            
            // Dump specific txn if requested
            if let Ok(txn_str) = std::env::var("A4_DUMP_TXN") {
                if let Ok(txn_idx) = txn_str.parse::<usize>() {
                    if txn_idx < trace.txns.len() {
                        let txn = &trace.txns[txn_idx];
                        println!("<a4_txn_detail>{{\\"txn_idx\\":{}, \\"addr\\":{}, \\"cycle\\":{}, \\"word\\":{}, \\"prev_cycle\\":{}, \\"prev_word\\":{}}}</a4_txn_detail>",
                                 txn_idx, txn.addr, txn.cycle, txn.word, txn.prev_cycle, txn.prev_word);
                    }
                }
            }
            
            // Dump all register transactions (for PRE_EXEC_REG_MOD fast search)
            // USER_REGS_ADDR = 0xFFFF0080, word addr = 0xFFFF0080 / 4 = 1073725472
            // Registers x0-x31 are at word addresses 1073725472 to 1073725503
            if std::env::var("A4_DUMP_REG_TXNS").is_ok() {
                const USER_REGS_BASE: u32 = 1073725472;
                let mut reg_txn_count = 0;
                for (txn_idx, txn) in trace.txns.iter().enumerate() {
                    if txn.addr >= USER_REGS_BASE && txn.addr < USER_REGS_BASE + 32 {
                        // Find which cycle this transaction belongs to
                        let mut txn_step = 0u32;
                        for (ci, cycle) in trace.cycles.iter().enumerate() {
                            let txn_end = if ci + 1 < trace.cycles.len() {
                                trace.cycles[ci + 1].txn_idx
                            } else {
                                trace.txns.len() as u32
                            };
                            if (cycle.txn_idx..txn_end).contains(&(txn_idx as u32)) {
                                txn_step = cycle.user_cycle;
                                break;
                            }
                        }
                        println!("<a4_reg_txn>{{\\"txn_idx\\":{}, \\"step\\":{}, \\"addr\\":{}, \\"cycle\\":{}, \\"word\\":{}, \\"prev_cycle\\":{}, \\"prev_word\\":{}}}</a4_reg_txn>",
                                 txn_idx, txn_step, txn.addr, txn.cycle, txn.word, txn.prev_cycle, txn.prev_word);
                        reg_txn_count += 1;
                    }
                }
                println!("<a4_reg_txn_summary>{{\\"count\\":{}}}</a4_reg_txn_summary>", reg_txn_count);
            }
            
            // Dump ALL transactions (memory + registers) with step info
            // This is used for efficient STORE_OUT_MOD and future MEM_VAL_MOD
            // Format: <a4_all_txn> with txn_type field indicating "reg" or "mem"
            if std::env::var("A4_DUMP_ALL_TXNS").is_ok() {
                const USER_REGS_BASE: u32 = 1073725472;
                let mut current_cycle_idx = 0usize;
                let mut reg_count = 0u32;
                let mut mem_count = 0u32;
                
                for (txn_idx, txn) in trace.txns.iter().enumerate() {
                    // Find which cycle/step this transaction belongs to
                    while current_cycle_idx + 1 < trace.cycles.len() {
                        if (txn_idx as u32) < trace.cycles[current_cycle_idx + 1].txn_idx {
                            break;
                        }
                        current_cycle_idx += 1;
                    }
                    
                    let step = trace.cycles[current_cycle_idx].user_cycle;
                    let is_register = txn.addr >= USER_REGS_BASE && txn.addr < USER_REGS_BASE + 32;
                    let txn_type = if is_register { "reg" } else { "mem" };
                    
                    if is_register {
                        reg_count += 1;
                    } else {
                        mem_count += 1;
                    }
                    
                    println!("<a4_all_txn>{{\\"txn_idx\\":{}, \\"step\\":{}, \\"txn_type\\":\\"{}\\", \\"addr\\":{}, \\"cycle\\":{}, \\"word\\":{}, \\"prev_cycle\\":{}, \\"prev_word\\":{}}}</a4_all_txn>",
                             txn_idx, step, txn_type, txn.addr, txn.cycle, txn.word, txn.prev_cycle, txn.prev_word);
                }
                
                println!("<a4_all_txn_summary>{{\\"total\\":{}, \\"reg_count\\":{}, \\"mem_count\\":{}}}</a4_all_txn_summary>",
                         trace.txns.len(), reg_count, mem_count);
            }
        }
        // >>> END A4: PREFLIGHT INSPECTION <<<

        // >>> A4: UNIFIED MUTATION CONFIG <<<
        // Usage: A4_MUTATION_CONFIG=/path/to/config.json
        //
        // INSTR_TYPE_MOD: Mutate cycles[].major/minor (matches Arguzz INSTR_WORD_MOD effect)
        //   {"mutation_type": "INSTR_TYPE_MOD", "step": 198, "major": 1, "minor": 0}
        //
        // INSTR_WORD_MOD: Mutate txns[].word for instruction fetch
        //   {"mutation_type": "INSTR_WORD_MOD", "step": 198, "word": 8897555}
        //
        // COMP_OUT_MOD: Mutate txns[].word for WRITE transaction (matches Arguzz COMP_OUT_MOD effect)
        //   {"mutation_type": "COMP_OUT_MOD", "step": 198, "txn_idx": 16261, "word": 73117827}
        //
        // LOAD_VAL_MOD: Mutate txns[].word for WRITE transaction (matches Arguzz LOAD_VAL_MOD effect)
        //   {"mutation_type": "LOAD_VAL_MOD", "step": 205, "txn_idx": 16289, "word": 73117824}
        //
        // STORE_OUT_MOD: Mutate txns[].word for WRITE transaction to memory (matches Arguzz STORE_OUT_MOD effect)
        //   {"mutation_type": "STORE_OUT_MOD", "step": 212, "txn_idx": 16318, "word": 73117825}
        //
        // PRE_EXEC_REG_MOD: Mutate txns[].word for register transaction (matches Arguzz PRE_EXEC_REG_MOD effect)
        //   Supports two strategies:
        //   - "next_read" (default): Modify READ txn's word -> triggers IsRead + MemoryWrite
        //   - "prev_write": Modify WRITE txn's word -> triggers MemoryWrite only
        //   {"mutation_type": "PRE_EXEC_REG_MOD", "step": 2001, "txn_idx": 16289, "word": 1, "strategy": "next_read"}
        //   {"mutation_type": "PRE_EXEC_REG_MOD", "step": 1990, "txn_idx": 16200, "word": 1, "strategy": "prev_write"}
        //
        // MEM_VAL_MOD: Mutate txns[].word for memory transactions (non-register, non-instruction-fetch)
        //   Targets memory READs during loads, memory READs during stores (RMW pattern),
        //   and other memory transactions from system calls (SHA2, Poseidon2, BigInt).
        //   {"mutation_type": "MEM_VAL_MOD", "step": 300, "txn_idx": 17000, "word": 12345678}
        //
        if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
            // Enable fault injection to skip throws on address mismatches
            // This allows mutations that cause transaction mismatches to continue
            // rather than crashing. Set A4_NO_FAULT_INJECTION=1 to disable.
            if std::env::var("A4_NO_FAULT_INJECTION").is_err() {
                unsafe { std::env::set_var("FAULT_INJECTION_ENABLED", "1"); }
                println!("<a4_fault_injection_enabled/>");
            }
            
            match std::fs::read_to_string(&config_path) {
                Ok(config_str) => {
                    // Simple JSON parsing helpers
                    let extract_str = |key: &str| -> Option<String> {
                        config_str.find(&format!("\\"{}\\"\", key)).and_then(|start| {
                            let rest = &config_str[start + key.len() + 3..];
                            if let Some(quote_start) = rest.find('"') {
                                let value_start = quote_start + 1;
                                if let Some(quote_end) = rest[value_start..].find('"') {
                                    return Some(rest[value_start..value_start + quote_end].to_string());
                                }
                            }
                            None
                        })
                    };
                    
                    let extract_num = |key: &str| -> Option<u32> {
                        config_str.find(&format!("\\"{}\\"\", key)).and_then(|start| {
                            let rest = &config_str[start + key.len() + 3..];
                            let num_str: String = rest.chars()
                                .skip_while(|c| c.is_whitespace() || *c == ':')
                                .take_while(|c| c.is_ascii_digit())
                                .collect();
                            num_str.parse().ok()
                        })
                    };
                    
                    let mutation_type = extract_str("mutation_type");
                    let step = extract_num("step");
                    
                    println!("<a4_config_loaded>{{\\"path\\":\\"{}\\", \\"mutation_type\\":{:?}, \\"step\\":{:?}}}</a4_config_loaded>",
                             config_path, mutation_type, step);
                    
                    match (mutation_type.as_deref(), step) {
                        (Some("INSTR_TYPE_MOD"), Some(target_step)) => {
                            let new_major = extract_num("major").map(|v| v as u8);
                            let new_minor = extract_num("minor").map(|v| v as u8);
                            
                            if new_major.is_some() || new_minor.is_some() {
                                let mut found = false;
                                for (cycle_idx, cycle) in trace.cycles.iter_mut().enumerate() {
                                    if cycle.user_cycle == target_step {
                                        let old_major = cycle.major;
                                        let old_minor = cycle.minor;
                                        
                                        if let Some(major) = new_major { cycle.major = major; }
                                        if let Some(minor) = new_minor { cycle.minor = minor; }
                                        
                                        println!("<a4_instr_type_mod>{{\\"step\\":{}, \\"cycle_idx\\":{}, \\"pc\\":{}, \\"old_major\\":{}, \\"old_minor\\":{}, \\"new_major\\":{}, \\"new_minor\\":{}}}</a4_instr_type_mod>",
                                                 target_step, cycle_idx, cycle.pc, old_major, old_minor, cycle.major, cycle.minor);
                                        found = true;
                                        break;
                                    }
                                }
                                if !found {
                                    println!("<a4_error>{{\\"error\\":\\"step not found\\", \\"step\\":{}}}</a4_error>", target_step);
                                }
                            } else {
                                println!("<a4_error>{{\\"error\\":\\"INSTR_TYPE_MOD requires major and/or minor\\"}}</a4_error>");
                            }
                        }
                        (Some("INSTR_WORD_MOD"), Some(target_step)) => {
                            if let Some(new_word) = extract_num("word") {
                                let mut found = false;
                                // Find the instruction cycle for this step
                                // Multi-cycle steps may have ECALL/CONTROL cycles first, then instruction
                                // We want: major <= 6 (instruction) OR major == 8 (ECALL)
                                for (cycle_idx, cycle) in trace.cycles.iter().enumerate() {
                                    if cycle.user_cycle == target_step && 
                                       (cycle.major <= 6 || cycle.major == 8) {
                                        // Found an instruction or ECALL cycle
                                        let fetch_txn_idx = cycle.txn_idx as usize;
                                        
                                        if fetch_txn_idx < trace.txns.len() {
                                            let txn = &mut trace.txns[fetch_txn_idx];
                                            
                                            // The first transaction at cycle.txn_idx is the instruction fetch
                                            // No address check needed - txn_idx is authoritative
                                            // This fixes the branch/jump bug where (cycle.pc - 4) / 4 was wrong
                                            let old_word = txn.word;
                                            txn.word = new_word;
                                            txn.prev_word = new_word;
                                            
                                            println!("<a4_instr_word_mod>{{\\"step\\":{}, \\"cycle_idx\\":{}, \\"txn_idx\\":{}, \\"pc\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_instr_word_mod>",
                                                     target_step, cycle_idx, fetch_txn_idx, cycle.pc, txn.addr, old_word, new_word, cycle.major, cycle.minor);
                                            found = true;
                                        }
                                        break;
                                    }
                                }
                                if !found {
                                    println!("<a4_error>{{\\"error\\":\\"no instruction/ECALL cycle found\\", \\"step\\":{}}}</a4_error>", target_step);
                                }
                            } else {
                                println!("<a4_error>{{\\"error\\":\\"INSTR_WORD_MOD requires word\\"}}</a4_error>");
                            }
                        }
                        (Some("COMP_OUT_MOD"), Some(target_step)) => {
                            // COMP_OUT_MOD: Mutate a specific WRITE transaction's word
                            // This corresponds to Arguzz's COMP_OUT_MOD which changes the output
                            // value written to the destination register.
                            let txn_idx = extract_num("txn_idx");
                            let new_word = extract_num("word");
                            
                            match (txn_idx, new_word) {
                                (Some(idx), Some(word)) => {
                                    let idx = idx as usize;
                                    if idx < trace.txns.len() {
                                        let txn = &mut trace.txns[idx];
                                        let old_word = txn.word;
                                        let old_prev_word = txn.prev_word;
                                        
                                        // Mutate the word (the value being written)
                                        txn.word = word;
                                        // Note: We keep prev_word as is - it represents the value
                                        // that was at this address before this write.
                                        // Changing it would break memory consistency in a different way.
                                        
                                        // Find the cycle this transaction belongs to for logging
                                        let mut cycle_info = None;
                                        for (ci, cycle) in trace.cycles.iter().enumerate() {
                                            if cycle.user_cycle == target_step {
                                                cycle_info = Some((ci, cycle.pc, cycle.major, cycle.minor));
                                                break;
                                            }
                                        }
                                        
                                        if let Some((ci, pc, major, minor)) = cycle_info {
                                            println!("<a4_comp_out_mod>{{\\"step\\":{}, \\"cycle_idx\\":{}, \\"txn_idx\\":{}, \\"pc\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_comp_out_mod>",
                                                     target_step, ci, idx, pc, txn.addr, old_word, word, old_prev_word, major, minor);
                                        } else {
                                            println!("<a4_comp_out_mod>{{\\"step\\":{}, \\"txn_idx\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}}}</a4_comp_out_mod>",
                                                     target_step, idx, txn.addr, old_word, word, old_prev_word);
                                        }
                                    } else {
                                        println!("<a4_error>{{\\"error\\":\\"txn_idx out of range\\", \\"txn_idx\\":{}, \\"max\\":{}}}</a4_error>",
                                                 idx, trace.txns.len());
                                    }
                                }
                                _ => {
                                    println!("<a4_error>{{\\"error\\":\\"COMP_OUT_MOD requires txn_idx and word\\"}}</a4_error>");
                                }
                            }
                        }
                        (Some("LOAD_VAL_MOD"), Some(target_step)) => {
                            // LOAD_VAL_MOD: Mutate a specific WRITE transaction's word
                            // This corresponds to Arguzz's LOAD_VAL_MOD which changes the loaded
                            // value before writing to the destination register.
                            // Structurally identical to COMP_OUT_MOD.
                            let txn_idx = extract_num("txn_idx");
                            let new_word = extract_num("word");
                            
                            match (txn_idx, new_word) {
                                (Some(idx), Some(word)) => {
                                    let idx = idx as usize;
                                    if idx < trace.txns.len() {
                                        let txn = &mut trace.txns[idx];
                                        let old_word = txn.word;
                                        let old_prev_word = txn.prev_word;
                                        
                                        // Mutate the word (the loaded value being written)
                                        txn.word = word;
                                        
                                        // Find the cycle this transaction belongs to for logging
                                        let mut cycle_info = None;
                                        for (ci, cycle) in trace.cycles.iter().enumerate() {
                                            if cycle.user_cycle == target_step {
                                                cycle_info = Some((ci, cycle.pc, cycle.major, cycle.minor));
                                                break;
                                            }
                                        }
                                        
                                        if let Some((ci, pc, major, minor)) = cycle_info {
                                            println!("<a4_load_val_mod>{{\\"step\\":{}, \\"cycle_idx\\":{}, \\"txn_idx\\":{}, \\"pc\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_load_val_mod>",
                                                     target_step, ci, idx, pc, txn.addr, old_word, word, old_prev_word, major, minor);
                                        } else {
                                            println!("<a4_load_val_mod>{{\\"step\\":{}, \\"txn_idx\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}}}</a4_load_val_mod>",
                                                     target_step, idx, txn.addr, old_word, word, old_prev_word);
                                        }
                                    } else {
                                        println!("<a4_error>{{\\"error\\":\\"txn_idx out of range\\", \\"txn_idx\\":{}, \\"max\\":{}}}</a4_error>",
                                                 idx, trace.txns.len());
                                    }
                                }
                                _ => {
                                    println!("<a4_error>{{\\"error\\":\\"LOAD_VAL_MOD requires txn_idx and word\\"}}</a4_error>");
                                }
                            }
                        }
                        (Some("STORE_OUT_MOD"), Some(target_step)) => {
                            // STORE_OUT_MOD: Mutate a specific WRITE transaction's word
                            // This corresponds to Arguzz's STORE_OUT_MOD which changes the data
                            // value before writing to memory.
                            // Key difference from LOAD_VAL_MOD/COMP_OUT_MOD: writes to MEMORY, not register.
                            let txn_idx = extract_num("txn_idx");
                            let new_word = extract_num("word");
                            
                            match (txn_idx, new_word) {
                                (Some(idx), Some(word)) => {
                                    let idx = idx as usize;
                                    if idx < trace.txns.len() {
                                        let txn = &mut trace.txns[idx];
                                        let old_word = txn.word;
                                        let old_prev_word = txn.prev_word;
                                        
                                        // Mutate the word (the data value being stored to memory)
                                        txn.word = word;
                                        
                                        // Find the cycle this transaction belongs to for logging
                                        let mut cycle_info = None;
                                        for (ci, cycle) in trace.cycles.iter().enumerate() {
                                            if cycle.user_cycle == target_step {
                                                cycle_info = Some((ci, cycle.pc, cycle.major, cycle.minor));
                                                break;
                                            }
                                        }
                                        
                                        if let Some((ci, pc, major, minor)) = cycle_info {
                                            println!("<a4_store_out_mod>{{\\"step\\":{}, \\"cycle_idx\\":{}, \\"txn_idx\\":{}, \\"pc\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_store_out_mod>",
                                                     target_step, ci, idx, pc, txn.addr, old_word, word, old_prev_word, major, minor);
                                        } else {
                                            println!("<a4_store_out_mod>{{\\"step\\":{}, \\"txn_idx\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}}}</a4_store_out_mod>",
                                                     target_step, idx, txn.addr, old_word, word, old_prev_word);
                                        }
                                    } else {
                                        println!("<a4_error>{{\\"error\\":\\"txn_idx out of range\\", \\"txn_idx\\":{}, \\"max\\":{}}}</a4_error>",
                                                 idx, trace.txns.len());
                                    }
                                }
                                _ => {
                                    println!("<a4_error>{{\\"error\\":\\"STORE_OUT_MOD requires txn_idx and word\\"}}</a4_error>");
                                }
                            }
                        }
                        (Some("PRE_EXEC_REG_MOD"), Some(target_step)) => {
                            // PRE_EXEC_REG_MOD: Mutate a register transaction's word
                            // This corresponds to Arguzz's PRE_EXEC_REG_MOD which writes a random
                            // value to a register BEFORE instruction execution.
                            //
                            // TWO STRATEGIES:
                            // - "next_read" (default): Modify a READ transaction's word
                            //   Effect: word != prev_word at READ -> triggers IsRead + MemoryWrite
                            // - "prev_write": Modify a WRITE transaction's word
                            //   Effect: next READ's prev_word != modified word -> triggers MemoryWrite only
                            //
                            let txn_idx = extract_num("txn_idx");
                            let new_word = extract_num("word");
                            let strategy = extract_str("strategy").unwrap_or_else(|| "next_read".to_string());
                            
                            match (txn_idx, new_word) {
                                (Some(idx), Some(word)) => {
                                    let idx = idx as usize;
                                    if idx < trace.txns.len() {
                                        let txn = &mut trace.txns[idx];
                                        let old_word = txn.word;
                                        let prev_word = txn.prev_word;
                                        
                                        // Check transaction type
                                        let is_read = txn.cycle % 2 == 0;
                                        let is_write = txn.cycle % 2 == 1;
                                        
                                        // Validate transaction type matches strategy
                                        let valid = match strategy.as_str() {
                                            "next_read" => is_read,
                                            "prev_write" => is_write,
                                            _ => {
                                                println!("<a4_error>{{\\"error\\":\\"Unknown strategy\\", \\"strategy\\":\\"{}\\"}}</a4_error>", strategy);
                                                false
                                            }
                                        };
                                        
                                        if !valid && (strategy == "next_read" || strategy == "prev_write") {
                                            let expected = if strategy == "next_read" { "READ" } else { "WRITE" };
                                            let actual = if is_read { "READ" } else { "WRITE" };
                                            println!("<a4_error>{{\\"error\\":\\"Strategy mismatch\\", \\"strategy\\":\\"{}\\", \\"expected\\":\\"{}\\", \\"actual\\":\\"{}\\", \\"txn_idx\\":{}, \\"cycle\\":{}}}</a4_error>",
                                                     strategy, expected, actual, idx, txn.cycle);
                                        } else if valid {
                                            // Mutate the word
                                            txn.word = word;
                                            
                                            // Find the cycle this transaction belongs to for logging
                                            let mut cycle_info = None;
                                            for (ci, cycle) in trace.cycles.iter().enumerate() {
                                                if cycle.user_cycle == target_step {
                                                    cycle_info = Some((ci, cycle.pc, cycle.major, cycle.minor));
                                                    break;
                                                }
                                            }
                                            
                                            let txn_type = if is_read { "READ" } else { "WRITE" };
                                            if let Some((ci, pc, major, minor)) = cycle_info {
                                                println!("<a4_pre_exec_reg_mod>{{\\"step\\":{}, \\"strategy\\":\\"{}\\", \\"txn_type\\":\\"{}\\", \\"cycle_idx\\":{}, \\"txn_idx\\":{}, \\"pc\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_pre_exec_reg_mod>",
                                                         target_step, strategy, txn_type, ci, idx, pc, txn.addr, old_word, word, prev_word, major, minor);
                                            } else {
                                                println!("<a4_pre_exec_reg_mod>{{\\"step\\":{}, \\"strategy\\":\\"{}\\", \\"txn_type\\":\\"{}\\", \\"txn_idx\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"prev_word\\":{}}}</a4_pre_exec_reg_mod>",
                                                         target_step, strategy, txn_type, idx, txn.addr, old_word, word, prev_word);
                                            }
                                        }
                                    } else {
                                        println!("<a4_error>{{\\"error\\":\\"txn_idx out of range\\", \\"txn_idx\\":{}, \\"max\\":{}}}</a4_error>",
                                                 idx, trace.txns.len());
                                    }
                                }
                                _ => {
                                    println!("<a4_error>{{\\"error\\":\\"PRE_EXEC_REG_MOD requires txn_idx and word\\"}}</a4_error>");
                                }
                            }
                        }
                        (Some("MEM_VAL_MOD"), Some(target_step)) => {
                            // MEM_VAL_MOD: Mutate a memory transaction's word value
                            // 
                            // This targets:
                            // - load_mem_read: Memory READ during load instructions
                            // - store_rmw_read: Memory READ during store instructions (Read-Modify-Write)
                            // - other_mem_read/write: Memory ops during ECALLs (SHA2, Poseidon2, etc.)
                            //
                            // Exclusions (handled by Python):
                            // - Instruction fetch transactions (covered by INSTR_WORD_MOD)
                            // - Register transactions (covered by other mutations)
                            // - Store memory writes (covered by STORE_OUT_MOD)
                            let txn_idx = extract_num("txn_idx");
                            let new_word = extract_num("word");
                            
                            match (txn_idx, new_word) {
                                (Some(idx), Some(word)) => {
                                    let idx = idx as usize;
                                    if idx < trace.txns.len() {
                                        let txn = &mut trace.txns[idx];
                                        let old_word = txn.word;
                                        let is_write = txn.cycle % 2 == 1;
                                        let txn_type = if is_write { "WRITE" } else { "READ" };
                                        
                                        // Mutate the word
                                        txn.word = word;
                                        
                                        // Find the cycle this transaction belongs to for logging
                                        let mut cycle_info = None;
                                        for (ci, cycle) in trace.cycles.iter().enumerate() {
                                            if cycle.user_cycle == target_step {
                                                cycle_info = Some((ci, cycle.pc, cycle.major, cycle.minor));
                                                break;
                                            }
                                        }
                                        
                                        if let Some((ci, pc, major, minor)) = cycle_info {
                                            println!("<a4_mem_val_mod>{{\\"step\\":{}, \\"txn_type\\":\\"{}\\", \\"cycle_idx\\":{}, \\"txn_idx\\":{}, \\"pc\\":{}, \\"addr\\":{}, \\"byte_addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_mem_val_mod>",
                                                     target_step, txn_type, ci, idx, pc, txn.addr, txn.addr * 4, old_word, word, major, minor);
                                        } else {
                                            println!("<a4_mem_val_mod>{{\\"step\\":{}, \\"txn_type\\":\\"{}\\", \\"txn_idx\\":{}, \\"addr\\":{}, \\"byte_addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}}}</a4_mem_val_mod>",
                                                     target_step, txn_type, idx, txn.addr, txn.addr * 4, old_word, word);
                                        }
                                    } else {
                                        println!("<a4_error>{{\\"error\\":\\"MEM_VAL_MOD txn_idx out of range\\", \\"txn_idx\\":{}, \\"max\\":{}}}</a4_error>",
                                                 idx, trace.txns.len());
                                    }
                                }
                                _ => {
                                    println!("<a4_error>{{\\"error\\":\\"MEM_VAL_MOD requires txn_idx and word\\"}}</a4_error>");
                                }
                            }
                        }
                        _ => {
                            println!("<a4_error>{{\\"error\\":\\"invalid config\\", \\"mutation_type\\":{:?}, \\"step\\":{:?}}}</a4_error>",
                                     mutation_type, step);
                        }
                    }
                }
                Err(e) => {
                    println!("<a4_error>{{\\"error\\":\\"failed to read config\\", \\"path\\":\\"{}\\", \\"details\\":\\"{}\\"}}</a4_error>",
                             config_path, e);
                }
            }
        }
        // >>> END A4: UNIFIED MUTATION CONFIG <<<

'''

# The complete injection point (what to search for and replace)
INJECTION_POINT_BEFORE = '''        let trace = segment.preflight(rand_z)?;

        tracing::trace!("{segment:#?}");
        tracing::trace!("{trace:#?}");

        let cycles = trace.cycles.len();'''

INJECTION_POINT_AFTER = '''        let mut trace = segment.preflight(rand_z)?;

        tracing::trace!("{segment:#?}");
        tracing::trace!("{trace:#?}");
''' + A4_CODE_BLOCK + '''
        let cycles = trace.cycles.len();'''


def get_patch():
    """Return the patch configuration"""
    return {
        'search': INJECTION_POINT_BEFORE,
        'replace': INJECTION_POINT_AFTER,
    }
