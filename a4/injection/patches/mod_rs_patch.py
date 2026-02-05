"""
A4 Patch for risc0/circuit/rv32im/src/prove/witgen/mod.rs

This patch adds:
1. A4_INSPECT - Preflight trace inspection
2. A4_MUTATION_CONFIG - Unified mutation configuration:
   - INSTR_TYPE_MOD: Mutate cycles[].major/minor
   - INSTR_WORD_MOD: Mutate instruction fetch txns[].word
   - COMP_OUT_MOD: Mutate WRITE transaction txns[].word (compute instructions)
   - LOAD_VAL_MOD: Mutate WRITE transaction txns[].word (load instructions)
   - STORE_OUT_MOD: Mutate WRITE transaction txns[].word (store instructions - memory)

Note: PRE_EXEC_PC_MOD is not supported by A4 because the circuit does not read
PC information from the preflight trace - it computes PC internally.
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
        if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
            match std::fs::read_to_string(&config_path) {
                Ok(config_str) => {
                    // Simple JSON parsing helpers
                    let extract_str = |key: &str| -> Option<String> {
                        config_str.find(&format!("\\"{}\\"", key)).and_then(|start| {
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
                        config_str.find(&format!("\\"{}\\"", key)).and_then(|start| {
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
                                for (cycle_idx, cycle) in trace.cycles.iter().enumerate() {
                                    if cycle.user_cycle == target_step {
                                        let fetch_txn_idx = cycle.txn_idx as usize;
                                        let expected_addr = cycle.pc / 4;
                                        
                                        if fetch_txn_idx < trace.txns.len() {
                                            let txn = &mut trace.txns[fetch_txn_idx];
                                            
                                            if txn.addr == expected_addr {
                                                let old_word = txn.word;
                                                txn.word = new_word;
                                                txn.prev_word = new_word;
                                                
                                                println!("<a4_instr_word_mod>{{\\"step\\":{}, \\"cycle_idx\\":{}, \\"txn_idx\\":{}, \\"pc\\":{}, \\"addr\\":{}, \\"old_word\\":{}, \\"new_word\\":{}, \\"major\\":{}, \\"minor\\":{}}}</a4_instr_word_mod>",
                                                         target_step, cycle_idx, fetch_txn_idx, cycle.pc, txn.addr, old_word, new_word, cycle.major, cycle.minor);
                                                found = true;
                                            } else {
                                                println!("<a4_error>{{\\"error\\":\\"addr mismatch\\", \\"expected\\":{}, \\"actual\\":{}}}</a4_error>",
                                                         expected_addr, txn.addr);
                                            }
                                        }
                                        break;
                                    }
                                }
                                if !found {
                                    println!("<a4_error>{{\\"error\\":\\"step not found\\", \\"step\\":{}}}</a4_error>", target_step);
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
