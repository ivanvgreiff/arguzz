from pathlib import Path

from risc0_fuzzer.settings import (
    GLOBAL_FAULT_INJECTION_ENV_KEY,
    CONSTRAINT_TRACE_ENV_KEY,
    CONSTRAINT_CONTINUE_ENV_KEY,
)
from zkvm_fuzzer_utils.file import create_file


def create_fuzzer_utils_crate(root: Path):
    create_cargo_toml(root)
    create_lib_rs(root)


def create_cargo_toml(root: Path):
    create_file(
        root / "fuzzer_utils" / "Cargo.toml",
        """[package]
name = "fuzzer_utils"
version = "1.0.0"
edition = "2021"

[dependencies]
lazy_static = "1.4"
""",
    )


def create_lib_rs(root: Path):
    create_file(
        root / "fuzzer_utils" / "src" / "lib.rs",
        '''use std::sync::Mutex;
use lazy_static::lazy_static;

use std::env;

////////////////
// GLOBAL STATE
/////////

#[derive(Debug, Clone)]
pub struct GlobalState {
    pub trace_logging: bool,
    pub injection: bool,
    pub assertions: bool,
    pub seed: u64,
    pub step: u64,
    pub injection_kind: String,
    pub injection_step: u64,
    pub hint_instruction: String,  // the default is an empty string
    pub hint_assembly: String,  // the default is an empty string
    pub hint_pc: u32,  // the default is an empty string
}

impl GlobalState {
    fn new() -> Self {
        Self {
            trace_logging: false,
            injection: false,
            assertions: true,
            seed: 0,
            injection_kind: String::new(),
            step: 0,
            injection_step: 0,
            hint_instruction: String::new(),
            hint_assembly: String::new(),
            hint_pc: 0,
        }
    }
}

lazy_static! {
    static ref GLOBAL_STATE: Mutex<GlobalState> = Mutex::new(GlobalState::new());
}

pub fn is_trace_logging() -> bool {
    GLOBAL_STATE.lock().unwrap().trace_logging
}

pub fn set_trace_logging(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.trace_logging = value;
}

pub fn enable_trace_logging() {
    set_trace_logging(true);
}

pub fn disable_trace_logging() {
    set_trace_logging(false);
}

////////////////
// CONSTRAINT TRACING
/////////

pub fn is_constraint_tracing() -> bool {
    env::var("''' + CONSTRAINT_TRACE_ENV_KEY + '''").is_ok()
}

pub fn set_constraint_tracing(value: bool) {
    if value {
        unsafe { env::set_var("''' + CONSTRAINT_TRACE_ENV_KEY + '''", "1"); }
    } else {
        unsafe { env::remove_var("''' + CONSTRAINT_TRACE_ENV_KEY + '''"); }
    }
}

pub fn enable_constraint_tracing() {
    set_constraint_tracing(true);
}

pub fn disable_constraint_tracing() {
    set_constraint_tracing(false);
}

/// Print a one-time "hello" message to confirm Rust constraint hook is active
pub fn hello_constraint_rust() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    if is_constraint_tracing() {
        ONCE.call_once(|| {
            println!("<hello_constraint>{{\\\"source\\\":\\\"rust_fuzzer_utils\\\", \\\"message\\\":\\\"constraint_hook_active\\\"}}</hello_constraint>");
        });
    }
}

////////////////
// CONSTRAINT CONTINUE MODE (Phase 2)
/////////

pub fn is_constraint_continue() -> bool {
    env::var("''' + CONSTRAINT_CONTINUE_ENV_KEY + '''").is_ok()
}

pub fn set_constraint_continue(value: bool) {
    if value {
        unsafe { env::set_var("''' + CONSTRAINT_CONTINUE_ENV_KEY + '''", "1"); }
    } else {
        unsafe { env::remove_var("''' + CONSTRAINT_CONTINUE_ENV_KEY + '''"); }
    }
}

pub fn enable_constraint_continue() {
    set_constraint_continue(true);
}

pub fn disable_constraint_continue() {
    set_constraint_continue(false);
}

pub fn is_injection() -> bool {
    GLOBAL_STATE.lock().unwrap().injection
}

pub fn set_injection(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection = value;
    if value {
        unsafe { env::set_var("'''
        + GLOBAL_FAULT_INJECTION_ENV_KEY
        + '''", "1"); }
    } else {
        unsafe { env::remove_var("'''
        + GLOBAL_FAULT_INJECTION_ENV_KEY
        + """"); }
    }
}

pub fn enable_injection() {
    set_injection(true);
}

pub fn disable_injection() {
    set_injection(false);
}

pub fn is_assertions() -> bool {
    GLOBAL_STATE.lock().unwrap().assertions
}

pub fn set_assertions(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.assertions = value;
}

pub fn enable_assertions() {
    set_assertions(true);
}

pub fn disable_assertions() {
    set_assertions(false);
}

pub fn set_seed(value: u64) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.seed = value;
}

pub fn get_seed() -> u64 {
    GLOBAL_STATE.lock().unwrap().seed
}

pub fn is_injection_kind(value: &str) -> bool {
    GLOBAL_STATE.lock().unwrap().injection_kind == value
}

pub fn set_injection_kind(value: String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection_kind = value.clone();
}

pub fn get_injection_kind() -> String {
    GLOBAL_STATE.lock().unwrap().injection_kind.clone()
}

pub fn inc_step() {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.step += 1;

    // TODO: in the future this should be either dynamic or a setting
    if state.step > 1000000 {
        panic!("Endless loop detection step bound triggered! Bound: 1000000 steps");
    }
}

pub fn get_step() -> u64 {
    GLOBAL_STATE.lock().unwrap().step
}

pub fn get_injection_step() -> u64 {
    GLOBAL_STATE.lock().unwrap().injection_step
}

pub fn set_injection_step(value: u64) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection_step = value;
}

pub fn is_injection_at_step(kind: &str) -> bool {
    let state = GLOBAL_STATE.lock().unwrap();
    state.injection &&
        state.step == state.injection_step &&
        state.injection_kind == kind
}

pub fn set_hint_instruction(value: &String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_instruction = value.clone();
}

pub fn get_hint_instruction() -> String {
    let state = GLOBAL_STATE.lock().unwrap();
    state.hint_instruction.clone()
}

pub fn set_hint_assembly(value: &String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_assembly = value.clone();
}

pub fn get_hint_assembly() -> String {
    let state = GLOBAL_STATE.lock().unwrap();
    state.hint_assembly.clone()
}

pub fn set_hint_pc(value: u32) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_pc = value;
}

pub fn get_hint_pc() -> u32 {
    let state = GLOBAL_STATE.lock().unwrap();
    state.hint_pc
}

pub fn update_hints(pc: u32, instruction: &String, assembly: &String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_pc = pc;
    state.hint_instruction = instruction.clone();
    state.hint_assembly = assembly.clone();
}

////////////////
// CUSTOM ASSERTION MACROS
/////////

/// Custom assert! macro
#[macro_export]
macro_rules! fuzzer_assert {
    ($cond:expr $(,)?) => {{
        if $crate::is_assertions() {
            assert!($cond);
        } else if !$cond {
            println!("Warning: fuzzer_assert! failed: {}", stringify!($cond));
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if $crate::is_assertions() {
            assert!($cond, $($arg)+);
        } else if !$cond {
            println!("Warning: fuzzer_assert! failed: {}", format_args!($($arg)+));
        }
    }};
}

/// Custom assert_eq! macro
#[macro_export]
macro_rules! fuzzer_assert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        if $crate::is_assertions() {
            assert_eq!($left, $right);
        } else if $left != $right {
            println!(
                "Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`)",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $crate::is_assertions() {
            assert_eq!($left, $right, $($arg)+);
        } else if $left != $right {
            println!(
                "Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`): {}",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
                format_args!($($arg)+),
            );
        }
    }};
}

/// Custom assert_ne! macro
#[macro_export]
macro_rules! fuzzer_assert_ne {
    ($left:expr, $right:expr $(,)?) => {{
        if $crate::is_assertions() {
            assert_ne!($left, $right);
        } else if $left == $right {
            println!(
                "Warning: fuzzer_assert_ne! failed: `{} == {}` (left: `{:?}`, right: `{:?}`)",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $crate::is_assertions() {
            assert_ne!($left, $right, $($arg)+);
        } else if $left == $right {
            println!(
                "Warning: fuzzer_assert_ne! failed: `{} == {}` (left: `{:?}`, right: `{:?}`): {}",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
                format_args!($($arg)+),
            );
        }
    }};
}


////////////////
// LOGGING
/////////

pub fn print_injection_info(
    inject_kind: &str,
    info: &String,
) {
    let state = GLOBAL_STATE.lock().unwrap();
    if state.trace_logging {
        println!(
            "<fault>{{\\
                \\"step\\":{}, \\
                \\"pc\\":{}, \\
                \\"instruction\\":\\"{}\\", \\
                \\"assembly\\":\\"{}\\", \\
                \\"kind\\":\\"{}\\", \\
                \\"info\\":\\"{}\\"\\
            }}</fault>",
            state.step,
            state.hint_pc,
            state.hint_instruction,
            state.hint_assembly,
            inject_kind,
            info,
        );
    }
}

pub fn print_trace_info() {
    let state = GLOBAL_STATE.lock().unwrap();
    if state.trace_logging {
        println!(
            "<trace>{{\\
                \\"step\\":{}, \\
                \\"pc\\":{}, \\
                \\"instruction\\":\\"{}\\", \\
                \\"assembly\\":\\"{}\\"\\
            }}</trace>",
            state.step,
            state.hint_pc,
            state.hint_instruction,
            state.hint_assembly,
        );
    }
}
""",  # noqa: E501
    )
