// =============================================================================
// IV.POS.9 Track-B  Guest 1 host (ECALL/control-boundary) — host_main.rs
// Baseline host structure preserved VERBATIM (fingerprint emit, injection hooks,
// prover, verifier) — only the input ABI (Args + ExecutorEnv writes) and the
// Receipt Decoder (lenient, since G1 commits multiple times) differ.
// =============================================================================
use fuzzer_utils;
use risc0_methods::{
    RISC0_GUEST_ELF, RISC0_GUEST_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use std::time::Instant;
use clap::Parser;

const STAGE_MAX: u32 = 24;   // must match the guest

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    trace: bool,

    #[arg(long, requires_all=["inject_step", "inject_kind", "seed"])]
    #[clap(long)]
    inject: bool,

    #[clap(long)]
    seed: Option<u64>,          // INJECTION seed (Arguzz/A4 fault path) — unchanged

    #[clap(long)]
    inject_step: Option<u64>,

    #[clap(long)]
    inject_kind: Option<String>,

    // ---- Guest-1 inputs (distinct names; `seed` above is the injection seed) ----
    #[clap(long)]
    ctrl: u32,                  // per-stage path-selector bitmask

    #[clap(long)]
    gseed: u32,                 // accumulator seed

    #[clap(long)]
    rounds: u32,                // requested stage count (clamped to STAGE_MAX in guest)
}

fn emit_build_fingerprint_if_requested() {
    if std::env::var("A4_INSPECT_FINGERPRINT").ok().as_deref() != Some("1") {
        return;
    }
    let planted_bug = option_env!("A4_PLANTED_BUG").unwrap_or("none");
    let isread_scope = option_env!("A4_ISREAD_SCOPE").unwrap_or("");
    let risc0_head_sha = option_env!("A4_RISC0_HEAD_SHA").unwrap_or("unknown");
    let load_rs2_present = option_env!("A4_LOAD_RS2_PRESENT").unwrap_or("1");
    let instrumentation_hash = option_env!("A4_INSTRUMENTATION_HASH").unwrap_or("unknown");
    let guest_id: Vec<u32> = RISC0_GUEST_ID.to_vec();
    println!(
        "<a4_fingerprint>{{\
            \"planted_bug\":\"{}\",\
            \"isread_scope\":\"{}\",\
            \"risc0_head_sha\":\"{}\",\
            \"load_rs2_present\":{},\
            \"instrumentation_hash\":\"{}\",\
            \"guest_image_id\":{:?}\
        }}</a4_fingerprint>",
        planted_bug, isread_scope, risc0_head_sha, load_rs2_present, instrumentation_hash, guest_id,
    );
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    emit_build_fingerprint_if_requested();

    let args = Args::parse();
    fuzzer_utils::set_trace_logging(args.trace);
    fuzzer_utils::set_injection(args.inject);
    if args.inject {
        fuzzer_utils::set_seed(args.seed.unwrap());
        fuzzer_utils::set_injection_step(args.inject_step.unwrap());
        fuzzer_utils::set_injection_kind(args.inject_kind.unwrap());
        fuzzer_utils::disable_assertions();
    } else {
        fuzzer_utils::enable_assertions();
    }

    let ctrl: u32 = args.ctrl;
    let gseed: u32 = args.gseed;
    let rounds: u32 = args.rounds;

    // == Setup ==
    println!("<record>{{\"context\":\"Environment Builder\", \"status\":\"start\"}}</record>");
    let timer = Instant::now();
    let mut builder = ExecutorEnv::builder();
    builder.write(&ctrl).unwrap();
    builder.write(&gseed).unwrap();
    builder.write(&rounds).unwrap();
    // STAGE_MAX deterministic stage values, derived from the args (host-side, so the
    // guest's per-stage env::read crossings always have data to consume).
    for i in 0..STAGE_MAX {
        let v: u32 = gseed.wrapping_mul(i.wrapping_add(1)) ^ ctrl.rotate_left(i & 31);
        builder.write(&v).unwrap();
    }
    let executor_env = match builder.build() {
        Ok(env) => {
            println!("<record>{{\"context\":\"Environment Builder\", \"status\":\"success\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed());
            env
        },
        Err(error) => {
            println!("<record>{{\"context\":\"Environment Builder\", \"status\":\"error\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed());
            panic!("{}", error);
        }
    };

    // == Prover ==
    println!("<record>{{\"context\":\"Prover\", \"status\":\"start\"}}</record>");
    let timer = Instant::now();
    let opts = ProverOpts::fast();
    let prover = default_prover();
    let prove_info = match prover.prove_with_opts(executor_env, RISC0_GUEST_ELF, &opts) {
        Ok(prove_info) => {
            println!("<record>{{\"context\":\"Prover\", \"status\":\"success\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed());
            prove_info
        },
        Err(error) => {
            println!("<record>{{\"context\":\"Prover\", \"status\":\"error\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed());
            panic!("{}", error);
        }
    };

    // == Output Receipt (LENIENT: G1 commits multiple u32s, so report journal size,
    //    not a strict single-u32 decode that would error on trailing data) ==
    println!("<record>{{\"context\":\"Receipt Decoder\", \"status\":\"start\"}}</record>");
    let timer = Instant::now();
    let receipt = prove_info.receipt;
    let n_journal_bytes = receipt.journal.bytes.len();
    let first_u32: u32 = {
        let b = &receipt.journal.bytes;
        if b.len() >= 4 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) } else { 0 }
    };
    println!(
        "<record>{{\"context\":\"Receipt Decoder\", \"status\":\"success\", \"time\":\"{:.2?}\", \"output\":\"{}\", \"journal_bytes\":{}}}</record>",
        timer.elapsed(), first_u32, n_journal_bytes
    );

    // == Verifier ==
    if args.inject { fuzzer_utils::enable_assertions(); }
    println!("<record>{{\"context\":\"Verifier\", \"status\":\"start\"}}</record>");
    let timer = Instant::now();
    match receipt.verify(RISC0_GUEST_ID) {
        Ok(_) => {
            println!("<record>{{\"context\":\"Verifier\", \"status\":\"success\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed());
        },
        Err(error) => {
            println!("<record>{{\"context\":\"Verifier\", \"status\":\"error\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed());
            panic!("{}", error);
        }
    }
}
