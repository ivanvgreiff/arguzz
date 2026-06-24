// =============================================================================
// IV.POS.9 Track-B  Guest 3 host (accelerator) — host_main.rs
// Baseline host structure VERBATIM (fingerprint, injection hooks, prover, verifier);
// only the input ABI (Args + writes) and the lenient Receipt Decoder differ.
// =============================================================================
use fuzzer_utils;
use risc0_methods::{RISC0_GUEST_ELF, RISC0_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use std::time::Instant;
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    trace: bool,
    #[arg(long, requires_all=["inject_step", "inject_kind", "seed"])]
    #[clap(long)]
    inject: bool,
    #[clap(long)]
    seed: Option<u64>,             // INJECTION seed
    #[clap(long)]
    inject_step: Option<u64>,
    #[clap(long)]
    inject_kind: Option<String>,

    // ---- Guest-3 inputs ----
    #[clap(long)]
    gseed: u32,                    // SHA seed + div accumulator seed
    #[clap(long)]
    modulus: u32,                  // divisor for the div/rem section (clamped in guest)
    #[clap(long)]
    rounds: u32,                   // SHA rounds (clamped in guest)
}

fn emit_build_fingerprint_if_requested() {
    if std::env::var("A4_INSPECT_FINGERPRINT").ok().as_deref() != Some("1") { return; }
    let planted_bug = option_env!("A4_PLANTED_BUG").unwrap_or("none");
    let isread_scope = option_env!("A4_ISREAD_SCOPE").unwrap_or("");
    let risc0_head_sha = option_env!("A4_RISC0_HEAD_SHA").unwrap_or("unknown");
    let load_rs2_present = option_env!("A4_LOAD_RS2_PRESENT").unwrap_or("1");
    let instrumentation_hash = option_env!("A4_INSTRUMENTATION_HASH").unwrap_or("unknown");
    let guest_id: Vec<u32> = RISC0_GUEST_ID.to_vec();
    println!(
        "<a4_fingerprint>{{\"planted_bug\":\"{}\",\"isread_scope\":\"{}\",\"risc0_head_sha\":\"{}\",\"load_rs2_present\":{},\"instrumentation_hash\":\"{}\",\"guest_image_id\":{:?}}}</a4_fingerprint>",
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

    let gseed: u32 = args.gseed;
    let modulus: u32 = args.modulus;
    let rounds: u32 = args.rounds;

    // == Setup ==
    println!("<record>{{\"context\":\"Environment Builder\", \"status\":\"start\"}}</record>");
    let timer = Instant::now();
    let executor_env = match ExecutorEnv::builder()
        .write(&gseed).unwrap()
        .write(&modulus).unwrap()
        .write(&rounds).unwrap()
        .build() {
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

    // == Output Receipt (lenient: multiple commits) ==
    println!("<record>{{\"context\":\"Receipt Decoder\", \"status\":\"start\"}}</record>");
    let timer = Instant::now();
    let receipt = prove_info.receipt;
    let n_journal_bytes = receipt.journal.bytes.len();
    let first_u32: u32 = { let b = &receipt.journal.bytes; if b.len() >= 4 { u32::from_le_bytes([b[0],b[1],b[2],b[3]]) } else { 0 } };
    println!("<record>{{\"context\":\"Receipt Decoder\", \"status\":\"success\", \"time\":\"{:.2?}\", \"output\":\"{}\", \"journal_bytes\":{}}}</record>", timer.elapsed(), first_u32, n_journal_bytes);

    // == Verifier ==
    if args.inject { fuzzer_utils::enable_assertions(); }
    println!("<record>{{\"context\":\"Verifier\", \"status\":\"start\"}}</record>");
    let timer = Instant::now();
    match receipt.verify(RISC0_GUEST_ID) {
        Ok(_) => { println!("<record>{{\"context\":\"Verifier\", \"status\":\"success\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed()); },
        Err(error) => { println!("<record>{{\"context\":\"Verifier\", \"status\":\"error\", \"time\":\"{:.2?}\"}}</record>", timer.elapsed()); panic!("{}", error); }
    }
}
