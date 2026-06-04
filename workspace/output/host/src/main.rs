use fuzzer_utils;
use risc0_methods::{
    RISC0_GUEST_ELF, RISC0_GUEST_ID
};
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
    seed: Option<u64>,

    #[clap(long)]
    inject_step: Option<u64>,

    #[clap(long)]
    inject_kind: Option<String>,


    #[clap(long)]
    in0: bool,

    #[clap(long)]
    in1: u32,

    #[clap(long)]
    in2: bool,

    #[clap(long)]
    in3: bool,

    #[clap(long)]
    in4: u32,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

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

    let in0: bool = args.in0;
    let in1: u32 = args.in1;
    let in2: bool = args.in2;
    let in3: bool = args.in3;
    let in4: u32 = args.in4;

    // == Setup ==

    println!(
        "<record>{{\
            \"context\":\"Environment Builder\", \
            \"status\":\"start\"\
        }}</record>"
    );
    let timer = Instant::now();
    let executor_env = match ExecutorEnv::builder()
        // -- c0 --
        .write(&in0).unwrap()
        .write(&in1).unwrap()
        .write(&in2).unwrap()
        .write(&in3).unwrap()
        .write(&in4).unwrap()

        // -- c1 --
        .write(&in0).unwrap()
        .write(&in1).unwrap()
        .write(&in2).unwrap()
        .write(&in3).unwrap()
        .write(&in4).unwrap()

        .build() {
            Ok(executor_env) => {
                println!(
                    "<record>{{\
                        \"context\":\"Environment Builder\", \
                        \"status\":\"success\", \
                        \"time\":\"{:.2?}\"\
                    }}</record>",
                    timer.elapsed()
                );
                executor_env
            },
            Err(error) => {
                println!(
                    "<record>{{\
                        \"context\":\"Environment Builder\", \
                        \"status\":\"error\", \
                        \"time\":\"{:.2?}\"\
                    }}</record>",
                    timer.elapsed()
                );
                panic!("{}", error);
            }
    };

    // == Prover ==

    println!(
        "<record>{{\
            \"context\":\"Prover\", \
            \"status\":\"start\"\
        }}</record>"
    );
    let timer = Instant::now();
    let opts = ProverOpts::fast(); // linear in size of proof
    // let opts = ProverOpts::succinct(); // requires a big timeout
    let prover = default_prover();
    let prove_info = match prover.prove_with_opts(executor_env, RISC0_GUEST_ELF, &opts) {
        Ok(prove_info)   => {
            println!(
                "<record>{{\
                    \"context\":\"Prover\", \
                    \"status\":\"success\", \
                    \"time\":\"{:.2?}\"\
                }}</record>",
                timer.elapsed()
            );
            prove_info
        },
        Err(error) => {
            println!(
                "<record>{{\
                    \"context\":\"Prover\", \
                    \"status\":\"error\", \
                    \"time\":\"{:.2?}\"\
                }}</record>",
                timer.elapsed()
            );
            panic!("{}", error);
        }
    };

    // == Output Receipt ==

    println!(
        "<record>{{\
            \"context\":\"Receipt Decoder\", \
            \"status\":\"start\"\
        }}</record>"
    );
    let timer = Instant::now();
    let receipt = prove_info.receipt;
    let _output = match receipt.journal.decode::<u32>() {
        Ok(output) => {
            println!(
                "<record>{{\
                    \"context\":\"Receipt Decoder\", \
                    \"status\":\"success\", \
                    \"time\":\"{:.2?}\", \
                    \"output\":\"{:?}\"\
                }}</record>",
                timer.elapsed(),
                output
            );
            output
        },
        Err(error) => {
            println!(
                "<record>{{\
                    \"context\":\"Receipt Decoder\", \
                    \"status\":\"error\", \
                    \"time\":\"{:.2?}\"\
                }}</record>",
                timer.elapsed()
            );
            panic!("{}", error);
        }
    };

    // == Verifier ==
     if args.inject { fuzzer_utils::enable_assertions(); }

    println!(
        "<record>{{\
            \"context\":\"Verifier\", \
            \"status\":\"start\"\
        }}</record>"
    );
    let timer = Instant::now();
    match receipt.verify(RISC0_GUEST_ID) {
        Ok(_) => {
            println!(
                "<record>{{\
                    \"context\":\"Verifier\", \
                    \"status\":\"success\", \
                    \"time\":\"{:.2?}\"\
                }}</record>",
                timer.elapsed()
            );
        },
        Err(error) => {
            println!(
                "<record>{{\
                    \"context\":\"Verifier\", \
                    \"status\":\"error\", \
                    \"time\":\"{:.2?}\"\
                }}</record>",
                timer.elapsed()
            );
            panic!("{}", error);
        }
    }
}
