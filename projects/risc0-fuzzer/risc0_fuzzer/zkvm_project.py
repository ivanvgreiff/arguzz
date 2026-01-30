import io
from pathlib import Path

from circil.ir.node import Circuit
from risc0_fuzzer.settings import (
    RUST_GUEST_CORRECT_VALUE,
    RUST_GUEST_RETURN_TYPE,
    RUST_TOOLCHAIN_VERSION,
)
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractCircuitProjectGenerator
from zkvm_fuzzer_utils.rust.common import (
    ir_type_to_str,
    stream_circuit_output_and_compare_routine,
)
from zkvm_fuzzer_utils.rust.ir2rust import CircIL2UnsafeRustEmitter


class CircuitProjectGenerator(AbstractCircuitProjectGenerator):
    def __init__(
        self,
        root: Path,
        zkvm_path: Path,
        circuits: list[Circuit],
        fault_injection: bool,
        trace_collection: bool,
    ):
        super().__init__(root, zkvm_path, circuits, fault_injection, trace_collection)

    def create(self):
        self.create_root_cargo_toml()
        self.create_root_rust_toolchain()
        self.create_host_cargo_toml()
        self.create_host_main_rs()
        self.create_methods_cargo_toml()
        self.create_methods_build_rs()
        self.create_methods_lib_rs()
        self.create_guest_cargo_toml()
        self.create_guest_main_rs()

    def create_root_cargo_toml(self):
        create_file(
            self.root / "Cargo.toml",
            """[workspace]
members = [
    "host",
    "methods",
    "methods/guest",
]
default-members = [ "host" ]

resolver = "2"
""",
        )

    def create_root_rust_toolchain(self):
        create_file(
            self.root / "rust-toolchain.toml",
            f"""[toolchain]
channel = "{RUST_TOOLCHAIN_VERSION}"
components = ["rustfmt", "rust-src"]
profile = "minimal"
""",
        )

    def create_host_cargo_toml(self):
        buffer = io.StringIO()
        buffer.write(
            f"""[package]
name = "risc0-host"
version = "0.1.0"
edition = "2021"
default-run = "risc0-host"

[dependencies]
risc0-methods = {{ path = "../methods" }}
risc0-zkvm = {{ path = "{self.zkvm_path}/risc0/zkvm" }}
tracing-subscriber = {{ version = "0.3", features = ["env-filter"] }}
clap = {{ version = "4.0", features = ["derive", "env"] }}
"""
        )

        if self.requires_fuzzer_utils:
            buffer.write(f'fuzzer_utils = {{ path = "{self.zkvm_path}/fuzzer_utils" }}\n')

        buffer.write(
            """

[features]
default = ["prove"] # ["prove", "heap-embedded-alloc"]
prove = ["risc0-zkvm/prove", "risc0-zkvm/witgen_debug"]
# heap-embedded-alloc = ["risc0-zkvm-platform/heap-embedded-alloc"]
"""
        )
        create_file(self.root / "host" / "Cargo.toml", buffer.getvalue())

    def create_host_main_rs(self):
        buffer = io.StringIO()

        if self.requires_fuzzer_utils:
            buffer.write("use fuzzer_utils;\n")

        buffer.write(
            """use risc0_methods::{
    RISC0_GUEST_ELF, RISC0_GUEST_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use std::time::Instant;
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
        """
        )

        if self.is_trace_collection:
            buffer.write("    #[clap(long)]\n")
            buffer.write("    trace: bool,\n")
            buffer.write("\n")

        if self.is_fault_injection:
            buffer.write('    #[arg(long, requires_all=["inject_step", "inject_kind", "seed"])]\n')
            buffer.write("    #[clap(long)]\n")
            buffer.write("    inject: bool,\n\n")

            buffer.write("    #[clap(long)]\n")
            buffer.write("    seed: Option<u64>,\n\n")

            buffer.write("    #[clap(long)]\n")
            buffer.write("    inject_step: Option<u64>,\n\n")

            buffer.write("    #[clap(long)]\n")
            buffer.write("    inject_kind: Option<String>,\n\n")

        for e in self.circuit_candidate.inputs:
            buffer.write("\n")
            buffer.write("    #[clap(long)]\n")
            buffer.write(f"    {e.name}: {ir_type_to_str(e.ty_hint)},\n")

        buffer.write(
            """}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
"""
        )

        if self.is_trace_collection:
            buffer.write("    fuzzer_utils::set_trace_logging(args.trace);\n")

        if self.is_fault_injection:
            buffer.write("    fuzzer_utils::set_injection(args.inject);\n")
            buffer.write("    if args.inject {\n")
            buffer.write("        fuzzer_utils::set_seed(args.seed.unwrap());\n")
            buffer.write("        fuzzer_utils::set_injection_step(args.inject_step.unwrap());\n")
            buffer.write("        fuzzer_utils::set_injection_kind(args.inject_kind.unwrap());\n")
            buffer.write("        fuzzer_utils::disable_assertions();\n")
            buffer.write("    } else {\n")
            buffer.write("        fuzzer_utils::enable_assertions();\n")
            buffer.write("    }\n\n")

        for e in self.circuit_candidate.inputs:
            param_type = ir_type_to_str(e.ty_hint)
            buffer.write(f"    let {e.name}: {param_type} = args.{e.name};\n")

        buffer.write(
            """
    // == Setup ==

    println!(
        "<record>{{\\
            \\"context\\":\\"Environment Builder\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();
    let executor_env = match ExecutorEnv::builder()
"""
        )
        for circuit in self.circuits:
            buffer.write(f"        // -- {circuit.name} --\n")
            for e in self.circuit_candidate.inputs:
                buffer.write(f"        .write(&{e.name}).unwrap()\n")
            buffer.write("\n")
        buffer.write(
            f"""        .build() {{
            Ok(executor_env) => {{
                println!(
                    "<record>{{{{\\
                        \\"context\\":\\"Environment Builder\\", \\
                        \\"status\\":\\"success\\", \\
                        \\"time\\":\\"{{:.2?}}\\"\\
                    }}}}</record>",
                    timer.elapsed()
                );
                executor_env
            }},
            Err(error) => {{
                println!(
                    "<record>{{{{\\
                        \\"context\\":\\"Environment Builder\\", \\
                        \\"status\\":\\"error\\", \\
                        \\"time\\":\\"{{:.2?}}\\"\\
                    }}}}</record>",
                    timer.elapsed()
                );
                panic!("{{}}", error);
            }}
    }};

    // == Prover ==

    println!(
        "<record>{{{{\\
            \\"context\\":\\"Prover\\", \\
            \\"status\\":\\"start\\"\\
        }}}}</record>"
    );
    let timer = Instant::now();
    let opts = ProverOpts::fast(); // linear in size of proof
    // let opts = ProverOpts::succinct(); // requires a big timeout
    let prover = default_prover();
    let prove_info = match prover.prove_with_opts(executor_env, RISC0_GUEST_ELF, &opts) {{
        Ok(prove_info)   => {{
            println!(
                "<record>{{{{\\
                    \\"context\\":\\"Prover\\", \\
                    \\"status\\":\\"success\\", \\
                    \\"time\\":\\"{{:.2?}}\\"\\
                }}}}</record>",
                timer.elapsed()
            );
            prove_info
        }},
        Err(error) => {{
            println!(
                "<record>{{{{\\
                    \\"context\\":\\"Prover\\", \\
                    \\"status\\":\\"error\\", \\
                    \\"time\\":\\"{{:.2?}}\\"\\
                }}}}</record>",
                timer.elapsed()
            );
            panic!("{{}}", error);
        }}
    }};

    // == Output Receipt ==

    println!(
        "<record>{{{{\\
            \\"context\\":\\"Receipt Decoder\\", \\
            \\"status\\":\\"start\\"\\
        }}}}</record>"
    );
    let timer = Instant::now();
    let receipt = prove_info.receipt;
    let _output = match receipt.journal.decode::<{RUST_GUEST_RETURN_TYPE}>() {{
        Ok(output) => {{
            println!(
                "<record>{{{{\\
                    \\"context\\":\\"Receipt Decoder\\", \\
                    \\"status\\":\\"success\\", \\
                    \\"time\\":\\"{{:.2?}}\\", \\
                    \\"output\\":\\"{{:?}}\\"\\
                }}}}</record>",
                timer.elapsed(),
                output
            );
            output
        }},
        Err(error) => {{
            println!(
                "<record>{{{{\\
                    \\"context\\":\\"Receipt Decoder\\", \\
                    \\"status\\":\\"error\\", \\
                    \\"time\\":\\"{{:.2?}}\\"\\
                }}}}</record>",
                timer.elapsed()
            );
            panic!("{{}}", error);
        }}
    }};

    // == Verifier ==
"""
        )

        if self.is_fault_injection:
            buffer.write("     if args.inject { fuzzer_utils::enable_assertions(); }\n")

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Verifier\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();
    match receipt.verify(RISC0_GUEST_ID) {
        Ok(_) => {
            println!(
                "<record>{{\\
                    \\"context\\":\\"Verifier\\", \\
                    \\"status\\":\\"success\\", \\
                    \\"time\\":\\"{:.2?}\\"\\
                }}</record>",
                timer.elapsed()
            );
        },
        Err(error) => {
            println!(
                "<record>{{\\
                    \\"context\\":\\"Verifier\\", \\
                    \\"status\\":\\"error\\", \\
                    \\"time\\":\\"{:.2?}\\"\\
                }}</record>",
                timer.elapsed()
            );
            panic!("{}", error);
        }
    }
}
"""
        )

        create_file(self.root / "host" / "src" / "main.rs", buffer.getvalue())

    def create_methods_cargo_toml(self):
        create_file(
            self.root / "methods" / "Cargo.toml",
            f"""[package]
name = "risc0-methods"
version = "0.1.0"
edition = "2021"

[build-dependencies]
risc0-build = {{ path = "{self.zkvm_path}/risc0/build" }}

[package.metadata.risc0]
methods = ["guest"]
""",  # noqa: E501
        )

    def create_methods_build_rs(self):
        create_file(
            self.root / "methods" / "build.rs",
            """fn main() {
    risc0_build::embed_methods();
}
""",
        )

    def create_methods_lib_rs(self):
        create_file(
            self.root / "methods" / "src" / "lib.rs",
            """include!(concat!(env!("OUT_DIR"), "/methods.rs"));
""",
        )

    def create_guest_cargo_toml(self):
        create_file(
            self.root / "methods" / "guest" / "Cargo.toml",
            f"""[package]
name = "risc0-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
risc0-zkvm = {{ path = "{self.zkvm_path}/risc0/zkvm", default-features = false, features = ['std'] }}
""",  # noqa: E501
        )

    def create_guest_main_rs(self):
        buffer = io.StringIO()

        buffer.write("#![allow(unconditional_panic)]\n")
        buffer.write("#![allow(arithmetic_overflow)]\n\n")
        buffer.write("use risc0_zkvm::guest::env;\n\n")

        for circuit in self.circuits:
            buffer.write(CircIL2UnsafeRustEmitter().run(circuit))
            buffer.write("\n")

        buffer.write(
            """
fn main() {
"""
        )

        # input and outputs for circuits
        for circuit in self.circuits:
            buffer.write(f"    // -- {circuit.name} --\n")
            for parameter in circuit.inputs:
                var_name = f"{circuit.name}_{parameter.name}"
                var_type = ir_type_to_str(parameter.ty_hint)
                buffer.write(f"    let {var_name}: {var_type} = env::read();\n")
            buffer.write("\n")
        buffer.write("\n")

        def helper_commit_and_exit(value: int, is_end: bool) -> list[str]:
            if is_end:
                return [f"env::commit(&{value}_u32);"]
            else:
                return [f"env::commit(&{value}_u32);", "return; // abort"]

        stream_circuit_output_and_compare_routine(
            buffer, self.circuits, RUST_GUEST_CORRECT_VALUE, helper_commit_and_exit
        )

        buffer.write("}\n")

        create_file(self.root / "methods" / "guest" / "src" / "main.rs", buffer.getvalue())
