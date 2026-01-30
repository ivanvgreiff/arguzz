import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import UUID

from zkvm_fuzzer_utils.circil import Circuit
from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.common import to_clean_quoted_entry, validate_circuits_arguments
from zkvm_fuzzer_utils.record import Record
from zkvm_fuzzer_utils.trace import ConstraintFailure, Trace

logger = logging.getLogger("fuzzer")

# ---------------------------------------------------------------------------- #
#                           Configuration and Helper                           #
# ---------------------------------------------------------------------------- #

PANIC_MESSAGE_MAX_LINE = 150


def _process_panic_message(message: str) -> str:
    result = to_clean_quoted_entry(message, max_msg_len=PANIC_MESSAGE_MAX_LINE)
    return result


# ---------------------------------------------------------------------------- #
#                                 Circuit Helper                               #
# ---------------------------------------------------------------------------- #


class CircuitDataHelper:
    _circuits: list[Circuit]

    def __init__(self, circuits: list[Circuit]):
        self._circuits = circuits
        validate_circuits_arguments(self._circuits)

    def accumulated_size(self) -> int:
        return sum([c.size() for c in self._circuits])

    def circuits_count(self) -> int:
        return len(self._circuits)

    def inputs_count(self) -> int:
        return len(self._circuits[0].inputs)  # safe because of validation

    def outputs_count(self) -> int:
        return len(self._circuits[0].outputs)  # safe because of validation


# ---------------------------------------------------------------------------- #
#                                   CSV Files                                  #
# ---------------------------------------------------------------------------- #


def log_normal_csv(
    project_dir: Path,
    fuzzer_id: UUID,
    run_id: int,
    iteration_id: int,
    record: Record,
    opt_circuit_data: CircuitDataHelper | None = None,
):
    normal_csv = project_dir.parent.absolute() / "normal.csv"

    if not normal_csv.is_file():
        logger.info(f"create log file: {normal_csv}")
        with open(normal_csv, "w") as fp:
            fp.write(
                "fuzzer_id,"
                "run_id,"
                "iteration_id,"
                "timestamp,"
                "execution_exitcode,"
                "execution_time,"
                "execution_is_timeout,"
                "last_context,"
                "panic_message,"
                "panic_location,"
                "circuits_accumulated_size,"
                "circuits_count,"
                "circuits_inputs,"
                "circuits_outputs\n"
            )

    last_context = ""
    last_record_entry = record.get_last_entry()
    if last_record_entry:
        last_context = last_record_entry.context

    panic_message = ""
    panic_location = ""
    if record.has_panicked():
        # Multiple panics hint that the guest code panicked. In this
        # case it is enough to look at the last panic entry.
        last_panic = record.panics[-1]
        panic_message = _process_panic_message(last_panic.rust_panic.message)
        panic_location = last_panic.rust_panic.full_location

    circuits_accumulated_size = ""
    circuits_count = ""
    circuits_inputs = ""
    circuits_outputs = ""
    if opt_circuit_data:
        circuits_accumulated_size = f"{opt_circuit_data.accumulated_size()}"
        circuits_count = f"{opt_circuit_data.circuits_count()}"
        circuits_inputs = f"{opt_circuit_data.inputs_count()}"
        circuits_outputs = f"{opt_circuit_data.outputs_count()}"

    unix_timestamp = int(datetime.now().timestamp())

    with open(normal_csv, "a") as fp:
        fp.write(
            f"{fuzzer_id},"
            f"{run_id},"
            f"{iteration_id},"
            f"{unix_timestamp},"
            f"{record.exec_status.returncode},"
            f"{record.exec_status.delta_time},"
            f"{record.exec_status.is_timeout},"
            f"{last_context},"
            f"{panic_message},"
            f"{panic_location},"
            f"{circuits_accumulated_size},"
            f"{circuits_count},"
            f"{circuits_inputs},"
            f"{circuits_outputs}\n"
        )


# ---------------------------------------------------------------------------- #


def log_summary_csv(
    project_dir: Path,
    fuzzer_id: UUID,
    run_id: int,
    iteration_id: int,
    trace: Trace,
    all_available_instructions: list[str],
):
    summary_csv = project_dir.parent.absolute() / "summary.csv"

    sorted_instructions = sorted(all_available_instructions)
    recorded_instructions = trace.as_instruction_to_count()

    if not summary_csv.is_file():
        logger.info(f"create log file: {summary_csv}")
        with open(summary_csv, "w") as fp:
            fp.write("fuzzer_id,run_id,iteration_id,")
            fp.write(",".join([e for e in sorted_instructions]) + "\n")

    with open(summary_csv, "a") as fp:
        fp.write(f"{fuzzer_id},{run_id},{iteration_id},")
        fp.write(",".join([str(recorded_instructions[e]) for e in sorted_instructions]) + "\n")


# ---------------------------------------------------------------------------- #


def log_injection_csv(
    project_dir: Path,
    fuzzer_id: UUID,
    run_id: int,
    iteration_id: int,
    record: Record,
    injection_trace: Trace,
    original_trace: Trace,
    is_correct_output: bool,
    opt_circuit_data: CircuitDataHelper | None = None,
):
    injection_csv = project_dir.parent.absolute() / "injection.csv"

    if not injection_csv.is_file():
        logger.info(f"create log file: {injection_csv}")
        with open(injection_csv, "w") as fp:
            fp.write(
                "fuzzer_id,"
                "run_id,"
                "iteration_id,"
                "timestamp,"
                "execution_exitcode,"
                "execution_time,"
                "execution_is_timeout,"
                "execution_is_correct_output,"
                "last_context,"
                "panic_message,"
                "panic_location,"
                "circuits_accumulated_size,"
                "circuits_inputs,"
                "circuits_outputs,"
                "fault_original_trace_size,"
                "fault_injection_trace_size,"
                "fault_injection_step,"
                "fault_injection_pc,"
                "fault_injection_kind,"
                "fault_injection_info,"
                "fault_injection_instruction,"
                "fault_original_instruction\n"
            )

    last_context = ""
    last_record_entry = record.get_last_entry()
    if last_record_entry:
        last_context = last_record_entry.context

    panic_message = ""
    panic_location = ""
    if record.has_panicked():
        # Multiple panics hint that the guest code panicked. In this
        # case it is enough to look at the last panic entry.
        last_panic = record.panics[-1]
        panic_message = _process_panic_message(last_panic.rust_panic.message)
        panic_location = last_panic.rust_panic.full_location

    circuits_accumulated_size = ""
    circuits_count = ""
    circuits_inputs = ""
    circuits_outputs = ""
    if opt_circuit_data:
        circuits_accumulated_size = f"{opt_circuit_data.accumulated_size()}"
        circuits_count = f"{opt_circuit_data.circuits_count()}"
        circuits_inputs = f"{opt_circuit_data.inputs_count()}"
        circuits_outputs = f"{opt_circuit_data.outputs_count()}"

    # NOTE: this assumes that only a single fault was done, so we only
    # consider the first fault in the list.

    injection_step = ""
    injection_pc = ""
    injection_kind = ""
    original_instr = ""
    injection_instr = ""
    injection_info = ""
    if injection_trace.has_fault_injection():
        fault = injection_trace.faults[0]  # pick original fault
        injection_step = fault.step
        injection_pc = fault.pc
        injection_kind = fault.kind_as_str
        original_instr = original_trace.steps[injection_step].instruction_as_str
        if len(injection_trace.steps) > injection_step:
            # if a pre modification panics or fails, the trace
            # is not printed anymore for this step so we skip it.
            injection_instr = injection_trace.steps[injection_step].instruction_as_str
        injection_info = to_clean_quoted_entry(fault.info)

    original_trace_size = len(original_trace.steps)
    injection_trace_size = len(injection_trace.steps)

    unix_timestamp = int(datetime.now().timestamp())

    with open(injection_csv, "a") as fp:
        fp.write(
            f"{fuzzer_id},"
            f"{run_id},"
            f"{iteration_id},"
            f"{unix_timestamp},"
            f"{record.exec_status.returncode},"
            f"{record.exec_status.delta_time},"
            f"{record.exec_status.is_timeout},"
            f"{is_correct_output},"
            f"{last_context},"
            f"{panic_message},"
            f"{panic_location},"
            f"{circuits_accumulated_size},"
            f"{circuits_count}"
            f"{circuits_inputs},"
            f"{circuits_outputs},"
            f"{original_trace_size},"
            f"{injection_trace_size},"
            f"{injection_step},"
            f"{injection_pc},"
            f"{injection_kind},"
            f"{injection_info},"
            f"{injection_instr},"
            f"{original_instr}\n"
        )


# ---------------------------------------------------------------------------- #


def log_constraint_failures_csv(
    project_dir: Path,
    fuzzer_id: UUID,
    run_id: int,
    iteration_id: int,
    is_injected: bool,
    injection_step: int | str,
    injection_kind: str,
    constraint_failures: list[ConstraintFailure],
    correlated_instruction: str = "",
):
    """Logs constraint failures to constraint_failures.csv (Phase 1).

    This function records which constraints failed during witness generation,
    along with the injection context that caused the failure.
    """
    csv_path = project_dir.parent.absolute() / "constraint_failures.csv"

    if not csv_path.is_file():
        logger.info(f"create log file: {csv_path}")
        with open(csv_path, "w") as fp:
            fp.write(
                "fuzzer_id,"
                "run_id,"
                "iteration_id,"
                "timestamp,"
                "is_injected,"
                "injection_step,"
                "injection_kind,"
                "fail_cycle,"
                "fail_loc,"
                "fail_value,"
                "correlated_instruction\n"
            )

    unix_timestamp = int(datetime.now().timestamp())

    with open(csv_path, "a") as fp:
        for cf in constraint_failures:
            # Escape the loc string since it may contain special characters
            escaped_loc = cf.loc.replace('"', '""')
            fp.write(
                f"{fuzzer_id},"
                f"{run_id},"
                f"{iteration_id},"
                f"{unix_timestamp},"
                f"{is_injected},"
                f"{injection_step},"
                f"{injection_kind},"
                f"{cf.cycle},"
                f'"{escaped_loc}",'
                f"{cf.value},"
                f"{correlated_instruction}\n"
            )


# ---------------------------------------------------------------------------- #


def log_build_csv(project_dir: Path, fuzzer_id: UUID, run_id: int, builds: list[ExecStatus]):
    build_csv = project_dir.parent.absolute() / "build.csv"

    if not build_csv.is_file():
        logger.info(f"create log file: {build_csv}")
        with open(build_csv, "w") as fp:
            fp.write("fuzzer_id,run_id,build_num,build_time,build_success\n")

    build_num = f"{len(builds)}"
    build_time = 0 if len(builds) == 0 else sum([build.delta_time for build in builds])
    build_success = False if len(builds) == 0 else not any([build.is_failure() for build in builds])

    with open(build_csv, "a") as fp:
        fp.write(f"{fuzzer_id},{run_id},{build_num},{build_time},{build_success}\n")


# ---------------------------------------------------------------------------- #


def log_run_csv(
    project_dir: Path, fuzzer_id: UUID, run_id: int, iteration_id: int, run_time: float
):
    run_csv = project_dir.parent.absolute() / "run.csv"

    if not run_csv.is_file():
        logger.info(f"create log file: {run_csv}")
        with open(run_csv, "w") as fp:
            fp.write("fuzzer_id,run_id,iterations,run_time\n")

    with open(run_csv, "a") as fp:
        fp.write(f"{fuzzer_id},{run_id},{iteration_id},{run_time}\n")


# ---------------------------------------------------------------------------- #


def log_pipeline_csv(
    project_dir: Path, fuzzer_id: UUID, run_id: int, iteration_id: int, record: Record
):
    pipeline_csv = project_dir.parent.absolute() / "pipeline.csv"

    time_data = {}
    for record_entry in record.entries:
        if "time" in record_entry.entries:
            context = record_entry.context
            time = record_entry.entries["time"]
            if context in time_data:
                raise ValueError(f"duplicated time for context '{context}'")
            time_data[context] = time

    time_data["full"] = f"{record.exec_status.delta_time}"
    stage_names = time_data.keys()

    if not pipeline_csv.is_file():
        logger.info(f"create log file: {pipeline_csv}")
        with open(pipeline_csv, "w") as fp:
            fp.write("fuzzer_id,run_id,iteration_id,")
            fp.write(",".join([key for key in stage_names]) + "\n")

    with open(pipeline_csv, "a") as fp:
        fp.write(f"{fuzzer_id},{run_id},{iteration_id},")
        fp.write(",".join([time_data[key] for key in stage_names]) + "\n")


# ---------------------------------------------------------------------------- #
#                             Bug Finding Functions                            #
# ---------------------------------------------------------------------------- #


@dataclass
class ParsedFinding:
    fuzzer_id: UUID
    run_id: int
    iteration_id: int
    timestamp: int
    runtime: float
    circuit_seed: float
    input_flags: list[str]
    is_injection: bool

    @classmethod
    def parse_from(cls, csv_file: Path) -> list["ParsedFinding"]:
        results = []
        lines = [line for line in csv_file.read_text().split("\n") if line != ""]
        if len(lines) == 0:
            raise ValueError(f"'{csv_file}' was empty ...")
        lines = lines[1:]  # skip header
        for idx, line in enumerate(lines):
            values = line.split(",")
            values_len = len(values)
            if values_len != 8:
                raise ValueError(
                    f"'{csv_file}' entry {idx} has {values_len} entries instead of expected 8!"
                )
            fuzzer_id = UUID(values[0])
            run_id = int(values[1])
            iteration_id = int(values[2])
            timestamp = int(values[3])
            runtime = float(values[4])
            circuit_seed = float(values[5])
            input_flags = values[6].split(" ")
            is_injection = values[7] == "True"

            results.append(
                ParsedFinding(
                    fuzzer_id,
                    run_id,
                    iteration_id,
                    timestamp,
                    runtime,
                    circuit_seed,
                    input_flags,
                    is_injection,
                )
            )

        return results


# ---------------------------------------------------------------------------- #


def log_findings_csv(
    project_dir: Path,
    fuzzer_id: UUID,
    run_id: int,
    iteration_id: int,
    runtime: float,
    circuit_seed: float,
    input_flags: list[str],
    is_injection: bool,
):
    findings_csv = project_dir.parent.absolute() / "findings.csv"

    if not findings_csv.is_file():
        logger.info(f"create log file: {findings_csv}")
        with open(findings_csv, "w") as fp:
            fp.write(
                "fuzzer_id,"
                "run_id,"
                "iteration_id,"
                "timestamp,"
                "runtime,"
                "circuit_seed,"
                "input_flags,"
                "is_injection\n"
            )

    unix_timestamp = int(datetime.now().timestamp())
    concat_input_flags = " ".join(input_flags)
    with open(findings_csv, "a") as fp:
        fp.write(
            f"{fuzzer_id},"
            f"{run_id},"
            f"{iteration_id},"
            f"{unix_timestamp},"
            f"{runtime},"
            f"{circuit_seed},"
            f"{concat_input_flags},"
            f"{is_injection}\n"
        )


# ---------------------------------------------------------------------------- #


def create_empty_checked_findings_csv(project_dir: Path):
    checked_findings_csv = project_dir.parent.absolute() / "checked_findings.csv"

    if not checked_findings_csv.is_file():
        logger.info(f"create log file: {checked_findings_csv}")
        with open(checked_findings_csv, "w") as fp:
            fp.write(
                "fuzzer_id,"
                "run_id,"
                "iteration_id,"
                "timestamp,"
                "runtime,"
                "circuit_seed,"
                "input_flags,"
                "is_injection,"
                "fixed\n"
            )


# ---------------------------------------------------------------------------- #


def log_checked_findings_csv(project_dir: Path, finding: ParsedFinding, fixed: bool):
    checked_findings_csv = project_dir.parent.absolute() / "checked_findings.csv"

    if not checked_findings_csv.is_file():
        logger.info(f"create log file: {checked_findings_csv}")
        with open(checked_findings_csv, "w") as fp:
            fp.write(
                "fuzzer_id,"
                "run_id,"
                "iteration_id,"
                "timestamp,"
                "runtime,"
                "circuit_seed,"
                "input_flags,"
                "is_injection,"
                "fixed\n"
            )

    concat_input_flags = " ".join(finding.input_flags)
    with open(checked_findings_csv, "a") as fp:
        fp.write(
            f"{finding.fuzzer_id},"
            f"{finding.run_id},"
            f"{finding.iteration_id},"
            f"{finding.timestamp},"
            f"{finding.runtime},"
            f"{finding.circuit_seed},"
            f"{concat_input_flags},"
            f"{finding.is_injection},"
            f"{fixed}\n"
        )


# ---------------------------------------------------------------------------- #
