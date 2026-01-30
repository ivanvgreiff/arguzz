import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Callable, Generic, Type
from uuid import UUID, uuid4

from circil.fuzzer.config import FuzzerConfig as CircilFuzzerConfig
from circil.ir.node import Circuit
from circil.rewrite.rule import Rule
from zkvm_fuzzer_utils.circil import SafeRemAndDivTransformer
from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.common import (
    convert_input_to_flags,
    generate_metamorphic_bundle,
    random_inputs,
    validate_circuits_arguments,
)
from zkvm_fuzzer_utils.csvlogger import (
    CircuitDataHelper,
    log_build_csv,
    log_constraint_failures_csv,
    log_findings_csv,
    log_injection_csv,
    log_normal_csv,
    log_pipeline_csv,
    log_run_csv,
    log_summary_csv,
)
from zkvm_fuzzer_utils.injection import InjectionArguments, InjectionContext
from zkvm_fuzzer_utils.kinds import InjectionKind, InstrKind
from zkvm_fuzzer_utils.record import Record, record_from_exec_status
from zkvm_fuzzer_utils.rust.cargo import CargoCmd
from zkvm_fuzzer_utils.trace import Trace, trace_from_exec

logger = logging.getLogger("fuzzer")

# ---------------------------------------------------------------------------- #
#                                  Exceptions                                  #
# ---------------------------------------------------------------------------- #


class FuzzerInternalError(Exception):
    pass


class OracleError(Exception):
    pass


# ---------------------------------------------------------------------------- #
#                                Configurations                                #
# ---------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CircuitGenerationConfig:
    min_value: int
    max_value: int
    min_rewrites: int
    max_rewrites: int
    min_batch_size: int
    max_batch_size: int
    rewrite_rules: list[Rule]
    fuzzer_config: CircilFuzzerConfig
    iterative_rewrite: bool
    apply_safe_rem_div_transformation: bool


# ---------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FuzzerConfig(Generic[InstrKind, InjectionKind]):
    input_iterations: int
    available_injections_lookup: dict[InstrKind, list[InjectionKind]]
    preferred_instructions: list[InstrKind]
    build_timeout: int
    execution_timeout: int
    instr_kind_enum: Type[InstrKind]
    injection_kind_enum: Type[InjectionKind]
    expected_output: dict[str, str] | None


# ---------------------------------------------------------------------------- #
#                               Helper Functions                               #
# ---------------------------------------------------------------------------- #


def generate_metamorphic_bundle_from_config(
    config: CircuitGenerationConfig, seed: float
) -> list[Circuit]:
    """Generates a new metamorphic bundle of circuits using the provided
    configuration and seed for randomness. Every generated bundle is validated
    for compatibility with the fuzzer and rust.
    """

    random = Random(seed)
    random_rewrites = random.randint(config.min_rewrites, config.max_rewrites)
    random_batch_size = random.randint(config.min_batch_size, config.max_batch_size)

    result = generate_metamorphic_bundle(
        random,
        config.min_value,
        config.max_value,
        random_rewrites,
        random_batch_size,
        config.rewrite_rules,
        config.fuzzer_config,
        config.iterative_rewrite,
    )

    if config.apply_safe_rem_div_transformation:
        result = [SafeRemAndDivTransformer().transform(c) for c in result]

    validate_circuits_arguments(result)
    return result


# ---------------------------------------------------------------------------- #
#                                  Fuzzer Core                                 #
# ---------------------------------------------------------------------------- #


class FuzzerCore(ABC, Generic[InstrKind, InjectionKind]):

    #
    # Fuzzer Configuration Data
    #

    __project_dir: Path
    __zkvm_dir: Path
    __fuzzer_config: FuzzerConfig

    #
    # Random
    #

    __random: Random

    #
    # Callbacks
    #

    __run_setup_callbacks: list[Callable[[], None]]
    __run_teardown_callbacks: list[Callable[[float], None]]
    __build_setup_callbacks: list[Callable[[], None]] = []
    __build_teardown_callbacks: list[Callable[[list[ExecStatus]], None]] = []
    __iteration_setup_callbacks: list[Callable[[], None]]
    __iteration_teardown_callbacks: list[Callable[[], None]]
    __execution_without_injection_callbacks: list[Callable[[Record, Trace | None], None]]
    __execution_with_injection_callbacks: list[Callable[[Record, Trace, Trace], None]]
    __on_error_callbacks: list[Callable[[bool], None]]  # boolean indicates if injection run

    #
    # Fuzzer State
    #

    __loop_timer: float | None
    __injection_context: InjectionContext
    __outputs_for_execution_without_injection: dict[str, str] | None
    __outputs_for_execution_with_injection: dict[str, str] | None
    __is_fault_injection: bool
    __is_trace_collection: bool
    __timeout: int | None

    #
    # constant fuzzer UUID and Incrementing IDs
    #

    __fuzzer_id: UUID
    __run_id: int
    __iteration_id: int

    def __init__(
        self, project_dir: Path, zkvm_dir: Path, fuzzer_config: FuzzerConfig, random: Random
    ):
        self.__project_dir = project_dir
        self.__zkvm_dir = zkvm_dir
        self.__fuzzer_config = fuzzer_config
        self.__random = random
        self.__is_fault_injection = False
        self.__is_trace_collection = False
        self.__run_setup_callbacks = []
        self.__run_teardown_callbacks = []
        self.__build_setup_callbacks = []
        self.__build_teardown_callbacks = []
        self.__iteration_setup_callbacks = []
        self.__iteration_teardown_callbacks = []
        self.__execution_without_injection_callbacks = []
        self.__execution_with_injection_callbacks = []
        self.__on_error_callbacks = []
        self.__loop_timer = None
        self.__injection_context = InjectionContext(
            fuzzer_config.available_injections_lookup, fuzzer_config.preferred_instructions
        )
        self.__outputs_for_execution_without_injection = None
        self.__outputs_for_execution_with_injection = None
        self.__run_id = 0
        self.__iteration_id = 0
        self.__fuzzer_id = uuid4()
        self.__timeout = None

    def loop(self):
        """Starts the fuzzing loop"""

        self.__loop_timer = time.time()

        try:
            while not self.is_timeout():
                self.run()

        except OracleError as e:
            logger.warning("Fuzzer stopped because of an oracle violation!")
            logger.error(e, exc_info=True)

        except FuzzerInternalError as e:
            logger.warning("Fuzzer stopped because of an internal error!")
            logger.critical(e, exc_info=True)

        except KeyboardInterrupt:
            # NOTE: this is the expected interrupt to turn off the fuzzer
            logger.warning("Fuzzer stopped by keyboard interrupt...")

        except Exception as e:
            # NOTE: this is really bad!
            logger.error("Fuzzer stopped because of an unexpected internal exception!")
            logger.critical(e, exc_info=True)

        self.__loop_timer = None

    def run(self):
        """Entry point for a single outer loop of the fuzzer"""

        run_timer = time.time()
        self.__run_id += 1
        self.__iteration_id = 0

        for callback in self.__run_setup_callbacks:
            callback()

        self.create_project()

        for callback in self.__build_setup_callbacks:
            callback()

        build_status_list = self.build_project()

        for callback in self.__build_teardown_callbacks:
            callback(build_status_list)

        for build_status in build_status_list:
            if build_status.is_failure():
                if build_status.is_timeout:
                    logger.error(f"COMMAND: {build_status.command}")
                    logger.error(f"zkvm build timed out with {self.fuzzer_config.build_timeout}")
                raise FuzzerInternalError("unable to build zkvm host build!")

        for iteration_idx in range(self.fuzzer_config.input_iterations):
            if not self.is_timeout():
                self.__iteration_id = iteration_idx + 1
                self.__outputs_for_execution_without_injection = None
                self.__outputs_for_execution_with_injection = None

                for callback in self.__iteration_setup_callbacks:
                    callback()

                optional_trace = self.execute_without_injection()

                if self.__is_fault_injection and optional_trace:
                    self.execute_with_injection(optional_trace)

                for callback in self.__iteration_teardown_callbacks:
                    callback()

        run_delta_time = time.time() - run_timer

        for callback in self.__run_teardown_callbacks:
            callback(run_delta_time)

    def register_run_setup_callback(self, callback: Callable[[], None]):
        self.__run_setup_callbacks.append(callback)

    def register_run_teardown_callback(self, callback: Callable[[float], None]):
        self.__run_teardown_callbacks.append(callback)

    def register_build_setup_callback(self, callback: Callable[[], None]):
        self.__build_setup_callbacks.append(callback)

    def register_build_teardown_callback(self, callback: Callable[[list[ExecStatus]], None]):
        self.__build_teardown_callbacks.append(callback)

    def register_iteration_setup_callback(self, callback: Callable[[], None]):
        self.__iteration_setup_callbacks.append(callback)

    def register_iteration_teardown_callback(self, callback: Callable[[], None]):
        self.__iteration_teardown_callbacks.append(callback)

    def register_execution_without_injection_callback(
        self, callback: Callable[[Record, Trace | None], None]
    ):
        self.__execution_without_injection_callbacks.append(callback)

    def register_execution_with_injection_callback(
        self, callback: Callable[[Record, Trace, Trace], None]
    ):
        self.__execution_with_injection_callbacks.append(callback)

    def register_on_error_callback(self, callback: Callable[[bool], None]):
        self.__on_error_callbacks.append(callback)

    def execute_without_injection(self) -> Trace | None:
        """Executes the zkvm project without fault injection"""

        # execute
        execution_status = self.execute_project(self.create_execution_arguments())

        # get trace and record data from execution
        record = record_from_exec_status(execution_status)
        trace = None
        if self.__is_trace_collection:
            trace = trace_from_exec(
                execution_status,
                self.fuzzer_config.instr_kind_enum,
                self.fuzzer_config.injection_kind_enum,
            )

        self.__outputs_for_execution_without_injection = self.get_outputs_from_record(record)
        logger.debug(f"record output: {self.__outputs_for_execution_without_injection}")

        # iterate over callbacks
        for callback in self.__execution_without_injection_callbacks:
            callback(record, trace)

        # if the execution failed we have to check the reason
        if execution_status.is_failure():
            # if it was a timeout we continue and log an error
            if execution_status.is_timeout:
                logger.error(
                    f"Host program reached timeout of {self.fuzzer_config.execution_timeout}s!"
                    " Consider increasing the timeout or change the prover setup..."
                )
                return None  # stop execution
            # if it was a known error we also continue
            if self.is_ignored_execution_error(execution_status):
                logger.info("Host program failed with an expected error...")
                return None  # stop execution

            # if it was an unknown cause we probably have a completeness violation

            # NOTE: This can be enabled to stop on an error. This can be useful
            #       for exploring.
            # prepare_reproducibility_kit(self.project_dir, host_execution)
            # raise OracleError("completeness violation in execution!")
            logger.error("completeness violation in execution!")
            for callback in self.__on_error_callbacks:
                callback(False)
            return None  # stop execution

        else:  # execution was successful

            # If the fuzzer_config has the expected_output value set,
            # we compare our execution output against it.
            if self.fuzzer_config.expected_output:
                if (
                    self.fuzzer_config.expected_output
                    != self.outputs_for_execution_without_injection
                ):
                    logger.error("Actual output value does not match expected value!")
                    logger.info(f"expected       : {self.fuzzer_config.expected_output}")
                    logger.info(f"actual         : {self.outputs_for_execution_without_injection}")

                    # NOTE: This can be enabled to stop on an error. This can be useful
                    #       for exploring.
                    # prepare_reproducibility_kit(self.project_dir, execution_status)
                    # raise OracleError("soundness violation in execution!")
                    logger.error("soundness violation in execution!")
                    for callback in self.__on_error_callbacks:
                        callback(False)
                    return None  # stop execution

        return trace

    def execute_with_injection(self, original_trace: Trace):
        """Executes the zkvm project with fault injection"""

        assert (
            self.__is_fault_injection
        ), "execute with injection called although fault injection is disabled!"

        # Generate injection arguments from original trace
        injection_arguments = self.injection_context.arguments_from_trace(
            original_trace, self.random
        )
        if injection_arguments is None:
            logger.warning("unable to build an injection environment! Skipping injection ...")
            return  # unable to execute as injection -> skip

        # execute the program in injection mode
        host_execution = self.execute_project(self.create_execution_arguments(injection_arguments))

        # get trace and record data from execution
        record = record_from_exec_status(host_execution)
        trace = trace_from_exec(
            host_execution,
            self.fuzzer_config.instr_kind_enum,
            self.fuzzer_config.injection_kind_enum,
        )
        self.__outputs_for_execution_with_injection = self.get_outputs_from_record(record)
        logger.debug(f"record output: {self.__outputs_for_execution_with_injection}")

        # iterate over callbacks
        for callback in self.__execution_with_injection_callbacks:
            callback(record, trace, original_trace)

        # check if we should skip the injection inspection
        if self.is_skip_fault_injection_inspection(trace, injection_arguments):
            return  # some known issue or edge case is triggered

        # Check that the trace of the fault injection execution has exactly on fault
        fault_count = len(trace.faults)
        if fault_count != 1:
            logger.critical(
                f"Unexpected number of fault injections! Expected 1, but was {fault_count}!"
            )
            raise FuzzerInternalError("unexpected number of fault injections!")

        # retrieve fault information
        fault = trace.faults[0]

        # compare the selected step from the original trace with the
        # fault step parsed by the actual fault injection execution
        if fault.step != self.injection_context.targeted_trace_step.step:
            logger.info(f"{self.injection_context.targeted_trace_step}")
            logger.info(f"{fault}")
            logger.critical("Something went wrong regarding the fault injection!")
            raise FuzzerInternalError("Injection info miss-match between chosen and actual!")

        # if the injection was successful we have to check a lot
        if record.is_success():

            # First we compare if the normal execution output is not equal the fault
            # injection execution. If this is the case we have successfully proven a
            # wrong output.
            if (
                self.outputs_for_execution_without_injection
                != self.outputs_for_execution_with_injection
            ):
                logger.error(
                    "Fault injection did not trigger an error although output values differ!"
                )
                logger.info(f"original       : {self.outputs_for_execution_without_injection}")
                logger.info(f"fault injection: {self.outputs_for_execution_with_injection}")

                # NOTE: This can be enabled to stop on an error. This can be useful
                #       for exploring.
                # prepare_reproducibility_kit(self.project_dir, host_execution)
                # raise OracleError("soundness violation with diverging output")
                logger.error("soundness violation with diverging output!")
                for callback in self.__on_error_callbacks:
                    callback(True)
                return  # stop

            # Create some helper variables for faster lookup
            original_trace_steps = original_trace.steps
            fault_trace_steps = trace.steps
            original_trace_steps_num = len(original_trace_steps)
            fault_trace_steps_num = len(fault_trace_steps)

            # Check if the original trace has the same amount of steps
            # as the fault injection trace
            if original_trace_steps_num != fault_trace_steps_num:
                step_difference = abs(original_trace_steps_num - fault_trace_steps_num)
                # logger.error
                logger.warning(
                    "Fault injection did not trigger an error although "
                    f"trace size differ ({step_difference})!"
                )
                #
                # NOTE: Currently we cannot be sure if it is a bug or not. During
                #       Explore runs we can either store the error and / or throw
                #       an exception, but for the experiments this can be ignored!
                #
                # prepare_reproducibility_kit(self.project_dir, host_execution)
                # raise OracleError("soundness violation by successful fault injection!")
                #
                return  # stop

            # Check if the original trace contains the same steps
            # as the fault injection trace
            diff_count = 0
            for step_idx in range(original_trace_steps_num):
                original_step_1 = original_trace_steps[step_idx]
                fault_step_1 = fault_trace_steps[step_idx]

                # NOTE: we compare assembly as this is the only thing that actually makes
                #       a visible difference!
                if not original_step_1.assembly == fault_step_1.assembly:
                    logger.info("step 1:")
                    logger.info(original_step_1)
                    logger.info(fault_step_1)
                    logger.warning(
                        "Fault injection did not trigger an error although trace step differs!"
                    )
                    diff_count += 1

            logger.warning(
                f"Fault injection did not change the behavior! Differences detected: {diff_count}"
            )

            # To avoid too many false positives we check if least 1 other instruction
            # was effected by the fault injection (besides the injection itself)
            if diff_count > fault_count:
                # logger.error
                logger.warning(
                    "Fault injection did not trigger an error "
                    f"although {diff_count} instructions differ!"
                )
                #
                # NOTE: Currently we cannot be sure if it is a bug or not. During
                #       Explore runs we can either store the error and / or throw
                #       an exception, but for the experiments this can be ignored!
                #
                # prepare_reproducibility_kit(self.project_dir, host_execution)
                # raise OracleError("soundness violation by successful fault injection!")
                #
                return  # stop

            # else: 0 or 1 instruction could still be a bug but it is very unlikely
            #       at this point and we ignore this case for now...

    @abstractmethod
    def create_project(self):
        """Updates or creates the zkvm host and guest code based"""
        raise NotImplementedError()

    def build_project(self) -> list[ExecStatus]:
        """Builds the zkvm host and guest code and returns the status"""
        return [
            CargoCmd.build()
            .with_cd(self.project_dir)
            .in_release()
            .with_timeout(self.fuzzer_config.build_timeout)
            .execute()
        ]

    def execute_project(self, arguments: list[str]) -> ExecStatus:
        """Executes the zkvm host and guest code with the provided arguments
        and returns the status"""
        return (
            CargoCmd.run()
            .with_cd(self.project_dir)
            .with_args(arguments)
            .with_timeout(self.fuzzer_config.execution_timeout)
            .in_release()
            .with_explicit_clean_zombies()
            .execute()
        )

    @abstractmethod
    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        """Given a failed command `ExecStatus` this function returns
        `True`if the failure can be ignored, `False` otherwise."""
        raise NotImplementedError()

    @abstractmethod
    def is_skip_fault_injection_inspection(
        self, trace: Trace, arguments: InjectionArguments
    ) -> bool:
        """Given a failed command `ExecStatus` this function returns
        `True`if the failure can be ignored, `False` otherwise."""
        raise NotImplementedError()

    @abstractmethod
    def create_execution_arguments(
        self, injection_arguments: InjectionArguments | None = None
    ) -> list[str]:
        """Generates arguments for an execution of the current project.
        If the `injection_arguments` parameter is provided, it is assume that
        the arguments are used for a fault injection."""
        raise NotImplementedError()

    @abstractmethod
    def get_outputs_from_record(self, record: Record) -> dict[str, str]:
        """Given a `Record` this function returns a dictionary containing
        output values. Note that these values are relevant for fault
        injection compares."""
        raise NotImplementedError()

    @property
    def fuzzer_config(self) -> FuzzerConfig[InstrKind, InjectionKind]:
        return self.__fuzzer_config

    @property
    def injection_context(self) -> InjectionContext[InstrKind, InjectionKind]:
        return self.__injection_context

    @property
    def project_dir(self) -> Path:
        return self.__project_dir

    @property
    def zkvm_dir(self) -> Path:
        return self.__zkvm_dir

    @property
    def random(self) -> Random:
        return self.__random

    @property
    def outputs_for_execution_without_injection(self) -> dict[str, str] | None:
        return self.__outputs_for_execution_without_injection

    @property
    def outputs_for_execution_with_injection(self) -> dict[str, str] | None:
        return self.__outputs_for_execution_with_injection

    @property
    def fuzzer_id(self) -> UUID:
        return self.__fuzzer_id

    @property
    def run_id(self) -> int:
        return self.__run_id

    @property
    def iteration_id(self) -> int:
        return self.__iteration_id

    def set_fault_injection(self, value: bool):
        if value:
            self.enable_fault_injection()
        else:
            self.disable_fault_injection()

    def enable_fault_injection(self):
        self.__is_trace_collection = True
        self.__is_fault_injection = True

    def disable_fault_injection(self):
        self.__is_fault_injection = False

    @property
    def is_fault_injection(self) -> bool:
        return self.__is_fault_injection

    def set_trace_collection(self, value: bool):
        if value:
            self.enable_trace_collection()
        else:
            self.disable_trace_collection()

    def enable_trace_collection(self):
        self.__is_trace_collection = True

    def disable_trace_collection(self):
        self.__is_trace_collection = False
        self.__is_fault_injection = False

    @property
    def is_trace_collection(self) -> bool:
        return self.__is_trace_collection

    @property
    def loop_runtime(self) -> float:
        assert self.__loop_timer, "not in loop"
        return time.time() - self.__loop_timer

    def enable_timeout(self, timeout: int):
        self.__timeout = timeout

    def disable_timeout(self):
        self.__timeout = None

    def is_timeout(self) -> bool:
        if self.__timeout is None or self.__timeout <= 0:
            return False
        return self.__timeout <= self.loop_runtime

    def disable_injection_schedular(self):
        self.__injection_context.disable_schedular()

    def enable_injection_schedular(self):
        self.__injection_context.enable_schedular()

    def is_injection_schedular(self):
        self.__injection_context.is_schedular()


# ---------------------------------------------------------------------------- #
#                              Circuit Fuzzer Base                             #
# ---------------------------------------------------------------------------- #


class CircuitFuzzerBase(FuzzerCore[InstrKind, InjectionKind]):
    __circuits: list[Circuit]
    __circuit_config: CircuitGenerationConfig
    __circuit_inputs: dict[str, int | bool]
    __circuits_seed: float
    __cached_execution_arguments: list[str] | None

    def __init__(
        self,
        project_dir: Path,
        zkvm_dir: Path,
        fuzzer_config: FuzzerConfig[InstrKind, InjectionKind],
        random: Random,
        circuit_config: CircuitGenerationConfig,
    ):
        super().__init__(project_dir, zkvm_dir, fuzzer_config, random)
        super().register_run_setup_callback(self.update_circuits)
        super().register_run_teardown_callback(self.process_run)
        super().register_build_teardown_callback(self.process_build)
        super().register_iteration_setup_callback(self.update_circuit_inputs)
        super().register_execution_without_injection_callback(
            self.process_execution_without_injection
        )
        super().register_execution_with_injection_callback(self.process_execution_with_injection)
        super().register_on_error_callback(self.record_finding)

        self.__circuit_config = circuit_config
        self.__circuits = []  # default for now, this is set during run setup
        self.__circuit_inputs = {}  # default for now, this is set during iteration setup
        self.__circuits_seed = -1  # random seed from last circuit generation
        self.__cached_execution_arguments = None

    def update_circuits(self):
        """Updates the available `circuits` with a new metamorphic bundle"""
        self.__circuits_seed = self.random.random()
        self.__circuits = generate_metamorphic_bundle_from_config(
            self.__circuit_config, self.__circuits_seed
        )

    def update_circuit_inputs(self):
        """Updates the available `circuit_inputs` based on the current `circuit_candidate`"""
        self.__circuit_inputs = random_inputs(self.circuit_candidate, self.random)

    def create_execution_arguments(
        self, injection_arguments: InjectionArguments | None = None
    ) -> list[str]:
        flags = convert_input_to_flags(self.circuit_candidate, self.circuit_inputs)
        if self.is_fault_injection and injection_arguments is not None:
            flags += [
                "--inject",  # enable injection
                "--seed",
                f"{self.random.getrandbits(64)}",  # random seed
                "--inject-step",
                f"{injection_arguments.step}",  # injection step
                "--inject-kind",
                f"{injection_arguments.kind}",  # injection kind
            ]
        if self.is_trace_collection:
            flags += [
                "--trace",  # enable trace logging
            ]
        self.__cached_execution_arguments = flags
        return flags

    def process_run(self, run_time: float):
        log_run_csv(self.project_dir, self.fuzzer_id, self.run_id, self.iteration_id, run_time)

    def process_build(self, builds: list[ExecStatus]):
        log_build_csv(self.project_dir, self.fuzzer_id, self.run_id, builds)

    def process_execution_without_injection(self, record: Record, trace: Trace | None):
        # save data as csv
        log_normal_csv(
            self.project_dir,
            self.fuzzer_id,
            self.run_id,
            self.iteration_id,
            record,
            CircuitDataHelper(self.circuits),
        )
        if trace:
            log_summary_csv(
                self.project_dir,
                self.fuzzer_id,
                self.run_id,
                self.iteration_id,
                trace,
                list(self.fuzzer_config.instr_kind_enum),
            )
        log_pipeline_csv(self.project_dir, self.fuzzer_id, self.run_id, self.iteration_id, record)

    def process_execution_with_injection(self, record: Record, trace: Trace, original_trace: Trace):
        # save data as csv
        log_injection_csv(
            self.project_dir,
            self.fuzzer_id,
            self.run_id,
            self.iteration_id,
            record,
            trace,
            original_trace,
            self.outputs_for_execution_without_injection
            == self.outputs_for_execution_with_injection,
            CircuitDataHelper(self.circuits),
        )

        # Phase 1: Log constraint failures if any occurred
        if trace.has_constraint_failures():
            # Get injection context for correlation
            injection_step = ""
            injection_kind = ""
            correlated_instruction = ""

            if trace.has_fault_injection():
                fault = trace.faults[0]
                injection_step = fault.step
                injection_kind = fault.kind_as_str

            # Try to correlate the first constraint failure to an instruction
            first_failure = trace.get_first_constraint_failure()
            if first_failure:
                correlated_step = trace.correlate_failure_to_step(first_failure)
                if correlated_step:
                    correlated_instruction = correlated_step.instruction_as_str

            log_constraint_failures_csv(
                self.project_dir,
                self.fuzzer_id,
                self.run_id,
                self.iteration_id,
                is_injected=True,
                injection_step=injection_step,
                injection_kind=injection_kind,
                constraint_failures=trace.constraint_failures,
                correlated_instruction=correlated_instruction,
            )

    def get_outputs_from_record(self, record: Record) -> dict[str, str]:
        output = {}
        output_value = record.search_by_key("output")
        if output_value is not None:
            output["output"] = output_value
        return output

    def record_finding(self, is_injection: bool):
        assert self.__cached_execution_arguments is not None, "impossible that this is not sets!"
        log_findings_csv(
            self.project_dir,
            self.fuzzer_id,
            self.run_id,
            self.iteration_id,
            self.loop_runtime,
            self.circuits_seed,
            self.__cached_execution_arguments,
            is_injection,
        )

    @property
    def circuit_inputs(self) -> dict[str, int | bool]:
        return self.__circuit_inputs

    @property
    def circuit_candidate(self) -> Circuit:
        return self.__circuits[0]  # safe because of validation

    @property
    def circuits(self) -> list[Circuit]:
        return self.__circuits

    @property
    def circuits_seed(self) -> float:
        return self.__circuits_seed


# ---------------------------------------------------------------------------- #
