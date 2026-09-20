# Arguzz

This repository contains the implementation of Arguzz, a zero knowledge virtual machine fuzzer.
Arguzz uses a combination of metamorphic testing and fault injection to find soundness and completeness issues in Rust-based zkVMs.

At the moment, Arguzz supports six different zkVMs:
 - [Jolt](https://github.com/a16z/jolt)
 - [NexusVM](https://github.com/nexus-xyz/nexus-zkvm)
 - [OpenVM](https://github.com/openvm-org/openvm)
 - [Pico](https://github.com/brevis-network/pico)
 - [RiscZero](https://github.com/risc0/risc0)
 - [SP1](https://github.com/succinctlabs/sp1)

___

**ATTENTION:** To preserve functionality and reproducibility, the zkVM github repositories in
the source code are set to forks, managed by our anonymous GitHub account
https://github.com/DanielHoffmann91. To use the original GitHub repositories, one has to
**manually** set the repository variable `<ZKVM-NAME>_ZKVM_GIT_REPOSITORY` in the `settings.py`
files for **each** zkVM respectively to the correct value!

___

## Project Overview

Arguzz's implementation can be structured in three main components:
  1. Re-implementation and extension of
  [Circuzz](https://github.com/Rigorous-Software-Engineering/circuzz)'s
  [CircIL](libs/circil) for circuit generation and transformation;
  2. A generic [fuzzer library](libs/zkvm-fuzzer-utils)
  3. Fuzzer implementations for [jolt](projects/nexus-fuzzer), [nexus](projects/nexus-fuzzer), [openvm](projects/openvm-fuzzer), [pico](projects/pico-fuzzer), [risc0](projects/risc0-fuzzer) and [sp1](projects/sp1-fuzzer)

To manage experiments we use a combination of `Makefile` entries and helper scripts written
in `Bash` and `Python` located in the [scripts](scripts) folder.

## Quickstart

The fastest and simplest way to use Arguzz is by building and running the provided `Dockerfile`
for a specific zkVM. In the following example we will start a fuzzer instances performing
fault injection for the `Pico` zkVM.

First build the image and give it an appropriate name. Execute following command in the project root:
```
> podman build -t arguzz-pico -f ./projects/pico-fuzzer/Dockerfile .
```

Next, start a new interactive container using the freshly built `arguzz-pico` image and load into `bash`:
```
> podman run --name arguzz-pico-container -it arguzz-pico bash
```

You should now be able to access the `pico-fuzzer` inside of the container.
```
(arguzz)> pico-fuzzer -h
usage: PICO Fuzzer [-h] {install,run,check,generate} ...

PICO zkVM Fuzzer using a combination of metamorphic testing and fault injection techniques

positional arguments:
  {install,run,check,generate}
    check               check refound instances from CSV file
    generate            generates a project with the provided seed

options:
  -h, --help            show this help message and exit
```

To install a VM you can either download it using `git` or use the fuzzer client directly
(recommend for metamorphic testing and **required** for fault injection).
Following command will install the `pico` zkVM repository together with source code
modifications to retrieve trace information and apply fault injections:
```
(arguzz)> pico-fuzzer install modified-pico-repo --zkvm-modification
```

To start a `Pico` fuzzing instance, execute following command:
```
(arguzz)> pico-fuzzer run --fault-injection -o output -z modified-pico-repo -l arguzz-x-pico.log -v0
```
The command above runs the `pico-fuzzer` with fault injection enabled (`--fault-injection`).
The fuzzer output only provides important debug information (`-v0`) but safes all kinds of execution
information in a log file (`-l arguzz-x-pico.log`). Note that any Pico repository can be provided using
the `-z` or `--zkvm` flag. However, by providing a repository without modifications the options:
`--fault-injection` and `--trace-collection`, are not supported!

After a couple of minutes up to an hour, CSV files with information on the runs should be available
in the current folder. Here is an example output of the examples working directory content:
```
(arguzz)> ls
arguzz-x-pico.log    build.csv      modified-pico-repo  output        run.csv
arguzz-x-pico.log.1  injection.csv  normal.csv          pipeline.csv  summary.csv
```
For information on the csv files see the [CSV Data](#csv-data) section and for more information on
available options see the [Fuzzer Options](#fuzzer-options) section.

The fuzzers implementation for the other five zkVMs can be installed and executed in similar fashion.

If anything breaks in-between the mentioned steps, note that these zkVMs are actively developed and
are prune to changes in their setup. These changes might require updates of the corresponding
`Dockerfile`s or injection mechanisms.

___

**ATTENTION:** Fuzzing is resource intensive and can require a lot of memory and / or computing power!
Users should be aware that hardware wears down quicker if fuzzing is active for a long period of time!
Executing a fuzzer run or podman build for the first time may take up a lot of time and resources
depending on the system at hand.

**HARDWARE RECOMMENDATIONS:** Our experiments and explore runs were all executed on a server with over
1TB RAM. The lowest RAM we tested it on was 32GB for a single fuzzer instance. While this was
possible, we recommend even more memory per running fuzzer instance (>64GB). In theory 1 CPU core is
enough, but more cores significantly decrease runtime.

___

## Install

Arguzz is written and tested on Linux using Python 3.10.


The quickest way to install the dependencies is to run the `install` command from the `Makefile`
and activating the created `Python` virtual environment. To see if everything worked as expected,
use the provided `check` and `test` command.

```
> make install
...
> source .venv/bin/activate
(.venv) > make check
...
(.venv) > make test
...
```

While running Arguzz directly is an option, we strongly recommend using `Podman` or `Docker` together
with the provided `Dockerfile`s as it makes managing resources much simpler. For persistent cache, we
mounted working-, Rust and zkVM related directories during image building and container execution, but
this is not a required step. See the [quickstart](#quickstart) section for more information on how to
start a container.

## CSV Data
Depending on the current setting, Arguzz produces information in form of CSV files.

Some column names occur more often and are used to link the data across files. When
starting a fuzzer a random UUID is assigned to the instance, which is saved as `fuzzer_id`.
Ever new fuzzer run (,i.e., building the program, generating a new project and executing
some iterations with potential injection,) gets an id, `run_id`, which is an increasing
number, belonging to a fuzzer instance. Similar every iteration gets an incremental id,
`iteration_id`, which is reset after the start of a new run. So one specific iteration
can be indexed by `fuzzer_id`, `run_id` and `iteration_id`.

In general following files can be generated depending on the setting:
  - `normal.csv`, contains information on normal executions;
  - `summary.csv`, contains information on instruction occurrences per execution;
  Requires the trace option to be enabled!
  - `injection.csv`: contains information on instructions selected for injection;
  Requires the injection option to be enabled!
  - `build.csv`: contains information on the builds per run;
  - `run.csv`: contains information on runs;
  - `pipeline.csv`: contains time information on a rough separation of stages for zkvms;
  - `findings.csv`: contains information on errors or crashes together with a generation seed and input flags;
  - `checked_findings.csv`: copy of a `findings.csv` with an addition `fixed` column indicating if the found bug was fixed; This is only relevant for checking refound bugs;


## Fuzzer Options

Every fuzzer has 2 positional "action" options, i.e., `install` and `run`. For the fuzzers,
where bugs were found, we have an addition option, namely `check`. For all the actions we
provide following debug options:
 - `--log-file`: Optional logging file location; Note that logging files are rotated after a certain size and old ones are deleted. Changes to the size and amount of rotation files can be done directly in [cli.py](libs/zkvm-fuzzer-utils/zkvm_fuzzer_utils/cli.py).
 - `--verbosity`: Verbosity of the output;
 - `--commit-or-branch`: Specific zkVM commit or branch that should be used for the current command;

In the next sub-sections we will shortly describe the actions and their specific options.

### install

This action is used to install the zkVM. Installing the zkVM using this option is required
if trace information or injection based testing is desired. The command takes one positional
argument indicating the desired location for the zkVM. Additional option:
  - `--zkvm-modification`: Specifies if the zkVM should be installed with modifications (trace collection, and injection locations) or without;

### run

The `run` command starts a fuzzing instance. It has following options:

  - `--seed`: Specific seed for the generation;
  - `--timeout`: "Soft" timeout in seconds, stopping after an iteration if the timeout is reached;
  - `--no-schedular`: Disables the injection schedular;
  - `--fault-injection`: Enables testing with fault injection;
  - `--trace-collection`: Enables the collection of trace information;
  - `--only-modify-word`: Disables all other injection types except the `MOD_INSTR_WORD`;
  - `--no-inline-assembly`: Disables the inline assembly generation;
  - `---zkvm`: Used to point to the zkVM installation folder;
  - `--out`: Output directory used for the zkVM project generation and execution;

### generate

The `generate` command is used to generate a zkVM project. It has the same options as the `run`
command with the difference that the provided `--seed` is directly used for project generation. 

### check

The `check` command is similar to `run` command, but instead of generating and executing random
projects, it executes specified instances from a `findings.csv`. This file is provided as positional argument.

___

Every command supports the `--help` option for more information.
___

**Note:** This version of Arguzz only supports specific commits to ensure their functionality.
Other commits require changes of the source code to get them to work.

## Common Issues

### Jolt Core Limitations

The new Jolt version has problems running on machines with many cores / threads available.
We have tested up to 32 threads which was fine. The error occurred on an unrestricted run with
192 available threads.

### Missing rust-std for toolchain / target

The error looks something like this:

```bash
error[E0463]: can't find crate for core
  |
  = note: the riscv32i-unknown-none-elf target may not be installed
  = help: consider downloading the target with rustup target add riscv32i-unknown-none-elf
  = help: consider building the standard library from source with cargo build -Zbuild-std
```

The best one can do here is to manually execute `rustup` to get the target for a specific toolchain.

```bash
$> rustup +<toolchain> target add <target-triple>
```

## Bug Trophies

### RiscZero
The RiscZero development team prefers bugs over a closed bug bounty site.
  - closed report on bug bounty site lead to this PR:
    - https://github.com/risc0/risc0/pull/3015
  - closed report on bug bounty site lead to these PRs:
    - https://github.com/risc0/risc0/pull/3181
    - https://github.com/risc0/zirgen/pull/238

### NexusVM
  - https://github.com/nexus-xyz/nexus-zkvm/issues/368
  - https://github.com/nexus-xyz/nexus-zkvm/issues/404
  - https://github.com/nexus-xyz/nexus-zkvm/issues/413

### Jolt
  - https://github.com/a16z/jolt/issues/719
  - https://github.com/a16z/jolt/issues/741
  - https://github.com/a16z/jolt/issues/741
  - https://github.com/a16z/jolt/issues/824
  - https://github.com/a16z/jolt/issues/833
  - https://github.com/a16z/jolt/issues/892
