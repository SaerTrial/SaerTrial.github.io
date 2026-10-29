---
title: "Making Two Emulators Agree: Hybrid Fuzzing for Cortex-M Firmware"
categories:
- fuzzing
- embedded systems
- program analysis
---

A firmware fuzzer has to decide what an input means before it can decide whether that input is interesting. A byte read from a peripheral register might change the next branch, enable an interrupt, or make an initialization loop continue. For a hybrid fuzzer, that decision has to survive a second execution engine: the symbolic executor must interpret the input in a way that the ordinary fuzzer can reproduce.

My [concolic-fuzzing project](https://github.com/SaerTrial/concolic-fuzzing) connects AFL++ to a full-system concolic executor through two QEMU forks. The supplied example runs Cortex-M7 firmware in a configurable environment. The part I want to explain here is the path from a concrete peripheral read to a symbolic expression, and from a solver's candidate back to an executable test case.

## Two engines and a shared queue

The fast execution path uses AFL++ and my `triforce-qemu` fork. AFL++ mutates input files; the emulator supplies a forkserver, consumes those files during firmware execution, and reports coverage.

The second path uses `concolic-executor`, a system-mode extension of SymQEMU. [SymQEMU](https://www.ndss-symposium.org/ndss-paper/symqemu-compilation-based-symbolic-execution-for-binaries/) adds symbolic execution to binary translation by modifying QEMU's intermediate representation before it is translated to host code. My fork combines that machinery with a configurable firmware execution environment.

A modified [SymCC fuzzing helper](https://github.com/eurecom-s3/symcc/blob/master/docs/Fuzzing.txt) connects the two:

```text
AFL++ queue
    |
    | select an unseen input
    v
concolic-executor + SymCC runtime
    |
    | generate candidate inputs
    v
afl-showmap + triforce-qemu
    |
    | keep interesting candidates in the helper queue
    v
AFL++ synchronization
```

This is an asynchronous loop. The helper ranks unseen inputs using coverage markers in their filenames, whether they are original seeds, and their size. It does not wait for a measured coverage plateau. AFL continues running while the helper explores inputs independently.

## What an input means inside the emulator

For an ordinary userspace target, a test case might be a file passed to a parser. In this prototype, an input can supply values for firmware memory-mapped I/O reads.

Both engines receive the same concrete byte stream. The fuzzer takes it through `-aflFile`; the concolic executor takes it through `-replayFile`. As execution requests values, the input cursor advances through the file. The meaning of a particular byte therefore depends on the sequence and sizes of those reads.

On the concolic side, `symbolize_mem_read()` obtains the concrete value and calls `symcc_make_symbolic()`. The symbolic load helper then associates an expression with the value entering the guest computation. The concrete value keeps that execution moving; the expression lets the solver reason about alternatives.

For example, consider this illustrative branch, rather than a fragment from the bundled firmware:

```c
uint32_t command = read_external_value();
if (command == 0x12345678) {
    handle_special_command();
}
```

A mutation might miss the required value. If the read is symbolic and the comparison is modeled, the executor can derive an input satisfying the other branch. The useful result is a new concrete test case. It still has to run through the fuzzing emulator.

That last step matters. The helper invokes `afl-showmap` on generated candidates and compares the resulting map with its accumulated coverage. Inputs it considers interesting enter an AFL-compatible queue. Its map is local to the helper, so a newly queued candidate is not automatically new coverage for the main AFL instance.

## Sharing the environment

Both emulators accept a JSON configuration through `-kernel`. Here that option points to the configuration, whose `flash[].file` field identifies the raw firmware image.

The configuration describes flash and RAM ranges, a CPU model, an entry point, optional register values, hooks, stopping addresses and an interrupt policy. The examples use a Cortex-M7 CPU and selected STM32 firmware images, but they do not provide a complete STM32 board model.

Hooks make that distinction visible. A configured address can stand in for a delay routine or a printing function. This helps execution reach code of interest, while also changing the environment in which that code runs. Coverage and failures must be interpreted against those choices.

The current interrupt policy cycles through enabled NVIC entries according to an emulator block-event counter. Its frequency is not a hardware clock frequency. Even a deterministic scheduling policy is useful only if both engines encounter compatible execution events.

There is also a `symbolize_at_pc` option for selected memory reads. In the current code, enabling it disables MMIO symbolization. This alternative needs its own validation: symbolic bytes attached to a RAM read must still correspond to an input the fuzzing engine can consume meaningfully.

## A trace comparison that could pass without a trace

While preparing the repository for release, I revisited the script intended to compare both engines' execution paths. It searched for the log marker:

```text
[cpu_tb_exec] executed at ...
```

The pinned emulators instead emit their block-entry records as:

```text
[arm_helper_func] executing at 0x8003de0 ...
```

The old extraction could produce two empty files and report that they matched. That is a particularly misleading result in this project: agreement between the engines is one of the assumptions the hybrid loop depends on.

The revised check recognizes the current marker, preserves address order and repetitions, and rejects missing, empty or malformed traces. The batch runner also records execution failures and timeouts separately from mismatches.

In a small Linux check, three inputs—80 `A` bytes followed by a newline, 81 zero bytes, and the byte sequence 0 through 79—produced matching nonempty block-entry traces in both freshly built emulators. That establishes agreement for those observed sequences. It does not compare all registers or memory values, and it does not establish equivalence with the physical device.

## Looking at the covered code

Both forks can export coverage using `-covFile`. The resulting EZCOV file records address ranges that [Ghidra Cartographer](https://github.com/nccgroup/Cartographer) can overlay on a matching program.

For the supplied example, I use the NUCLEO-H753ZI ELF for Ghidra and the corresponding raw image for emulation. Converting that ELF back to a raw binary produced an exact byte-for-byte match with the bundled image.

![Cartographer highlights in Ghidra's disassembly and decompiler]({{ site.baseurl }}/assets/image/hybrid-fuzzing/ghidra-coverage.png)

*A view from the project, showing coverage ranges highlighted in the disassembly and decompiled C. This illustration is separate from the release-validation runs.*

Preparing that workflow exposed another small but consequential bug. Input exhaustion uses `_exit()`, which does not flush standard I/O buffers. One export stopped at exactly 4,096 bytes, partway through a record. Enabling line buffering for the coverage stream in both engines preserved the records written before termination; six runs across the two engines now produce well-formed files.

File integrity is only one requirement. The exporter observes execution at a different point from the block-entry logger, and some logged addresses are absent from the exported ranges. The colors help locate observed execution, but an uncolored region is not proof that the firmware never reached it. They also do not establish that hybrid fuzzing outperforms a mutation-only baseline.

## What I would measure next

The current release checks establish that the pinned sources build on Linux, that selected concrete executions agree at block entry, and that the concolic executor can produce candidate inputs. In a 45-second integration check, AFL imported four inputs from the helper, identifiable by their `sync:symqemu` filenames. That check disabled deterministic mutation stages and shortened the synchronization interval to exercise the feedback path; it was not a performance comparison. A useful evaluation must go further.

I would compare AFL-only and hybrid campaigns under the same CPU and wall-clock budgets, repeat them with multiple seeds, and replay their corpora through a common coverage collector. I would also track how many solver candidates are generated, how many the helper accepts, and how many AFL actually imports as new coverage.

Coverage stability belongs in that evaluation as well. The initial integration run reported variable coverage for some mutated inputs. That needs investigation before interpreting a coverage increase as a benefit of symbolic execution.

The implementation gives me a place to study these questions. Its central requirement is that an input generated under the symbolic model remains meaningful when it returns to concrete execution.
