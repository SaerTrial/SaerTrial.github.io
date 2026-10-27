# Research idea: RTT transport for on-MCU concolic execution

**Status:** Future experiment. No CO3/RTT integration or performance result is claimed here. This note is separate from the instrumentation blog and from the record-and-replay prototype's demonstrated results.

## Starting point

[CO3: Concolic Co-execution for Firmware](https://www.usenix.org/system/files/usenixsecurity24-liu-changming.pdf) runs instrumented firmware concretely on an MCU. The firmware reports runtime values relevant to symbolic reasoning; a workstation builds and solves the constraints. CO3 describes 35 message types of 2–13 bytes each, batched in a 64-byte MCU buffer. Its evaluated links include physical UART at **7.5 Mbaud** on STM32 F429ZI and **USB CDC** on other boards, including STM32 H743ZI. It is inaccurate to describe CO3 as using only a low-baud-rate UART. See Sections 5 and 7, especially Table 1.

In one comparison, CO3 transmitted less than 8 KB per execution versus about 150 KB for Symbion. The paper attributes about 1% of end-to-end execution time to MCU–workstation interaction in that evaluation. Yet its Full-On mode also shows a 121× MCU runtime overhead versus unmodified firmware. These are **CO3's measurements**, not predictions for RTT. See Section 7.1 and 7.2 of the [paper](https://www.usenix.org/system/files/usenixsecurity24-liu-changming.pdf).

## Hypothesis

Keep CO3-style instrumentation, event encoding, and workstation solver fixed, and vary **only the host–MCU transport**. One candidate is [J-Link RTT](https://www.segger.com/products/debug-probes/j-link/technology/about-real-time-transfer/): the instrumented code writes output into an MCU RAM ring buffer, J-Link drains it over background debug memory access through SWD/JTAG, and an RTT down-channel can deliver the next input. RTT is distinct from [J-Link Virtual COM Port](https://kb.segger.com/J-Link_Virtual_COM_Port), which forwards a target UART, and from a halt/GDB exchange.

Hypothesis to test: RTT could lower MCU-side reporting cost or raise sustained event throughput relative to a blocking UART implementation. A UART backed by a RAM queue and DMA may also avoid blocking and may cost less CPU for bulk transfer. USB CDC could outperform either. Faster raw transfer alone would not establish more completed concolic executions per second.

## Proposed experiment

Build a small transport interface and run the same MCU, firmware, instrumented workload, message format, initial buffer budget, and workstation solver with four backends:

1. Blocking UART.
2. Buffered UART with DMA.
3. USB CDC.
4. J-Link RTT in a mode that uses background memory access.

Measure MCU cycles per 2–13-byte event and per 64-byte flush; sustained bytes/events per second; input-delivery latency; buffer occupancy, stalls, and loss; ordering across normal code and ISR events; code size, RAM use, and runtime perturbation; and end-to-end concolic runs and coverage per unit time. Repeat at several event rates so a low-traffic case does not hide saturation, then sweep buffer sizes. Record probe model, SWD/JTAG clock, MCU clock/cache settings, UART baud rate, USB configuration, and buffer sizes alongside results.

For symbolic-trace integrity, add sequence numbers and an explicit overflow counter or marker. Validate that the workstation detects every gap and reconstructs the intended order across ISR and normal code. Compare blocking and nonblocking RTT policies separately: [SEGGER documents](https://kb.segger.com/RTT) that a full buffer can either stall the writer or discard data, depending on configuration. Account for target-side copies and synchronization costs. On a cached Cortex-M7, follow SEGGER's [cache-line alignment and cache-maintenance requirements](https://kb.segger.com/RTT) for RTT control structures and buffers.

The experiment supports a performance claim only if RTT improves a measured target or end-to-end metric **while preserving complete, ordered traces** under the tested conditions. If it only moves the bottleneck to buffering, host processing, or the solver, report that result instead.

## Relationship to the blog

The blog's current point is that software instrumentation can report chosen semantic events that hardware instruction trace does not directly label. CO3 is another possible application of that flexibility. This transport experiment belongs in this separate note until it is implemented and measured.
