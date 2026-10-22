# BPF contract

xdev_ext separates programmable plans from resource admission and native device ownership. Programs operate on the bounded information supplied at a defined callback phase. The kernel validates their output before using it.

The principal declarations are the [mechanism kernel interface](../../kernel/include/linux/xdev_ext_mech.h), [mechanism UAPI](../../kernel/include/uapi/linux/xdev_ext_mech.h), and [policy interface](../../kernel/include/linux/xdev_ext_binding.h). Example class programs live in [tools/xdev_ext_mech](../../kernel/tools/xdev_ext_mech).

## Policy and mechanism callbacks

The policy interface has phase-specific dispatch and completion collections. Policy decisions remain subject to backend admission, references and completion rules.

Mechanism programs attach through class-specific struct_ops. Their build callbacks construct bounded descriptors; completion callbacks interpret the supplied native result and select permitted next actions. Class contracts define the available information, limits, and actions. An action legal for AF_XDP receive is not automatically legal for a different class or phase.

The kernel owns descriptor scratch capacity, frame identity, generation, direction, range, coverage and native submission. Drivers retain mapping, queue and completion responsibility. Programs cannot authorize an out-of-window transfer, invent DMA addresses, access MMIO, or reclaim a buffer still owned by an accepted device operation.

## Plans and results

A plan must fit the bound layout and the class's descriptor limits. Source and destination offsets refer to admitted resources. Transform plans distinguish destination capacity from the actual produced length.

A refusal before native acceptance may permit bounded retry or backpressure. Once accepted, the operation follows the native terminal path. BPF cannot turn uncertain DMA into a safe retry. Invalid descriptors or incompatible completion actions fail the session contract rather than bypassing admission.

## Build against the target

Build programs using the BTF of the intended configured kernel, as shown in the [build guide](../build.md). The verifier must accept the exact loaded object against that kernel. Host fixtures that compile program logic do not substitute for kernel verifier acceptance or execution.

When adding a program, test legal plans, boundary values, rejected descriptors and the corresponding completion actions. Include stale/duplicate results and uncertain accepted completion where applicable.
