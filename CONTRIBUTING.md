# Contributing

Changes should preserve the boundary between bounded BPF plans, kernel admission and ownership, and provider-native execution. Follow the surrounding source style and retain existing copyright and SPDX notices.

## Build and test

Start with the [host checks](docs/getting-started.md). Use the [build guide](docs/build.md) for complete sources and target-specific builds. Run the tests that exercise the changed behavior, including failure paths when changing acceptance, completion or lifetime handling.

A useful regression demonstrates the original failure and checks an observable contract. Tests that use fake devices or CPU copies should identify that scope. Use a matching kernel and BTF for changes to UAPI, struct_ops or kfunc behavior.

## Pull requests

Explain the trigger, the observed problem, and the resulting behavior. Include the commands you ran, their outcomes, configuration and test scope. Distinguish host tests, software-device guest runs, builds and physical-device execution.

Keep changes focused. Describe any altered ABI, unsupported case, mapping requirement or teardown behavior. Include the relevant source or test updates when a contract changes.

## Issues

For a bug, include the project revision, exact command, full diagnostic output, exit status, toolchain and kernel configuration. For a device path, also include driver versions, device model and relevant topology. Remove credentials and unrelated private data from attachments.

Feature requests should describe the I/O route, memory type, device requirements and desired result. The issue templates prompt for this information.

## Licenses

Licenses apply per component and file; a contribution does not replace upstream license terms. See [LICENSE.md](LICENSE.md) for the component map. Preserve required attribution when moving or deriving code.
