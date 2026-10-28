# Troubleshooting

Include the project revision, exact command, target kernel configuration, complete output, and exit status in a report. For device paths, also include driver versions, device model and the relevant PCIe topology. Remove credentials and unrelated private data before attaching logs.

| Symptom | Check |
|---|---|
| Host tests cannot compile | A C compiler with C11 and pthread support is available; retain the complete compiler error |
| Missing upstream headers or build files | Run `make prepare-linux` or `make prepare-nvidia`; complete trees are generated under `build/assembled` |
| Source download or hash check fails | Network access and cache contents; retain the expected and actual artifact identity |
| BPF build cannot find project types or kfuncs | `VMLINUX_BTF` names the matching configured xdev_ext `vmlinux`, not an unrelated stock kernel |
| BPF object is rejected at load | Capture the verifier log; check kernel/BPF ABI and enabled class configuration |
| CREATE rejects the session | Pool kind, layout, stage count, depth, fd access, window bounds, device capabilities and loaded programs/providers |
| Strict NVMe path rejects a controller | Controller data-SGL support, alignment, segment limits and the selected strict/test-mode configuration |
| Compatibility calls use libc fallback | Opt-in settings, exact allowlisted path, direct-I/O alignment, call shape and whether setup succeeded before publication |
| Peer mapping is refused | Allocation authority/generation, consuming device capability, supported direction and DMA/PCIe reachability |
| NVIDIA module build has unresolved symbols | Kernel build/configuration/symbol versions and the provider feature switch; match compiler and driver release |
| STOP leaves retained resources | Final status, outstanding native work and provider quiescence; a notification alone does not establish drain |

Use [supported paths](../reference/supported-paths.md) to distinguish an unsupported route from a setup problem. Shared host-memory staging and a peer-memory path have different prerequisites.

An uncertain accepted operation must retain its resource references until its lifetime contract permits release. Replaying it or recycling its memory can violate the ownership model. Diagnose the provider's native outcome and the session's final status before selecting recovery.
