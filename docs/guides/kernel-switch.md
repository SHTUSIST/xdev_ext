# Orderly kernel switching

`tools/boot/kernel_switch.py` checks an installed trial kernel and an existing
known-good GRUB default. It reads boot facts by default. Only `switch --execute`
loads the trial kernel and asks systemd to perform an orderly kexec.

Use this tool for development on a dedicated host after stopping workloads and
draining device users. Use the same firmware reboot procedure for all formal
performance measurements. A kexec boot skips firmware initialization; the tool
cannot prove that GPU firmware, Thunderbolt/NHI queues, DMA, or IOMMU state has
been reset or that every device is quiescent.

## Supported installation

The initial backend supports x86-64 Linux with systemd PID 1 and the Ubuntu EFI
GRUB 2 chain: the active first EFI boot entry selects `EFI/ubuntu/shimx64.efi`
on the mounted ESP, followed by `grubx64.efi` and a literal GRUB forwarding
configuration leading to `/boot/grub/grub.cfg`. Other firmware chains,
systemd-boot, direct EFI kernel entries, BIOS boot, custom forwarding scripts,
UKIs, and dynamic GRUB menus are unsupported. The tool rejects an unknown
chain rather than treating an old `grub.cfg` as proof of the active loader.

The machine needs installed `kexec`, `systemctl`, `grub-editenv`, `findmnt`,
`lsinitramfs`, `efibootmgr`, and `lsblk`. The tool does not install packages,
rewrite bootloader settings, enable watchdogs, reserve crashkernel memory,
reset PCI devices, unload drivers, or change Secure Boot policy. Kernel loading
can still be rejected by the running kernel's permissions or signature policy.

GRUB entries must have explicit full IDs, including every submenu ID separated
by `>`. Titles and numeric selectors such as `1>0` are not supported. The
generated `grub.cfg` and its actual environment determine the persistent
default. `/etc/default/grub` can be stale and is not used to infer that default.
Saved defaults require the standard generated header to load `grubenv`.
Custom default/environment assignments, helper functions, or fallback-changing
control flow are refused rather than interpreted as a general GRUB program.
The standard alternate-environment prefix branch is accepted only while the
stored `env_block` is empty, so that branch is inactive. Nonempty `env_block`
and active or unknown `initrdfail` recovery state are refused. Standard display
and EFI-menu availability probes can be inspected; their presence does not
make an unsafe selected entry executable.
Both selected entries must have one literal Linux image, one initrd, and a
filesystem UUID that maps to the installed root/boot filesystem.
Both selected entries and every parent submenu must also be unconditionally
defined. Conditional menus remain visible during inspection, marked unsafe;
the tool does not assume that an unknown GRUB condition will make a chosen
trial or fallback entry available.

The exact top-level Ubuntu `41_custom` block can load
`/boot/grub/custom.cfg`. The tool expands that one block once, at its original
position. The optional regular file may contain comments and literal
`menuentry` declarations with explicit IDs. Global statements, functions,
submenus, other sources, duplicate menu/submenu IDs, and redirected source
paths are refused. Imported `prefix` or `config_directory`, and assignments
that override those paths, are also refused. Inspection lists unsupported
custom bodies as unsafe; selected entries containing `cutmem`, unknown effects,
or unsupported conditional/compound commands are rejected. Kexec does not
reproduce GRUB memory-map edits. Custom menus cannot change the required
permanent good default.

The image's embedded release, its installed filename, the initrd's modules
release, and `/lib/modules/RELEASE` must agree. An initrd with no identifiable
modules release or with multiple releases is unsupported. Root/boot paths must
be unambiguous and installed under `/boot`; this is not a loader for arbitrary
build-directory images.

## Inspect and plan

Run from the repository root:

```sh
python3 tools/boot/kernel_switch.py
python3 tools/boot/kernel_switch.py inspect
```

These commands only read facts and print JSON. They list full entry IDs and
the effective permanent default. Reading restricted kernel or EFI files may
require root, even though inspection performs no writes.

Choose a trial entry and a **previously boot-tested** good entry from that
output. The good entry must already be the permanent default. Planning checks
that the good entry and its installed files still exist; it does not itself
perform another boot test.

```sh
python3 tools/boot/kernel_switch.py plan \
  --target-entry 'advanced-example>trial-example' \
  --good-entry 'advanced-example>good-example' \
  --panic-seconds 10
```

Replace the example IDs with complete IDs from inspection. `plan`, and
`switch` without `--execute`, never load a kernel, acquire the execution lock,
write a receipt, or alter boot settings.

The trial command line comes from the selected trial entry. Existing `panic=`
arguments are replaced with exactly one positive timeout. The timeout must fit a positive signed 32-bit integer. Other supported
arguments keep their values and order. The tool does not silently copy the
running kernel's command line or add watchdog/kdump options.
The final UTF-8 command line must fit both the image's advertised boot-protocol
limit and the tool's conservative 2047-byte limit. Oversized input is rejected,
not truncated, so the final positive `panic=` argument cannot be lost that way.

## Explicit execution

Actual execution needs root, an authorized maintenance window, and a private
receipt directory owned by the caller with mode `0700`. The receipt itself is
written with mode `0600` using atomic replacement. Choose a project-owned
directory; the example path below is a placeholder.

```sh
python3 tools/boot/kernel_switch.py switch \
  --target-entry 'advanced-example>trial-example' \
  --good-entry 'advanced-example>good-example' \
  --panic-seconds 10 \
  --receipt /path/to/private-run/kernel-switch.json \
  --execute
```

Immediately before loading, the tool takes an execution lock and repeats the
read-only checks. Changed boot facts, image/initrd metadata, or custom menu
contents/file identity stop execution.
Do not update boot files or run another kernel-switch program concurrently;
the lock coordinates this tool's invocations, not every privileged program.

The only switching commands are normal `kexec --load` and then
`systemctl kexec`. The tool never substitutes raw `kexec -e`, force options,
or an ordinary reboot after a failure. `handoff-requested` means systemd
accepted a request; it does not mean the trial kernel booted. Verify the new
boot ID, actual kernel release, management access, and relevant device/data
paths after reconnecting.

## Recovery and failure states

The permanent good default is kept in place. Nonempty GRUB `next_entry`,
`prev_entry`, or `prev_saved_entry` prevents execution. So do unsupported
default-changing commands or a selected entry's unverified `savedefault` call.
EFI `BootNext` and a
boot order that does not start with the qualified GRUB entry are refused.
Kexec bypasses GRUB and would not consume a pending trial oneshot; leaving one
set could select the failed trial again on the next firmware reboot.

The exact generated Ubuntu `savedefault` helper is supported: when `boot_once`
is empty, it saves `chosen` to the standard environment. Its alternate-file
branch must be inactive because `env_block` is empty. Every selected entry and
parent submenu has an explicit ID, and an imported or overridden `chosen`
prefix is refused. Kexec does not execute the trial's GRUB body; a later
firmware fallback selects the existing good full ID, so this verified helper
saves the same good ID. Modified, conditionally defined, or redefined helpers
remain unsupported. The tool itself never calls the helper or writes GRUB's
environment.

A positive panic timeout can cause a panicking trial kernel to reboot through
firmware to the existing good default. This interrupts all processes and
connections; it does not resume the old kernel. A hard hang that never reaches
panic may require an already configured, independently verified hardware
watchdog or out-of-band recovery. The tool does not enable either mechanism
or claim that recovery has been tested on the physical host.

An already loaded normal image is refused rather than overwritten. A separate
crash image is reported and left unchanged. Load failures, ambiguous loaded
flags, interrupted execution, receipt failures, and rejected systemd handoff
are reported separately. A successful load followed by a failed handoff may
leave a normal image loaded. No automatic retry or unload is attempted because
the loaded flag cannot prove ownership against other privileged programs.
Inspect the state and arrange explicit cleanup before another switch.
If the process is killed or the machine stops before a receipt update, the
receipt contains only the last durable stage; it cannot report events that
occurred after that write.

Exit codes are `0` for a successful read-only result or accepted request, `2`
for invalid arguments, `3` for unsupported/preflight conditions, `4` for a load
failure with confirmed empty loaded state, `5` for a rejected handoff, and `6`
for interrupted, ambiguous, or receipt-related failures. No software-only
fixture test certifies physical boot, panic recovery, device reset, or
performance equivalence.
