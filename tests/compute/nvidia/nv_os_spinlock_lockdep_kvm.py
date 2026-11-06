#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Lockdep behaviour of the NVIDIA os_spinlock code, in a KVM guest.

Builds a module from the os_spinlock section of an os-interface.c (ours, or
upstream for the baseline), boots it under a lockdep kernel and reads the
console.  All RM spinlocks come from os_alloc_spinlock(), so with one lockdep
class any nesting of two of them looks recursive: the first RTX 5090
strict-debug window reported exactly that at GPU open
(rmGpuLockInfo.pLock held around gpumgrGetGpu(), which takes the TLS lock)
and lockdep then switched itself off for the rest of the boot.

PASS needs: three distinct locks nested with no lockdep report; the same
with a hardirq timer taking a lock concurrently, and no nesting depth left
on any CPU; lockdep still on; and lockdep still reporting a real inversion
between an RM spinlock and an ordinary kernel spinlock.

  nv_os_spinlock_lockdep_kvm.py --os-interface FILE --kernel-build DIR \
      --bzimage FILE --out DIR [--cc gcc-14] [--busybox /bin/busybox]
      [--qemu qemu-system-x86_64]
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

MODULE = 'nv_os_spinlock_lockdep'
SHIM = r'''// SPDX-License-Identifier: MIT
#include <linux/atomic.h>
#include <linux/debug_locks.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/lockdep.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

typedef int NV_STATUS;
typedef unsigned long long NvU64;
#define NV_OK 0
#define NV_ERR_NO_MEMORY 0x51
#define NV_API_CALL
#define NV_DBG_ERRORS 0
#define NVCPU_X86_64 1
#define nv_printf(level, ...) pr_err(__VA_ARGS__)
typedef spinlock_t nv_spinlock_t;
#define NV_SPIN_LOCK_INIT(lock) spin_lock_init(lock)
#define NV_SPIN_LOCK_IRQSAVE(lock, flags) spin_lock_irqsave(lock, flags)
#define NV_SPIN_UNLOCK_IRQRESTORE(lock, flags) spin_unlock_irqrestore(lock, flags)
static NV_STATUS os_alloc_mem(void **address, size_t size)
{
	*address = kmalloc(size, GFP_KERNEL);
	return *address ? NV_OK : NV_ERR_NO_MEMORY;
}
static void os_free_mem(void *address) { kfree(address); }

/* ---- os_spinlock section of the os-interface.c under test ---- */
'''
BODY = r'''
/* ---- end of the section under test ---- */

static void *locks[3];
static DEFINE_SPINLOCK(kernel_lock);
static struct hrtimer tick_timer;
static atomic_t ticks = ATOMIC_INIT(0);

static enum hrtimer_restart tick(struct hrtimer *timer)
{
	NvU64 irql = os_acquire_spinlock(locks[2]);

	os_release_spinlock(locks[2], irql);
	if (atomic_inc_return(&ticks) >= 2000)
		return HRTIMER_NORESTART;
	hrtimer_forward_now(timer, ns_to_ktime(20000));
	return HRTIMER_RESTART;
}

static int depth_left(void)
{
	int total = 0;
#ifdef CHECK_DEPTH
	int cpu;

	for_each_possible_cpu(cpu)
		total += per_cpu(os_spinlock_depth, cpu);
#endif
	return total;
}

static int __init lockdep_test_init(void)
{
	unsigned long deadline, flags;
	NvU64 a, b, c;
	int i;

	for (i = 0; i < 3; i++)
		if (os_alloc_spinlock(&locks[i]) != NV_OK)
			return -ENOMEM;
	pr_info("OS_SPINLOCK_TEST step=nested begin\n");
	/* RM: rmGpuLockInfo.pLock held while gpumgrGetGpu() takes the TLS lock. */
	a = os_acquire_spinlock(locks[0]);
	b = os_acquire_spinlock(locks[1]);
	c = os_acquire_spinlock(locks[2]);
	os_release_spinlock(locks[2], c);
	os_release_spinlock(locks[1], b);
	os_release_spinlock(locks[0], a);
	pr_info("OS_SPINLOCK_TEST step=nested end irqs_enabled=%d\n", !irqs_disabled());

	pr_info("OS_SPINLOCK_TEST step=irq begin\n");
	hrtimer_setup(&tick_timer, tick, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer_start(&tick_timer, ns_to_ktime(20000), HRTIMER_MODE_REL);
	deadline = jiffies + 5 * HZ;
	while (atomic_read(&ticks) < 2000 && time_before(jiffies, deadline)) {
		a = os_acquire_spinlock(locks[0]);
		b = os_acquire_spinlock(locks[1]);
		udelay(5);
		os_release_spinlock(locks[1], b);
		os_release_spinlock(locks[0], a);
		cond_resched();
	}
	hrtimer_cancel(&tick_timer);
	pr_info("OS_SPINLOCK_TEST step=irq end ticks=%d depth_left=%d depth_checked=%d\n",
		atomic_read(&ticks), depth_left(),
#ifdef CHECK_DEPTH
		1
#else
		0
#endif
		);
	pr_info("OS_SPINLOCK_TEST debug_locks=%d\n", debug_locks);

	/* A real AB-BA between an RM spinlock and an ordinary kernel lock. */
	pr_info("OS_SPINLOCK_TEST step=inversion begin\n");
	spin_lock_irqsave(&kernel_lock, flags);
	a = os_acquire_spinlock(locks[0]);
	os_release_spinlock(locks[0], a);
	spin_unlock_irqrestore(&kernel_lock, flags);
	a = os_acquire_spinlock(locks[0]);
	spin_lock(&kernel_lock);
	spin_unlock(&kernel_lock);
	os_release_spinlock(locks[0], a);
	pr_info("OS_SPINLOCK_TEST step=inversion end\n");
	return 0;
}

static void __exit lockdep_test_exit(void)
{
	int i;

	for (i = 0; i < 3; i++)
		os_free_spinlock(locks[i]);
}

module_init(lockdep_test_init);
module_exit(lockdep_test_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("lockdep check of the NVIDIA os_spinlock code");
'''
INIT = '''#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
echo OS_SPINLOCK_GUEST=boot
insmod /MODULE.ko
echo "OS_SPINLOCK_GUEST=insmod rc=$?"
grep -E 'debug_locks|lock-classes' /proc/lockdep_stats
echo OS_SPINLOCK_GUEST=done
poweroff -f
'''.replace('MODULE', MODULE)
REPORT = re.compile(r'possible recursive locking|possible circular locking|inconsistent lock state|'
                    r'possible irq lock inversion|lock order detected|bad unlock balance|'
                    r'BUG: |WARNING: |turning off the locking correctness validator')


def section(text):
    """typedef struct os_spinlock_s .. the end of os_release_spinlock()."""
    start = text.index('typedef struct os_spinlock_s')
    release = text.index('void NV_API_CALL os_release_spinlock', start)
    end = text.index('\n}\n', release) + 3
    return text[start:end]


def build(args, out):
    module = out / 'module'
    shutil.rmtree(module, ignore_errors=True)
    module.mkdir(parents=True)
    code = section(Path(args.os_interface).read_text())
    (module / f'{MODULE}.c').write_text(SHIM + code + BODY)
    defines = ' -DCHECK_DEPTH' if 'os_spinlock_depth' in code else ''
    (module / 'Kbuild').write_text(f'obj-m += {MODULE}.o\nccflags-y += -Wno-unused-parameter{defines}\n')
    with open(out / 'module-build.log', 'w') as log:
        subprocess.run(['make', '-C', args.kernel_build, f'M={module}', f'CC={args.cc}',
                        f'HOSTCC={args.cc}', 'modules'], stdout=log, stderr=subprocess.STDOUT, check=True)
    return module / f'{MODULE}.ko'


def cpio_newc(root):
    data = bytearray()
    ino = 1

    def entry(name, mode, body=b'', nlink=1, rdev=(0, 0)):
        nonlocal ino
        header = '070701' + ''.join(f'{v:08x}' for v in (
            ino, mode, 0, 0, nlink, 0, len(body), 0, 0, *rdev, len(name) + 1, 0))
        ino += 1
        data.extend(header.encode() + name.encode() + b'\0')
        data.extend(b'\0' * (-len(data) % 4))
        data.extend(body)
        data.extend(b'\0' * (-len(data) % 4))

    for path in sorted(root.rglob('*')):
        name = str(path.relative_to(root))
        if path.is_symlink():
            entry(name, 0o120777, os.readlink(path).encode())
        elif path.is_dir():
            entry(name, 0o040755, nlink=2)
        else:
            entry(name, 0o100755 if os.access(path, os.X_OK) else 0o100644, path.read_bytes())
    # init's stdout: the kernel opens /dev/console of the initramfs.
    entry('dev/console', 0o020600, rdev=(5, 1))
    entry('TRAILER!!!', 0)
    return bytes(data)


def initramfs(args, out, ko):
    root = out / 'initroot'
    shutil.rmtree(root, ignore_errors=True)
    for name in ('bin', 'proc', 'sys', 'dev'):
        (root / name).mkdir(parents=True)
    shutil.copy2(args.busybox, root / 'bin/busybox')
    for applet in ('sh', 'mount', 'insmod', 'grep', 'poweroff'):
        (root / 'bin' / applet).symlink_to('busybox')
    (root / 'init').write_text(INIT)
    (root / 'init').chmod(0o755)
    shutil.copy2(ko, root / f'{MODULE}.ko')
    image = out / 'initramfs.cpio.gz'
    image.write_bytes(gzip.compress(cpio_newc(root)))
    return image


def boot(args, out, image):
    command = [args.qemu, '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '4', '-m', '2048',
               '-nographic', '-no-reboot', '-nic', 'none', '-kernel', args.bzimage, '-initrd', str(image),
               '-append', 'console=ttyS0 rdinit=/init panic=-1 loglevel=7']
    (out / 'qemu.command').write_text(' '.join(command) + '\n')
    with open(out / 'console.log', 'w') as console:
        result = subprocess.run(['timeout', '600', *command], stdout=console, stderr=subprocess.STDOUT)
    return result.returncode, (out / 'console.log').read_text(errors='replace')


def judge(console):
    problems, steps, current = [], {}, None
    for line in console.splitlines():
        marker = re.search(r'OS_SPINLOCK_TEST step=(\w+) (begin|end)', line)
        if marker:
            current = marker.group(1) if marker.group(2) == 'begin' else None
            steps.setdefault(marker.group(1), []).append(marker.group(2))
            if marker.group(2) == 'end':
                steps[marker.group(1)].append(line)
            continue
        if current and REPORT.search(line):
            steps.setdefault(current + '-reports', []).append(line.strip())
    for step in ('nested', 'irq'):
        if 'end' not in steps.get(step, []):
            problems.append(f'step {step} did not finish')
        for report in steps.get(step + '-reports', []):
            problems.append(f'lockdep in {step}: {report}')
    irq_end = next((l for l in steps.get('irq', []) if 'ticks=' in l), '')
    fields = dict(re.findall(r'(\w+)=(-?\d+)', irq_end))
    if int(fields.get('ticks', 0)) < 1:
        problems.append('the hardirq timer never took its lock')
    if fields.get('depth_checked') == '1' and fields.get('depth_left') != '0':
        problems.append(f'nesting depth left behind: {fields.get("depth_left")}')
    if 'OS_SPINLOCK_TEST debug_locks=1' not in console:
        problems.append('lockdep was off before the inversion step')
    inversion = steps.get('inversion-reports', [])
    if not any('possible circular locking dependency detected' in line for line in inversion):
        problems.append('a real RM-spinlock/kernel-lock inversion was not reported')
    return dict(verdict='FAIL' if problems else 'PASS', problems=problems,
                ticks=fields.get('ticks'), depth_left=fields.get('depth_left'),
                depth_checked=fields.get('depth_checked') == '1', inversion_reports=inversion)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--os-interface', required=True)
    parser.add_argument('--kernel-build', required=True)
    parser.add_argument('--bzimage', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--cc', default='gcc-14')
    parser.add_argument('--busybox', default='/bin/busybox')
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ko = build(args, out)
    rc, console = boot(args, out, initramfs(args, out, ko))
    result = judge(console)
    result['qemu_exit'] = rc
    result['os_interface'] = str(Path(args.os_interface).resolve())
    (out / 'result.json').write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    print(f'OS_SPINLOCK_LOCKDEP={result["verdict"]} ticks={result["ticks"]} '
          f'depth_left={result["depth_left"]} inversion_reported={int(not any("inversion" in p for p in result["problems"]))}')
    for problem in result['problems']:
        print('PROBLEM ' + problem)
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
