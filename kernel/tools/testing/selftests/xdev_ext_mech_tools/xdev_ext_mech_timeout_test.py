#!/usr/bin/env python3
"""Execute the controller's actual terminal timeout branches."""
from pathlib import Path
import subprocess
import os
import tempfile

root = Path(os.environ.get('XDEV_EXT_TEST_SRC', Path(__file__).resolve().parents[4]))
scratch = tempfile.TemporaryDirectory(prefix='xdev_ext-regression-')
out = Path(scratch.name)
text = (root / 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
nic_start = text.index('\n\tif (ret &&', text.index('static int cmd_nic_nvme('))
nic_end = text.index('\n\tif (o->expect_window_reject)', nic_start)
source_start = text.index('\n\tif (ret == -ETIMEDOUT)', text.index('static int ctl_run_source('))
source_end = text.index('\n\tfor (i = 0; !ret && src->user_pattern', source_start)
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include "include/uapi/linux/xdev_ext_mech.h"
struct ctl_opts { bool reliable; unsigned long long timeout_ms; bool expect_unbind; };
struct ctl_run { int ring; __u64 session; };
#define CTL_FAIL 1
static unsigned int snapshots, stops, printed;
static __u64 ctl_now_ns(void) { return 1; }
static int ctl_stats(int ring, __u64 session, struct xdev_ext_mech_stats *s) {
    (void)ring; (void)session; snapshots++; s->inflight = 0; return 0;
}
static void ctl_print_stats(const struct xdev_ext_mech_stats *s) { (void)s; printed++; }
static int ctl_mech(int ring, int op, __u64 session) {
    (void)ring; (void)session; stops += op == XDEV_EXT_MECH_OP_STOP; return 0;
}
static void usleep(unsigned int us) { (void)us; }
#define ctl_err(...) (void)0
static int source_timeout(bool legacy) {
    struct ctl_opts options = {.expect_unbind = legacy};
    struct ctl_opts *o = &options;
    int ret = -ETIMEDOUT;
    (void)o;
'''
middle = r'''
    return ret;
}
static int nic_timeout(bool coarse) {
    struct ctl_opts options = {0};
    struct ctl_opts *o = &options;
    int ret = -ETIMEDOUT;
    int verdict = 0;
    struct xdev_ext_mech_stats s = { .inflight = coarse };
    struct ctl_run r = { .ring = 17, .session = 3 };
    (void)o;
    (void)coarse;
'''
suffix = r'''
    return 0; /* The report/possible PASS path was reached. */
out:
    (void)verdict;
    return ret;
}
int main(void) {
    int failures = 0;
    if (source_timeout(false) != -ETIMEDOUT) {
        fprintf(stderr, "source coarse timeout was cleared before verdict\n");
        failures++;
    }
    if (nic_timeout(true) != -ETIMEDOUT) {
        fprintf(stderr, "nic coarse timeout reached verdict path\n");
        failures++;
    }
    if (source_timeout(true) || nic_timeout(false)) {
        fprintf(stderr, "legacy diagnostic timeout behavior changed\n");
        failures++;
    }
    if (snapshots != 1 || stops != 1 || printed != 1) {
        fprintf(stderr, "timeout must retain a drained final snapshot before STOP\n");
        failures++;
    }
    printf("coarse timeout failure/legacy compatibility: %s\n", failures ? "FAIL" : "PASS");
    return failures != 0;
}
'''
source = out / 'coarse-timeout-regression.c'
binary = out / 'coarse-timeout-regression'
source.write_text(prefix + text[source_start:source_end] + middle + text[nic_start:nic_end] + suffix)
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(root),
                str(source), '-o', str(binary)], check=True)
raise SystemExit(subprocess.run([str(binary)]).returncode)
