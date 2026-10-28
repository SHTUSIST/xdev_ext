#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Isolate the FANOUT class-bind regression with an executable counterfactual.

Reuse poll/core_poll_test.py's extracted production session_bind fixture. The
only old production behavior substituted is poll_split from 6723cf8^; current
CREATE admission, session binding, and group/reference rules run in both arms.
The class recorders execute the actual NVMe and AF_XDP bind flag guards before
accepting the mocked resource-binding boundary. No device is opened, no DMA is
submitted, and this is neither a guest run nor a whole historical-kernel test.

Output is JSON; exit zero means every before/after expectation held. An older
splitter can be supplied with --before-header for source archives without git
history. Such input is identified by SHA256 and its path rather than a git ref.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'poll'))
from core_poll_test import build_fixture  # noqa: E402
from poll_extract import KERNEL, compile_and_run, fields, function, source  # noqa: E402

PRE_FIX = '6723cf8797ce1d8006a5e7c0cb3ff3bf79b6664a^'
HEADER = 'io_uring/xdev_ext_mech_poll.h'


def git(*args):
    return subprocess.check_output(['git', '-C', str(KERNEL), *args], text=True).strip()


def guard(relative, name):
    """Extract the complete initial production if(flags) return -EINVAL."""
    body = function(source(relative), name)
    match = re.search(r'\tif \(\(?u->flags\b.*?\n\t\treturn -EINVAL;', body, re.S)
    if not match:
        raise AssertionError('native flag guard missing: ' + name)
    return match.group()


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise AssertionError('fixture seam changed: ' + before[:80])
    return text.replace(before, after, 1)


BIND_CASE = r'''
static int bind_case(const char *mode)
{
    struct xdev_ext_mech_session s = {0};
    struct xdev_ext_mech_create c = { .abi_version = XDEV_EXT_MECH_ABI_VERSION,
        .nr_stages = 3, .pool_kind = XDEV_EXT_MECH_POOL_XSK, .pool_fd = 3,
        .layout = { .frame_size = 4096, .hdr_room = 360,
                    .seg_len = 1432, .group_bytes = 8192 },
        .depth = 4, .eventfd = -1 };
    const u32 F = XDEV_EXT_MECH_STAGE_F_FANOUT, P = XDEV_EXT_MECH_STAGE_F_POLL;
    u32 frames = 0;
    int admission, ret;

    c.st[0] = (struct xdev_ext_mech_stage_uapi){
        .class_id = XDEV_EXT_MECH_CLASS_NVME,
        .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 1, .arg1 = 64 };
    c.st[1] = (struct xdev_ext_mech_stage_uapi){
        .class_id = XDEV_EXT_MECH_CLASS_NVME,
        .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 2, .arg1 = 64 };
    c.st[2] = (struct xdev_ext_mech_stage_uapi){
        .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
        .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 3, .flags = F };
    if (strstr(mode, "nvme")) {
        c.st[1].class_id = XDEV_EXT_MECH_CLASS_AFXDP;
        c.st[1].fd = 3;
        c.st[1].arg1 = 0;
        c.st[2].class_id = XDEV_EXT_MECH_CLASS_NVME;
        c.st[2].fd = 2;
        c.st[2].arg1 = 64;
    }
    if (strstr(mode, "poll")) c.st[2].flags |= P;
    if (strstr(mode, "reliable")) c.st[2].flags |= XDEV_EXT_AFXDP_F_RELIABLE;
    if (!strcmp(mode, "sequential")) c.st[2].flags = 0;
    if (!strcmp(mode, "unknown")) c.st[2].flags |= 1U << 28;
    s.nr_stages = c.nr_stages;
    /* Exact plan-copy statement extracted from production session_init. */
    const struct xdev_ext_mech_create *input = &c;
    /* PLAN_COPY */
    admission = xdev_ext_mech_create_check(&c, &frames);
    ret = admission ? admission : xdev_ext_mech_session_bind(&s, &c);
    printf("admission=%d bind_ret=%d nr_bound=%u frames=%u "
           "bind0=%u bind1=%u bind2=%u class_flags2=%u bound_flags2=%u "
           "caller_flags2=%u plan_flags2=%u group_end=%u consumer_refs=%u poll2=%u\n",
           admission, ret, s.nr_bound, frames,
           bind_calls[0], bind_calls[1], bind_calls[2], bind_flags[2], s.st[2].flags,
           c.st[2].flags, s.plan[2].flags,
           xdev_ext_mech_stage_group_end(s.plan, s.nr_stages, 1),
           xdev_ext_mech_chain_refs(s.plan, s.nr_stages, 1), s.st[2].poll);
    return 0;
}
'''


def fixture(header):
    text = build_fixture()
    # Both arms use the same production functions and headers except the exact
    # splitter implementation from the historical source.
    split = function(header, 'xdev_ext_mech_poll_split')
    current = source(HEADER)
    swapped = replace_once(current, function(current, 'xdev_ext_mech_poll_split'), split)
    swapped = swapped.replace('#include "xdev_ext_mech_core.h"',
                              '#include "io_uring/xdev_ext_mech_core.h"')
    text = replace_once(text, '#include "io_uring/xdev_ext_mech_poll.h"',
                        '#include "io_uring/xdev_ext_mech_step.h"\n' + swapped)
    text = replace_once(text, 'struct sess ss;',
                        'struct sess ss;\nstruct xdev_ext_mech_stage_uapi plan[XDEV_EXT_MECH_MAX_STAGES];')
    nvme = guard('drivers/nvme/host/xdev_ext_mech_nvme.c', 'nvme_xdev_ext_class_bind')
    xsk = guard('net/xdp/xsk_xdev_ext_mech.c', 'xsk_xdev_ext_mech_bind')
    recorder = '''static int record_bind(struct xdev_ext_mech_stage *st,
                         const struct xdev_ext_mech_stage_uapi *u)
{
    bind_calls[st->index]++;
    bind_flags[st->index] = u->flags;
    bind_saw_poll[st->index] = st->poll;
    if (st->class_id == XDEV_EXT_MECH_CLASS_NVME) {
        bool write = st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
''' + nvme + '''
    } else if (st->class_id == XDEV_EXT_MECH_CLASS_AFXDP) {
''' + xsk + '''
    }
    /* Namespace/socket/resource binding is mocked after the exact guards. */
    return 0;
}'''
    text = replace_once(text, function(text, 'record_bind'), recorder)
    init = function(source('io_uring/xdev_ext_mech.c'), 'xdev_ext_mech_session_init')
    copy = re.search(r'memcpy\(s->plan, c->st, sizeof\(s->plan\)\);', init)
    if not copy:
        raise AssertionError('session_init no longer preserves the plan verbatim')
    # Run the exact statement, adapting local variable names only.
    copy = copy.group().replace('s->', 's.').replace('c->', 'input->')
    case = BIND_CASE.replace('/* PLAN_COPY */', copy)
    return replace_once(text, function(text, 'bind_case'), case)


def check(case, before, after):
    errors = []

    def expect(condition, why):
        if not condition:
            errors.append(why)

    for label, result in (('before', before), ('after', after)):
        expect(result['admission'] == (-22 if case == 'unknown' else 0), label + ': admission')
        if case == 'unknown':
            expect(result['bind0'] + result['bind1'] + result['bind2'] == 0,
                   label + ': invalid admission reached bind')
            continue
        expect(result['frames'] == 6, label + ': six frames per 8192-byte group')
        expect(result['consumer_refs'] == 2, label + ': two consumer references')
        expect(result['caller_flags2'] == result['plan_flags2'], label + ': plan flags changed')
        expect(result['group_end'] == (2 if case == 'sequential' else 3), label + ': fanout group')
        expect(result['poll2'] == int('poll' in case), label + ': poll request changed')
    if case == 'unknown':
        expect(before['bind_ret'] == after['bind_ret'] == -22, 'unknown bit was accepted')
    elif case == 'sequential':
        expect(before['bind_ret'] == after['bind_ret'] == 0, 'sequential control failed')
        expect(before['nr_bound'] == after['nr_bound'] == 3, 'sequential control not all bound')
    else:
        expect(before['bind_ret'] == -22 and before['nr_bound'] == 2,
               'old splitter must fail at third class bind with -EINVAL')
        expect(after['bind_ret'] == 0 and after['nr_bound'] == 3, 'fixed bind must accept all stages')
        expect(before['class_flags2'] & (1 << 31), 'old splitter did not expose FANOUT to class')
        flags = 1 if 'reliable' in case else 0
        expect(after['class_flags2'] == after['bound_flags2'] == flags,
               'fixed class flags differ from the requested class-specific bits')
        expect(after['plan_flags2'] & (1 << 31), 'core lost FANOUT semantics')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before-header', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = {'schema': 'xdev_ext.fanout_bind_counterfactual.v1',
              'scope': 'host_extracted_production_bind_with_mocked_resources',
              'real_guest_executed': False, 'native_dma_executed': False,
              'historical_scope': 'only pre-fix poll_split substituted into current fixture',
              'cases': [], 'passed': False}
    try:
        if args.before_header:
            before_text = args.before_header.read_text()
            report['before_source'] = str(args.before_header)
        else:
            prefix = git('rev-parse', '--show-prefix')
            before_text = git('show', PRE_FIX + ':' + prefix + HEADER)
            report['before_source'] = git('rev-parse', PRE_FIX)
        try:
            report['base_commit'] = git('rev-parse', 'HEAD')
        except subprocess.CalledProcessError:
            report['base_commit'] = None
        after_text = source(HEADER)
        report['splitter_sha256'] = {
            label: hashlib.sha256(function(header, 'xdev_ext_mech_poll_split').encode()).hexdigest()
            for label, header in (('before', before_text), ('after', after_text))}
        fixtures = (fixture(before_text), fixture(after_text))
        for case in ('afxdp', 'afxdp-poll', 'afxdp-reliable-poll', 'nvme', 'nvme-poll',
                     'sequential', 'unknown'):
            results = []
            for code in fixtures:
                rc, output = compile_and_run(code, ('bind', case))
                if rc:
                    raise AssertionError('fixture exited %d: %s' % (rc, output))
                results.append(fields(output))
            errors = check(case, *results)
            report['cases'].append({'name': case, 'before': results[0], 'after': results[1],
                                    'passed': not errors, 'errors': errors})
        report['passed'] = all(case['passed'] for case in report['cases'])
    except (AssertionError, OSError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    rendered = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end='')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
