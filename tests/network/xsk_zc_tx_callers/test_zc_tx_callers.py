#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Transmit-only zero-copy AF_XDP callers get XDP mode before CREATE.

CREATE refuses a non-reliable zero-copy TX stage whose queue refuses a TX
wakeup (igb, ice, i40e, ixgbe -EINVAL; igc -ENXIO; mlx5 -ENETDOWN while no XDP
program is attached).  The CLI's rule (ctl_zc_tx_xdp): kick the TX queue
before CREATE; attach the pass program only when the kick is refused with
EINVAL, ENXIO or ENETDOWN; accept another owner's program (-EBUSY); detach
only what was attached.  This suite checks the shared rule in the redirect
helper, the NVMe->NIC and GPU->NIC benchmark session arms, and the session
library, which applies it automatically and owns the program until close.
"""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('XDEV_EXT_CANONICAL_ROOT') or HERE.parents[2])
CLI = ROOT / 'src/cli'
CC = os.environ.get('CC', 'gcc')
_spec = importlib.util.spec_from_file_location('zc_tx_callers_adapter',
                                               HERE.parent / 'pool_dma' / 'adapter.py')
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)

NNB = 'tests/benchmarks/nvme_nic/nnb_session.c'
NNB_PRODUCER = 'tests/benchmarks/nvme_nic/nnb_producer.c'
GNB = 'tests/benchmarks/gpu_nic/session_gpu_nic.c'


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def strip_comments(text):
    return re.sub(r'/\*.*?\*/', '', text, flags=re.S)


def nnb_problems(session, producer):
    """NVMe READ -> AF_XDP TX (forward) is the arm's transmit-only zero-copy socket."""
    setup = strip_comments(adapter.function(session, 'session_setup'))
    teardown = strip_comments(adapter.function(session, 'session_teardown'))
    problems = []
    create = setup.find('mech(p->ring, XDEV_EXT_MECH_OP_CREATE')
    rule = re.search(r'if \(!c->reverse\)\s*\{\s*ret = xdev_ext_xsk_redirect_zc_tx_xdp\(\s*&p->redirect,'
                     r'\s*p->x\.fd,\s*\(int\)if_nametoindex\(c->ifname\),\s*XDP_FLAGS_DRV_MODE\s*\);', setup)
    if create < 0:
        return ['session_setup lacks CREATE']
    if not rule:
        problems.append('forward transmit-only socket gets no XDP-mode rule before CREATE')
    elif rule.start() > create:
        problems.append('XDP-mode rule runs after CREATE')
    elif not re.search(r'^\s*if \(ret\)\s*\{[^{}]*\breturn ret;', setup[rule.end():create], re.M):
        problems.append('a failed XDP-mode rule does not end setup before CREATE')
    fill = setup.find('fq_push(&p->x.fq, addr, S_RING)')
    redirect = setup.find('xdev_ext_xsk_redirect_attach(&p->redirect,')
    if fill < 0 or fill < create:
        problems.append('fill ring not supplied after CREATE')
    elif 'if (c->reverse)' in setup[create:fill]:
        problems.append('zero-copy transmit-only socket leaves its fill ring empty')
    if redirect < 0 or redirect < fill:
        problems.append('reverse redirect no longer follows the fill')
    stop = teardown.find('XDEV_EXT_MECH_OP_STOP')
    detach = re.search(r'if \(xdev_ext_xsk_redirect_is_active\(&p->redirect\)\)\s*'
                       r'xdev_ext_xsk_redirect_detach\(&p->redirect\);', teardown)
    if not detach or stop < 0 or detach.start() < stop:
        problems.append('teardown does not detach the owned program after STOP')
    # A refused setup still reaches that teardown (the producer counts it as set).
    if not re.search(r'ret = a->ops->setup\(a\);.*?if \(ret\) \{\s*set\+\+;\s*goto out;', producer, re.S) or \
            not re.search(r'for \(unsigned i = 0; i < set && i < c->nr_arms; i\+\+\)\s*'
                          r'if \(arms\[i\]\.ops\)\s*arms\[i\]\.ops->teardown\(&arms\[i\]\);', producer):
        problems.append('a refused session setup no longer reaches its teardown')
    return problems


def gnb_problems(text):
    """CE D2H -> AF_XDP TX (egress, zero-copy) is the arm's transmit-only socket."""
    body = strip_comments(adapter.function(text, 'main'))
    problems = []
    create = body.find('err = es_create(&r, &c, p.groups);')
    out = body.find('\nout:\n')
    if create < 0 or out < 0:
        return ['main lacks CREATE or its out: label']
    rule = re.search(r'if \((?:!o\.ingest && x\.zero_copy|x\.zero_copy && !o\.ingest)\)\s*\{\s*'
                     r'err = xdev_ext_xsk_redirect_zc_tx_xdp\(\s*&(\w+),\s*x\.fd,\s*'
                     r'\(int\)if_nametoindex\(o\.ifname\),\s*XDP_FLAGS_DRV_MODE\s*\);', body)
    if not rule:
        return ['egress zero-copy socket gets no XDP-mode rule before CREATE']
    owner = rule.group(1)
    if rule.start() > create:
        problems.append('XDP-mode rule runs after CREATE')
    elif not re.search(r'^\s*if \(err\)\s*\{[^{}]*\bgoto out;', body[rule.end():create], re.M):
        problems.append('a failed XDP-mode rule does not end setup before CREATE')
    if owner == 'redirect':
        problems.append('the pass program shares the receive redirect, detached before STOP')
    if re.search(r'\breturn\b', body[rule.end():out]):
        problems.append('an exit after the XDP-mode rule bypasses out:')
    fill = re.search(r'^\terr = xp_fq_fill\(&x, 0, XP_RING_SIZE\);', body, re.M)
    if not fill or fill.start() < create:
        problems.append('zero-copy transmit-only socket leaves its fill ring empty')
    tail = body[out:]
    close = tail.find('es_close(&r)')
    detach = re.search(r'if \(xdev_ext_xsk_redirect_is_active\(&' + re.escape(owner) + r'\)\)\s*'
                       r'xdev_ext_xsk_redirect_detach\(&' + re.escape(owner) + r'\);', tail)
    if not detach or close < 0 or detach.start() < close:
        problems.append('out: does not detach the owned program after the session is closed')
    if 'xdev_ext_xsk_redirect_attach(&redirect, &filter,' not in body or \
            not re.search(r'if \(!err && o\.ingest\)', body):
        problems.append('ingest redirect changed')
    return problems


def rule_run(redirect_text=None):
    """Build zc_tx_rule_test.c against the helper (or a mutated copy); (exit, output)."""
    with tempfile.TemporaryDirectory(prefix='zc-tx-rule-') as tmp:
        tmp = Path(tmp)
        source = CLI / 'xdev_ext_xsk_redirect.c'
        if redirect_text is not None:
            (tmp / 'include').mkdir()
            for header in (CLI / 'include').glob('xdev_ext_xsk_redirect*.h'):
                (tmp / 'include' / header.name).write_bytes(header.read_bytes())
            source = tmp / 'xdev_ext_xsk_redirect.c'
            source.write_text(redirect_text)
        exe = tmp / 'zc_tx_rule_test'
        built = run([CC, '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                     '-I' + str(CLI / 'include'), str(HERE / 'zc_tx_rule_test.c'),
                     str(source), '-o', str(exe), '-lbpf'])
        if built.returncode:
            return built.returncode, 'COMPILE FAILED\n' + built.stdout + built.stderr
        ran = run([str(exe)], timeout=60)
        return ran.returncode, ran.stdout + ran.stderr


# name -> (old, new): each reverts one part of the rule and must be detected.
RULE_MUTATIONS = {
    'attach_on_every_kick_failure': ('if (ret != -EINVAL && ret != -ENXIO && ret != -ENETDOWN)\n\t\treturn 0;',
                                     'if (!ret)\n\t\treturn 0;'),
    'attach_without_kick': ('ret = kick(xsk_fd);', 'ret = -EINVAL;'),
    'never_attach': ('if (ret != -EINVAL && ret != -ENXIO && ret != -ENETDOWN)\n\t\treturn 0;',
                     'if (ret || !ret)\n\t\treturn 0;'),
    'other_owner_is_an_error': ('xdp_flags);\n\treturn ret == -EBUSY ? 0 : ret;', 'xdp_flags);\n\treturn ret;'),
    'kick_carries_payload': ('sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0)',
                             'sendto(xsk_fd, "k", 1, MSG_DONTWAIT, NULL, 0)'),
}


class SharedRule(unittest.TestCase):
    def test_rule_against_injected_kicks_and_control_plane(self):
        code, out = rule_run()
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r'zc_tx_rule: \d+ checks, 0 failures')

    def test_each_reverted_part_of_the_rule_is_detected(self):
        text = (CLI / 'xdev_ext_xsk_redirect.c').read_text()
        for name, (old, new) in RULE_MUTATIONS.items():
            with self.subTest(mutation=name):
                self.assertEqual(text.count(old), 1, name + ': anchor missing or ambiguous')
                code, out = rule_run(text.replace(old, new, 1))
                self.assertNotEqual(code, 0, name + ' survived')
                self.assertNotIn('COMPILE FAILED', out, name)
                self.assertRegex(out, r'zc_tx_rule: \d+ checks, [1-9]\d* failures', name)


def block(pattern, text):
    found = re.search(pattern, text, re.S)
    if not found:
        raise AssertionError('mutation anchor missing: ' + pattern)
    return found.group(0)


def cut(text, piece):
    if text.count(piece) != 1:
        raise AssertionError('mutation anchor not unique')
    return text.replace(piece, '', 1)


def insert_after(text, anchor, piece):
    if text.count(anchor) != 1:
        raise AssertionError('mutation anchor not unique: ' + anchor)
    return text.replace(anchor, anchor + piece, 1)


def insert_before(text, anchor, piece):
    if text.count(anchor) != 1:
        raise AssertionError('mutation anchor not unique: ' + anchor)
    return text.replace(anchor, piece + anchor, 1)


NNB_RULE = r'\tif \(!c->reverse\) \{\n\t\tret = xdev_ext_xsk_redirect_zc_tx_xdp\(.*?\n\t\}\n'
NNB_FILL = r'\tfor \(uint32_t i = 0; i < S_RING; i\+\+\)\n\t\taddr\[i\][^\n]*\n\tif \(fq_push\(&p->x\.fq, addr, S_RING\) != S_RING\)\n\t\treturn -ENOSPC;\n'
NNB_DETACH = '\tif (xdev_ext_xsk_redirect_is_active(&p->redirect))\n\t\txdev_ext_xsk_redirect_detach(&p->redirect);\n'
NNB_CREATE = '\t/* Strict kernel admission checks native NVMe SGL and every NIC mapping. */\n'
NNB_MUTATIONS = {
    'rule_removed': lambda t: cut(t, block(NNB_RULE, t)),
    'rule_unguarded': lambda t: t.replace('\tif (!c->reverse) {\n\t\tret = xdev_ext_xsk_redirect_zc_tx_xdp(',
                                          '\t{\n\t\tret = xdev_ext_xsk_redirect_zc_tx_xdp(', 1),
    'rule_after_create': lambda t: insert_after(cut(t, block(NNB_RULE, t)), '\ta->registrations = 1;\n',
                                                block(NNB_RULE, t)),
    'rule_failure_ignored': lambda t: t.replace('strerror(-ret));\n\t\t\treturn ret;\n\t\t}\n\t}\n\t/* Strict',
                                                'strerror(-ret));\n\t\t}\n\t}\n\t/* Strict', 1),
    'fill_reverse_only': lambda t: t.replace(block(NNB_FILL, t),
                                             '\tif (c->reverse) {\n' + block(NNB_FILL, t) + '\t}\n', 1),
    'fill_before_create': lambda t: insert_before(cut(t, block(NNB_FILL, t)), NNB_CREATE, block(NNB_FILL, t)),
    'teardown_keeps_program': lambda t: cut(t, NNB_DETACH),
}

GNB_RULE = r'\tif \(!o\.ingest && x\.zero_copy\) \{\n\t\terr = xdev_ext_xsk_redirect_zc_tx_xdp\(.*?\n\t\}\n'
GNB_FILL = '\terr = xp_fq_fill(&x, 0, XP_RING_SIZE);\n'
GNB_DETACH = '\tif (xdev_ext_xsk_redirect_is_active(&pass))\n\t\txdev_ext_xsk_redirect_detach(&pass);\n'
GNB_OUT_CLOSE = '\tif (es_close(&r) && ret == XG_EXIT_PASS)\n\t\tret = XG_EXIT_FAIL;\n\t/* The session'
GNB_CREATE = '\terr = es_create(&r, &c, p.groups);\n'
GNB_MUTATIONS = {
    'rule_removed': lambda t: cut(t, block(GNB_RULE, t)),
    'rule_for_ingest_too': lambda t: t.replace('if (!o.ingest && x.zero_copy) {', 'if (x.zero_copy) {', 1),
    'rule_after_create': lambda t: insert_before(cut(t, block(GNB_RULE, t)), GNB_FILL, block(GNB_RULE, t)),
    'rule_failure_ignored': lambda t: t.replace('o.ifname, strerror(-err));\n\t\t\tgoto out;\n',
                                                'o.ifname, strerror(-err));\n', 1),
    'old_fill_condition': lambda t: t.replace(GNB_FILL, '\tif (o.ingest || !x.zero_copy)\n\t' + GNB_FILL, 1),
    'program_kept': lambda t: cut(t, GNB_DETACH),
    'detached_before_close': lambda t: insert_before(cut(t, GNB_DETACH), GNB_OUT_CLOSE.split('\t/* The')[0],
                                                     GNB_DETACH),
    'shares_receive_redirect': lambda t: t.replace('&pass', '&redirect'),
    'exit_bypasses_out': lambda t: insert_before(t, GNB_CREATE, '\tif (o.seed == 7654321)\n\t\treturn XG_EXIT_FAIL;\n'),
}


def source_view():
    view = os.environ.get('XDEV_EXT_SOURCE_VIEW')
    if view and (Path(view) / 'kernel/tools/xdev_ext_xsk_redirect.c').is_file():
        return Path(view)
    sys.path.insert(0, str(ROOT / 'tools'))
    from layout import materialize_view
    return Path(materialize_view(ROOT).root)


class SessionArmBuilds(unittest.TestCase):
    """Both arms still compile and link the helper, with the session backend on."""

    @classmethod
    def setUpClass(cls):
        cls.view = source_view()

    def test_nvme_nic_producer_with_session_backend(self):
        with tempfile.TemporaryDirectory(prefix='zc-tx-nnb-') as tmp:
            target = Path(tmp) / 'nnb_producer'
            built = run(['make', '-s', '-C', str(self.view / 'tests/eval/nvme_nic'), 'ENABLE_SESSION=1',
                         'BUILD_DIR=' + tmp, 'CC=' + CC, str(target)], timeout=300)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertTrue(target.is_file())

    def test_gpu_nic_session_arm(self):
        with tempfile.TemporaryDirectory(prefix='zc-tx-gnb-') as tmp:
            built = run([sys.executable, '-B', str(self.view / 'tests/eval/gpu_nic/run.py'),
                         '--arms', 'session', '--direction', 'nic-gpu', '--shape', 'ingest',
                         '--build-only', '--build-dir', tmp], timeout=300)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertTrue((Path(tmp) / 'session_gpu_nic').is_file(), built.stdout + built.stderr)


class NvmeNicSession(unittest.TestCase):
    def setUp(self):
        self.session = (ROOT / NNB).read_text()
        self.producer = (ROOT / NNB_PRODUCER).read_text()

    def test_forward_socket_gets_xdp_mode_before_create(self):
        self.assertEqual(nnb_problems(self.session, self.producer), [])

    def test_wiring_mutations_are_detected(self):
        for name, mutate in NNB_MUTATIONS.items():
            with self.subTest(mutation=name):
                mutated = mutate(self.session)
                self.assertNotEqual(mutated, self.session, name + ': no change')
                self.assertNotEqual(nnb_problems(mutated, self.producer), [], name + ' survived')
        lost = self.producer.replace('\t\t\tset++;\n\t\t\tgoto out;', '\t\t\tgoto out;', 1)
        self.assertNotEqual(lost, self.producer)
        self.assertNotEqual(nnb_problems(self.session, lost), [], 'refused setup skipping teardown survived')


class GpuNicSession(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / GNB).read_text()

    def test_egress_socket_gets_xdp_mode_before_create(self):
        self.assertEqual(gnb_problems(self.text), [])

    def test_wiring_mutations_are_detected(self):
        for name, mutate in GNB_MUTATIONS.items():
            with self.subTest(mutation=name):
                mutated = mutate(self.text)
                self.assertNotEqual(mutated, self.text, name + ': no change')
                self.assertNotEqual(gnb_problems(mutated), [], name + ' survived')


if __name__ == '__main__':
    unittest.main(verbosity=2)
