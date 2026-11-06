#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Zero-copy AF_XDP TX wakeups across a down link, and the CREATE queue probe.

A driver may take a TX wakeup without draining the kernel source while its
link is down (igb, ice) or refuse it with -ENETDOWN (ice, a down interface);
the mechanism must wake it again once the link is up, without changing
custody: the netdev notifier only flags the provider and kicks the session
worker, which wakes the queue.  CREATE must refuse a transmit-only queue whose
driver refuses the wakeup for a configuration reason.  The production submit, kernel-source peek, completion,
cancellation and wakeup bodies run verbatim (extracted by the pool_dma
adapter); only the device is simulated.  Call-site checks cover bind, the
reliable transport and the xsk netdev notifier.  Each mutation reverts one
part of the fix and must be detected.
"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('XDEV_EXT_CANONICAL_ROOT') or HERE.parents[2])
POOL = HERE.parent / 'pool_dma'
_spec = importlib.util.spec_from_file_location('xsk_wakeup_pool_adapter', POOL / 'adapter.py')
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)

MECH = 'src/network/net/xdp/xsk_xdev_ext_mech.c'
REL = 'src/network/net/xdp/xsk_xdev_ext_mech_reliable.inc'
XSK = 'src/network/net/xdp/xsk.c'
HDR = 'src/network/net/xdp/xsk_xdev_ext_mech.h'
WAKE_CALL = 'xs->dev->netdev_ops->ndo_xsk_wakeup(xs->dev, xs->queue_id, XDP_WAKEUP_TX)'


def build_and_run(root, work, mutate=None):
    """Compile the fixture against production bodies; (exit, output)."""
    have, _ = adapter.generate(root, work)
    mech = (root / MECH).read_text()
    rel = (root / REL).read_text()
    (work / 'wakeup_extra.c.inc').write_text(
        adapter.function(mech, 'xsk_xdev_ext_mech_link_up') + '\n\n' +
        adapter.function(mech, 'xsk_mech_zc_rewake') + '\n\n' +
        adapter.function(rel, 'xsk_rel_wakeup') + '\n')
    shutil.copy2(POOL / 'os_boundary.h', work / 'os_boundary.h')
    shutil.copy2(HERE / 'zc_wakeup_fixture.c', work / 'zc_wakeup_fixture.c')
    if mutate:
        changed = False
        for name in ('production_journal.h', 'production.c.inc', 'wakeup_extra.c.inc'):
            path = work / name
            before = path.read_text()
            after = mutate(name, before)
            changed |= after != before
            path.write_text(after)
        if not changed:
            raise AssertionError('mutation anchor missing')
    cmd = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O0', '-g', '-funsigned-char',
           '-fno-strict-aliasing', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
           '-Wno-unused-parameter', '-Wno-sign-compare', f'-DHAVE_POOL={int(have)}',
           '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
           'zc_wakeup_fixture.c', '-o', 'zc_wakeup_fixture']
    built = subprocess.run(cmd, cwd=work, capture_output=True, text=True)
    if built.returncode:
        return built.returncode, 'COMPILE FAILED\n' + built.stdout + built.stderr
    ran = subprocess.run([str(work / 'zc_wakeup_fixture')], cwd=work, capture_output=True,
                         text=True, timeout=60)
    return ran.returncode, ran.stdout + ran.stderr


def bind_problems(mech):
    body = adapter.function(mech, 'xsk_xdev_ext_mech_bind')
    probe = re.search(r'if \(!err && tx && xs->zc &&\s*!\(u->flags & XDEV_EXT_AFXDP_F_RELIABLE\)\)\s*'
                      r'err = xsk_mech_zc_wake\(xs\);', body)
    if not probe:
        return ['CREATE does not probe the transmit-only zero-copy TX queue']
    order = [('mutex_lock(&xs->mutex)', 'before'), ('xsk_xdev_ext_mech_stage_check(', 'before'),
             ('xsk_rel_bind(st, u)', 'after'), ('smp_store_release(&xs->xdev_ext_mech_tx', 'after'),
             ('mutex_unlock(&xs->mutex)', 'after')]
    problems = []
    for anchor, where in order:
        at = body.find(anchor)
        if at < 0:
            problems.append('bind anchor missing: ' + anchor)
        elif (at < probe.start()) != (where == 'before'):
            problems.append(f'CREATE probe must come {"after" if where == "before" else "before"} {anchor}')
    return problems


def wakeup_site_problems(mech, rel):
    problems = []
    helper = adapter.function(mech, 'xsk_mech_zc_wake')
    if 'xsk_mech_zc_wake_deferred(err, netif_running(dev), netif_carrier_ok(dev))' not in helper:
        problems.append('wakeup helper does not apply the link rule')
    rest = mech.replace(helper, '') + rel
    if 'ndo_xsk_wakeup' in re.sub(r'/\*.*?\*/', '', rest, flags=re.S):
        problems.append('a TX wakeup bypasses xsk_mech_zc_wake()')
    if 'xsk_mech_zc_wake(xs)' not in adapter.function(mech, 'xsk_xdev_ext_mech_zc_submit'):
        problems.append('zero-copy submit does not use xsk_mech_zc_wake()')
    if 'xsk_mech_zc_wake(xst->xs)' not in adapter.function(rel, 'xsk_rel_wakeup'):
        problems.append('reliable wakeup does not use xsk_mech_zc_wake()')
    return problems


def notifier_problems(xsk, header, mech):
    problems = []
    body = adapter.function(xsk, 'xsk_notifier')
    case = re.search(r'case NETDEV_UP:\s*case NETDEV_CHANGE:(.*?)(?=\n\tcase |\n\t}\n)', body, re.S)
    if not case:
        return ['xsk_notifier ignores NETDEV_UP/NETDEV_CHANGE']
    section = case.group(1)
    if not re.search(r'^\s*if \(!netif_running\(dev\) \|\| !netif_carrier_ok\(dev\)\)\s*break;', section, re.M):
        problems.append('link-up hook not limited to a running device with carrier')
    # The netdev instance lock may be held here: no mutex, no driver call.
    if re.search(r'mutex_lock|ndo_xsk_wakeup|xsk_mech_zc_wake', section):
        problems.append('link-up notifier takes a mutex or wakes the driver itself')
    lock, walk, hook, unlock = (section.find('rcu_read_lock()'),
                                section.find('sk_for_each_rcu(sk, &net->xdp.list)'),
                                section.find('xsk_xdev_ext_mech_link_up(xs)'),
                                section.find('rcu_read_unlock()'))
    if not (0 <= lock < walk < hook < unlock):
        problems.append('socket list not walked under RCU around the link-up hook')
    hook_body = adapter.function(mech, 'xsk_xdev_ext_mech_link_up')
    if re.search(r'mutex_lock|ndo_xsk_wakeup|xsk_mech_zc_wake\(', hook_body):
        problems.append('link-up hook wakes the driver in notifier context')
    if 'xdev_ext_mech_stage_kick(st)' not in hook_body or 'xdev_ext_mech_rx' not in hook_body:
        problems.append('link-up hook does not kick the worker for a TX or reliable RX stage')
    progress = adapter.function(mech, 'xsk_mech_progress')
    if not re.match(r'[^{]*\{\s*(?:[^;{}]*;\s*)*?xsk_mech_zc_rewake\(st\);', progress):
        problems.append('session worker progress does not run the link-up wakeup first')
    if not re.search(r'#ifdef CONFIG_XDEV_EXT_MECH.*?void xsk_xdev_ext_mech_link_up\(struct xdp_sock \*xs\);'
                     r'.*?#else.*?static inline void xsk_xdev_ext_mech_link_up\(struct xdp_sock \*xs\)',
                     header, re.S):
        problems.append('link-up hook lacks a declaration and !CONFIG_XDEV_EXT_MECH stub')
    return problems


# name -> (file, old, new, designated failure in the fixture output)
MUTATIONS = {
    'worker_never_wakes': ('wakeup_extra.c.inc', 'err = xsk_mech_zc_wake(xs);', 'err = 0;',
                           'ASSERT igb_carrier_down: link_up_wakes_once'),
    'link_up_never_flags': ('wakeup_extra.c.inc', 'p->rewake = true;', '(void)0;',
                            'ASSERT igb_carrier_down: link_up_wakes_once'),
    'link_up_ignores_rx_stage': ('wakeup_extra.c.inc', 'st = smp_load_acquire(&xs->xdev_ext_mech_rx);', 'st = NULL;',
                                 'ASSERT receiver_controls: receiver_link_up_kicks_worker'),
    'worker_ignores_stopping_session': ('wakeup_extra.c.inc', ' &&\n\t    xdev_ext_mech_session_admits(st->s))', ')',
                                        'ASSERT link_up_stopping: stopping_session_no_wakeup'),
    'enetdown_always_fatal': ('production_journal.h',
                              'return err == -ENETDOWN && (!running || !carrier);', 'return false;',
                              'ASSERT ice_carrier_down: link_down_refusal_is_not_fatal'),
    'deferral_ignores_link': ('production_journal.h',
                              'return err == -ENETDOWN && (!running || !carrier);',
                              'return err == -ENETDOWN;',
                              'ASSERT mlx5_xdp_inactive: enetdown_with_link_up_is_fatal'),
    'submit_bypasses_link_rule': ('production.c.inc', '\terr = xsk_mech_zc_wake(xs);\n\tif (err) {\n\t\tspin_lock_irqsave',
                                  '\terr = ' + WAKE_CALL + ';\n\tif (err) {\n\t\tspin_lock_irqsave',
                                  'ASSERT ice_carrier_down: link_down_refusal_is_not_fatal'),
    'reliable_bypasses_link_rule': ('wakeup_extra.c.inc', 'xsk_mech_zc_wake(xst->xs)',
                                    'xst->xs->dev->netdev_ops->ndo_xsk_wakeup(xst->xs->dev,xst->xs->queue_id,XDP_WAKEUP_TX)',
                                    'ASSERT reliable_ice_carrier_down: reliable_link_down_not_fatal'),
    'link_up_ignores_stopped': ('wakeup_extra.c.inc', 'waiting = !p->stopped && ', 'waiting = ',
                                'ASSERT link_up_stopped: stopped_source_no_wakeup'),
    'worker_ignores_refusal': ('wakeup_extra.c.inc', '\tif (err) {\n\t\txsk_mech_zc_cancel_pending(p, err);\n\t\txdev_ext_mech_stage_dead(st, err);\n\t}',
                               '\t(void)err;',
                               'ASSERT link_up_xdp_removed: link_up_refusal_stops_stage'),
    'worker_refusal_skips_cancel': ('wakeup_extra.c.inc', '\t\txsk_mech_zc_cancel_pending(p, err);\n\t\txdev_ext_mech_stage_dead(st, err);',
                                    '\t\txdev_ext_mech_stage_dead(st, err);',
                                    'ASSERT link_up_xdp_removed: link_up_refusal_cancels_untaken'),
}


class Behaviour(unittest.TestCase):
    def test_production_bodies_against_simulated_drivers(self):
        with tempfile.TemporaryDirectory(prefix='xsk-wakeup-') as tmp:
            code, out = build_and_run(ROOT, Path(tmp))
        self.assertEqual(code, 0, out)
        self.assertIn('RESULT assertions_failed=0', out)


class Mutations(unittest.TestCase):
    def test_each_reverted_part_is_detected(self):
        for name, (target, old, new, designated) in MUTATIONS.items():
            with self.subTest(mutation=name):
                def mutate(file, text, target=target, old=old, new=new):
                    return text.replace(old, new, 1) if file == target else text
                with tempfile.TemporaryDirectory(prefix='xsk-wakeup-mut-') as tmp:
                    code, out = build_and_run(ROOT, Path(tmp), mutate)
                self.assertNotEqual(code, 0, name + ' survived')
                self.assertIn(designated, out, name + ' failed for another reason:\n' + out)


class CallSites(unittest.TestCase):
    def setUp(self):
        self.mech = (ROOT / MECH).read_text()
        self.rel = (ROOT / REL).read_text()
        self.xsk = (ROOT / XSK).read_text()
        self.hdr = (ROOT / HDR).read_text()

    def test_create_probes_zero_copy_tx_queue_before_publication(self):
        self.assertEqual(bind_problems(self.mech), [])

    def test_every_mechanism_tx_wakeup_applies_the_link_rule(self):
        self.assertEqual(wakeup_site_problems(self.mech, self.rel), [])

    def test_netdev_notifier_repeats_waiting_tx_wakeups(self):
        self.assertEqual(notifier_problems(self.xsk, self.hdr, self.mech), [])

    def test_call_site_mutations_are_detected(self):
        probe = re.search(r'\tif \(!err && tx && xs->zc &&[^\n]*\n[^\n]*\n\t\terr = xsk_mech_zc_wake\(xs\);\n',
                          self.mech)
        self.assertIsNotNone(probe)
        reliable_too = self.mech.replace(probe.group(0),
                                         '\tif (!err && tx && xs->zc)\n\t\terr = xsk_mech_zc_wake(xs);\n', 1)
        self.assertNotEqual(bind_problems(reliable_too), [])
        self.assertNotEqual(bind_problems(self.mech.replace(probe.group(0), '', 1)), [])
        moved = self.mech.replace(probe.group(0), '', 1).replace(
            'bind_unlock:\n', 'bind_unlock:\n' + probe.group(0), 1)
        self.assertNotEqual(bind_problems(moved), [])
        bypass = self.rel.replace('xsk_mech_zc_wake(xst->xs)',
                                  'xst->xs->dev->netdev_ops->ndo_xsk_wakeup(xst->xs->dev,'
                                  'xst->xs->queue_id,XDP_WAKEUP_TX)', 1)
        self.assertNotEqual(wakeup_site_problems(self.mech, bypass), [])
        unwired = self.xsk.replace('xsk_xdev_ext_mech_link_up(xs);', ';', 1)
        self.assertNotEqual(notifier_problems(unwired, self.hdr, self.mech), [])
        locked = self.xsk.replace('\t\t\txsk_xdev_ext_mech_link_up(xs);',
                                  '\t\t\tmutex_lock(&xs->mutex);\n\t\t\txsk_xdev_ext_mech_link_up(xs);\n'
                                  '\t\t\tmutex_unlock(&xs->mutex);', 1)
        self.assertNotEqual(locked, self.xsk)
        self.assertNotEqual(notifier_problems(locked, self.hdr, self.mech), [])
        no_rewake = self.mech.replace('\txsk_mech_zc_rewake(st);\n', '', 1)
        self.assertNotEqual(no_rewake, self.mech)
        self.assertNotEqual(notifier_problems(self.xsk, self.hdr, no_rewake), [])


CTL = 'src/cli/xdev_ext_mech_ctl.c'


def source_view():
    view = os.environ.get('XDEV_EXT_SOURCE_VIEW')
    if view and (Path(view) / 'kernel/tools/xdev_ext_xsk_redirect.c').is_file():
        return Path(view)
    sys.path.insert(0, str(ROOT / 'tools'))
    from layout import materialize_view
    return Path(materialize_view(ROOT).root)


def cli_order_problems(ctl):
    """A transmit-only zero-copy socket gets XDP mode before CREATE only when its
    driver refuses a TX kick; a reliable sender fills the ring before its redirect."""
    body = adapter.function(ctl, 'ctl_run_source')
    create = body.find('ret = ctl_create(')
    guard = body.find('if (!iou_umem && x.zero_copy && !o->reliable) {')
    probe = body.find('ctl_zc_tx_xdp(&redirect, src, &x)')
    fill = body.find('ret = ctl_fq_fill(&x);')
    redirect = body.find('ctl_reliable_redirect(&redirect, src, o, x.fd)')
    problems = []
    if min(create, guard, probe, fill, redirect) < 0:
        return ['ctl_run_source lacks the zero-copy TX XDP order']
    if not guard < probe < create:
        problems.append('transmit-only XDP mode not settled before CREATE')
    if not create < fill < redirect:
        # igb configures its receive ring when XDP is attached and a TX wakeup
        # kicks only the TX vector: the fill ring must be full by then.
        problems.append('reliable redirect attached before the fill ring is supplied')
    if 'x.zero_copy && !o->reliable ? 0 : ctl_fq_fill' in body:
        problems.append('zero-copy transmit-only socket leaves its fill ring empty')
    kick = adapter.function(ctl, 'ctl_zc_tx_xdp')
    if not re.search(r'sendto\(x->fd, NULL, 0, MSG_DONTWAIT, NULL, 0\)', kick):
        problems.append('transmit-only probe is not the AF_XDP TX kick')
    if not re.search(r'errno != EINVAL && errno != ENXIO && errno != ENETDOWN', kick) or \
            'xdev_ext_xsk_redirect_attach_pass(' not in kick:
        problems.append('pass program not attached exactly for refused kicks')
    return problems


class CliZeroCopyTx(unittest.TestCase):
    def test_redirect_helper_pass_program_contracts(self):
        view = source_view()
        test_dir = view / 'kernel/tools/testing/selftests/xsk_xdev_ext'
        with tempfile.TemporaryDirectory(prefix='xsk-redirect-') as tmp:
            exe = Path(tmp) / 'xdev_ext_xsk_redirect_test'
            built = subprocess.run(
                [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                 '-I../../..', 'xdev_ext_xsk_redirect_test.c', '../../../xdev_ext_xsk_redirect.c',
                 '-o', str(exe), '-lbpf'], cwd=test_dir, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            ran = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertRegex(ran.stdout, r'xdev_ext_xsk_redirect: \d+ checks, 0 failures')

    def test_zero_copy_tx_attaches_xdp_before_create(self):
        self.assertEqual(cli_order_problems((ROOT / CTL).read_text()), [])

    def test_cli_order_mutations_are_detected(self):
        ctl = (ROOT / CTL).read_text()
        guard = 'if (!iou_umem && x.zero_copy && !o->reliable) {'
        self.assertIn(guard, ctl)
        self.assertNotEqual(cli_order_problems(ctl.replace(guard, 'if (0) {', 1)), [])
        old_fill = ctl.replace('ret = ctl_fq_fill(&x);',
                               'ret = x.zero_copy && !o->reliable ? 0 : ctl_fq_fill(&x);', 1)
        self.assertNotEqual(cli_order_problems(old_fill), [])
        always = ctl.replace('errno != EINVAL && errno != ENXIO && errno != ENETDOWN', 'false', 1)
        self.assertNotEqual(always, ctl)
        self.assertNotEqual(cli_order_problems(always), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
