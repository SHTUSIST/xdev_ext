#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Classification rules of tools/analysis/chain_composition.py (T-COMP).

Each fixture is a few lines of kernel-style C.  A test fails when an item
written for a device pair is reported as per-class or shared, when a
registration entry or per-class dispatch is reported as a pair, or when the
output is not byte-identical across runs.

The last test runs the real tree when pinned upstream Git caches are given
(XDEV_EXT_UPSTREAM_LINUX / XDEV_EXT_UPSTREAM_NVIDIA, or build/upstream/*.git);
without them it is skipped and says so.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/analysis'))
import chain_composition as cc  # noqa: E402

CORE = 'src/core/io_uring/xdev_ext_mech.c'
NVME = 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c'
PCI = 'src/storage/drivers/nvme/host/pci.c'
BPF = 'examples/pipelines/pair.bpf.c'

COMPONENTS = {
    'core': dict(role='core', own=[], files=['src/core/**']),
    'class:NVME': dict(role='class', own=['nvme'], cls='NVME', files=[NVME]),
    'driver:nvme': dict(role='driver', own=['nvme'], files=[PCI]),
}


def chain(**kw):
    c = dict(id='T', title='fixture', sessions=[], classes=['NVME'],
             components=['core', 'class:NVME', 'driver:nvme'], bpf=[], evidence=[],
             absent=[], missing=[])
    c.update(kw)
    return c


def run(files, upstream=None, chains=None):
    up = {p: None for p in files}
    up.update(upstream or {})
    tree = cc.Tree(files, up, 'f' * 40)
    return cc.analyze(tree, COMPONENTS, chains or [chain()])


def item(result, name, kind=None):
    hits = [i for i in result['chains'][0]['items'] if i['name'] == name
            and (kind is None or i['kind'] == kind)]
    assert len(hits) == 1, (name, [i['name'] for i in result['chains'][0]['items']])
    return hits[0]


def sites(result, token):
    return [s for s in result['core_decisions']['sites'] if s['token'] == token]


CLASS_OK = '''
static int nvme_mech_bind(struct nvme_ctrl *ctrl)
{
	return nvme_mech_helper(ctrl);
}

static int nvme_mech_helper(struct nvme_ctrl *ctrl)
{
	/* a comment naming xdomain and nvidia must not count */
	pr_info("xdomain nvidia");
	return 0;
}

static const struct xdev_ext_mech_class_ops nvme_class = {
	.class_id = XDEV_EXT_MECH_CLASS_NVME,
	.bind = nvme_mech_bind,
};
'''

# The hooked function itself calls into another device's code.
CLASS_PAIR = CLASS_OK.replace('return nvme_mech_helper(ctrl);',
                              'return nvme_mech_helper(ctrl) + xdev_ext_xdomain_ring_kick(ctrl);')


class ItemScope(unittest.TestCase):
    def test_class_code_naming_only_its_device_is_per_class(self):
        r = run({NVME: CLASS_OK})
        self.assertEqual(item(r, 'nvme_mech_helper')['scope'], 'per-class')
        self.assertEqual(item(r, 'nvme_class.bind = nvme_mech_bind', 'hook')['scope'], 'per-class')
        self.assertEqual(r['chains'][0]['totals']['per_pair_trusted'], 0)

    def test_class_code_naming_another_device_is_per_pair(self):
        r = run({NVME: CLASS_PAIR})
        bind = item(r, 'nvme_mech_bind')
        self.assertEqual(bind['scope'], 'per-pair')
        self.assertEqual(bind['trust'], 'kernel')
        self.assertIn('xdomain', bind['names'])
        # Each item is judged by its own text: the callee stays per-class.
        self.assertEqual(item(r, 'nvme_mech_helper')['scope'], 'per-class')
        # The hook into a per-pair function inherits the verdict.
        self.assertEqual(item(r, 'nvme_class.bind = nvme_mech_bind', 'hook')['scope'], 'per-pair')
        self.assertEqual(r['chains'][0]['totals']['per_pair_trusted'], 2)

    def test_unreached_function_is_not_counted_in_the_chain(self):
        r = run({NVME: CLASS_OK + '\nstatic int nvme_unused(void)\n{\n\treturn 1;\n}\n'})
        names = [i['name'] for i in r['chains'][0]['items']]
        self.assertNotIn('nvme_unused', names)
        self.assertEqual(r['inventory']['class:NVME']['functions'], 3)


CORE_TEXT = '''
#define XDEV_EXT_SAME(t) sizeof(struct xdev_ext_nvme_mech_ops)

static const u32 rows[] = { XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_CLASS_XDOMAIN };

static bool pair_rule(struct st *a, struct st *b)
{
	if (a->class_id == XDEV_EXT_MECH_CLASS_NVME && b->class_id == XDEV_EXT_MECH_CLASS_XDOMAIN)
		return true;
	return false;
}

static bool set_rule(u32 c)
{
	return c == XDEV_EXT_MECH_CLASS_NVME || c == XDEV_EXT_MECH_CLASS_AFXDP;
}

static bool one_rule(struct st *a)
{
	switch (a->class_id) {
	case XDEV_EXT_MECH_CLASS_CE:
		return true;
	}
	return false;
}

static int reg_rule(void *k)
{
	return xdev_ext_mech_reg(XDEV_EXT_MECH_CLASS_USER, k);
}

static int names_two(void)
{
	return sizeof(struct nvme_command) + sizeof(struct xdev_ext_xdomain_desc);
}

static const struct xdev_ext_ops core_ops = {
	.a = pair_rule, .b = set_rule, .c = one_rule, .d = reg_rule, .e = names_two,
};
'''


# A pair condition split over two statements: neither statement compares two
# identities, the function does.
NESTED_PAIR = '''
static bool nested_pair(struct st *a, struct st *b)
{
	if (a->class_id == XDEV_EXT_MECH_CLASS_NVME) {
		if (b->class_id == XDEV_EXT_MECH_CLASS_XDOMAIN)
			return true;
	}
	return false;
}

static bool nested_switch_pair(struct st *a, struct st *b)
{
	switch (a->class_id) {
	case XDEV_EXT_MECH_CLASS_NVME:
		switch (b->class_id) {
		case XDEV_EXT_MECH_CLASS_AFXDP:
			return true;
		}
	}
	return false;
}

static int split_kinds(struct st *a)
{
	int x = sizeof(struct nvme_command);

	return x + sizeof(struct xdev_ext_xdomain_desc);
}

static const struct xdev_ext_ops nested_ops = {
	.a = nested_pair, .b = nested_switch_pair, .c = split_kinds,
};
'''

# A dispatcher: one operand, each arm names one kind; and a per-class set.
DISPATCH = '''
static u32 recipe_mask(u32 backend)
{
	switch (backend) {
	case XDEV_EXT_BINDING_BACKEND_AFXDP:
		return bit(XDEV_EXT_BINDING_RECIPE_AFXDP_COPY) |
		       bit(XDEV_EXT_BINDING_RECIPE_AFXDP_RX);
	case XDEV_EXT_BINDING_BACKEND_NVME:
		return bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_READ);
	default:
		return 0;
	}
}

static bool class_dispatch(struct st *a)
{
	if (a->class_id == XDEV_EXT_MECH_CLASS_NVME)
		return nvme_ok(a);
	return a->class_id == XDEV_EXT_MECH_CLASS_CE;
}

static int emit(void)
{
	BTF_TYPE_EMIT(struct xdev_ext_nvme_mech_ops);
	BTF_TYPE_EMIT(struct xdev_ext_afxdp_mech_ops);
	return 0;
}

static const struct xdev_ext_ops dispatch_ops = { .a = recipe_mask, .b = class_dispatch, .c = emit };
'''


class FunctionPairs(unittest.TestCase):
    def test_pair_condition_over_nested_statements_is_per_pair(self):
        r = run({CORE: NESTED_PAIR})
        for name in ('nested_pair', 'nested_switch_pair', 'split_kinds'):
            self.assertEqual(item(r, name)['scope'], 'per-pair', name)
        self.assertEqual(item(r, 'nested_ops.a = nested_pair', 'hook')['scope'], 'per-pair')
        self.assertEqual(r['chains'][0]['totals']['per_pair_trusted'], 6)
        self.assertEqual({p['name'] for p in r['inventory']['core']['per_pair']},
                         {'nested_pair', 'nested_switch_pair', 'split_kinds'})

    def test_single_operand_dispatch_and_registration_stay_per_class(self):
        r = run({CORE: DISPATCH})
        for name in ('recipe_mask', 'class_dispatch', 'emit'):
            self.assertEqual(item(r, name)['scope'], 'per-class', name)
        self.assertEqual(r['chains'][0]['totals']['per_pair_trusted'], 0)


NETFAM = 'src/network/io_uring/family/xdev_ext_netfam.c'
FAMILY_COMPONENTS = dict(COMPONENTS, **{'family:network': dict(role='family', own=[], files=[
    'src/network/io_uring/family/*.c'])})
FAMILY_TEXT = '''
static bool fam_pair(struct st *a, struct st *b)
{
	return a->class_id == XDEV_EXT_MECH_CLASS_AFXDP && b->class_id == XDEV_EXT_MECH_CLASS_NVME;
}

static const struct xdev_ext_netfam_ops fam_ops = { .pair = fam_pair };
'''


class FamilyCode(unittest.TestCase):
    def test_family_file_sites_are_collected_and_pairs_found(self):
        tree = cc.Tree({NETFAM: FAMILY_TEXT}, {NETFAM: None}, None)
        r = cc.analyze(tree, FAMILY_COMPONENTS,
                       [chain(components=['core', 'class:NVME', 'driver:nvme', 'family:network'])])
        fam = [s for s in r['core_decisions']['sites'] if s['file'] == NETFAM]
        self.assertTrue(fam)
        self.assertEqual({(s['category'], s['rule']) for s in fam if s['identity']}, {('per-pair', 'R-PAIR')})
        self.assertEqual(item(r, 'fam_pair')['scope'], 'per-pair')
        self.assertEqual([p['name'] for p in r['inventory']['family:network']['per_pair']], ['fam_pair'])
        self.assertEqual(r['chains'][0]['totals']['per_pair_trusted'], 2)


class CoreDecisions(unittest.TestCase):
    def setUp(self):
        self.r = run({CORE: CORE_TEXT})

    def verdict(self, token, context):
        hits = [s for s in sites(self.r, token) if s['context'] == context]
        self.assertTrue(hits, (token, context))
        return {(s['category'], s['rule']) for s in hits}

    def test_two_identities_on_two_operands_are_a_pair_condition(self):
        self.assertEqual(self.verdict('XDEV_EXT_MECH_CLASS_XDOMAIN', 'pair_rule'), {('per-pair', 'R-PAIR')})
        self.assertEqual(item(self.r, 'pair_rule')['scope'], 'per-pair')
        # pair_rule and names_two, plus the two table hooks that point at them.
        self.assertEqual(item(self.r, 'core_ops.a = pair_rule', 'hook')['scope'], 'per-pair')
        self.assertEqual(self.r['chains'][0]['totals']['per_pair_trusted'], 4)

    def test_identities_on_one_operand_are_a_class_set(self):
        self.assertEqual(self.verdict('XDEV_EXT_MECH_CLASS_AFXDP', 'set_rule'), {('per-class', 'R-SET')})
        self.assertEqual(item(self.r, 'set_rule')['scope'], 'per-class')

    def test_case_label_is_per_class_dispatch(self):
        self.assertEqual(self.verdict('XDEV_EXT_MECH_CLASS_CE', 'one_rule'), {('per-class', 'R-ONE')})

    def test_registration_call_scope_and_preprocessor(self):
        self.assertEqual(self.verdict('XDEV_EXT_MECH_CLASS_USER', 'reg_rule'), {('registration', 'R-REGCALL')})
        self.assertEqual(self.verdict('XDEV_EXT_MECH_CLASS_XDOMAIN', 'file scope'), {('registration', 'R-SCOPE')})
        self.assertEqual(self.verdict('xdev_ext_nvme_mech_ops', 'preprocessor'), {('registration', 'R-PP')})

    def test_two_kinds_named_without_comparison_are_a_pair(self):
        self.assertEqual(self.verdict('nvme_command', 'names_two'), {('per-pair', 'R-PAIR')})

    def test_summary_counts_identity_sites(self):
        s = self.r['core_decisions']['summary']
        self.assertEqual(s['identity_sites'], 8)
        self.assertEqual(s['identity_by_category'], {'registration': 3, 'per-class': 3, 'per-pair': 2})

    def test_comment_mention_is_not_a_site(self):
        r = run({CORE: '/* XDEV_EXT_MECH_CLASS_NVME */\nint x;\n'})
        self.assertEqual(r['core_decisions']['summary']['identity_sites'], 0)


UP_PCI = '''
static int nvme_setup(struct nvme_dev *d)
{
	return 0;
}

static int nvme_stock(struct nvme_dev *d)
{
	return 1;
}

static const struct nvme_ctrl_ops nvme_pci_ctrl_ops = {
	.name = nvme_name,
	.reg_read32 = nvme_pci_reg_read32,
};
'''
NEW_PCI = UP_PCI.replace('return 0;', 'return nvme_pci_peer_rw(d);').replace(
    '.reg_read32 = nvme_pci_reg_read32,', '.reg_read32 = nvme_pci_reg_read32,\n\t.peer_rw = nvme_pci_peer_rw,'
) + '''
static int nvme_pci_peer_rw(struct nvme_dev *d)
{
	return 2;
}

static int nvme_pci_reg_read32(struct nvme_dev *d)
{
	return 3;
}
'''


class UpstreamOverlay(unittest.TestCase):
    def test_only_new_or_changed_functions_and_entries_count(self):
        up_pci = UP_PCI + '\nstatic int nvme_pci_reg_read32(struct nvme_dev *d)\n{\n\treturn 3;\n}\n'
        r = run({PCI: NEW_PCI, NVME: CLASS_OK}, {PCI: up_pci})
        names = {i['name']: i for i in r['chains'][0]['items']}
        self.assertIn('nvme_pci_ctrl_ops.peer_rw = nvme_pci_peer_rw', names)
        self.assertEqual(names['nvme_pci_peer_rw']['status'], 'added')
        self.assertEqual(names['nvme_setup']['status'], 'changed')
        self.assertNotIn('nvme_stock', names)
        self.assertNotIn('nvme_pci_reg_read32', names)
        self.assertNotIn('nvme_pci_ctrl_ops.reg_read32 = nvme_pci_reg_read32', names)


    def test_stock_caller_is_counted_but_its_other_callees_are_not(self):
        # A changed upstream dispatcher that calls chain code is a hook site;
        # its other arms are not used by the chain.
        up = UP_PCI + '\nstatic long nvme_dispatch(int cmd)\n{\n\treturn 0;\n}\n'
        new = NEW_PCI + (
            '\nstatic long nvme_dispatch(int cmd)\n{\n'
            '\tif (cmd == 1)\n\t\treturn nvme_pci_peer_rw(0);\n'
            '\treturn nvme_other_arm(cmd);\n}\n'
            '\nstatic long nvme_other_arm(int cmd)\n{\n\treturn xdev_ext_xdomain_kick(cmd);\n}\n')
        r = run({PCI: new, NVME: CLASS_OK}, {PCI: up})
        names = {i['name']: i for i in r['chains'][0]['items']}
        self.assertEqual(names['nvme_dispatch']['reach'], 'caller')
        self.assertNotIn('nvme_other_arm', names)
        self.assertEqual(names['nvme_pci_peer_rw']['reach'], 'callee')
        self.assertEqual(names['nvme_pci_ctrl_ops.peer_rw = nvme_pci_peer_rw']['reach'], 'root')

    def test_root_tables_limit_which_tables_start_the_closure(self):
        new = NEW_PCI + (
            '\nstatic const struct other_ops policy_ops = {\n\t.submit = nvme_policy_submit,\n};\n'
            '\nstatic int nvme_policy_submit(int x)\n{\n\treturn x;\n}\n')
        comps = dict(COMPONENTS, **{'driver:nvme': dict(COMPONENTS['driver:nvme'],
                                                          root_tables=['nvme_pci_ctrl_ops'])})
        tree = cc.Tree({PCI: new, NVME: CLASS_OK}, {PCI: UP_PCI, NVME: None}, None)
        r = cc.analyze(tree, comps, [chain()])
        names = {i['name'] for i in r['chains'][0]['items']}
        self.assertIn('nvme_pci_peer_rw', names)
        self.assertNotIn('nvme_policy_submit', names)


    def test_added_function_in_upstream_file_is_not_a_caller(self):
        # Only a *changed* stock function is a site where stock code enters
        # the chain; an added function is product code reached by closure.
        new = NEW_PCI + '\nstatic int nvme_side_entry(void)\n{\n\treturn nvme_pci_peer_rw(0);\n}\n'
        r = run({PCI: new, NVME: CLASS_OK}, {PCI: UP_PCI})
        self.assertNotIn('nvme_side_entry', {i['name'] for i in r['chains'][0]['items']})


UP_DISPATCH = UP_PCI + '''
static long nvme_ioctl(int cmd)
{
	switch (cmd) {
	case NVME_STOCK:
		return 0;
	}
	return -1;
}
'''
NEW_DISPATCH = NEW_PCI + '''
static long nvme_ioctl(int cmd)
{
	switch (cmd) {
	case NVME_STOCK:
		return 0;
	case NVME_PEER:
		return nvme_pci_peer_rw(0);
	case NVME_XSK_PIN:
		return xsk_pin_umem(cmd);
	}
	return -1;
}
'''


class DispatcherArms(unittest.TestCase):
    def test_unexecuted_pair_arm_is_reported_not_counted(self):
        r = run({PCI: NEW_DISPATCH, NVME: CLASS_OK}, {PCI: UP_DISPATCH},
                chains=[chain(commands=['NVME_PEER'])])
        c = r['chains'][0]
        fn = item(r, 'nvme_ioctl')
        self.assertEqual(fn['scope'], 'per-class')
        self.assertEqual([a['label'] for a in fn['arms_executed']], ['NVME_PEER'])
        skipped = {a['label']: a for a in fn['arms_not_executed']}
        self.assertEqual(skipped['NVME_XSK_PIN']['scope'], 'per-pair')
        self.assertEqual(c['totals']['per_pair_trusted'], 0)
        self.assertEqual(c['totals']['per_pair_trusted_not_executed'], 1)

    def test_without_command_evidence_every_added_arm_counts(self):
        r = run({PCI: NEW_DISPATCH, NVME: CLASS_OK}, {PCI: UP_DISPATCH})
        fn = item(r, 'nvme_ioctl')
        self.assertEqual(fn['scope'], 'per-pair')
        self.assertIn('afxdp', fn['names'])
        self.assertEqual(r['chains'][0]['totals']['per_pair_trusted'], 1)


BPF_TEXT = '''
static __always_inline int shared_helper(const struct xdev_ext_mech_ctx *c)
{
	return 0;
}

static __always_inline int nvme_only(const struct xdev_ext_mech_ctx *c)
{
	return 1;
}

SEC("struct_ops/a_build")
__s32 BPF_PROG(a_build, const struct xdev_ext_mech_ctx *c)
{
	return shared_helper(c) + nvme_only(c);
}

SEC("struct_ops/b_build")
__s32 BPF_PROG(b_build, const struct xdev_ext_mech_ctx *c)
{
	return shared_helper(c);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops a_ops = {
	.build = (void *)a_build,
};

SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops b_ops = {
	.build = (void *)b_build,
};
'''


class BpfPrograms(unittest.TestCase):
    def test_helper_shared_by_two_class_programs_is_a_bpf_pair(self):
        r = run({BPF: BPF_TEXT}, chains=[chain(bpf=[(BPF, ['a_ops', 'b_ops'])])])
        shared = item(r, 'shared_helper')
        self.assertEqual((shared['scope'], shared['trust'], shared['kind']), ('per-pair', 'bpf', 'bpf-helper'))
        self.assertEqual(shared['classes'], ['afxdp', 'nvme'])
        self.assertEqual(item(r, 'nvme_only')['scope'], 'per-class')
        self.assertEqual(item(r, 'a_build')['kind'], 'bpf-callback')
        t = r['chains'][0]['totals']
        self.assertEqual((t['per_pair_trusted'], t['per_pair_bpf']), (0, 1))

    def test_only_the_struct_ops_maps_the_chain_attaches_count(self):
        # The chain attaches a_ops only: b_ops and its callback are not used,
        # and the helper is no longer shared by two attached programs.
        r = run({BPF: BPF_TEXT}, chains=[chain(bpf=[(BPF, ['a_ops'])])])
        names = {i['name'] for i in r['chains'][0]['items']}
        self.assertNotIn('b_build', names)
        shared = item(r, 'shared_helper')
        self.assertEqual((shared['scope'], shared['classes']), ('per-class', ['nvme']))
        t = r['chains'][0]['totals']
        self.assertEqual((t['bpf'], t['per_pair_bpf']), (3, 0))
        self.assertEqual(r['chains'][0]['errors'], [])
        self.assertEqual(r['chains'][0]['bpf_programs'], [dict(file=BPF, maps=['a_ops'])])

    def test_bpf_program_without_named_maps_or_with_an_unknown_map_is_an_error(self):
        bare = run({BPF: BPF_TEXT}, chains=[chain(bpf=[BPF])])
        self.assertTrue(any('names no struct_ops map' in e for e in bare['chains'][0]['errors']))
        unknown = run({BPF: BPF_TEXT}, chains=[chain(bpf=[(BPF, ['a_ops', 'c_ops'])])])
        self.assertTrue(any('c_ops' in e for e in unknown['chains'][0]['errors']))


FAMILY = 'src/core/include/linux/xdev_ext_family_core.h'
UAPI = 'src/core/include/uapi/linux/xdev_ext_mech.h'
UAPI_TEXT = '''
enum xdev_ext_mech_class {
	XDEV_EXT_MECH_CLASS_AFXDP = 2,
	XDEV_EXT_MECH_CLASS_NVME = 3,
	XDEV_EXT_MECH_CLASS_MAX = 4,
};
'''


class ClassTable(unittest.TestCase):
    def table(self, nvme_check):
        return '''
static const struct xdev_ext_mech_class_desc xdev_ext_mech_class_decls[4] = {
	{}, {},
	{ /* AFXDP */
		.family = 1,
		.check_stage = xdev_ext_decl_afxdp_check,
	},
	{ /* NVME */
		.family = 2,
		.check_stage = %s,
	},
};
''' % nvme_check

    def test_row_naming_its_own_class_is_per_class(self):
        r = run({FAMILY: self.table('xdev_ext_decl_nvme_check'), UAPI: UAPI_TEXT})
        row = item(r, 'xdev_ext_mech_class_decls[NVME] (2 fields)', 'class-table')
        self.assertEqual(row['scope'], 'per-class')

    def test_row_naming_another_class_is_per_pair(self):
        r = run({FAMILY: self.table('xdev_ext_decl_afxdp_check'), UAPI: UAPI_TEXT})
        row = item(r, 'xdev_ext_mech_class_decls[NVME] (2 fields)', 'class-table')
        self.assertEqual(row['scope'], 'per-pair')
        self.assertIn('afxdp', row['names'])


class CatalogAndOutput(unittest.TestCase):
    def test_catalog_names_the_struct_ops_maps_each_chain_attaches(self):
        bpf = {c['id']: dict((p, list(m)) for p, m in c['bpf']) for c in cc.CHAINS}
        # E4-ce attaches nxp_nvme_ops only (session_nvme_ce.c, guest_correctness.sh);
        # E3-a2 attaches both maps of nnb_bench.bpf.c (nnb_session.c attach()).
        self.assertEqual(bpf['E4-ce']['examples/pipelines/nxp_mech.bpf.c'], ['nxp_nvme_ops'])
        self.assertEqual(sorted(bpf['E3-a2']['tests/benchmarks/nvme_nic/nnb_bench.bpf.c']),
                         ['nnb_afxdp_ops', 'nnb_nvme_ops'])

    def test_evidence_and_absent_paths_are_checked(self):
        files = {NVME: CLASS_OK, 'src/lib/x.c': 'int y = XDEV_EXT_MECH_CLASS_NVME;\n',
                 'tests/benchmarks/kv/run.py': ''}
        good = run(files, chains=[chain(evidence=[('src/lib/x.c', 'XDEV_EXT_MECH_CLASS_NVME')])])
        self.assertEqual(good['chains'][0]['errors'], [])
        self.assertEqual(good['chains'][0]['evidence'][0]['line'], 1)
        bad = run(files, chains=[chain(evidence=[('src/lib/x.c', 'no such text')],
                                       absent=['tests/benchmarks/kv'])])
        self.assertEqual(len(bad['chains'][0]['errors']), 2)

    def test_output_is_byte_identical_across_runs(self):
        files = {NVME: CLASS_PAIR, CORE: CORE_TEXT, BPF: BPF_TEXT}
        a = run(files, chains=[chain(bpf=[(BPF, ['a_ops', 'b_ops'])])])
        b = run(dict(reversed(list(files.items()))), chains=[chain(bpf=[(BPF, ['a_ops', 'b_ops'])])])
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(cc.markdown(a), cc.markdown(b))

    def test_file_in_two_components_is_an_input_error(self):
        comps = dict(COMPONENTS, other=dict(role='class', own=['nvme'], files=[NVME]))
        tree = cc.Tree({NVME: CLASS_OK}, {NVME: None}, None)
        with self.assertRaises(cc.InputError):
            cc.analyze(tree, comps, [chain()])


def _upstream_args():
    args = []
    for comp, env in (('linux', 'XDEV_EXT_UPSTREAM_LINUX'), ('nvidia', 'XDEV_EXT_UPSTREAM_NVIDIA')):
        path = os.environ.get(env) or str(ROOT / 'build/upstream' / (comp + '.git'))
        if not Path(path).is_dir():
            return None
        args += ['--upstream-git', '%s=%s' % (comp, path)]
    return args


class RealTree(unittest.TestCase):
    def test_real_tree_chains_have_evidence_and_classified_sites(self):
        args = _upstream_args()
        if args is None:
            self.skipTest('no pinned upstream Git caches; set XDEV_EXT_UPSTREAM_LINUX/NVIDIA')
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/analysis/chain_composition.py'),
                            '--repo', str(ROOT), *args], capture_output=True, text=True)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual({c['id'] for c in r['chains']}, {'M-TP', 'E4-direct', 'E4-ce', 'E3-a2', 'K-KV'})
        for c in r['chains']:
            self.assertEqual(c['errors'], [], c['id'])
            self.assertTrue(c['evidence'])
        family = tuple(f.split('*')[0] for n, c in cc.COMPONENTS.items() if c['role'] == 'family'
                       for f in c['files'])
        for s in r['core_decisions']['sites']:
            self.assertIn(s['category'], ('registration', 'per-class', 'per-pair'))
            self.assertTrue(s['file'].startswith(('src/core/',) + family) and s['line'] > 0, s['file'])
        self.assertTrue(any(s['file'].startswith(family) for s in r['core_decisions']['sites']))
        # Single-operand dispatchers and registration functions that name
        # several kinds are not pairs.
        core_pairs = {p['name'] for p in r['inventory']['core']['per_pair']}
        for name in ('xdev_ext_binding_backend_recipe_mask', 'xdev_ext_binding_stage_recipe_mask',
                     'xdev_ext_binding_backend_stage_direction_valid', 'xdev_ext_mech_emit_btf_types',
                     'xdev_ext_mech_ops_init', 'io_unified_ops_issue'):
            self.assertNotIn(name, core_pairs)


if __name__ == '__main__':
    unittest.main()
