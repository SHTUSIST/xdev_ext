#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute binding's selected production helper resolver (host evidence only).

BUG.1: binding may delegate only map_lookup_elem and loop. Map lookup supports
policy maps; loop preserves the existing binding_success concurrent-release
fixture. The reference policy uses direct BSS map values, with no helper call.
The upstream resolver is the sole controlled capability boundary here; this
test does not certify a kernel verifier decision.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(os.environ['XDEV_EXT_CANONICAL_ROOT']) if os.environ.get('XDEV_EXT_CANONICAL_ROOT') else next(
    p for p in Path(__file__).resolve().parents if (p / 'source-layout.json').is_file())
sys.path.insert(0, str(ROOT / 'tests/network/xdomain/contracts'))
from xdomain_fixture import closure, scrub


def selected_resolver(source):
    clean = scrub(source)
    registration = re.search(r'static struct bpf_struct_ops bpf_xdev_ext_binding_ops\s*=\s*\{([^}]+)\}', clean, re.S)
    if not registration:
        raise AssertionError('binding registration missing')
    selected = re.search(r'\.verifier_ops\s*=\s*&(\w+)', registration.group(1))
    if not selected:
        raise AssertionError('binding verifier selection missing')
    table = re.search(r'static\s+const\s+struct\s+bpf_verifier_ops\s+' + re.escape(selected.group(1)) + r'\s*=\s*\{[^}]+\};', clean, re.S)
    if not table:
        raise AssertionError('selected binding verifier table missing')
    actual = source[table.start():table.end()]
    resolver = re.search(r'\.get_func_proto\s*=\s*(\w+)', actual)
    if not resolver:
        raise AssertionError('binding helper resolver missing')
    name = resolver.group(1)
    # Direct upstream selection is valid baseline code, not a missing-symbol RED.
    functions = closure(source, (name,)) if name != 'bpf_base_func_proto' else ''
    return functions + '\n' + actual, selected.group(1), name


ENV = r'''
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
/* Freeze the required ABI IDs from pinned Linux include/uapi/linux/bpf.h.
 * Old host UAPI headers predate loop; all other kernel types are boundaries too.
 */
enum bpf_func_id { BPF_FUNC_map_lookup_elem = 1, BPF_FUNC_loop = 181 };
struct bpf_prog { unsigned marker; };
struct bpf_func_proto { unsigned marker; };
struct bpf_verifier_ops {
 const struct bpf_func_proto *(*get_func_proto)(enum bpf_func_id, const struct bpf_prog *);
 int (*is_valid_access)(void);
 int (*btf_struct_access)(void);
};
static int xdev_ext_ops_is_valid_access(void) { return 1; }
static int xdev_ext_binding_ops_btf_struct_access(void) { return 0; }
static const struct bpf_func_proto upstream_proto = {77};
static unsigned calls, upstream_available;
static enum bpf_func_id delegated_id;
static const struct bpf_prog *delegated_prog;
static const struct bpf_func_proto *bpf_base_func_proto(enum bpf_func_id id,
                                                       const struct bpf_prog *p)
{ calls++; delegated_id=id; delegated_prog=p; return upstream_available ? &upstream_proto : NULL; }
'''

CASES = r'''
int main(void)
{
 struct bpf_prog programs[] = {{17}, {29}};
 const int sentinels[] = {-1, INT_MIN, INT_MAX, 180, 182, 4096};
 unsigned tested=0, violations=0;
 for (unsigned available=0;available<2;available++)
  for (unsigned p=0;p<2;p++)
   for (unsigned i=0;i<4096+sizeof(sentinels)/sizeof(sentinels[0]);i++) {
    int id = i < 4096 ? (int)i : sentinels[i-4096];
    unsigned allowed = id == 1 || id == 181;
    upstream_available=available; calls=0; delegated_prog=NULL;
    const struct bpf_func_proto *got = BINDING_TABLE.get_func_proto(
        (enum bpf_func_id)id, &programs[p]);
    unsigned bad = got != (allowed && available ? &upstream_proto : NULL) ||
                   calls != allowed ||
                   (allowed && (delegated_id != (enum bpf_func_id)id ||
                                delegated_prog != &programs[p]));
    if (bad && violations < 12)
     printf("forbidden/incorrect delegation helper_id=%d allowed=%u upstream_calls=%u returned_proto=%u\n",
            id, allowed, calls, got != NULL);
    violations += bad; tested++;
   }
 printf("binding_resolver_execution cases=%u violations=%u scan_ids=0..4095\n",
        tested, violations);
 return violations ? 1 : 0;
}
'''


class BindingHelperWhitelist(unittest.TestCase):
    def test_only_policy_map_lookup_and_existing_concurrency_loop_delegate(self):
        source = (ROOT / 'src/core/io_uring/xdev_ext_binding.c').read_text()
        production, table, helper = selected_resolver(source)
        fixture = ENV + production + CASES.replace('BINDING_TABLE', table)
        compiler = shlex.split(os.environ.get('CC', 'gcc'))
        self.assertTrue(compiler and 'clang' not in Path(compiler[0]).name,
                        'host binding resolver contract requires GCC')
        with tempfile.TemporaryDirectory(prefix='binding-helper-contract-') as temp:
            directory = Path(temp)
            path = directory / 'selected-resolver.c'
            path.write_text(fixture)
            binary = directory / 'selected-resolver'
            built = subprocess.run(compiler + ['-std=gnu11', '-Wall', '-Wextra',
                                   '-Werror', str(path), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            if os.environ.get('HELPER_TEST_ARTIFACT_DIR'):
                artifacts = Path(os.environ['HELPER_TEST_ARTIFACT_DIR'])
                artifacts.mkdir(parents=True, exist_ok=True)
                (artifacts / 'selected-resolver.c').write_text(fixture)
                (artifacts / 'compile.log').write_text(built.stdout + built.stderr)
            self.assertEqual(built.returncode, 0,
                             'fixture compilation failure is NOT behavior RED:\n' + built.stderr)
            print('actual_selected_binding_resolver=' + helper, flush=True)
            result = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=10)
        print(result.stdout, end='', flush=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
