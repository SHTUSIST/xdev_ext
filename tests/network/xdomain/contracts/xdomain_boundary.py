# SPDX-License-Identifier: GPL-2.0
"""Host production filter/resolver execution; not kernel verifier acceptance.

Project class/member/private-filter and helper-resolver bodies stay real.
BTF id membership and base-helper lookup are kernel-environment boundaries.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
from xdomain_fixture import KERNEL, PRIVATE, local, definition, closure

ENV = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <linux/bpf.h>
#include "include/uapi/linux/xdev_ext_mech.h"
typedef __u8 u8; typedef __u32 u32; typedef __u64 u64; typedef __s32 s32;
#define __bpf_kfunc
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define KF_TRUSTED_ARGS 1
struct bpf_func_proto { unsigned marker; };
struct bpf_verifier_log { unsigned unused; };
struct bpf_reg_state { unsigned unused; };
struct bpf_insn_access_aux { unsigned unused; };
struct bpf_struct_ops { unsigned marker; };
struct bpf_prog_aux { const struct bpf_struct_ops *st_ops; u32 attach_st_ops_member_off; };
struct bpf_prog { struct bpf_prog_aux *aux; };
struct btf_id_set { u32 cnt; u32 ids[16]; };
struct btf_id_set8 { u32 cnt; struct {u32 id, flags;} pairs[16]; };
static bool btf_id_set_contains(const struct btf_id_set *s, u32 id)
{ for(u32 i=0;i<s->cnt;i++) if(s->ids[i]==id) return true; return false; }
static bool btf_id_set8_contains(const struct btf_id_set8 *s, u32 id)
{ for(u32 i=0;i<s->cnt;i++) if(s->pairs[i].id==id) return true; return false; }
static const struct bpf_func_proto proto = {77};
static unsigned base_calls;
static const struct bpf_func_proto *bpf_base_func_proto(enum bpf_func_id id,
                                                       const struct bpf_prog *prog)
{ (void)id; (void)prog; base_calls++; return &proto; }
/* Syntax-only entry declarations; runtime uses actual extracted functions. */
int private_filter(const struct bpf_prog *, u32);
const struct bpf_func_proto *private_helper(enum bpf_func_id, const struct bpf_prog *);
'''

CASES = r'''
int main(void)
{
 struct bpf_prog_aux aux = {};
 struct bpf_prog prog = { .aux=&aux };
 const struct bpf_struct_ops *types[] = {
  &bpf_xdev_ext_afxdp_mech_ops, &bpf_xdev_ext_nvme_mech_ops,
  &bpf_xdev_ext_iaa_mech_ops, &bpf_xdev_ext_ce_mech_ops,
  &bpf_xdev_ext_dma_mech_ops, &bpf_xdev_ext_socket_mech_ops,
  &bpf_xdev_ext_net_mech_ops, &bpf_xdev_ext_cpu_mech_ops,
  &bpf_xdev_ext_user_mech_ops, &bpf_xdev_ext_xdomain_mech_ops,
 };
 const u32 members[] = {
  offsetof(struct xdev_ext_nvme_mech_ops,prepare),
  offsetof(struct xdev_ext_nvme_mech_ops,build),
  offsetof(struct xdev_ext_nvme_mech_ops,complete),
  offsetof(struct xdev_ext_nvme_mech_ops,compute), 0xffffffffU,
 };
 for (u32 t=0;t<ARRAY_SIZE(types);t++)
  for(u32 m=0;m<ARRAY_SIZE(members);m++) {
   aux.st_ops=types[t];aux.attach_st_ops_member_off=members[m];
   for(u32 id=1001;id<=1002;id++)
    assert(private_filter(&prog,id)==(t==9 && m==2 ? 0 : -EACCES));
  }
 puts("ok - private filter admits exact XDOMAIN complete, excludes every other class/member");
 for(u32 id=0;id<__BPF_FUNC_MAX_ID;id++) {
  unsigned before=base_calls;
  const struct bpf_func_proto *got=private_helper((enum bpf_func_id)id,&prog);
  assert(got==(id==BPF_FUNC_map_lookup_elem ? &proto : NULL));
  assert(base_calls-before==(id==BPF_FUNC_map_lookup_elem ? 1U : 0U));
 }
 assert(private_helper((enum bpf_func_id)~0U,&prog)==NULL);
 puts("ok - XDOMAIN resolver grants only map lookup, with no base resolver fallback");
 return 0;
}
'''


def abi_layout():
    header = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    macro = re.search(r"^#define XDEV_EXT_MECH_OPS_TYPE\(name\).*?^}", header, re.M | re.S)
    if not macro:
        raise AssertionError("missing struct_ops layout")
    return macro.group() + "\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);\n"


def object_shims():
    # These are distinct stand-ins for BTF type identities, never a fabricated
    # class/member acceptance algorithm; st_ops_of's actual mapping is executed.
    return "\n".join("static const struct bpf_struct_ops bpf_xdev_ext_" + cls +
        "_mech_ops = {" + str(i + 1) + "};" for i, cls in enumerate(
        ("afxdp", "nvme", "iaa", "ce", "dma", "socket", "net", "cpu", "user", "xdomain")))


def runtime_boundary():
    ops = (KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text()
    private = PRIVATE.read_text()
    ids = {"bpf_xdev_ext_xdomain_info": 1001, "bpf_xdev_ext_xdomain_verdict": 1002,
           "bpf_xdev_ext_xdomain_info_v2": 1003, "bpf_xdev_ext_xdomain_verdict_v2": 1004}
    sets = []
    observed = set()
    for kind, name, body in re.findall(
            r"BTF_(KFUNCS|SET)_START\((\w+)\)(.*?)BTF_(?:KFUNCS|SET)_END\(\s*\2\s*\)",
            private, re.S):
        entries = re.findall(r"BTF_ID(?:_FLAGS)?\(\s*func\s*,\s*(\w+)(?:\s*,\s*([^)]*))?\)", body)
        if not entries:
            continue
        if any(name not in ids for name, _ in entries):
            raise AssertionError("unexpected private kfunc in XDOMAIN registration")
        if kind == "KFUNCS":
            for func, flags in entries:
                if "KF_TRUSTED_ARGS" not in flags:
                    raise AssertionError("private kfunc lacks KF_TRUSTED_ARGS: " + func)
                observed.add(func)
            values = ",".join("{" + str(ids[f]) + ",KF_TRUSTED_ARGS}" for f, _ in entries)
            sets.append(f"static const struct btf_id_set8 {name} = {{.cnt={len(entries)},.pairs={{{values}}}}};")
        else:
            values = ",".join(str(ids[f]) for f, _ in entries)
            sets.append(f"static const struct btf_id_set {name} = {{.cnt={len(entries)},.ids={{{values}}}}};")
    if observed != set(ids):
        raise AssertionError("missing private BTF trusted registration artifact")
    filters = re.findall(r"\.filter\s*=\s*(\w+)", private)
    if len(set(filters)) != 1:
        raise AssertionError("expected one private registered filter; inspect new registration shape")
    # Follow the actual XDOMAIN registration. Other classes may also install
    # private helper resolvers; uniqueness among non-base tables is no ABI.
    registration = re.search(
        r'static\s+struct\s+bpf_struct_ops\s+bpf_xdev_ext_xdomain_mech_ops\s*='
        r'\s*\{([^}]+)\}', ops, re.S)
    if not registration:
        raise AssertionError("missing actual XDOMAIN struct_ops registration")
    selected = re.search(r'\.verifier_ops\s*=\s*&(\w+)', registration.group(1))
    if not selected:
        raise AssertionError("XDOMAIN registration has no verifier table")
    tables = re.findall(r"static\s+const\s+struct\s+bpf_verifier_ops\s+(\w+)\s*=\s*\{([^}]+)\}", ops, re.S)
    tables = [(name, body) for name, body in tables
              if name == selected.group(1)]
    if len(tables) != 1:
        raise AssertionError("missing selected XDOMAIN verifier table")
    table_name, table = tables[0]
    for required in ("xdev_ext_ops_is_valid_access", "xdev_ext_mech_btf_struct_access"):
        if required not in table:
            raise AssertionError("XDOMAIN verifier table lost existing access denial: " + required)
    helper = re.search(r"\.get_func_proto\s*=\s*(\w+)", table).group(1)
    # Linkage selection needs the actual registration after activation. This
    # rejects a dead unused verifier table; X7 proves compiled type selection.
    without_table = ops.replace("static const struct bpf_verifier_ops " + table_name, "", 1)
    if len(re.findall(r"\b" + re.escape(table_name) + r"\b", without_table)) < 1:
        raise AssertionError("XDOMAIN verifier table exists but is never selected")
    core_h = (KERNEL / "io_uring/xdev_ext_ops_core.h").read_text()
    core_c = (KERNEL / "io_uring/xdev_ext_ops_core.c").read_text()
    rules = "\n".join(definition(core_h, n, True) for n in
                      ("xdev_ext_ops_kfunc_member", "xdev_ext_ops_kfunc_rule"))
    functions = "\n".join((definition(ops, "xdev_ext_mech_st_ops_of"),
        definition(core_c, "xdev_ext_ops_kfunc_filter"),
        definition(ops, "xdev_ext_mech_class_kfunc_filter"),
        closure(private, (filters[0],)), closure(ops, (helper,))))
    # Wrapper aliases refer to actual extracted functions, with no substitute
    # result or filtering logic. Only their identifiers are implementation-private.
    functions += "\n#define private_filter " + filters[0] + "\n#define private_helper " + helper + "\n"
    return rules + "\n" + "\n".join(sets) + "\n" + functions


def build_boundary(syntax=False):
    source = ENV + abi_layout() + object_shims()
    if syntax:
        source += CASES
    else:
        if not PRIVATE.exists():
            raise AssertionError("missing implementation artifact: private kfunc unit; no filter verdict")
        source += runtime_boundary() + CASES
    with tempfile.TemporaryDirectory(prefix="xdomain-boundary-") as directory:
        src = Path(directory) / "boundary.c"
        src.write_text(source)
        compiler = shlex.split(os.environ.get("CC", "gcc"))
        if not compiler or "clang" in Path(compiler[0]).name:
            raise AssertionError("X1 host boundary fixture requires GCC")
        command = compiler + ["-std=gnu11", "-Wall", "-Wextra", "-Werror",
                              "-Wno-unused-function", "-Wno-unused-parameter",
                              "-I" + str(KERNEL), str(src)]
        if syntax:
            command += ["-fsyntax-only"]
        else:
            command += ["-o", str(Path(directory) / "probe")]
        run = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if run.returncode:
            raise AssertionError("boundary fixture compile error (not behavior RED):\n" + run.stdout + run.stderr)
        if syntax:
            print("DECLARATION_SYNTAX_ONLY: filter/helper declarations; no bodies or runtime verdict")
        else:
            run = subprocess.run([str(Path(directory) / "probe")], capture_output=True, text=True, timeout=15)
            if run.returncode:
                raise AssertionError("boundary behavior failure:\n" + run.stdout + run.stderr)
            print(run.stdout, end="")
