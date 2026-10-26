# SPDX-License-Identifier: GPL-2.0
"""X1 fixture infrastructure. No implementation/identity replacement bodies.

KERNEL_SRC may select another checkout. --syntax-only compiles declarations
with no link/run and never supplies a behavior verdict.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = Path(os.environ.get("KERNEL_SRC", HERE.parents[4])).resolve()
PRIVATE = KERNEL / "io_uring/xdev_ext_mech_xdomain_kfunc.c"


def local(name):
    plain = HERE / name
    return plain if plain.exists() else HERE / (name + ".draft")


def scrub(text):
    # Keep offsets/newlines; braces and call spellings in comments/strings
    # cannot change the extracted production function boundaries.
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: re.sub(r"[^\n]", " ", m.group()), text, flags=re.S)


def definition(text, name, structure=False):
    clean = scrub(text)
    prefix = (r"^struct\s+" + re.escape(name) + r"\s*\{" if structure else
              r"^[A-Za-z_][^;{}=()]*?\b" + re.escape(name) + r"\s*\([^;{}()]*\)\s*\{")
    found = re.search(prefix, clean, re.M)
    if not found:
        raise AssertionError("missing production artifact: " + name)
    end, depth = found.end(), 1
    while depth and end < len(clean):
        depth += (clean[end] == "{") - (clean[end] == "}")
        end += 1
    if depth:
        raise AssertionError("unterminated production artifact: " + name)
    return text[found.start():end] + (";" if structure else "")


def closure(text, roots):
    """Include real local callees; a newly factored validator is never omitted."""
    clean = scrub(text)
    # Registration macros have parenthesized arguments but no C body. A
    # declaration prefix/argument list cannot swallow adjacent macro calls.
    names = re.findall(r"^[A-Za-z_][^;{}=()]*?\b([A-Za-z_]\w*)\s*\([^;{}()]*\)\s*\{",
                       clean, re.M)
    bodies = {name: definition(text, name) for name in names}
    wanted = set(roots)
    for name in wanted:
        if name not in bodies:
            raise AssertionError("missing production artifact: " + name)
    while True:
        more = set()
        for name in wanted:
            more.update(n for n in re.findall(r"\b(\w+)\s*\(", scrub(bodies[name]))
                        if n in bodies)
        if more <= wanted:
            break
        wanted |= more
    selected = [n for n in names if n in wanted]
    # Preserve source order; declaration prefixes permit any helper placement.
    prototypes = [bodies[n].split("{", 1)[0].rstrip() + ";" for n in selected]
    return "\n".join(prototypes + [bodies[n] for n in selected])


def declarations(syntax):
    header = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    internal = (KERNEL / "io_uring/xdev_ext_mech_internal.h").read_text()
    macro = re.search(r"^#define XDEV_EXT_MECH_OPS_TYPE\(name\).*?^}", header, re.M | re.S)
    if not macro:
        raise AssertionError("missing real struct_ops layout")
    parts = [macro.group(), "XDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);"]
    if syntax and "struct xdev_ext_xdomain_proto_result {" not in header:
        parts.append("struct xdev_ext_xdomain_proto_result { struct xdev_ext_xdomain_proto_verdict verdict; __u32 calls; };")
    else:
        parts.append(definition(header, "xdev_ext_xdomain_proto_result", True))
    for name in ("xdev_ext_mech_frame", "xdev_ext_mech_call", "xdev_ext_mech_call_args"):
        body = definition(header, name, True)
        if syntax and name != "xdev_ext_mech_frame" and not re.search(r"\*xdomain\b", body):
            body = body[:-2] + "struct xdev_ext_xdomain_proto_result *xdomain;\n};"
        parts.append(body)
    parts.append(definition(internal, "xdev_ext_mech_target", True))
    magic = re.search(r"^#define XDEV_EXT_MECH_CALL_MAGIC\b.*$", header, re.M)
    if not magic:
        raise AssertionError("missing real call seal")
    parts.append(magic.group())
    accessor = re.search(r"^u64\s+xdev_ext_mech_session_id\s*\([^;{}]*\)\s*;", header, re.M)
    if not accessor:
        raise AssertionError("missing real session-id accessor declaration")
    parts.append(accessor.group())
    parts.append("typedef __s32 (*xdev_ext_mech_cb_t)(const struct xdev_ext_mech_ctx *ctx);")
    # Device/session environment for the real call wrapper and target checker.
    # No identity, filter or protocol success function is supplied here.
    parts.append(r'''
struct xdev_ext_mech_batch { u64 id, key, bytes; };
struct xdev_ext_mech_session {
 u64 id; struct xdev_ext_mech_layout layout; u32 frames;
 const void *ops[XDEV_EXT_MECH_CLASS_MAX + 1];
};
struct xdev_ext_mech_stage {
 struct xdev_ext_mech_session *s; u32 class_id, index, direction; void *priv;
};
int bpf_xdev_ext_xdomain_info(const struct xdev_ext_mech_ctx *, void *, u32);
int bpf_xdev_ext_xdomain_verdict(const struct xdev_ext_mech_ctx *, const void *, u32);
struct xdev_ext_mech_call *xdev_ext_mech_call_of(const struct xdev_ext_mech_ctx *);
int xdev_ext_mech_invoke(const void *, const struct xdev_ext_mech_target *,
 const struct xdev_ext_mech_call_args *, s32 *, struct xdev_ext_mech_hold_intent *);
int xdev_ext_mech_call(struct xdev_ext_mech_stage *, const struct xdev_ext_mech_call_args *,
 s32 *, struct xdev_ext_mech_hold_intent *);
u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *, size_t);
u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *, u32, size_t);
u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *, u32, size_t);
u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *, u32, u32, size_t);
''')
    return "\n\n".join(parts)


def production():
    header = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    missing = []
    if not PRIVATE.exists():
        missing.append("io_uring/xdev_ext_mech_xdomain_kfunc.c")
    if not re.search(r"struct\s+xdev_ext_xdomain_proto_result\s*\{", header):
        missing.append("struct xdev_ext_xdomain_proto_result")
    for name in ("xdev_ext_mech_call", "xdev_ext_mech_call_args"):
        if not re.search(r"\*\s*xdomain\b", definition(header, name, True)):
            missing.append(name + ".xdomain")
    if missing:
        raise AssertionError("missing implementation artifacts: " + "; ".join(missing) +
                             "; expected X1 implementation-boundary RED, no behavior verdict")
    ops = (KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text()
    private = PRIVATE.read_text()
    active = re.search(r"^(?:static\s+)?DEFINE_PER_CPU\([^;]*\bxdev_ext_mech_active_call\s*\);", ops, re.M)
    if not active:
        raise AssertionError("missing production active-call publication")
    core = (KERNEL / "io_uring/xdev_ext_mech.c").read_text()
    parts = [definition(core, "xdev_ext_mech_session_id"), active.group(),
             definition(ops, "xdev_ext_mech_prepare_call", True)]
    parts.extend(re.findall(r"^(?:static\s+)?DEFINE_(?:HASHTABLE|(?:RAW_)?SPINLOCK)\([^;]*\);", ops, re.M))
    parts.append(closure(ops, ("xdev_ext_mech_prepare_current", "xdev_ext_mech_call_of",
        "xdev_ext_mech_invoke", "bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_cqe",
        "bpf_xdev_ext_frame")))
    parts.append(closure(private, ("bpf_xdev_ext_xdomain_info", "bpf_xdev_ext_xdomain_verdict")))
    parts.append(definition(core, "xdev_ext_mech_call"))
    return "\n\n".join(parts)


def source(syntax=False):
    env = local("xdomain_fixture.c.in").read_text()
    if syntax:
        env = env.replace('/* DECLARATIONS */', '#include "' + str(local("xdomain_declarations.h")) + '"')
    bodies = "" if syntax else production()
    return (env.replace("/* PRODUCTION */", declarations(syntax) + bodies)
            .replace("/* CASES */", local("xdomain_cases.c.in").read_text()))


def build_and_run(names, syntax=False):
    compiler = shlex.split(os.environ.get("CC", "gcc"))
    if not compiler or "clang" in Path(compiler[0]).name:
        raise AssertionError("X1 host fixtures require GCC")
    with tempfile.TemporaryDirectory(prefix="xdomain-x1-") as directory:
        src = Path(directory) / "fixture.c"
        src.write_text(source(syntax))
        cmd = compiler + ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                          "-Wno-unused-function", "-Wno-unused-parameter", "-pthread",
                          "-I" + str(KERNEL), str(src)]
        if syntax:
            run = subprocess.run(cmd + ["-fsyntax-only"], capture_output=True, text=True, timeout=30)
            if run.returncode:
                raise AssertionError("declaration-only syntax failed:\n" + run.stdout + run.stderr)
            print("DECLARATION_SYNTAX_ONLY: no production bodies, no runtime RED/GREEN verdict")
            return
        binary = Path(directory) / "probe"
        built = subprocess.run(cmd + ["-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                                      "-o", str(binary)], capture_output=True, text=True, timeout=30)
        if built.returncode:
            raise AssertionError("production-slice compile error (not behavior RED):\n" + built.stdout + built.stderr)
        for name in names:
            run = subprocess.run([str(binary), name], capture_output=True, text=True, timeout=15)
            if run.returncode:
                raise AssertionError(name + ":\n" + run.stdout + run.stderr)
            print(run.stdout, end="")
