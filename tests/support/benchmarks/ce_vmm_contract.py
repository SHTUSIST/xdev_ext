# SPDX-License-Identifier: GPL-2.0
"""Actual C option/helper extraction for CE allocation qualification only.

Never launches a benchmark or calls a real GPU, storage, network or ioctl.
The driver and fd boundaries are fixtures; the option parser, CE selection,
identity checks, attach loop and cleanup are unmodified production function bytes.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile


def braced(text, opening):
    tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(text, opening):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if not depth:
                return token.end()
    raise AssertionError("unbalanced actual C source")


def function(text, name, optional=False):
    match = re.search(r"(?m)^(?:static\s+)?(?:inline\s+)?[\w *]+\b" +
                      re.escape(name) + r"\s*\([^;{}]*\)\s*\{", text)
    if not match:
        if optional:
            return ""
        raise AssertionError("missing actual function " + name)
    return text[match.start():braced(text, text.index("{", match.start()))]


def structure(text, name, kind="struct"):
    match = re.search(r"\b" + kind + r"\s+" + re.escape(name) + r"\s*\{", text)
    if not match:
        raise AssertionError("missing actual " + kind + " " + name)
    end = braced(text, text.index("{", match.start()))
    return text[match.start():text.index(";", end) + 1]


class Compiled:
    def __init__(self, text):
        self.temp = tempfile.TemporaryDirectory(prefix="eval-ce-vmm-")
        path = Path(self.temp.name)
        source = path / "actual.c"
        self.binary = path / "actual"
        source.write_text(text)
        command = shlex.split(os.environ.get("CC", "gcc")) + [
            "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
            str(source), "-o", str(self.binary)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            self.temp.cleanup()
            raise AssertionError("actual-source fixture compile error (not intended RED):\n" + result.stderr)

    def run(self, *args):
        import json
        result = subprocess.run([str(self.binary), *map(str, args)],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise AssertionError("fixture execution failed:\n" + result.stderr)
        return json.loads(result.stdout)

    def close(self):
        self.temp.cleanup()


COMMON = r'''
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/types.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define XDEV_EXT_MECH_MAX_FRAMES 32U
'''


def parser(root, arm):
    root = Path(root)
    here = root / "tests/benchmarks"
    source = (here / arm / ("session_nvme_ce.c" if arm == "nvme_gpu" else "session_gpu_nic.c")).read_text()
    prefix = "sn" if arm == "nvme_gpu" else "sg"
    opts = structure(source, prefix + "_opts")
    prelude = COMMON + '\n#include "' + str(here / "nvme_gpu/nvme_gpu_core.h") + '"\n'
    if arm == "nvme_gpu":
        prelude += "#define SN_IO_ALIGN 4096ULL\n"
    else:
        uapi = (root / "src/core/include/uapi/linux/xdev_ext_mech.h").read_text()
        gpu_core = (here / "gpu_nic/gpu_nic_core.h").read_text()
        ctl = (root / "src/cli/xdev_ext_mech_ctl_core.h").read_text()
        prelude += structure(uapi, "xdev_ext_mech_peer") + "\n"
        for name in ("GN_MAX_SIZE", "GN_MAX_MESSAGES", "GN_MAX_DEPTH"):
            match = re.search(r"(?m)^#define\s+" + name + r"[^\n]*", gpu_core)
            if match is None:
                raise AssertionError("missing parser limit " + name)
            prelude += match.group() + "\n"
        for text, name in ((gpu_core, "gn_parse_ip"), (gpu_core, "gn_parse_port"),
                           (ctl, "xdev_ext_mech_ctl_hex"), (ctl, "xdev_ext_mech_ctl_parse_mac")):
            prelude += function(text, name) + "\n"
        prelude += r'''
static int sg_if_query(const char *name, unsigned long request, struct ifreq *ifr)
{ (void)name; (void)request; (void)ifr; return -ENODEV; }
'''
    # Older source has no ce_vmm member: it must still compile so rejection of
    # the new option is an executable parser failure, not a missing-member error.
    vmm = "o.ce_vmm" if re.search(r"\bce_vmm\b", opts) else "0"
    main = r'''
int main(int argc, char **argv) {
    struct @P@_opts o;
    int rc = @P@_parse(argc, argv, &o);
    printf("{\"rc\":%d,\"alloc\":%d,\"vmm\":%d}\n", rc, o.ce_alloc, @VMM@);
    return 0;
}
'''.replace("@P@", prefix).replace("@VMM@", vmm)
    return Compiled(prelude + opts + "\n" + function(source, prefix + "_usage") +
                    "\n" + function(source, prefix + "_parse") + "\n" + main)


HELPER_BOUNDARIES = r'''
#define XDEV_EXT_GPU_PCI_BDF_SIZE 32
#define XDEV_EXT_GPU_IDENTITY_ANY_MINOR (-1)
enum { XG_EXIT_PASS=0, XG_EXIT_FAIL=1, XG_EXIT_USAGE=2, XG_EXIT_UNAVAILABLE=4 };
static unsigned opened, closed, native_calls, vmm_calls, attached, attach_bad;
static unsigned identities, mismatch, fail_attach, fail_close, close_order=1;
static int fixture_open(const char *path, int flags)
{ (void)path; (void)flags; return 100 + (int)opened++; }
static int fixture_close(int fd)
{ if (fd >= 100 && fd < 102) closed++; return 0; }
int xdev_ext_gpu_identity_from_opened(int fd, const char *dev, int minor, char *bdf)
{
    (void)dev; (void)minor; identities++;
    strcpy(bdf, mismatch && fd == 101 ? "0000:02:00.0" : "0000:01:00.0");
    return 0;
}
int xdev_ext_mech_cuda_open(struct xdev_ext_mech_cuda *cuda, const char *bdf, uint64_t len)
{
    (void)bdf; native_calls++; cuda->lib=(void *)1;
    cuda->va=0x100000; cuda->vmm_bytes=len; return 0;
}
int xdev_ext_mech_cuda_open_vmm(struct xdev_ext_mech_cuda *cuda, const char *bdf, uint64_t len)
{
    (void)bdf; vmm_calls++; cuda->lib=(void *)1; cuda->va=0x200000;
    cuda->vmm=1; cuda->exported=1; cuda->export_fd=55;
    cuda->vmm_bytes=(len+65535)/65536*65536; return 0;
}
int xdev_ext_mech_cuda_close(struct xdev_ext_mech_cuda *cuda)
{
    if (!cuda->lib) return 0;
    if (opened != closed) close_order=0;
    if (fail_close) { fail_close--; return -EIO; }
    memset(cuda,0,sizeof(*cuda)); return 0;
}
int xdev_ext_nv_ce_attach_memory(int fd, struct xdev_ext_nv_ce_attach_memory *a)
{
    attached++;
    if (fd != 99+(int)attached || a->mem_fd != 55 || a->gpu_va != 0x200000 ||
        a->size != 65536 || a->flags || a->reserved) attach_bad++;
    if (fail_attach == attached) { a->status=0x51; errno=EIO; return -1; }
    a->status=0; return 0;
}
static void fixture_copy(void) {}
static void *fixture_dlsym(void *lib, const char *name)
{ (void)lib; (void)name; return (void *)fixture_copy; }
#define open fixture_open
#define close fixture_close
#define dlsym fixture_dlsym
'''


def helper(root):
    root = Path(root)
    source = (root / "tests/benchmarks/nvme_gpu/eval_session.h").read_text()
    cuda = (root / "src/cli/xdev_ext_mech_cuda.h").read_text()
    ioctl = (root / "src/cli/include/xdev_ext_nv_p2p_ioctl.h").read_text()
    prelude = COMMON
    for name in ("xdev_ext_mech_cuda_mem_prop", "xdev_ext_mech_cuda_access", "xdev_ext_mech_cuda"):
        prelude += structure(cuda, name) + "\n"
    prelude += structure(ioctl, "xdev_ext_nv_ce_attach_memory") + "\n"
    prelude += r'''
typedef int (*es_cu_copy_htod)(uint64_t, const void *, size_t);
typedef int (*es_cu_copy_dtoh)(void *, uint64_t, size_t);
'''
    prelude += structure(source, "es_ce") + "\n"
    if re.search(r"enum\s+es_ce_allocation_mode\s*\{", source):
        prelude += structure(source, "es_ce_allocation_mode", "enum") + "\n"
    prelude += HELPER_BOUNDARIES
    actual = "\n".join(function(source, name, optional=name == "es_ce_attach")
                       for name in ("es_ce_is_sim", "es_ce_attach", "es_ce_open", "es_ce_close"))
    main = r'''
int main(int argc, char **argv) {
    if (argc != 7) return 2;
    unsigned mode=strtoul(argv[1],NULL,0), stages=strtoul(argv[2],NULL,0);
    fail_attach=strtoul(argv[3],NULL,0); mismatch=strtoul(argv[4],NULL,0);
    fail_close=strtoul(argv[5],NULL,0);
    const char *dev=atoi(argv[6]) ? "/dev/xdev_ext_ce_sim" : "/dev/nvidia0";
    struct es_ce ce;
    int rc=es_ce_open(&ce,dev,stages,mode,4096,8192);
    uint64_t va=ce.va, len=ce.len;
    int close_rc=es_ce_close(&ce);
    int owned=ce.cuda.lib != NULL;
    int retry_rc=es_ce_close(&ce);
    printf("{\"rc\":%d,\"native\":%u,\"vmm\":%u,\"attach\":%u,"
           "\"attach_bad\":%u,\"identity\":%u,\"opened\":%u,\"closed\":%u,"
           "\"close_rc\":%d,\"retry_rc\":%d,\"owned_after_fail\":%d,"
           "\"close_order\":%u,\"va\":%llu,\"len\":%llu,\"remaining\":%d}\n",
           rc,native_calls,vmm_calls,attached,attach_bad,identities,opened,closed,
           close_rc,retry_rc,owned,close_order,(unsigned long long)va,
           (unsigned long long)len,ce.cuda.lib != NULL);
    return 0;
}
'''
    return Compiled(prelude + actual + main)
