#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Pure host tests of the real SGL profile parser; no tracefs or devices.

The four original independent cases are retained, with extra owned-miss and
near-prefix cases.  Only read_all() is replaced, returning fixed profile text.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def actual_function(source, name):
    match = re.search(r'^static\s+int\s+' + name + r'\s*\(', source, re.M)
    if not match:
        raise AssertionError('missing actual ' + name)
    start = source.index('{', match.start())
    depth, end = 1, start + 1
    # Count structural braces only: strings, character literals and comments
    # may contain braces and must not terminate the actual-function extraction.
    token = re.compile(r'"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|/\*.*?\*/|//[^\n]*|[{}]', re.S)
    for part in token.finditer(source, end):
        if part.group() == '{':
            depth += 1
        elif part.group() == '}':
            depth -= 1
            if not depth:
                return source[match.start():part.end()]
    raise AssertionError('unterminated actual ' + name)


PRE = r'''#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
struct tracer {char root[512];};
static const char *events;
static char *read_all(const char *path,size_t *len) {(void)path;(void)len;return strdup(events);}
'''
POST = r'''
static int failed;
static void run(const char *name,const char *input,unsigned long long want_hits,unsigned long long want_missed) {
 struct tracer t={};unsigned long long hits,missed;events=input;
 int ret=profile_copy_hits(&t,&hits,&missed);
 if(ret||hits!=want_hits||missed!=want_missed) {failed++;fprintf(stderr,"not ok - %s: ret=%d hits=%llu/%llu missed=%llu/%llu\n",name,ret,hits,want_hits,missed,want_missed);} else printf("ok - %s\n",name);
}
int main(void) {
 puts("TAP version 13\n1..7");
 run("positive direct-copy event","xdev_ext_sgl_copy0 2 1\n",2,1);
 run("allocation/free/retry are not copies","xdev_ext_sgl_kmalloc 2 0\nxdev_ext_sgl_freepages 2 0\nxdev_ext_sgl_mapret 1 0\n",0,0);
 run("foreign xdev event is ignored","xdev_ext_foreign 9 3\n",0,0);
 run("mixed native profile counts only copy hits","xdev_ext_sgl_kmalloc 3 0\nxdev_ext_sgl_copy0 3 0\nxdev_ext_sgl_freepages 3 0\n",3,0);
 run("owned non-copy misses still count","xdev_ext_sgl_kmalloc 8 2\nxdev_ext_sgl_freepages 8 3\nxdev_ext_sgl_mapret 1 4\n",0,9);
 run("copy and namespace lookalikes are ignored","xdev_ext_sgl_copycat 7 2\nxdev_ext_sgl_copy 7 2\nxdev_ext_sgl_copy0tail 7 2\nxdev_ext_sgl_x 7 2\nxdev_ext_sglx_copy0 7 2\nxdev_ext_sgl_kmalloc_extra 7 2\n",0,0);
 run("multiple indexed copy probes plus malformed log","xdev_ext_sgl_copy1 4 2\nxdev_ext_sgl_copy12 5 3\nnot-a-profile-row\n",9,5);
 return !!failed;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path,
                        default=Path(__file__).with_name('nvme_sgl_gap_runtime.c'))
    args = parser.parse_args()
    body = actual_function(args.source.read_text(), 'profile_copy_hits')
    with tempfile.TemporaryDirectory(prefix='nvme-sgl-profile-') as tmp:
        source, binary = Path(tmp) / 'actual-profile.c', Path(tmp) / 'profile'
        source.write_text(PRE + body + POST)
        subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
            '-fno-sanitize-recover=undefined', str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == '__main__':
    main()
