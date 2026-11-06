#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the actual channelPushMethod LAUNCH_DMA output.

Requirement: a callback on the final CE chunk requests NON_BLOCKING completion;
no callback or a nonfinal chunk emits no completion notification. Pipeline mode
must not change that requirement. Removing the final interrupt assignment must
fail the two positive cases; an unconditional assignment must fail negatives.

This is a host command-encoding test; it does not run a GPU or prove DMA.

Usage: python3 tests/compute/nvidia/nv_xdev_ext_ce_launch_test.py --source /path/channel_utils.c \
         --sdk-include /path/to/nvidia/src/common/sdk/nvidia/inc
The include directory must supply nvtypes.h, nvmisc.h and class/clb0b5.h,
class/clc5b5.h. Extra --include directories support split SDK layouts.
"""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def extract_function(source):
    # Match the definition rather than the forward declaration. Body bytes are
    # taken unchanged from the requested source; comments and strings do not
    # participate in brace counting.
    match = re.search(
        r"(?m)^static\s+void\s+channelPushMethod\s*\([^;{}]*\)\s*\{", source
    )
    if match is None:
        raise ValueError("actual channelPushMethod definition missing")
    opening = source.index("{", match.start())
    tokens = re.compile(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',
        re.S,
    )
    depth = 0
    for token in tokens.finditer(source, opening):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():token.end()]
    raise ValueError("unbalanced channelPushMethod definition")


PRELUDE = r'''
#include <stdio.h>
#include <stdlib.h>
#include "nvtypes.h"
#include "nvmisc.h"
#include "class/clb0b5.h"
#include "class/clc5b5.h"

/* Only channel fields consumed by the extracted function are supplied.
 * Class IDs below select no memset case: all calls are actual memcopy. */
#ifndef MAXWELL_DMA_COPY_A
#define MAXWELL_DMA_COPY_A 0xb0b5
#endif
#ifndef PASCAL_DMA_COPY_A
#define PASCAL_DMA_COPY_A 0xc0b5
#endif
#ifndef PASCAL_DMA_COPY_B
#define PASCAL_DMA_COPY_B 0xc1b5
#endif
#ifndef VOLTA_DMA_COPY_A
#define VOLTA_DMA_COPY_A 0xc3b5
#endif
typedef struct { NvU32 hTdCopyClass; } OBJCHANNEL;
typedef struct {
    NvBool bCeMemcopy;
    void (*pCompletionCallback)(void *);
} CHANNEL_PB_INFO;
#define RM_SUBCHANNEL 0
/* Preserve both method address and actual value emitted by production code. */
#define NV_PUSH_INC_1U(subch, method, value) do { \
    *pPtr++ = (NvU32)(method); \
    *pPtr++ = (NvU32)(value); \
} while (0)
'''

MAIN = r'''
static void callback(void *unused) { (void)unused; }
int main(void)
{
    unsigned failures = 0;
    for (unsigned cb = 0; cb < 2; cb++) {
        for (unsigned final = 0; final < 2; final++) {
            for (unsigned pipeline = 0; pipeline < 2; pipeline++) {
                NvU32 words[4] = { 0 }, *end = words;
                OBJCHANNEL channel = { .hTdCopyClass = 0 };
                CHANNEL_PB_INFO info = {
                    .bCeMemcopy = 1,
                    .pCompletionCallback = cb ? callback : NULL,
                };
                channelPushMethod(&channel, &info, pipeline, final,
                                  0, 0, 0, &end);
                if (end != words + 2 || words[0] != NVB0B5_LAUNCH_DMA) {
                    fprintf(stderr, "FAIL: actual launch output missing\n");
                    return 2;
                }
                /* Expected literals are SDK protocol constants. No source
                 * expressions or implementation helpers compute the result. */
                NvU32 want = cb && final ?
                    NVB0B5_LAUNCH_DMA_INTERRUPT_TYPE_NON_BLOCKING :
                    NVB0B5_LAUNCH_DMA_INTERRUPT_TYPE_NONE;
                NvU32 got = DRF_VAL(B0B5, _LAUNCH_DMA, _INTERRUPT_TYPE,
                                   words[1]);
                printf("%s callback=%u final=%u pipeline=%u launch=0x%x "
                       "interrupt=%u expected=%u\n",
                       got == want ? "PASS" : "FAIL", cb, final, pipeline,
                       words[1], got, want);
                failures += got != want;
            }
        }
    }
    printf("cases=8 failures=%u\n", failures);
    return failures ? 1 : 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--sdk-include", required=True, type=Path)
    parser.add_argument("--include", action="append", type=Path, default=[])
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    source = args.source.read_text()
    actual = extract_function(source)
    with tempfile.TemporaryDirectory(prefix="xdev-ce-launch-") as temp:
        build = Path(temp)
        c_file = build / "actual_channel_launch.c"
        binary = build / "actual_channel_launch"
        c_file.write_text(PRELUDE + "\n" + actual + "\n" + MAIN)
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror"]
        for directory in [args.sdk_include, *args.include]:
            command.extend(["-I", str(directory)])
        command.extend([str(c_file), "-o", str(binary)])
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary)], check=False)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
