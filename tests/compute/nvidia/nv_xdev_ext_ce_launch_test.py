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


def extract_function(source, name="channelPushMethod"):
    # Match the definition rather than the forward declaration. Body bytes are
    # taken unchanged from the requested source; comments and strings do not
    # participate in brace counting.
    match = re.search(
        r"(?m)^static\s+(?:void|NvU32)\s+" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", source
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



PROPERTIES_PRELUDE = r"""
#include <stdio.h>
#include <stdint.h>
#include "class/clb0b5.h"
typedef int NV_ADDRESS_SPACE;
#define DRF_SHIFT(drf) ((0 ? drf) % 32)
#define DRF_DEF(d,r,f,c) ((NV##d##r##f##c) << DRF_SHIFT(NV##d##r##f))
#define ADDR_SYSMEM 1
#define ADDR_FBMEM 2
#define ADDR_VIRTUAL 3
#define NV_MEMORY_CACHED 1
#define RM_SUBCHANNEL 0
#define NV_PUSH_INC_1U(s,m,v) do { *pPtr++=(m); *pPtr++=(v); } while(0)
#define NV_PUSH_INC_2U(s,m1,v1,m2,v2) do { NV_PUSH_INC_1U(s,m1,v1); NV_PUSH_INC_1U(s,m2,v2); } while(0)
typedef struct { NvBool bUseVasForCeCopy; NvU64 fbAliasVA,startFbOffset; } OBJCHANNEL;
typedef struct { NvBool bCeMemcopy; NvU64 srcAddr,dstAddr; NvU32 pattern,srcCpuCacheAttrib,dstCpuCacheAttrib; NV_ADDRESS_SPACE srcAddressSpace,dstAddressSpace; } CHANNEL_PB_INFO;
"""
PROPERTIES_MAIN = r"""
int main(void) {
 unsigned failures=0,checks=0;
 for(unsigned reverse=0;reverse<2;reverse++)for(unsigned virtual_host=0;virtual_host<2;virtual_host++)for(unsigned fb_alias=0;fb_alias<2;fb_alias++) {
  NvU32 words[32]={0},*end=words;
  NvU64 host=0x8000001234ULL,fb=0x204000;
  OBJCHANNEL c={fb_alias,0x40000000,0x200000};
  CHANNEL_PB_INFO p={.bCeMemcopy=1,.srcCpuCacheAttrib=NV_MEMORY_CACHED,.dstCpuCacheAttrib=NV_MEMORY_CACHED,
   .srcAddr=reverse?fb:host,.dstAddr=reverse?host:fb,
   .srcAddressSpace=reverse?ADDR_FBMEM:virtual_host?ADDR_VIRTUAL:ADDR_SYSMEM,
   .dstAddressSpace=reverse?(virtual_host?ADDR_VIRTUAL:ADDR_SYSMEM):ADDR_FBMEM};
  NvU32 launch=channelPushMemoryProperties(&c,&p,&end);
  NvU32 want_src=(reverse?fb_alias:virtual_host)?0:1;
  NvU32 want_dst=(reverse?virtual_host:fb_alias)?0:1;
  checks++;if(((launch>>12)&1)!=want_src || ((launch>>13)&1)!=want_dst) {failures++;fprintf(stderr,"FAIL virtual-host=%u reverse=%u alias=%u launch=%x\n",virtual_host,reverse,fb_alias,launch);}
  NvU64 src=0,dst=0;
  for(NvU32 *w=words;w<end;w+=2) {
   if(w[0]==NVB0B5_OFFSET_IN_UPPER)src|=(NvU64)w[1]<<32;
   if(w[0]==NVB0B5_OFFSET_IN_LOWER)src|=w[1];
   if(w[0]==NVB0B5_OFFSET_OUT_UPPER)dst|=(NvU64)w[1]<<32;
   if(w[0]==NVB0B5_OFFSET_OUT_LOWER)dst|=w[1];
  }
  NvU64 want_fb=fb_alias?fb+c.fbAliasVA-c.startFbOffset:fb;
  checks++;if(src!=(reverse?want_fb:host)||dst!=(reverse?host:want_fb)) {failures++;fprintf(stderr,"FAIL address mode changed operand bytes\n");}
 }
 printf("MEMORY_PROPERTIES checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
"""

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--sdk-include", required=True, type=Path)
    parser.add_argument("--include", action="append", type=Path, default=[])
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--properties", action="store_true", help="check both operand addressing modes")
    args = parser.parse_args()
    source = args.source.read_text()
    actual = extract_function(source, "channelPushMemoryProperties" if args.properties else "channelPushMethod")
    with tempfile.TemporaryDirectory(prefix="xdev-ce-launch-") as temp:
        build = Path(temp)
        c_file = build / "actual_channel_launch.c"
        binary = build / "actual_channel_launch"
        pre, main_body = (PROPERTIES_PRELUDE, PROPERTIES_MAIN) if args.properties else (PRELUDE, MAIN)
        c_file.write_text(pre + "\n" + actual + "\n" + main_body)
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror"]
        for directory in [args.sdk_include, *args.include]:
            command.extend(["-I", str(directory)])
        command.extend([str(c_file), "-o", str(binary)])
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary)], check=False)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
