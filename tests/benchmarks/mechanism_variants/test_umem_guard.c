// SPDX-License-Identifier: GPL-2.0
/* Host-memory guard selfcheck only, not an AF_XDP registration claim. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "mv_umem_guard.h"
int main(int argc,char **argv)
{
    struct mv_umem_guard g={0};
    unsigned char *memory=malloc(8192);
    struct xdp_umem_reg reg={.addr=(uintptr_t)memory,.len=8192,.chunk_size=4096};
    struct xdev_ext_mech_layout layout={.frame_size=4096,.hdr_room=88,.seg_len=64,.group_bytes=64};
    assert(argc==3 && memory);
    assert(!mv_guard_begin(&g,&reg,argv[1]));
    g.registration_return=0;
    memset(memory+88,0xab,64); memset(memory+6,0xcd,82);
    if (!strcmp(argv[2],"corrupt")) memory[0]^=1;
    int result=mv_guard_finish(&g,&layout,42,0,0);
    assert((result!=0)==!strcmp(argv[2],"corrupt"));
    free(memory);
    return 0;
}
