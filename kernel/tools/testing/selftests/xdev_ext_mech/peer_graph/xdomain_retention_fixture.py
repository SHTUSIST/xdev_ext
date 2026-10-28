# SPDX-License-Identifier: GPL-2.0
"""Environmental extraction only: retention decisions always come from real core."""
from xdomain_ring_test import no_includes, declaration

def retention_unit(kernel):
    return (no_includes((kernel/'include/linux/xdev_ext_requester_retention.h').read_text())+
            no_includes((kernel/'io_uring/family/xdev_ext_requester_retention.c').read_text()))

def descriptor_unit(kernel):
    # The overlay omits unchanged upstream headers. Explicitly use the prepared
    # locked-upstream source, never a hand-written descriptor byte formula.
    from xdomain_fixture import definition
    regs=kernel/'drivers/thunderbolt/nhi_regs.h'
    return ('#undef RING_DESC_CRC_ERROR\n#undef RING_DESC_BUFFER_OVERRUN\n#define __packed __attribute__((packed))\n'+
            declaration((kernel/'include/linux/thunderbolt.h').read_text(),'enum ring_desc_flags')+
            declaration(regs.read_text(),'struct ring_desc')+
            definition((kernel/'drivers/thunderbolt/nhi.c').read_text(),'tb_ring_descriptor_bytes')+'\n')
