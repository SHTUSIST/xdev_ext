#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Executes the production NET bind failure path; proves the endpoint is unbound
before the stage's private pointer is cleared, so a dead callback in between
cannot dereference NULL."""
import net_async_stage_test as fixture

BIND_SHIM = r'''
static int allocation_count, unbind_calls, rx_checks;
static void *priv_at_unbind, *priv_at_bind;
static struct xdev_ext_mech_stage *binding_stage;
static void *test_calloc(size_t n,size_t size)
{void *p=calloc(n,size);if(p)allocation_count++;return p;}
static void test_free(void *p)
{if(p){assert(allocation_count>0);allocation_count--;}free(p);}
#undef kzalloc
#undef kvcalloc
#undef kvfree
#undef kfree
#define kzalloc(n,g) test_calloc(1,n)
#define kvcalloc(n,s,g) test_calloc(n,s)
#define kvfree(p) test_free(p)
#define kfree(p) test_free(p)
static int reject_rx_check(u32 mtu,u32 hdr,u32 span,u32 flags)
{assert(mtu==1500&&hdr==42&&span==1000&&!flags);rx_checks++;return -EINVAL;}
#define xdev_ext_peer_net_rx_check(m,h,s,f) reject_rx_check(m,h,s,f)
'''

MAIN = r'''
int main(void)
{
 struct xdev_ext_mech_session session={.pool={3,4096,16},.l={4096,0,1000,1000},.depth=4,.admits=true};
 struct xdev_ext_mech_stage stage={.s=&session,.file=&allocation,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};
 struct xdev_ext_mech_stage_uapi u={.arg0=4,.arg1=2|(42ULL<<32)};
 binding_stage=&stage;
 assert(xdev_ext_net_bind(&stage,&u)==-EINVAL);
 assert(rx_checks==1&&unbind_calls==1&&priv_at_unbind!=NULL&&priv_at_unbind==priv_at_bind);
 assert(stage.priv==NULL&&!allocation_count&&!live&&!quarantined&&!posts);
 puts("ok 1 - NET failed RX bind unbinds while priv is valid, then clears priv and frees every allocation");
 return 0;
}
'''

def main():
    fixture.require_family()
    original = "void xdev_ext_peer_net_unbind(struct xdev_ext_peer_net_endpoint *e){assert(e==&endpoint);}"
    replacement = ("void xdev_ext_peer_net_unbind(struct xdev_ext_peer_net_endpoint *e){"
                   "assert(e==&endpoint&&binding_stage&&binding_stage->priv==priv_at_bind);"
                   "priv_at_unbind=binding_stage->priv;unbind_calls++;}")
    assert fixture.SHIM.count(original) == 1
    # Declare the observer before the original boundary stub; allocators only
    # wrap production allocations, not Python or test infrastructure.
    declarations = ("static int allocation_count, unbind_calls, rx_checks;\n"
                    "static void *priv_at_unbind, *priv_at_bind;\n"
                    "static struct xdev_ext_mech_stage *binding_stage;\n")
    insertion = "struct xdev_ext_peer_net_endpoint {bool rx;};"
    bind_stub = ("struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_dir(u32 i,u32 q,bool rx,"
                 "void(*dead)(void*),void *arg){assert(i==4&&q==2&&dead&&arg);endpoint.rx=rx;return &endpoint;}")
    observe_bind = ("struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_dir(u32 i,u32 q,bool rx,"
                    "void(*dead)(void*),void *arg){assert(i==4&&q==2&&dead&&arg==binding_stage&&binding_stage->priv);"
                    "priv_at_bind=binding_stage->priv;endpoint.rx=rx;return &endpoint;}")
    assert fixture.SHIM.count(bind_stub) == 1
    fixture.SHIM = (fixture.SHIM.replace(insertion, declarations + insertion)
                    .replace(original, replacement).replace(bind_stub, observe_bind))
    fixture.FAMILY_SHIM += BIND_SHIM[BIND_SHIM.index("static void *test_calloc"):]
    fixture.compile_and_run(fixture.family_runtime() + fixture.net_completion_body(), MAIN, "net-bind-order-")

if __name__ == "__main__":
    main()
