/* Requirement-derived direct authority tests; no arbitrary-pointer constructor. */
#if HOST_AVAILABLE
#include "socket_member.inc"
static struct xdev_ext_netfam_stage authority_ns;
#define authority_slots (authority_ns.slots)
#define authority_elements (authority_ns.elems)
static struct xdev_ext_net_member authority_member;
static void authority_reset(void)
{
 if(authority_ns.slots)xdev_ext_netfam_fini(&authority_ns);
 memset(&authority_ns,0,sizeof(authority_ns));
 authority_member=HOST_SOCKET_MEMBER;
 CHECK(xdev_ext_netfam_init(&authority_ns,&stage,&authority_member,false,0)==0);
 CHECK(authority_ns.max_elems==32&&authority_member.lease_kind==XDEV_EXT_NET_LEASE_HOST_CPU);
 CHECK(xdev_ext_netfam_slot_get(&authority_ns,&batches[0])==&authority_slots[0]);
}
static void authority_reject(u32 index,u32 pos,u32 off,u32 len,int want)
{
 struct xdev_ext_net_elem before[32];
 memcpy(before,authority_elements,sizeof(before));
 u32 nr=authority_slots[0].nr;
 int old_peer=peer_calls,old_requester=requester_calls,old_sends=sends,old_completion=completions;
 CHECK(xdev_ext_netfam_lease_host(&authority_ns,&authority_slots[0],index,pos,off,len)==want);
 CHECK(memcmp(before,authority_elements,sizeof(before))==0&&authority_slots[0].nr==nr);
 CHECK(peer_calls==old_peer&&requester_calls==old_requester&&sends==old_sends&&completions==old_completion);
}
static void direct_host_cases(void)
{
 setup(false,false);authority_reset();
 struct xdev_ext_mech_frame good=batches[0].f[1];
 /* API preflight wins over unresolvable frame; member mismatch is separate. */
 authority_reject(32,99,0,1,-EPROTO);
 authority_reject(0,99,0,0,-EPROTO);
 authority_member.lease_kind=XDEV_EXT_NET_LEASE_PEER_DMA;
 authority_reject(0,99,0,1,-EPROTO);
 authority_member.lease_kind=XDEV_EXT_NET_LEASE_HOST_CPU;
 authority_reject(0,99,0,1,-ERANGE);
 batches[0].f[1].kaddr=NULL;authority_reject(0,1,4,1,-EINVAL);
 batches[0].f[1]=good;batches[0].f[1].index=3;authority_reject(0,1,4,1,-EINVAL);
 batches[0].f[1]=good;batches[0].f[1].data_len=0;authority_reject(0,1,4,1,-EINVAL);
 batches[0].f[1]=good;batches[0].f[1].data_off=129;authority_reject(0,1,4,1,-EINVAL);
 batches[0].f[1]=good;batches[0].f[1].data_len=125;authority_reject(0,1,4,1,-EINVAL);
 batches[0].f[1]=good;
 authority_reject(0,1,3,1,-ERANGE);
 authority_reject(0,1,12,1,-ERANGE);
 authority_reject(0,1,5,8,-ERANGE);
 authority_reject(0,1,UINT32_MAX,2,-ERANGE);
 /* Busy is last: malformed authority must still win and remain untouched. */
 authority_elements[0].lease.kind=XDEV_EXT_NET_LEASE_HOST_CPU;
 authority_reject(0,1,3,1,-ERANGE);
 authority_reject(0,1,4,1,-EBUSY);
 authority_elements[0].lease.kind=XDEV_EXT_NET_LEASE_NONE;
 batches[0].f[1].umem_addr=(1ULL<<33)+128;
 CHECK(xdev_ext_netfam_lease_host(&authority_ns,&authority_slots[0],0,1,5,7)==0);
 CHECK(authority_elements[0].lease.kind==XDEV_EXT_NET_LEASE_HOST_CPU);
 CHECK(authority_elements[0].lease.u.host.addr==buffers[1]+5&&authority_elements[0].lease.u.host.len==7);
 CHECK(authority_elements[0].slot==&authority_slots[0]&&authority_elements[0].len==7&&authority_elements[0].buf_len==7&&authority_slots[0].nr==1);
 struct xdev_ext_net_elem leased=authority_elements[0];
 u8 states_before[3];memcpy(states_before,states,sizeof(states));
 int alloc_before=allocations,refs_before=cred_refs;
 xdev_ext_netfam_release(&authority_slots[0],false);
 CHECK(memcmp(&leased,&authority_elements[0],sizeof(leased))==0&&authority_slots[0].busy);
 CHECK(memcmp(states_before,states,sizeof(states))==0&&allocations==alloc_before&&cred_refs==refs_before);
 xdev_ext_netfam_release(&authority_slots[0],true);
 CHECK(authority_elements[0].lease.kind==XDEV_EXT_NET_LEASE_NONE&&!authority_slots[0].busy);
 CHECK(authority_elements[0].lease.u.host.addr==NULL&&authority_elements[0].lease.u.host.len==0);
 CHECK(memcmp(states_before,states,sizeof(states))==0&&allocations==alloc_before&&cred_refs==refs_before);
 CHECK(peer_calls==0&&requester_calls==0&&sends==0&&completions==0);
 /* Exact lower/upper edges, and actual batch accessor authority after validate. */
 authority_reset();batches[0].f[1]=good;
 CHECK(xdev_ext_netfam_lease_host(&authority_ns,&authority_slots[0],0,1,4,8)==0);
 CHECK(authority_elements[0].lease.u.host.addr==buffers[1]+4);
 CHECK(xdev_ext_netfam_lease_host(&authority_ns,&authority_slots[0],1,1,11,1)==0);
 CHECK(authority_elements[1].lease.u.host.addr==buffers[1]+11&&authority_slots[0].nr==2);
 xdev_ext_netfam_release(&authority_slots[0],true);
 xdev_ext_netfam_fini(&authority_ns);
 teardown();puts("PASS direct HOST authority, rejection ordering, immutable refusal, quiesced/UNKNOWN custody");
}
#else
static void direct_host_cases(void)
{
 puts("SETUP HOST interface absent; no semantic RED claimed");
 exit(2);
}
#endif
