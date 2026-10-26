#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Executes the network family runtime with the mechanism core, peer leases and
 the device replaced by recording stubs; proves slot custody, hand-off, release
 and abandonment decisions, not device behavior."""
from net_async_stage_test import compile_and_run, family_runtime, require_family

MAIN = r'''
static struct xdev_ext_netfam_stage ns;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_batch batches[10];
static struct xdev_ext_net_slot *slots[10];
static struct xdev_ext_net_elem *posted[10];
static u32 posted_nr[10];
static int result_calls[10], post_refusal, device_posts;
static struct xdev_ext_net_dev_ops dev;
static struct xdev_ext_net_member member;
static int batch_index(const struct xdev_ext_mech_batch *b)
{ assert(b >= batches && b < batches + 10); return (int)(b - batches); }
static int record_tx(void *lk, struct xdev_ext_net_elem *e, u32 n)
{
 assert(lk == &endpoint && !ns.rx && e && n && n <= dev.max_elems);
 if (post_refusal) return post_refusal;
 int id = batch_index(e[0].slot->batch);
 assert(!posted[id]); posted[id] = e; posted_nr[id] = n; device_posts++;
 for (u32 i=0;i<n;i++) assert(e[i].slot == slots[id] && e[i].lease.file == &allocation);
 return 0;
}
static int record_rx(void *lk, struct xdev_ext_net_elem *e, u32 n)
{
 assert(lk == &endpoint && ns.rx && e && n && n <= dev.max_elems);
 if (post_refusal) return post_refusal;
 int id = batch_index(e[0].slot->batch);
 assert(!posted[id]); posted[id] = e; posted_nr[id] = n; device_posts++;
 for (u32 i=0;i<n;i++) assert(e[i].slot == slots[id] && e[i].lease.file == &allocation);
 return 0;
}
static void result(struct xdev_ext_netfam_stage *n, struct xdev_ext_mech_batch *b,
                   const struct xdev_ext_net_slot *slot, int status, bool sequester)
{
 int id = batch_index(b);
 assert(n == &ns && slot == slots[id] && b->claims == 1 && !b->publishes);
 assert(!result_calls[id]++);
 (void)status; (void)sequester;
}
static void init(bool rx, u32 max)
{
 live=retired=quarantined=posts=refusal=inline_complete=0;
 post_refusal=device_posts=0; now_ms=10;
 memset(&ns,0,sizeof(ns)); memset(batches,0,sizeof(batches));
 memset(slots,0,sizeof(slots)); memset(posted,0,sizeof(posted));
 memset(posted_nr,0,sizeof(posted_nr)); memset(result_calls,0,sizeof(result_calls));
 session=(struct xdev_ext_mech_session){.pool={3,4096,16},.l={4096,0,3000,3000},.depth=4,.admits=true};
 stage=(struct xdev_ext_mech_stage){.s=&session,.file=&allocation,
  .direction=rx?XDEV_EXT_MECH_DIR_FROM_DEVICE:XDEV_EXT_MECH_DIR_TO_DEVICE};
 dev=(struct xdev_ext_net_dev_ops){.hdr_policy=XDEV_EXT_NET_HDR_SPLIT,.max_elems=max,
  .bind=NULL,.requester=NULL,.post_tx=record_tx,.post_rx=record_rx};
 member=(struct xdev_ext_net_member){.dev=&dev,.admit=false,.result=result};
 /* Endpoint setup is metadata only; payload submission stays in the real family. */
 assert(!xdev_ext_netfam_init(&ns,&stage,&member,rx,0));
 ns.lk=&endpoint; endpoint.rx=rx;
 for(int i=0;i<10;i++) batches[i].ticket=(u64)i+1;
}
static struct pci_dev *requester(void *lk) { assert(lk==&endpoint);return &peer; }
static int submit_n(int id, u32 n)
{
 struct xdev_ext_net_slot *s=xdev_ext_netfam_slot_get(&ns,&batches[id]);
 if(!s)return -EAGAIN;
 slots[id]=s;
 for(u32 i=0;i<n;i++) {
  int ret=xdev_ext_netfam_lease(&ns,s,i,(u64)(id*64+i)*4096,4096,4096);
  if(ret){xdev_ext_netfam_release(s,true);return ret;}
 }
 return xdev_ext_netfam_post(&ns,s);
}
static void done(int id,u32 i,int status,bool q)
{
 assert(posted[id] && i < posted_nr[id]);
 xdev_ext_net_elem_done(&posted[id][i],status,status?0:4096,0,q);
}
static void fill(int id){xdev_ext_netfam_fill_cqe(&ns,&slots[id]);assert(!slots[id]);}
static void release_known_stage(void)
{assert(!live);ns.lk=NULL;xdev_ext_netfam_fini(&ns);}
int main(void)
{
 init(false,64);dev.requester=requester;
 assert(!submit_n(0,64)&&live==64&&device_posts==1);
 for(int i=0;i<63;i++)done(0,(u32)((i*17)%63),0,true);
 assert(!batches[0].publishes&&!result_calls[0]&&live==64);
 done(0,63,0,true);
 assert(batches[0].claims==1&&batches[0].publishes==1&&!batches[0].status&&result_calls[0]==1);
 fill(0);assert(!live&&!quarantined&&retired==64);release_known_stage();
 puts("ok 1 - 64 elements retain leases until the last callback; one handoff and 64 quiesced releases");

 init(false,4);dev.requester=requester;assert(!submit_n(0,4));
 done(0,0,0,true);done(0,1,-EIO,false);done(0,2,0,true);
 assert(!batches[0].publishes);done(0,3,0,true);
 assert(batches[0].publishes==1&&batches[0].status==-EIO&&batches[0].sequester&&live==4);
 struct xdev_ext_net_slot *uncertain=slots[0];fill(0);
 assert(!live&&quarantined==4&&retired==4&&uncertain->busy);
 assert(xdev_ext_netfam_slot_get(&ns,&batches[1])!=uncertain);
 puts("ok 2 - one UNKNOWN element quarantines every lease and keeps its callback slot pinned");

 init(false,4);dev.requester=requester;
 for(int i=0;i<4;i++)assert(!submit_n(i,4));
 int depth_live=live;assert(depth_live==16&&device_posts==4);
 assert(submit_n(9,4)==-EAGAIN&&live==depth_live&&!batches[9].claims&&!slots[9]&&device_posts==4);
 for(int i=0;i<4;i++){for(u32 j=0;j<4;j++)done(i,j,0,true);fill(i);}
 assert(!live&&!quarantined);release_known_stage();
 puts("ok 3 - a full slot array rejects before acceptance without acquiring or releasing another batch's leases");

 init(false,4);dev.requester=requester;post_refusal=-ENOSPC;
 assert(submit_n(0,4)==-ENOSPC&&!live&&!quarantined&&retired==4);
 assert(!slots[0]->busy&&!batches[0].claims&&!batches[0].publishes&&!device_posts);
 post_refusal=0;assert(!submit_n(1,4));
 for(u32 j=0;j<4;j++)done(1,j,0,true);
 fill(1);release_known_stage();
 puts("ok 4 - a refused post releases all preaccept leases quiesced and permits slot reuse");

 init(true,4);dev.requester=requester;dev.rx_flush=NULL;assert(!submit_n(0,4));
 now_ms+=29999;xdev_ext_netfam_progress(&ns);assert(!batches[0].publishes&&live==4);
 now_ms++;xdev_ext_netfam_progress(&ns);
 assert(batches[0].publishes==1&&batches[0].claims==1&&batches[0].status==-ETIMEDOUT&&batches[0].sequester);
 struct xdev_ext_net_slot *abandoned=slots[0];fill(0);assert(!live&&quarantined==4&&abandoned->busy);
 for(u32 j=0;j<4;j++)done(0,j,0,true);
 xdev_ext_netfam_progress(&ns);
 assert(batches[0].publishes==1&&batches[0].claims==1&&result_calls[0]==1&&abandoned->busy&&quarantined==4);
 puts("ok 5 - exact deadline abandons without flush, retains uncertain custody and ignores every late callback");

 init(false,16);dev.requester=requester;
 slots[0]=xdev_ext_netfam_slot_get(&ns,&batches[0]);assert(slots[0]);
 assert(xdev_ext_netfam_lease(&ns,slots[0],16,0,4096,4096)==-EPROTO&&!live&&!retired&&!device_posts);
 assert(xdev_ext_netfam_lease(&ns,slots[0],0,0,0,4096)==-EPROTO&&!live);
 assert(xdev_ext_netfam_lease(&ns,slots[0],0,0,4096,4095)==-EPROTO&&!live);
 xdev_ext_netfam_release(slots[0],true);assert(!slots[0]->busy);release_known_stage();
 puts("ok 6 - subclass maximum and invalid length bounds reject before acquiring a lease");
 return 0;
}
'''

def main():
    require_family()
    compile_and_run(family_runtime(), MAIN, "netfam-body-")

if __name__ == "__main__":
    main()
