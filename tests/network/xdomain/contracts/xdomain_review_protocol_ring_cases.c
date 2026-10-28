/* SPDX-License-Identifier: GPL-2.0 */
/* Actual production ring.c dispatch for the no-bound-RX contract. */
static void review_ring_require(bool truth,const char *message)
{ if(!truth){fprintf(stderr,"REVIEW-P RING ASSERTION: %s\n",message);exit(1);} }
static struct xdev_ext_xd_msg review_last_fail(void)
{
 struct xdev_ext_xd_msg msg={0};
 review_ring_require(xl.ctl_tx->queued_nr>0,"FAIL has an admitted native control frame");
 struct ring_frame *frame=xl.ctl_tx->queued[xl.ctl_tx->queued_nr-1];
 review_ring_require(!xdev_ext_xd_msg_decode((void *)(uintptr_t)frame->buffer_phy,128,crc32c,&msg),"decode real control backing");
 review_ring_require(msg.type==XDEV_EXT_XD_FAIL&&msg.status==ENODEV&&msg.stream==7&&msg.group==1,"unbound RTS gets exact group/stream FAIL");
 return msg;
}
static void review_unbound_ring_full(void)
{
 fresh();fill_ctl();struct xdev_ext_xd_msg msg=incoming(XDEV_EXT_XD_RTS,1);
 deliver(msg);
 fprintf(stderr,"unbound_full consumed=%llu free_ctl=%u native_ctl=%u link_fail=%u\n",(unsigned long long)xl.chan[0].consumed,free_ctl(),xl.ctl_tx->queued_nr,fail_calls);
 review_ring_require(xl.chan[0].consumed==0,"unbound RTS must remain unconsumed while FAIL native-control admission is full");
 /* The frozen contract permits explicit incarnation termination when no RX
  * is bound. This must transfer an exact error responsibility, not silently
  * consume or pretend that a native FAIL frame was accepted. The runner then
  * executes real main.c fail/down_work and real class sender-deadline proofs. */
 review_ring_require(fail_calls==1&&fail_error==-EAGAIN,"full unbound reply transfers exactly one EAGAIN terminal responsibility");
 review_ring_require(xl.ctl_tx->queued_nr==128&&free_ctl()==0,"no FAIL frame was admitted into the full native ring");
 for(unsigned n=0;n<xl.ctl_tx->queued_nr;n++)
  review_ring_require(*(u8 *)(uintptr_t)xl.ctl_tx->queued[n]->buffer_phy==0x31,"all prior native control frames retain their backing/ownership");
 review_ring_require(xl.chan[0].consumed==0,"terminal transfer does not consume an unanswered request");
}
static void review_unbound_duplicate(void)
{
 fresh();struct xdev_ext_xd_msg msg=incoming(XDEV_EXT_XD_RTS,1);
 deliver(msg);review_last_fail();
 review_ring_require(xl.chan[0].consumed==4&&!fail_calls,"first unbound request gets terminal error");
 deliver(msg);
 fprintf(stderr,"unbound_duplicate consumed=%llu failures=%u ctl_frames=%u\n",(unsigned long long)xl.chan[0].consumed,fail_calls,xl.ctl_tx->queued_nr);
 review_ring_require(xl.chan[0].consumed==4&&!fail_calls,"duplicate unbound RTS cannot consume twice or fail shared link");
}
int main(int argc,char **argv)
{
 review_ring_require(argc==2,"select ring case");
 if(!strcmp(argv[1],"unbound_ring_full"))review_unbound_ring_full();
 else if(!strcmp(argv[1],"unbound_duplicate"))review_unbound_duplicate();
 else return 2;
 return 0;
}
