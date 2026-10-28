/* SPDX-License-Identifier: GPL-2.0 */
/* Business precondition: X5's qualified already-bound pair, not production
 * startup. Only existing class protocol custody facts are under test here. */
static unsigned diag_failures;
static void diag_check(bool value,const char *message)
{ if(!value){diag_failures++;fprintf(stderr,"DIAG_CLASS_ASSERT: %s\n",message);} }
int main(int argc,char **argv)
{
 assert(argc==2);const char *name=argv[1];pair(0,2,8192);
#if DIAG_CLASS_HAS_HOOK
 if(!registered->stage_diag){fprintf(stderr,"DIAG_CLASS_MISSING_FEATURE: registered class has no stage_diag hook\n");return 1;}
 struct xdev_ext_mech_stage *st=stage_of(&sides[1]);
 struct xdev_ext_xd_stage *xs=st->priv;
 struct xdev_ext_mech_stage_diag d={.size=168,.version=1,.session_id=st->s->id,.stage=st->index};
 u32 cts=0,ack=0,fail=0,wait=0,down=0;
 struct xdev_ext_xd_reply *r=&xs->replies[0];
 *r=(struct xdev_ext_xd_reply){.used=true,.group=91};
 if(!strcmp(name,"cts")){r->cts=true;cts=1;}
 else if(!strcmp(name,"ack")){r->final=true;r->chain_done=true;ack=1;}
 else if(!strcmp(name,"fail-local")){r->final=true;r->local_status=-EIO;fail=1;}
 else if(!strcmp(name,"fail-chain")){r->final=true;r->chain_status=-ECANCELED;fail=1;}
 else if(!strcmp(name,"fail-sequester")){r->final=true;r->sequestered=true;fail=1;}
 else if(!strcmp(name,"rts-admitted")){xs->rts_count=1;xs->rts[0].admission=true;fail=1;}
 else if(!strcmp(name,"rts-unadmitted")){xs->rts_count=1;xs->rts[0].status=-EIO;}
 else if(!strcmp(name,"final-wait")){r->final=true;wait=1;}
 else if(!strncmp(name,"downstream",10)){
  r->native_posted=true;
  if(strcmp(name,"downstream-no-live-slot")){
   xs->ns.slots[0].busy=true;xs->ns.slots[0].group=91;
   xs->ns.slots[0].local_known=true;
   xs->ns.slots[0].local_quiesced=strcmp(name,"downstream-unquiesced")!=0;
   if(!strcmp(name,"downstream"))down=1;
  }
 }else if(!strcmp(name,"unused-reply")){r->used=false;r->cts=r->final=true;r->local_status=-EIO;}
 else{
  assert(!strcmp(name,"mixed"));
  r->cts=true;cts=1;r->final=true;r->chain_done=true;ack=1;
  xs->replies[1]=(struct xdev_ext_xd_reply){.used=true,.final=true,.chain_status=-EIO};fail=2;
  xs->rts_count=1;xs->rts[0].admission=true;
 }
 struct xdev_ext_xd_stage saved=*xs;
 size_t slot_bytes=xs->ns.depth*sizeof(*xs->ns.slots),fact_bytes=xs->ns.depth*sizeof(*xs->facts);
 void *saved_slots=malloc(slot_bytes),*saved_facts=malloc(fact_bytes);
 assert(saved_slots&&saved_facts);memcpy(saved_slots,xs->ns.slots,slot_bytes);memcpy(saved_facts,xs->facts,fact_bytes);
 unsigned policy=protocol_calls,posts=sides[0].posts+sides[1].posts,wires=sides[0].wires+sides[1].wires;
 unsigned admits=sides[1].admission_calls,leases=sides[1].lease_calls,allocs=diag_allocations;
 int rc=registered->stage_diag(st,&d);
 diag_check(!rc,"bound class query succeeds");
 diag_check(d.cts_owed==cts,"CTS owed counts only used CTS replies");
 diag_check(d.ack_owed==ack,"ACK owed requires successful final chain disposition");
 diag_check(d.fail_owed==fail,"FAIL owed includes status and held RTS rejection admission");
 diag_check(d.final_waiting_chain==wait,"successful final without chain disposition remains waiting");
 diag_check(d.downstream_release_pending==down,"release pending needs posted RX, live local quiescence and pending chain");
 diag_check((d.valid&16U)!=0,"protocol fields have explicit validity");
 diag_check(!memcmp(xs,&saved,sizeof(saved)) && !memcmp(xs->facts,saved_facts,fact_bytes) && !memcmp(xs->ns.slots,saved_slots,slot_bytes),"query preserves epoch, cursor, worker_event, slots, replies and waits");
 diag_check(policy==protocol_calls && posts==sides[0].posts+sides[1].posts && wires==sides[0].wires+sides[1].wires && admits==sides[1].admission_calls && leases==sides[1].lease_calls,"query does not invoke policy, post data/control, readmit or acquire leases");
 diag_check(allocs==diag_allocations,"query performs no class/family allocation");
 diag_check(!held_spinlocks&&!held_mutexes,"class releases all locks");
 printf("DIAG_CLASS %s cts=%u ack=%u fail=%u wait=%u downstream=%u failures=%u\n",name,d.cts_owed,d.ack_owed,d.fail_owed,d.final_waiting_chain,d.downstream_release_pending,diag_failures);
 free(saved_slots);free(saved_facts);return !!diag_failures;
#else
 fprintf(stderr,"DIAG_CLASS_MISSING_FEATURE: class ABI lacks registered stage_diag hook; no protocol sampling certified\n");
 printf("DIAG_CLASS %s failures=1\n",name);return 1;
#endif
}
