/* Requirements: CONTRACT3-7, PLAN literal vectors, opus5.1. Injection is separate from want. */
static unsigned char payload[8192];
static struct xdev_ext_nvme_mech_cqe out_cqe;
static void start7(bool peer,bool write){
 fixture();queue_a.queuedata=&ns;queue_a.disk=&disk;disk.private_data=&ns;lease_calls=release_calls=retire_calls=claim_calls=publish_calls=complete_traces=0;
 claim_ticket=publish_ticket=complete_ticket=0;claim_errno=lease_error=lease_error_at=release_error=0;lease_len_override=-1;lease_max_bytes=4096;
 append_error_once=0;page_fault=false;early_complete=observe_done=false;copies_to=copies_from=0;
 early_native_status=early_transport=early_residual=0;publish_payload=NULL;published_first=0;
 pool_authority=&authority_file;pool_generation=5;memset(lease_dma,0,sizeof(lease_dma));
 memset(payload,0x19,sizeof(payload));memset(&out_cqe,0,sizeof(out_cqe));
 if(peer)session.pool.kind=XDEV_EXT_MECH_POOL_PEER;
 if(write){stage.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;sqe[0]=1;}
 if(!peer)batch.frames[0].kaddr=payload;
}
static void admitted7(void){bind_ok();validate_ok();clear_observers();}
static struct nvme_xdev_ext_mech_stage *member7(void){return stage.priv;}
static void watch7(void){
 watch_count=4;watch_length=0;watch_trace[0]=0;
 watch_functions[0]=(void *)nvme_init_request;watch_codes[0]='I';
 watch_functions[1]=(void *)xdev_ext_stor_slot_get;watch_codes[1]='G';
 watch_functions[2]=(void *)xdev_ext_stor_block_preflight;watch_codes[2]='M';
 watch_functions[3]=(void *)xdev_ext_peer_file_acquire;watch_codes[3]='L';
}
static void stopwatch7(void){watch_count=0;}
static void finish_host7(void){
 nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);unbind_ok();
}
static void finish_peer7(void){
 nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);unbind_ok();
}
/* Deliberately test-only teardown after proving a retained state. This makes no
 * recovery claim: production has no API converting UNKNOWN/ZOMBIE to known. */
static void discard_retained7(void){
 struct nvme_xdev_ext_mech_stage *p=member7();
 if(p->slots)for(u32 i=0;i<p->nr_slots;i++)p->slots[i].runtime.busy=false;
 if(p->peer)for(u32 i=0;i<p->peer->nr_slots;i++)p->peer->slots[i].runtime.busy=false;
 nvme_xdev_ext_class_unbind(&stage);EQ("retained_test_teardown_no_allocations",live_allocs,0);
}
static const u8 host_read64[64]={[0]=2,[4]=7,[40]=100,[48]=7};
static const u8 host_write64[64]={[0]=1,[4]=7,[40]=100,[48]=7};
static const u8 peer_inline64[64]={[0]=2,[1]=0x40,[4]=7,[26]=0x10,[33]=0x10,[40]=100,[48]=7};
static const u8 peer_two_sgl64[64]={[0]=2,[1]=0x40,[4]=7,[25]=0x10,[26]=0x20,[32]=0x20,[39]=0x30,[40]=100,[48]=7};
static const u8 peer_two_list32[32]={[2]=0x10,[9]=0x08,[18]=0x30,[25]=0x08};
static void test_host_submit7(void){
 /* Breaks caught: init after slot/map, wrong op kind, regenerated command, map failure leaked slot. */
 start7(false,false);admitted7();watch7();EQ("host_real_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);stopwatch7();
 CK("host_init_before_slot_map",strcmp(watch_trace,"IGM")==0);
 EQ("host_DRV_IN34",allocated_op,34);EQ("host_request_PDU64",memcmp(req.pdu.cmd,host_read64,64),0);
 EQ("host_USERCMD_flag",req.pdu.flags&NVME_REQ_USERCMD,NVME_REQ_USERCMD);
#ifdef TEST_STRICT
 EQ("host_ZC_flag",req.pdu.flags&NVME_REQ_XDEV_EXT_ZC,NVME_REQ_XDEV_EXT_ZC);
#endif
 CK("host_slot_and_bio_owned",private_batch.slot && private_batch.bio==private_batch.slot->bio);
 EQ("host_captured56",private_batch.slot->done.ticket,56);EQ("host_one_execute",posts,1);
 finish_host7();
 start7(false,true);admitted7();EQ("host_write_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);EQ("host_DRV_OUT35",allocated_op,35);EQ("host_write_PDU64",memcmp(req.pdu.cmd,host_write64,64),0);finish_host7();
 start7(false,false);admitted7();private_batch.family.sqe[50]=0x34;private_batch.family.sqe[51]=0x12;
 EQ("host_encode_upper_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);EQ("host_encode_upper12340007",req.pdu.cmd->common.cdw12,0x12340007);finish_host7();
 start7(false,false);admitted7();member7()->pool.free=NULL;watch7();EQ("host_empty_EAGAIN",nvme_xdev_ext_class_submit(&stage,&batch),-EAGAIN);stopwatch7();CK("host_empty_init_before_get",strcmp(watch_trace,"IG")==0);EQ("host_empty_free_once",rq_frees,1);EQ("host_empty_no_post",posts,0);unbind_ok();
 start7(false,false);admitted7();page_fault=true;watch7();EQ("host_preflight_EFAULT",nvme_xdev_ext_class_submit(&stage,&batch),-EFAULT);stopwatch7();CK("host_fault_init_before_map",strcmp(watch_trace,"IGM")==0);EQ("host_fault_no_active_bounce",private_batch.bounce,NULL);EQ("host_fault_clears_slot",private_batch.slot,NULL);EQ("host_fault_free_once",rq_frees,1);EQ("host_fault_zero_execute",posts,0);unbind_ok();
 start7(false,false);admitted7();append_errno=-EIO;EQ("host_append_EIO_not_bounced",nvme_xdev_ext_class_submit(&stage,&batch),-EIO);EQ("host_append_EIO_zero_post",posts,0);EQ("host_append_EIO_zero_copy",copies_to+copies_from,0);EQ("host_append_EIO_slot_returned",private_batch.slot,NULL);unbind_ok();
 start7(false,false);admitted7();member7()->nr_vecs=0;EQ("host_capacity_EREMOTEIO_no_fallback",nvme_xdev_ext_class_submit(&stage,&batch),-EREMOTEIO);EQ("host_capacity_zero_post",posts,0);EQ("host_capacity_zero_active_bounce",private_batch.bounce,NULL);unbind_ok();
}
static void test_host_completion7(void){
 /* Literal status/uncertainty vectors are specified in PLAN Task5. */
 const struct {unsigned residual,status,flags;int transport;bool owned;int want;bool uncertain;} v[]={
  {4096,0,0,0,true,0,false},{4096,0,0,0,false,-EIO,true},{1,0,0,0,true,-EIO,true},
  {0,0,0,0,false,0,false},{0,0x81,0,-EIO,false,0x81,false},{0,0x81,NVME_REQ_CANCELLED,-EIO,false,-EINTR,false}
 };
 for(unsigned i=0;i<ARRAY_SIZE(v);i++){
  start7(false,false);stage.poll=true;admitted7();EQ("completion_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);
  struct nvme_xdev_ext_mech_slot *slot=private_batch.slot;req.residual=v[i].residual;req.pdu.status=v[i].status;req.pdu.flags|=v[i].flags;
  if(!v[i].owned)req.bio=NULL;req.pdu.result.u64=0x8877665544332211ULL;batch.ticket=99;observe_done=true;
  EQ("host_end_io_FREE",req.end_io(&req,v[i].transport),RQ_END_IO_FREE);
  EQ("host_completion_status_literal",published_status,v[i].want);EQ("host_completion_uncertain_literal",published_uncertain,v[i].uncertain);
  EQ("host_complete_captured_ticket56",claim_ticket,56);EQ("host_publish_captured_ticket56",publish_ticket,56);EQ("host_complete_result_exact",private_batch.cqe.result,0x8877665544332211ULL);
  EQ("host_end_io_clears_poll",slot->done.poll_live,false);EQ("host_end_io_does_not_return_slot",slot->runtime.busy,true);
  nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("host_consume_invalidates",private_batch.family.validated,false);
  if(v[i].uncertain){EQ("host_UNKNOWN_keeps_slot",private_batch.slot,slot);EQ("host_UNKNOWN_keeps_bio",private_batch.bio,slot->bio);EQ("host_UNKNOWN_busy",slot->runtime.busy,true);void *saved=stage.priv;nvme_xdev_ext_class_unbind(&stage);EQ("host_UNKNOWN_unbind_busy",stage.priv,saved);discard_retained7();}
  else {EQ("host_known_returns_slot",slot->runtime.busy,false);EQ("host_known_clears_bio",private_batch.bio,NULL);unbind_ok();}
 }
 /* Stale claim must precede native classification and every batch write. */
 start7(false,false);stage.poll=true;admitted7();EQ("stale_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);struct nvme_xdev_ext_mech_slot *slot=private_batch.slot;
 memset(&private_batch.cqe,0xa5,sizeof(private_batch.cqe));struct xdev_ext_nvme_mech_cqe before=private_batch.cqe;
 claim_errno=-ESTALE;batch.ticket=99;req.pdu.status=0x81;observe_done=true;req.end_io(&req,0);
 EQ("stale_claim_captured56",claim_ticket,56);EQ("stale_no_classify_CQE",memcmp(&private_batch.cqe,&before,sizeof(before)),0);EQ("stale_no_publish",publish_calls,0);EQ("stale_no_complete_trace",complete_traces,0);EQ("stale_clears_poll",slot->done.poll_live,false);
 nvme_xdev_ext_class_slot_put(&stage,&private_batch);unbind_ok();
 /* Execute may complete synchronously, returning to common code after request retirement. */
 start7(false,false);admitted7();early_complete=true;early_residual=4096;observe_done=true;
 EQ("host_early_completion_return0",nvme_xdev_ext_class_submit(&stage,&batch),0);EQ("host_early_exactly_one_execute",posts,1);EQ("host_early_publish1",publish_calls,1);EQ("host_early_capture56",claim_ticket,56);EQ("host_early_known0",published_status,0);finish_host7();
 /* ZOMBIE prevents worker retirement even after known completion. */
 start7(false,false);admitted7();EQ("host_zombie_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);slot=private_batch.slot;session.state=XDEV_EXT_MECH_SESSION_ZOMBIE;
 nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("host_ZOMBIE_keeps_slot",private_batch.slot,slot);EQ("host_ZOMBIE_busy",slot->runtime.busy,true);discard_retained7();
}
static void peer_frames2(void){batch.nr=2;batch.frames[0]=(struct xdev_ext_mech_frame){.index=0,.umem_addr=0,.data_len=2048};batch.frames[1]=(struct xdev_ext_mech_frame){.index=1,.umem_addr=4096,.data_len=2048};lease_dma[0]=0x100000;lease_dma[1]=0x300000;}
static void test_peer_walk7(void){
 start7(true,false);admitted7();watch7();EQ("peer_inline_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);stopwatch7();
 CK("peer_init_after_lease",strcmp(watch_trace,"GLI")==0);EQ("peer_DRV_IN34",allocated_op,34);EQ("peer_inline_PDU64",memcmp(req.pdu.cmd,peer_inline64,64),0);
 EQ("peer_exact_authority",lease_authorities[0],&authority_file);EQ("peer_exact_requester",lease_requesters[0],&pci_a);EQ("peer_generation5",lease_generations[0],5);EQ("peer_offset0",lease_offsets[0],0);EQ("peer_length4096",lease_lengths[0],4096);EQ("peer_read_direction",lease_directions[0],DMA_FROM_DEVICE);
 EQ("peer_PDU_SGL_flag",req.pdu.cmd->common.flags,0x40);EQ("peer_FAILFAST",req.cmd_flags&REQ_FAILFAST_MASK,REQ_FAILFAST_MASK);EQ("peer_native_flag",req.pdu.flags&(NVME_REQ_USERCMD|NVME_REQ_XDEV_EXT_PEER),5);EQ("peer_trace_live",req.pdu.peer_trace,&private_batch.peer_slot->trace);finish_peer7();
 start7(true,false);admitted7();peer_frames2();watch7();EQ("peer_two_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);stopwatch7();CK("peer_frame_order_then_init",strcmp(watch_trace,"GLLI")==0);
 EQ("peer_frame0_offset0",lease_offsets[0],0);EQ("peer_frame1_offset4096",lease_offsets[1],4096);EQ("peer_two_PDU64",memcmp(req.pdu.cmd,peer_two_sgl64,64),0);EQ("peer_two_SGL_list32",memcmp(private_batch.peer_slot->sgl,peer_two_list32,32),0);finish_peer7();
 start7(true,false);ctrl.sgl=false;admitted7();EQ("peer_PRP_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);u8 prp64[64]={[0]=2,[4]=7,[26]=0x10,[40]=100,[48]=7};EQ("peer_PRP_full64",memcmp(req.pdu.cmd,prp64,64),0);finish_peer7();
 start7(true,false);ctrl.sgl=false;session.layout.group_bytes=12288;session.layout.frame_size=16384;session.pool.frame_size=16384;batch.bytes=12288;batch.frames[0].data_len=12288;sqe[48]=23;lease_max_bytes=4096;admitted7();EQ("peer_PRP_list_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);
 /* Actual shrink probes 12288,8192,4096 then8192,4096 then4096. DMA derives from supplied offsets. */
 u8 prplist64[64]={[0]=2,[4]=7,[26]=0x10,[33]=0x10,[34]=0x20,[40]=100,[48]=23};u8 prplist16[16]={[1]=0x10,[2]=0x10,[9]=0x20,[10]=0x10};
 EQ("peer_PRP_list_PDU64",memcmp(req.pdu.cmd,prplist64,64),0);EQ("peer_PRP_list_exact16",memcmp(private_batch.peer_slot->sgl,prplist16,16),0);finish_peer7();
 /* Provider errors precede drift; successful map exposes drift only afterwards. */
 start7(true,false);admitted7();private_batch.family.rw.nlb=9;lease_error=-EIO;watch7();EQ("peer_provider_EIO_before_drift",nvme_xdev_ext_class_submit(&stage,&batch),-EIO);stopwatch7();CK("peer_failure_no_init",strcmp(watch_trace,"GL")==0);EQ("peer_provider_error_free1",rq_frees,1);EQ("peer_provider_error_no_post",posts,0);EQ("peer_provider_error_slot_returned",private_batch.peer_slot,NULL);EQ("peer_preaccept_runtime_free",member7()->peer->slots[1].runtime.busy,false);unbind_ok();
 start7(true,false);admitted7();private_batch.family.rw.nlb=9;EQ("peer_success_map_then_drift_EPROTO",nvme_xdev_ext_class_submit(&stage,&batch),-EPROTO);EQ("peer_drift_releases_one",release_calls,1);EQ("peer_drift_release_true",release_quiesced[0],true);EQ("peer_drift_no_post",posts,0);unbind_ok();
 start7(true,false);admitted7();private_batch.family.rw.nlb=9;lease_len_override=0;EQ("peer_empty_lease_EPROTO",nvme_xdev_ext_class_submit(&stage,&batch),-EPROTO);EQ("peer_empty_handle_retired",release_calls,1);EQ("peer_empty_release_true",release_quiesced[0],true);unbind_ok();
 start7(true,false);admitted7();lease_len_override=4097;EQ("peer_overlong_EPROTO",nvme_xdev_ext_class_submit(&stage,&batch),-EPROTO);EQ("peer_overlong_handle_retired",release_calls,1);unbind_ok();
 start7(true,false);admitted7();peer_frames2();member7()->peer->max_pieces=1;EQ("peer_capacity_EREMOTEIO",nvme_xdev_ext_class_submit(&stage,&batch),-EREMOTEIO);EQ("peer_capacity_no_second_acquire",lease_calls,1);EQ("peer_capacity_retire_first",release_calls,1);unbind_ok();
 for(unsigned invalid=0;invalid<5;invalid++){
 start7(true,false);admitted7();switch(invalid){case 0:batch.frames[0].kaddr=payload;break;case 1:batch.frames[0].data_len=0;break;case 2:batch.frames[0].data_off=4097;break;case 3:batch.frames[0].data_off=1;break;case 4:batch.frames[0].umem_addr=1;break;}
 EQ("peer_invalid_frame_EPROTO",nvme_xdev_ext_class_submit(&stage,&batch),-EPROTO);EQ("peer_invalid_zero_acquire",lease_calls,0);EQ("peer_invalid_zero_post",posts,0);unbind_ok();}
 start7(true,false);admitted7();pool_authority=NULL;EQ("peer_no_authority_EINVAL",nvme_xdev_ext_class_submit(&stage,&batch),-EINVAL);EQ("peer_no_authority_no_acquire",lease_calls,0);unbind_ok();
 start7(true,false);admitted7();batch.nr=0;EQ("peer_no_frames_EINVAL",nvme_xdev_ext_class_submit(&stage,&batch),-EINVAL);unbind_ok();
 start7(true,false);admitted7();member7()->peer->pool.free=NULL;watch7();EQ("peer_empty_EAGAIN",nvme_xdev_ext_class_submit(&stage,&batch),-EAGAIN);stopwatch7();CK("peer_empty_no_init",strcmp(watch_trace,"G")==0);EQ("peer_empty_zero_acquire",lease_calls,0);unbind_ok();
 /* native checks keep their prior priority even with downstream failures injected. */
 start7(true,true);admitted7();ctrl.state=0;disk.ro=true;tag_errno=-EAGAIN;EQ("peer_LIVE_precedes_RO_tag",nvme_xdev_ext_class_submit(&stage,&batch),-ENODEV);EQ("peer_LIVE_zero_alloc",rq_allocs,0);unbind_ok();
 start7(true,true);admitted7();disk.ro=true;tag_errno=-EAGAIN;EQ("peer_RO_precedes_tag",nvme_xdev_ext_class_submit(&stage,&batch),-EROFS);unbind_ok();
 start7(true,false);admitted7();queue_a.max_hw_sectors=7;tag_errno=-EAGAIN;EQ("peer_maxbytes_precedes_tag",nvme_xdev_ext_class_submit(&stage,&batch),-E2BIG);unbind_ok();
}
static void test_peer_completion7(void){
 const struct {unsigned status,flags;int transport;int want;bool uncertain;} v[]={{0,0,0,0,false},{0x81,0,-EIO,0x81,true},{0,NVME_REQ_CANCELLED,0,-EINTR,true},{0,0,-EIO,-EIO,true}};
 for(unsigned i=0;i<ARRAY_SIZE(v);i++){
 start7(true,false);stage.poll=true;admitted7();peer_frames2();EQ("peer_complete_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);
 struct nvme_xdev_ext_peer_slot *slot=private_batch.peer_slot;req.pdu.status=v[i].status;req.pdu.flags|=v[i].flags;req.residual=0;req.pdu.result.u64=0x1020304050607080ULL;batch.ticket=99;observe_done=true;
 EQ("peer_end_io_FREE",req.end_io(&req,v[i].transport),RQ_END_IO_FREE);EQ("peer_status_priority",published_status,v[i].want);EQ("peer_error_uncertain_even_residual0",published_uncertain,v[i].uncertain);
 EQ("peer_endio_flag_cleared",req.pdu.flags&NVME_REQ_XDEV_EXT_PEER,0);EQ("peer_endio_trace_cleared",req.pdu.peer_trace,NULL);EQ("peer_endio_no_handle_retire",release_calls,0);EQ("peer_claim_captured56",claim_ticket,56);EQ("peer_complete_result_exact",private_batch.cqe.result,0x1020304050607080ULL);
 event_count=0;events[0]=0;nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("peer_consume_retires_two",release_calls,2);EQ("peer_retire_order_ticket100",released_tickets[0],100);EQ("peer_retire_order_ticket101",released_tickets[1],101);EQ("peer_consume_clear_count",slot->nr_leases,0);EQ("peer_consume_clear_batch",private_batch.peer_slot,NULL);EQ("peer_consume_trace_cookie_zero",slot->trace.cookie,0);EQ("peer_consume_invalidates",private_batch.family.validated,false);
 if(v[i].uncertain){CK("peer_UNKNOWN_release_then_trace",strcmp(events,"ufuft")==0);EQ("peer_UNKNOWN_release_false",release_quiesced[0],false);EQ("peer_UNKNOWN_trace_EINPROGRESS",trace_status,-EINPROGRESS);EQ("peer_UNKNOWN_busy",slot->runtime.busy,true);void *saved=stage.priv;nvme_xdev_ext_class_unbind(&stage);EQ("peer_UNKNOWN_unbind_retains",stage.priv,saved);discard_retained7();}
 else{CK("peer_known_release_then_trace",strcmp(events,"qfqft")==0);EQ("peer_known_release_true",release_quiesced[0],true);EQ("peer_known_trace_known",trace_status,0);EQ("peer_known_free_slot",slot->runtime.busy,false);unbind_ok();}
 }
 start7(true,false);admitted7();EQ("peer_ZOMBIE_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);struct nvme_xdev_ext_peer_slot *slot=private_batch.peer_slot;session.state=XDEV_EXT_MECH_SESSION_ZOMBIE;
 nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("peer_ZOMBIE_no_release",release_calls,0);EQ("peer_ZOMBIE_no_trace_retire",retire_calls,0);EQ("peer_ZOMBIE_keep_count1",slot->nr_leases,1);EQ("peer_ZOMBIE_keep_slot",private_batch.peer_slot,slot);CK("peer_ZOMBIE_keep_handle",slot->leases[0].file!=NULL);CK("peer_ZOMBIE_keep_cookie",slot->trace.cookie!=0);discard_retained7();
 /* fd_release failure preserves handle, native trace still reports ESTALE. */
 start7(true,false);admitted7();EQ("peer_release_failure_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);slot=private_batch.peer_slot;release_error=-EIO;nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("peer_release_failure_trace_ESTALE",trace_status,-ESTALE);CK("peer_release_failure_handle_preserved",slot->leases[0].file!=NULL);unbind_ok();
 start7(true,false);admitted7();early_complete=true;early_native_status=0x81;observe_done=true;EQ("peer_early_return0",nvme_xdev_ext_class_submit(&stage,&batch),0);EQ("peer_early_execute_once",posts,1);EQ("peer_early_publish1",publish_calls,1);EQ("peer_early_uncertain",published_uncertain,true);slot=private_batch.peer_slot;nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("peer_early_UNKNOWN_busy",slot->runtime.busy,true);discard_retained7();
}
static void test_bounce7(void){
#ifdef TEST_BOUNCE
 /* Native module counter must observe only active successful bounce, before submit. */
 start7(false,false);admitted7();long long before=atomic64_read(&nvme_xdev_ext_mech_bounces);EQ("bounce_preallocated_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);EQ("bounce_preallocated_not_counted",atomic64_read(&nvme_xdev_ext_mech_bounces),before);finish_host7();
 start7(false,false);admitted7();before=atomic64_read(&nvme_xdev_ext_mech_bounces);append_error_once=-EREMOTEIO;EQ("bounce_fallback_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);EQ("bounce_active_count_once",atomic64_read(&nvme_xdev_ext_mech_bounces),before+1);CK("bounce_counter_before_submit",strchr(events,'c')<strchr(events,'S'));EQ("bounce_active_pages1",private_batch.nr_bounce,1);struct nvme_xdev_ext_mech_slot *slot=private_batch.slot;
 memset(slot->bounce[0]->bytes,0x7e,4096);req.residual=4096;publish_payload=payload;observe_done=true;req.end_io(&req,0);EQ("bounce_copyback_before_publish",published_first,0x7e);EQ("bounce_copyback_once",copies_from,1);finish_host7();
 start7(false,true);admitted7();append_error_once=-EREMOTEIO;EQ("bounce_write_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);EQ("bounce_write_copyin_once",copies_to,1);EQ("bounce_write_payload_literal",private_batch.bounce[0]->bytes[0],0x19);req.residual=0;req.end_io(&req,0);EQ("bounce_write_no_copyback",copies_from,0);finish_host7();
 start7(false,false);admitted7();before=atomic64_read(&nvme_xdev_ext_mech_bounces);append_errno=-EREMOTEIO;EQ("bounce_failed_append_errno",nvme_xdev_ext_class_submit(&stage,&batch),-EREMOTEIO);EQ("bounce_failed_not_counted",atomic64_read(&nvme_xdev_ext_mech_bounces),before);EQ("bounce_failed_zero_post",posts,0);unbind_ok();
 start7(false,false);admitted7();append_error_once=-EREMOTEIO;EQ("bounce_UNKNOWN_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);slot=private_batch.slot;memset(slot->bounce[0]->bytes,0x7e,4096);req.residual=1;req.end_io(&req,0);EQ("bounce_UNKNOWN_no_copyback",copies_from,0);nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("bounce_UNKNOWN_active_cleared",private_batch.bounce,NULL);EQ("bounce_UNKNOWN_owns_pages",slot->nr_bounce,1);EQ("bounce_UNKNOWN_bio_retained",private_batch.bio,slot->bio);EQ("bounce_UNKNOWN_slot_retained",private_batch.slot,slot);discard_retained7();
 start7(false,false);admitted7();append_error_once=-EREMOTEIO;EQ("bounce_ZOMBIE_submit0",nvme_xdev_ext_class_submit(&stage,&batch),0);session.state=XDEV_EXT_MECH_SESSION_ZOMBIE;req.residual=4096;req.end_io(&req,0);EQ("bounce_ZOMBIE_no_copyback",copies_from,0);nvme_xdev_ext_stage_fill_cqe(&stage,&batch,&out_cqe);EQ("bounce_ZOMBIE_active_cleared",private_batch.bounce,NULL);CK("bounce_ZOMBIE_owns_slot",private_batch.slot!=NULL);discard_retained7();
 char counter_text[64];EQ("bounce_parameter_set_EPERM",nvme_xdev_ext_mech_bounces_ops.set("0",NULL),-EPERM);CK("bounce_parameter_get_positive",nvme_xdev_ext_mech_bounces_ops.get(counter_text,NULL)>0);
#else
 start7(false,false);admitted7();append_errno=-EREMOTEIO;EQ("no_bounce_EREMOTEIO",nvme_xdev_ext_class_submit(&stage,&batch),-EREMOTEIO);EQ("no_bounce_zero_copy",copies_from+copies_to,0);EQ("no_bounce_zero_post",posts,0);unbind_ok();
#endif
}
static void test_resources7(void){
#ifdef TEST_BOUNCE
 const int host_failures=8;
#else
 const int host_failures=4;
#endif
 for(int failure=1;failure<=host_failures;failure++){
  start7(false,false);alloc_fail=failure;EQ("host_allocation_failure_ENOMEM",nvme_xdev_ext_class_bind(&stage,&uapi),-ENOMEM);EQ("host_allocation_failure_no_leak",live_allocs,0);EQ("host_allocation_failure_no_priv",stage.priv,NULL);EQ("host_allocation_failure_no_execute",posts,0);
 }
 for(int failure=1;failure<=5;failure++){
  start7(true,false);alloc_fail=failure;EQ("peer_allocation_failure_ENOMEM",nvme_xdev_ext_class_bind(&stage,&uapi),-ENOMEM);EQ("peer_allocation_failure_no_leak",live_allocs,0);EQ("peer_allocation_failure_no_priv",stage.priv,NULL);EQ("peer_allocation_failure_no_lease",lease_calls,0);
 }
 start7(true,false);bind_ok();struct nvme_xdev_ext_mech_stage *p=member7();EQ("peer_coherent_total8192",p->peer->sgl_bytes,8192);EQ("peer_slot0_dma200000",p->peer->slots[0].sgl_dma,0x200000);EQ("peer_slot1_dma201000",p->peer->slots[1].sgl_dma,0x201000);EQ("peer_depth2_stride_count",p->family.poll_views[1].count,2);unbind_ok();
}
static void tests_7b(void){test_host_submit7();test_host_completion7();test_peer_walk7();test_peer_completion7();test_bounce7();test_resources7();}
int main(void){tests_7b();printf("PASS STOR7B literal assertions %u\n",checks);return 0;}
