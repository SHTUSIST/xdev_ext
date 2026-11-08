/* Candidate-only tests from CONTRACT2-7; 7A missing types/APIs are SETUP. */
static unsigned common_checks;
#define GC(name,expr) do{common_checks++;if(!(expr)){fprintf(stderr,"ASSERTION %s line%d\n",name,__LINE__);exit(1);}}while(0)
#define GE(name,a,w) GC(name,(a)==(w))
static struct blk_mq_tag_set gt={.nr_maps=3,.map={[2]={.nr_queues=1}}};
static struct pci_dev gp={.dev={.pci=true}};
static struct nvme_ctrl_ops gco={.name="pcie",.peer_rw=(void *)1};
static struct nvme_ctrl gctrl;
static struct nvme_ns_head gh;
static struct gendisk gd;
static struct nvme_ns gn;
static struct inode ginode;
static struct file_operations gfo={.uring_cmd=nvme_ns_chr_uring_cmd};
static struct file gf;
static struct xdev_ext_mech_session gs;
static struct xdev_ext_mech_stage gst;
static struct xdev_ext_mech_stage_uapi gu;
static struct nvme_xdev_ext_mech_batch gbp;
static struct xdev_ext_mech_batch gb;
static u8 gdesc[64];static unsigned char gpayload[4096];
static struct xdev_ext_stor_dev_ops go;
static const struct xdev_ext_stor_dev_ops *original_ops;
static unsigned binds,encodes,dptrs,inits,post_hooks,retires,unbinds;
static bool alter_encode,alter_dptr;
static const struct xdev_ext_stor_command *init_command,*post_command;
static int gbinding(struct xdev_ext_mech_stage *s,const struct xdev_ext_mech_stage_uapi *u,struct xdev_ext_stor_stage **ss,void **m){binds++;return original_ops->bind(s,u,ss,m);}
static void gunbinding(void *m){unbinds++;original_ops->unbind(m);}
static int gencode(void *m,const struct xdev_ext_stor_rw *r,const u8 sqe[64],u32 n,bool peer,struct xdev_ext_stor_rw *p,struct xdev_ext_stor_command *c){
 encodes++;int rc=original_ops->encode(m,r,sqe,n,peer,p,c);if(!rc && alter_encode)c->bytes[4]=11;return rc;
}
static int gdptr(void *m,struct xdev_ext_stor_command *c,const struct xdev_ext_stor_extent *s,u32 n,struct xdev_ext_stor_extent *w,u32 cap,void *cpu,u64 dma,u32 bytes){
 dptrs++;GE("common_DP_control_capacity512",cap,512);GE("common_DP_list_bytes4096",bytes,4096);GC("common_DP_spans_alias_work",s==w);GC("common_DP_storage_aligned512",!(dma&511));GC("common_DP_list_present",cpu!=NULL);
 int rc=original_ops->encode_dptr(m,c,s,n,w,cap,cpu,dma,bytes);if(!rc && alter_dptr){memset(c->bytes+24,0,8);c->bytes[26]=0x70;}return rc;
}
static void ginit(void *m,struct request *rq,struct xdev_ext_stor_command *c,bool peer){inits++;init_command=c;GE("common_init_uses_pinned_command",c,&gbp.family.command);original_ops->request_init(m,rq,c,peer);}
static void gpost(void *m,struct request *rq,struct xdev_ext_stor_io *io,struct xdev_ext_mech_batch *batch,const struct xdev_ext_stor_command *c,bool peer){
 post_hooks++;post_command=c;GE("common_post_same_command",c,init_command);GE("common_post_captured_batch",io->done.b,batch);GE("common_post_captured_ticket56",io->done.ticket,56);GE("common_post_busy_before_execute",io->runtime.busy,true);original_ops->post(m,rq,io,batch,c,peer);
}
static void gretire(void *m,struct xdev_ext_stor_io *io,bool q){
 retires++;GE("common_retire_before_count_clear",io->nr_leases,1);GE("common_retire_after_fd_handle",io->leases[0].file,NULL);GE("common_retire_after_mapping_handle",io->leases[0].lease.mapping,NULL);original_ops->retire_peer(m,io,q);
}
static void gfixture(bool peer){
 GE("common_previous_no_allocations",live_allocs,0);event_count=0;events[0]=0;alloc_call=alloc_fail=0;rq_allocs=rq_frees=posts=0;tag_errno=append_errno=0;append_error_once=0;effects_allowed=1;force_unpolled=false;early_complete=false;page_fault=false;observe_done=false;
 claim_calls=publish_calls=complete_traces=lease_calls=release_calls=retire_calls=0;claim_errno=lease_error=release_error=0;lease_error_at=0;lease_len_override=-1;lease_max_bytes=4096;pool_authority=&authority_file;pool_generation=5;memset(lease_dma,0,sizeof(lease_dma));
 binds=encodes=dptrs=inits=post_hooks=retires=unbinds=0;alter_encode=alter_dptr=false;init_command=post_command=NULL;
 queue_a=(struct request_queue){.limits={.features=1},.tag_set=&gt,.max_segments=8,.max_segment_size=4096,.max_hw_sectors=128,.queuedata=&gn,.disk=&gd};
 gctrl=(struct nvme_ctrl){.dev=&gp.dev,.ops=&gco,.sgl=true,.state=1};gh=(struct nvme_ns_head){.lba_shift=9,.ns_id=7};gd=(struct gendisk){.capacity=4096,.diskseq=23,.private_data=&gn};
 gn=(struct nvme_ns){.head=&gh,.disk=&gd,.queue=&queue_a,.ctrl=&gctrl,.flags=1};ginode.i_cdev=&gn.cdev;gf=(struct file){.f_op=&gfo,.inode=&ginode,.f_mode=3};
 gs=(struct xdev_ext_mech_session){.layout={.seg_len=4096,.group_bytes=4096,.frame_size=4096},.pool={.frame_size=4096,.kind=peer?XDEV_EXT_MECH_POOL_PEER:0},.depth=2};
 gst=(struct xdev_ext_mech_stage){.s=&gs,.file=&gf,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.arg0=100,.arg1=64};gu=(struct xdev_ext_mech_stage_uapi){};
 gbp=(struct nvme_xdev_ext_mech_batch){};gb=(struct xdev_ext_mech_batch){.priv=&gbp,.stage=&gst,.bytes=4096,.id=41,.ticket=56,.nr=1,.frames={{.data_len=4096,.kaddr=peer?NULL:gpayload}}};
 memset(gdesc,0,64);gdesc[0]=2;gdesc[40]=100;gdesc[48]=7;
 original_ops=&nvme_xdev_ext_member_ops;go=*original_ops;go.bind=gbinding;go.unbind=gunbinding;go.encode=gencode;go.encode_dptr=gdptr;go.request_init=ginit;go.post=gpost;go.retire_peer=gretire;
}
static struct xdev_ext_stor_stage *gss(void){return gst.priv;}
static void gbind(void){GE("common_bind0",xdev_ext_storfam_bind(&gst,&gu,&go),0);GE("common_native_bind_once",binds,1);GE("common_stage_first_field",gss(),gst.priv);}
static void gadmit(void){GE("common_actual_native_validate0",nvme_xdev_ext_mech_class.validate(&gst,&gb,gdesc,1),0);}
static void gfinish(void){struct xdev_ext_nvme_mech_cqe c;nvme_xdev_ext_mech_class.fill_cqe(&gst,&gb,&c);nvme_xdev_ext_mech_class.unbind(&gst);GE("common_adapter_unbind_once",unbinds,1);GE("common_adapter_clears_priv",gst.priv,NULL);GE("common_resources_balanced",live_allocs,0);}
static void test_common_layout(void){
 GE("common_command_exact64",sizeof(struct xdev_ext_stor_command),64);GC("common_command_alignment8",_Alignof(struct xdev_ext_stor_command)>=8);GE("common_peer_prefix_io_offset0",offsetof(struct xdev_ext_stor_peer_io,io),0);
 gfixture(false);go.post=NULL;GE("common_missing_post_EINVAL",xdev_ext_storfam_bind(&gst,&gu,&go),-EINVAL);GE("common_missing_post_zero_native_bind",binds,0);GE("common_missing_post_no_allocations",live_allocs,0);
 gfixture(true);go.peer_slot_bytes=sizeof(struct xdev_ext_stor_peer_io)-1;GE("common_short_stride_EINVAL",xdev_ext_storfam_bind(&gst,&gu,&go),-EINVAL);GE("common_short_stride_no_bind",binds,0);
 gfixture(true);go.peer_native_offset=0;GE("common_trace_overlaps_prefix_EINVAL",xdev_ext_storfam_bind(&gst,&gu,&go),-EINVAL);GE("common_bad_offset_no_bind",binds,0);
}
static void test_common_host(void){
 gfixture(false);gbind();GE("common_HOST_view_depth2",gss()->poll_views[0].count,2);GE("common_HOST_view_stride_io",gss()->poll_views[0].stride,sizeof(struct xdev_ext_stor_io));GE("common_HOST_view_first_owned",gss()->poll_views[0].first,&gss()->slots[0].done);GE("common_HOST_no_peer_view",gss()->poll_views[1].count,0);
 gadmit();alter_encode=true;GE("common_actual_class_submit0",nvme_xdev_ext_mech_class.submit(&gst,&gb),0);GE("common_class_consumes_encode",encodes,1);GE("common_class_consumes_init",inits,1);GE("common_class_consumes_post",post_hooks,1);GE("common_encode_changes_actual_PDU_nsid11",req.pdu.cmd->common.nsid,11);GC("common_HOST_batch_owns_io",gbp.family.host_io!=NULL);GE("common_HOST_no_peer_io",gbp.family.peer_io,NULL);GE("common_HOST_counter_no_DP",dptrs,0);
 struct xdev_ext_stor_io *io=gbp.family.host_io;GE("common_unbind_busy_false",xdev_ext_storfam_unbind(gss()),false);GE("common_busy_no_native_unbind",unbinds,0);GE("common_busy_keeps_array",gss()->slots!=NULL,true);GE("common_one_native_execute",posts,1);
 req.residual=4096;req.end_io(&req,0);GE("common_endio_known",published_status,0);GE("common_before_consume_busy",io->runtime.busy,true);gfinish();
}
static void test_common_peer(void){
 gfixture(true);gbind();GE("common_PEER_view_depth2",gss()->poll_views[1].count,2);GE("common_PEER_view_native_stride",gss()->poll_views[1].stride,go.peer_slot_bytes);GE("common_PEER_no_host_view",gss()->poll_views[0].count,0);
 gadmit();alter_dptr=true;GE("common_direct_submit0",xdev_ext_storfam_submit(gss(),&gb,&gbp.family),0);GE("common_consumes_DPTR",dptrs,1);GE("common_DPTR_changes_actual_PDU_addr",req.pdu.cmd->rw.dptr.sgl.addr,0x700000);struct xdev_ext_stor_io *io=gbp.family.peer_io;GC("common_PEER_has_io",io!=NULL);GE("common_PEER_native_same_allocation",io->peer_native,(char *)io+go.peer_native_offset);GE("common_PEER_spans_inline",io->spans,((struct xdev_ext_stor_peer_io *)io)->spans);GE("common_PEER_one_real_handle",io->nr_leases,1);
 req.pdu.status=0x81;req.residual=0;req.end_io(&req,0);GE("common_PEER_native_error_UNKNOWN",published_uncertain,true);GE("common_endio_does_not_retire",release_calls,0);xdev_ext_storfam_consume(gss(),&gb,&gbp.family);GE("common_consume_actual_release_false",release_quiesced[0],false);GE("common_consume_native_retire_once",retires,1);GE("common_UNKNOWN_clears_batch_io",gbp.family.peer_io,NULL);GE("common_UNKNOWN_retains_busy_slot",io->runtime.busy,true);GE("common_UNKNOWN_count_clear",io->nr_leases,0);GE("common_UNKNOWN_unbind_false",xdev_ext_storfam_unbind(gss()),false);GE("common_UNKNOWN_no_free_member",unbinds,0);
 /* test-only cleanup after retained-state proof; no recovery claim */
 io->runtime.busy=false;nvme_xdev_ext_mech_class.unbind(&gst);GE("common_retained_teardown_balance",live_allocs,0);
}
/* CREATE refuses a group larger than one native transfer (max_hw_sectors 128 = 64 KiB). */
static void test_common_group_limit(void){
 gfixture(false);gs.layout.group_bytes=65536+4096;gst.arg1=1024;GE("common_HOST_group_over_max_hw_EMSGSIZE",xdev_ext_storfam_bind(&gst,&gu,&go),-EMSGSIZE);GE("common_HOST_group_over_native_bound_once",binds,1);GE("common_HOST_group_over_native_unbound",unbinds,1);GE("common_HOST_group_over_no_priv",gst.priv,NULL);GE("common_HOST_group_over_no_allocations",live_allocs,0);
 gfixture(true);gs.layout.group_bytes=65536+4096;gst.arg1=1024;GE("common_PEER_group_over_max_hw_EMSGSIZE",xdev_ext_storfam_bind(&gst,&gu,&go),-EMSGSIZE);GE("common_PEER_group_over_native_unbound",unbinds,1);GE("common_PEER_group_over_no_allocations",live_allocs,0);
 gfixture(false);gs.layout.group_bytes=65536;gst.arg1=1024;GE("common_HOST_group_at_max_hw_bind0",xdev_ext_storfam_bind(&gst,&gu,&go),0);nvme_xdev_ext_mech_class.unbind(&gst);GE("common_HOST_group_at_max_unbind",unbinds,1);GE("common_HOST_group_at_max_balanced",live_allocs,0);
}
int main(void){test_common_layout();test_common_host();test_common_peer();test_common_group_limit();printf("PASS STOR7B common ownership and wiring %u assertions\n",common_checks);return 0;}
