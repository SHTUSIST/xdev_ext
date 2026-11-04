/* SPDX-License-Identifier: GPL-2.0 */
/* Literal contract assertions. Never compute an expected result with production rules. */
static unsigned checks;
#define CK(name,expr) do { checks++; if(!(expr)){fprintf(stderr,"ASSERTION %s line%d\n",name,__LINE__);exit(1);} }while(0)
#define EQ(name,a,b) CK(name,(a)==(b))
static void clear_observers(void){event_count=0;events[0]=0;plan_calls=0;plan_errno=123;rq_allocs=rq_frees=posts=0;allocated_queue=polled_queue=NULL;poll_count=0;dead_errno=0;}
static struct blk_mq_tag_set tags={.nr_maps=3,.map={[2]={.nr_queues=1}}};
static struct request_queue queue_a,queue_b;
static struct pci_dev pci_a,pci_decoy;
static struct nvme_ctrl_ops ctrl_ops;
static struct nvme_ctrl ctrl;
static struct nvme_ns_head nshead;
static struct gendisk disk;
static struct nvme_ns ns;
static struct inode inode;
static struct file_operations fops={.uring_cmd=nvme_ns_chr_uring_cmd};
static struct file file;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_stage_uapi uapi;
static struct xdev_ext_mech_batch batch;
static struct nvme_xdev_ext_mech_batch private_batch;
static u8 sqe[64];
static void fixture(void){
 CK("previous_fixture_no_allocations",live_allocs==0);
 clear_observers();alloc_call=alloc_fail=0;effects_allowed=1;tag_errno=0;append_errno=0;force_unpolled=false;poll_negative_key=-1;
 queue_a=(struct request_queue){.limits={.features=1},.tag_set=&tags,.max_segments=8,.max_segment_size=4096,.max_hw_sectors=128,.id=10};queue_b=queue_a;queue_b.id=20;
 pci_a=(struct pci_dev){.dev={.pci=true,.marker=71}};pci_decoy=(struct pci_dev){.dev={.pci=true,.marker=93}};
 ctrl_ops=(struct nvme_ctrl_ops){.name="pcie",.peer_rw=(void *)1};ctrl=(struct nvme_ctrl){.dev=&pci_a.dev,.device=&pci_decoy.dev,.ops=&ctrl_ops,.sgl=true,.state=1};
 nshead=(struct nvme_ns_head){.lba_shift=9,.ns_id=7};nshead.ids.eui64[0]=11;nshead.ids.nguid[0]=22;nshead.ids.uuid[0]=33;
 disk=(struct gendisk){.capacity=4096,.diskseq=23};ns=(struct nvme_ns){.head=&nshead,.disk=&disk,.queue=&queue_a,.ctrl=&ctrl,.flags=1};inode.i_cdev=&ns.cdev;
 file=(struct file){.f_op=&fops,.inode=&inode,.f_mode=3};session=(struct xdev_ext_mech_session){.layout={.seg_len=4096,.group_bytes=4096,.frame_size=4096},.pool={.frame_size=4096},.depth=2};
 stage=(struct xdev_ext_mech_stage){.s=&session,.file=&file,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.arg0=100,.arg1=64};uapi=(struct xdev_ext_mech_stage_uapi){};
 private_batch=(struct nvme_xdev_ext_mech_batch){};batch=(struct xdev_ext_mech_batch){.priv=&private_batch,.stage=&stage,.bytes=4096,.id=41,.ticket=56,.nr=1,.frames={{.index=0,.data_len=4096}}};
 memset(sqe,0,sizeof(sqe));sqe[0]=2;sqe[40]=100;sqe[48]=7;
}
static void bind_ok(void){EQ("bind_success",nvme_xdev_ext_class_bind(&stage,&uapi),0);CK("bind_publishes_priv",stage.priv!=NULL);}
static void unbind_ok(void){nvme_xdev_ext_class_unbind(&stage);EQ("unbind_clears_priv",stage.priv,NULL);EQ("unbind_balances_allocations",live_allocs,0);}
static void validate_ok(void){EQ("validate_success",nvme_xdev_ext_class_validate(&stage,&batch,sqe,1),0);}
static void test_bind_order(void){
 fixture();uapi.flags=1;file.f_op=NULL;EQ("flags_precede_namespace",nvme_xdev_ext_class_bind(&stage,&uapi),-EINVAL);EQ("bad_flags_zero_alloc",alloc_call,0);CK("bad_flags_zero_inode",!strchr(events,'N'));
 fixture();stage.direction=0;EQ("direction_EINVAL",nvme_xdev_ext_class_bind(&stage,&uapi),-EINVAL);
 fixture();file.f_op=NULL;stage.poll=true;EQ("namespace_EOPNOTSUPP",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);EQ("namespace_zero_alloc",alloc_call,0);
 fixture();stage.poll=true;queue_a.limits.features=0;ctrl_ops.name="tcp";file.f_mode=0;effects_allowed=0;EQ("poll_precedes_transport_mode_effects",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);CK("poll_zero_effects",!strchr(events,'E'));EQ("poll_zero_alloc",alloc_call,0);
 fixture();stage.poll=true;queue_a.limits.features=0;EQ("poll_capability_alone",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);EQ("poll_capability_zero_alloc",alloc_call,0);
 fixture();ctrl_ops.name="tcp";file.f_mode=0;effects_allowed=0;EQ("strict_transport_precedes_mode_effects",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);CK("transport_zero_effects",!strchr(events,'E'));
 fixture();ctrl.sgl=false;EQ("strict_host_SGL_required",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);
 fixture();queue_a.virt_boundary=4095;EQ("strict_host_boundary_required",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);
 fixture();session.pool.kind=XDEV_EXT_MECH_POOL_PEER;ctrl_ops.peer_rw=NULL;file.f_mode=0;effects_allowed=0;EQ("peer_capability_before_readmode",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);CK("peer_capability_zero_effects",!strchr(events,'E'));
 fixture();session.pool.kind=XDEV_EXT_MECH_POOL_PEER;file.f_mode=0;effects_allowed=0;EQ("peer_readmode_before_effects",nvme_xdev_ext_class_bind(&stage,&uapi),-EBADF);CK("peer_mode_zero_effects",!strchr(events,'E'));
 fixture();stage.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;file.f_mode=1;effects_allowed=0;EQ("writemode_before_effects",nvme_xdev_ext_class_bind(&stage,&uapi),-EBADF);CK("write_mode_zero_effects",!strchr(events,'E'));
 fixture();effects_allowed=0;alloc_fail=1;EQ("effects_before_alloc",nvme_xdev_ext_class_bind(&stage,&uapi),-EACCES);EQ("effects_zero_alloc",alloc_call,0);
 fixture();alloc_fail=1;EQ("member_alloc_ENOMEM",nvme_xdev_ext_class_bind(&stage,&uapi),-ENOMEM);EQ("member_alloc_no_leak",live_allocs,0);EQ("member_alloc_no_publish",stage.priv,NULL);
 fixture();ns.head=NULL;EQ("capture_missing_head_ENODEV",nvme_xdev_ext_class_bind(&stage,&uapi),-ENODEV);EQ("capture_member_freed",live_allocs,0);CK("capture_alloc_free_order",strcmp(events,"NEAF")==0);EQ("capture_no_publish",stage.priv,NULL);
 fixture();nshead.lba_shift=8;EQ("capture_shift_EINVAL",nvme_xdev_ext_class_bind(&stage,&uapi),-EINVAL);EQ("capture_shift_no_leak",live_allocs,0);
 fixture();stage.arg1=7;EQ("window_ERANGE",nvme_xdev_ext_class_bind(&stage,&uapi),-ERANGE);EQ("window_member_freed",live_allocs,0);EQ("window_no_publish",stage.priv,NULL);
 fixture();ns.flags=0;EQ("native_namespace_permission_ENODEV",nvme_xdev_ext_class_bind(&stage,&uapi),-ENODEV);EQ("namespace_permission_no_leak",live_allocs,0);
 for(int fail=2;fail<=4;fail++){fixture();alloc_fail=fail;EQ("host_create_resource_failure_ENOMEM",nvme_xdev_ext_class_bind(&stage,&uapi),-ENOMEM);EQ("host_partial_create_no_leak",live_allocs,0);EQ("host_partial_create_no_priv",stage.priv,NULL);}
 fixture();stage.poll=true;watch_count=6;watch_length=0;watch_trace[0]=0;
 watch_functions[0]=(void *)nvme_xdev_ext_class_ns;watch_codes[0]='N';
 watch_functions[1]=(void *)xdev_ext_stor_block_poll_capable;watch_codes[1]='P';
 watch_functions[2]=(void *)nvme_ctrl_sgl_supported;watch_codes[2]='S';
 watch_functions[3]=(void *)queue_virt_boundary;watch_codes[3]='V';
 watch_functions[4]=(void *)nvme_xdev_ext_mech_cmd_allowed;watch_codes[4]='E';
 watch_functions[5]=(void *)zalloc;watch_codes[5]='A';
 bind_ok();watch_count=0;CK("native_authorization_function_order",strcmp(watch_trace,"NPSVEAAAA")==0);unbind_ok();
 fixture();bind_ok();struct nvme_xdev_ext_mech_stage *p=stage.priv;EQ("window_slba100",p->window.slba,100);EQ("window_nlb64",p->window.nlb,64);EQ("window_capacity4096",p->window.capacity_lbas,4096);EQ("window_shift9",p->window.lba_shift,9);EQ("host_resources_depth2",p->nr_slots,2);EQ("host_native_alloc_count4",alloc_call,4);EQ("namespace_borrowed_pointer",p->ns,&ns);EQ("head_borrowed_pointer",p->head,&nshead);EQ("disk_borrowed_pointer",p->disk,&disk);EQ("queue_snapshot_pointer",p->queue,&queue_a);unbind_ok();
}
static void test_validate(void){
 fixture();bind_ok();validate_ok();EQ("validated_published",private_batch.validated,true);EQ("admitted_sqe_all64",memcmp(private_batch.sqe,sqe,64),0);EQ("admitted_slba100",private_batch.rw.slba,100);EQ("admitted_nlb8",private_batch.rw.nlb,8);EQ("admitted_byteoffset51200",private_batch.rw.byte_offset,51200);EQ("admitted_bytelength4096",private_batch.rw.byte_length,4096);EQ("admitted_read0",private_batch.rw.write,0);EQ("admitted_batchid41",private_batch.batch_id,41);EQ("plan_trace_once",plan_calls,1);
 for(int n=0;n<=2;n+=2){private_batch.validated=true;clear_observers();sqe[1]=1;EQ("count_EPROTO_before_schema",nvme_xdev_ext_class_validate(&stage,&batch,sqe,n),-EPROTO);EQ("count_clears_validated",private_batch.validated,false);EQ("count_no_plan_trace",plan_calls,0);sqe[1]=0;}
 const int forbidden[]={1,2,4,8,12,16,24,32,50,51,52,56,60,63};
 for(unsigned i=0;i<ARRAY_SIZE(forbidden);i++){int pos=forbidden[i];clear_observers();sqe[pos]=1;private_batch.validated=true;EQ("forbidden_sqe_EPERM",nvme_xdev_ext_class_validate(&stage,&batch,sqe,1),-EPERM);EQ("forbidden_no_publish",private_batch.validated,false);EQ("forbidden_trace_once",plan_calls,1);EQ("forbidden_trace_errno",plan_errno,-EPERM);EQ("forbidden_keeps_previous_record",private_batch.sqe[pos],0);sqe[pos]=0;}
 clear_observers();sqe[0]=1;EQ("wrong_opcode_EOPNOTSUPP",nvme_xdev_ext_class_validate(&stage,&batch,sqe,1),-EOPNOTSUPP);EQ("wrong_opcode_trace_once",plan_calls,1);sqe[0]=2;
 sqe[40]=157;EQ("window_past_end_ERANGE",nvme_xdev_ext_class_validate(&stage,&batch,sqe,1),-ERANGE);EQ("window_no_validate_publish",private_batch.validated,false);sqe[40]=100;
 batch.bytes=512;EQ("payload_mismatch_EMSGSIZE",nvme_xdev_ext_class_validate(&stage,&batch,sqe,1),-EMSGSIZE);EQ("payload_no_validate_publish",private_batch.validated,false);batch.bytes=4096;
 validate_ok();sqe[40]=101;EQ("caller_scratch_not_retained",private_batch.sqe[40],100);unbind_ok();
}
static void test_gate_and_identity(void){
 fixture();bind_ok();struct nvme_xdev_ext_mech_stage *p=stage.priv;
 ns.queue=NULL;private_batch.validated=false;atomic_set(&p->dead,1);clear_observers();EQ("dead_before_validated_identity",nvme_xdev_ext_class_submit(&stage,&batch),-ENODEV);EQ("dead_zero_native_alloc",rq_allocs,0);EQ("dead_no_stage_dead_callback",dead_errno,0);
 atomic_set(&p->dead,0);EQ("validated_before_identity",nvme_xdev_ext_class_submit(&stage,&batch),-EPROTO);EQ("invalidated_no_identity_callback",dead_errno,0);
 ns.queue=&queue_a;validate_ok();batch.id=42;ns.queue=NULL;EQ("old_batchid_before_identity",nvme_xdev_ext_class_submit(&stage,&batch),-EPROTO);EQ("old_batchid_zero_alloc",rq_allocs,0);batch.id=41;ns.queue=&queue_a;ns.disk=NULL;
 EQ("identity_missing_disk_ENODEV",nvme_xdev_ext_class_submit(&stage,&batch),-ENODEV);EQ("identity_ENODEV_marks_dead",atomic_read(&p->dead),1);EQ("identity_errno_to_stage_dead",dead_errno,-ENODEV);ns.disk=&disk;EQ("dead_after_identity_failure",nvme_xdev_ext_class_submit(&stage,&batch),-ENODEV);unbind_ok();
 fixture();bind_ok();validate_ok();p=stage.priv;ns.queue=&queue_b;clear_observers();EQ("queue_pointer_drift_ESTALE",nvme_xdev_ext_class_submit(&stage,&batch),-ESTALE);EQ("queue_drift_marks_dead",atomic_read(&p->dead),1);EQ("queue_drift_zero_alloc",rq_allocs,0);unbind_ok();
 fixture();bind_ok();validate_ok();p=stage.priv;struct nvme_ns_head head2=nshead;ns.head=&head2;EQ("head_pointer_drift_ESTALE",nvme_xdev_ext_class_submit(&stage,&batch),-ESTALE);unbind_ok();
 fixture();bind_ok();validate_ok();struct gendisk disk2=disk;ns.disk=&disk2;EQ("disk_pointer_drift_ESTALE",nvme_xdev_ext_class_submit(&stage,&batch),-ESTALE);unbind_ok();
 /* Every captured identity value is checked through the actual recheck consumer. */
 for(unsigned i=0;i<13;i++){fixture();bind_ok();validate_ok();p=stage.priv;
 switch(i){case 0:nshead.ns_id++;break;case 1:nshead.lba_shift++;break;case 2:ns.flags=0;break;case 3:ns.flags|=2;break;case 4:nshead.ids.csi++;break;case 5:nshead.ms++;break;case 6:nshead.pi_size++;break;case 7:nshead.pi_type++;break;case 8:disk.capacity++;break;case 9:disk.diskseq++;break;case 10:nshead.ids.eui64[0]++;break;case 11:nshead.ids.nguid[0]++;break;case 12:nshead.ids.uuid[0]++;break;}
 clear_observers();EQ("identity_value_drift_ESTALE",nvme_xdev_ext_class_submit(&stage,&batch),-ESTALE);EQ("identity_ESTALE_marks_dead",atomic_read(&p->dead),1);EQ("identity_drift_zero_alloc",rq_allocs,0);unbind_ok();}
}
static void test_queue_consumers(void){
 fixture();bind_ok();validate_ok();clear_observers();tag_errno=-EAGAIN;EQ("native_tag_errno_preserved",nvme_xdev_ext_class_submit(&stage,&batch),-EAGAIN);EQ("native_alloc_uses_real_queue",allocated_queue,&queue_a);EQ("native_tag_zero_map_post",posts,0);EQ("native_tag_not_freed",rq_frees,0);unbind_ok();
 fixture();stage.poll=true;bind_ok();validate_ok();clear_observers();force_unpolled=true;EQ("poll_check_EOPNOTSUPP",nvme_xdev_ext_class_submit(&stage,&batch),-EOPNOTSUPP);CK("poll_check_before_init_slot_map",strcmp(events,"RQ")==0);EQ("poll_failure_free_once",rq_frees,1);EQ("poll_failure_zero_post",posts,0);EQ("poll_failure_zero_slot",private_batch.slot,NULL);unbind_ok();
 fixture();stage.poll=true;bind_ok();validate_ok();clear_observers();ctrl.state=0;disk.ro=true;EQ("host_no_new_live_readonly_policy",nvme_xdev_ext_class_submit(&stage,&batch),0);CK("host_issue_order",strcmp(events,"RIMBSX")==0);EQ("host_one_native_post",posts,1);EQ("host_polled_opf",req.cmd_flags&REQ_POLLED,REQ_POLLED);EQ("host_snapshot_sqe_native_opcode",last_command.bytes[0],2);EQ("host_native_nsid7",last_command.rw.nsid,7);EQ("host_native_slba100",last_command.rw.slba,100);EQ("host_native_zero_based_nlb7",last_command.rw.length,7);EQ("host_poll_armed",private_batch.slot->done.poll_live,true);EQ("host_captured_ticket56",private_batch.slot->done.ticket,56);nvme_xdev_ext_class_slot_put(&stage,&private_batch);unbind_ok();
 fixture();bind_ok();validate_ok();queue_a.max_hw_sectors=7;clear_observers();EQ("map_runtime_caps_EMSGSIZE",nvme_xdev_ext_class_submit(&stage,&batch),-EMSGSIZE);EQ("map_failure_free_once",rq_frees,1);EQ("map_failure_slot_cleared",private_batch.slot,NULL);EQ("map_failure_zero_post",posts,0);unbind_ok();
 fixture();bind_ok();validate_ok();struct nvme_xdev_ext_mech_stage *p=stage.priv;struct nvme_xdev_ext_mech_slot *slot=nvme_xdev_ext_class_slot_get(&stage,&private_batch);CK("direct_map_slot_real",!IS_ERR(slot));ns.queue=&queue_b;queue_b.max_hw_sectors=7;EQ("map_consumes_current_queue",nvme_xdev_ext_class_map(&stage,&batch,&req,&private_batch),-EMSGSIZE);queue_b.max_hw_sectors=128;EQ("map_queue_change_changes_output",nvme_xdev_ext_class_map(&stage,&batch,&req,&private_batch),0);EQ("map_attaches_actual_bio",req.bio,p->slots[1].bio);nvme_xdev_ext_class_slot_put(&stage,&private_batch);unbind_ok();
}
static void test_peer_resources_requester(void){
 fixture();session.pool.kind=XDEV_EXT_MECH_POOL_PEER;bind_ok();struct nvme_xdev_ext_mech_stage *p=stage.priv;EQ("peer_exact_native_requester",p->peer->dma_dev,&pci_a.dev);CK("peer_not_controller_class_device",p->peer->dma_dev!=ctrl.device);EQ("peer_original_depth2",p->peer->nr_slots,2);EQ("peer_original_maxpieces2",p->peer->max_pieces,2);EQ("peer_original_lists8192",p->peer->sgl_bytes,8192);EQ("peer_native_alloc_count5",alloc_call,5);EQ("peer_no_host_array",p->slots,NULL);unbind_ok();
 fixture();session.pool.kind=XDEV_EXT_MECH_POOL_PEER;pci_a.dev.pci=false;EQ("peer_nonPCI_original_EOPNOTSUPP",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);EQ("peer_nonPCI_unwind_no_leak",live_allocs,0);EQ("peer_nonPCI_no_publish",stage.priv,NULL);
 for(int fail=2;fail<=5;fail++){fixture();session.pool.kind=XDEV_EXT_MECH_POOL_PEER;alloc_fail=fail;EQ("peer_resource_failure_ENOMEM",nvme_xdev_ext_class_bind(&stage,&uapi),-ENOMEM);EQ("peer_partial_create_no_leak",live_allocs,0);EQ("peer_partial_create_no_priv",stage.priv,NULL);}
 fixture();bind_ok();p=stage.priv;p->slots[0].runtime.busy=true;nvme_xdev_ext_class_unbind(&stage);EQ("busy_host_retains_member",stage.priv,p);EQ("busy_host_retains_allocations",live_allocs,4);p->slots[0].runtime.busy=false;unbind_ok();
 fixture();session.pool.kind=XDEV_EXT_MECH_POOL_PEER;bind_ok();p=stage.priv;p->peer->slots[0].runtime.busy=true;nvme_xdev_ext_class_unbind(&stage);EQ("busy_peer_retains_member",stage.priv,p);EQ("busy_peer_retains_allocations",live_allocs,5);p->peer->slots[0].runtime.busy=false;unbind_ok();
}
static void test_poll_views(void){
 fixture();bind_ok();struct nvme_xdev_ext_mech_stage *p=stage.priv;p->peer=zalloc(sizeof(*p->peer));p->peer->nr_slots=3;p->peer->slots=zalloc(3*sizeof(*p->peer->slots));
 p->slots[0].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=9};p->slots[1].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=4};p->peer->slots[0].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=4};p->peer->slots[1].done=(struct xdev_ext_stor_completion){.poll_live=false,.poll_queue=99};p->peer->slots[2].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=7};
 clear_observers();poll_negative_key=4;ns.queue=&queue_b;EQ("class_poll_positive_only_sum2",nvme_xdev_ext_class_poll(&stage),2);EQ("class_poll_current_real_queue",polled_queue,&queue_b);EQ("dualview_dedup_count3",poll_count,3);EQ("dualview_host_first_key9",poll_keys[0],9);EQ("dualview_host_second_key4",poll_keys[1],4);EQ("dualview_peer_stride_key7",poll_keys[2],7);unbind_ok();
 /* Real common block poll with unlike owner strides and >64 unique live keys. */
 struct host_owner {u64 prefix;struct xdev_ext_stor_completion done;u8 suffix[3];} host[64]={0};
 struct peer_owner {u8 prefix[19];struct xdev_ext_stor_completion done;u8 suffix[73];} peer[4]={0};
 for(unsigned i=0;i<64;i++)host[i].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=i};
 peer[0].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=64};peer[1].done=peer[0].done;peer[2].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=0};peer[3].done=(struct xdev_ext_stor_completion){.poll_live=false,.poll_queue=81};
 struct xdev_ext_stor_poll_view views[]={{.first=&host[0].done,.stride=sizeof(host[0]),.count=64},{.first=&peer[0].done,.stride=sizeof(peer[0]),.count=4}};
 clear_observers();poll_negative_key=-1;EQ("seen64_overflow_sum66",xdev_ext_stor_block_poll(&queue_a,views,2),66);EQ("seen64_overflow_calls66",poll_count,66);EQ("seen64_unrecorded_first",poll_keys[64],64);EQ("seen64_unrecorded_repeated",poll_keys[65],64);EQ("seen64_recorded_zero_not_repolled",poll_keys[63],63);
}
int main(void){test_bind_order();test_validate();test_gate_and_identity();test_queue_consumers();test_peer_resources_requester();test_poll_views();printf("PASS native_member_7a %u literal assertions\n",checks);return 0;}
