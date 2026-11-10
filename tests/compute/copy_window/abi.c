static void abi(void) {
#define TYPE(t) printf("ABI %s.size=%zu align=%zu\n",#t,sizeof(struct t),_Alignof(struct t))
#define FIELD(t,f) printf("ABI %s.%s=%zu\n",#t,#f,offsetof(struct t,f))
#define FIELDS_DESC(t,dev) TYPE(t); FIELD(t,frame_pos); FIELD(t,frame_off); FIELD(t,dev); FIELD(t,len); FIELD(t,flags)
 FIELDS_DESC(xdev_ext_ce_copy_desc,gpu_off); FIELDS_DESC(xdev_ext_dma_copy_desc,device_off);
#define CQE(t,status) TYPE(t); FIELD(t,outcome); FIELD(t,status); FIELD(t,bytes_done); FIELD(t,entries_done); FIELD(t,rsvd)
 CQE(xdev_ext_ce_mech_cqe,backend_status); CQE(xdev_ext_dma_mech_cqe,provider_status);
#define INFO(t,win,seg) TYPE(t); FIELD(t,l); FIELD(t,win); FIELD(t,seg); FIELD(t,max_entry_len); FIELD(t,nr_frames); FIELD(t,rsvd); FIELD(t,f); FIELD(t,window_slot); FIELD(t,window_depth); FIELD(t,lease_generation)
 INFO(xdev_ext_ce_mech_info,gpu_window_len,gpu_seg_size); INFO(xdev_ext_dma_mech_info,window_len,segment_size);
 FIELD(xdev_ext_dma_mech_info,alignment); FIELD(xdev_ext_dma_mech_info,directions);
 TYPE(xdev_ext_mech_layout); FIELD(xdev_ext_mech_layout,frame_size); FIELD(xdev_ext_mech_layout,hdr_room); FIELD(xdev_ext_mech_layout,seg_len); FIELD(xdev_ext_mech_layout,group_bytes);
 TYPE(xdev_ext_mech_frame_info); FIELD(xdev_ext_mech_frame_info,umem_addr); FIELD(xdev_ext_mech_frame_info,data_off); FIELD(xdev_ext_mech_frame_info,data_len);
 TYPE(xdev_ext_binding_ctx_v2); FIELD(xdev_ext_binding_ctx_v2,abi_version); FIELD(xdev_ext_binding_ctx_v2,ctx_size); FIELD(xdev_ext_binding_ctx_v2,event); FIELD(xdev_ext_binding_ctx_v2,backend); FIELD(xdev_ext_binding_ctx_v2,current_stage); FIELD(xdev_ext_binding_ctx_v2,direction); FIELD(xdev_ext_binding_ctx_v2,frame_state); FIELD(xdev_ext_binding_ctx_v2,capabilities); FIELD(xdev_ext_binding_ctx_v2,allowed_recipe_mask); FIELD(xdev_ext_binding_ctx_v2,allowed_next_mask); FIELD(xdev_ext_binding_ctx_v2,allowed_profile_mask); FIELD(xdev_ext_binding_ctx_v2,reserved0); FIELD(xdev_ext_binding_ctx_v2,request_id); FIELD(xdev_ext_binding_ctx_v2,chain_id); FIELD(xdev_ext_binding_ctx_v2,endpoint_id); FIELD(xdev_ext_binding_ctx_v2,src_buffer_id); FIELD(xdev_ext_binding_ctx_v2,dst_buffer_id); FIELD(xdev_ext_binding_ctx_v2,src_offset); FIELD(xdev_ext_binding_ctx_v2,dst_offset); FIELD(xdev_ext_binding_ctx_v2,logical_offset); FIELD(xdev_ext_binding_ctx_v2,length); FIELD(xdev_ext_binding_ctx_v2,bytes_done); FIELD(xdev_ext_binding_ctx_v2,result); FIELD(xdev_ext_binding_ctx_v2,reserved1);
 TYPE(xdev_ext_mech_ctx); FIELD(xdev_ext_mech_ctx,base); FIELD(xdev_ext_mech_ctx,mech_abi_version); FIELD(xdev_ext_mech_ctx,member); FIELD(xdev_ext_mech_ctx,class_id); FIELD(xdev_ext_mech_ctx,callsite); FIELD(xdev_ext_mech_ctx,nr_frames); FIELD(xdev_ext_mech_ctx,desc_cap); FIELD(xdev_ext_mech_ctx,session_id); FIELD(xdev_ext_mech_ctx,batch_id);
#define XFER(t,dev) TYPE(t); FIELD(t,owner); FIELD(t,generation); FIELD(t,host_byte_off); FIELD(t,dev); FIELD(t,len); FIELD(t,flags)
 XFER(xdev_ext_ce_xfer,gpu_off); XFER(xdev_ext_dma_xfer,device_off);
#define OPS(t) TYPE(t); FIELD(t,owner); FIELD(t,fops); FIELD(t,bind_region); FIELD(t,unbind_region); FIELD(t,bind_host); FIELD(t,unbind_host); FIELD(t,submit)
 OPS(xdev_ext_ce_backend_ops); FIELD(xdev_ext_ce_backend_ops,progress); OPS(xdev_ext_dma_provider_ops); FIELD(xdev_ext_dma_provider_ops,poll);
#define BPFOPS(t) TYPE(t); FIELD(t,abi_version); FIELD(t,flags); FIELD(t,prepare); FIELD(t,build); FIELD(t,complete); FIELD(t,compute)
 BPFOPS(xdev_ext_ce_mech_ops); BPFOPS(xdev_ext_dma_mech_ops);
 printf("ABI versions=%u,%u,%u class=%u,%u\n",XDEV_EXT_MECH_ABI_VERSION,XDEV_EXT_CE_MECH_ABI_VERSION,XDEV_EXT_DMA_MECH_ABI_VERSION,XDEV_EXT_MECH_CLASS_CE,XDEV_EXT_MECH_CLASS_DMA);
}
