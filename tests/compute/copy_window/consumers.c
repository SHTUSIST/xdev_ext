/* Must execute actual class consumers. Traces inspect object identity only. */
static void one_consumer(bool dma) {
 struct xdev_ext_mech_session s=session(); struct xdev_ext_mech_batch b=batch();
 struct xdev_ext_mech_stage st={.s=&s,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_stage_uapi u={.arg1=4096};
 struct xdev_ext_ce_copy_desc ce={.frame_off=16,.gpu_off=1024,.len=128};
 struct xdev_ext_dma_copy_desc dm={.frame_off=16,.device_off=1024,.len=128};
 struct xdev_ext_ce_batch cb,cbold; struct xdev_ext_dma_batch db,dbold;
 memset(&cb,0xa5,sizeof(cb)); memcpy(&cbold,&cb,sizeof(cb)); memset(&db,0xa5,sizeof(db)); memcpy(&dbold,&db,sizeof(db));
 memset(&trace,0,sizeof(trace)); nevents=0;
 EQ(dma?xdev_ext_dma_bind(&st,&u):xdev_ext_ce_bind(&st,&u),0);
 EQ(trace.prepare_calls,1); assert(trace.prepared); EQ(trace.prepared->direction,1); EQ(trace.prepared->depth,2); EQ(trace.prepared->group_bytes,1024);
 EQ(dma?xdev_ext_dma_validate(&st,&b,(void *)&dm,1):xdev_ext_ce_validate(&st,&b,(void *)&ce,1),0);
 EQ(trace.validate_calls,1); assert(trace.validated_window==trace.prepared); assert(trace.admitted);
 EQ(trace.admitted->batch_id,91); EQ(trace.admitted->slot,1); EQ(trace.admitted->entry[0].host_byte_off,1104);
 /* Change admitted state through its frozen type, not guessed private fields.
  * A redundant helper plus the old handwritten translation cannot pass. */
 trace.admitted->entry[0].host_byte_off=1600; trace.admitted->entry[0].device_off=1152;
 trace.admitted->entry[0].len=64; trace.admitted->entry[0].flags=3; trace.admitted->total=64;
 memset(&ce,0xff,sizeof(ce)); memset(&dm,0xff,sizeof(dm));
 EQ(dma?xdev_ext_dma_stage_xfers(st.priv,&b,&db):xdev_ext_ce_stage_xfers(st.priv,&b,&cb),0);
 EQ(trace.transfer_calls,1); assert(trace.consumed==trace.admitted);
 if(dma) { EQ(db.n,1); EQ(db.total,64); EQ(db.x[0].host_byte_off,1600); EQ(db.x[0].device_off,1152); EQ(db.x[0].len,64); EQ(db.x[0].flags,3); EQ(db.x[0].owner,b.owner[0]); EQ(db.x[0].generation,b.generation[0]); }
 else { EQ(cb.n,1); EQ(cb.total,64); EQ(cb.x[0].host_byte_off,1600); EQ(cb.x[0].gpu_off,1152); EQ(cb.x[0].len,64); EQ(cb.x[0].flags,3); EQ(cb.x[0].owner,b.owner[0]); EQ(cb.x[0].generation,b.generation[0]); }
 ce=(struct xdev_ext_ce_copy_desc){.frame_off=16,.gpu_off=1024,.len=128}; dm=(struct xdev_ext_dma_copy_desc){.frame_off=16,.device_off=1024,.len=128};
 /* A reused pointer with a different accepted identity must be refused before claims. */
 for(u32 which=0;which<2;which++) {
  b.id=91; b.slot=1; b.claim_calls=0;
  EQ(dma?xdev_ext_dma_validate(&st,&b,(void *)&dm,1):xdev_ext_ce_validate(&st,&b,(void *)&ce,1),0);
  if(which)b.slot=0; else b.id=92;
  EQ(dma?xdev_ext_dma_stage_xfers(st.priv,&b,&db):xdev_ext_ce_stage_xfers(st.priv,&b,&cb),-EPROTO); EQ(b.claim_calls,0);
  EQ(dma?xdev_ext_dma_stage_xfers(st.priv,&b,&db):xdev_ext_ce_stage_xfers(st.priv,&b,&cb),-EPROTO);
 }
 /* Two frames: second claim refusal must not expose the first adapted transfer. */
 b.id=91; b.slot=1; b.nr=2; b.frame[0].data_len=64;
 b.frame[1]=(struct xdev_ext_mech_frame){.index=5,.data_off=32,.data_len=64}; b.owner[1]=19; b.generation[1]=23; b.claim_refuse=1;
 struct xdev_ext_ce_copy_desc ces[2]={{.frame_off=16,.gpu_off=1024,.len=64},{.frame_pos=1,.frame_off=32,.gpu_off=1088,.len=64}};
 struct xdev_ext_dma_copy_desc dms[2]={{.frame_off=16,.device_off=1024,.len=64},{.frame_pos=1,.frame_off=32,.device_off=1088,.len=64}};
 memcpy(&cb,&cbold,sizeof(cb)); memcpy(&db,&dbold,sizeof(db));
 EQ(dma?xdev_ext_dma_validate(&st,&b,(void *)dms,2):xdev_ext_ce_validate(&st,&b,(void *)ces,2),0);
 EQ(dma?xdev_ext_dma_stage_xfers(st.priv,&b,&db):xdev_ext_ce_stage_xfers(st.priv,&b,&cb),-ESTALE);
 if(dma)assert(!memcmp(db.x,dbold.x,sizeof(db.x))); else assert(!memcmp(cb.x,cbold.x,sizeof(cb.x)));
 for(size_t i=0;i<sizeof(b.payload);i++) EQ(b.payload[i],0x5a);
 free(st.priv);
}
static void consumers(void) { one_consumer(false); one_consumer(true); puts("typed consumers: real prepared-window/admitted-plan identity, plan read, saved batch/slot, all-claims-before-adaptation"); }
