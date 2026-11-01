/* Literal expectations are frozen from compute-copy-typed-v1. */
static struct xdev_ext_mech_session session(void) {
 struct xdev_ext_mech_session s={0}; s.depth=2; s.layout.group_bytes=1024;
 s.pool=(struct xdev_ext_mech_pool){.pages=(void *)1,.nr_pages=2,.first_page_off=64,.frame_size=512,.nr_frames=8}; return s;
}
static struct xdev_ext_mech_batch batch(void) {
 struct xdev_ext_mech_batch b={.id=91,.slot=1,.nr=1,.claim_refuse=-1};
 b.frame[0]=(struct xdev_ext_mech_frame){.umem_addr=0x1000,.data_off=16,.data_len=128,.index=2};
 b.owner[0]=0x1020304050607080ULL; b.generation[0]=0x8877665544332211ULL;
 memset(b.payload,0x5a,sizeof(b.payload)); return b;
}
static void init_geom(struct xdev_ext_ce_geom *c,struct xdev_ext_dma_geom *d) {
 EQ(xdev_ext_ce_geom_init(c,4096,4096,0,4096,8192,64,512,8),0);
 EQ(xdev_ext_dma_geom_init(d,4096,4096,0,4096,8192,64,512,8,1,XDEV_EXT_WINDOW_COPY_DIRS),0);
}
static void pure_baseline(void) {
 struct xdev_ext_ce_geom c; struct xdev_ext_dma_geom g; init_geom(&c,&g);
 struct xdev_ext_mech_frame_info f[2]={{.data_off=16,.data_len=128}};
 u32 ix[2]={2,3};
 struct xdev_ext_ce_copy_desc cd[2]={{.frame_off=16,.gpu_off=1024,.len=128}};
 struct xdev_ext_dma_copy_desc dd[2]={{.frame_off=16,.device_off=1024,.len=128}};
 struct xdev_ext_ce_plan cp; struct xdev_ext_dma_plan dp, before;
 memset(&cp,0xa5,sizeof(cp)); memset(&dp,0xa5,sizeof(dp));
 EQ(xdev_ext_ce_plan_check(&c,f,ix,1,cd,1,&cp),0); EQ(cp.total,128); EQ(cp.n,1); EQ(cp.host_off[0],1104);
 EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,1,&dp),0); EQ(dp.total,128); EQ(dp.n,1); EQ(dp.host_off[0],1104);
 /* Later refusal preserves CE's earlier offset write, DMA preserves all bytes. */
 cd[0].len=64; dd[0].len=64; cd[1]=(struct xdev_ext_ce_copy_desc){.frame_off=80,.gpu_off=1088,.len=64,.flags=0x80000000};
 dd[1]=(struct xdev_ext_dma_copy_desc){.frame_off=80,.device_off=1088,.len=64,.flags=0x80000000};
 memset(&cp,0xa5,sizeof(cp)); memset(&dp,0xa5,sizeof(dp)); memcpy(&before,&dp,sizeof(dp));
 EQ(xdev_ext_ce_plan_check(&c,f,ix,1,cd,2,&cp),-EOPNOTSUPP); EQ(cp.host_off[0],1104); EQ(cp.host_off[1],0xa5a5a5a5a5a5a5a5ULL); EQ(cp.total,0xa5a5a5a5a5a5a5a5ULL);
 EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,2,&dp),-EOPNOTSUPP); assert(!memcmp(&dp,&before,sizeof(dp)));
 /* Flags precede max-length; coverage precedes device; segment precedes host/alignment. */
 dd[0]=(struct xdev_ext_dma_copy_desc){.frame_off=16,.device_off=1024,.len=128,.flags=0x80000000}; g.max_entry_len=64;
 EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,1,&dp),-EOPNOTSUPP);
 dd[0].flags=0; EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,1,&dp),-EMSGSIZE);
 g.max_entry_len=4096; dd[0].frame_off=17; dd[0].device_off=UINT64_MAX;
 EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,1,&dp),-EINVAL);
 dd[0].frame_off=16; dd[0].device_off=960; g.segment_size=1024; ix[0]=99; g.alignment=256;
 EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,1,&dp),-EXDEV);
 g.segment_size=0; EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,1,&dp),-ERANGE);
 ix[0]=2; EQ(xdev_ext_dma_plan_check(&g,f,ix,1,1,dd,1,&dp),-EINVAL);
 g.alignment=1; g.directions=1U<<XDEV_EXT_MECH_DIR_FROM_DEVICE;
 EQ(xdev_ext_dma_plan_check(&g,f,ix,1,XDEV_EXT_MECH_DIR_TO_DEVICE,dd,1,&dp),-EOPNOTSUPP);
 EQ(xdev_ext_ce_plan_check(&c,f,ix,1,cd,1,&cp),-ENODATA);
 EQ(xdev_ext_dma_geom_init(&g,4096,4096,0,4096,8192,64,512,8,3,6),-EINVAL);
 puts("baseline pure: offset=1104 total=128 CE-partial/DMA-transactional order preserved");
}
static void bind_baseline(void) {
 struct xdev_ext_mech_session s=session(); struct xdev_ext_mech_stage st={.s=&s,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_stage_uapi u={.arg1=4096};
 nevents=0; EQ(xdev_ext_ce_bind(&st,&u),0); EQ(nevents,4); EQ(events[0],0); EQ(events[1],1); EQ(events[2],2); EQ(events[3],3); free(st.priv);
 st.priv=NULL; nevents=0; EQ(xdev_ext_dma_bind(&st,&u),0); EQ(nevents,5); EQ(events[0],0); EQ(events[1],4); EQ(events[2],3); EQ(events[3],1); EQ(events[4],2); free(st.priv);
 /* Bind capacity refuses before host entry; DMA direction refusal precedes capacity. */
 s.depth=5; st.priv=NULL; nevents=0; EQ(xdev_ext_ce_bind(&st,&u),-ENOSPC); EQ(nevents,2); free(st.priv);
 native_directions=1U<<XDEV_EXT_MECH_DIR_FROM_DEVICE; st.priv=NULL; nevents=0; EQ(xdev_ext_dma_bind(&st,&u),-EOPNOTSUPP); EQ(nevents,4); free(st.priv);
 native_directions=XDEV_EXT_WINDOW_COPY_DIRS; native_alignment=3; st.priv=NULL; nevents=0; EQ(xdev_ext_dma_bind(&st,&u),-EINVAL); EQ(nevents,4); free(st.priv); native_alignment=1;
 u.flags=1; nevents=0; EQ(xdev_ext_ce_bind(&st,&u),-EINVAL); EQ(xdev_ext_dma_bind(&st,&u),-EINVAL); EQ(nevents,0);
 puts("baseline bind: CE native-region→geometry/window→host→lease; DMA scope/lease→region→geometry/direction/window→host");
}
static void consumer_baseline(void) {
 struct xdev_ext_mech_session s=session(); struct xdev_ext_mech_batch b=batch();
 struct xdev_ext_ce_stage c={0}; struct xdev_ext_dma_stage d={0}; init_geom(&c.geom,&d.geom);
 struct xdev_ext_mech_stage cs={.priv=&c,.s=&s,.direction=1}, ds={.priv=&d,.s=&s,.direction=1};
 struct xdev_ext_ce_copy_desc cd={.frame_off=16,.gpu_off=1024,.len=128};
 struct xdev_ext_dma_copy_desc dd={.frame_off=16,.device_off=1024,.len=128};
 struct xdev_ext_ce_batch cb={0}; struct xdev_ext_dma_batch db={0};
#ifdef HAVE_TYPED
 /* Modern bind is independently tested; baseline fixtures need its admitted window too. */
 nevents=0; EQ(xdev_ext_ce_bind(&cs,&(struct xdev_ext_mech_stage_uapi){.arg1=4096}),0);
 nevents=0; EQ(xdev_ext_dma_bind(&ds,&(struct xdev_ext_mech_stage_uapi){.arg1=4096}),0);
#endif
 EQ(xdev_ext_ce_validate(&cs,&b,(void *)&cd,1),0);
 EQ(xdev_ext_ce_stage_xfers(cs.priv,&b,&cb),0); EQ(cb.n,1); EQ(cb.total,128); EQ(cb.x[0].host_byte_off,1104); EQ(cb.x[0].gpu_off,1024); EQ(cb.x[0].owner,b.owner[0]); EQ(cb.x[0].generation,b.generation[0]);
 EQ(xdev_ext_dma_validate(&ds,&b,(void *)&dd,1),0);
 EQ(xdev_ext_dma_stage_xfers(ds.priv,&b,&db),0); EQ(db.n,1); EQ(db.total,128); EQ(db.x[0].host_byte_off,1104); EQ(db.x[0].device_off,1024); EQ(db.x[0].owner,b.owner[0]); EQ(db.x[0].generation,b.generation[0]);
 EQ(xdev_ext_ce_stage_xfers(cs.priv,&b,&cb),-EPROTO); EQ(xdev_ext_dma_stage_xfers(ds.priv,&b,&db),-EPROTO);
 ((struct xdev_ext_ce_stage *)cs.priv)->dead=true; ((struct xdev_ext_dma_stage *)ds.priv)->dead=true;
 EQ(xdev_ext_ce_stage_xfers(cs.priv,&b,&cb),-ENODEV); EQ(xdev_ext_dma_stage_xfers(ds.priv,&b,&db),-ENODEV);
 ((struct xdev_ext_ce_stage *)cs.priv)->dead=false; ((struct xdev_ext_dma_stage *)ds.priv)->dead=false;
 b.frame_error=-EFAULT; EQ(xdev_ext_ce_validate(&cs,&b,(void *)&cd,33),-E2BIG); EQ(xdev_ext_dma_validate(&ds,&b,(void *)&dd,33),-E2BIG);
 EQ(xdev_ext_ce_validate(&cs,&b,(void *)&cd,1),-EFAULT); EQ(xdev_ext_dma_validate(&ds,&b,(void *)&dd,1),-EFAULT); b.frame_error=0;
 b.slot=0; EQ(xdev_ext_ce_validate(&cs,&b,(void *)&cd,1),-ERANGE); EQ(xdev_ext_dma_validate(&ds,&b,(void *)&dd,1),-ERANGE);
 b.slot=1; cd.gpu_off=960; dd.device_off=960; EQ(xdev_ext_ce_validate(&cs,&b,(void *)&cd,1),-ERANGE); EQ(xdev_ext_dma_validate(&ds,&b,(void *)&dd,1),-ERANGE);
 for(size_t i=0;i<sizeof(b.payload);i++) EQ(b.payload[i],0x5a);
#ifdef HAVE_TYPED
 free(cs.priv); free(ds.priv);
#endif
 puts("baseline consumers: real validate/stage offsets, claims, payload, dead/staged and count/collect ordering");
}
static void baseline(void) { pure_baseline(); bind_baseline(); consumer_baseline(); }
