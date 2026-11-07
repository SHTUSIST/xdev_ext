/* Contract-authored independent tests; no production implementation is embedded. */
static struct xdev_ext_window_copy_geom geometry(void) {
 return (struct xdev_ext_window_copy_geom){.window_len=4096,.host_bytes=8192,.max_entry_len=4096,.first_page_off=64,.frame_size=512,.nr_frames=8,.alignment=1,.directions=XDEV_EXT_WINDOW_COPY_DIRS};
}
static int claim(void *b,u32 pos,u64 *owner,u64 *generation) { return xdev_ext_mech_batch_frame_claim(b,pos,owner,generation); }
static void typed_prepare(void) {
 struct xdev_ext_window_copy_geom g=geometry();
 struct xdev_ext_comp_copy_window w,old;
 memset(&w,0xa5,sizeof(w)); memcpy(&old,&w,sizeof(w));
 EQ(xdev_ext_comp_copy_prepare(&w,XDEV_EXT_COMP_INPLACE,&g,1,2,1024),-EINVAL); assert(!memcmp(&w,&old,sizeof(w)));
 EQ(xdev_ext_comp_copy_prepare(&w,XDEV_EXT_COMP_TRANSFORM,&g,1,2,1024),-EINVAL); assert(!memcmp(&w,&old,sizeof(w)));
 EQ(xdev_ext_comp_copy_prepare(&w,XDEV_EXT_COMP_COPY_WINDOW,&g,0,5,1024),-EOPNOTSUPP); assert(!memcmp(&w,&old,sizeof(w)));
 g.directions=1U<<2;
 EQ(xdev_ext_comp_copy_prepare(&w,XDEV_EXT_COMP_COPY_WINDOW,&g,1,5,1024),-EOPNOTSUPP); assert(!memcmp(&w,&old,sizeof(w)));
 g=geometry(); EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,0,1024),-EINVAL); assert(!memcmp(&w,&old,sizeof(w)));
 EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,2,0),-EINVAL); assert(!memcmp(&w,&old,sizeof(w)));
 EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,5,1024),-ENOSPC); assert(!memcmp(&w,&old,sizeof(w)));
 EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,UINT32_MAX,UINT32_MAX),-ENOSPC); assert(!memcmp(&w,&old,sizeof(w)));
 EQ(xdev_ext_comp_copy_prepare(&w,1,&g,2,2,1024),0);
 EQ(w.geom.window_len,g.window_len);
 EQ(w.geom.host_bytes,g.host_bytes);
 EQ(w.geom.seg_size,g.seg_size);
 EQ(w.geom.max_entry_len,g.max_entry_len);
 EQ(w.geom.first_page_off,g.first_page_off);
 EQ(w.geom.frame_size,g.frame_size);
 EQ(w.geom.nr_frames,g.nr_frames);
 EQ(w.geom.alignment,g.alignment);
 EQ(w.geom.directions,g.directions); EQ(w.direction,2); EQ(w.depth,2); EQ(w.group_bytes,1024);
}
static void typed_literal(void) {
 struct xdev_ext_window_copy_geom g=geometry(); struct xdev_ext_comp_copy_window w;
 struct xdev_ext_comp_copy_plan p,old; struct xdev_ext_mech_frame_info f={.data_off=16,.data_len=128}; u32 ix=2;
 struct xdev_ext_dma_copy_desc d={.frame_off=16,.device_off=1024,.len=128};
 EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,2,1024),0);
 EQ(xdev_ext_comp_copy_validate(&w,&f,&ix,1,&d,1,32,3,1,91,&p),0);
 EQ(p.batch_id,91); EQ(p.slot,1); EQ(p.n,1); EQ(p.total,128); EQ(p.entry[0].host_byte_off,1104); EQ(p.entry[0].device_off,1024); EQ(p.entry[0].frame_pos,0); EQ(p.entry[0].len,128); EQ(p.entry[0].flags,0);
 memcpy(&old,&p,sizeof(p));
#define V(want,slot) do { EQ(xdev_ext_comp_copy_validate(&w,&f,&ix,1,&d,1,32,3,slot,91,&p),want); assert(!memcmp(&p,&old,sizeof(p))); } while(0)
 V(-ERANGE,0); d.device_off=960; V(-ERANGE,1); d.device_off=1024; V(-EINVAL,2);
 /* Max capacity guards precede descriptor reads (NULL is intentional). */
 EQ(xdev_ext_comp_copy_validate(&w,NULL,NULL,0,NULL,1,XDEV_EXT_COMP_COPY_MAX_ENTRIES + 1,3,1,91,&p),-EINVAL); assert(!memcmp(&p,&old,sizeof(p)));
 EQ(xdev_ext_comp_copy_validate(&w,NULL,NULL,0,NULL,33,32,3,1,91,&p),-E2BIG); assert(!memcmp(&p,&old,sizeof(p)));
 EQ(xdev_ext_comp_copy_validate(&w,&f,&ix,1,&d,0,32,3,1,91,&p),-EINVAL); assert(!memcmp(&p,&old,sizeof(p)));
 g.max_entry_len=64; EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,2,1024),0); d.flags=8; V(-EOPNOTSUPP,1); d.flags=0; V(-EMSGSIZE,1);
 g=geometry(); EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,2,1024),0); d.frame_off=17; d.device_off=UINT64_MAX; V(-EINVAL,1);
 d.frame_off=16; d.device_off=UINT64_MAX; V(-ERANGE,1);
 g.seg_size=1024; g.alignment=256; EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,2,1024),0); ix=99; d.device_off=960; V(-EXDEV,1);
 g.seg_size=0; EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,2,1024),0); V(-ERANGE,1);
 ix=2; V(-EINVAL,1);
#undef V
}
/* Single-frame oracle uses independently enumerated byte coordinates. It never
 * calls the production cover/span/offset helpers or builds expected via them. */
static int independent_one(u32 frame_off,u32 payload,u32 frame_pos,u32 off,u32 len,u32 ix,u64 dev,u32 flags,u32 alignment,u32 seg,u32 limit,u32 slot) {
 if (!len) return -EINVAL;
 if (flags&~3U) return -EOPNOTSUPP;
 if (len>limit) return -EMSGSIZE;
 if (!payload) return -ERANGE;
 if (frame_pos || off!=frame_off) return -EINVAL;
 if ((u64)off+len>(u64)frame_off+payload) return -ERANGE;
 if (dev>4096 || len>4096-dev) return -ERANGE;
 if (seg && dev/seg!=(dev+len-1)/seg) return -EXDEV;
 if (ix>=8 || (u64)off+len>512) return -ERANGE;
 u64 host=64+(u64)ix*512+off;
 if (host+len>8192) return -ERANGE;
 if (host%alignment || dev%alignment || len%alignment) return -EINVAL;
 if (len<payload) return -ENODATA;
 if (slot>=2) return -EINVAL;
 if (dev<(u64)slot*1024 || dev+len>(u64)(slot+1)*1024) return -ERANGE;
 return 0;
}
static void typed_exhaustive(void) {
 struct xdev_ext_window_copy_geom g=geometry(); struct xdev_ext_comp_copy_window w;
 const u64 devices[]={0,960,1024,1088,1984,2048,4095,UINT64_MAX};
 const u32 lengths[]={0,1,32,64,128,129}; unsigned long cases=0;
 for(u32 alignment=1;alignment<=64;alignment*=8) for(u32 seg=0;seg<=1024;seg+=1024) {
  g.alignment=alignment; g.seg_size=seg; EQ(xdev_ext_comp_copy_prepare(&w,1,&g,1,2,1024),0);
  for(u32 ix=0;ix<=8;ix+=2) for(u32 pos=0;pos<2;pos++) for(u32 off=15;off<=17;off++)
  for(u32 li=0;li<sizeof(lengths)/sizeof(lengths[0]);li++) for(u32 di=0;di<sizeof(devices)/sizeof(devices[0]);di++) for(u32 slot=0;slot<3;slot++) {
   struct xdev_ext_mech_frame_info f={.data_off=16,.data_len=128};
   struct xdev_ext_dma_copy_desc d={.frame_pos=pos,.frame_off=off,.len=lengths[li],.device_off=devices[di]};
   struct xdev_ext_comp_copy_plan p,old; memset(&p,0xa5,sizeof(p)); memcpy(&old,&p,sizeof(p));
   int expected=independent_one(16,128,pos,off,d.len,ix,d.device_off,0,alignment,seg,4096,slot);
   EQ(xdev_ext_comp_copy_validate(&w,&f,&ix,1,&d,1,32,3,slot,91,&p),expected);
   if(expected) assert(!memcmp(&p,&old,sizeof(p)));
   else { EQ(p.total,128); EQ(p.entry[0].host_byte_off,64+(u64)ix*512+16); EQ(p.entry[0].device_off,d.device_off); EQ(p.batch_id,91); EQ(p.slot,slot); }
   cases++;
  }
 }
 printf("typed independent interval oracle: %lu exhaustive vectors\n",cases);
}
static u32 rng_state=0x37b913U;
static u32 random32(void) { rng_state^=rng_state<<13; rng_state^=rng_state>>17; rng_state^=rng_state<<5; return rng_state; }
static void typed_random(void) {
 struct xdev_ext_window_copy_geom g=geometry(); struct xdev_ext_comp_copy_window w;
 EQ(xdev_ext_comp_copy_prepare(&w,1,&g,2,2,1024),0);
 for(u32 trial=0;trial<2048;trial++) {
  struct xdev_ext_mech_frame_info f[2]={{.data_off=16,.data_len=64},{.data_off=32,.data_len=64}}; u32 ix[2]={2,5};
  struct xdev_ext_dma_copy_desc d[4]; u32 a=1+random32()%63,b=1+random32()%63;
  d[0]=(struct xdev_ext_dma_copy_desc){.frame_pos=0,.frame_off=16,.device_off=1024,.len=a,.flags=random32()%4};
  d[1]=(struct xdev_ext_dma_copy_desc){.frame_pos=0,.frame_off=16+a,.device_off=1024+a,.len=64-a,.flags=random32()%4};
  d[2]=(struct xdev_ext_dma_copy_desc){.frame_pos=1,.frame_off=32,.device_off=1152,.len=b,.flags=random32()%4};
  d[3]=(struct xdev_ext_dma_copy_desc){.frame_pos=1,.frame_off=32+b,.device_off=1152+b,.len=64-b,.flags=random32()%4};
  struct xdev_ext_comp_copy_plan p,old; EQ(xdev_ext_comp_copy_validate(&w,f,ix,2,d,4,32,3,1,trial+92,&p),0);
  EQ(p.n,4); EQ(p.total,128); EQ(p.entry[0].host_byte_off,1104); EQ(p.entry[1].host_byte_off,1104+a); EQ(p.entry[2].host_byte_off,2656); EQ(p.entry[3].host_byte_off,2656+b);
  for(u32 i=0;i<4;i++) { EQ(p.entry[i].frame_pos,i/2); EQ(p.entry[i].device_off,d[i].device_off); EQ(p.entry[i].len,d[i].len); EQ(p.entry[i].flags,d[i].flags); }
  memcpy(&old,&p,sizeof(p)); u32 bad=random32()%4; d[bad].frame_off++; EQ(xdev_ext_comp_copy_validate(&w,f,ix,2,d,4,32,3,1,trial+92,&p),-EINVAL); assert(!memcmp(&p,&old,sizeof(p)));
 }
 puts("typed independent random oracle: 2048 valid split plans + 2048 gap mutations");
}
static void typed_transfer(void) {
 struct xdev_ext_comp_copy_plan p={.batch_id=91,.slot=1,.n=2,.total=128};
 p.entry[0]=(struct xdev_ext_comp_copy_entry){.host_byte_off=1104,.device_off=1024,.frame_pos=0,.len=64,.flags=1};
 p.entry[1]=(struct xdev_ext_comp_copy_entry){.host_byte_off=2656,.device_off=1152,.frame_pos=1,.len=64,.flags=2};
 struct xdev_ext_mech_batch b=batch(); b.nr=2; b.owner[1]=0x9999888877776666ULL; b.generation[1]=0x1111222233334444ULL;
 struct xdev_ext_comp_copy_transfer out[32],old[32]; memset(out,0xa5,sizeof(out)); memcpy(old,out,sizeof(out));
 EQ(xdev_ext_comp_copy_transfer(&p,92,1,&b,claim,out),-EPROTO); EQ(b.claim_calls,0); assert(!memcmp(out,old,sizeof(out)));
 EQ(xdev_ext_comp_copy_transfer(&p,91,0,&b,claim,out),-EPROTO); EQ(b.claim_calls,0); assert(!memcmp(out,old,sizeof(out)));
 b.claim_refuse=1; EQ(xdev_ext_comp_copy_transfer(&p,91,1,&b,claim,out),-ESTALE); assert(!memcmp(out,old,sizeof(out)));
 b.claim_refuse=-1; EQ(xdev_ext_comp_copy_transfer(&p,91,1,&b,claim,out),0);
 for(u32 i=0;i<2;i++) { EQ(out[i].owner,b.owner[i]); EQ(out[i].generation,b.generation[i]); EQ(out[i].host_byte_off,p.entry[i].host_byte_off); EQ(out[i].device_off,p.entry[i].device_off); EQ(out[i].len,64); EQ(out[i].flags,i+1); }
 assert(!memcmp(&out[2],&old[2],sizeof(out)-2*sizeof(out[0])));
 for(size_t i=0;i<sizeof(b.payload);i++) EQ(b.payload[i],0x5a);
}
static void typed(void) { typed_prepare(); typed_literal(); typed_exhaustive(); typed_random(); typed_transfer(); puts("typed pure: transactional prepare/validate/transfer, metadata and owner/generation"); }
