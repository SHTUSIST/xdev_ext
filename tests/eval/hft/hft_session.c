/* SPDX-License-Identifier: GPL-2.0 */
/* Setup helpers adapted from current tools/xdev_ext_mech/xdev_ext_mech_ctl.c.
 * This adapter owns only its unpinned struct_ops links and socket mappings. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "hft_runtime.h"
#include "benchmark_policy.h"
#ifdef HFT_HAVE_SESSION
#include <zlib.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/if_xdp.h>
#include <linux/fs.h>
#include "../../../kernel/include/uapi/linux/io_uring.h"
#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"
#define CTL_RING_SIZE 64U
#define XDEV_EXT_MECH_CTL_FRAME_SIZE 4096U
static struct bpf_map *ctl_section_map(struct bpf_object *obj, const char *sec)
{
	size_t n = strlen(sec);
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
		size_t len = strlen(name);

		if (bpf_map__is_internal(map) && len >= n &&
		    !strcmp(name + len - n, sec))
			return map;
	}
	return NULL;
}

/* Before load: patch global @name in the initial image of its section map. */
static int ctl_set_global(struct bpf_object *obj, const char *name,
			  __u64 value)
{
	static const char *const sections[] = { ".bss", ".data" };
	struct btf *btf = bpf_object__btf(obj);
	unsigned int i;

	if (!btf)
		return -ENOENT;
	for (i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
		const struct btf_var_secinfo *vsi;
		const struct btf_type *sec;
		int id = btf__find_by_name_kind(btf, sections[i],
						BTF_KIND_DATASEC);
		__u16 v;

		if (id < 0)
			continue;
		sec = btf__type_by_id(btf, id);
		vsi = btf_var_secinfos(sec);
		for (v = 0; v < btf_vlen(sec); v++, vsi++) {
			const struct btf_type *var = btf__type_by_id(btf,
								     vsi->type);
			struct bpf_map *map;
			const void *image;
			size_t size;
			void *copy;
			int ret;

			if (strcmp(btf__name_by_offset(btf, var->name_off),
				   name))
				continue;
			map = ctl_section_map(obj, sections[i]);
			image = map ? bpf_map__initial_value(map, &size) : NULL;
			if (!image)
				return -ENOENT;
			copy = malloc(size);
			if (!copy)
				return -ENOMEM;
			memcpy(copy, image, size);
			ret = 0;
            if (vsi->offset > size || vsi->size > size-vsi->offset ||
                (vsi->size != 4 && vsi->size != 8) ||
                (vsi->size == 4 && value > UINT32_MAX)) ret = -EINVAL;
            else for (unsigned j=0;j<vsi->size;j++)
                ((unsigned char *)copy)[vsi->offset+j]=(unsigned char)(value>>(8*j));
			if (!ret)
				ret = bpf_map__set_initial_value(map, copy,
								 size);
			free(copy);
			return ret;
		}
	}
	return -ENOENT;
}

static int ctl_set_bytes(struct bpf_object *obj,const char *name,const void *bytes,size_t length)
{
 struct btf *btf=bpf_object__btf(obj);const char *sections[]={".bss",".data"};
 if(!btf)return -ENOENT;
 for(unsigned i=0;i<2;i++) {
  int id=btf__find_by_name_kind(btf,sections[i],BTF_KIND_DATASEC);if(id<0)continue;
  const struct btf_type *sec=btf__type_by_id(btf,id);const struct btf_var_secinfo *v=btf_var_secinfos(sec);
  for(unsigned n=0;n<btf_vlen(sec);n++,v++) {
   const struct btf_type *var=btf__type_by_id(btf,v->type);
   if(strcmp(btf__name_by_offset(btf,var->name_off),name))continue;
   struct bpf_map *map=ctl_section_map(obj,sections[i]);size_t size;const void *image=map?bpf_map__initial_value(map,&size):NULL;
   if(!image||v->size!=length||v->offset>size||length>size-v->offset)return -EINVAL;
   void *copy=malloc(size);if(!copy)return -ENOMEM;memcpy(copy,image,size);memcpy((char *)copy+v->offset,bytes,length);
   int ret=bpf_map__set_initial_value(map,copy,size);free(copy);return ret;
  }
 }
 return -ENOENT;
}

struct ctl_xring {
	__u32 *producer;
	__u32 *consumer;
	void *descs;
	__u32 mask;
	void *map;
	size_t map_len;
};

struct ctl_xsk {
	int fd;
	bool zero_copy;
	void *umem;
	size_t umem_size;
	struct ctl_xring fq, cq, rx, tx;
};

static int ctl_xring_map(int fd, const struct xdp_ring_offset *off,
			 __u64 pgoff, size_t esize, struct ctl_xring *r)
{
	r->map_len = off->desc + CTL_RING_SIZE * esize;
	r->map = mmap(NULL, r->map_len, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, fd, (off_t)pgoff);
	if (r->map == MAP_FAILED) {
		r->map = NULL;
		return -errno;
	}
	r->producer = (__u32 *)((char *)r->map + off->producer);
	r->consumer = (__u32 *)((char *)r->map + off->consumer);
	r->descs = (char *)r->map + off->desc;
	r->mask = CTL_RING_SIZE - 1;
	return 0;
}

static int ctl_setsockopt_u32(int fd, int opt, __u32 v)
{
	return setsockopt(fd, SOL_XDP, opt, &v, sizeof(v)) ? -errno : 0;
}

/*
 * An explicitly selected AF_XDP socket mode on @ifname/@queue.  The UMEM owner registers an
 * aligned UMEM of 4 KiB chunks with @headroom and maps its fill and
 * completion rings; @rx and @tx add those rings.  With @shared_fd >= 0 the
 * socket binds XDP_SHARED_UMEM onto it instead, and the bind result is the
 * return value.
 */
static int ctl_xsk_open(struct ctl_xsk *x, const char *ifname, __u32 queue,
			__u32 headroom, bool rx, bool tx, int shared_fd,
			bool copy_mode, __u32 pool_frames)
{
	struct sockaddr_xdp sxdp = { .sxdp_family = AF_XDP };
	struct xdp_mmap_offsets off;
	socklen_t optlen = sizeof(off);
	unsigned int ifindex = if_nametoindex(ifname);
	int ret;

	memset(x, 0, sizeof(*x));
	x->fd = -1;
	if (!ifindex)
		return -errno;
	x->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (x->fd < 0)
		return -errno;
	if (shared_fd < 0) {
		struct xdp_umem_reg reg = {
			.len = (__u64)pool_frames * XDEV_EXT_MECH_CTL_FRAME_SIZE,
			.chunk_size = XDEV_EXT_MECH_CTL_FRAME_SIZE,
			.headroom = headroom,
		};

		x->umem_size = reg.len;
		x->umem = mmap(NULL, x->umem_size, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1,
			       0);
		if (x->umem == MAP_FAILED) {
			x->umem = NULL;
			return -errno;
		}
		reg.addr = (uintptr_t)x->umem;
		if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)))
			return -errno;
		ret = ctl_setsockopt_u32(x->fd, XDP_UMEM_FILL_RING,
					 CTL_RING_SIZE);
		if (!ret)
			ret = ctl_setsockopt_u32(x->fd,
						 XDP_UMEM_COMPLETION_RING,
						 CTL_RING_SIZE);
		if (ret)
			return ret;
	}
	if (rx && (ret = ctl_setsockopt_u32(x->fd, XDP_RX_RING, CTL_RING_SIZE)))
		return ret;
	if (tx && (ret = ctl_setsockopt_u32(x->fd, XDP_TX_RING, CTL_RING_SIZE)))
		return ret;
	if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen))
		return -errno;
	if (shared_fd < 0) {
		ret = ctl_xring_map(x->fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING,
				    sizeof(__u64), &x->fq);
		if (!ret)
			ret = ctl_xring_map(x->fd, &off.cr,
					    XDP_UMEM_PGOFF_COMPLETION_RING,
					    sizeof(__u64), &x->cq);
		if (ret)
			return ret;
	}
	if (rx && (ret = ctl_xring_map(x->fd, &off.rx, XDP_PGOFF_RX_RING,
				       sizeof(struct xdp_desc), &x->rx)))
		return ret;
	if (tx && (ret = ctl_xring_map(x->fd, &off.tx, XDP_PGOFF_TX_RING,
				       sizeof(struct xdp_desc), &x->tx)))
		return ret;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	if (shared_fd < 0) {
		sxdp.sxdp_flags = copy_mode ? XDP_COPY : XDP_ZEROCOPY;
	} else {
		sxdp.sxdp_flags = XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = (__u32)shared_fd;
	}
	if (bind(x->fd, (struct sockaddr *)&sxdp, sizeof(sxdp)))
		return -errno;
	{
		struct xdp_options options = {};

		optlen = sizeof(options);
		if (getsockopt(x->fd, SOL_XDP, XDP_OPTIONS, &options, &optlen))
			return -errno;
		x->zero_copy = !!(options.flags & XDP_OPTIONS_ZEROCOPY);
		ret = copy_mode || !x->zero_copy ? -EOPNOTSUPP : 0;
	}
	return ret;
}

static void ctl_xring_unmap(struct ctl_xring *r)
{
	if (r->map)
		munmap(r->map, r->map_len);
}

static void ctl_xsk_close(struct ctl_xsk *x)
{
	ctl_xring_unmap(&x->fq);
	ctl_xring_unmap(&x->cq);
	ctl_xring_unmap(&x->rx);
	ctl_xring_unmap(&x->tx);
	if (x->fd >= 0)
		close(x->fd);
	if (x->umem)
		munmap(x->umem, x->umem_size);
	memset(x, 0, sizeof(*x));
	x->fd = -1;
}

static int mech(int ring,unsigned op,uint64_t arg)
{
 struct io_uring_xdev_ext_mech req={.op=op,.arg=arg};
 int n=(int)syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_MECH,&req,1);
 return n<0?-errno:n;
}
static int mac(const char *s,unsigned char *out)
{
 unsigned values[6];char extra;
 if(sscanf(s,"%2x:%2x:%2x:%2x:%2x:%2x%c",&values[0],&values[1],&values[2],&values[3],&values[4],&values[5],&extra)!=6) return -1;
 for(unsigned i=0;i<6;i++) out[i]=(unsigned char)values[i];
 return 0;
}
static int attach_maps(const struct hft_config *c,struct bpf_object **object,struct bpf_link **links,struct hft_actor *a)
{
 struct bpf_object *obj=bpf_object__open_file(c->bpf_object,NULL);
 const char *names[]={c->measured?"hftb_nvme_ops":"nxp_nvme_ops",c->measured?"hftb_afxdp_ops":"nxp_afxdp_ops"};int err;
 err=(int)libbpf_get_error(obj);if(err) return err;
 *object=obj;
 if(c->measured) {
  unsigned char lm[6],pm[6],network[42];uint32_t lip,pip;
  if(mac(c->local_mac,lm)||mac(c->peer_mac,pm)||inet_pton(AF_INET,c->local_ip,&lip)!=1||inet_pton(AF_INET,c->peer_ip,&pip)!=1||
     hftb_setup_template(network,lm,pm,lip,pip,htons(c->local_port),htons(c->peer_port),c->payload)||
     ctl_set_global(obj,"hftb_session",c->session_base)||ctl_set_global(obj,"hftb_payload",c->payload)||
     ctl_set_global(obj,"hftb_depth",c->depth)||ctl_set_global(obj,"hftb_groups",(uint64_t)c->burst*c->bursts)||
     ctl_set_bytes(obj,"hftb_network_template",network,sizeof(network)))return -EINVAL;
  struct bpf_map *history=bpf_object__find_map_by_name(obj,"hftb_guard_history");
  if(!history||bpf_map__value_size(history)!=sizeof(struct hft_guard_record)||bpf_map__max_entries(history)<(uint64_t)c->burst*c->bursts)return -EINVAL;
 } else if(ctl_set_global(obj,"nxp_session",c->session_base)||ctl_set_global(obj,"key_base",1)||ctl_set_global(obj,"nvme_mode",0))return -EINVAL;
 if(bpf_object__load(obj)) return -EOPNOTSUPP;
 for(unsigned i=0;i<2;i++) {
  struct bpf_map *map=bpf_object__find_map_by_name(obj,names[i]);
  struct bpf_map_info info={0};__u32 len=sizeof(info);
  if(!map||bpf_map__type(map)!=BPF_MAP_TYPE_STRUCT_OPS || bpf_obj_get_info_by_fd(bpf_map__fd(map),&info,&len) ||
     info.type!=BPF_MAP_TYPE_STRUCT_OPS || strncmp(info.name,names[i],sizeof(info.name))) return -EPROTO;
  if(i==0)a->nvme_map_id=info.id;else a->afxdp_map_id=info.id;
  links[i]=bpf_map__attach_struct_ops(map);
  err=(int)libbpf_get_error(links[i]);if(err) {links[i]=NULL;return err;}
 }
 return 0;
}
static int stats_ok(const struct xdev_ext_mech_stats *s,uint64_t count)
{
 return s->state==XDEV_EXT_MECH_SESSION_ACTIVE && s->batches_done==count && !s->batches_abort &&
  !s->rejects&&!s->sequestered&&!s->timeouts&&!s->protocol_err&&!s->last_err&&!s->inflight &&
  s->submitted[0]==count&&s->submitted[1]==count&&s->completed[0]==count&&s->completed[1]==count;
}
int hft_session_gate(const struct hft_config *c)
{
 struct stat st;unsigned mtu;char path[256];FILE *f;gzFile config;int ok=0;
 if(!c->source_block||!c->source_ng||!c->ifname||!*c->ifname||!c->bpf_object||!*c->bpf_object||!c->kernel_config||!*c->kernel_config||
    c->actors!=1||!c->nlb||!c->local_port||!*c->local_mac||!*c->peer_mac||!*c->local_ip||!*c->peer_ip||c->payload>3584) return -1;
 if(stat(c->source_block,&st)||!S_ISBLK(st.st_mode)||stat(c->source_ng,&st)||!S_ISCHR(st.st_mode)||access("/sys/kernel/btf/vmlinux",R_OK)||access(c->bpf_object,R_OK)) return -1;
 config=gzopen(c->kernel_config,"r");if(!config) return -1;
 while(gzgets(config,path,sizeof(path))) if(!strcmp(path,"CONFIG_XDEV_EXT_MECH_ZEROCOPY=y\n")) ok=1;
 gzclose(config);if(!ok) return -1;
 snprintf(path,sizeof(path),"/sys/class/net/%s/mtu",c->ifname);f=fopen(path,"r");if(!f) return -1;
 ok=fscanf(f,"%u",&mtu)==1 && c->payload+68<=mtu;fclose(f);
 return ok?0:-1;
}
int hft_session(struct hft_actor *a)
{
 const struct hft_config *c=a->c;struct bpf_object *obj=NULL;struct bpf_link *links[2]={NULL,NULL};
 struct ctl_xsk x={.fd=-1};struct io_uring_params params={0};struct xdev_ext_mech_create create={0};
 struct xdev_ext_mech_stats stats={0};int ring=-1,efd=-1,ng=-1,block=-1,ctl=-1,ret=4,stop=0,started=0,unsafe=0,guarded=0;
 hft_setup_begin(a);
 unsigned sector=0;uint64_t capacity=0,groups=(uint64_t)c->burst*c->bursts;
 block=open(c->source_block,O_RDONLY|O_CLOEXEC);ng=open(c->source_ng,O_RDONLY|O_CLOEXEC);
 if(block<0||ng<0||ioctl(block,BLKSSZGET,&sector)||ioctl(block,BLKGETSIZE64,&capacity)||!sector||c->payload%sector||
    c->slba>capacity/sector||c->nlb>capacity/sector-c->slba||c->nlb<groups*(c->payload/sector)) goto setup;
 ring=(int)syscall(__NR_io_uring_setup,8,&params);efd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
 ctl=hft_connect(c->control_ip,c->control_port);
 if(ring<0||efd<0||ctl<0) goto setup;
 if(hft_history_setup(a)||attach_maps(c,&obj,links,a)||ctl_xsk_open(&x,c->ifname,c->queue,512,false,true,-1,false,c->measured?2*c->depth:64)) goto setup;
 a->native_xdp_zc=x.zero_copy;a->counts.registrations++;
 /* Source partition is the latter half, enough for bounded depth. No FQ
  * publication or userspace TX pumping is needed for the native source path. */
 for(unsigned i=0;i<(c->measured?2*c->depth:64);i++) {
  unsigned char *p=(unsigned char *)x.umem+i*4096;
  memset(p,0xa5,430);memset(p+512+c->payload,0x5a,4096-512-c->payload);
 }
 guarded=1;
 create.abi_version=XDEV_EXT_MECH_ABI_VERSION;create.nr_stages=2;
 create.pool_kind=XDEV_EXT_MECH_POOL_XSK;create.pool_fd=x.fd;
 create.layout=(struct xdev_ext_mech_layout){.frame_size=4096,.hdr_room=512,.seg_len=c->payload,.group_bytes=c->payload};
 create.depth=c->depth;create.eventfd=efd;
 if(mac(c->local_mac,create.peer.local_mac)||mac(c->peer_mac,create.peer.peer_mac)||
    inet_pton(AF_INET,c->local_ip,&create.peer.local_ip)!=1||inet_pton(AF_INET,c->peer_ip,&create.peer.peer_ip)!=1) goto setup;
 create.peer.local_port=htons(c->local_port);create.peer.peer_port=htons(c->peer_port);
 create.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=ng,.arg0=c->slba,.arg1=c->nlb};
 create.st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_AFXDP,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=x.fd};
 /* Strict kernel admission also checks native NVMe SGL and every NIC mapping.
  * Stock UAPI or bounce-mode kernels cannot pass the locked config gate. */
 if(mech(ring,XDEV_EXT_MECH_OP_CREATE,(uintptr_t)&create)) goto setup;
 a->native_create=1;
 ret=0;
 setup:
 if(ret) atomic_store(a->startup_error,4);
 pthread_barrier_wait(a->barrier);
 if(atomic_load(a->startup_error)) {ret=4;goto out;}
 ret=1;hft_setup_done(a);
 if(c->probe) {
  stats=(struct xdev_ext_mech_stats){.session_id=create.session_id};
  if(mech(ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&stats)||!stats_ok(&stats,0)) goto out;
  a->native.state=stats.state;ret=0;goto out;
 }
 for(unsigned b=0;b<c->bursts;b++) {
  uint64_t target=(uint64_t)(b+1)*c->burst,event;
  struct xdev_ext_mech_notify_arm arm={.session_id=create.session_id,.batches_target=target};
  struct xdev_ext_mech_start start={.session_id=create.session_id,.nr_batches=c->burst,.first_seq=(uint64_t)b*c->burst+1};
  struct pollfd wait={.fd=efd,.events=POLLIN};int n;
  hft_burst_begin(a,b);
  if(mech(ring,XDEV_EXT_MECH_OP_NOTIFY_ARM,(uintptr_t)&arm)) goto out;
  /* START errors cannot prove non-acceptance after an interrupted syscall. */
  started=1;
  if(mech(ring,XDEV_EXT_MECH_OP_START,(uintptr_t)&start)) goto out;
  do {n=poll(&wait,1,20000);} while(n<0&&errno==EINTR);
  if(n!=1||!(wait.revents&POLLIN)||read(efd,&event,sizeof(event))!=(ssize_t)sizeof(event)) goto out;
  stats=(struct xdev_ext_mech_stats){.session_id=create.session_id};
  if(mech(ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&stats)||!stats_ok(&stats,target)) goto out;
  a->counts.reads=stats.submitted[0];a->counts.sends=stats.submitted[1];
  hft_burst_release(a,b);
  if(hft_receipt(ctl,a,b*c->burst)) goto out;
  hft_burst_done(a,b);
 }
 a->counts.reads=stats.submitted[0];a->counts.sends=stats.submitted[1];
 a->native=(struct hft_native_stats){.batches_done=stats.batches_done,.batches_abort=stats.batches_abort,
  .rejects=stats.rejects,.sequestered=stats.sequestered,.timeouts=stats.timeouts,.protocol_err=stats.protocol_err,
  .inflight=stats.inflight,.read_submitted=stats.submitted[0],.read_completed=stats.completed[0],
  .send_submitted=stats.submitted[1],.send_completed=stats.completed[1],.last_err=stats.last_err,.state=stats.state};ret=0;
 out:
 hft_teardown_begin(a);
 if(create.session_id) {
  stop=mech(ring,XDEV_EXT_MECH_OP_STOP,create.session_id);a->native.stop_ret=stop;
  if(stop) {ret=1;unsafe=1;fputs("{\"status\":\"error\",\"diagnostic\":\"STOP failed; UNKNOWN native resources retained\"}\n",stderr);}
 }
 if(started&&ret) ret=1;
 if(!unsafe) {
  if(c->measured&&a->history&&obj&&ret==0) {
   struct bpf_map *history=bpf_object__find_map_by_name(obj,"hftb_guard_history");
   if(!history)ret=1;
   else for(unsigned i=0;i<a->history_count;i++) {
    struct hft_guard_record *r=&a->history[i];
    if(bpf_map_lookup_elem(bpf_map__fd(history),&i,r)||r->committed!=1||r->generation!=i+1||r->frame_pos!=i%c->depth||r->payload_bytes!=c->payload||r->slot_addr!=(uint64_t)(c->depth+i%c->depth)*4096){ret=1;break;}
    a->frame_slots[r->frame_pos]=r->slot_addr;
   }
  }
  if(!c->measured&&guarded && x.umem) for(unsigned i=0;i<64;i++) {
   const unsigned char *p=(const unsigned char *)x.umem+i*4096;
   if(!hft_guards_ok(p,430,430,0)||!hft_guards_ok(p+512,c->payload+4096-512-c->payload,0,c->payload)) ret=1;
  }
  ctl_xsk_close(&x);
  if(ring>=0) close(ring);
  if(efd>=0) close(efd);
  if(ng>=0) close(ng);
  if(block>=0) close(block);
  for(unsigned i=0;i<2;i++) if(links[i]) bpf_link__destroy(links[i]);
  if(obj) bpf_object__close(obj);
 }
 if(ctl>=0) close(ctl);
 hft_teardown_done(a);
 return ret;
}
#else
int hft_session_gate(const struct hft_config *c) {(void)c;return -1;}
int hft_session(struct hft_actor *a)
{ atomic_store(a->startup_error,4);pthread_barrier_wait(a->barrier);return 4; }
#endif
