// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <linux/fs.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/nvme_ioctl.h"
#include "include/uapi/linux/xdev_ext_policy.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_cuda.h"
#include "tools/include/xdev_ext_gpu_identity.h"
#include "tools/include/xdev_ext_nv_p2p_ioctl.h"
#include "private_loader.h"

static struct {
	const char *object, *requests, *ng, *block, *ce, *output;
	struct rr_geometry g;
	uint64_t scratch_slba, scratch_nlb, timeout_ms;
	bool save;
} opt;
static struct {
	int ring, efd, ng, block, ce;
	uint64_t session, allocation_bytes, disk_full, disk_base, max_inflight;
	bool created, retained;
	void *umem;
	size_t umem_bytes;
	struct xdev_ext_mech_cuda cuda;
	struct rr_private programs;
} run = { .ring=-1,.efd=-1,.ng=-1,.block=-1,.ce=-1,.umem=MAP_FAILED,
	.cuda={.export_fd=-1}, .programs={.map_fd=-1,.nvme_fd=-1,.ce_fd=-1} };

static uint64_t millis(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
	return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static int state(const char *name, const char *reason)
{
	char path[4096], pending[4096];
	FILE *f;
	if (snprintf(path,sizeof(path),"%s/driver-state.json",opt.output)>=(int)sizeof(path) ||
	    snprintf(pending,sizeof(pending),"%s/driver-state.tmp",opt.output)>=(int)sizeof(pending)) return -ENAMETOOLONG;
	f=fopen(pending,"w"); if (!f) return -errno;
	int ret=fprintf(f,"{\"state\":\"%s\",\"reason\":\"%s\",\"pid\":%ld,\"session_id\":%"PRIu64",\"max_logical_inflight\":%"PRIu64",\"performance\":false}\n",
		name,reason,(long)getpid(),run.session,run.max_inflight)<0 ? -EIO : 0;
	if (fclose(f) && !ret) ret=-errno;
	if (!ret && rename(pending,path)) ret=-errno;
	return ret;
}
static int save_bytes(const char *name,const void *data,size_t bytes)
{
	char path[4096]; FILE *f;
	if (snprintf(path,sizeof(path),"%s/%s",opt.output,name)>=(int)sizeof(path)) return -ENAMETOOLONG;
	f=fopen(path,"wx"); if (!f) return -errno;
	int ret=fwrite(data,1,bytes,f)==bytes ? 0 : -EIO;
	if (fclose(f) && !ret) ret=-errno;
	return ret;
}
static int mech(unsigned op, void *arg)
{
	struct io_uring_xdev_ext_mech request={.op=op,.arg=(uintptr_t)arg};
	int ret=syscall(__NR_io_uring_register,run.ring,IORING_REGISTER_XDEV_EXT_MECH,&request,1);
	return ret<0 ? -errno : ret;
}
static int stats(struct xdev_ext_mech_stats *s)
{
	memset(s,0,sizeof(*s)); s->session_id=run.session;
	return mech(XDEV_EXT_MECH_OP_STATS,s);
}
static int stop(void)
{
	if (!run.created) return 0;
	struct xdev_ext_mech_stop_report report;
	uint64_t deadline=millis()+opt.timeout_ms;
	int ret;
	do {
		memset(&report,0,sizeof(report)); report.size=sizeof(report);
		report.version=XDEV_EXT_MECH_STOP_REPORT_VERSION; report.session_id=run.session;
		ret=mech(XDEV_EXT_MECH_OP_STOP_REPORT,&report);
		if (ret!=-EAGAIN) break;
		usleep(1000);
	} while (millis()<deadline);
	if (ret) return ret; /* No successful report means no cleanup permission. */
	run.created=false;
	return save_bytes("stop-report.bin",&report,sizeof(report));
}
static _Noreturn void fail(int code,const char *reason)
{
	fprintf(stderr,"RANDOM_NATIVE failure=%s errno=%d\n",reason,errno);
	if (run.created && stop()) run.retained=true;
	if (run.retained) {
		(void)state("retained",reason);
		/* Minimal handoff, no recovery daemon. Controller reports this PID
		 * and must not kill/free potentially DMA-referenced resources. */
		raise(SIGSTOP);
		for (;;) pause();
	}
	if (opt.output) (void)state(code==4 ? "unqualified" : "failed",reason);
	if (run.ring>=0) close(run.ring);
	if (run.efd>=0) close(run.efd);
	if (run.umem!=MAP_FAILED) munmap(run.umem,run.umem_bytes);
	rr_private_close(&run.programs);
	if (run.ce>=0) close(run.ce);
	(void)xdev_ext_mech_cuda_close(&run.cuda);
	if (run.ng>=0) close(run.ng);
	if (run.block>=0) close(run.block);
	exit(code);
}
#define NEED(call, label) do { int error_=(call); if (error_) { errno=error_<0 ? -error_ : error_; fail(2,label); } } while (0)
static uint64_t integer(const char *s)
{
	char *end;
	if (!s || !isdigit((unsigned char)*s)) fail(2,"invalid unsigned integer");
	errno=0; uint64_t value=strtoull(s,&end,10);
	if (errno || *end) fail(2,"invalid unsigned integer");
	return value;
}
static struct rr_request *read_requests(size_t *count)
{
	FILE *f=fopen(opt.requests,"r");
	char line[256]; struct rr_request *rows=NULL;
	size_t n=0, capacity=0;
	if (!f) fail(2,"open frozen requests");
	while (fgets(line,sizeof(line),f)) {
		uint64_t v[5]; char *p=line, *end;
		unsigned i;
		if (!strchr(line,'\n') && !feof(f)) fail(2,"request line too long");
		for (i=0;i<5;i++) {
			while (isspace((unsigned char)*p)) p++;
			if (!isdigit((unsigned char)*p)) fail(2,"request field missing");
			errno=0; v[i]=strtoull(p,&end,10);
			if (errno || (end==p) || (*end && !isspace((unsigned char)*end))) fail(2,"request integer overflow");
			p=end;
		}
		while (isspace((unsigned char)*p)) p++;
		if (*p || v[1]>UINT32_MAX || v[4]>UINT32_MAX) fail(2,"request trailing data");
		if (n==capacity) {
			if (capacity>SIZE_MAX/2/sizeof(*rows) || capacity>=UINT32_MAX/2) fail(2,"request count overflow");
			capacity=capacity ? capacity*2 : 16;
			void *next=realloc(rows,capacity*sizeof(*rows));
			if (!next) fail(2,"request allocation");
			rows=next;
		}
		rows[n++]=(struct rr_request){v[0],v[2],v[3],(uint32_t)v[4],(uint32_t)v[1]};
	}
	if (ferror(f) || fclose(f)) fail(2,"read requests");
	*count=n; return rows;
}
static void pattern(unsigned char *bytes,size_t length,uint64_t seed)
{
	size_t at;
	for (at=0;at<length;at+=8) {
		uint64_t word=(uint64_t)(at/8)*UINT64_C(0x9e3779b97f4a7c15)+seed;
		unsigned j;
		for (j=0;j<8 && j<length-at;j++) bytes[at+j]=(unsigned char)(word>>(8*j));
	}
}
static int disk_io(bool write,void *buffer,size_t bytes)
{
	size_t done=0;
	while (done<bytes) {
		ssize_t n=write ? pwrite(run.block,(char *)buffer+done,bytes-done,(off_t)(run.disk_base+done)) :
			pread(run.block,(char *)buffer+done,bytes-done,(off_t)(run.disk_base+done));
		if (n<0 && errno==EINTR) continue;
		if (n<=0 || (size_t)n%opt.g.lba_bytes) return n<0 ? -errno : -EIO;
		done+=(size_t)n;
	}
	return write && fsync(run.block) ? -errno : 0;
}
static int gpu_io(bool write,void *buffer,size_t bytes)
{
	int (*htod)(uint64_t,const void *,size_t)=NULL;
	int (*dtoh)(void *,uint64_t,size_t)=NULL;
	void *previous=NULL;
	*(void **)(&htod)=dlsym(run.cuda.lib,"cuMemcpyHtoD_v2");
	*(void **)(&dtoh)=dlsym(run.cuda.lib,"cuMemcpyDtoH_v2");
	if (!htod || !dtoh) return -ENOSYS;
	int ret=xdev_ext_mech_cuda_result(run.cuda.ctx_get(&previous),"cuCtxGetCurrent");
	if (ret) return ret;
	ret=xdev_ext_mech_cuda_result(run.cuda.ctx_set(run.cuda.ctx),"cuCtxSetCurrent");
	if (!ret) ret=xdev_ext_mech_cuda_result(write ? htod(run.cuda.va,buffer,bytes) : dtoh(buffer,run.cuda.va,bytes),"whole allocation copy");
	int restore=xdev_ext_mech_cuda_result(run.cuda.ctx_set(previous),"cuCtxSetCurrent restore");
	return ret ? ret : restore;
}
static void namespace_identity(void)
{
	struct stat a,b; char x[128],y[128],ax[PATH_MAX],by[PATH_MAX];
	if (fstat(run.ng,&a) || fstat(run.block,&b) || !S_ISCHR(a.st_mode) || !S_ISBLK(b.st_mode)) fail(2,"namespace fd types");
	if (snprintf(y,sizeof(y),"/sys/dev/block/%u:%u/partition",major(b.st_rdev),minor(b.st_rdev))>=(int)sizeof(y))
		fail(2,"partition identity path");
	errno=0;
	if (!access(y,F_OK) || errno!=ENOENT) fail(4,"whole namespace block device required");
	int na=ioctl(run.ng,NVME_IOCTL_ID), nb=ioctl(run.block,NVME_IOCTL_ID);
	if (na<=0 || na!=nb) fail(4,"namespace ID mismatch");
	if (snprintf(x,sizeof(x),"/sys/dev/char/%u:%u/device",major(a.st_rdev),minor(a.st_rdev))>=(int)sizeof(x) ||
	    snprintf(y,sizeof(y),"/sys/dev/block/%u:%u/device",major(b.st_rdev),minor(b.st_rdev))>=(int)sizeof(y) ||
	    !realpath(x,ax) || !realpath(y,by) || strcmp(ax,by)) fail(4,"namespace sysfs identity mismatch");
	int logical=0; uint64_t capacity=0;
	if (ioctl(run.block,BLKSSZGET,&logical) || logical!=(int)opt.g.lba_bytes ||
	    ioctl(run.block,BLKGETSIZE64,&capacity) || run.disk_base>capacity || run.disk_full>capacity-run.disk_base)
		fail(4,"scratch namespace geometry");
	NEED(save_bytes("namespace-sysfs.txt",ax,strlen(ax)),"namespace evidence");
}
static void allocate_gpu(void)
{
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE]; size_t granule=0; void *previous=NULL;
	NEED(xdev_ext_gpu_identity_from_opened(run.ce,opt.ce,XDEV_EXT_GPU_IDENTITY_ANY_MINOR,bdf),"real GPU CE identity");
	NEED(xdev_ext_mech_cuda_open_vmm(&run.cuda,bdf,opt.g.gpu_bytes+2*opt.g.guard_bytes),"CUDA VMM export");
	struct xdev_ext_mech_cuda_mem_prop prop={.type=XDEV_EXT_MECH_CUDA_ALLOCATION_PINNED,
		.requested_handle_types=XDEV_EXT_MECH_CUDA_HANDLE_POSIX_FD,
		.location={XDEV_EXT_MECH_CUDA_LOCATION_DEVICE,run.cuda.device}};
	NEED(xdev_ext_mech_cuda_result(run.cuda.ctx_get(&previous),"get context"),"CUDA context");
	NEED(xdev_ext_mech_cuda_result(run.cuda.ctx_set(run.cuda.ctx),"set context"),"CUDA context");
	int ret=xdev_ext_mech_cuda_result(run.cuda.granularity(&granule,&prop,XDEV_EXT_MECH_CUDA_GRANULARITY_MINIMUM),"VMM granularity");
	int restore=xdev_ext_mech_cuda_result(run.cuda.ctx_set(previous),"restore context");
	NEED(ret ? ret : restore,"CUDA actual granularity");
	if (!granule || opt.g.guard_bytes%granule || run.cuda.vmm_bytes>SIZE_MAX ||
	    run.cuda.va>UINT64_MAX-opt.g.guard_bytes || run.cuda.va+opt.g.guard_bytes>UINT64_MAX-opt.g.gpu_bytes)
		fail(4,"guard incompatible with actual VMM granularity");
	run.allocation_bytes=run.cuda.vmm_bytes;
	struct xdev_ext_nv_ce_attach_memory attach={.mem_fd=run.cuda.export_fd,.gpu_va=run.cuda.va,.size=run.cuda.vmm_bytes};
	if (xdev_ext_nv_ce_attach_memory(run.ce,&attach)) fail(4,"actual CE VMM attach");
	char metadata[512];
	int n=snprintf(metadata,sizeof(metadata),"{\"allocation_bytes\":%"PRIu64",\"guard_bytes\":%"PRIu64",\"gpu_bytes\":%"PRIu64",\"disk_bytes\":%"PRIu64",\"disk_full_bytes\":%"PRIu64",\"granularity\":%zu,\"depth\":%u,\"direction\":\"%s\"}\n",
		run.allocation_bytes,opt.g.guard_bytes,opt.g.gpu_bytes,opt.g.disk_bytes,run.disk_full,granule,opt.g.depth,opt.save?"save":"load");
	if (n<0 || n>=(int)sizeof(metadata)) fail(2,"allocation metadata overflow");
	NEED(save_bytes("allocation.json",metadata,(size_t)n),"allocation evidence");
}
static void wait_phase(uint64_t target,uint32_t phase)
{
	uint64_t deadline=millis()+opt.timeout_ms;
	struct xdev_ext_mech_stats s;
	for (;;) {
		NEED(stats(&s),"native stats");
		if (s.inflight>run.max_inflight) run.max_inflight=s.inflight;
		if (s.sequestered || s.state==XDEV_EXT_MECH_SESSION_ERROR || s.state==XDEV_EXT_MECH_SESSION_ZOMBIE) {
			run.retained=true; fail(1,"UNKNOWN holds resources");
		}
		if (s.batches_abort || s.rejects || s.protocol_err || s.timeouts || s.last_err) fail(1,"native batch failure");
		if (s.batches_done==target && !s.inflight) break;
		if (s.batches_done>target || millis()>=deadline) fail(1,"phase deadline or cumulative count mismatch");
		struct pollfd p={.fd=run.efd,.events=POLLIN};
		int ret=poll(&p,1,0);
		if (ret<0 && errno!=EINTR) fail(2,"eventfd poll");
		if (ret>0) { uint64_t notifications; if (read(run.efd,&notifications,sizeof(notifications))<0 && errno!=EAGAIN && errno!=EINTR) fail(2,"eventfd read"); }
	}
	if (s.submitted[0]!=target || s.submitted[1]!=target || s.completed[0]!=target || s.completed[1]!=target)
		fail(1,"actual native stage command counts");
	char name[64]; snprintf(name,sizeof(name),"phase-%u-stats.bin",phase);
	NEED(save_bytes(name,&s,sizeof(s)),"phase stats evidence");
}
int main(int argc,char **argv)
{
	enum {O_OBJECT=1,O_REQUESTS,O_NG,O_BLOCK,O_CE,O_OUTPUT,O_DIRECTION,O_GPU,O_DISK,O_GUARD,O_DEPTH,O_LBA,O_SLBA,O_NLB,O_TIMEOUT};
	static const struct option options[]={
		{"object",1,0,O_OBJECT},{"requests",1,0,O_REQUESTS},{"ng",1,0,O_NG},{"block",1,0,O_BLOCK},
		{"ce",1,0,O_CE},{"output",1,0,O_OUTPUT},{"direction",1,0,O_DIRECTION},
		{"gpu-bytes",1,0,O_GPU},{"disk-bytes",1,0,O_DISK},{"guard-bytes",1,0,O_GUARD},
		{"depth",1,0,O_DEPTH},{"lba-bytes",1,0,O_LBA},{"scratch-slba",1,0,O_SLBA},
		{"scratch-nlb",1,0,O_NLB},{"timeout-ms",1,0,O_TIMEOUT},{0,0,0,0}};
	int c; bool direction=false;
	opt.timeout_ms=60000;
	while ((c=getopt_long(argc,argv,"",options,NULL))!=-1) {
		uint64_t v;
		switch(c) {
		case O_OBJECT:opt.object=optarg;break; case O_REQUESTS:opt.requests=optarg;break;
		case O_NG:opt.ng=optarg;break;case O_BLOCK:opt.block=optarg;break;case O_CE:opt.ce=optarg;break;
		case O_OUTPUT:opt.output=optarg;break;
		case O_DIRECTION:if(strcmp(optarg,"load") && strcmp(optarg,"save")) return 2;opt.save=!strcmp(optarg,"save");direction=true;break;
		case O_GPU:opt.g.gpu_bytes=integer(optarg);break;case O_DISK:opt.g.disk_bytes=integer(optarg);break;
		case O_GUARD:opt.g.guard_bytes=integer(optarg);break;
		case O_DEPTH:v=integer(optarg);if(v>UINT32_MAX)return 2;opt.g.depth=(uint32_t)v;break;
		case O_LBA:v=integer(optarg);if(v>UINT32_MAX)return 2;opt.g.lba_bytes=(uint32_t)v;break;
		case O_SLBA:opt.scratch_slba=integer(optarg);break;case O_NLB:opt.scratch_nlb=integer(optarg);break;
		case O_TIMEOUT:opt.timeout_ms=integer(optarg);break;default:return 2;
		}
	}
	if (optind!=argc || !direction || !opt.output || !opt.object || !opt.requests || !opt.ng || !opt.block || !opt.ce ||
	    !opt.timeout_ms || opt.timeout_ms>3600000 || rr_geometry_check(&opt.g)) return 2;
	NEED(state("setup","initializing"),"state evidence");
	if (opt.scratch_slba>INT64_MAX/opt.g.lba_bytes) fail(2,"scratch byte offset overflow");
	run.disk_base=opt.scratch_slba*opt.g.lba_bytes;
	run.disk_full=opt.g.disk_bytes+2*opt.g.guard_bytes;
	if (run.disk_full>SIZE_MAX || run.disk_full>(uint64_t)INT64_MAX-run.disk_base ||
	    opt.scratch_nlb!=run.disk_full/opt.g.lba_bytes) fail(2,"exclusive scratch bounds");
	size_t count; struct rr_request *rows=read_requests(&count);
	NEED(rr_validate(&opt.g,rows,count,opt.save),"frozen request qualification");
	run.ng=open(opt.ng,O_RDWR|O_CLOEXEC); run.block=open(opt.block,O_RDWR|O_CLOEXEC|O_DIRECT);
	run.ce=open(opt.ce,O_RDWR|O_CLOEXEC);
	if (run.ng<0 || run.block<0 || run.ce<0) fail(4,"actual devices unavailable");
	namespace_identity(); allocate_gpu();
	void *gpu=malloc((size_t)run.allocation_bytes), *disk=NULL;
	if (!gpu || posix_memalign(&disk,opt.g.lba_bytes>4096?opt.g.lba_bytes:4096,(size_t)run.disk_full)) fail(2,"whole-image buffers");
	pattern(gpu,(size_t)run.allocation_bytes,UINT64_C(0x10213243c9a47f5a));
	pattern(disk,(size_t)run.disk_full,UINT64_C(0x21324354c6b5a493));
	NEED(save_bytes("gpu-initial.bin",gpu,(size_t)run.allocation_bytes),"frozen GPU initial");
	NEED(save_bytes("disk-initial.bin",disk,(size_t)run.disk_full),"frozen disk initial");
	NEED(gpu_io(true,gpu,(size_t)run.allocation_bytes),"whole GPU initialization");
	NEED(disk_io(true,disk,(size_t)run.disk_full),"exclusive scratch initialization");
	NEED(rr_private_open(&run.programs,opt.object,count,opt.output),"PRIVATE paired object load");
	struct io_uring_params params={0}; run.ring=syscall(__NR_io_uring_setup,8,&params);
	run.efd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
	if (run.ring<0 || run.efd<0 || sysconf(_SC_PAGESIZE)>RR_FRAME) fail(4,"native ring/frame geometry");
	run.umem_bytes=(size_t)opt.g.depth*RR_PAYLOAD;
	run.umem=mmap(NULL,run.umem_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,-1,0);
	if (run.umem==MAP_FAILED) fail(2,"host UMEM allocation");
	struct io_uring_xdev_ext_umem_reg reg={.addr=(uintptr_t)run.umem,.size=run.umem_bytes,.frame_size=RR_FRAME};
	if (syscall(__NR_io_uring_register,run.ring,IORING_REGISTER_XDEV_EXT_UMEM,&reg,1)) fail(4,"native32KiB UMEM register");
	struct xdev_ext_mech_create request; int selectors[4]; struct xdev_ext_mech_create_report report;
	NEED(rr_create(&request,&opt.g,run.ng,run.ce,run.cuda.va+opt.g.guard_bytes,
		opt.scratch_slba+opt.g.guard_bytes/opt.g.lba_bytes,opt.g.disk_bytes/opt.g.lba_bytes,opt.save,run.efd),"actual range CREATE assembly");
	rr_selectors(selectors,run.programs.nvme_fd,run.programs.ce_fd,opt.save);
	NEED(save_bytes("create-request.bin",&request,sizeof(request)),"CREATE evidence");
	NEED(save_bytes("private-selectors.bin",selectors,sizeof(selectors)),"PRIVATE selector evidence");
	int result=xdev_ext_create_programs_read(run.ring,&request,selectors,2,&report);
	/* Record ownership immediately: evidence I/O itself can fail. Missing
	 * delivery after a CREATE attempt grants no cleanup permission. */
	if (!result && report.session_id) {run.session=report.session_id;run.created=true;}
	if (report.cleanup==XDEV_EXT_MECH_CREATE_CLEANUP_RETAINED ||
	    (result && report.size!=sizeof(report))) run.retained=true;
	NEED(save_bytes("create-report.bin",&report,sizeof(report)),"CREATE report evidence");
	if (run.retained) fail(1,"CREATE retained or undelivered resources");
	if (result || !report.session_id) fail(4,"native reported CREATE refused");
	for (unsigned stage=0;stage<2;stage++) {
		struct xdev_ext_mech_stage_caps caps={.size=sizeof(caps),.version=1,.session_id=run.session,.stage=stage};
		NEED(mech(XDEV_EXT_MECH_OP_STAGE_CAPS,&caps),"actual native caps");
		char name[64];snprintf(name,sizeof(name),"stage-%u-caps.bin",stage);
		NEED(save_bytes(name,&caps,sizeof(caps)),"native caps evidence");
		/* CE/NVMe currently leave native_queue UNKNOWN. Preserve the raw
		 * metadata; actual device identity, native command counts and full
		 * device readback below are separate evidence, not a cap rewrite. */
		if (caps.refused) fail(4,"native admission capability refusal");
	}
	NEED(rr_private_fill_freeze(&run.programs,run.session,rows,count,opt.output),"all-phase map readback/freeze");
	if (!run.programs.frozen) fail(2,"START forbidden before map freeze");
	NEED(state("running","map frozen before START"),"running evidence");
	uint32_t *indices=calloc(opt.g.depth*RR_FRAMES,sizeof(*indices));
	if (!indices) fail(2,"host frame index allocation");
	for (uint32_t i=0;i<opt.g.depth*RR_FRAMES;i++) indices[i]=i;
	for (size_t first=0;first<count;) {
		size_t end=first+1; while(end<count && rows[end].phase==rows[first].phase) end++;
		struct xdev_ext_mech_notify_arm arm={.session_id=run.session,.batches_target=end};
		NEED(mech(XDEV_EXT_MECH_OP_NOTIFY_ARM,&arm),"cumulative notification arm");
		struct xdev_ext_mech_start start={.session_id=run.session,.nr_batches=end-first,.first_seq=rows[first].key,
			.flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE,
			.nr_user_frames=opt.g.depth*RR_FRAMES,.user_frames=(uintptr_t)indices};
		uint64_t deadline=millis()+opt.timeout_ms;
		do { result=mech(XDEV_EXT_MECH_OP_START,&start); if(result!=-EBUSY)break;usleep(1000); } while(millis()<deadline);
		if (result) fail(1,"native phase START refused");
		wait_phase(end,rows[first].phase);
		/* No pending work/inflight/UNKNOWN remains. Caller has not submitted
		 * the next phase, so whole-image reads cannot race a future DMA. */
		NEED(gpu_io(false,gpu,(size_t)run.allocation_bytes),"whole GPU allocation snapshot");
		NEED(disk_io(false,disk,(size_t)run.disk_full),"whole storage snapshot");
		char name[64]; snprintf(name,sizeof(name),"phase-%u-gpu.bin",rows[first].phase);
		NEED(save_bytes(name,gpu,(size_t)run.allocation_bytes),"whole GPU phase evidence");
		snprintf(name,sizeof(name),"phase-%u-disk.bin",rows[first].phase);
		NEED(save_bytes(name,disk,(size_t)run.disk_full),"whole disk phase evidence");
		first=end;
	}
	NEED(stop(),"synchronous STOP_REPORT release");
	if (run.max_inflight<2) fail(4,"multiple logical batches not observed");
	rr_private_close(&run.programs);
	close(run.ring);run.ring=-1;close(run.efd);run.efd=-1;
	munmap(run.umem,run.umem_bytes);run.umem=MAP_FAILED;
	close(run.ce);run.ce=-1;
	NEED(xdev_ext_mech_cuda_close(&run.cuda),"CUDA VMM release");
	close(run.ng);run.ng=-1;close(run.block);run.block=-1;
	free(indices);free(rows);free(gpu);free(disk);
	NEED(state("captured","independent whole-image oracle required"),"capture evidence");
	return 0; /* Capture is not a correctness PASS; controller runs oracle. */
}
