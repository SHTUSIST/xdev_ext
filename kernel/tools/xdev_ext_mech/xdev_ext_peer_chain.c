// SPDX-License-Identifier: GPL-2.0
/* One registration and one START: NVMe -> authoritative GPU pool -> NVMe or
 * native NIC TX. This tool never creates a software provider or accesses it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "../../include/uapi/linux/io_uring.h"
#include "../../include/uapi/linux/xdev_ext_peer.h"
#include "../../include/uapi/linux/xdev_ext_mech.h"
#include "xdev_ext_mech_cuda.h"
struct peer_bpf { struct bpf_object *object; struct bpf_link *link; };
static int load_ops(const char *directory, const char *name, struct peer_bpf *bpf)
{
 char path[PATH_MAX];
 struct bpf_map *map;
 long error;
 if (snprintf(path, sizeof(path), "%s/%s.bpf.o", directory, name) >= (int)sizeof(path)) return -ENAMETOOLONG;
 bpf->object = bpf_object__open_file(path, NULL);
 error = libbpf_get_error(bpf->object);
 if (error) { bpf->object = NULL; return error; }
 error = bpf_object__load(bpf->object);
 if (error) return error;
 bpf_object__for_each_map(map, bpf->object) {
  if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS) continue;
  bpf->link = bpf_map__attach_struct_ops(map);
  error = libbpf_get_error(bpf->link);
  if (error) { bpf->link = NULL; return error; }
  return 0;
 }
 return -ENOENT;
}
static int mech(int ring, __u32 op, uint64_t argument)
{
 struct io_uring_xdev_ext_mech req = {.op = op, .arg = argument};
 int ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);
 return ret < 0 ? -errno : ret;
}
static int parse_u64(const char *s, uint64_t *value)
{
 char *end;
 unsigned long long n;
 if (!s || !*s || *s == '-') return -EINVAL;
 errno = 0; n = strtoull(s, &end, 0);
 if (errno || *end) return -EINVAL;
 *value = n; return 0;
}
static int mac(const char *text, __u8 bytes[6])
{
 unsigned int value[6]; char extra;
 if (sscanf(text, "%x:%x:%x:%x:%x:%x%c", &value[0], &value[1], &value[2], &value[3], &value[4], &value[5], &extra) != 6)
  return -EINVAL;
 for (int i=0;i<6;i++) { if (value[i]>255) return -EINVAL; bytes[i]=value[i]; }
 return 0;
}
static int run_chain(int allocation, const char *source, const char *target,
                      uint64_t groups, uint32_t bytes, uint32_t shift,
                      uint64_t source_slba, uint64_t target_slba)
{
 struct io_uring_params params = {};
 struct xdev_ext_mech_create create = {
  .abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
  .pool_kind = XDEV_EXT_MECH_POOL_PEER, .pool_fd = allocation,
  .layout = {65536,0,bytes,bytes}, .depth = 1, .eventfd = -1,
 };
 struct xdev_ext_mech_notify_arm arm = {.batches_target = groups};
 struct xdev_ext_mech_start start = {.nr_batches = groups};
 struct xdev_ext_mech_stats stats = {};
 struct pollfd wait;
 uint64_t nlb;
 int src = -1, dst = -1, ring = -1, notify = -1, ret;
 unsigned int ifindex, queue;
 char local[18], remote[18], extra;
 bool created = false;
 if (!groups || shift < 9 || shift > 31 || !bytes || bytes > 65536 ||
     (bytes & ((1U << shift)-1)) || groups > UINT64_MAX / (bytes >> shift)) return -EINVAL;
 if (!strncmp(target, "net/", 4) && bytes > 16384) return -EINVAL;
 nlb = groups * (bytes >> shift);
 if (source_slba > UINT64_MAX - nlb || target_slba > UINT64_MAX - nlb) return -EOVERFLOW;
 src = open(source, O_RDONLY | O_CLOEXEC);
 if (src < 0) { ret=-errno; goto out; }
 if (!strncmp(target,"net/",4)) {
  if (sscanf(target,"net/%u/%u/%17[^/]/%17s%c",&ifindex,&queue,local,remote,&extra)!=4 ||
      !ifindex || mac(local,create.peer.local_mac) || mac(remote,create.peer.peer_mac)) { ret=-EINVAL; goto out; }
  dst = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC);
  create.st[1] = (struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NET,
     .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=dst,.arg0=ifindex,.arg1=queue};
 } else {
  dst = open(target, O_RDWR | O_CLOEXEC);
  create.st[1] = (struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,
     .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=dst,.arg0=target_slba,.arg1=nlb};
 }
 if (dst < 0) { ret=-errno; goto out; }
 create.st[0] = (struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,
    .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=src,.arg0=source_slba,.arg1=nlb};
 notify = eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
 if (notify<0) { ret=-errno; goto out; }
 create.eventfd=notify;
 ring=syscall(__NR_io_uring_setup,8,&params);
 if (ring<0) { ret=-errno; goto out; }
 ret=mech(ring,XDEV_EXT_MECH_OP_CREATE,(uintptr_t)&create);
 if (ret) goto out;
 created=true;
 arm.session_id=start.session_id=stats.session_id=create.session_id;
 ret=mech(ring,XDEV_EXT_MECH_OP_NOTIFY_ARM,(uintptr_t)&arm);
 if (!ret) ret=mech(ring,XDEV_EXT_MECH_OP_START,(uintptr_t)&start);
 if (ret) goto out;
 wait=(struct pollfd){.fd=notify,.events=POLLIN};
 do { ret=poll(&wait,1,120000); } while (ret<0 && errno==EINTR);
 if (ret<=0) { ret=ret ? -errno : -ETIMEDOUT; goto out; }
 ret=mech(ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&stats);
 if (ret) goto out;
 fprintf(stdout,"peer chain: done=%llu abort=%llu inflight=%llu sequestered=%llu status=%d\n",
   (unsigned long long)stats.batches_done,(unsigned long long)stats.batches_abort,
   (unsigned long long)stats.inflight,(unsigned long long)stats.sequestered,stats.last_err);
 ret=stats.batches_done==groups && !stats.batches_abort && !stats.inflight && !stats.sequestered &&
     !stats.last_err && stats.completed[0]==groups && stats.completed[1]==groups ? 0 : -EIO;
out:
 if (created) {
  int stop=mech(ring,XDEV_EXT_MECH_OP_STOP,create.session_id);
  if (!ret && stop) ret=stop;
 }
 if (ring>=0) close(ring);
 if (notify>=0) close(notify);
 if (dst>=0) close(dst);
 if (src>=0) close(src);
 return ret;
}
int main(int argc, char **argv)
{
 struct xdev_ext_mech_cuda cuda={};
 struct peer_bpf nvme={},net={};
 struct xdev_ext_peer_register registration={};
 uint64_t groups,bytes,shift,srcslba,dstslba,fd_number;
 int base,allocation=-1,gpu=-1,control=-1,ret=0;
 bool owns_allocation=false;
 if (argc==2 && !strcmp(argv[1],"--help")) goto usage_ok;
 if (argc==11 && !strcmp(argv[1],"--allocation-fd")) {
  if (parse_u64(argv[2],&fd_number) || fd_number>INT_MAX) goto usage;
  allocation=fd_number; base=3;
 } else if (argc==12 && !strcmp(argv[1],"--cuda")) {
  base=4;
 } else goto usage;
 if (parse_u64(argv[base+2],&groups) || parse_u64(argv[base+3],&bytes) || bytes>UINT32_MAX ||
     parse_u64(argv[base+4],&shift) || shift>31 || parse_u64(argv[base+5],&srcslba) ||
     parse_u64(argv[base+6],&dstslba)) goto usage;
 ret=load_ops(argv[base+7],"nvme_s0",&nvme);
 if (!ret && !strncmp(argv[base+1],"net/",4)) ret=load_ops(argv[base+7],"net_peer",&net);
 if (ret) goto out;
 if (allocation<0) {
  ret=xdev_ext_mech_cuda_open(&cuda,argv[2],65536);
  if (ret) goto out;
  gpu=open(argv[3],O_RDWR|O_CLOEXEC); control=open("/dev/xdev_ext_peer",O_RDWR|O_CLOEXEC);
  if (gpu<0 || control<0) { ret=-errno; goto out; }
  registration=(struct xdev_ext_peer_register){.gpu_fd=gpu,.gpu_va=cuda.va,.len=65536};
  allocation=ioctl(control,XDEV_EXT_PEER_REGISTER,&registration);
  if (allocation<0) { ret=-errno; goto out; }
  owns_allocation=true;
 }
 ret=run_chain(allocation,argv[base],argv[base+1],groups,bytes,shift,srcslba,dstslba);
out:
 if (owns_allocation) close(allocation);
 if (control>=0) close(control);
 if (gpu>=0) close(gpu);
 bpf_link__destroy(net.link); bpf_object__close(net.object);
 bpf_link__destroy(nvme.link); bpf_object__close(nvme.object);
 { int cleanup=xdev_ext_mech_cuda_close(&cuda); if (!ret) ret=cleanup; }
 if (ret) fprintf(stderr,"peer chain failed: %s (%d)\n",strerror(-ret),ret);
 return ret ? 1 : 0;
usage:
 ret=2;
usage_ok:
 fprintf(stderr,"usage: %s --allocation-fd FD SOURCE_NG TARGET GROUPS BYTES LBA_SHIFT SOURCE_SLBA TARGET_SLBA BPF_DIR\n"
                "       %s --cuda PCI_BDF GPU_NODE SOURCE_NG TARGET GROUPS BYTES LBA_SHIFT SOURCE_SLBA TARGET_SLBA BPF_DIR\n"
                "TARGET is a writable NVMe generic namespace or net/IFINDEX/QUEUE/LOCAL_MAC/PEER_MAC.\n",argv[0],argv[0]);
 return ret;
}
