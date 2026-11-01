/* SPDX-License-Identifier: GPL-2.0 */
/* Requirement: successful XSK open creates all four rings without seeding
 * device/kernel-held frames. Missing RX construction is the intended RED. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include "libxdev_ext.h"
#include "libxdev_ext_internal.h"
#include "include/uapi/linux/io_uring.h"

#define XSK_FD 10001
#define RING_FD 10002
#define EVENT_FD 10003
struct mapping { void *base; size_t bytes; uint64_t offset; int active; };
static struct mapping maps[8];
static unsigned int nr_maps, ring_options, close_count;
static int failures, fail_rx_map, allow_create;
static void check(int ok, const char *name)
{
 printf("%s - %s\n", ok ? "ok" : "not ok", name);
 if (!ok) failures++;
}
int __wrap_socket(int domain, int type, int protocol)
{
 (void)protocol;
 if (domain != AF_XDP || type != (SOCK_RAW | SOCK_CLOEXEC)) { errno = EAFNOSUPPORT; return -1; }
 return XSK_FD;
}
unsigned int __wrap_if_nametoindex(const char *name)
{
 if (!strcmp(name, "fixture0")) return 7;
 errno = ENODEV; return 0;
}
int __wrap_eventfd(unsigned int initial, int flags)
{ (void)initial; (void)flags; return EVENT_FD; }
int __wrap_close(int fd)
{
 if (fd == XSK_FD || fd == RING_FD || fd == EVENT_FD) { close_count++; return 0; }
 errno = EBADF; return -1;
}
int __wrap_setsockopt(int fd, int level, int opt, const void *value, socklen_t bytes)
{
 if (fd != XSK_FD || level != SOL_XDP) { errno = EINVAL; return -1; }
 if (opt == XDP_UMEM_REG) {
  const struct xdp_umem_reg *reg = value;
  if (bytes != sizeof(*reg) || !reg->addr || reg->len != 8 * 4096 || reg->chunk_size != 4096) {
   errno = EINVAL; return -1;
  }
  return 0;
 }
 if (bytes != sizeof(uint32_t) || *(const uint32_t *)value != 2048) { errno = EINVAL; return -1; }
 switch (opt) {
 case XDP_RX_RING: ring_options |= 1; break;
 case XDP_UMEM_FILL_RING: ring_options |= 2; break;
 case XDP_UMEM_COMPLETION_RING: ring_options |= 4; break;
 case XDP_TX_RING: ring_options |= 8; break;
 default: errno = ENOPROTOOPT; return -1;
 }
 return 0;
}
int __wrap_getsockopt(int fd, int level, int opt, void *value, socklen_t *bytes)
{
 if (fd != XSK_FD || level != SOL_XDP) { errno = EINVAL; return -1; }
 if (opt == XDP_MMAP_OFFSETS && *bytes >= sizeof(struct xdp_mmap_offsets)) {
  struct xdp_mmap_offsets *o = value;
  memset(o, 0, sizeof(*o));
  /* Deliberately distinct offsets expose using a TX/FILL offset for RX. */
  o->rx = (struct xdp_ring_offset){ .producer=16, .consumer=32, .desc=128, .flags=48 };
  o->tx = (struct xdp_ring_offset){ .producer=20, .consumer=36, .desc=192, .flags=52 };
  o->fr = (struct xdp_ring_offset){ .producer=24, .consumer=40, .desc=256, .flags=56 };
  o->cr = (struct xdp_ring_offset){ .producer=28, .consumer=44, .desc=320, .flags=60 };
  *bytes = sizeof(*o); return 0;
 }
 if (opt == XDP_OPTIONS && *bytes >= sizeof(struct xdp_options)) {
  *(struct xdp_options *)value = (struct xdp_options){ .flags = 0 };
  *bytes = sizeof(struct xdp_options); return 0;
 }
 errno = ENOPROTOOPT; return -1;
}
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t bytes)
{
 const struct sockaddr_xdp *a = (const void *)addr;
 if (fd != XSK_FD || bytes != sizeof(*a) || a->sxdp_family != AF_XDP ||
     a->sxdp_ifindex != 7 || a->sxdp_queue_id != 3 || !(a->sxdp_flags & XDP_COPY)) {
  errno = EINVAL; return -1;
 }
 return 0;
}
void *__wrap_mmap(void *addr, size_t bytes, int prot, int flags, int fd, off_t offset)
{
 void *p;
 (void)addr; (void)prot; (void)flags;
 if (fd != -1 && fd != XSK_FD) { errno = EBADF; return MAP_FAILED; }
 if (fail_rx_map && fd == XSK_FD && offset == XDP_PGOFF_RX_RING) { errno=ENOMEM; return MAP_FAILED; }
 p = calloc(1, bytes);
 if (!p) { errno=ENOMEM; return MAP_FAILED; }
 if (nr_maps == 8) abort();
 maps[nr_maps++] = (struct mapping){p, bytes, fd == -1 ? UINT64_MAX : (uint64_t)offset, 1};
 return p;
}
int __wrap_munmap(void *addr, size_t bytes)
{
 unsigned int i;
 for (i=0; i<nr_maps; i++) if (maps[i].base == addr && maps[i].active) {
  if (maps[i].bytes != bytes) { errno=EINVAL; return -1; }
  maps[i].active=0; free(addr); return 0;
 }
 errno=EINVAL; return -1;
}
static int setup(unsigned int entries, struct io_uring_params *p)
{ (void)p; return entries == 8 ? RING_FD : -EINVAL; }
static int reg(int fd, unsigned int op, void *arg, unsigned int nr)
{
 (void)fd;(void)nr;
 if(op==IORING_REGISTER_XDEV_EXT_UMEM)return 0;
 if(allow_create && op==IORING_REGISTER_XDEV_EXT_MECH) {
  struct io_uring_xdev_ext_mech *req=arg;
  if(req->op==XDEV_EXT_MECH_OP_CREATE){((struct xdev_ext_mech_create *)(uintptr_t)req->arg)->session_id=77;return 0;}
  if(req->op==XDEV_EXT_MECH_OP_STOP)return 0;
 }
 return -EOPNOTSUPP;
}
static int active_maps(void)
{ unsigned int i; int n=0; for(i=0;i<nr_maps;i++) n+=maps[i].active; return n; }
static int has_map(uint64_t offset, size_t bytes)
{
 unsigned int i;
 for(i=0;i<nr_maps;i++) if(maps[i].active && maps[i].offset==offset && maps[i].bytes==bytes) return 1;
 return 0;
}
static int rings_untouched(void)
{
 unsigned int i;
 for(i=0;i<nr_maps;i++) if(maps[i].active && maps[i].offset != UINT64_MAX) {
  size_t j; const unsigned char *p=maps[i].base;
  for(j=0;j<maps[i].bytes;j++) if(p[j]) return 0;
 }
 return 1;
}
#ifndef SHARED_RECEIVE_FIXTURE_ONLY
int main(int argc, char **argv)
{
 const struct xdev_ext_sys ops={ .io_uring_setup=setup, .io_uring_register=reg };
 struct xdev_ext_pool_opts opts=XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
  .pool_kind=XDEV_EXT_MECH_POOL_XSK,.xsk_mode=XDEV_EXT_XSK_COPY,
  .ifname="fixture0",.queue=3,.nr_frames=8);
 struct xdev_ext_session *s=NULL;
 int ret;
 fail_rx_map=argc>1 && !strcmp(argv[1],"rx-map-failure");
 xdev_ext__set_sys(&ops);
 ret=xdev_ext_session_open(&opts,&s);
 if(fail_rx_map) {
  check(ret==-ENOMEM,"RX mapping failure reaches caller as -ENOMEM");
  if(!ret) xdev_ext_session_close(s);
  check(active_maps()==0,"RX map failure rolls back every successfully mapped ring and UMEM");
  check(close_count==3,"RX map failure closes XSK, io_uring and event FDs");
 } else {
  check(ret==0 && s,"XSK session opens successfully on complete OS fixture");
  if(ret) return 2;
  check(ring_options==15,"successful XSK open configures RX, FILL, CQ and TX");
  check(has_map(XDP_PGOFF_RX_RING,128+2048*sizeof(struct xdp_desc)),"RX maps its own returned offset and xdp_desc capacity");
  check(has_map(XDP_UMEM_PGOFF_FILL_RING,256+2048*sizeof(uint64_t)),"FILL maps its returned offset and address capacity");
  check(has_map(XDP_UMEM_PGOFF_COMPLETION_RING,320+2048*sizeof(uint64_t)),"CQ maps its returned offset and address capacity");
  check(has_map(XDP_PGOFF_TX_RING,192+2048*sizeof(struct xdp_desc)),"TX maps its returned offset and descriptor capacity");
  check(rings_untouched(),"open does not seed frames or consume kernel/device-owned rings");
  check(xdev_ext_session_close(s)==0,"uncreated session closes successfully");
  check(active_maps()==0,"close unmaps all four rings and UMEM");
  check(close_count==3,"close releases all owned descriptors");
 }
 printf("RESULT failures=%d\n",failures);
 return failures ? 1 : 0;
}
#endif
