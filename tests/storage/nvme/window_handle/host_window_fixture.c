/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Host test of the NVMe LBA window handle code (prototype for ASK.69): the
 * production issue ioctl, release, namespace resolution, CREATE window
 * admission and NVMe member bind run verbatim (pasted at PRODUCTION by
 * host_window_test.py); this file supplies OS objects and records what the
 * production code did with them. Requirement under test, as stated in the
 * design: a holder issues a handle for one range and access its own fd and
 * the native policy allow; handles of one namespace sharing an LBA are
 * refused unless both are read-only; a handle leaves the registry at its last
 * reference; a stage presenting a handle binds the namespace the holder
 * opened, only inside the range and in a granted direction; a raw namespace
 * file keeps its whole capacity.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xdev_ext_storfam_core.h"
#include "nvme_ioctl.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define __user
#undef static_assert
#define static_assert(e) _Static_assert(e, #e)
#define THIS_MODULE ((void *)0)
#define GFP_KERNEL 0
#define FMODE_READ 1U
#define FMODE_WRITE 2U
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CLOEXEC 02000000
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define XDEV_EXT_MECH_DIR_TO_DEVICE 1
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 2
#define XDEV_EXT_MECH_POOL_IOU_UMEM 2
#define XDEV_EXT_MECH_POOL_PEER 3

/* ---- lists and locks ---- */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
static void INIT_LIST_HEAD(struct list_head *l) { l->next = l->prev = l; }
static void list_add(struct list_head *n, struct list_head *h)
{ n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static void list_del_init(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; INIT_LIST_HEAD(n); }
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(pos, head, member) \
	for (pos = container_of((head)->next, typeof(*pos), member); \
	     &pos->member != (head); \
	     pos = container_of(pos->member.next, typeof(*pos), member))
struct mutex { int held; };
#define DEFINE_MUTEX(n) struct mutex n = { 0 }
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held = 1; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held = 0; }

/* ---- files ---- */
struct inode;
struct file;
struct file_operations {
	void *owner;
	int (*release)(struct inode *, struct file *);
	int (*uring_cmd)(void);
};
struct file {
	const struct file_operations *f_op;
	unsigned f_mode;
	void *private_data;
	int refs;
	bool released;
};
static unsigned allocations, frees;
static void *kzalloc(size_t n, int flags) { (void)flags; allocations++; return calloc(1, n); }
/* Counted, never returned to the allocator: a freed node a mutant leaves
 * listed stays readable, so the registry checks report it instead of crashing. */
static void kfree(void *p) { if (p) frees++; }
static struct file *get_file(struct file *f) { f->refs++; return f; }
static void fput(struct file *f)
{
	assert(f->refs > 0);
	if (--f->refs)
		return;
	f->released = true;
	if (f->f_op && f->f_op->release)
		f->f_op->release(NULL, f);
}
static int anon_error;
static unsigned anon_files;
static struct file *anon_inode_getfile(const char *name, const struct file_operations *fops,
				       void *priv, int flags)
{
	struct file *f;

	(void)name;
	if (anon_error)
		return ERR_PTR(anon_error);
	f = calloc(1, sizeof(*f));
	f->f_op = fops;
	f->private_data = priv;
	f->refs = 1;
	f->f_mode = (flags & 3) == O_RDONLY ? FMODE_READ : (flags & 3) == O_WRONLY ? FMODE_WRITE :
		    FMODE_READ | FMODE_WRITE;
	anon_files++;
	return f;
}
#define NR_FDS 64
static struct file *fd_table[NR_FDS];
static bool fd_reserved[NR_FDS];
static int fd_error;
static int get_unused_fd_flags(int flags)
{
	int i;

	assert(flags == O_CLOEXEC);
	if (fd_error)
		return fd_error;
	for (i = 3; i < NR_FDS; i++)
		if (!fd_reserved[i]) {
			fd_reserved[i] = true;
			return i;
		}
	return -EMFILE;
}
static void put_unused_fd(int fd) { assert(fd_reserved[fd] && !fd_table[fd]); fd_reserved[fd] = false; }
static void fd_install(int fd, struct file *f) { assert(fd_reserved[fd] && !fd_table[fd]); fd_table[fd] = f; }
static void fd_close(int fd)
{
	struct file *f = fd_table[fd];

	assert(f);
	fd_table[fd] = NULL;
	fd_reserved[fd] = false;
	fput(f);
}
static unsigned long copy_from_user(void *to, const void *from, unsigned long n)
{ memcpy(to, from, n); return 0; }

/* ---- the NVMe namespace and its native policy ---- */
struct nvme_ctrl_ops { const char *name; bool peer_rw; };
struct nvme_ctrl { const struct nvme_ctrl_ops *ops; };
struct nvme_ns_head { int id; };
struct request_queue { int id; };
struct gendisk { int id; };
struct nvme_ns { struct nvme_ctrl *ctrl; struct nvme_ns_head *head; struct request_queue *queue; };
struct nvme_xdev_ext_identity { u64 capacity_lbas; bool namespace_ready, namespace_removing; };
static const struct nvme_ctrl_ops pcie = { "pcie", true };
static struct nvme_ctrl ctrl = { &pcie };
static struct nvme_ns_head head_a = { 1 }, head_b = { 2 };
static struct request_queue queue;
static struct gendisk disk;
static struct nvme_ns ns_a = { &ctrl, &head_a, &queue }, ns_b = { &ctrl, &head_b, &queue };
static int fixture_uring_cmd(void) { return 0; }
static const struct file_operations ng_fops = { .uring_cmd = fixture_uring_cmd };
static struct file ng_a_rw = { &ng_fops, FMODE_READ | FMODE_WRITE, &ns_a, 1, false };
static struct file ng_a_ro = { &ng_fops, FMODE_READ, &ns_a, 1, false };
static struct file ng_a_wo = { &ng_fops, FMODE_WRITE, &ns_a, 1, false };
static struct file ng_b_rw = { &ng_fops, FMODE_READ | FMODE_WRITE, &ns_b, 1, false };
static const u64 capacity = 8192;
static bool allowed_read = true, allowed_write = true;
static bool ns_ready = true, ns_removing;
static int nvme_xdev_ext_capture_identity(struct nvme_ns *ns, struct nvme_xdev_ext_identity *id,
		const struct nvme_ns_head **head, const struct gendisk **d, const struct request_queue **q)
{
	*id = (struct nvme_xdev_ext_identity){ .capacity_lbas = capacity,
		.namespace_ready = ns_ready, .namespace_removing = ns_removing };
	*head = ns->head;
	*d = &disk;
	*q = ns->queue;
	return 0;
}
static bool nvme_xdev_ext_mech_cmd_allowed(struct nvme_ns *ns, struct file *file, bool write)
{
	(void)ns;
	/* As upstream nvme_cmd_allowed: a write needs the fd open for write. */
	if (write && !(file->f_mode & FMODE_WRITE))
		return false;
	return write ? allowed_write : allowed_read;
}

/* ---- the stage ---- */
struct xdev_ext_stor_stage { int unused; };
struct nvme_xdev_ext_mech_stage { struct xdev_ext_stor_stage family; struct nvme_ns *ns; bool write; };
struct xdev_ext_mech_pool { unsigned kind; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
struct xdev_ext_mech_stage {
	struct xdev_ext_mech_session *s;
	struct file *file;
	unsigned direction;
	bool poll;
	u64 arg0, arg1;
};
struct xdev_ext_mech_stage_uapi { u32 flags; };
static struct xdev_ext_mech_session session = { { XDEV_EXT_MECH_POOL_IOU_UMEM } };
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ return &s->pool; }
static bool xdev_ext_stor_block_poll_capable(const struct request_queue *q) { (void)q; abort(); }
static struct file *bound_file;
/* As production: only the ng file type binds. Records the file it got. */
static struct nvme_ns *nvme_xdev_ext_class_ns(struct file *file)
{
	bound_file = file;
	if (!file->f_op || file->f_op->uring_cmd != fixture_uring_cmd)
		return NULL;
	return file->private_data;
}

/* PRODUCTION */

/* ---- cases ---- */
static unsigned checks;
#define EQ(what, got, want) do { long long g_ = (got), w_ = (want); checks++; \
	if (g_ != w_) { fprintf(stderr, "FAIL %s: got %lld want %lld\n", what, g_, w_); exit(1); } } while (0)

static long issue(struct file *ng, u64 slba, u64 nlb, u32 flags, u32 rsvd)
{
	struct nvme_xdev_ext_window w = { .slba = slba, .nlb = nlb, .flags = flags, .rsvd = rsvd };

	return nvme_xdev_ext_window_ioctl(ng->private_data, ng, &w);
}

/* fd numbers reserved by get_unused_fd_flags() and neither installed nor put. */
static unsigned reserved_fds(void)
{
	unsigned n = 0;
	int i;

	for (i = 0; i < NR_FDS; i++)
		n += fd_reserved[i] && !fd_table[i];
	return n;
}

static unsigned listed(void)
{
	struct nvme_xdev_ext_window_handle *w;
	unsigned n = 0;

	list_for_each_entry(w, &nvme_xdev_ext_windows, node)
		n++;
	return n;
}

static struct nvme_ns *file_ns(struct file *f)
{
	if (f->f_op == &ng_fops)
		return f->private_data;
	return ((struct nvme_xdev_ext_window_handle *)f->private_data)->target->private_data;
}

static int bind(struct file *file, bool write, u64 slba, u64 nlb)
{
	struct xdev_ext_mech_stage st = { &session, file,
		write ? XDEV_EXT_MECH_DIR_TO_DEVICE : XDEV_EXT_MECH_DIR_FROM_DEVICE, false, slba, nlb };
	struct xdev_ext_mech_stage_uapi u = { 0 };
	struct xdev_ext_stor_stage *family = NULL;
	void *member = NULL;
	int ret;

	bound_file = NULL;
	ret = nvme_xdev_ext_member_bind(&st, &u, &family, &member);
	if (!ret) {
		struct nvme_xdev_ext_mech_stage *p = member;

		EQ("bound member namespace", p->ns == file_ns(file), 1);
		kfree(member);
	}
	return ret;
}

#define RD NVME_XDEV_EXT_WINDOW_F_READ
#define WR NVME_XDEV_EXT_WINDOW_F_WRITE
#define RDWR (RD | WR)

int main(void)
{
	int a, b, r1, r2, ro, wo, x;
	unsigned before;

	/* Issue errors publish nothing and leak nothing. */
	before = allocations - frees;
	EQ("rsvd", issue(&ng_a_rw, 0, 64, RDWR, 1), -EINVAL);
	EQ("no access", issue(&ng_a_rw, 0, 64, 0, 0), -EINVAL);
	EQ("unknown access", issue(&ng_a_rw, 0, 64, 4, 0), -EINVAL);
	EQ("empty", issue(&ng_a_rw, 0, 0, RDWR, 0), -EINVAL);
	EQ("past capacity", issue(&ng_a_rw, capacity - 8, 64, RDWR, 0), -ERANGE);
	EQ("write on a read-only fd", issue(&ng_a_ro, 0, 64, WR, 0), -EBADF);
	EQ("read on a write-only fd", issue(&ng_a_wo, 0, 64, RD, 0), -EBADF);
	/* Issuing reserves the range against writers: a read handle too
	 * needs an issuer that may write the namespace. */
	EQ("read on a read-only fd", issue(&ng_a_ro, 0, 64, RD, 0), -EBADF);
	allowed_write = false;
	EQ("native policy refuses write", issue(&ng_a_rw, 0, 64, RDWR, 0), -EACCES);
	EQ("native policy refuses write, read handle", issue(&ng_a_rw, 0, 64, RD, 0), -EACCES);
	allowed_write = true;
	allowed_read = false;
	EQ("native policy refuses read", issue(&ng_a_rw, 0, 64, RD, 0), -EACCES);
	allowed_read = true;
	/* As CREATE's namespace admission: only a live namespace issues. */
	ns_ready = false;
	EQ("namespace not ready", issue(&ng_a_rw, 0, 64, RDWR, 0), -ENODEV);
	ns_ready = true;
	ns_removing = true;
	EQ("namespace being removed", issue(&ng_a_rw, 0, 64, RDWR, 0), -ENODEV);
	ns_removing = false;
	EQ("no leak after refusals", allocations - frees, before);
	EQ("nothing listed", listed(), 0);
	EQ("no fd reserved after refusals", reserved_fds(), 0);
	EQ("holder file untouched", ng_a_rw.refs, 1);

	/* A handle: its mode is its access, it pins the holder's file. */
	a = issue(&ng_a_rw, 0, 64, RDWR, 0);
	EQ("issue [0,64) rw", a >= 3, 1);
	EQ("rw handle mode", fd_table[a]->f_mode, FMODE_READ | FMODE_WRITE);
	EQ("handle pins the holder file", ng_a_rw.refs, 2);
	ro = issue(&ng_a_rw, 256, 64, RD, 0);
	EQ("read-only handle", ro >= 3 && fd_table[ro]->f_mode == FMODE_READ, 1);
	wo = issue(&ng_a_rw, 512, 64, WR, 0);
	EQ("write-only handle", wo >= 3 && fd_table[wo]->f_mode == FMODE_WRITE, 1);

	/* Overlap. */
	EQ("rw over rw", issue(&ng_a_rw, 32, 64, RDWR, 0), -EBUSY);
	EQ("read over rw", issue(&ng_a_rw, 63, 1, RD, 0), -EBUSY);
	EQ("write over read-only", issue(&ng_a_rw, 300, 1, WR, 0), -EBUSY);
	EQ("refused overlap leaves no extra pin", ng_a_rw.refs, 4);
	EQ("refused overlap leaves no fd reserved", reserved_fds(), 0);
	r1 = issue(&ng_a_rw, 280, 64, RD, 0);
	EQ("read over read-only allowed", r1 >= 3, 1);
	b = issue(&ng_b_rw, 0, 64, RDWR, 0);
	EQ("same LBAs of another namespace", b >= 3, 1);
	x = issue(&ng_a_rw, 64, 64, RDWR, 0);
	EQ("adjacent", x >= 3, 1);
	EQ("listed", listed(), 6);

	/* Release at the last reference frees the range. */
	get_file(fd_table[x]);	/* a second reference, as a session's stage file */
	{
		struct file *held = fd_table[x];

		fd_close(x);
		EQ("still listed while referenced", listed(), 6);
		EQ("still reserved while referenced", issue(&ng_a_rw, 64, 1, WR, 0), -EBUSY);
		fput(held);
	}
	EQ("unlisted at the last reference", listed(), 5);
	r2 = issue(&ng_a_rw, 64, 64, RDWR, 0);
	EQ("re-issue after release", r2 >= 3, 1);

	/* Failure after the handle file exists frees it, never listed. */
	before = allocations - frees;
	fd_error = -EMFILE;
	EQ("no fd", issue(&ng_a_rw, 1024, 64, RDWR, 0), -EMFILE);
	fd_error = 0;
	anon_error = -ENOMEM;
	EQ("no file", issue(&ng_a_rw, 1024, 64, RDWR, 0), -ENOMEM);
	anon_error = 0;
	EQ("no leak after late failures", allocations - frees, before);
	EQ("late failures unlisted", listed(), 6);
	EQ("no fd reserved after late failures", reserved_fds(), 0);
	x = issue(&ng_a_rw, 1024, 64, RDWR, 0);
	EQ("range of a failed issue is free", x >= 3, 1);
	fd_close(x);

	/* CREATE: a raw namespace file keeps its whole capacity. */
	EQ("raw write anywhere", bind(&ng_a_rw, true, 4096, 64), 0);
	EQ("raw binds the file itself", bound_file == &ng_a_rw, 1);

	/* CREATE through a handle. */
	EQ("write inside", bind(fd_table[a], true, 0, 64), 0);
	EQ("namespace resolved through the handle", bound_file == &ng_a_rw, 1);
	EQ("read inside", bind(fd_table[a], false, 16, 16), 0);
	before = allocations;
	EQ("next window", bind(fd_table[a], true, 64, 64), -EACCES);
	EQ("straddle", bind(fd_table[a], true, 32, 64), -EACCES);
	EQ("one LBA longer", bind(fd_table[a], true, 0, 65), -EACCES);
	EQ("read outside", bind(fd_table[a], false, 4096, 64), -EACCES);
	EQ("write on a read-only handle", bind(fd_table[ro], true, 256, 64), -EBADF);
	EQ("read on a write-only handle", bind(fd_table[wo], false, 512, 64), -EBADF);
	EQ("refusals precede the member allocation", allocations, before);
	EQ("read on a read-only handle", bind(fd_table[ro], false, 256, 64), 0);
	EQ("write on a write-only handle", bind(fd_table[wo], true, 512, 64), 0);

	fd_close(a); fd_close(ro); fd_close(wo); fd_close(r1); fd_close(b); fd_close(r2);
	EQ("all released", listed(), 0);
	EQ("holder pins dropped", ng_a_rw.refs, 1);
	EQ("other holder pin dropped", ng_b_rw.refs, 1);
	EQ("no leak", allocations, frees);
	EQ("no fd reserved", reserved_fds(), 0);
	printf("PASS host window handle checks=%u\n", checks);
	return 0;
}
