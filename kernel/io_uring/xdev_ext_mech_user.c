// SPDX-License-Identifier: GPL-2.0
/*
 * USER stage class: an application thread does the work of a stage, for
 * functions a CPU-class BPF program cannot express.
 * Documentation/userspace-api/xdev_ext-user-stage.rst.
 *
 * A user stage fd (XDEV_EXT_MECH_OP_USER_STAGE) owns one vmalloc_user()
 * region that user space maps: a header with four ring indices and two
 * flag words, a ready ring (kernel -> user), a completion ring (user ->
 * kernel) and a slot table describing each held batch's frames.  ->submit
 * hands a batch out through the ready ring and parks it in this class's
 * held table; ->progress, on the session worker, reaps the completion ring,
 * applies the reported lengths through the same claim-checked call as the
 * CPU class and completes the batch, or cancels held batches at their
 * deadline, on STOP and when the stage is dead.  Frames keep the INPLACE
 * lifecycle of a fixed CPU transform: OUT_PENDING/INFLIGHT while held,
 * republished READY with the new length on completion.
 *
 * The session holds no reference to the user stage file, only to its
 * object, so the file's release (the last descriptor and mapping gone, for
 * example at process exit) marks the stage dead.  The kernel reads each
 * user-written value once and validates its own copy.
 */
#include <linux/anon_inodes.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kref.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_internal.h"
#include "xdev_ext_mech_user_core.h"

/* The object behind a user stage fd. */
struct xdev_ext_user_obj {
	struct kref ref;		/* the file, and the bound stage */
	spinlock_t lock;		/* st, bound */
	struct xdev_ext_mech_stage *st;	/* the live bound stage, NULL otherwise */
	bool bound;			/* bound once: one stage of one session */
	void *region;			/* vmalloc_user(), mapped by user space */
	struct xdev_ext_user_ring_offsets off;
	u32 entries;
	struct eventfd_ctx *evfd;	/* optional kernel -> user wakeup */
};

/* A batch the user thread holds: what completing or cancelling it needs. */
struct xdev_ext_user_held {
	struct xdev_ext_mech_batch *b;	/* NULL: slot not held */
	u64 ticket;
	unsigned long deadline;		/* jiffies */
	u32 nr;
	u32 in_len[XDEV_EXT_MECH_MAX_FRAMES];
	u32 cap[XDEV_EXT_MECH_MAX_FRAMES];
};

/* Stage private data; everything but obj and dead is worker-only. */
struct xdev_ext_user_stage {
	struct xdev_ext_user_obj *obj;
	struct xdev_ext_user_ring_hdr *hdr;
	struct xdev_ext_user_ready *ready;
	struct xdev_ext_user_done *done;
	struct xdev_ext_user_slot *slots;
	struct eventfd_ctx *evfd;
	struct xdev_ext_mech_batch *staged;	/* ->validate admitted it for ->submit */
	u64 staged_arg;
	s64 delta;
	unsigned long timeout;			/* jiffies from submit to deadline */
	u32 entries, depth, nr_held;
	u32 ready_prod, done_cons;		/* the kernel's own indices */
	u32 kflags;				/* the kernel's own copy of kernel_flags */
	bool varlen, dead, stopped;
	struct xdev_ext_user_held held[];	/* depth */
};

static int xdev_ext_user_default_build(struct xdev_ext_mech_stage *st,
				       struct xdev_ext_mech_batch *b, u8 *scratch)
{
	*(struct xdev_ext_user_desc *)scratch = (struct xdev_ext_user_desc) {
		.version = XDEV_EXT_USER_DESC_VERSION,
	};
	return 0;
}

static int xdev_ext_user_validate(struct xdev_ext_mech_stage *st,
				  struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
	struct xdev_ext_user_stage *us = st->priv;
	const struct xdev_ext_user_desc *d = (const void *)scratch;
	int err;

	us->staged = NULL;
	err = xdev_ext_user_desc_check(d, n);
	if (err)
		return err;
	us->staged = b;
	us->staged_arg = d->arg;
	return 0;
}

/* Worker or unbind: nothing more comes; wake a sleeping user thread once. */
static void xdev_ext_user_stopped(struct xdev_ext_user_stage *us)
{
	if (us->stopped)
		return;
	us->stopped = true;
	us->kflags |= XDEV_EXT_USER_K_STOPPED;
	WRITE_ONCE(us->hdr->kernel_flags, us->kflags);
	smp_mb();	/* the flag before the wakeup */
	if (us->evfd)
		eventfd_signal(us->evfd);
}

/* Worker: held batch @slot leaves the stage, completed or cancelled with @err. */
static void xdev_ext_user_end(struct xdev_ext_mech_stage *st, u32 slot, int err, bool cancel)
{
	struct xdev_ext_user_stage *us = st->priv;
	struct xdev_ext_user_held *h = &us->held[slot];
	struct xdev_ext_mech_batch *b = h->b;
	u64 ticket = h->ticket;

	h->b = NULL;
	us->nr_held--;
	WRITE_ONCE(us->slots[slot].ticket, 0);
	if (cancel)
		xdev_ext_mech_batch_complete_cancelled(b, ticket, err);
	else
		xdev_ext_mech_batch_complete(b, ticket, err);
}

/*
 * Worker, the batch already IN_FLIGHT: describe it in the slot table, hand
 * it out through the ready ring and hold it until its completion entry,
 * its deadline or a stop.  A negative return handed out nothing.
 */
static int xdev_ext_user_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_user_stage *us = st->priv;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	u32 slot = xdev_ext_mech_batch_slot(b), nr = xdev_ext_mech_batch_nr_frames(b), i;
	u64 ticket = xdev_ext_mech_batch_ticket(b);
	struct xdev_ext_user_held *h;
	struct xdev_ext_user_slot *ss;
	struct xdev_ext_user_ready *r;
	struct xdev_ext_mech_frame f;
	int err;

	if (READ_ONCE(us->dead))
		return -ENODEV;
	if (!xdev_ext_mech_session_admits(st->s))
		return -ESHUTDOWN;
	if (us->staged != b)
		return -EPROTO;
	us->staged = NULL;
	if (slot >= us->depth || !nr || nr > XDEV_EXT_MECH_MAX_FRAMES)
		return -EINVAL;
	h = &us->held[slot];
	if (h->b)
		return -EBUSY;
	/* A consuming user thread never fills it: at most depth batches are held. */
	if (!xdev_ext_user_ring_room(us->ready_prod, READ_ONCE(us->hdr->ready_cons), us->entries))
		return -ENOBUFS;
	ss = &us->slots[slot];
	for (i = 0; i < nr; i++) {
		err = xdev_ext_mech_batch_frame(b, i, &f);
		if (err)
			return err;
		if (f.data_off >= pool->frame_size || f.data_len > pool->frame_size - f.data_off)
			return -EINVAL;
		h->in_len[i] = f.data_len;
		h->cap[i] = pool->frame_size - f.data_off;
		WRITE_ONCE(ss->f[i].umem_addr, f.umem_addr);
		WRITE_ONCE(ss->f[i].data_off, f.data_off);
		WRITE_ONCE(ss->f[i].data_len, f.data_len);
		WRITE_ONCE(ss->f[i].capacity, h->cap[i]);
		WRITE_ONCE(ss->f[i].out_len, f.data_len);
	}
	h->nr = nr;
	WRITE_ONCE(ss->nr_frames, nr);
	WRITE_ONCE(ss->ticket, ticket);
	r = &us->ready[us->ready_prod & (us->entries - 1)];
	WRITE_ONCE(r->slot, slot);
	WRITE_ONCE(r->nr_frames, nr);
	WRITE_ONCE(r->ticket, ticket);
	WRITE_ONCE(r->batch_id, xdev_ext_mech_batch_id(b));
	WRITE_ONCE(r->key, xdev_ext_mech_batch_key(b));
	WRITE_ONCE(r->arg, us->staged_arg);
	us->ready_prod++;
	smp_store_release(&us->hdr->ready_prod, us->ready_prod);
	h->ticket = ticket;
	h->deadline = jiffies + us->timeout;
	h->b = b;
	/* Deadlines grow with submit order: only a first held batch arms ->progress. */
	if (!us->nr_held++)
		xdev_ext_mech_stage_kick(st);
	smp_mb();	/* ready_prod before user_flags; pairs with the user's barrier */
	if (us->evfd && (READ_ONCE(us->hdr->user_flags) & XDEV_EXT_USER_F_SLEEPING))
		eventfd_signal(us->evfd);
	return 0;
}

/* Worker: one completion entry, already copied out of user memory. */
static void xdev_ext_user_reap_one(struct xdev_ext_mech_stage *st, const struct xdev_ext_user_done *e)
{
	struct xdev_ext_user_stage *us = st->priv;
	u32 out[XDEV_EXT_MECH_MAX_FRAMES], i;
	struct xdev_ext_user_held *h;
	bool bad;
	int err;

	if (e->slot >= us->depth || !us->held[e->slot].b || us->held[e->slot].ticket != e->ticket) {
		/* Stale, duplicate or garbage: never attributable to a held batch. */
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_REJECTS, 1);
		return;
	}
	h = &us->held[e->slot];
	err = xdev_ext_user_status_err(e->status, &bad);
	/* Every length is checked before the first one is applied. */
	for (i = 0; !err && i < h->nr; i++) {
		out[i] = READ_ONCE(us->slots[e->slot].f[i].out_len);
		if (!xdev_ext_user_len_ok(h->in_len[i], out[i], h->cap[i], us->delta, us->varlen)) {
			err = -EPROTO;
			bad = true;
		}
	}
	if (bad)
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
	for (i = 0; !err && i < h->nr; i++)
		err = xdev_ext_mech_batch_cpu_length(h->b, i, out[i]);
	/* Like a CPU transform error: terminal, the payload may be modified. */
	xdev_ext_user_end(st, e->slot, err, false);
}

/*
 * Worker: one bounded pass over the completion ring.  NEED_KICK is clear
 * while the pass runs and set once it found the ring empty; the ring is
 * read once more after setting it, so an entry posted meanwhile is either
 * seen here or its producer sees the flag and kicks.  True when the budget
 * ran out with entries left.
 */
static bool xdev_ext_user_reap(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_user_stage *us = st->priv;
	u32 budget = us->entries, n;
	struct xdev_ext_user_done e;
	bool armed = false, bad;

	us->kflags &= ~XDEV_EXT_USER_K_NEED_KICK;
	WRITE_ONCE(us->hdr->kernel_flags, us->kflags);
	smp_mb();
	for (;;) {
		n = xdev_ext_user_done_window(smp_load_acquire(&us->hdr->done_prod),
					      &us->done_cons, us->entries, &bad);
		if (bad)
			xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_REJECTS, 1);
		if (!n) {
			smp_store_release(&us->hdr->done_cons, us->done_cons);
			if (armed)
				return false;
			armed = true;
			us->kflags |= XDEV_EXT_USER_K_NEED_KICK;
			WRITE_ONCE(us->hdr->kernel_flags, us->kflags);
			smp_mb();	/* the flag before reading done_prod again */
			continue;
		}
		if (armed) {
			armed = false;
			us->kflags &= ~XDEV_EXT_USER_K_NEED_KICK;
			WRITE_ONCE(us->hdr->kernel_flags, us->kflags);
		}
		while (n--) {
			const struct xdev_ext_user_done *s = &us->done[us->done_cons & (us->entries - 1)];

			if (!budget--) {
				smp_store_release(&us->hdr->done_cons, us->done_cons);
				return true;
			}
			e.ticket = READ_ONCE(s->ticket);
			e.slot = READ_ONCE(s->slot);
			e.status = READ_ONCE(s->status);
			us->done_cons++;
			xdev_ext_user_reap_one(st, &e);
		}
	}
}

/*
 * Worker (progress work, the kick ioctl, the deadline timer and STOP):
 * reap, then cancel what passed its deadline, or everything when the stage
 * is dead or the session stops admitting.  Returns the jiffies until the
 * earliest remaining deadline, 0 when nothing is held.
 */
static unsigned long xdev_ext_user_progress(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_user_stage *us = st->priv;
	bool dead = READ_ONCE(us->dead);
	bool stopping = dead || !xdev_ext_mech_session_admits(st->s);
	unsigned long now, next = 0;
	u32 i;

	if (xdev_ext_user_reap(st))
		xdev_ext_mech_stage_kick(st);
	now = jiffies;
	for (i = 0; i < us->depth && us->nr_held; i++) {
		struct xdev_ext_user_held *h = &us->held[i];

		if (!h->b)
			continue;
		if (stopping) {
			/* -EPIPE: the user stage file was released. */
			xdev_ext_user_end(st, i, dead ? -EPIPE : -ESHUTDOWN, true);
			continue;
		}
		if (time_after_eq(now, h->deadline)) {
			xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_TIMEOUTS, 1);
			xdev_ext_user_end(st, i, -ETIMEDOUT, true);
			continue;
		}
		if (!next || h->deadline - now < next)
			next = h->deadline - now;
	}
	if (stopping)
		xdev_ext_user_stopped(us);
	return next;
}

/* Any context, never blocks: the user side went away; ->progress cancels. */
static void xdev_ext_user_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_user_stage *us = st->priv;

	WRITE_ONCE(us->dead, true);
	xdev_ext_mech_stage_kick(st);
}

/* User stage fd. */

static void xdev_ext_user_obj_free(struct kref *ref)
{
	struct xdev_ext_user_obj *obj = container_of(ref, struct xdev_ext_user_obj, ref);

	if (obj->evfd)
		eventfd_ctx_put(obj->evfd);
	vfree(obj->region);
	kfree(obj);
}

/* The last descriptor and mapping are gone: a bound stage is dead. */
static int xdev_ext_user_release(struct inode *inode, struct file *file)
{
	struct xdev_ext_user_obj *obj = file->private_data;

	spin_lock(&obj->lock);
	if (obj->st)
		xdev_ext_mech_stage_dead(obj->st, -EPIPE);
	spin_unlock(&obj->lock);
	kref_put(&obj->ref, xdev_ext_user_obj_free);
	return 0;
}

static int xdev_ext_user_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct xdev_ext_user_obj *obj = file->private_data;

	if (vma->vm_pgoff || vma->vm_end - vma->vm_start > obj->off.mmap_size)
		return -EINVAL;
	return remap_vmalloc_range(vma, obj->region, 0);
}

static long xdev_ext_user_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct xdev_ext_user_obj *obj = file->private_data;
	long ret = -ENOTCONN;

	if (cmd != XDEV_EXT_USER_IOC_KICK)
		return -ENOTTY;
	if (arg)
		return -EINVAL;
	spin_lock(&obj->lock);
	if (obj->st) {
		xdev_ext_mech_stage_kick(obj->st);
		ret = 0;
	}
	spin_unlock(&obj->lock);
	return ret;
}

static const struct file_operations xdev_ext_user_fops = {
	.owner = THIS_MODULE,
	.release = xdev_ext_user_release,
	.mmap = xdev_ext_user_mmap,
	.unlocked_ioctl = xdev_ext_user_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

int xdev_ext_mech_user_stage_create(void __user *uarg)
{
	struct xdev_ext_mech_user_stage __user *ureq = uarg;
	struct xdev_ext_mech_user_stage r;
	struct xdev_ext_user_obj *obj;
	struct file *file;
	int fd, err;

	if (copy_from_user(&r, ureq, sizeof(r)))
		return -EFAULT;
	err = xdev_ext_user_request_check(&r);
	if (err)
		return err;
	obj = kzalloc(sizeof(*obj), GFP_KERNEL_ACCOUNT);
	if (!obj)
		return -ENOMEM;
	kref_init(&obj->ref);
	spin_lock_init(&obj->lock);
	obj->entries = r.entries;
	err = xdev_ext_user_layout(r.entries, PAGE_SIZE, &obj->off);
	if (err)
		goto free;
	err = -ENOMEM;
	obj->region = vmalloc_user(obj->off.mmap_size);
	if (!obj->region)
		goto free;
	if (r.eventfd >= 0) {
		obj->evfd = eventfd_ctx_fdget(r.eventfd);
		if (IS_ERR(obj->evfd)) {
			err = PTR_ERR(obj->evfd);
			obj->evfd = NULL;
			goto free;
		}
	}
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto free;
	}
	file = anon_inode_getfile("[xdev_ext_user_stage]", &xdev_ext_user_fops, obj, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		err = PTR_ERR(file);
		goto free;
	}
	if (put_user(fd, &ureq->fd) || copy_to_user(&ureq->off, &obj->off, sizeof(obj->off))) {
		/* The file owns obj now: its release frees it. */
		put_unused_fd(fd);
		fput(file);
		return -EFAULT;
	}
	fd_install(fd, file);
	return 0;
free:
	if (obj->evfd)
		eventfd_ctx_put(obj->evfd);
	vfree(obj->region);
	kfree(obj);
	return err;
}

/* Stage. */

static int xdev_ext_user_bind(struct xdev_ext_mech_stage *st,
			      const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	u32 depth = xdev_ext_mech_session_depth(st->s);
	struct xdev_ext_user_stage *us;
	struct xdev_ext_user_obj *obj;
	struct file *f;
	bool varlen;
	s64 delta;
	int err;

	/* The user thread addresses frames through the pool's CPU mapping. */
	if (!pool->vaddr)
		return -EOPNOTSUPP;
	err = xdev_ext_user_stage_check(u, pool->frame_size, &delta, &varlen);
	if (err)
		return err;
	f = fget(u->fd);
	if (!f)
		return -EBADF;
	if (f->f_op != &xdev_ext_user_fops) {
		fput(f);
		return -EINVAL;
	}
	obj = f->private_data;
	us = kzalloc(struct_size(us, held, depth), GFP_KERNEL_ACCOUNT);
	if (!us) {
		fput(f);
		return -ENOMEM;
	}
	us->obj = obj;
	us->hdr = obj->region + obj->off.hdr;
	us->ready = obj->region + obj->off.ready;
	us->done = obj->region + obj->off.done;
	us->slots = obj->region + obj->off.slots;
	us->evfd = obj->evfd;
	us->delta = delta;
	us->varlen = varlen;
	us->timeout = msecs_to_jiffies(u->arg0) ?: 1;
	us->entries = obj->entries;
	us->depth = depth;
	us->kflags = XDEV_EXT_USER_K_NEED_KICK;
	/* The file reference held here keeps obj alive and its release out. */
	spin_lock(&obj->lock);
	if (obj->bound)
		err = -EBUSY;
	else if (obj->entries < depth)
		err = -EINVAL;
	if (!err) {
		obj->bound = true;
		kref_get(&obj->ref);
		WRITE_ONCE(us->hdr->kernel_flags, us->kflags);
		st->priv = us;
		obj->st = st;
	}
	spin_unlock(&obj->lock);
	fput(f);
	if (err)
		kfree(us);
	return err;
}

/* After drain (nothing held), process context. */
static void xdev_ext_user_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_user_stage *us = st->priv;
	struct xdev_ext_user_obj *obj = us->obj;

	spin_lock(&obj->lock);
	obj->st = NULL;
	spin_unlock(&obj->lock);
	WARN_ON_ONCE(us->nr_held);
	xdev_ext_user_stopped(us);
	st->priv = NULL;
	kfree(us);
	kref_put(&obj->ref, xdev_ext_user_obj_free);
}

/* No ->poll: F_POLL would requeue the poll work for the whole user compute. */
static const struct xdev_ext_mech_class_ops xdev_ext_user_class = {
	.class_id = XDEV_EXT_MECH_CLASS_USER,
	.desc_size = sizeof(struct xdev_ext_user_desc), .desc_cap = 1,
	.owner = THIS_MODULE,
	.bind = xdev_ext_user_bind, .unbind = xdev_ext_user_unbind,
	.default_build = xdev_ext_user_default_build, .validate = xdev_ext_user_validate,
	.submit = xdev_ext_user_submit, .progress = xdev_ext_user_progress,
	.mark_dead = xdev_ext_user_mark_dead,
};

static int __init xdev_ext_mech_user_init(void)
{
	return xdev_ext_mech_class_register(&xdev_ext_user_class);
}
late_initcall_sync(xdev_ext_mech_user_init);
