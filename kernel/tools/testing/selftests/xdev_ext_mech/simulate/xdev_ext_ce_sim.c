// SPDX-License-Identifier: GPL-2.0
/*
 * CPU stand-in for a GPU copy-engine backend of the XDEV_EXT mechanism layer.
 *
 * Test infrastructure, kept apart from the real backend: the "device memory"
 * is a vmalloc window and the "copy engine" is memcpy() in a workqueue.  It
 * registers through xdev_ext_ce_backend_register() like the real driver, so CE
 * stages, plan validation, completion classification and sequestering run
 * unchanged.  The completion comes from the workqueue, or from an hrtimer
 * (non-process context) when delay_us is set.  fail_mode injects a failure
 * before the engine saw the transfer (pre_submit) or after (ambiguous).
 */
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/xdev_ext_mech.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

enum xdev_ext_ce_sim_fail {
	SIM_FAIL_NONE,
	SIM_FAIL_PRE_SUBMIT,
	SIM_FAIL_AMBIGUOUS,
};

static const char * const fail_mode_names[] = {
	[SIM_FAIL_NONE] = "none", [SIM_FAIL_PRE_SUBMIT] = "pre_submit",
	[SIM_FAIL_AMBIGUOUS] = "ambiguous",
};

static int fail_mode;

static int fail_mode_set(const char *val, const struct kernel_param *kp)
{
	int mode = sysfs_match_string(fail_mode_names, val);

	if (mode < 0)
		return mode;
	WRITE_ONCE(fail_mode, mode);
	return 0;
}

static int fail_mode_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%s\n", fail_mode_names[READ_ONCE(fail_mode)]);
}

static const struct kernel_param_ops fail_mode_ops = {
	.set = fail_mode_set,
	.get = fail_mode_get,
};
module_param_cb(fail_mode, &fail_mode_ops, NULL, 0644);
MODULE_PARM_DESC(fail_mode, "none, pre_submit or ambiguous; read at each submit");

static unsigned int delay_us;
module_param(delay_us, uint, 0644);
MODULE_PARM_DESC(delay_us, "complete from an hrtimer this long after the copy; 0: from the workqueue");

static unsigned long window_size = 4UL << 20;
module_param(window_size, ulong, 0444);
MODULE_PARM_DESC(window_size, "bytes of stand-in device memory");

static unsigned int seg_size = 64U << 10;
module_param(seg_size, uint, 0444);
MODULE_PARM_DESC(seg_size, "device-contiguous segment reported to the CE class; 0: one segment");

/* One lock defines the submit/complete accounting order, including hard IRQ. */
static DEFINE_SPINLOCK(xdev_ext_ce_sim_stats_lock);
static unsigned long long accepted, completed, pending, peak_pending;
static unsigned long long submit_before_first_complete;

static int xdev_ext_ce_sim_stat_get(char *buf, const struct kernel_param *kp)
{
	unsigned long flags;
	unsigned long long value;

	spin_lock_irqsave(&xdev_ext_ce_sim_stats_lock, flags);
	value = *(unsigned long long *)kp->arg;
	spin_unlock_irqrestore(&xdev_ext_ce_sim_stats_lock, flags);
	return sysfs_emit(buf, "%llu\n", value);
}

static const struct kernel_param_ops xdev_ext_ce_sim_stat_ops = {
	.get = xdev_ext_ce_sim_stat_get,
};
#define SIM_STAT(name) module_param_cb(name, &xdev_ext_ce_sim_stat_ops, &name, 0444)
SIM_STAT(accepted);
SIM_STAT(completed);
SIM_STAT(pending);
SIM_STAT(peak_pending);
SIM_STAT(submit_before_first_complete);

static void *xdev_ext_ce_sim_window;
static struct workqueue_struct *xdev_ext_ce_sim_wq;

/* The pool pages, mapped once at bind_host(). */
struct xdev_ext_ce_sim_host {
	void *vaddr;
	u64 bytes;
};

/* One accepted submit, owned by the stand-in until xdev_ext_ce_complete(). */
struct xdev_ext_ce_sim_req {
	struct work_struct work;
	struct hrtimer timer;
	struct xdev_ext_ce_cookie *ck;
	u64 ticket;
	void *window;
	u64 window_len;
	struct xdev_ext_ce_sim_host *host;
	u64 bytes;
	int status;
	bool hw_submitted;
	int mode;
	unsigned int delay_us;
	u32 dir;
	u32 n;
	struct xdev_ext_ce_xfer x[] __counted_by(n);
};

static int xdev_ext_ce_sim_bind_region(struct file *f, u64 gpu_va, u64 len,
				  struct xdev_ext_ce_region *out)
{
	u64 end;

	if (!len || check_add_overflow(gpu_va, len, &end) || end > window_size)
		return -EINVAL;
	out->priv = xdev_ext_ce_sim_window + gpu_va;
	out->len = len;
	out->seg_size = seg_size;
	out->max_entry_len = 0;
	return 0;
}

/* The window belongs to the module; binding took nothing. */
static void xdev_ext_ce_sim_unbind_region(struct xdev_ext_ce_region *r)
{
}

static int xdev_ext_ce_sim_bind_host(struct xdev_ext_ce_region *r, struct page **pages,
				u32 nr, void **host)
{
	struct xdev_ext_ce_sim_host *h = kzalloc(sizeof(*h), GFP_KERNEL);

	if (!h)
		return -ENOMEM;
	h->vaddr = vmap(pages, nr, VM_MAP, PAGE_KERNEL);
	if (!h->vaddr) {
		kfree(h);
		return -ENOMEM;
	}
	h->bytes = (u64)nr << PAGE_SHIFT;
	*host = h;
	return 0;
}

static void xdev_ext_ce_sim_unbind_host(void *host)
{
	struct xdev_ext_ce_sim_host *h = host;

	vunmap(h->vaddr);
	kfree(h);
}

static bool xdev_ext_ce_sim_in(u64 off, u32 len, u64 size)
{
	u64 end;

	return !check_add_overflow(off, (u64)len, &end) && end <= size;
}

/* The engine: every range is checked before the first byte moves. */
static int xdev_ext_ce_sim_copy(struct xdev_ext_ce_sim_req *req)
{
	u32 i;

	for (i = 0; i < req->n; i++) {
		if (!xdev_ext_ce_sim_in(req->x[i].gpu_off, req->x[i].len,
				   req->window_len) ||
		    !xdev_ext_ce_sim_in(req->x[i].host_byte_off, req->x[i].len,
				   req->host->bytes))
			return -EFAULT;
	}
	for (i = 0; i < req->n; i++) {
		void *dev = req->window + req->x[i].gpu_off;
		void *mem = req->host->vaddr + req->x[i].host_byte_off;

		if (req->dir == XDEV_EXT_MECH_DIR_TO_DEVICE)
			memcpy(dev, mem, req->x[i].len);
		else
			memcpy(mem, dev, req->x[i].len);
		req->bytes += req->x[i].len;
	}
	return 0;
}

static void xdev_ext_ce_sim_finish(struct xdev_ext_ce_sim_req *req)
{
	unsigned long flags;

	/* Publish accounting before complete can wake a waiter or release ck. */
	spin_lock_irqsave(&xdev_ext_ce_sim_stats_lock, flags);
	completed++;
	pending--;
	spin_unlock_irqrestore(&xdev_ext_ce_sim_stats_lock, flags);
	xdev_ext_ce_complete(req->ck, req->ticket, req->status, req->hw_submitted, req->bytes);
	/* The cookie may already be gone: only our private request remains. */
	kfree(req);
}

/* Interrupt context: HRTIMER_MODE_REL expires in hard interrupt. */
static enum hrtimer_restart xdev_ext_ce_sim_timer(struct hrtimer *t)
{
	xdev_ext_ce_sim_finish(container_of(t, struct xdev_ext_ce_sim_req, timer));
	return HRTIMER_NORESTART;
}

static void xdev_ext_ce_sim_work(struct work_struct *work)
{
	struct xdev_ext_ce_sim_req *req = container_of(work, struct xdev_ext_ce_sim_req,
						  work);

	switch (req->mode) {
	case SIM_FAIL_PRE_SUBMIT:
		/* Refused before the engine saw it: nothing moved. */
		req->status = -EBUSY;
		req->hw_submitted = false;
		break;
	case SIM_FAIL_AMBIGUOUS:
		/* The engine ran and its outcome was lost. */
		xdev_ext_ce_sim_copy(req);
		req->status = -EIO;
		req->hw_submitted = true;
		break;
	default:
		req->status = xdev_ext_ce_sim_copy(req);
		/* A refused range never reached the engine. */
		req->hw_submitted = !req->status;
		break;
	}
	if (req->delay_us)
		hrtimer_start(&req->timer, us_to_ktime(req->delay_us),
			      HRTIMER_MODE_REL);
	else
		xdev_ext_ce_sim_finish(req);
}

static int xdev_ext_ce_sim_submit(struct xdev_ext_ce_region *r, void *host, u32 dir,
			     const struct xdev_ext_ce_xfer *x, u32 n,
			     struct xdev_ext_ce_cookie *ck, u64 ticket)
{
	struct xdev_ext_ce_sim_req *req;
	unsigned long flags;

	req = kzalloc(struct_size(req, x, n), GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	req->n = n;
	memcpy(req->x, x, n * sizeof(*x));
	INIT_WORK(&req->work, xdev_ext_ce_sim_work);
	hrtimer_setup(&req->timer, xdev_ext_ce_sim_timer, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);
	req->ck = ck;
	req->ticket = ticket;
	req->window = r->priv;
	req->window_len = r->len;
	req->host = host;
	req->dir = dir;
	req->mode = READ_ONCE(fail_mode);
	req->delay_us = READ_ONCE(delay_us);
	spin_lock_irqsave(&xdev_ext_ce_sim_stats_lock, flags);
	accepted++;
	pending++;
	if (pending > peak_pending)
		peak_pending = pending;
	if (!completed)
		submit_before_first_complete++;
	spin_unlock_irqrestore(&xdev_ext_ce_sim_stats_lock, flags);
	queue_work(xdev_ext_ce_sim_wq, &req->work);
	return 0;
}

/* read()/write() fill and check the window from user space. */
static ssize_t xdev_ext_ce_sim_read(struct file *f, char __user *buf, size_t len,
			       loff_t *pos)
{
	return simple_read_from_buffer(buf, len, pos, xdev_ext_ce_sim_window,
				       window_size);
}

static ssize_t xdev_ext_ce_sim_write(struct file *f, const char __user *buf,
				size_t len, loff_t *pos)
{
	return simple_write_to_buffer(xdev_ext_ce_sim_window, window_size, pos, buf,
				      len);
}

static loff_t xdev_ext_ce_sim_llseek(struct file *f, loff_t off, int whence)
{
	return fixed_size_llseek(f, off, whence, window_size);
}

static const struct file_operations xdev_ext_ce_sim_fops = {
	.owner		= THIS_MODULE,
	.read		= xdev_ext_ce_sim_read,
	.write		= xdev_ext_ce_sim_write,
	.llseek		= xdev_ext_ce_sim_llseek,
};

static struct miscdevice xdev_ext_ce_sim_dev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "xdev_ext_ce_sim",
	.fops		= &xdev_ext_ce_sim_fops,
	.mode		= 0600,
};

static const struct xdev_ext_ce_backend_ops xdev_ext_ce_sim_backend = {
	.owner		= THIS_MODULE,
	.fops		= &xdev_ext_ce_sim_fops,
	.bind_region	= xdev_ext_ce_sim_bind_region,
	.unbind_region	= xdev_ext_ce_sim_unbind_region,
	.bind_host	= xdev_ext_ce_sim_bind_host,
	.unbind_host	= xdev_ext_ce_sim_unbind_host,
	.submit		= xdev_ext_ce_sim_submit,
};

static int __init xdev_ext_ce_sim_init(void)
{
	int err;

	if (!window_size || window_size > SZ_1G)
		return -EINVAL;
	xdev_ext_ce_sim_window = vzalloc(window_size);
	if (!xdev_ext_ce_sim_window)
		return -ENOMEM;
	xdev_ext_ce_sim_wq = alloc_workqueue("xdev_ext_ce_sim", WQ_UNBOUND, 0);
	if (!xdev_ext_ce_sim_wq) {
		err = -ENOMEM;
		goto free_window;
	}
	err = misc_register(&xdev_ext_ce_sim_dev);
	if (err)
		goto free_wq;
	err = xdev_ext_ce_backend_register(&xdev_ext_ce_sim_backend);
	if (err)
		goto deregister;
	return 0;

deregister:
	misc_deregister(&xdev_ext_ce_sim_dev);
free_wq:
	destroy_workqueue(xdev_ext_ce_sim_wq);
free_window:
	vfree(xdev_ext_ce_sim_window);
	return err;
}

/*
 * Sessions pin this module until their last completion, but a completion
 * callback may still be returning: destroy_workqueue() waits for the work,
 * and synchronize_rcu() for an hrtimer callback, which runs with interrupts
 * disabled.
 */
static void __exit xdev_ext_ce_sim_exit(void)
{
	xdev_ext_ce_backend_unregister(&xdev_ext_ce_sim_backend);
	misc_deregister(&xdev_ext_ce_sim_dev);
	destroy_workqueue(xdev_ext_ce_sim_wq);
	synchronize_rcu();
	vfree(xdev_ext_ce_sim_window);
}

module_init(xdev_ext_ce_sim_init);
module_exit(xdev_ext_ce_sim_exit);
MODULE_DESCRIPTION("XDEV_EXT mechanism layer: memcpy stand-in for a copy-engine backend (tests only)");
MODULE_LICENSE("GPL");
