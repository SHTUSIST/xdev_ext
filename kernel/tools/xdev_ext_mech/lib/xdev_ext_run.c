// SPDX-License-Identifier: GPL-2.0
/*
 * libxdev_ext one call: NVMe READ into AF_XDP UMEM frames, AF_XDP TX of
 * the same frames (SPEC.md section 4), built only from the public steps.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "libxdev_ext.h"
#include "libxdev_ext_internal.h"

static int run_validate(const struct xdev_ext_nvme_nic_opts *o,
			const struct xdev_ext_run_result *r)
{
	int ret;

	if (!o || !r || r->sz < sizeof(*r))
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags)
		return -EOPNOTSUPP;
	if (!o->nvme_path || !o->ifname || !o->nlb || !o->group_bytes ||
	    !o->depth || !o->nr_batches ||
	    (o->xsk_mode != XDEV_EXT_XSK_ZEROCOPY && o->xsk_mode != XDEV_EXT_XSK_COPY) ||
	    o->nr_progs > XDEV_EXT_MAX_PROGS || (o->nr_progs && !o->progs))
		return -EINVAL;
	return 0;
}

static void detach_all(struct xdev_ext_prog **prog, __u32 n)
{
	while (n--)
		xdev_ext_prog_detach(prog[n]);
}

int xdev_ext_nvme_to_nic(const struct xdev_ext_nvme_nic_opts *o,
			 struct xdev_ext_run_result *r)
{
	struct xdev_ext_prog *prog[XDEV_EXT_MAX_PROGS];
	struct xdev_ext_session *s = NULL;
	struct xdev_ext_pool_opts pool;
	struct xdev_ext_create_opts c;
	struct xdev_ext_start_opts st;
	size_t rsz;
	__u32 nr_prog = 0, i;
	int ret, nvme = -1, nvme_stage;

	ret = run_validate(o, r);
	if (ret)
		return ret;
	rsz = r->sz;
	memset(r, 0, rsz);
	r->sz = rsz;
	for (i = 0; i < o->nr_progs; i++) {
		ret = xdev_ext_prog_attach(&o->progs[i], &prog[nr_prog]);
		if (ret)
			goto unwind;
		nr_prog++;
	}
	nvme = open(o->nvme_path, O_RDONLY | O_CLOEXEC);
	if (nvme < 0) {
		ret = -errno;
		goto unwind;
	}
	pool = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = XDEV_EXT_MECH_POOL_XSK, .xsk_mode = o->xsk_mode,
		.ifname = o->ifname, .queue = o->queue);
	ret = xdev_ext_session_open(&pool, &s);
	if (ret)
		goto unwind;
	/* From here the session owns the NVMe fd and the programs. */
	nvme_stage = nvme;
	xdev_ext__session_own_fd(s, nvme);
	nvme = -1;
	for (i = 0; i < nr_prog; i++)
		xdev_ext__session_adopt_prog(s, prog[i], xdev_ext_prog_detach);
	nr_prog = 0;
	r->zero_copy = xdev_ext_session_zero_copy(s);

	c = XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
		.group_bytes = o->group_bytes, .depth = o->depth,
		.nr_stages = 2, .peer = o->peer);
	c.st[0] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE,
		.fd = nvme_stage, .arg0 = o->slba, .arg1 = o->nlb };
	c.st[1] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = -1 };
	ret = xdev_ext_session_create(s, &c);
	if (ret)
		goto close;
	r->session_id = xdev_ext_session_id(s);
	ret = xdev_ext_session_arm(s, o->nr_batches, 0);
	if (ret)
		goto stop;
	st = XDEV_EXT_OPTS_INIT(xdev_ext_start_opts, .nr_batches = o->nr_batches);
	ret = xdev_ext_session_start(s, &st);
	if (ret)
		goto stop;
	r->wait_err = xdev_ext_session_wait(s, o->timeout_ms, &r->stats);
	ret = r->wait_err;
	/* STOP releases the session: read the NIC accounting while it lives. */
	r->nic_err = xdev_ext_session_nic_accounting(s, &r->nic);
	if (!ret)
		ret = r->nic_err;
stop:
	r->stop_err = xdev_ext_session_stop(s);
	if (!ret)
		ret = r->stop_err;
close:
	if (xdev_ext_session_close(s)) {
		/* Retained: every resource, programs included, stays with it. */
		r->retained = true;
		r->session = s;
		return ret ? ret : -EBUSY;
	}
	return ret;
unwind:
	if (nvme >= 0)
		close(nvme);
	detach_all(prog, nr_prog);
	return ret;
}
