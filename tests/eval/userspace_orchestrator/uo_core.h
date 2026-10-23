/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UO_CORE_H
#define UO_CORE_H

/*
 * Pure part of uo_bench, the user-space shared-region baseline (reviewer
 * E2): one region is registered with every subsystem (AF_XDP UMEM, io_uring
 * fixed buffers, optionally cudaHostRegister) and this process sequences the
 * stages itself.  Spec parsing, the frame map of the region, the NVMe
 * passthrough command and the I/O vectors live here so test_uo_core.c can
 * check them without devices.
 *
 * Frame map: the region is CHAIN_XSK_FRAMES chunks of 4 KiB (the AF_XDP
 * UMEM).  In-flight slot k of depth owns chunks [k * F, (k + 1) * F) for a
 * group of F NXP segments; a segment's payload sits at the layout's
 * hdr_room inside its chunk, its 82 header bytes right before it, which is
 * where an AF_XDP packet starts and where a receiving socket puts it.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>

#include "../chains/chain_spec.h"
#include "../../../kernel/include/uapi/linux/nvme_ioctl.h"

#define UO_SCHEMA	"xdev-uo-spec-v1"
#define UO_CHUNK	XDEV_EXT_MECH_CTL_FRAME_SIZE
#define UO_MAX_SEGS	XDEV_EXT_MECH_MAX_FRAMES

enum uo_wait { UO_WAIT_POLL = 1, UO_WAIT_EVENTFD };
enum uo_nvme_io { UO_IO_PASSTHRU_VEC = 1, UO_IO_READ_FIXED };

struct uo_spec {
	char chain[32];
	enum chain_mode mode;
	enum uo_wait wait;
	enum uo_nvme_io nvme_io;
	enum chain_xsk_mode xsk_mode;
	enum chain_load load;
	uint32_t group_bytes, depth, burst, lba_bytes;
	uint64_t batches, warmup, timeout_ms;
	bool hugepage;
	char ng[CHAIN_PATH_MAX], block[CHAIN_PATH_MAX];
	uint64_t slba, nlb;
	char ifname[16];
	uint32_t queue;
	char gpu_bdf[32];
	struct xdev_ext_mech_peer peer;
	uint64_t nxp_session;
	enum chain_oracle_kind oracle;
	char oracle_path[CHAIN_PATH_MAX], reference[CHAIN_PATH_MAX];
	uint64_t oracle_offset;
	char out[CHAIN_PATH_MAX];
	/* derived */
	bool rx, gpu;
};

static inline int uo_parse(const char *text, size_t len, struct uo_spec *s,
			   struct chain_err *e)
{
	static const char *const keys[] = { "schema", "chain", "mode", "wait",
		"nvme_io", "afxdp_mode", "group_bytes", "batches", "warmup", "burst",
		"depth", "timeout_ms", "hugepage", "nvme", "nic", "gpu", "peer",
		"oracle", "out", "load", NULL };
	static const char *const nvme_keys[] = { "ng", "block", "slba", "nlb",
		"lba_bytes", NULL };
	static const char *const nic_keys[] = { "ifname", "queue", NULL };
	static const char *const gpu_keys[] = { "bdf", NULL };
	static const char *const oracle_keys[] = { "kind", "path", "reference",
		"offset", NULL };
	static struct cj_doc doc;
	char buf[32];
	const char *bad;
	int root, o, x;

	memset(s, 0, sizeof(*s));
	root = cj_parse(&doc, text, len);
	if (root < 0)
		return chain_bad(e, "invalid: JSON at byte %zu: %s", doc.err_off, doc.err);
	bad = cj_unknown(&doc, root, keys);
	if (bad)
		return chain_bad(e, "invalid: unknown member %s", bad);
	if (cj_str(&doc, root, "schema", buf, sizeof(buf)) || strcmp(buf, UO_SCHEMA))
		return chain_bad(e, "invalid: schema must be %s", UO_SCHEMA);
	if (chain_path(&doc, root, "chain", true, s->chain, sizeof(s->chain), e) ||
	    CHAIN_ENUM(&doc, root, "mode", -1, &x, e, "correctness", "timing"))
		return -1;
	s->mode = (enum chain_mode)x;
	if (CHAIN_ENUM(&doc, root, "wait", -1, &x, e, "poll", "eventfd"))
		return -1;
	s->wait = (enum uo_wait)x;
	if (CHAIN_ENUM(&doc, root, "nvme_io", UO_IO_PASSTHRU_VEC, &x, e, "passthru-vec",
		       "read-fixed"))
		return -1;
	s->nvme_io = (enum uo_nvme_io)x;
	if (CHAIN_ENUM(&doc, root, "afxdp_mode", CH_XSK_ZC, &x, e, "zc", "copy"))
		return -1;
	s->xsk_mode = (enum chain_xsk_mode)x;
	if (CHAIN_ENUM(&doc, root, "load", CH_LOAD_CLOSED, &x, e, "closed", "sustained"))
		return -1;
	s->load = (enum chain_load)x;
	s->hugepage = true;
	if (cj_bool(&doc, root, "hugepage", &s->hugepage) < 0)
		return chain_bad(e, "invalid: hugepage must be a boolean");
	if (chain_u32(&doc, root, "group_bytes", 0, true, 512, 1U << 20,
		      &s->group_bytes, e) ||
	    chain_u64(&doc, root, "batches", 0, true, 1, CHAIN_MAX_BATCHES, &s->batches, e) ||
	    chain_u64(&doc, root, "warmup", 0, false, 0, CHAIN_MAX_BATCHES, &s->warmup, e) ||
	    chain_u32(&doc, root, "burst", 1, false, 1, CHAIN_MAX_BATCHES, &s->burst, e) ||
	    chain_u32(&doc, root, "depth", 0, true, 1, CHAIN_MAX_DEPTH, &s->depth, e) ||
	    chain_u64(&doc, root, "timeout_ms", 30000, false, 1, 3600000, &s->timeout_ms, e) ||
	    chain_path(&doc, root, "out", false, s->out, sizeof(s->out), e))
		return -1;
	o = cj_get(&doc, root, "nvme");
	if (o < 0 || doc.n[o].type != CJ_OBJECT)
		return chain_bad(e, "invalid: nvme must be an object");
	bad = cj_unknown(&doc, o, nvme_keys);
	if (bad)
		return chain_bad(e, "invalid: unknown nvme member %s", bad);
	if (chain_path(&doc, o, "ng", false, s->ng, sizeof(s->ng), e) ||
	    chain_path(&doc, o, "block", false, s->block, sizeof(s->block), e) ||
	    chain_u64(&doc, o, "slba", 0, true, 0, UINT64_MAX >> 16, &s->slba, e) ||
	    chain_u64(&doc, o, "nlb", 0, true, 1, UINT64_MAX >> 16, &s->nlb, e) ||
	    chain_u32(&doc, o, "lba_bytes", 0, true, 512, 4096, &s->lba_bytes, e))
		return -1;
	o = cj_get(&doc, root, "nic");
	if (o < 0 || doc.n[o].type != CJ_OBJECT)
		return chain_bad(e, "invalid: nic must be an object");
	bad = cj_unknown(&doc, o, nic_keys);
	if (bad)
		return chain_bad(e, "invalid: unknown nic member %s", bad);
	if (chain_path(&doc, o, "ifname", true, s->ifname, sizeof(s->ifname), e) ||
	    chain_u32(&doc, o, "queue", 0, false, 0, 4095, &s->queue, e))
		return -1;
	o = cj_get(&doc, root, "gpu");
	if (o >= 0) {
		if (doc.n[o].type != CJ_OBJECT || (bad = cj_unknown(&doc, o, gpu_keys)))
			return chain_bad(e, "invalid: gpu must be {\"bdf\": ...}");
		if (chain_path(&doc, o, "bdf", true, s->gpu_bdf, sizeof(s->gpu_bdf), e))
			return -1;
	}
	o = cj_get(&doc, root, "peer");
	{
		struct chain_spec tmp;

		memset(&tmp, 0, sizeof(tmp));
		if (o < 0 || doc.n[o].type != CJ_OBJECT ||
		    chain_parse_peer(&doc, o, &tmp, e))
			return e->msg[0] ? -1 : chain_bad(e, "invalid: missing peer");
		s->peer = tmp.peer;
		s->nxp_session = tmp.nxp_session;
	}
	s->oracle = CH_ORACLE_NONE;
	o = cj_get(&doc, root, "oracle");
	if (o >= 0) {
		if (doc.n[o].type != CJ_OBJECT)
			return chain_bad(e, "invalid: oracle must be an object");
		bad = cj_unknown(&doc, o, oracle_keys);
		if (bad)
			return chain_bad(e, "invalid: unknown oracle member %s", bad);
		if (CHAIN_ENUM(&doc, o, "kind", -1, &x, e, "none", "file"))
			return -1;
		s->oracle = (enum chain_oracle_kind)x;
		if (s->oracle == CH_ORACLE_FILE &&
		    (chain_path(&doc, o, "path", true, s->oracle_path,
				sizeof(s->oracle_path), e) ||
		     chain_path(&doc, o, "reference", true, s->reference,
				sizeof(s->reference), e) ||
		     chain_u64(&doc, o, "offset", 0, false, 0, UINT64_MAX >> 1,
			       &s->oracle_offset, e)))
			return -1;
	}
	return 0;
}

/* @have_cuda: this binary was built with UO_CUDA=1. */
static inline int uo_validate(struct uo_spec *s, bool have_cuda, struct chain_err *e)
{
	if (!strcmp(s->chain, "nvme-nic") || !strcmp(s->chain, "nvme-gpu-nic")) {
		s->rx = false;
	} else if (!strcmp(s->chain, "nic-nvme") || !strcmp(s->chain, "nic-gpu-nvme")) {
		s->rx = true;
	} else if (!strcmp(s->chain, "nvme-iaa-gpu") || !strcmp(s->chain, "nic-iaa-gpu")) {
		return chain_bad(e, "unsupported: the user-space orchestrator has no IAA "
				 "stage (user-space IAA via QPL/accel-config is not implemented)");
	} else if (!strcmp(s->chain, "nvme-crc-nic")) {
		return chain_bad(e, "%s", CHAIN_REFUSE_CRC);
	} else {
		return chain_bad(e, "invalid: unknown chain %s", s->chain);
	}
	s->gpu = strstr(s->chain, "-gpu-") != NULL;
	if (s->gpu && !have_cuda)
		return chain_bad(e, "unsupported: %s needs a UO_CUDA=1 build (cuMemHostRegister)",
				 s->chain);
	if (s->gpu && !s->gpu_bdf[0])
		return chain_bad(e, "invalid: %s needs gpu.bdf", s->chain);
	if (s->nvme_io == UO_IO_PASSTHRU_VEC && !s->ng[0])
		return chain_bad(e, "invalid: nvme_io passthru-vec needs nvme.ng");
	if (s->nvme_io == UO_IO_READ_FIXED && !s->block[0])
		return chain_bad(e, "invalid: nvme_io read-fixed needs nvme.block");
	if (s->group_bytes % s->lba_bytes)
		return chain_bad(e, "invalid: group_bytes must be whole LBAs");
	if (s->batches % s->burst || s->warmup % s->burst)
		return chain_bad(e, "invalid: batches and warmup must be multiples of burst");
	if (!s->rx && s->oracle != CH_ORACLE_NONE)
		return chain_bad(e, "invalid: a sender has no local oracle; the receiver checks");
	return 0;
}

/* The NXP geometry of a layout from xdev_ext_mech_ctl_layout(). */
struct uo_map {
	struct xdev_ext_mech_layout l;
	uint32_t segs;			/* frames (segments) per group */
	uint32_t headroom;		/* UMEM headroom of a receiving socket */
};

static inline int uo_map(const struct uo_spec *s, uint32_t mtu, struct uo_map *m,
			 struct chain_err *e)
{
	int ret = xdev_ext_mech_ctl_layout(mtu, s->group_bytes, &m->l);

	if (ret)
		return chain_bad(e, "invalid: NXP layout of %u bytes at MTU %u: %d",
				 s->group_bytes, mtu, ret);
	m->segs = (uint32_t)xdev_ext_mech_layout_frames(&m->l);
	m->headroom = 0;
	if (s->rx && xdev_ext_mech_ctl_rx_headroom(&m->l, &m->headroom))
		return chain_bad(e, "invalid: receive headroom");
	if ((uint64_t)s->depth * m->segs > CHAIN_XSK_FRAMES / 2)
		return chain_bad(e, "invalid: depth x segments exceeds half the UMEM");
	if (s->nvme_io == UO_IO_READ_FIXED &&
	    (m->l.seg_len % s->lba_bytes || m->l.hdr_room % s->lba_bytes))
		return chain_bad(e, "unsupported: read-fixed needs LBA-sized, LBA-aligned "
				 "segments; the NXP layout has %u-byte segments at offset %u "
				 "(use passthru-vec)", m->l.seg_len, m->l.hdr_room);
	if (s->batches + s->warmup >
	    s->nlb / (s->group_bytes / s->lba_bytes))
		return chain_bad(e, "invalid: NVMe window holds fewer groups than the run");
	return 0;
}

/* UMEM offset of the chunk of segment @j of slot @k. */
static inline uint64_t uo_chunk(const struct uo_map *m, uint32_t k, uint32_t j)
{
	return ((uint64_t)k * m->segs + j) * UO_CHUNK;
}

/* Payload span of segment @j inside its chunk. */
static inline void uo_span(const struct uo_map *m, uint32_t j, uint32_t *off,
			   uint32_t *len)
{
	uint32_t done = j * m->l.seg_len;

	*off = m->l.hdr_room;
	*len = m->l.group_bytes - done < m->l.seg_len ? m->l.group_bytes - done :
							m->l.seg_len;
}

/*
 * The payload spans of slot @k's group as I/O vectors over @region, in
 * segment order: what one vectored NVMe passthrough command transfers.
 */
static inline uint32_t uo_iov(const struct uo_map *m, uint8_t *region, uint32_t k,
			      struct iovec *iov)
{
	uint32_t j, off, len;

	for (j = 0; j < m->segs; j++) {
		uo_span(m, j, &off, &len);
		iov[j].iov_base = region + uo_chunk(m, k, j) + off;
		iov[j].iov_len = len;
	}
	return m->segs;
}

/* NVMe READ (0x02) or WRITE (0x01) of group @g, vectored over @nr iovecs. */
static inline void uo_nvme_cmd(const struct uo_spec *s, uint32_t nsid, bool write,
			       uint64_t g, const struct iovec *iov, uint32_t nr,
			       struct nvme_uring_cmd *c)
{
	uint32_t lbas = s->group_bytes / s->lba_bytes;
	uint64_t slba = s->slba + g * lbas;

	memset(c, 0, sizeof(*c));
	c->opcode = write ? 0x01 : 0x02;
	c->nsid = nsid;
	c->addr = (uintptr_t)iov;
	c->data_len = nr;		/* NVME_URING_CMD_IO_VEC: the iovec count */
	c->cdw10 = (uint32_t)slba;
	c->cdw11 = (uint32_t)(slba >> 32);
	c->cdw12 = lbas - 1;
}

/* The one result line of a spec uo_bench refuses before running. */
static inline void uo_print_refusal(FILE *f, bool invalid, const char *msg)
{
	fprintf(f, "{\"schema\":\"xdev-uo-result-v1\",\"status\":\"%s\",\"failure\":",
		invalid ? "invalid" : "not_run");
	cj_write_str(f, msg);
	fputs("}\n", f);
}

#endif /* UO_CORE_H */
