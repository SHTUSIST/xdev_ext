// SPDX-License-Identifier: GPL-2.0
/*
 * chain_bench - one multi-stage pipeline of the reviewer's composability
 * experiment (E1), its ablations (E7) and sweeps (E10).
 *
 *   chain_bench --spec FILE.json	run the spec, print one JSON result line
 *   chain_bench --check FILE.json	parse and validate only, print the plan
 *
 * Arms: "session" (one kernel mechanism session for the whole chain, see
 * chain_session.c) and "staged" (per-pair Linux composition with
 * registered/pinned buffers, see chain_staged.c).  The user-space shared
 * region arm is tests/eval/userspace_orchestrator/uo_bench.
 *
 * Exit: 0 pass, 1 run failed, 2 invalid spec, 4 not run (an unsupported
 * chain or a missing device/facility).  A correctness-mode result carries
 * no timing; a timing-mode result carries the raw per-window samples and
 * run.py summarizes them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chain_bench.h"
#include "../common/fd_check.h"
#include "chain_oracle.h"

int cb_fail(struct chain_result *r, int status, const char *fmt, ...)
{
	va_list ap;

	if (r->status)
		return r->status;
	r->status = status;
	va_start(ap, fmt);
	vsnprintf(r->failure, sizeof(r->failure), fmt, ap);
	va_end(ap);
	return status;
}

uint8_t *chain_read_reference(const struct chain_spec *s, size_t *len,
			      struct chain_result *r)
{
	int fd = open(s->reference, O_RDONLY | O_CLOEXEC);
	struct stat sb;
	uint8_t *buf;
	size_t got = 0;

	if (fd < 0 || fstat(fd, &sb) || !S_ISREG(sb.st_mode) || !sb.st_size) {
		cb_fail(r, CB_NOT_RUN, "reference %s: %s", s->reference,
			fd < 0 ? strerror(errno) : "not a non-empty regular file");
		if (fd >= 0)
			close(fd);
		return NULL;
	}
	buf = malloc((size_t)sb.st_size);
	while (buf && got < (size_t)sb.st_size) {
		ssize_t n = read(fd, buf + got, (size_t)sb.st_size - got);

		if (n <= 0)
			break;
		got += (size_t)n;
	}
	close(fd);
	if (!buf || got != (size_t)sb.st_size) {
		free(buf);
		cb_fail(r, CB_NOT_RUN, "reference %s: short read", s->reference);
		return NULL;
	}
	*len = got;
	return buf;
}

/*
 * After the campaign: the bytes at oracle.path + offset against the whole
 * reference, read with O_DIRECT (falling back to a plain read for regular
 * files), since the session writes through the NVMe passthrough device and
 * never through the block device's page cache.
 */
int chain_oracle_file(const struct chain_spec *s, struct chain_result *r)
{
	size_t len = 0, done = 0, chunk = 1U << 20;
	uint8_t *ref = chain_read_reference(s, &len, r), *buf = NULL;
	int fd = -1;

	if (!ref) {
		r->oracle_verdict = "fail";
		return r->status;
	}
	fd = open(s->oracle_path, O_RDONLY | O_CLOEXEC | O_DIRECT);
	if (fd < 0 && errno == EINVAL)
		fd = open(s->oracle_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || posix_memalign((void **)&buf, 4096, chunk)) {
		cb_fail(r, CB_FAIL, "oracle readback %s: %s", s->oracle_path,
			strerror(errno));
		goto out;
	}
	if (s->oracle_offset % 4096) {
		cb_fail(r, CB_INVALID, "oracle offset must be 4096-aligned");
		goto out;
	}
	while (done < len) {
		size_t want = len - done < chunk ? (len - done + 4095) & ~(size_t)4095 :
						   chunk;
		ssize_t n = pread(fd, buf, want, (off_t)(s->oracle_offset + done));
		size_t use;
		long long diff;

		if (n <= 0) {
			cb_fail(r, CB_FAIL, "oracle readback at %zu: %s", done,
				n < 0 ? strerror(errno) : "end of device");
			goto out;
		}
		use = (size_t)n < len - done ? (size_t)n : len - done;
		diff = chain_first_diff(buf, ref + done, use);
		if (diff >= 0) {
			r->oracle_detail = (long long)done + diff;
			cb_fail(r, CB_FAIL, "oracle: first differing byte at %lld (group %llu)",
				r->oracle_detail,
				(unsigned long long)((size_t)r->oracle_detail / s->group_bytes));
			goto out;
		}
		done += use;
	}
	r->oracle_bytes = done;
out:
	r->oracle_verdict = r->status ? "fail" : "pass";
	if (fd >= 0)
		close(fd);
	free(buf);
	free(ref);
	return r->status;
}

/* --- output ------------------------------------------------------------- */

static const char *cb_status(int status)
{
	switch (status) {
	case CB_PASS: return "pass";
	case CB_FAIL: return "fail";
	case CB_INVALID: return "invalid";
	default: return "not_run";
	}
}

static void cb_json_str(FILE *f, const char *s)
{
	cj_write_str(f, s);
}

static uint64_t cb_tv_us(const struct timeval *tv)
{
	return (uint64_t)tv->tv_sec * 1000000ULL + (uint64_t)tv->tv_usec;
}

static void cb_emit(FILE *f, const struct chain_spec *s, const struct chain_result *r)
{
	unsigned int i;
	uint64_t k;

	fprintf(f, "{\"schema\":\"xdev-chain-result-v1\",\"status\":\"%s\",",
		cb_status(r->status));
	fputs("\"chain\":", f);
	cb_json_str(f, s->chain);
	fprintf(f, ",\"arm\":\"%s\",\"mode\":\"%s\",\"group_bytes\":%u,"
		"\"batches\":%llu,\"warmup\":%llu,\"burst\":%u,\"depth\":%u,"
		"\"start_per\":\"%s\",\"plan\":\"%s\",\"afxdp_mode\":\"%s\","
		"\"stages\":%u,\"ce_backend\":\"%s\",\"load\":\"%s\",",
		s->arm == CH_SESSION ? "session" : "staged",
		s->mode == CH_TIMING ? "timing" : "correctness", s->group_bytes,
		(unsigned long long)s->batches, (unsigned long long)s->warmup,
		s->burst, s->depth, s->start_per == CH_START_RUN ? "run" : "batch",
		s->plan == CH_PLAN_BPF ? "bpf" : "default",
		s->xsk_mode == CH_XSK_ZC ? "zc" : "copy", s->nr_stages,
		r->ce_backend ? r->ce_backend : "none",
		s->load == CH_LOAD_SUSTAINED ? "sustained" : "closed");
	if (r->wire_crc)
		fprintf(f, "\"wire_crc\":\"%s\",", r->wire_crc);
	fprintf(f, "\"windows_done\":%llu,\"batches_done\":%llu,",
		(unsigned long long)r->windows_done,
		(unsigned long long)r->batches_done);
	if (s->mode == CH_TIMING && !r->status && s->load == CH_LOAD_SUSTAINED) {
		uint64_t t0 = chain_sustained_t0(&r->sus);

		/*
		 * Completions of the measured records, relative to the end of
		 * the warmup; t0_ns is absolute so run.py can merge concurrent
		 * sessions on the one system-wide clock.
		 */
		fprintf(f, "\"timing\":{\"load\":\"sustained\",\"clock\":\"CLOCK_MONOTONIC_RAW\","
			"\"unit\":\"ns\",\"observer\":\"%s\",\"record_bytes\":%llu,"
			"\"records\":%llu,\"warmup_records\":%llu,\"t0_ns\":%llu,"
			"\"completions\":[", r->observer ? r->observer : "in-process",
			(unsigned long long)s->burst * s->group_bytes,
			(unsigned long long)(r->sus.records - r->sus.warm),
			(unsigned long long)r->sus.warm, (unsigned long long)t0);
		for (k = r->sus.warm; k < r->sus.next; k++)
			fprintf(f, "%s%llu", k > r->sus.warm ? "," : "",
				(unsigned long long)(r->sus.done_ns[k] - t0));
		fputs("]},", f);
	} else if (s->mode == CH_TIMING && !r->status) {
		fprintf(f, "\"timing\":{\"load\":\"closed\",\"clock\":\"CLOCK_MONOTONIC_RAW\","
			"\"unit\":\"ns\",\"window_batches\":%llu,\"window_bytes\":%llu,\"samples\":[",
			(unsigned long long)chain_window_batches(s),
			(unsigned long long)chain_window_batches(s) * s->group_bytes);
		for (k = 0; k < r->nr_samples; k++)
			fprintf(f, "%s%llu", k ? "," : "", (unsigned long long)r->samples[k]);
		fputs("]},", f);
	}
	if (r->have_stats) {
		const struct xdev_ext_mech_stats *t = &r->stats;

		fprintf(f, "\"counters\":{\"state\":\"%s\",\"last_err\":%d,"
			"\"batches_done\":%llu,\"batches_abort\":%llu,\"rejects\":%llu,"
			"\"recycled\":%llu,\"held\":%llu,\"sequestered\":%llu,"
			"\"timeouts\":%llu,\"inflight\":%llu,\"published\":%llu,"
			"\"protocol_err\":%llu,\"submitted\":[",
			xdev_ext_mech_ctl_state_name(t->state), t->last_err,
			(unsigned long long)t->batches_done,
			(unsigned long long)t->batches_abort,
			(unsigned long long)t->rejects, (unsigned long long)t->recycled,
			(unsigned long long)t->held, (unsigned long long)t->sequestered,
			(unsigned long long)t->timeouts, (unsigned long long)t->inflight,
			(unsigned long long)t->published,
			(unsigned long long)t->protocol_err);
		for (i = 0; i < s->nr_stages; i++)
			fprintf(f, "%s%llu", i ? "," : "",
				(unsigned long long)t->submitted[i]);
		fputs("],\"completed\":[", f);
		for (i = 0; i < s->nr_stages; i++)
			fprintf(f, "%s%llu", i ? "," : "",
				(unsigned long long)t->completed[i]);
		fputs("]},", f);
	}
	/* Only a completed run can claim it saw no CPU payload copy. */
	fprintf(f, "\"copies\":{\"zero_cpu_payload_copies\":%s,\"sources\":[",
		r->status ? "null" : r->nr_copy_sources ? "false" : "true");
	for (i = 0; i < r->nr_copy_sources; i++) {
		if (i)
			fputc(',', f);
		cb_json_str(f, r->copy_sources[i]);
	}
	if (s->arm == CH_SESSION) {
		const char *declared[CHAIN_MAX_COPY_SOURCES];
		unsigned int nd = chain_declared_copies(s, declared);

		fputs("],\"declared\":[", f);
		for (i = 0; i < nd; i++) {
			if (i)
				fputc(',', f);
			cb_json_str(f, declared[i]);
		}
	}
	fprintf(f, "],\"nvme_bounces\":%lld,\"xsk_zero_copy\":%d,"
		"\"staged_cpu_copies\":%llu,\"staged_cpu_copy_bytes\":%llu,"
		"\"cpu_read_bytes\":%llu,\"socket_bytes\":%llu},",
		(long long)r->nvme_bounces, r->xsk_zero_copy,
		(unsigned long long)r->cpu_copies,
		(unsigned long long)r->cpu_copy_bytes,
		(unsigned long long)r->cpu_read_bytes,
		(unsigned long long)r->socket_bytes);
	if (r->iaa_completes >= 0)
		fprintf(f, "\"iaa_plan\":{\"completes\":%lld,\"errors\":%lld,\"scope\":\"%s\"},",
			(long long)r->iaa_completes, (long long)r->iaa_errors,
			r->iaa_scope ? r->iaa_scope : "this-process");
	fprintf(f, "\"oracle\":{\"kind\":\"%s\",\"verdict\":\"%s\",\"bytes\":%llu,"
		"\"detail\":%lld},",
		s->oracle == CH_ORACLE_FILE ? "file" :
		s->oracle == CH_ORACLE_CE ? "ce-window" : "none",
		r->oracle_verdict ? r->oracle_verdict : "not-checked",
		(unsigned long long)r->oracle_bytes, r->oracle_detail);
	fprintf(f, "\"cost\":{\"syscalls\":%llu,\"observer_syscalls\":%llu,"
		"\"voluntary_ctxsw\":%ld,"
		"\"involuntary_ctxsw\":%ld,\"user_us\":%llu,\"sys_us\":%llu},",
		(unsigned long long)r->syscalls,
		(unsigned long long)r->observer_syscalls,
		r->ru_after.ru_nvcsw - r->ru_before.ru_nvcsw,
		r->ru_after.ru_nivcsw - r->ru_before.ru_nivcsw,
		(unsigned long long)(cb_tv_us(&r->ru_after.ru_utime) -
				     cb_tv_us(&r->ru_before.ru_utime)),
		(unsigned long long)(cb_tv_us(&r->ru_after.ru_stime) -
				     cb_tv_us(&r->ru_before.ru_stime)));
	fputs("\"failure\":", f);
	cb_json_str(f, r->failure);
	fputs("}\n", f);
}

/* --check: what the spec would create, without opening anything. */
static void cb_plan(const struct chain_spec *s)
{
	struct xdev_ext_mech_stage_uapi u[XDEV_EXT_MECH_MAX_STAGES];
	struct chain_iou_plan iou = { 0 };
	struct chain_err e = { { 0 } };
	int fds[XDEV_EXT_MECH_MAX_STAGES] = { 10, 11, 12, 13 };
	bool xsk = chain_has(s, CH_AFXDP);
	unsigned int i;

	if (!xsk && chain_iou_layout(s, &iou, &e)) {
		printf("{\"status\":\"invalid\",\"failure\":");
		cb_json_str(stdout, e.msg);
		printf("}\n");
		return;
	}
	chain_stage_uapi(s, fds, 99, s->ce_va, iou.iaa_first, u);
	printf("{\"status\":\"ok\",\"chain\":\"%s\",\"pool\":\"%s\",\"load\":\"%s\","
	       "\"windows\":%llu,\"window_batches\":%llu,\"start_batches\":%llu", s->chain,
	       xsk ? "xsk" : "iou_umem", s->load == CH_LOAD_SUSTAINED ? "sustained" : "closed",
	       (unsigned long long)chain_windows(s),
	       (unsigned long long)chain_window_batches(s),
	       (unsigned long long)chain_start_batches(s));
	if (!xsk)
		printf(",\"frame_size\":%u,\"seg_len\":%u,\"src_frames\":%u,"
		       "\"lend_frames\":%u,\"pool_frames\":%u", iou.l.frame_size,
		       iou.l.seg_len, iou.src_frames, iou.lend_frames,
		       iou.pool_frames);
	printf(",\"stages\":[");
	for (i = 0; i < s->nr_stages; i++)
		printf("%s{\"class_id\":%u,\"direction\":%u,\"fd\":%d,\"flags\":%u,"
		       "\"arg0\":%llu,\"arg1\":%llu}", i ? "," : "", u[i].class_id,
		       u[i].direction, u[i].fd, u[i].flags,
		       (unsigned long long)u[i].arg0, (unsigned long long)u[i].arg1);
	printf("]}\n");
}

static char *cb_slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf = NULL;
	long n;

	if (!f)
		return NULL;
	if (!fseek(f, 0, SEEK_END) && (n = ftell(f)) > 0 && n < (1 << 20) &&
	    !fseek(f, 0, SEEK_SET)) {
		buf = malloc((size_t)n + 1);
		if (buf && fread(buf, 1, (size_t)n, f) == (size_t)n) {
			buf[n] = '\0';
			*len = (size_t)n;
		} else {
			free(buf);
			buf = NULL;
		}
	}
	fclose(f);
	return buf;
}

int main(int argc, char **argv)
{
	int fd_before = eval_fd_count();
	static struct chain_spec spec;
	struct chain_result r = { .nvme_bounces = -1, .xsk_zero_copy = -1,
				  .iaa_completes = -1, .iaa_errors = -1 };
	struct chain_err e = { { 0 } };
	char why[128];
	bool check;
	size_t len = 0;
	char *text;
	FILE *out;

	if (argc != 3 || (strcmp(argv[1], "--spec") && strcmp(argv[1], "--check"))) {
		fprintf(stderr, "usage: %s --spec|--check FILE.json\n", argv[0]);
		return CB_INVALID;
	}
	check = !strcmp(argv[1], "--check");
	text = cb_slurp(argv[2], &len);
	if (!text) {
		fprintf(stderr, "chain_bench: cannot read %s\n", argv[2]);
		return CB_INVALID;
	}
	if (chain_parse(text, len, &spec, &e) || chain_validate(&spec, &e)) {
		int status = strncmp(e.msg, "unsupported:", 12) ? CB_INVALID : CB_NOT_RUN;

		free(text);
		printf("{\"schema\":\"xdev-chain-result-v1\",\"status\":\"%s\",\"failure\":",
		       cb_status(status));
		cb_json_str(stdout, e.msg);
		printf("}\n");
		fprintf(stderr, "chain_bench: %s\n", e.msg);
		return status;
	}
	free(text);
	if (check) {
		cb_plan(&spec);
		return CB_PASS;
	}
	/* hardware_gate.py admits timed runs; this catches a direct start. */
	if (spec.mode == CH_TIMING && chain_env_virtual("", why, sizeof(why)))
		cb_fail(&r, CB_NOT_RUN, "unsupported: timing refused: %s", why);
	else if (spec.arm == CH_SESSION)
		chain_run_session(&spec, &r);
	else
		chain_run_staged(&spec, &r);
	/*
	 * The session arm's claim: no CPU payload copy beyond what the spec
	 * declares (the copy-mode ablation's AF_XDP copy).  The staged arm
	 * only counts its copies.
	 */
	if (spec.arm == CH_SESSION && spec.mode == CH_TIMING && !r.status) {
		const char *extra = chain_undeclared_copy(&spec, r.copy_sources,
							  r.nr_copy_sources);

		if (extra)
			cb_fail(&r, CB_FAIL, "timed session run shows an undeclared CPU "
				"payload copy: %s", extra);
	}
	if (eval_fd_check(fd_before))
		cb_fail(&r, CB_FAIL, "descriptor count changed after cleanup");
	cb_emit(stdout, &spec, &r);
	if (spec.out[0]) {
		out = fopen(spec.out, "wx");
		if (!out) {
			fprintf(stderr, "chain_bench: %s: %s\n", spec.out, strerror(errno));
			return r.status ? r.status : CB_FAIL;
		}
		cb_emit(out, &spec, &r);
		fclose(out);
	}
	if (r.failure[0])
		fprintf(stderr, "chain_bench: %s\n", r.failure);
	free(r.samples);
	free(r.rec_ns);
	return r.status;
}
