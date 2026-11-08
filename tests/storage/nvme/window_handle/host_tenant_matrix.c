/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Host oracle: four tenants sharing one NVMe namespace through LBA window
 * handles, written from the stated requirement, not from the implementation.
 *
 * A holder issues each tenant a writable handle for its own 64-LBA window of
 * the shared namespace (adjacent windows) and a read-only handle for its own
 * source range; read-only handles of the source may overlap. Then:
 *
 *  - registry: a handle that shares an LBA with a live handle is refused
 *    unless both are read-only; adjacent ones are not; a released range can
 *    be issued again, a range whose session is never released cannot;
 *  - bind: a tenant's handle admits a stage window only inside its own range
 *    and only in a granted direction (never another tenant's window, a
 *    straddle, one LBA more, or a write through a read-only handle);
 *  - per descriptor: every SQE a tenant's program may build is admitted only
 *    when [slba, slba + nlb) lies inside that tenant's bound window, with the
 *    exact decoded byte range; an SQE touching any LBA outside it, or setting
 *    a field C owns (nsid, flags/PSDT, DPTR), is refused before submission.
 *
 * Production rules under test, included unmodified from the product headers:
 * xdev_ext_storfam_core.h (grants, windows) and nvme_xdev_ext_passthru.h
 * (nvme_xdev_ext_mech_validate). The issue loop below is the same loop as the
 * NVME_IOCTL_XDEV_EXT_WINDOW registry (host_window_test.py pastes that one).
 * No device, no kernel.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "nvme_xdev_ext_passthru.h"

#define TENANTS 4U
#define WIN 64ULL			/* LBAs per tenant window */
#define LBA_SHIFT 9U
#define GROUP_LBAS 8ULL			/* one 4 KiB group per command */
#define CAPACITY 8192ULL		/* 4 MiB of 512-byte LBAs */
#define SRC_BASE 4096ULL		/* source range of the same namespace */
#define R XDEV_EXT_STOR_GRANT_READ
#define W XDEV_EXT_STOR_GRANT_WRITE
#define RW (XDEV_EXT_STOR_GRANT_READ | XDEV_EXT_STOR_GRANT_WRITE)

static unsigned checks, failures;

#define EQ(what, got, want) do { long long g_ = (long long)(got), w_ = (long long)(want); \
	checks++; if (g_ != w_) { failures++; \
		fprintf(stderr, "FAIL %s: got %lld want %lld\n", what, g_, w_); } } while (0)

/* ---- registry of one namespace: refuse a conflicting grant, else list it ---- */
#define MAX_LIVE 32
static struct xdev_ext_stor_grant live[MAX_LIVE];
static bool used[MAX_LIVE];

static int issue(__u64 slba, __u64 nlb, __u32 access)
{
	struct xdev_ext_stor_grant g;
	int i, ret = xdev_ext_stor_grant_make(&g, CAPACITY, slba, nlb, access);

	if (ret)
		return ret;
	for (i = 0; i < MAX_LIVE; i++)
		if (used[i] && xdev_ext_stor_grant_conflict(&live[i], &g))
			return -EBUSY;
	for (i = 0; i < MAX_LIVE; i++)
		if (!used[i]) {
			live[i] = g;
			used[i] = true;
			return i;
		}
	return -ENOSPC;
}

/* The session holding the handle was released. */
static void release(int h)
{
	used[h] = false;
}

/* ---- a READ/WRITE SQE exactly as a program builds it in the scratch slot ---- */
static void put_dw(__u8 *sqe, unsigned dw, __u32 v)
{
	sqe[4 * dw] = (__u8)v;
	sqe[4 * dw + 1] = (__u8)(v >> 8);
	sqe[4 * dw + 2] = (__u8)(v >> 16);
	sqe[4 * dw + 3] = (__u8)(v >> 24);
}

static void sqe_rw(__u8 sqe[64], bool write, __u64 slba, __u64 nlb)
{
	memset(sqe, 0, 64);
	sqe[0] = write ? NVME_XDEV_EXT_NVM_WRITE : NVME_XDEV_EXT_NVM_READ;
	put_dw(sqe, 10, (__u32)slba);
	put_dw(sqe, 11, (__u32)(slba >> 32));
	put_dw(sqe, 12, (__u32)(nlb - 1));
}

static struct nvme_xdev_ext_mech_bounds bounds(__u64 wslba, bool write, __u64 nlb)
{
	return (struct nvme_xdev_ext_mech_bounds) {
		.window_slba = wslba, .window_nlb = WIN, .capacity_lbas = CAPACITY,
		.data_len = (__u32)(nlb << LBA_SHIFT), .lba_shift = LBA_SHIFT, .write = write,
	};
}

static __u64 dst(unsigned t) { return (__u64)t * WIN; }
static __u64 src(unsigned t) { return SRC_BASE + (__u64)t * WIN; }

/* One SQE of tenant @t (window base(t)) at @slba: admitted iff inside. */
static void one_sqe(unsigned t, bool write, __u64 (*base)(unsigned), __u64 slba, __u64 nlb)
{
	struct nvme_xdev_ext_mech_bounds b = bounds(base(t), write, nlb);
	bool inside = slba >= base(t) && slba + nlb <= base(t) + WIN;
	struct nvme_xdev_ext_decoded d;
	char what[160];
	__u8 sqe[64];
	int ret;

	sqe_rw(sqe, write, slba, nlb);
	memset(&d, 0x5a, sizeof(d));
	ret = nvme_xdev_ext_mech_validate(sqe, &b, &d);
	snprintf(what, sizeof(what), "tenant %u %s slba %llu nlb %llu", t, write ? "write" : "read",
		 (unsigned long long)slba, (unsigned long long)nlb);
	EQ(what, ret, inside ? 0 : -ERANGE);
	if (inside) {
		EQ("decoded slba", d.slba, slba);
		EQ("decoded nlb", d.nlb, nlb);
		EQ("decoded byte offset", d.byte_offset, slba << LBA_SHIFT);
		EQ("decoded byte length", d.byte_length, nlb << LBA_SHIFT);
		EQ("decoded direction", d.write, write);
	} else {
		EQ("a refused SQE decodes nothing", d.nlb | d.byte_length, 0);
	}
}

/* A field C owns, set by the program: refused even inside the window. */
static void owned_field(unsigned t, bool write, __u64 (*base)(unsigned), const char *name,
			unsigned byte, __u8 value)
{
	struct nvme_xdev_ext_mech_bounds b = bounds(base(t), write, GROUP_LBAS);
	struct nvme_xdev_ext_decoded d;
	char what[160];
	__u8 sqe[64];

	sqe_rw(sqe, write, base(t), GROUP_LBAS);
	sqe[byte] = value;
	snprintf(what, sizeof(what), "tenant %u %s sets %s", t, write ? "write" : "read", name);
	EQ(what, nvme_xdev_ext_mech_validate(sqe, &b, &d), -EPERM);
}

/* Every group-sized command from tenant 0's first LBA - 8 to past the last tenant. */
static void descriptor_matrix(unsigned t, bool write, __u64 (*base)(unsigned))
{
	__u64 slba, first = base(0) >= GROUP_LBAS ? base(0) - GROUP_LBAS : 0;
	__u64 end = base(TENANTS - 1) + WIN + GROUP_LBAS;
	struct nvme_xdev_ext_mech_bounds b;
	struct nvme_xdev_ext_decoded d;
	char what[160];
	__u8 sqe[64];

	for (slba = first; slba + GROUP_LBAS <= end && slba + GROUP_LBAS <= CAPACITY; slba++)
		one_sqe(t, write, base, slba, GROUP_LBAS);
	one_sqe(t, write, base, base(t), WIN);		/* the whole window at once */
	one_sqe(t, write, base, base(t), WIN + 1);	/* one LBA more */
	one_sqe(t, write, base, base(t) + WIN - 1, 1);	/* last LBA */
	one_sqe(t, write, base, base(t) + WIN, 1);	/* first LBA of the next tenant */
	owned_field(t, write, base, "nsid", 4, 2);
	owned_field(t, write, base, "PSDT", 1, 0x40);
	owned_field(t, write, base, "DPTR", 25, 0x10);
	owned_field(t, write, base, "command id", 2, 1);
	b = bounds(base(t), write, GROUP_LBAS);
	sqe_rw(sqe, !write, base(t), GROUP_LBAS);
	snprintf(what, sizeof(what), "tenant %u opposite opcode", t);
	EQ(what, nvme_xdev_ext_mech_validate(sqe, &b, &d), -EOPNOTSUPP);
}

int main(void)
{
	int wh[TENANTS], rh[TENANTS], h;
	unsigned t, o;
	char what[160];

	/* Issue: four adjacent writable windows; read-only sources overlap. */
	for (t = 0; t < TENANTS; t++) {
		wh[t] = issue(dst(t), WIN, RW);
		snprintf(what, sizeof(what), "issue tenant %u window", t);
		EQ(what, wh[t] >= 0, 1);
	}
	for (t = 0; t < TENANTS; t++) {
		rh[t] = issue(src(t), t + 1 < TENANTS ? 2 * WIN : WIN, R);
		snprintf(what, sizeof(what), "issue tenant %u read-only source", t);
		EQ(what, rh[t] >= 0, 1);
	}
	for (t = 0; t < TENANTS; t++) {
		snprintf(what, sizeof(what), "a second writer over tenant %u", t);
		EQ(what, issue(dst(t), WIN, W), -EBUSY);
		snprintf(what, sizeof(what), "a reader inside tenant %u's writable window", t);
		EQ(what, issue(dst(t) + WIN / 2, 1, R), -EBUSY);
		snprintf(what, sizeof(what), "a straddle into tenant %u", t);
		EQ(what, issue(dst(t) + WIN - 1, 2, RW), -EBUSY);
		snprintf(what, sizeof(what), "a writer over tenant %u's source", t);
		EQ(what, issue(src(t), 1, W), -EBUSY);
	}
	EQ("the adjacent free window", (h = issue(dst(TENANTS), WIN, RW)) >= 0, 1);
	if (h >= 0)
		release(h);

	/* Bind: a tenant's handle admits only its own window and direction. */
	for (t = 0; t < TENANTS; t++)
		for (o = 0; o < TENANTS; o++) {
			snprintf(what, sizeof(what), "tenant %u binds window %u", t, o);
			EQ(what, xdev_ext_stor_grant_admit(&live[wh[t]], true, dst(o), WIN),
			   o == t ? 0 : -EACCES);
			snprintf(what, sizeof(what), "tenant %u reads source %u", t, o);
			EQ(what, xdev_ext_stor_grant_admit(&live[rh[t]], false, src(o), WIN),
			   (o == t || o == t + 1) ? 0 : -EACCES);
			snprintf(what, sizeof(what), "tenant %u writes through read handle at %u", t, o);
			EQ(what, xdev_ext_stor_grant_admit(&live[rh[t]], true, src(o), WIN), -EBADF);
		}
	for (t = 0; t < TENANTS; t++) {
		snprintf(what, sizeof(what), "tenant %u window one LBA longer", t);
		EQ(what, xdev_ext_stor_grant_admit(&live[wh[t]], true, dst(t), WIN + 1), -EACCES);
		snprintf(what, sizeof(what), "tenant %u window shifted by one", t);
		EQ(what, xdev_ext_stor_grant_admit(&live[wh[t]], true, dst(t) + 1, WIN), -EACCES);
		snprintf(what, sizeof(what), "tenant %u inner window", t);
		EQ(what, xdev_ext_stor_grant_admit(&live[wh[t]], true, dst(t) + 8, 16), 0);
	}

	/* Per descriptor, against each tenant's bound window, both directions. */
	for (t = 0; t < TENANTS; t++) {
		descriptor_matrix(t, true, dst);
		descriptor_matrix(t, false, src);
	}

	/* A released tenant frees its range; a quarantined one never does. */
	release(wh[0]);
	EQ("a released range issues again", issue(dst(0), WIN, RW) >= 0, 1);
	EQ("a quarantined tenant keeps its range", issue(dst(3), WIN, RW), -EBUSY);

	printf("%s tenant matrix: %u checks, %u failures\n", failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
