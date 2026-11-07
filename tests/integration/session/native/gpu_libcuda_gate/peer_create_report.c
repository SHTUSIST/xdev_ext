// SPDX-License-Identifier: GPL-2.0
/*
 * One NVMe -> PEER pool -> NVMe CREATE through XDEV_EXT_MECH_OP_CREATE_REPORT,
 * printing the admission report: which phase and stage refused, the
 * requester, and the PEER requester admission values (reachability,
 * pci_p2pdma_distance, backing flags, refusal flags).  No START, no DMA.
 * A session that is created is stopped at once.
 *
 *   peer_create_report --allocation-fd FD SOURCE_NG TARGET_NG NLB \
 *       SOURCE_SLBA TARGET_SLBA BPF_DIR
 *
 * FD is an allocation file returned by XDEV_EXT_PEER_REGISTER (for example
 * by xdev_ext_gpu_dmabuf, which substitutes '{fd}').  BPF_DIR holds
 * nvme_s0.bpf.o, attached for the duration of the call as the peer chain
 * tool does.  Build against the uapi headers of the running kernel:
 *   gcc -I SRC/src/core/include/uapi ... -lbpf
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <linux/io_uring.h>
#include <linux/xdev_ext_mech.h>

static int parse_u64(const char *s, uint64_t *value)
{
	char *end;

	if (!s || !*s || *s == '-')
		return -EINVAL;
	errno = 0;
	*value = strtoull(s, &end, 0);
	return errno || *end ? -EINVAL : 0;
}

static struct bpf_link *attach_nvme_ops(const char *directory, struct bpf_object **object)
{
	char path[PATH_MAX];
	struct bpf_map *map;

	snprintf(path, sizeof(path), "%s/nvme_s0.bpf.o", directory);
	*object = bpf_object__open_file(path, NULL);
	if (libbpf_get_error(*object) || bpf_object__load(*object))
		return NULL;
	bpf_object__for_each_map(map, *object) {
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS)
			return bpf_map__attach_struct_ops(map);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	struct xdev_ext_mech_create_with_report e = {
		.size = sizeof(e), .version = XDEV_EXT_MECH_CREATE_REPORT_VERSION,
	};
	struct io_uring_xdev_ext_mech req = {
		.op = XDEV_EXT_MECH_OP_CREATE_REPORT, .arg = (uintptr_t)&e,
	};
	struct xdev_ext_mech_create *c = &e.create;
	struct xdev_ext_mech_create_report *r = &e.report;
	struct io_uring_params params = {};
	struct bpf_object *object = NULL;
	struct bpf_link *link;
	uint64_t fd, nlb, source_slba, target_slba;
	int src, dst, ring, ret;

	if (argc != 9 || strcmp(argv[1], "--allocation-fd") || parse_u64(argv[2], &fd) ||
	    fd > INT_MAX || parse_u64(argv[5], &nlb) || parse_u64(argv[6], &source_slba) ||
	    parse_u64(argv[7], &target_slba)) {
		fprintf(stderr, "usage: %s --allocation-fd FD SOURCE_NG TARGET_NG NLB "
			"SOURCE_SLBA TARGET_SLBA BPF_DIR\n", argv[0]);
		return 2;
	}
	link = attach_nvme_ops(argv[8], &object);
	if (!link || libbpf_get_error(link)) {
		fprintf(stderr, "attach nvme_s0 failed\n");
		return 1;
	}
	src = open(argv[3], O_RDONLY | O_CLOEXEC);
	dst = open(argv[4], O_RDWR | O_CLOEXEC);
	ring = syscall(__NR_io_uring_setup, 8, &params);
	if (src < 0 || dst < 0 || ring < 0) {
		perror("open/ring");
		return 1;
	}
	c->abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c->nr_stages = 2;
	c->pool_kind = XDEV_EXT_MECH_POOL_PEER;
	c->pool_fd = (int)fd;
	c->layout = (struct xdev_ext_mech_layout){ 65536, 0, 8192, 8192 };
	c->depth = 1;
	c->eventfd = -1;
	c->st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = src,
		.arg0 = source_slba, .arg1 = nlb };
	c->st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = dst,
		.arg0 = target_slba, .arg1 = nlb };
	ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);
	if (ret < 0) {
		printf("XDEV_EXT_PEER_CREATE_REPORT delivery_errno=%d\n", -errno);
		return 1;
	}
	printf("XDEV_EXT_PEER_CREATE_REPORT size=%u version=%u result=%d rollback_errno=%d "
	       "phase=%u failed_stage=%u valid=0x%x cleanup=%u requester=%04x:%02x:%02x.%u "
	       "reachability=%u p2p_distance=%d backing=0x%x refused=0x%x requester_mapping=%u\n",
	       r->size, r->version, r->result, r->rollback_errno, r->phase, r->failed_stage,
	       r->valid, r->cleanup, r->requester.domain, r->requester.bus,
	       r->requester.devfn >> 3, r->requester.devfn & 7, r->caps.reachability,
	       r->caps.p2p_distance, r->caps.backing, r->caps.refused,
	       r->caps.requester_mapping);
	if (!r->result && r->session_id) {
		struct io_uring_xdev_ext_mech stop = {
			.op = XDEV_EXT_MECH_OP_STOP, .arg = r->session_id,
		};

		ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &stop, 1);
		printf("XDEV_EXT_PEER_CREATE_REPORT stop=%d\n", ret < 0 ? -errno : ret);
	}
	close(ring);
	close(dst);
	close(src);
	bpf_link__destroy(link);
	bpf_object__close(object);
	return r->result ? 1 : 0;
}
