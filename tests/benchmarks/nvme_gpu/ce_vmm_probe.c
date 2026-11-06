// SPDX-License-Identifier: GPL-2.0
/* Actual eval-helper qualification only: no session, NVMe/NIC or timing. */
#define _GNU_SOURCE
#include "../common/cpu_timer.h"
static struct cpu_timer endpoint_timer;
#include "eval_session.h"

#define PROBE_BYTES (32U * 1024U)

int main(int argc, char **argv)
{
	struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
	unsigned char sent[PROBE_BYTES], received[PROBE_BYTES];
	unsigned int stages = 1;
	const char *attached = "0";
	int ret, cleanup;

	/* Match the existing arm's include prerequisite without starting a timer. */
	(void)endpoint_timer;
	if (argc != 1) {
		if (argc != 3 || strcmp(argv[1], "--stages") ||
		    (strcmp(argv[2], "1") && strcmp(argv[2], "2"))) {
			fprintf(stderr, "usage: ce_vmm_probe [--stages 1|2]\n");
			printf("CE_VMM_QUALIFICATION=FAIL attached_stages=0\n");
			return XG_EXIT_USAGE;
		}
		stages = (unsigned int)(argv[2][0] - '0');
	}
	for (unsigned int i = 0; i < PROBE_BYTES; i++)
		sent[i] = (unsigned char)((i * 73U + (i >> 8) + 0xa5U) & 0xffU);
	memset(received, 0, sizeof(received));
	/* A failed multi-fd setup does not expose a partial attachment count. */
	attached = "unknown";
	ret = es_ce_open(&ce, "/dev/nvidia0", stages, ES_CE_VMM, 0, PROBE_BYTES);
	if (ret)
		goto out;
	attached = stages == 1 ? "1" : "2";
	ret = es_ce_access(&ce, true, 0, sent, sizeof(sent));
	if (!ret)
		ret = es_ce_access(&ce, false, 0, received, sizeof(received));
	if (ret || memcmp(sent, received, sizeof(sent)))
		ret = XG_EXIT_FAIL;
out:
	cleanup = es_ce_close(&ce);
	if (cleanup)
		ret = XG_EXIT_FAIL;
	printf("CE_VMM_QUALIFICATION=%s attached_stages=%s\n",
		ret ? "FAIL" : "PASS", attached);
	if (fflush(stdout))
		return XG_EXIT_FAIL;
	return ret < 0 ? XG_EXIT_FAIL : ret;
}
