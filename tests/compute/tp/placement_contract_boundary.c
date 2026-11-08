/* SPDX-License-Identifier: GPL-2.0 */
/* Real endpoint placement, with only its session/OS boundary recorded.
 * The native loopback and BPF-body tests call this same production rule. */
#define main tp_endpoint_contract_unused_main
#include TP_ENDPOINT_TEST_SOURCE
#undef main
#include <pthread.h>

int tp_frame_placement(__u32 direction, __u32 group, __u64 window,
	__u64 sequence, __u64 *offset, __u32 *bytes)
{
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	struct xdev_ext_frame_endpoint_opts o;
	struct xdev_ext_frame_endpoint *endpoint = NULL;
	int ret, close_ret;

	pthread_mutex_lock(&lock);
	reset();
	o = opts(direction, window);
	o.group_bytes = group;
	ret = wait_fd < 0 ? -EMFILE : xdev_ext_frame_endpoint_open(&o, &endpoint);
	if (!ret)
		ret = xdev_ext_frame_endpoint_place(endpoint, sequence, offset, bytes);
	if (endpoint) {
		close_ret = xdev_ext_frame_endpoint_close(endpoint);
		if (!ret) ret = close_ret;
	}
	if (wait_fd >= 0) close(wait_fd);
	wait_fd = -1;
	pthread_mutex_unlock(&lock);
	return ret;
}
