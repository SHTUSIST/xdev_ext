/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBXDEV_EXT_CUDA_H
#define LIBXDEV_EXT_CUDA_H
#include <cuda.h>
#include "libxdev_ext.h"
#ifdef __cplusplus
extern "C" {
#endif
struct xdev_ext_cuda_user;
struct xdev_ext_cuda_message {
	unsigned long long ticket, key;
	unsigned int slot, nr_frames;
	int status;
	struct xdev_ext_user_frame f[XDEV_EXT_MECH_MAX_FRAMES];
	unsigned long long device_address[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_cuda_diagnostic {
	int cuda_result;
	char operation[96];
};
/* PTX path is set with XDEV_EXT_CUDA_PTX before open; no runtime CUDA library
 * or default-stream switch. Context, allocation and graph lifetimes are caller's. */
int xdev_ext_cuda_user_open(struct xdev_ext_user_stage *, CUcontext,
	CUdeviceptr allocation_va, unsigned long long allocation_bytes,
	unsigned int frame_size, struct xdev_ext_cuda_user **);
/* device_message is a device-memory pointer. Only enqueue real GPU work. */
int xdev_ext_cuda_user_wait(struct xdev_ext_cuda_user *, CUstream,
	struct xdev_ext_cuda_message *device_message);
int xdev_ext_cuda_user_done(struct xdev_ext_cuda_user *, CUstream,
	struct xdev_ext_cuda_message *device_message);
int xdev_ext_cuda_receive_visible(struct xdev_ext_cuda_user *, CUstream);
int xdev_ext_cuda_user_close(struct xdev_ext_cuda_user *, CUstream);
int xdev_ext_cuda_last_diagnostic(struct xdev_ext_cuda_diagnostic *);
/* d1 helpers: capture is rejected before any ready consumption/submission.
 * Event success is the proof preceding status0; negative failures never done0. */
int xdev_ext_cuda_event_complete(struct xdev_ext_user_stage *,
	const struct xdev_ext_user_batch *, CUcontext, CUstream, CUevent);
int xdev_ext_cuda_host_receive_visible(CUcontext);
#ifdef __cplusplus
}
#endif
#endif
