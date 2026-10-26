/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_GPU_ADAPTER_H
#define XDEV_EXT_GPU_ADAPTER_H
#include "check_contract.h"
#ifdef __cplusplus
extern "C" {
#endif
enum tb_gpu_visibility { TB_GPU_NATIVE_OWNER, TB_GPU_HOST_FLUSH_OWNER };
enum tb_gpu_status {
 TB_GPU_OK = 0, TB_GPU_UNAVAILABLE = 1, TB_GPU_UNSUPPORTED = 2,
 TB_GPU_FAILED_SAFE = 3, TB_GPU_UNPROVED = 4, TB_GPU_HELD = 5
};
struct tb_gpu;
struct tb_gpu_request {
 const char *pci_bdf, *nvidia_node, *ptx_path;
 uint64_t registered_bytes;
};
struct tb_gpu_registration {
 uint64_t registered_address, registered_bytes;
 int nvidia_fd;
 uint32_t visibility;
};
/* registration address stays inside the resource-owner process. */
int tb_gpu_open(struct tb_gpu **, struct tb_guard *,
                const struct tb_gpu_request *);
int tb_gpu_registration(const struct tb_gpu *, struct tb_gpu_registration *);
int tb_gpu_fill(struct tb_gpu *, uint64_t seed, bool receiver_guard);
int tb_gpu_receive_visible(struct tb_gpu *);
int tb_gpu_verify(struct tb_gpu *, const struct tb_verify_extent *, size_t nr,
                  uint64_t launch_cookie, struct tb_verify_result *);
int tb_gpu_close(struct tb_gpu *); /* checks permissions, no implicit destructor */

#ifdef __cplusplus
}
#endif
#endif /* XDEV_EXT_GPU_ADAPTER_H */
