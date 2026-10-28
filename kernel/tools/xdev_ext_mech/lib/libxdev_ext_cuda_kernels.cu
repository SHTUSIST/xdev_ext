// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include "libxdev_ext_cuda_device.h"

static_assert(offsetof(xdev_ext_user_ring_hdr, ready_prod) % 4 == 0 &&
	offsetof(xdev_ext_user_ring_hdr, ready_cons) % 4 == 0 &&
	offsetof(xdev_ext_user_ring_hdr, done_prod) % 4 == 0 &&
	offsetof(xdev_ext_user_ring_hdr, done_cons) % 4 == 0 &&
	offsetof(xdev_ext_user_ring_hdr, kernel_flags) % 4 == 0,
	"system-scope32-bit fields are naturally aligned");
static_assert(offsetof(xdev_ext_user_slot, ticket) % 8 == 0 &&
	sizeof(xdev_ext_user_slot) % 8 == 0,
	"system-scope64-bit tickets are naturally aligned");

template<class T> __device__ T acquire(T *p)
{
	T value;
	if constexpr (sizeof(T) == 8)
		asm volatile("ld.acquire.sys.global.u64 %0, [%1];" : "=l"(value) : "l"(p) : "memory");
	else
		asm volatile("ld.acquire.sys.global.u32 %0, [%1];" : "=r"(value) : "l"(p) : "memory");
	return value;
}
template<class T> __device__ void release(T *p, T value)
{
	if constexpr (sizeof(T) == 8)
		asm volatile("st.release.sys.global.u64 [%0], %1;" :: "l"(p), "l"(value) : "memory");
	else
		asm volatile("st.release.sys.global.u32 [%0], %1;" :: "l"(p), "r"(value) : "memory");
}

extern "C" __global__ void xdev_user_wait(struct xdev_cuda_ring r,
	struct xdev_ext_cuda_message *message)
{
	if (blockIdx.x || threadIdx.x) return;
	message->ticket = 0;
	message->status = -EAGAIN;
	for (unsigned int i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
		message->device_address[i] = 0;
	if (acquire(&r.hdr->kernel_flags) & (XDEV_EXT_USER_K_DRAINING | XDEV_EXT_USER_K_STOPPED)) {
		message->status = -ESHUTDOWN; return;
	}
	unsigned int cons = acquire(&r.hdr->ready_cons), prod;
	for (;;) {
		prod = acquire(&r.hdr->ready_prod);
		if (prod != cons) break;
		if (acquire(&r.hdr->kernel_flags) & (XDEV_EXT_USER_K_DRAINING | XDEV_EXT_USER_K_STOPPED)) {
			message->status = -ESHUTDOWN; return;
		}
		__nanosleep(128);
	}
	if (prod - cons > r.entries) { message->status = -EOVERFLOW; return; }
	const struct xdev_ext_user_ready ready = r.ready[cons & (r.entries - 1)];
	if (ready.slot >= r.entries || !ready.ticket || !ready.nr_frames ||
	    ready.nr_frames > XDEV_EXT_MECH_MAX_FRAMES) { message->status = -EPROTO; return; }
	struct xdev_ext_user_slot *slot = &r.slots[ready.slot];
	if (acquire(&slot->ticket) != ready.ticket || slot->nr_frames != ready.nr_frames) {
		message->status = -ESTALE; return;
	}
	message->slot = ready.slot;
	message->ticket = ready.ticket;
	message->key = ready.key;
	message->nr_frames = ready.nr_frames;
	int status = 0;
	for (unsigned int i = 0; i < ready.nr_frames; i++) {
		const struct xdev_ext_user_frame f = slot->f[i];
		message->f[i] = f;
		message->f[i].out_len = f.data_len;
		if (f.umem_addr % r.frame_size || f.data_off > r.frame_size ||
		    f.capacity > r.frame_size - f.data_off || f.data_len > f.capacity ||
		    f.umem_addr > r.allocation_bytes || r.frame_size > r.allocation_bytes - f.umem_addr) {
			status = -ERANGE; break;
		}
		unsigned long long offset = f.umem_addr + f.data_off;
		if (r.allocation_va > UINT64_MAX - offset ||
		    f.capacity > UINT64_MAX - (r.allocation_va + offset)) { status = -EOVERFLOW; break; }
		message->device_address[i] = r.allocation_va + offset;
	}
	if (acquire(&slot->ticket) != ready.ticket) status = -ESTALE;
	/* STOP can race the metadata copy even when ready was already queued.
	 * Retain a copied ticket for an error completion, but expose no usable
	 * payload addresses after stopping or another validation failure. */
	if (acquire(&r.hdr->kernel_flags) & (XDEV_EXT_USER_K_DRAINING | XDEV_EXT_USER_K_STOPPED))
		status = -ESHUTDOWN;
	if (status)
		for (unsigned int i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
			message->device_address[i] = 0;
	message->status = status;
	release(&r.hdr->ready_cons, cons + 1);
}

extern "C" __global__ void xdev_user_done(struct xdev_cuda_ring r,
	struct xdev_ext_cuda_message *message)
{
	if (blockIdx.x || threadIdx.x) return;
	if (!message->ticket || message->slot >= r.entries ||
	    !message->nr_frames || message->nr_frames > XDEV_EXT_MECH_MAX_FRAMES) return;
	struct xdev_ext_user_slot *slot = &r.slots[message->slot];
	if (acquire(&slot->ticket) != message->ticket) { message->status = -ESTALE; return; }
	unsigned int prod = acquire(&r.hdr->done_prod);
	while (prod - acquire(&r.hdr->done_cons) >= r.entries) {
		if (acquire(&r.hdr->kernel_flags) & (XDEV_EXT_USER_K_DRAINING | XDEV_EXT_USER_K_STOPPED)) {
			message->status = -ENOSPC; return;
		}
		__nanosleep(128);
	}
	int status = message->status > 0 ? -EIO : message->status;
	for (unsigned int i = 0; i < message->nr_frames; i++) {
		if (!message->f[i].out_len || message->f[i].out_len > message->f[i].capacity)
			status = -ERANGE;
		slot->f[i].out_len = message->f[i].out_len;
	}
	struct xdev_ext_user_done *d = &r.done[prod & (r.entries - 1)];
	d->ticket = message->ticket;
	d->slot = message->slot;
	d->status = status;
	release(&r.hdr->done_prod, prod + 1);
	message->status = status;
}
