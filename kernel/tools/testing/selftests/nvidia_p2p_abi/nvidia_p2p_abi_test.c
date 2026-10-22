// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "../../../include/xdev_ext_nv_p2p_ioctl.h"

static unsigned int tests_run;
static unsigned int tests_failed;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	tests_run++;                                                        \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		tests_failed++;                                               \
	}                                                                   \
} while (0)

enum fake_reply {
	FAKE_OK,
	FAKE_SYSCALL_ERROR,
	FAKE_NATIVE_ERROR,
	FAKE_ZERO_HANDLE,
	FAKE_BATCH_BAD_FAILURE_INDEX,
	FAKE_BATCH_BAD_SUCCESS_ENTRY,
};

struct fake_ioctl_state {
	enum fake_reply reply;
	unsigned long request;
	uint32_t command;
	uint32_t size;
	unsigned int calls;
};

static struct fake_ioctl_state fake;

static int fake_ioctl(int fd, unsigned long request, void *argument)
{
	struct xdev_ext_nv_ioctl_xfer *xfer = argument;

	EXPECT_EQ(fd, 17);
	fake.calls++;
	fake.request = request;
	fake.command = xfer->cmd;
	fake.size = xfer->size;
	if (fake.reply == FAKE_SYSCALL_ERROR) {
		errno = ENOTTY;
		return -1;
	}

	switch (xfer->cmd) {
	case XDEV_EXT_NV_ESC_P2P_PIN_UMEM: {
		struct xdev_ext_nv_p2p_pin_umem *pin =
			(void *)(uintptr_t)xfer->ptr;

		pin->status = fake.reply == FAKE_NATIVE_ERROR ? 0x56U : 0U;
		pin->handle = fake.reply == FAKE_ZERO_HANDLE ? 0U : 0x1234U;
		break;
	}
	case XDEV_EXT_NV_ESC_P2P_UNPIN_UMEM: {
		struct xdev_ext_nv_p2p_unpin_umem *unpin =
			(void *)(uintptr_t)xfer->ptr;

		unpin->status = fake.reply == FAKE_NATIVE_ERROR ? 0x57U : 0U;
		break;
	}
	case XDEV_EXT_NV_ESC_P2P_DMA_XFER: {
		struct xdev_ext_nv_p2p_dma_xfer *dma =
			(void *)(uintptr_t)xfer->ptr;

		dma->status = fake.reply == FAKE_NATIVE_ERROR ? 0x58U : 0U;
		break;
	}
	case XDEV_EXT_NV_ESC_P2P_DMA_XFER_BATCH: {
		struct xdev_ext_nv_p2p_dma_batch *batch =
			(void *)(uintptr_t)xfer->ptr;

		for (uint32_t i = 0; i < batch->count; i++)
			batch->entries[i].status = 0;
		batch->status = 0;
		batch->completed = batch->count;
		batch->failed_index = UINT32_MAX;
		if (fake.reply == FAKE_NATIVE_ERROR ||
		    fake.reply == FAKE_BATCH_BAD_FAILURE_INDEX) {
			batch->status = 0x59U;
			batch->completed = 1U;
			batch->failed_index = fake.reply == FAKE_NATIVE_ERROR ? 1U : 0U;
			batch->entries[1].status = 0x59U;
		} else if (fake.reply == FAKE_BATCH_BAD_SUCCESS_ENTRY) {
			batch->entries[0].status = 0x5aU;
		}
		break;
	}
	default:
		return -1;
	}
	return 0;
}

static void reset_fake(enum fake_reply reply)
{
	memset(&fake, 0, sizeof(fake));
	fake.reply = reply;
	errno = 0;
}

static void test_abi_layout(void)
{
	EXPECT_EQ(sizeof(struct xdev_ext_nv_ioctl_xfer), 16);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_ioctl_xfer, ptr), 8);
	EXPECT_EQ(sizeof(struct xdev_ext_nv_p2p_pin_umem), 40);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_pin_umem, status), 20);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_pin_umem, handle), 24);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_pin_umem, xsk_fd), 32);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_pin_umem, flags), 36);
	EXPECT_EQ(sizeof(struct xdev_ext_nv_p2p_unpin_umem), 16);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_unpin_umem, status), 8);
	EXPECT_EQ(sizeof(struct xdev_ext_nv_p2p_dma_xfer), 40);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_dma_xfer, direction), 32);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_dma_xfer, status), 36);
	EXPECT_EQ(XDEV_EXT_NV_P2P_MAX_BATCH, 64);
	EXPECT_EQ(sizeof(struct xdev_ext_nv_p2p_dma_batch_entry), 32);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_dma_batch_entry, direction), 24);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_dma_batch_entry, status), 28);
	EXPECT_EQ(sizeof(struct xdev_ext_nv_p2p_dma_batch), 2080);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_dma_batch, failed_index), 16);
	EXPECT_EQ(offsetof(struct xdev_ext_nv_p2p_dma_batch, entries), 32);
	EXPECT_EQ(_IOC_TYPE(XDEV_EXT_NV_IOCTL_XFER_CMD), 'F');
	EXPECT_EQ(_IOC_NR(XDEV_EXT_NV_IOCTL_XFER_CMD), 211);
	EXPECT_EQ(_IOC_SIZE(XDEV_EXT_NV_IOCTL_XFER_CMD), 16);
}

static void test_pin_requires_native_success_and_handle(void)
{
	struct xdev_ext_nv_p2p_pin_umem pin = {
		.umem_addr = 0x1000,
		.size = 0x2000,
		.frame_size = 4096,
		.xsk_fd = 23,
	};

	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_pin_umem_with(17, &pin, fake_ioctl), 0);
	EXPECT_EQ(fake.calls, 1);
	EXPECT_EQ(fake.request, XDEV_EXT_NV_IOCTL_XFER_CMD);
	EXPECT_EQ(fake.command, XDEV_EXT_NV_ESC_P2P_PIN_UMEM);
	EXPECT_EQ(fake.size, sizeof(pin));
	EXPECT_EQ(pin.status, 0);
	EXPECT_EQ(pin.handle, 0x1234);

	reset_fake(FAKE_NATIVE_ERROR);
	EXPECT_EQ(xdev_ext_nv_p2p_pin_umem_with(17, &pin, fake_ioctl), -1);
	EXPECT_EQ(errno, EIO);
	EXPECT_EQ(pin.status, 0x56);
	EXPECT_EQ(pin.handle, 0);

	reset_fake(FAKE_ZERO_HANDLE);
	EXPECT_EQ(xdev_ext_nv_p2p_pin_umem_with(17, &pin, fake_ioctl), -1);
	EXPECT_EQ(errno, EPROTO);
	EXPECT_EQ(pin.handle, 0);

	reset_fake(FAKE_SYSCALL_ERROR);
	EXPECT_EQ(xdev_ext_nv_p2p_pin_umem_with(17, &pin, fake_ioctl), -1);
	EXPECT_EQ(errno, ENOTTY);

	pin.xsk_fd = -1;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_pin_umem_with(17, &pin, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);

	pin.xsk_fd = 23;
	pin.flags = 2;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_pin_umem_with(17, &pin, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);

	pin.xsk_fd = -1;
	pin.flags = XDEV_EXT_NV_P2P_PIN_F_HOST_REGION;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_pin_umem_with(17, &pin, fake_ioctl), 0);
	EXPECT_EQ(fake.calls, 1);
}

static void test_dma_requires_native_success(void)
{
	struct xdev_ext_nv_p2p_dma_xfer dma = {
		.handle = 0x1234,
		.gpu_offset = 0x100000,
		.umem_offset = 4096,
		.size = 2048,
		.direction = XDEV_EXT_NV_P2P_UMEM_TO_GPU,
	};

	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_xfer_with(17, &dma, fake_ioctl), 0);
	EXPECT_EQ(fake.command, XDEV_EXT_NV_ESC_P2P_DMA_XFER);
	EXPECT_EQ(fake.size, sizeof(dma));
	EXPECT_EQ(dma.status, 0);

	reset_fake(FAKE_NATIVE_ERROR);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_xfer_with(17, &dma, fake_ioctl), -1);
	EXPECT_EQ(errno, EIO);
	EXPECT_EQ(dma.status, 0x58);

	dma.handle = 0;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_xfer_with(17, &dma, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);
}

static void test_unpin_uses_full_driver_layout(void)
{
	struct xdev_ext_nv_p2p_unpin_umem unpin = { .handle = 0x1234 };

	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_unpin_umem_with(17, &unpin, fake_ioctl), 0);
	EXPECT_EQ(fake.command, XDEV_EXT_NV_ESC_P2P_UNPIN_UMEM);
	EXPECT_EQ(fake.size, 16);
	EXPECT_EQ(unpin.status, 0);

	reset_fake(FAKE_NATIVE_ERROR);
	EXPECT_EQ(xdev_ext_nv_p2p_unpin_umem_with(17, &unpin, fake_ioctl), -1);
	EXPECT_EQ(errno, EIO);
	EXPECT_EQ(unpin.status, 0x57);

	unpin.handle = 0;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_unpin_umem_with(17, &unpin, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);
}

static void test_bounded_batch_requires_valid_items_and_reports_prefix(void)
{
	struct xdev_ext_nv_p2p_dma_batch batch = {
		.handle = 0x1234,
		.count = 2,
		.entries = {
			{
				.gpu_offset = 0x100000,
				.umem_offset = 0,
				.size = 128,
				.direction = XDEV_EXT_NV_P2P_UMEM_TO_GPU,
			},
			{
				.gpu_offset = 0x101000,
				.umem_offset = 4096,
				.size = 256,
				.direction = XDEV_EXT_NV_P2P_GPU_TO_UMEM,
			},
		},
	};

	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), 0);
	EXPECT_EQ(fake.command, XDEV_EXT_NV_ESC_P2P_DMA_XFER_BATCH);
	EXPECT_EQ(fake.size, sizeof(batch));
	EXPECT_EQ(batch.completed, 2);
	EXPECT_EQ(batch.failed_index, UINT32_MAX);
	EXPECT_EQ(batch.status, 0);

	reset_fake(FAKE_NATIVE_ERROR);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), -1);
	EXPECT_EQ(errno, EIO);
	EXPECT_EQ(batch.completed, 1);
	EXPECT_EQ(batch.failed_index, 1);
	EXPECT_EQ(batch.status, 0x59);

	reset_fake(FAKE_BATCH_BAD_FAILURE_INDEX);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), -1);
	EXPECT_EQ(errno, EPROTO);

	reset_fake(FAKE_BATCH_BAD_SUCCESS_ENTRY);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), -1);
	EXPECT_EQ(errno, EPROTO);

	batch.count = 0;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);

	batch.count = XDEV_EXT_NV_P2P_MAX_BATCH + 1;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);

	batch.count = 2;
	batch.entries[1].size = 0;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);

	batch.entries[1].size = 256;
	batch.entries[1].direction = 2;
	reset_fake(FAKE_OK);
	EXPECT_EQ(xdev_ext_nv_p2p_dma_batch_with(17, &batch, fake_ioctl), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(fake.calls, 0);
}

int main(void)
{
	test_abi_layout();
	test_pin_requires_native_success_and_handle();
	test_dma_requires_native_success();
	test_unpin_uses_full_driver_layout();
	test_bounded_batch_requires_valid_items_and_reports_prefix();
	printf("nvidia_p2p_abi: %u tests, %u failures\n",
	       tests_run, tests_failed);
	return tests_failed ? 1 : 0;
}
