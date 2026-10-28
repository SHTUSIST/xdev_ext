/* SPDX-License-Identifier: GPL-2.0 */
/* Actual UAPI normalization and promoted helper, no device emulation. */
#define _GNU_SOURCE
#define HFT_HAVE_URING
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../kernel/include/uapi/linux/io_uring.h"
#include "hft_runtime.h"
#include "hft_send_zc.h"
#define REQUIRE(x) do {if(!(x)) {fprintf(stderr,"FAIL line %d\n",__LINE__);return 1;}} while(0)
int main(void)
{
 struct io_uring_sqe sqe;unsigned char data[552]={0};struct hft_slot slot;
 struct hft_counts counts={0};struct io_uring_cqe cqe={0};
 prep_send_zc_fixed(&sqe,7,data,sizeof(data),0,3);
 REQUIRE(sqe.opcode==IORING_OP_SEND_ZC && sqe.fd==7 && sqe.addr==(uintptr_t)data && sqe.len==552 && sqe.buf_index==3);
 REQUIRE(sqe.ioprio==(IORING_RECVSEND_FIXED_BUF|IORING_SEND_ZC_REPORT_USAGE));
 hft_slot_init(&slot,3);
 REQUIRE(!hft_slot_read_begin(&slot,10));REQUIRE(!hft_slot_read_complete(&slot,10,512,512));
 REQUIRE(!hft_slot_send_begin(&slot,11,552));
 cqe.user_data=11;cqe.res=552;cqe.flags=IORING_CQE_F_MORE;
 REQUIRE(!wait_zc_cqes(&slot,&cqe,&counts));REQUIRE(!hft_slot_reusable(&slot));
 cqe.res=(int)IORING_NOTIF_USAGE_ZC_COPIED;cqe.flags=IORING_CQE_F_NOTIF;
 REQUIRE(!wait_zc_cqes(&slot,&cqe,&counts));REQUIRE(hft_slot_reusable(&slot));
 REQUIRE(counts.result_cqes==1 && counts.notif_cqes==1 && counts.copied==1);
 REQUIRE(wait_zc_cqes(&slot,&cqe,&counts)<0);REQUIRE(slot.phase==HFT_UNKNOWN);
 hft_slot_init(&slot,3);REQUIRE(!hft_slot_read_begin(&slot,20));
 REQUIRE(!hft_slot_read_complete(&slot,20,512,512));REQUIRE(!hft_slot_send_begin(&slot,21,552));
 cqe.user_data=21;cqe.res=552;cqe.flags=0;
 REQUIRE(!wait_zc_cqes(&slot,&cqe,&counts));REQUIRE(hft_slot_reusable(&slot));
 puts("SEND_ZC: actual UAPI flags and source-promoted helper PASS (software only)");return 0;
}
