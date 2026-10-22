/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HFT_SEND_ZC_H
#define HFT_SEND_ZC_H
/* Selected source promotion: bench_nvme_pipeline_compare.c:307-348,
 * prep_send_zc_fixed; commit 7937fd11cb5632f83376404fda7d2ea2a38426ff,
 * blob 8a9f19cfd0636e29087c307ce8dd17856524eb1b.
 * Retained SQE preparation; numeric opcode fallbacks removed, REPORT_USAGE added.
 * wait_zc_cqes is adapted below to dispatch stable tokens and explicit NOTIF,
 * instead of treating every successful send as an unconditional two-CQE pair.
 */
#ifdef HFT_HAVE_URING
static void prep_send_zc_fixed(struct io_uring_sqe *sqe, int sockfd,
                               const void *buf, size_t len, int flags,
                               int buf_index)
{
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_SEND_ZC;
    sqe->fd = sockfd;
    sqe->addr = (unsigned long)(uintptr_t)buf;
    sqe->len = (unsigned)len;
    sqe->msg_flags = (unsigned)flags;
    sqe->ioprio = IORING_RECVSEND_FIXED_BUF | IORING_SEND_ZC_REPORT_USAGE;
    sqe->buf_index = (unsigned short)buf_index;
}
/* Normalize actual checked-in UAPI; notification usage is not sent bytes. */
static int wait_zc_cqes(struct hft_slot *slot,const struct io_uring_cqe *cqe,
                        struct hft_counts *counts)
{
 unsigned flags=0;int result=cqe->res;
 if(cqe->flags & ~(IORING_CQE_F_MORE|IORING_CQE_F_NOTIF)) {
  hft_slot_unknown(slot);return -EPROTO;
 }
 if(cqe->flags&IORING_CQE_F_MORE) flags|=HFT_CQE_MORE;
 if(cqe->flags&IORING_CQE_F_NOTIF) {
  uint32_t usage=(uint32_t)result;
  counts->notif_cqes++;flags|=HFT_CQE_NOTIF;
  if(usage&~IORING_NOTIF_USAGE_ZC_COPIED) {hft_slot_unknown(slot);return -EPROTO;}
  if(usage&IORING_NOTIF_USAGE_ZC_COPIED) {counts->copied++;flags|=HFT_CQE_COPIED;}
  result=0;
 } else counts->result_cqes++;
 return hft_slot_cqe(slot,cqe->user_data,result,flags);
}
#endif
#endif
