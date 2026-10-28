/* SPDX-License-Identifier: MIT */
#ifndef _NV_XDEV_EXT_CE_CLASSIFY_H_
#define _NV_XDEV_EXT_CE_CLASSIFY_H_

/*
 * Completion classification of one XDEV_EXT CE request.  The numbering matches
 * XDEV_EXT_CE_OK, XDEV_EXT_CE_PRE_SUBMIT_FAILED and XDEV_EXT_CE_AMBIGUOUS of the kernel CE
 * mechanism, which receives the same (status, hw_submitted) pair through
 * xdev_ext_ce_complete().
 */
enum nv_xdev_ext_ce_outcome {
	NV_XDEV_EXT_CE_OK = 0,
	NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED = 1,
	NV_XDEV_EXT_CE_AMBIGUOUS = 2,
};

/*
 * rm_status is the NV_STATUS of the RM submit path (0 is NV_OK).
 * hw_submitted is set by RM once the step that ended the request entered
 * memmgrMemCopy(), past which a GPFIFO entry, GPPut or doorbell write may
 * have reached the copy engine.  A failure before that point left nothing
 * for the hardware to complete: the backing stays reusable and the request
 * may be retried.  A failure after it cannot be proven quiescent and must be
 * sequestered.
 */
static inline enum nv_xdev_ext_ce_outcome
nv_xdev_ext_ce_classify(unsigned int rm_status, int hw_submitted)
{
	if (rm_status == 0)
		return NV_XDEV_EXT_CE_OK;
	return hw_submitted ? NV_XDEV_EXT_CE_AMBIGUOUS : NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED;
}

#endif /* _NV_XDEV_EXT_CE_CLASSIFY_H_ */
