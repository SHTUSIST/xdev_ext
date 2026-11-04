/* SPDX-License-Identifier: GPL-2.0 */
/* Source: include/linux/blk-mq.h
 * Linux commit: 89be9a83ccf1f88522317ce02f854f30d6115c41
 * The following payload is byte-exact; see provenance.json.
 */
enum hctx_type {
	HCTX_TYPE_DEFAULT,
	HCTX_TYPE_READ,
	HCTX_TYPE_POLL,

	HCTX_MAX_TYPES,
};
