/* SPDX-License-Identifier: GPL-2.0 */
/* Source: block/blk-mq.c
 * Linux commit: 89be9a83ccf1f88522317ce02f854f30d6115c41
 * Copyright (C) 2013-2014 Jens Axboe; Copyright (C) 2013-2014 Christoph Hellwig.
 * The following payload is byte-exact; see provenance.json.
 */
bool blk_rq_is_poll(struct request *rq)
{
	if (!rq->mq_hctx)
		return false;
	if (rq->mq_hctx->type != HCTX_TYPE_POLL)
		return false;
	return true;
}
