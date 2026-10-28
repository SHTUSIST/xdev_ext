// SPDX-License-Identifier: GPL-2.0
// Link-only consumer. Never execute a CUDA Driver link stub.
#include "../xdev_tp.h"
int main()
{
    xdev_tp_comm *comm = nullptr;
    xdev_tp_work *work = nullptr;
    xdev_tp_config config{};
    xdev_tp_stats stats{};
    xdev_tp_work_stats work_stats{};
    xdev_tp_trace_record record{};
    size_t written = 0;
    int rc = xdev_tp_create(&config, &comm);
    rc += xdev_tp_allreduce_sum(comm, 0, 0, 0, XDEV_TP_F32, nullptr, 1, &work);
    rc += xdev_tp_logits_gather(comm, 0, 0, 0, 0, XDEV_TP_F32, 0, 0, nullptr, 1, &work);
    rc += xdev_tp_work_query(work);
    rc += xdev_tp_work_wait(work, 1);
    rc += xdev_tp_work_get_stats(work, &work_stats);
    rc += xdev_tp_work_destroy(work);
    rc += xdev_tp_get_stats(comm, &stats);
    rc += xdev_tp_trace_read(comm, &record, 1, &written);
    rc += xdev_tp_destroy(comm, 1);
    return rc;
}
