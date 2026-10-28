// SPDX-License-Identifier: GPL-2.0
#include "xdev_tp.h"
int main()
{
    xdev_tp_comm *comm = nullptr;
    xdev_tp_work *work = nullptr;
    int rc = xdev_tp_create(nullptr, &comm);
    rc += xdev_tp_allreduce_sum(comm, 0, 0, 0, XDEV_TP_F16, nullptr, 1, &work);
    rc += xdev_tp_logits_gather(comm, 0, 0, 0, 0, XDEV_TP_F16, 0, 0, nullptr, 1, &work);
    rc += xdev_tp_work_query(work);
    rc += xdev_tp_work_wait(work, 1);
    rc += xdev_tp_work_destroy(work);
    rc += xdev_tp_destroy(comm, 1);
    return rc == 0;
}
