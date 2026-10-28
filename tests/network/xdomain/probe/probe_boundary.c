/* SPDX-License-Identifier: GPL-2.0 */
/* Reuse the established complete stack boundary. Only count the existing
 * requester boundary and expose raw, lock-protected link observations. */
#define xdev_ext_requester_bind probe_recorded_requester_bind
#include "stack_boundary.c"
#undef xdev_ext_requester_bind
#include "probe_observation.h"

static unsigned requester_binds[2];

int xdev_ext_requester_bind(struct xdev_ext_requester *requester,
 struct xdev_ext_mech_stage *stage, struct pci_dev *pdev, u32 flags)
{
 requester_binds[stack_endpoint_stage(stage)]++;
 return probe_recorded_requester_bind(requester, stage, pdev, flags);
}

int probe_observe(struct stack_world *w, unsigned endpoint,
                  struct probe_observation *out)
{
 unsigned long flags;
 if (w != world || endpoint > 1 || !out || !w->side[endpoint].probed ||
     w->side[endpoint].removed)
  return -EINVAL;
 memset(out, 0, sizeof(*out));
 struct xdev_ext_xd_link *xl = link(endpoint);
 mutex_lock(&xl->ep_mutex);
 spin_lock_irqsave(&xl->lock, flags);
 out->up = xl->up;
 out->logged_in = xl->logged_in;
 out->remote_logged_in = xl->remote_logged_in;
 out->receive_ready = xl->receive_ready;
 out->local_inc = xl->local_inc;
 out->remote_inc = xl->remote_inc;
 out->accepted_inc = xl->accepted_inc;
 out->response_inc = xl->response_inc;
 for (unsigned c = 0; c < xl->channels; c++) {
  out->endpoints += !!xl->chan[c].ep[0] + !!xl->chan[c].ep[1];
  out->announced += xl->chan[c].announced;
  out->consumed += xl->chan[c].consumed;
  out->native_data_running += !!xl->chan[c].rx->running;
  out->native_data_running += !!xl->chan[c].tx->running;
 }
 spin_unlock_irqrestore(&xl->lock, flags);
 mutex_unlock(&xl->ep_mutex);
 out->requester_binds = requester_binds[endpoint];
 for (size_t i = 0; i < w->logs; i++) {
  const struct stack_event *event = &w->log[i];
  if (event->endpoint != endpoint || event->control)
   continue;
  out->data_posts += event->kind == STACK_EV_DATA_POST;
  out->data_callbacks += event->kind == STACK_EV_DATA_CALLBACK;
  out->native_data_callbacks += event->kind == STACK_EV_NHI_CALLBACK;
 }
 return 0;
}
