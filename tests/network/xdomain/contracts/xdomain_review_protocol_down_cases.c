/* SPDX-License-Identifier: GPL-2.0 */
/* Real X3 main.c callback -> retained error -> down_work -> teardown. */
int main(void)
{
 current_case=1;current_name="review unbound EAGAIN responsibility reaches actual down_work";
 up_link();bind_ep(false);
 u64 old_local=xl->local_inc,old_remote=xl->remote_inc;
 CHECK(xl->chan[0].consumed==0&&xl->chan[0].ep[0]==&endpoint);
 /* Identical NULL endpoint/error delivered by actual ring unbound refusal. */
 xdev_ext_xd_link_fail(xl,NULL,-EAGAIN);
 CHECK(xl->down_work.pending&&xl->down_err==-EAGAIN&&xl->down_local_inc==old_local);
 CHECK(xl->up&&xl->remote_inc==old_remote&&!endpoint.detached&&!dead_calls);
 /* Repeated failure cannot lose the first terminal responsibility. */
 xdev_ext_xd_link_fail(xl,NULL,-EPROTO);
 CHECK(xl->down_work.pending&&xl->down_err==-EAGAIN&&xl->down_local_inc==old_local);
 down_run();
 CHECK(!xl->up&&!xl->remote_inc&&!xl->logged_in&&!xl->remote_logged_in);
 CHECK(endpoint.detached&&!xl->chan[0].ep[0]);
 CHECK(dead_calls==1&&dead_error==-EAGAIN&&dead_stage==&stage);
 CHECK(!rings_running&&ring_stops==1&&events("paths_disable")>0&&!xl->down_work.pending);
 CHECK(xl->local_inc&&xl->local_inc!=old_local&&xl->chan[0].consumed==0);
 CHECK(!xl->down_err&&!xl->down_local_inc);
 CHECK(xl->login_work.work.pending&&xl->login_work.work.delay==1000);
 CHECK(event_index("stage_dead")<event_index("rings_stop"));
 int dead_before=dead_calls;
 xdev_ext_xd_link_fail(xl,&endpoint,-EPROTO);
 CHECK(!xl->down_work.pending&&dead_calls==dead_before);
 printf("ok - real main fail/down terminal old_local=%llu new_local=%llu error=%d consumed=%llu\n",
  (unsigned long long)old_local,(unsigned long long)xl->local_inc,dead_error,(unsigned long long)xl->chan[0].consumed);
 return 0;
}
