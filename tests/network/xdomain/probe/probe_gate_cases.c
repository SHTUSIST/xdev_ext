/* SPDX-License-Identifier: GPL-2.0 */
/* Requirement: completed LOGIN alone must reject ordinary business bind with
 * EAGAIN, without publishing an endpoint or entering requester mapping.
 * Removing the data-challenge bind gate is the production bug caught here. */
#include "probe_observation.h"
#include <inttypes.h>

static unsigned assertions, failures;
#define EXPECT(condition, why) do { assertions++; if (!(condition)) { \
 fprintf(stderr, "PROBE_ASSERT: %s\n", why); failures++; } } while (0)
#define SETUP(condition, why) do { if (!(condition)) { \
 fprintf(stderr, "PROBE_SETUP_FAILURE: %s\n", why); return 2; } } while (0)

static struct stack_config geometry(void)
{
 struct stack_config c = {0};
 c.mapping_base[0] = UINT64_C(0x1100000000);
 c.mapping_base[1] = UINT64_C(0x2200000000);
 c.local_inc[0] = 101; c.local_inc[1] = 203;
 c.generation[0] = 17; c.generation[1] = 29;
 c.first_seq = 37; c.depth = 3; c.nr_frames = 2;
 c.frame_size = 65536; c.native_elems = 4; c.channels = 1;
 c.span[0] = (struct stack_span){65536, 4096, 8192};
 c.span[1] = (struct stack_span){196608, 8192, 8192};
 return c;
}

int main(int argc, char **argv)
{
 struct stack_world *w = NULL;
 struct stack_config c = geometry();
 struct probe_observation before[2], after;
 SETUP(argc == 3, "usage: probe-gate ENDPOINT DIRECTION");
 unsigned endpoint = strtoul(argv[1], NULL, 10);
 unsigned direction = strtoul(argv[2], NULL, 10);
 SETUP(endpoint < 2 && (direction == 1 || direction == 2), "valid case selector");
 SETUP(stack_new(&c, &w) == 0 && w, "recording environment allocation");
 /* Freeze the required boundary even when the full startup implementation is
  * present: LOGIN/control progresses, no native data completion is supplied. */
 for(unsigned e=0;e<2;e++) {
  struct stack_fault hold={.kind=STACK_FAULT_HOLD_CALLBACK,.endpoint=e};
  SETUP(stack_fault(w,&hold)==0,"withhold real native data completions");
 }
 SETUP(stack_probe(w, 0) == 0 && stack_probe(w, 1) == 0, "actual main probes");
 SETUP(stack_pump(w, 4096, 1000000) == 0, "bounded actual LOGIN work");
 for (unsigned e = 0; e < 2; e++) {
  SETUP(probe_observe(w, e, &before[e]) == 0, "raw link observation");
  SETUP(before[e].up && before[e].logged_in && before[e].remote_logged_in &&
        before[e].receive_ready, "actual bidirectional LOGIN reaches control UP");
  SETUP(before[e].remote_inc == c.local_inc[1-e] &&
        before[e].accepted_inc == c.local_inc[1-e] &&
        before[e].response_inc == c.local_inc[1-e], "actual LOGIN pair matches");
  SETUP(before[e].native_data_running == 2, "both actual native data rings running");
  SETUP(!before[e].endpoints && !before[e].requester_binds,
        "fresh link has no business endpoint or requester mapping");
  SETUP(!before[e].data_callbacks && !before[e].native_data_callbacks,
        "no startup data completion was supplied");
 }
 struct stack_session_config business = {
  .direction = direction, .stage_index = 0, .groups = 1,
 };
 /* Actual class -> actual netfam -> actual transport dev_ops.bind. */
 int result = stack_session(w, endpoint, &business);
 SETUP(probe_observe(w, endpoint, &after) == 0, "post-bind raw observation");
 printf("PROBE_OBS endpoint=%u direction=%u control_up=%u "
        "data_callbacks=%u native_data_callbacks=%u bind_result=%d "
        "endpoints=%u requester_binds=%u announced=%" PRIu64 " consumed=%" PRIu64 "\n",
        endpoint, direction, after.up, after.data_callbacks,
        after.native_data_callbacks, result, after.endpoints,
        after.requester_binds, after.announced, after.consumed);
 EXPECT(result == -11, "LOGIN-only ordinary business bind must return -EAGAIN");
 EXPECT(after.endpoints == 0, "unverified bind must not publish a business endpoint");
 EXPECT(after.requester_binds == 0, "unverified bind must precede requester mapping");
 EXPECT(after.up == 1, "refused bind preserves control-ready state");
 EXPECT(after.announced == 0 && after.consumed == 0,
        "refused bind does not consume business sequence");
 EXPECT(after.data_posts == before[endpoint].data_posts &&
        after.data_callbacks == 0 && after.native_data_callbacks == 0,
        "ordinary bind does not invent startup native completion");
 stack_destroy(w);
 printf("PROBE_CASE_ASSERTIONS %u failures=%u\n", assertions, failures);
 return failures ? 1 : 0;
}
