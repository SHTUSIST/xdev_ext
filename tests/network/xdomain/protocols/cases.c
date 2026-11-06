/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fixed wire oracle for the two independent XDOMAIN protocol programs.
 *
 * run.py appends this file after tests/network/xdomain/early/cases.c (whose
 * main is renamed early_cases_main) inside the actual NHI/XDOMAIN host
 * composition. stack_x6.c is rewritten to include the reference program, the
 * RTS/CTS program and the early-grant program under private symbol names; the
 * table stack_program[] selects the program attached at each endpoint.
 *
 * Expected control bytes are built here, field by field, from the two wire
 * layouts and from protocol rules: a 32-group reliable window starting at
 * group 1, four 4096-byte native elements per 16384-byte group, the batch key
 * as the tag, and the cumulative element sequence. Only the link incarnations,
 * the session identity and the endpoint bind identities are read from the
 * environment, before the exchange starts. Nothing is recorded from a run.
 */
extern unsigned stack_program[2];
extern unsigned stack_force_endpoint, stack_force_event, stack_force_action, stack_force_hits;
enum { PROTO_REFERENCE = 0, PROTO_RTS_CTS = 1, PROTO_EARLY = 2 };
enum { PROTO_V1_RTS = 1, PROTO_V1_CTS, PROTO_V1_ACK, PROTO_V1_HELD, PROTO_V1_FAIL, PROTO_V1_CANCEL };
enum { PROTO_V2_HELLO = 7, PROTO_V2_CHALLENGE, PROTO_V2_CONFIRM };
#define PROTO_GROUP_BYTES 16384U
#define PROTO_SEG_LEN 8192U
#define PROTO_ELEMS 4U
#define PROTO_WINDOW 32U
#define PROTO_ECANCELED 125U

static u8 proto_want[64][128];
static unsigned proto_want_endpoint[64], proto_wants;

static u8 *proto_slot(unsigned endpoint)
{
 CHECK(proto_wants < 64, "golden sequence capacity");
 proto_want_endpoint[proto_wants] = endpoint;
 memset(proto_want[proto_wants], 0, 128);
 return proto_want[proto_wants++];
}
/* The 24-byte tag is the batch key as eight big-endian bytes, then zeros. */
static void proto_tag(u8 *p, u64 key)
{
 for (unsigned i = 0; i < 8; i++)
  p[i] = (u8)(key >> (56 - 8 * i));
}
/* Version 1: "NXD1", version 1, type, channel 0, byte 7 zero; source and
 * destination incarnations at 8 and 16; stream 24, group 32, credit 40;
 * total length 48 (4), element count 52 (2), status 54 (2); data sequence
 * 56; tag 64..87; bytes 88..123 zero; CRC32C of bytes 0..123 at 124. */
static void proto_v1(unsigned endpoint, unsigned type, u64 src, u64 dst, u64 stream,
                     u64 group, u64 credit, u32 total, u32 count, u32 status,
                     u64 data_seq, bool tag, u64 key)
{
 u8 *p = proto_slot(endpoint);
 memcpy(p, "NXD1", 4); p[4] = 1; p[5] = (u8)type;
 early_put(p + 8, src, 8); early_put(p + 16, dst, 8);
 early_put(p + 24, stream, 8); early_put(p + 32, group, 8); early_put(p + 40, credit, 8);
 early_put(p + 48, total, 4); early_put(p + 52, count, 2); early_put(p + 54, status, 2);
 early_put(p + 56, data_seq, 8);
 if (tag) proto_tag(p + 64, key);
 early_recrc(p);
}
/* Version 2 (frozen early contract, early/wire_cases.c): "NXD2", version 2,
 * type, channel 0; incarnations 8 and 16; TX bind 24, RX bind 32; group 40,
 * credit 48, data sequence 56, key 64; total length 72 (4), count 76 (2),
 * status 78 (2), segment length 80 (4); 84..95 zero; tag 96..119; CRC32C. */
static void proto_v2(unsigned endpoint, unsigned type, u64 src, u64 dst, u64 tx_bind,
                     u64 rx_bind, u64 group, u64 credit, u64 data_seq, u64 key,
                     bool shape, bool tag)
{
 u8 *p = proto_slot(endpoint);
 memcpy(p, "NXD2", 4); p[4] = 2; p[5] = (u8)type;
 early_put(p + 8, src, 8); early_put(p + 16, dst, 8);
 early_put(p + 24, tx_bind, 8); early_put(p + 32, rx_bind, 8);
 early_put(p + 40, group, 8); early_put(p + 48, credit, 8);
 early_put(p + 56, data_seq, 8); early_put(p + 64, key, 8);
 if (shape) {
  early_put(p + 72, PROTO_GROUP_BYTES, 4); early_put(p + 76, PROTO_ELEMS, 2);
  early_put(p + 80, PROTO_SEG_LEN, 4);
 }
 if (tag) proto_tag(p + 96, key);
 early_recrc(p);
}
static void proto_hex(const char *label, unsigned endpoint, const u8 *p)
{
 fprintf(stderr, "PROTO_WIRE %s endpoint=%u ", label, endpoint);
 for (unsigned i = 0; i < 128; i++) fprintf(stderr, "%02x", p[i]);
 fprintf(stderr, "\n");
}
/* Every business control message on the link, in order, equals the golden. */
static void proto_expect_wire(void)
{
 unsigned n = 0;
 for (size_t i = 0; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind != STACK_EV_CONTROL_TX) continue;
  if (n >= proto_wants || e.endpoint != proto_want_endpoint[n] || e.raw_len != 128 ||
      memcmp(e.raw, proto_want[n], 128)) {
   fprintf(stderr, "PROTO_WIRE_MISMATCH index=%u\n", n);
   proto_hex("actual", e.endpoint, e.raw);
   if (n < proto_wants) proto_hex("golden", proto_want_endpoint[n], proto_want[n]);
  }
  CHECK(n < proto_wants, "no control message beyond the fixed golden sequence");
  CHECK(e.endpoint == proto_want_endpoint[n] && e.raw_len == 128 &&
        !memcmp(e.raw, proto_want[n], 128), "control message equals its fixed golden bytes in order");
  n++;
 }
 if (n != proto_wants) {
  fprintf(stderr, "PROTO_WIRE_SHORT sent=%u golden=%u\n", n, proto_wants);
  proto_hex("first-missing", proto_want_endpoint[n], proto_want[n]);
 }
 CHECK(n == proto_wants, "every fixed golden control message was sent");
}
static u64 proto_cts_group(const struct stack_event *e)
{ return e->raw[3] == '2' ? early_le(e->raw + 40, 8) : early_le(e->raw + 32, 8); }
/*
 * The sender never transmits a group the receiver has not posted and
 * advertised: each TX native post of group g follows the sender's receipt of
 * a CTS naming g, and each such CTS follows every RX native post of g.
 */
static void proto_cts_invariant(unsigned groups)
{
 for (unsigned g = 1; g <= groups; g++) {
  u64 cts_tx = 0, cts_rx = 0, rx_posts = 0, tx_posts = 0;
  for (size_t i = 0; i < world->logs; i++) {
   struct stack_event e = world->log[i];
   if ((e.kind == STACK_EV_CONTROL_TX || e.kind == STACK_EV_CONTROL_RX) && e.control_type == 2 &&
       proto_cts_group(&e) == g) {
    if (e.kind == STACK_EV_CONTROL_TX && e.endpoint == 1 && !cts_tx) cts_tx = e.id;
    if (e.kind == STACK_EV_CONTROL_RX && e.endpoint == 0 && !cts_rx) cts_rx = e.id;
   }
  }
  CHECK(cts_tx && cts_rx, "receiver advertised each group by CTS and the sender received it");
  for (size_t i = 0; i < world->logs; i++) {
   struct stack_event e = world->log[i];
   if (e.kind != STACK_EV_DATA_POST || e.group != g) continue;
   if (e.endpoint == 1) { rx_posts++; CHECK(e.id < cts_tx, "receiver posts a group before advertising it"); }
   else { tx_posts++; CHECK(e.id > cts_rx, "sender posts a group only after its CTS arrived"); }
  }
  CHECK(rx_posts == PROTO_ELEMS && tx_posts == PROTO_ELEMS, "each side posts exactly one whole group");
 }
}
/* The sender chooses RTS/CTS by its first RTS, the receiver by its first CTS.
 * From then on the endpoint sends only version-1 control and its program sees
 * no pairing or grant event (PAIR_DUE 18 .. EARLY_RX_READY 23). */
static void proto_no_v2_after(unsigned endpoint)
{
 u64 chosen = first(world, STACK_EV_CONTROL_TX, (int)endpoint, endpoint ? PROTO_V1_CTS : PROTO_V1_RTS);
 CHECK(chosen, "the endpoint chose RTS/CTS by sending its first RTS or CTS");
 for (size_t i = 0; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind == STACK_EV_CONTROL_TX && e.endpoint == endpoint)
   CHECK(!memcmp(e.raw, "NXD1", 4), "an RTS/CTS endpoint sends only version-1 control");
  if (e.kind == STACK_EV_PROTOCOL && e.endpoint == endpoint && e.id > chosen)
   CHECK(e.control_type < 18 || e.control_type > 23,
         "after the RTS/CTS choice no pairing or grant event reaches the program");
 }
}
static size_t proto_failures(unsigned endpoint)
{ return count(world, STACK_EV_FAILURE, (int)endpoint, -1); }
/* Called by the bridge after each protocol callback. An RTS/CTS endpoint
 * declines the first pairing offer; a repeated offer is a class fault (a few
 * stale re-offers are tolerated). */
static unsigned proto_pair_offers[2];
void proto_observe(unsigned endpoint, unsigned program, unsigned event)
{
 if (endpoint > 1 || program != PROTO_RTS_CTS || event != 18) return;
 CHECK(++proto_pair_offers[endpoint] <= 3, "an RTS/CTS endpoint is not offered pairing again after declining it");
}
static void proto_programs(unsigned tx, unsigned rx)
{
 stack_program[0] = tx; stack_program[1] = rx; stack_force_endpoint = 2; stack_force_hits = 0;
 proto_pair_offers[0] = proto_pair_offers[1] = 0;
}

/* RTS -> receiver posts -> CTS -> sender posts -> release -> ACK, two groups. */
static void proto_rts_cts(unsigned tx_prog, unsigned rx_prog, unsigned flags)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(tx_prog, rx_prog);
 early_flags = flags;
 u64 tx_bind = link(0)->early_bind_next;
 sessions(w, 2, 0);
 /* A v2-envelope sender first sees PAIR_DUE; RTS/CTS declines pairing. */
 pump(w, 1000000);
 u64 i0 = link(0)->local_inc, i1 = link(1)->local_inc;
 u64 stream = flags ? tx_bind : w->side[0].current->s.id;
 for (unsigned g = 0; g < 2; g++) {
  start(w, c.first_seq + g, 0);
  pump(w, 1000000);
  release_group(w, c.first_seq + g);
 }
 proto_wants = 0;
 for (unsigned g = 1; g <= 2; g++) {
  u64 key = c.first_seq + g - 1;
  proto_v1(0, PROTO_V1_RTS, i0, i1, stream, g, 0, PROTO_GROUP_BYTES, PROTO_ELEMS, 0,
           (g - 1) * PROTO_ELEMS, true, key);
  /* Credit is the window end: base group + 32. A CTS sees groups below g
   * closed; the ACK of g closes g itself. */
  proto_v1(1, PROTO_V1_CTS, i1, i0, stream, g, g + PROTO_WINDOW, 0, 0, 0, 0, false, 0);
  proto_v1(1, PROTO_V1_ACK, i1, i0, stream, g, g + PROTO_WINDOW + 1, 0, 0, 0, 0, false, 0);
 }
 proto_expect_wire();
 proto_cts_invariant(2);
 proto_no_v2_after(0);
 proto_no_v2_after(1);
 addresses(w, &c);
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 2 && count(w, STACK_EV_PUBLISH, 1, -1) == 2,
       "both groups publish once at each end");
 CHECK(!proto_failures(0) && !proto_failures(1), "no stage failure on the RTS/CTS path");
 safety(w);
 CHECK(stack_stop(w, 0) == 0 && stack_stop(w, 1) == 0, "clean final STOP");
}
/* Pair, receiver posts and advertises the next group before the sender asks,
 * sender posts on the grant, release -> ACK; two groups in sequence. */
static void proto_early(unsigned tx_prog, unsigned rx_prog)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(tx_prog, rx_prog);
 early_flags = 2;
 u64 tx_bind = link(0)->early_bind_next, rx_bind = link(1)->early_bind_next;
 struct stack_session_config rx = {.direction = 2, .groups = 2}, tx = {.direction = 1, .groups = 2};
 CHECK(stack_session(w, 1, &rx) == 0 && stack_session(w, 0, &tx) == 0, "v2-envelope endpoints bind");
 pump(w, 1000000);
 u64 i0 = link(0)->local_inc, i1 = link(1)->local_inc;
 for (unsigned g = 0; g < 2; g++) {
  CHECK(stack_start(w, 1, c.first_seq + g, 0) == 0, "receiver batch arms before any sender batch");
  pump(w, 1000000);
  CHECK(early_data(1) == (g + 1) * PROTO_ELEMS, "receiver posted the next group before the sender asked");
  CHECK(early_data(0) == g * PROTO_ELEMS, "the grant exists before matching sender native work");
  CHECK(stack_start(w, 0, c.first_seq + g, 0) == 0, "sender batch consumes its grant");
  pump(w, 1000000);
  release_group(w, c.first_seq + g);
 }
 proto_wants = 0;
 proto_v2(0, PROTO_V2_HELLO, i0, i1, tx_bind, 0, 0, 0, 0, 0, true, false);
 proto_v2(1, PROTO_V2_CHALLENGE, i1, i0, tx_bind, rx_bind, 0, 0, 0, 0, true, false);
 proto_v2(0, PROTO_V2_CONFIRM, i0, i1, tx_bind, rx_bind, 0, 0, 0, 0, true, false);
 for (unsigned g = 1; g <= 2; g++) {
  u64 key = c.first_seq + g - 1;
  proto_v2(1, PROTO_V1_CTS, i1, i0, tx_bind, rx_bind, g, g + PROTO_WINDOW,
           (g - 1) * PROTO_ELEMS, key, true, true);
  proto_v2(1, PROTO_V1_ACK, i1, i0, tx_bind, rx_bind, g, g + PROTO_WINDOW + 1, 0, 0, false, false);
 }
 proto_expect_wire();
 proto_cts_invariant(2);
 CHECK(!count(w, STACK_EV_CONTROL_TX, -1, PROTO_V1_RTS), "the early-grant exchange never sends an RTS");
 addresses(w, &c);
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 2 && count(w, STACK_EV_PUBLISH, 1, -1) == 2,
       "both groups publish once at each end");
 CHECK(!proto_failures(0) && !proto_failures(1), "no stage failure on the early-grant path");
 safety(w);
}
/* RTS/CTS sender, early-grant receiver: the receiver never binds a group from
 * the RTS; the withdrawn group ends in one refusal, with no payload DMA. */
static void proto_mismatch_rts_sender(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(PROTO_RTS_CTS, PROTO_EARLY);
 early_flags = 2;
 u64 tx_bind = link(0)->early_bind_next;
 sessions(w, 1, 0);
 pump(w, 1000000);
 u64 i0 = link(0)->local_inc, i1 = link(1)->local_inc;
 start(w, c.first_seq, 0);
 pump(w, 1000000);
 CHECK(!early_data(0) && !early_data(1), "no native payload before any CTS");
 pump(w, UINT64_C(16000000000));
 for (unsigned i = 0; i < 4; i++) pump(w, 1000000);
 CHECK(!early_data(0) && !early_data(1), "mismatched binding never authorizes payload DMA");
 CHECK(!count(w, STACK_EV_CONTROL_TX, 1, PROTO_V1_CTS), "the early receiver never advertises an RTS group");
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 1, "the withdrawn sender batch publishes once");
 for (size_t i = 0; i < world->logs; i++)
  if (world->log[i].kind == STACK_EV_PUBLISH && world->log[i].endpoint == 0)
   CHECK(world->log[i].status < 0, "the withdrawn sender batch reports failure");
 CHECK(!proto_failures(1), "the receiver stage stays alive");
 proto_wants = 0;
 proto_v1(0, PROTO_V1_RTS, i0, i1, tx_bind, 1, 0, PROTO_GROUP_BYTES, PROTO_ELEMS, 0, 0, true, c.first_seq);
 proto_v1(0, PROTO_V1_CANCEL, i0, i1, tx_bind, 1, 0, 0, 0, 0, 0, false, 0);
 /* The refusal closes group 1, so its credit is base 2 + 32. */
 proto_v1(1, PROTO_V1_FAIL, i1, i0, tx_bind, 1, 1 + PROTO_WINDOW + 1, 0, 0, PROTO_ECANCELED, 0, false, 0);
 proto_expect_wire();
 safety(w);
}
/* Early-grant sender, RTS/CTS receiver: the receiver declines pairing; the
 * sender's bounded pairing deadline ends it, with no payload DMA. */
static void proto_mismatch_pair_sender(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(PROTO_EARLY, PROTO_RTS_CTS);
 early_flags = 2;
 struct stack_session_config rx = {.direction = 2, .groups = 1}, tx = {.direction = 1, .groups = 1};
 CHECK(stack_session(w, 1, &rx) == 0 && stack_session(w, 0, &tx) == 0, "v2-envelope endpoints bind");
 CHECK(stack_start(w, 1, c.first_seq, 0) == 0, "receiver batch arms");
 pump(w, 1000000);
 CHECK(count(w, STACK_EV_CONTROL_TX, 0, PROTO_V2_HELLO) >= 1, "the early sender starts pairing");
 pump(w, UINT64_C(31000000000));
 for (unsigned i = 0; i < 4; i++) pump(w, 1000000);
 CHECK(!count(w, STACK_EV_CONTROL_TX, 1, PROTO_V2_CHALLENGE), "the RTS/CTS receiver never answers pairing");
 CHECK(!early_data(0) && !early_data(1), "mismatched binding never authorizes payload DMA");
 CHECK(stage_facts(w, 0, 0).stage_dead, "the sender's pairing deadline ends the unpaired sender");
 /* The receiver's armed batch may time out by itself; the stage lives. */
 CHECK(!stage_facts(w, 1, 0).stage_dead, "the receiver stage stays alive");
 for (size_t i = 0; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind == STACK_EV_CONTROL_TX && e.endpoint == 0)
   CHECK(e.control_type == PROTO_V2_HELLO, "the unpaired early sender sends only HELLO");
 }
 safety(w);
}
/* After the RTS/CTS choice a v2 pairing input is dropped at the receiver. */
static void proto_rts_drops_hello(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(PROTO_RTS_CTS, PROTO_RTS_CTS);
 early_flags = 2;
 u64 tx_bind = link(0)->early_bind_next;
 sessions(w, 2, 0);
 pump(w, 1000000);
 start(w, c.first_seq, 0);
 pump(w, 1000000);
 release_group(w, c.first_seq);
 u8 hello[128] = {0};
 memcpy(hello, "NXD2", 4); hello[4] = 2; hello[5] = PROTO_V2_HELLO;
 early_put(hello + 8, link(0)->local_inc, 8); early_put(hello + 16, link(1)->local_inc, 8);
 early_put(hello + 24, tx_bind + 7, 8);
 early_put(hello + 72, PROTO_GROUP_BYTES, 4); early_put(hello + 76, PROTO_ELEMS, 2);
 early_put(hello + 80, PROTO_SEG_LEN, 4);
 early_recrc(hello);
 early_inject(1, hello);
 start(w, c.first_seq + 1, 0);
 pump(w, 1000000);
 release_group(w, c.first_seq + 1);
 proto_no_v2_after(0);
 proto_no_v2_after(1);
 CHECK(!count(w, STACK_EV_CONTROL_TX, 1, PROTO_V2_CHALLENGE), "no CHALLENGE answers the late HELLO");
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 2 && count(w, STACK_EV_PUBLISH, 1, -1) == 2,
       "the RTS/CTS session continues after the dropped HELLO");
 CHECK(!proto_failures(0) && !proto_failures(1), "no stage failure");
 safety(w);
}
/* A sender that announces before its first progress pass chose RTS/CTS by
 * that RTS: it is never offered pairing afterwards. */
static void proto_announce_latches_choice(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(PROTO_RTS_CTS, PROTO_RTS_CTS);
 early_flags = 2;
 sessions(w, 1, 0);
 start(w, c.first_seq, 0);
 u64 rts = first(w, STACK_EV_CONTROL_TX, 0, PROTO_V1_RTS);
 CHECK(rts, "the sender announced by RTS");
 /* Precondition of this case: the RTS came before any pairing offer. */
 for (size_t i = 0; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind == STACK_EV_PROTOCOL && e.endpoint == 0 && e.id < rts)
   CHECK(e.control_type == 1, "the sender's only event before its RTS was TX_SUBMIT");
 }
 for (unsigned k = 0; k < 4; k++) pump(w, 25000000);
 release_group(w, c.first_seq);
 proto_no_v2_after(0);
 proto_no_v2_after(1);
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 1 && count(w, STACK_EV_PUBLISH, 1, -1) == 1,
       "the group completes at both ends");
 safety(w);
}
/* A paired stage cannot fall back to an RTS: a forced TX_ANNOUNCE is refused. */
static void proto_paired_refuses_announce(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(PROTO_EARLY, PROTO_EARLY);
 early_flags = 2;
 struct stack_session_config rx = {.direction = 2, .groups = 1}, tx = {.direction = 1, .groups = 1};
 CHECK(stack_session(w, 1, &rx) == 0 && stack_session(w, 0, &tx) == 0, "v2-envelope endpoints bind");
 pump(w, 1000000);
 CHECK(count(w, STACK_EV_CONTROL_TX, 0, PROTO_V2_CONFIRM) >= 1, "pairing completed");
 stack_force_endpoint = 0; stack_force_event = 1; stack_force_action = 3; /* TX_SUBMIT -> TX_ANNOUNCE */
 int ret = stack_start(w, 0, c.first_seq, 0);
 pump(w, 1000000);
 CHECK(stack_force_hits == 1, "the forced announce reached the class");
 CHECK(ret != 0 || proto_failures(0) > 0, "the class refuses an RTS binding on a paired stage");
 CHECK(!count(w, STACK_EV_CONTROL_TX, 0, PROTO_V1_RTS), "no RTS is sent by a paired stage");
 CHECK(!early_data(0), "no sender payload DMA");
}
/* A forced early post without an advertised grant is refused: no TX DMA. */
static void proto_post_needs_grant(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 proto_programs(PROTO_EARLY, PROTO_EARLY);
 early_flags = 2;
 struct stack_session_config rx = {.direction = 2, .groups = 1}, tx = {.direction = 1, .groups = 1};
 CHECK(stack_session(w, 1, &rx) == 0 && stack_session(w, 0, &tx) == 0, "v2-envelope endpoints bind");
 pump(w, 1000000);
 stack_force_endpoint = 0; stack_force_event = 1; stack_force_action = 24; /* TX_POST_EARLY */
 int ret = stack_start(w, 0, c.first_seq, 0);
 pump(w, 1000000);
 CHECK(stack_force_hits == 1, "the forced early post reached the class");
 CHECK(ret != 0 || proto_failures(0) > 0, "the class refuses a post without an advertised grant");
 CHECK(!early_data(0), "no sender payload DMA without CTS credit");
}

/* A v2-envelope receiver that no peer paired with holds a pairing offer: its
 * program answered the HELLO with WAIT because control TX was full. Returns
 * the log index after the precondition. */
static size_t proto_hello_held(unsigned prog)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 budget = 512; /* a loop fails a named bounded-pump check, not the log limit */
 proto_programs(prog, prog);
 early_flags = 2;
 struct stack_session_config rx = {.direction = 2, .groups = 2};
 CHECK(stack_session(w, 1, &rx) == 0, "the v2-envelope receiver binds alone");
 CHECK(stack_start(w, 1, c.first_seq, 0) == 0, "the receiver arms one batch");
 pump(w, 1000000);
 fault(w, STACK_FAULT_CONTROL_REFUSE, 1, 0, 0, 1, 0);
 u8 hello[128] = {0};
 memcpy(hello, "NXD2", 4); hello[4] = 2; hello[5] = PROTO_V2_HELLO;
 early_put(hello + 8, link(0)->local_inc, 8); early_put(hello + 16, link(1)->local_inc, 8);
 early_put(hello + 24, link(0)->early_bind_next, 8);
 early_put(hello + 72, PROTO_GROUP_BYTES, 4); early_put(hello + 76, PROTO_ELEMS, 2);
 early_put(hello + 80, PROTO_SEG_LEN, 4);
 early_recrc(hello);
 early_inject(1, hello);
 size_t offers = 0, waits = 0;
 for (size_t i = 0; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind == STACK_EV_PROTOCOL && e.endpoint == 1 && e.control_type == 19) {
   offers++;
   if (e.length == 1) waits++;
  }
 }
 CHECK(offers && offers == waits, "precondition: the receiver's program waits on the HELLO for control room");
 CHECK(!count(w, STACK_EV_CONTROL_TX, 1, -1) && !stage_facts(w, 1, 0).stage_dead,
       "precondition: the live receiver has answered nothing yet");
 return world->logs;
}
/* Diagnostic: what the receiver's program was asked from log index mark on. */
static void proto_offer_report(size_t mark, const char *when)
{
 size_t events = 0, hello = 0, fail_link = 0;
 for (size_t i = mark; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind != STACK_EV_PROTOCOL || e.endpoint != 1) continue;
  events++;
  if (e.control_type == 19) hello++;
  if (e.length == 16) fail_link++;
 }
 fprintf(stderr, "PROTO_RECEIVER_EVENTS %s events=%zu hello=%zu fail_link=%zu up1=%u\n",
         when, events, hello, fail_link, (unsigned)link(1)->up);
}
/* Protocol events of the receiver's program from log index mark on. */
static void proto_no_offer_after(size_t mark, bool none)
{
 for (size_t i = mark; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind != STACK_EV_PROTOCOL || e.endpoint != 1) continue;
  CHECK(e.length != 16, "the ending receiver's program is never asked to fail the link");
  CHECK(e.control_type != 19, "an ending receiver is not offered its held pairing offer");
  CHECK(!none, "an ended receiver's program is offered no further event");
 }
}
/* STOP: the receiver nobody paired follows the version-1 STOP rules. It ends
 * in a bounded number of steps, cancels its armed batch, keeps the link up
 * in the same incarnation and records no stage failure. */
static void proto_hello_then_stop(unsigned prog)
{
 size_t mark = proto_hello_held(prog);
 u64 inc1 = link(1)->local_inc;
 int stop = stack_stop(world, 1);
 for (unsigned i = 0; i < 4; i++) {
  int pumped = stack_pump(world, 64, 25000000);
  proto_offer_report(mark, "after-stop");
  CHECK(pumped == 0, "STOP of a receiver holding a pairing offer ends in a bounded number of steps");
 }
 CHECK(stop == 0 || stop == -EAGAIN, "STOP is accepted");
 proto_no_offer_after(mark, false);
 CHECK(link(1)->up && link(1)->local_inc == inc1, "STOP keeps the link up in the same incarnation");
 /* The harness records each nonzero CQE as a failure: the canceled batch is
  * the only one, and the stage itself is not ended. */
 CHECK(proto_failures(1) == 1 && !stage_facts(world, 1, 0).stage_dead,
       "an uncommitted receiver stops without a stage failure");
 CHECK(count(world, STACK_EV_PUBLISH, 1, -1) == 1, "the armed batch completes once");
 for (size_t i = 0; i < world->logs; i++)
  if (world->log[i].kind == STACK_EV_PUBLISH && world->log[i].endpoint == 1)
   CHECK(world->log[i].status == -ECANCELED, "STOP cancels the armed batch");
 CHECK(!count(world, STACK_EV_CONTROL_TX, 1, -1), "the stopped receiver sends no control");
 CHECK(!early_data(1), "no payload DMA");
 CHECK(stack_stop(world, 1) == 0, "STOP drains");
 safety(world);
}
/* Link failure: the receiver ends in a bounded number of steps without its
 * program seeing another event, and it does not end the successor link. */
static void proto_hello_then_link_down(unsigned prog)
{
 size_t mark = proto_hello_held(prog);
 u64 inc1 = link(1)->local_inc;
 xdev_ext_xd_link_fail(link(1), NULL, -ENOLINK);
 /* The second pump runs after the program's wake on the HELLO expired. */
 for (unsigned i = 0; i < 2; i++) {
  int pumped = stack_pump(world, 64, i ? 25000000 : 1000000);
  proto_offer_report(mark, "after-link-failure");
  CHECK(pumped == 0, "a link failure ends a receiver holding a pairing offer in a bounded number of steps");
 }
 CHECK(link(1)->local_inc != inc1, "the link failure ended the receiver's incarnation");
 CHECK(stage_facts(world, 1, 0).stage_dead, "the link failure ends the receiver stage");
 proto_no_offer_after(mark, true);
 CHECK(count(world, STACK_EV_PUBLISH, 1, -1) == 1, "the armed batch completes once");
 for (size_t i = 0; i < world->logs; i++)
  if (world->log[i].kind == STACK_EV_PUBLISH && world->log[i].endpoint == 1)
   CHECK(world->log[i].status < 0, "the armed batch reports the failure");
 for (unsigned i = 0; i < 8 && !(link(0)->up && link(1)->up); i++)
  CHECK(stack_pump(world, 256, 1000000000) == 0, "relogin runs in a bounded number of steps");
 CHECK(link(0)->up && link(1)->up, "the link logs in again");
 u64 succ = link(1)->local_inc;
 for (unsigned i = 0; i < 4; i++)
  CHECK(stack_pump(world, 256, 25000000) == 0, "the ended receiver stays quiet");
 proto_no_offer_after(mark, true);
 CHECK(link(1)->up && link(1)->local_inc == succ, "the ended receiver does not end the successor link");
 CHECK(!count(world, STACK_EV_CONTROL_TX, 1, PROTO_V2_CHALLENGE) && !early_data(1),
       "the ended receiver never pairs and posts nothing");
}

/* Raw version-1 control message for injection (same layout as proto_v1). */
static void proto_v1_raw(u8 *p, unsigned type, u64 stream, u64 group, u64 credit, u32 total,
                         u32 count, u64 data_seq, u64 key)
{
 memset(p, 0, 128);
 memcpy(p, "NXD1", 4); p[4] = 1; p[5] = (u8)type;
 early_put(p + 8, link(0)->local_inc, 8); early_put(p + 16, link(1)->local_inc, 8);
 early_put(p + 24, stream, 8); early_put(p + 32, group, 8); early_put(p + 40, credit, 8);
 early_put(p + 48, total, 4); early_put(p + 52, count, 2);
 early_put(p + 56, data_seq, 8);
 if (key) proto_tag(p + 64, key);
 early_recrc(p);
}
static void proto_v1_raw_to_sender(u8 *p, unsigned type, u64 stream, u64 group, u64 credit)
{
 proto_v1_raw(p, type, stream, group, credit, 0, 0, 0, 0);
 early_put(p + 8, link(1)->local_inc, 8); early_put(p + 16, link(0)->local_inc, 8);
 early_recrc(p);
}
/* Diagnostic: every failure record and the link state. */
static void proto_failure_report(const char *when)
{
 for (size_t i = 0; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind == STACK_EV_FAILURE)
   fprintf(stderr, "PROTO_FAILURE %s endpoint=%u id=%llu status=%d group=%llu\n", when, e.endpoint,
           (unsigned long long)e.id, e.status, (unsigned long long)e.group);
 }
 fprintf(stderr, "PROTO_LINK %s up0=%u up1=%u rx_dead=%u tx_dead=%u\n", when, (unsigned)link(0)->up,
         (unsigned)link(1)->up, stage_facts(world, 1, 0).stage_dead, stage_facts(world, 0, 0).stage_dead);
}
/* A version-1 RTS from another stream reached a receiver nobody had paired
 * with yet. Pairing drops it with the rest of the stage's version-1 control,
 * as the link drops version-1 control to a paired endpoint: the pair's
 * transfer completes and the RTS is never answered with the pair's facts. */
static void proto_stray_rts_then_pair(unsigned prog)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 budget = 512; /* a loop fails a named bounded-pump check, not the log limit */
 proto_programs(prog, prog);
 early_flags = 2;
 struct stack_session_config rx = {.direction = 2, .groups = 2}, tx = {.direction = 1, .groups = 2};
 CHECK(stack_session(w, 1, &rx) == 0, "the v2-envelope receiver binds first");
 CHECK(stack_start(w, 1, c.first_seq, 0) == 0, "the receiver arms one batch");
 pump(w, 1000000);
 u64 inc0 = link(0)->local_inc, inc1 = link(1)->local_inc;
 u8 raw[128];
 proto_v1_raw(raw, PROTO_V1_RTS, link(0)->early_bind_next + 7, 1, 0, PROTO_GROUP_BYTES, PROTO_ELEMS, 0, 999);
 early_inject(1, raw);
 pump(w, 1000000);
 CHECK(!count(w, STACK_EV_CONTROL_TX, 1, -1) && !stage_facts(w, 1, 0).stage_dead,
       "precondition: the live receiver holds the RTS unanswered");
 CHECK(stack_session(w, 0, &tx) == 0, "the early sender binds");
 for (unsigned i = 0; i < 8; i++) pump(w, 25000000);
 CHECK(count(w, STACK_EV_CONTROL_TX, 0, PROTO_V2_CONFIRM) >= 1, "the endpoints pair");
 CHECK(early_data(1) == PROTO_ELEMS, "the receiver posted its group for the pair");
 int started = stack_start(w, 0, c.first_seq, 0);
 proto_failure_report("after-pairing");
 CHECK(started == 0, "the sender batch consumes its grant");
 for (unsigned i = 0; i < 4; i++) pump(w, 25000000);
 release_group(w, c.first_seq);
 CHECK(early_data(0) == PROTO_ELEMS && early_data(1) == PROTO_ELEMS,
       "the pair's group is posted once at each end");
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 1 && count(w, STACK_EV_PUBLISH, 1, -1) == 1,
       "the pair's group completes once at each end");
 for (size_t i = 0; i < world->logs; i++) {
  struct stack_event e = world->log[i];
  if (e.kind == STACK_EV_PUBLISH) CHECK(e.status == 0, "the pair's group completes successfully");
  if (e.kind == STACK_EV_CONTROL_TX && e.endpoint == 1)
   CHECK(!memcmp(e.raw, "NXD2", 4) && e.control_type != PROTO_V1_FAIL,
         "the receiver never refuses the stray RTS with the pair's facts");
 }
 CHECK(!stage_facts(w, 0, 0).stage_dead && !stage_facts(w, 1, 0).stage_dead, "both stages stay alive");
 CHECK(link(0)->up && link(1)->up && link(0)->local_inc == inc0 && link(1)->local_inc == inc1,
       "the link stays up in the same incarnation");
 safety(w);
}
/* A stray version-1 CTS reached an early sender that had not started pairing
 * (its first PAIR_DUE waited for control room); it names a group the sender
 * never announced. The sender still pairs and transfers, and its program never
 * takes the record for a CTS. */
static void proto_stray_cts_then_pair(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 budget = 512; /* a loop fails a named bounded-pump check, not the log limit */
 proto_programs(PROTO_EARLY, PROTO_EARLY);
 early_flags = 2;
 u64 tx_bind = link(0)->early_bind_next;
 fault(w, STACK_FAULT_CONTROL_REFUSE, 0, 0, 0, 1, 0);
 struct stack_session_config rx = {.direction = 2, .groups = 2}, tx = {.direction = 1, .groups = 2};
 CHECK(stack_session(w, 0, &tx) == 0, "the early sender binds first");
 pump(w, 1000000);
 CHECK(count(w, STACK_EV_PROTOCOL, 0, 18) >= 1 && !count(w, STACK_EV_CONTROL_TX, 0, -1),
       "precondition: the sender's first PAIR_DUE waits for control room");
 u64 inc0 = link(0)->local_inc, inc1 = link(1)->local_inc;
 u8 raw[128];
 proto_v1_raw_to_sender(raw, PROTO_V1_CTS, tx_bind, 1, 1 + PROTO_WINDOW);
 early_inject(0, raw);
 size_t mark = world->logs;
 fault(w, STACK_FAULT_RELEASE_CONTROLS, 0, 0, 0, 0, 0);
 CHECK(stack_session(w, 1, &rx) == 0, "the early receiver binds");
 for (unsigned i = 0; i < 8; i++) pump(w, 25000000);
 CHECK(count(w, STACK_EV_CONTROL_TX, 0, PROTO_V2_CONFIRM) >= 1, "the endpoints pair");
 for (size_t i = mark; i < world->logs; i++)
  if (world->log[i].kind == STACK_EV_PROTOCOL && world->log[i].endpoint == 0)
   CHECK(world->log[i].control_type != 4, "the version-1 CTS never reaches the sender's program as a CTS");
 CHECK(stack_start(w, 1, c.first_seq, 0) == 0, "the receiver arms one batch");
 pump(w, 1000000);
 int started = stack_start(w, 0, c.first_seq, 0);
 proto_failure_report("after-pairing");
 CHECK(started == 0, "the sender batch consumes its grant");
 for (unsigned i = 0; i < 4; i++) pump(w, 25000000);
 release_group(w, c.first_seq);
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 1 && count(w, STACK_EV_PUBLISH, 1, -1) == 1,
       "the pair's group completes once at each end");
 for (size_t i = 0; i < world->logs; i++)
  if (world->log[i].kind == STACK_EV_PUBLISH) CHECK(world->log[i].status == 0, "the pair's group completes successfully");
 CHECK(!stage_facts(w, 0, 0).stage_dead && !stage_facts(w, 1, 0).stage_dead, "both stages stay alive");
 CHECK(link(0)->up && link(1)->up && link(0)->local_inc == inc0 && link(1)->local_inc == inc1,
       "the link stays up in the same incarnation");
 safety(w);
}
/* An RTS/CTS session on the version-2 envelope has no pairing deadline: after
 * the sender declined pairing, both stages outlive 30 s and then transfer. */
static void proto_rts_cts_v2_idle(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 budget = 512; /* a loop fails a named bounded-pump check, not the log limit */
 proto_programs(PROTO_RTS_CTS, PROTO_RTS_CTS);
 early_flags = 2;
 sessions(w, 1, 0);
 pump(w, 1000000);
 CHECK(count(w, STACK_EV_PROTOCOL, 0, 18) >= 1, "the sender was offered pairing and declined it");
 pump(w, UINT64_C(31000000000));
 for (unsigned i = 0; i < 4; i++) pump(w, 25000000);
 CHECK(!stage_facts(w, 0, 0).stage_dead && !stage_facts(w, 1, 0).stage_dead,
       "neither RTS/CTS stage ends at the 30-second pairing deadline");
 start(w, c.first_seq, 0);
 pump(w, 1000000);
 release_group(w, c.first_seq);
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 1 && count(w, STACK_EV_PUBLISH, 1, -1) == 1,
       "the group completes at both ends after 31 s");
 for (size_t i = 0; i < world->logs; i++)
  if (world->log[i].kind == STACK_EV_PUBLISH) CHECK(world->log[i].status == 0, "the late group completes successfully");
 proto_no_v2_after(0);
 proto_no_v2_after(1);
 CHECK(!proto_failures(0) && !proto_failures(1), "no stage failure");
 safety(w);
}
/* A paired endpoint takes no version-1 control: the link drops an RTS to the
 * paired receiver and a CTS to the paired sender before any program sees
 * them, and the pair's transfer is unaffected. */
static void proto_paired_drops_v1(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 budget = 512; /* a loop fails a named bounded-pump check, not the log limit */
 proto_programs(PROTO_EARLY, PROTO_EARLY);
 early_flags = 2;
 u64 tx_bind = link(0)->early_bind_next;
 struct stack_session_config rx = {.direction = 2, .groups = 1}, tx = {.direction = 1, .groups = 1};
 CHECK(stack_session(w, 1, &rx) == 0 && stack_session(w, 0, &tx) == 0, "v2-envelope endpoints bind");
 pump(w, 1000000);
 CHECK(count(w, STACK_EV_CONTROL_TX, 0, PROTO_V2_CONFIRM) >= 1, "pairing completed");
 u64 dropped0 = link(0)->ctl_dropped, dropped1 = link(1)->ctl_dropped;
 size_t mark = world->logs;
 u8 raw[128];
 proto_v1_raw(raw, PROTO_V1_RTS, tx_bind, 1, 0, PROTO_GROUP_BYTES, PROTO_ELEMS, 0, c.first_seq);
 early_inject(1, raw);
 proto_v1_raw_to_sender(raw, PROTO_V1_CTS, tx_bind, 1, 1 + PROTO_WINDOW);
 early_inject(0, raw);
 for (unsigned i = 0; i < 2; i++) pump(w, 25000000);
 CHECK(link(1)->ctl_dropped == dropped1 + 1 && link(0)->ctl_dropped == dropped0 + 1,
       "the link drops version-1 control to each paired endpoint");
 for (size_t i = mark; i < world->logs; i++)
  if (world->log[i].kind == STACK_EV_PROTOCOL)
   CHECK(world->log[i].control_type != 3 && world->log[i].control_type != 4,
         "no program of a paired endpoint is offered a version-1 RTS or CTS");
 CHECK(stack_start(w, 1, c.first_seq, 0) == 0, "receiver batch arms");
 pump(w, 1000000);
 CHECK(stack_start(w, 0, c.first_seq, 0) == 0, "sender batch consumes its grant");
 pump(w, 1000000);
 release_group(w, c.first_seq);
 CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 1 && count(w, STACK_EV_PUBLISH, 1, -1) == 1,
       "the pair's group completes at both ends");
 CHECK(!proto_failures(0) && !proto_failures(1), "no stage failure");
 safety(w);
}
/* Pairing started cannot be declined: a forced IGNORE on PAIR_DUE of a sender
 * that already sent HELLO is refused, and the stage never falls back to RTS. */
static void proto_paired_refuses_decline(void)
{
 struct stack_config c = geometry();
 struct stack_world *w = create(&c);
 login(w);
 budget = 512; /* a loop fails a named bounded-pump check, not the log limit */
 proto_programs(PROTO_EARLY, PROTO_EARLY);
 early_flags = 2;
 struct stack_session_config tx = {.direction = 1, .groups = 1};
 CHECK(stack_session(w, 0, &tx) == 0, "the early sender binds alone");
 pump(w, 1000000);
 CHECK(count(w, STACK_EV_CONTROL_TX, 0, PROTO_V2_HELLO) >= 1, "the sender started pairing");
 stack_force_endpoint = 0; stack_force_event = 18; stack_force_action = 2; /* PAIR_DUE -> IGNORE */
 for (unsigned i = 0; i < 2; i++) pump(w, 25000000);
 CHECK(stack_force_hits == 1, "the forced decline reached the class");
 CHECK(proto_failures(0) > 0, "the class refuses to decline pairing after it started");
 CHECK(!count(w, STACK_EV_CONTROL_TX, 0, PROTO_V1_RTS), "the sender never falls back to RTS");
}

static void proto_set_programs(const char *spec)
{
 unsigned tx = 0, rx = 0;
 if (spec && sscanf(spec, "%u,%u", &tx, &rx) == 2 && tx <= 2 && rx <= 2) proto_programs(tx, rx);
 else proto_programs(PROTO_REFERENCE, PROTO_REFERENCE);
}
int main(int argc, char **argv)
{
 if (argc < 2) return 2;
 const char *name = argv[1];
 if (!strncmp(name, "early:", 6)) {
  char *args[] = {argv[0], (char *)name + 6, NULL};
  proto_set_programs(argc > 2 ? argv[2] : NULL);
  return early_cases_main(2, args);
 }
 case_name = name; budget = 30000;
 if (!strcmp(name, "rts_cts_v2")) proto_rts_cts(PROTO_RTS_CTS, PROTO_RTS_CTS, 2);
 else if (!strcmp(name, "rts_cts_legacy")) proto_rts_cts(PROTO_RTS_CTS, PROTO_RTS_CTS, 0);
 else if (!strcmp(name, "reference_legacy")) proto_rts_cts(PROTO_REFERENCE, PROTO_REFERENCE, 0);
 else if (!strcmp(name, "early_v2")) proto_early(PROTO_EARLY, PROTO_EARLY);
 else if (!strcmp(name, "reference_early")) proto_early(PROTO_REFERENCE, PROTO_REFERENCE);
 else if (!strcmp(name, "mismatch_rts_sender")) proto_mismatch_rts_sender();
 else if (!strcmp(name, "mismatch_pair_sender")) proto_mismatch_pair_sender();
 else if (!strcmp(name, "rts_drops_hello")) proto_rts_drops_hello();
 else if (!strcmp(name, "announce_latches_choice")) proto_announce_latches_choice();
 else if (!strcmp(name, "paired_refuses_announce")) proto_paired_refuses_announce();
 else if (!strcmp(name, "post_needs_grant")) proto_post_needs_grant();
 else if (!strcmp(name, "hello_stop_early")) proto_hello_then_stop(PROTO_EARLY);
 else if (!strcmp(name, "hello_stop_reference")) proto_hello_then_stop(PROTO_REFERENCE);
 else if (!strcmp(name, "hello_link_down_early")) proto_hello_then_link_down(PROTO_EARLY);
 else if (!strcmp(name, "hello_link_down_reference")) proto_hello_then_link_down(PROTO_REFERENCE);
 else if (!strcmp(name, "stray_rts_then_pair_early")) proto_stray_rts_then_pair(PROTO_EARLY);
 else if (!strcmp(name, "stray_rts_then_pair_reference")) proto_stray_rts_then_pair(PROTO_REFERENCE);
 else if (!strcmp(name, "stray_cts_then_pair")) proto_stray_cts_then_pair();
 else if (!strcmp(name, "rts_cts_v2_idle")) proto_rts_cts_v2_idle();
 else if (!strcmp(name, "paired_drops_v1")) proto_paired_drops_v1();
 else if (!strcmp(name, "paired_refuses_decline")) proto_paired_refuses_decline();
 else return 2;
 printf("PROTOCOL_ASSERTIONS %s %u\n", name, assertions);
 return 0;
}
