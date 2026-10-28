// SPDX-License-Identifier: GPL-2.0
/* Independent X2 requirements tests; host safety rules only, hardware=none.
 * A missing X1 dependency is NOT X2 RED.
 * Mutations caught: swapped offsets/endian/CRC seed, unchecked per-type fields,
 * stale incarnation acceptance, software-pending overcommit/underflow and short-RX success.
 * These helpers do not post work, consume channel sequence or release leases;
 * X4/X5 must prove accepted requests are never resubmitted and UNKNOWN quarantines.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#if !defined(XDEV_EXT_XDOMAIN_PROTO_VERSION) || \
    !defined(XDEV_EXT_XDOMAIN_TAG_LEN) || \
    !defined(XDEV_EXT_XDOMAIN_MAX_ELEMS) || \
    !defined(XDEV_EXT_XDOMAIN_MAX_FRAME)
int main(void) { puts("not ok 1 - missing X1 XDOMAIN ABI dependency"); return 1; }
#define X2_NO_RULES
#elif !__has_include("io_uring/xdomain/xdev_ext_xdomain_core.h")
int main(void) { puts("not ok 1 - no XDOMAIN rules"); return 1; }
#define X2_NO_RULES
#else
#include "io_uring/xdomain/xdev_ext_xdomain_core.h"
#include "io_uring/xdev_ext_mech_step.h"
_Static_assert(XDEV_EXT_XD_MAX_DEPTH == XDEV_EXT_MECH_MAX_DEPTH,
               "XDOMAIN pending depth must match mechanism session depth");
#endif
#ifndef X2_NO_RULES
static unsigned int checks, failures;
#define EQ(label, got, expected) do { \
 long long actual_ = (long long)(got), expected_ = (long long)(expected); \
 checks++; if (actual_ != expected_) { \
 fprintf(stderr, "not ok %u - %s (line %d): got %lld want %lld\n", \
 checks, label, __LINE__, actual_, expected_); failures++; } \
} while (0)
static void bytes_eq(const char *label, const void *a, const void *b, size_t n)
{
 EQ(label, memcmp(a, b, n), 0);
}
/* Test-local bitwise reflected Castagnoli; no inversion inside the callback. */
static __u32 crc_bitwise(__u32 crc, const void *p, size_t len)
{
 const __u8 *s = p;
 size_t i;
 unsigned int bit;
 for (i = 0; i < len; i++) {
  crc ^= s[i];
  for (bit = 0; bit < 8; bit++)
   crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0x82f63b78) : 0);
 }
 return crc;
}
/* Independent literal wire vectors: LE ASCII NXD1 and per-type field table. */
static const __u8 literal_rts[128] = {
	0x4e, 0x58, 0x44, 0x31, 0x01, 0x01, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
	0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x20, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0xaf, 0x95, 0xe2,
};
static const __u8 literal_nonrts[5][128] = {
	{
	0x4e, 0x58, 0x44, 0x31, 0x01, 0x02, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
	0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x28, 0x38, 0x13,
	},
	{
	0x4e, 0x58, 0x44, 0x31, 0x01, 0x03, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
	0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0xa0, 0x66, 0x15,
	},
	{
	0x4e, 0x58, 0x44, 0x31, 0x01, 0x04, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
	0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaf, 0x1b, 0xff, 0x06,
	},
	{
	0x4e, 0x58, 0x44, 0x31, 0x01, 0x05, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
	0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x73, 0xc9, 0x9f,
	},
	{
	0x4e, 0x58, 0x44, 0x31, 0x01, 0x06, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
	0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x67, 0xd9, 0xa1,
	}
};
static struct xdev_ext_xd_msg rts(void)
{
 struct xdev_ext_xd_msg m = {
  .src_inc = UINT64_C(0x0102030405060708),
  .dst_inc = UINT64_C(0x1112131415161718),
  .stream = UINT64_C(0x2122232425262728),
  .group = UINT64_C(0x3132333435363738),
  .data_seq = UINT64_C(0x4142434445464748),
  .total_len = 8192, .count = 2, .type = XDEV_EXT_XD_RTS,
  .tag = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
           0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
           0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7 },
 };
 return m;
}
static struct xdev_ext_xd_msg typed(__u8 type)
{
 struct xdev_ext_xd_msg m = rts();
 if (type != XDEV_EXT_XD_RTS) {
  m.total_len = 0; m.count = 0; m.data_seq = 0;
  memset(m.tag, 0, sizeof(m.tag));
 }
 m.type = type;
 if (type == XDEV_EXT_XD_CTS || type == XDEV_EXT_XD_ACK || type == XDEV_EXT_XD_HELD)
  m.credit = 99;
 if (type == XDEV_EXT_XD_FAIL) m.status = EIO;
 return m;
}
static void same_msg(const struct xdev_ext_xd_msg *a, const struct xdev_ext_xd_msg *b)
{
 EQ("src incarnation", a->src_inc, b->src_inc);
 EQ("dst incarnation", a->dst_inc, b->dst_inc);
 EQ("stream", a->stream, b->stream);
 EQ("group", a->group, b->group);
 EQ("credit", a->credit, b->credit);
 EQ("sequence", a->data_seq, b->data_seq);
 EQ("total length", a->total_len, b->total_len);
 EQ("count", a->count, b->count);
 EQ("status", a->status, b->status);
 EQ("type", a->type, b->type);
 EQ("channel", a->channel, b->channel);
 bytes_eq("opaque tag", a->tag, b->tag, 24);
}
/* Recompute only the input CRC to expose semantic validation after transport
 * integrity succeeds. Expected semantic answers are literal requirements. */
static void repair_crc(__u8 b[128])
{
 __u32 c = ~crc_bitwise(~0U, b, 124);
 b[124] = (__u8)c; b[125] = (__u8)(c >> 8);
 b[126] = (__u8)(c >> 16); b[127] = (__u8)(c >> 24);
}
static void wire_tests(void)
{
 struct xdev_ext_xd_msg m = rts(), got;
 __u8 b[128], bad[128];
 unsigned int type, bit, i;
 EQ("standard CRC32C vector", (__u32)~crc_bitwise(~0U, "123456789", 9), UINT32_C(0xe3069283));
 EQ("literal wire CRC", (__u32)~crc_bitwise(~0U, literal_rts, 124), UINT32_C(0xe295afdf));
 EQ("literal encode", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
 bytes_eq("literal LE field positions and full reserved padding", b, literal_rts, 128);
 memset(&got, 0xa5, sizeof(got));
 EQ("literal decode", xdev_ext_xd_msg_decode(literal_rts, 128, crc_bitwise, &got), 0);
 same_msg(&m, &got);
 for (type = 1; type <= 6; type++) {
  m = typed((__u8)type);
  EQ("each type encode", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
  bytes_eq("independent literal vector for each control type", b,
           type == 1 ? literal_rts : literal_nonrts[type - 2], 128);
  memset(&got, 0xa5, sizeof(got));
  EQ("each type decode", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), 0);
  same_msg(&m, &got);
  for (bit = 0; bit < 1024; bit++) {
   int ret;
   memcpy(bad, b, 128); bad[bit / 8] ^= (__u8)(1U << (bit % 8));
   ret = xdev_ext_xd_msg_decode(bad, 128, crc_bitwise, &got);
   if (bit < 40 || bit >= 992)
    EQ("single-bit header/CRC corruption", ret, -EBADMSG);
   else EQ("single-bit corruption never accepted", ret == -EBADMSG || ret == -EPROTO, 1);
  }
 }
 for (i = 0; i < 128; i++)
  EQ("all short control lengths", xdev_ext_xd_msg_decode(literal_rts, i, crc_bitwise, &got), -EBADMSG);
 /* Unknown type, invalid layout and nonzero reserved padding with valid CRC. */
 memcpy(b, literal_rts, 128); b[5] = 7; repair_crc(b);
 EQ("unknown type semantic rejection", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), -EPROTO);
 memcpy(b, literal_rts, 128); b[40] = 1; repair_crc(b);
 EQ("RTS credit semantic rejection", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), -EPROTO);
 for (i = 88; i < 124; i++) {
  memcpy(b, literal_rts, 128); b[i] = 1; repair_crc(b);
  EQ("reserved byte semantic rejection", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), -EPROTO);
 }
 memcpy(b, literal_rts, 128); b[7] = 1; repair_crc(b);
 EQ("unsupported flags", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), -EBADMSG);
 memcpy(b, literal_rts, 128); b[4] = 2; repair_crc(b);
 EQ("unsupported version", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), -EBADMSG);
 {
  static const struct { unsigned int type, off; __u8 value; } invalid[] = {
   {1,40,1}, {1,48,0}, {1,52,0}, {1,52,65}, {1,54,5},
   {2,40,0}, {2,48,1}, {2,52,1}, {2,54,5}, {2,56,1}, {2,64,1},
   {3,40,0}, {3,48,1}, {3,52,1}, {3,54,5}, {3,56,1}, {3,87,1},
   {4,40,0}, {4,48,1}, {4,52,1}, {4,54,5}, {4,56,1}, {4,64,1},
   {5,54,0}, {5,48,1}, {5,52,1}, {5,56,1}, {5,87,1},
   {6,40,1}, {6,48,1}, {6,52,1}, {6,54,5}, {6,56,1}, {6,64,1},
  };
  for (i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
   const __u8 *source = invalid[i].type == 1 ? literal_rts : literal_nonrts[invalid[i].type - 2];
   memcpy(b, source, 128);
   if (invalid[i].type == 1 && invalid[i].off == 48)
    memset(b + 48, 0, 4); /* RTS nonzero total_len spans two bytes. */
   else b[invalid[i].off] = invalid[i].value;
   repair_crc(b);
   EQ("per-type decoder semantic rejection", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), -EPROTO);
  }
 }
 /* Sequence is opaque to X2 for RTS; consumption is X4, never invented here. */
 m = rts(); m.data_seq = UINT64_MAX;
 EQ("maximum sequence encodes without narrowing", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
 EQ("maximum sequence decodes", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), 0);
 EQ("maximum sequence preserved", got.data_seq == UINT64_MAX, 1);
 m = rts(); m.channel = 3;
 EQ("last negotiated channel encode", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
 EQ("channel occupies exact wire byte", b[6], 3);
 EQ("last negotiated channel decode", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), 0);
 same_msg(&m, &got);
 m = typed(XDEV_EXT_XD_FAIL); m.credit = UINT64_MAX;
 EQ("FAIL nonzero wide credit encode", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
 EQ("FAIL nonzero wide credit decode", xdev_ext_xd_msg_decode(b, 128, crc_bitwise, &got), 0);
 same_msg(&m, &got);
}
static void invalid_message_tests(void)
{
 struct xdev_ext_xd_msg m;
 __u8 b[128];
 unsigned int type;
#define BAD(label, statement) do { m = typed((__u8)type); statement; \
 EQ(label, xdev_ext_xd_msg_encode(b, &m, crc_bitwise), -EINVAL); } while (0)
 for (type = 1; type <= 6; type++) {
  BAD("zero group", m.group = 0);
  BAD("zero stream", m.stream = 0);
  if (type == 1) {
   BAD("RTS credit", m.credit = 1);
   BAD("RTS total length zero", m.total_len = 0);
   BAD("RTS count zero", m.count = 0);
   BAD("RTS count 65", m.count = 65);
   BAD("RTS status", m.status = EIO);
   m = typed(1); m.count = 64;
   EQ("RTS maximum count", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
  } else {
   BAD("non-RTS total length", m.total_len = 1);
   BAD("non-RTS count", m.count = 1);
   BAD("non-RTS sequence", m.data_seq = 1);
   BAD("non-RTS tag", m.tag[23] = 1);
   if (type == 5) {
    BAD("FAIL requires status", m.status = 0);
    m = typed(5); m.credit = 0;
    EQ("pre-CTS FAIL credit zero permitted", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
    m.credit = UINT64_MAX;
    EQ("FAIL any credit permitted", xdev_ext_xd_msg_encode(b, &m, crc_bitwise), 0);
   } else {
    BAD("non-FAIL status", m.status = EIO);
    if (type == 6) BAD("CANCEL credit", m.credit = 1);
    else BAD("CTS/ACK/HELD credit required", m.credit = 0);
   }
  }
 }
 type = 1;
 BAD("type zero", m.type = 0);
 BAD("unknown type", m.type = 255);
#undef BAD
}
static void identity_tests(void)
{
 struct xdev_ext_xd_msg m = rts();
 EQ("matching incarnation pair", xdev_ext_xd_msg_for_us(&m, m.dst_inc, m.src_inc, 1), 0);
 EQ("foreign destination", xdev_ext_xd_msg_for_us(&m, m.dst_inc + 1, m.src_inc, 1), -ESTALE);
 EQ("foreign source", xdev_ext_xd_msg_for_us(&m, m.dst_inc, m.src_inc + 1, 1), -ESTALE);
 EQ("zero local incarnation", xdev_ext_xd_msg_for_us(&m, 0, m.src_inc, 1), -ESTALE);
 EQ("zero remote incarnation", xdev_ext_xd_msg_for_us(&m, m.dst_inc, 0, 1), -ESTALE);
 EQ("no channels", xdev_ext_xd_msg_for_us(&m, m.dst_inc, m.src_inc, 0), -ESTALE);
 m.channel = 1;
 EQ("channel equals negotiated bound", xdev_ext_xd_msg_for_us(&m, m.dst_inc, m.src_inc, 1), -ESTALE);
 m.channel = 3;
 EQ("last wire channel", xdev_ext_xd_msg_for_us(&m, m.dst_inc, m.src_inc, 4), 0);
 m.channel = 4;
 EQ("channel exceeds wire maximum", xdev_ext_xd_msg_for_us(&m, m.dst_inc, m.src_inc, 4), -ESTALE);
}
static void rx_tests(void)
{
 static const struct { __u32 flags, size, want; int result; } v[] = {
  {0,0,4096,0}, {0,1000,1000,0}, {0,1000,4096,-EMSGSIZE},
  {1,0,4096,-EBADMSG}, {4,0,4096,-EOVERFLOW},
  {1|4,1000,4096,-EBADMSG}, {4,1000,4096,-EOVERFLOW},
  {0,4095,4096,-EMSGSIZE}, {0,1,1,0}, {0,0,4095,-EMSGSIZE},
 };
 unsigned int i;
 for (i = 0; i < sizeof(v)/sizeof(v[0]); i++)
  EQ("completed RX length/status classification", xdev_ext_xd_rx_frame(v[i].flags, v[i].size, v[i].want), v[i].result);
 /* Input is a normally completed ring_frame: canceled/no-callback UNKNOWN
  * cannot be manufactured by choosing flags or a successful size here. */
}
static void budget_layout_tests(void)
{
 static const struct { __u32 depth, elems, ring; bool result; } v[] = {
  {3,64,256,true}, {4,64,256,true}, {16,16,256,true}, {64,64,256,true},
  {64,64,2,true}, {65,1,256,false}, {64,65,256,false},
  {0,1,256,false}, {1,65,256,false},
  {1,0,256,false}, {1,1,0,false}, {1,1,1,false}, {1,1,2,true},
  {1,64,64,true}, {1,64,65,true}, {3,64,192,true}, {3,64,193,true},
  {255,1,256,false}, {256,1,256,false},
  {UINT32_MAX,64,UINT32_MAX,false}, {UINT32_MAX,1,UINT32_MAX,false},
  {UINT32_MAX-1,1,UINT32_MAX,false}, {UINT32_C(0x40000000),4,256,false},
 };
 static const struct { struct xdev_ext_mech_layout l; __u32 result; } l[] = {
  {{65536,0,65536,131072},32}, {{4096,0,4096,8192},2},
  {{8192,0,6000,12000},4}, {{4096,0,4096,4096},1},
  {{8192,0,4097,8194},4}, {{4096,0,4095,8190},2},
  {{0,0,0,0},0}, {{4096,0,0,4096},0}, {{4096,0,4096,0},0},
  {{UINT32_MAX,0,1,UINT32_MAX},UINT32_MAX},
  {{UINT32_MAX,0,4096,UINT32_MAX},1048576},
  {{UINT32_MAX,0,UINT32_MAX,UINT32_MAX},1048576},
  {{UINT32_MAX,0,UINT32_MAX-1,UINT32_MAX},2097152},
  {{UINT32_MAX,0,UINT32_C(0x80000000),UINT32_MAX},1048576},
 };
 unsigned int i;
 for (i = 0; i < sizeof(v)/sizeof(v[0]); i++)
  EQ("bounded software pending: depth<=64 elems<=64 ring>1", xdev_ext_xd_budget_ok(v[i].depth, v[i].elems, v[i].ring), v[i].result);
 for (i = 0; i < sizeof(l)/sizeof(l[0]); i++)
  EQ("layout bounds segment count", xdev_ext_xd_layout_elems(&l[i].l), l[i].result);
}
static struct xdev_ext_xd_login valid_login(void)
{
 struct xdev_ext_xd_login l = {
  .length_sn = 27, .type = XDEV_EXT_XD_LOGIN, .proto_version = 2,
  .channels = 1, .ctl_tx_path = 8, .data_tx_path = {8,9,10,11},
  .incarnation = UINT64_C(0x1020304050607080), .caps = XDEV_EXT_XD_CAP_E2E,
 };
 return l;
}
static void login_tests(void)
{
 struct xdev_ext_xd_login l;
 unsigned int i;
 EQ("LOGIN packet size", sizeof(l), 120);
 EQ("LOGIN response size", sizeof(struct xdev_ext_xd_login_response), 96);
 l = valid_login();
 EQ("valid v2 one-channel LOGIN", xdev_ext_xd_login_check(&l, 120, 1), 0);
 EQ("short LOGIN", xdev_ext_xd_login_check(&l, 119, 1), -EPROTO);
 EQ("long LOGIN", xdev_ext_xd_login_check(&l, 121, 1), -EPROTO);
#define BAD_LOGIN(label, statement) do { l = valid_login(); statement; \
 EQ(label, xdev_ext_xd_login_check(&l, 120, 1), -EPROTO); } while (0)
 BAD_LOGIN("wrong length words", l.length_sn = 26);
 BAD_LOGIN("type zero", l.type = 0);
 BAD_LOGIN("LOGOUT is not LOGIN", l.type = XDEV_EXT_XD_LOGOUT);
 BAD_LOGIN("response is not LOGIN", l.type = XDEV_EXT_XD_LOGIN_RESPONSE);
 BAD_LOGIN("legacy v1 cannot echo requester incarnation", l.proto_version = 1);
 BAD_LOGIN("zero channels", l.channels = 0);
 BAD_LOGIN("exceeds caller one-channel limit", l.channels = 2);
 BAD_LOGIN("zero incarnation", l.incarnation = 0);
 BAD_LOGIN("control HopID below floor", l.ctl_tx_path = 7);
 BAD_LOGIN("data HopID below floor", l.data_tx_path[0] = 7);
#undef BAD_LOGIN
 l = valid_login(); l.length_sn |= 3U << 27;
 EQ("length sequence bits do not alter low six length bits", xdev_ext_xd_login_check(&l, 120, 1), 0);
 l = valid_login(); l.channels = 4;
 EQ("maximum wire channels", xdev_ext_xd_login_check(&l, 120, 4), 0);
 for (i = 0; i < 4; i++) {
  l = valid_login(); l.channels = 4; l.data_tx_path[i] = 7;
  EQ("each negotiated data HopID checked", xdev_ext_xd_login_check(&l, 120, 4), -EPROTO);
 }
 l = valid_login(); l.channels = 5;
 EQ("exceeds caller four-channel limit", xdev_ext_xd_login_check(&l, 120, 4), -EPROTO);
 EQ("wire limit independent of caller bound", xdev_ext_xd_login_check(&l, 120, 5), -EPROTO);
 l = valid_login();
 EQ("zero offered maximum", xdev_ext_xd_login_check(&l, 120, 0), -EPROTO);
}
int main(void)
{
 wire_tests(); invalid_message_tests(); identity_tests(); rx_tests();
 budget_layout_tests(); login_tests();
 printf("%s 1 - XDOMAIN pure rules checks=%u failures=%u hardware=none\n",
        failures ? "not ok" : "ok", checks, failures);
 return failures ? 1 : 0;
}
#endif
