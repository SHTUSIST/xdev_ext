/* SPDX-License-Identifier: GPL-2.0 */
/* Expected bytes were independently frozen from the accepted wire document.
 * Codec output never builds the expected packet or repairs negative fixtures. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xdev_ext_xdomain_probe_core.h"

static unsigned assertions, failures;
#define CHECK(condition, why) do { assertions++; if (!(condition)) { \
 fprintf(stderr, "PROBE_WIRE_ASSERT %s:%u: %s\n", __FILE__, __LINE__, why); \
 failures++; } } while (0)

/* External CRC boundary matches crc32c's non-inverting update contract.
 * Its public standard vector is checked separately before exercising codecs. */
static __u32 crc(__u32 value, const void *ptr, size_t length)
{
 const unsigned char *data = ptr;
 while (length--) {
  value ^= *data++;
  for (unsigned bit = 0; bit < 8; bit++)
   value = (value >> 1) ^ ((value & 1) ? 0x82f63b78U : 0);
 }
 return value;
}

static void repair_crc(unsigned char *data, unsigned length)
{
 __u32 value = ~crc(~0U, data, length - 4);
 for (unsigned byte = 0; byte < 4; byte++)
  data[length - 4 + byte] = value >> (8 * byte);
}

static int vector(const char *directory, const char *name, unsigned char *out,
                  unsigned length)
{
 char path[4096];
 snprintf(path, sizeof(path), "%s/%s.bin", directory, name);
 FILE *file = fopen(path, "rb");
 if (!file) return 2;
 size_t bytes = fread(out, 1, length, file);
 int extra = fgetc(file);
 fclose(file);
 return bytes == length && extra == EOF ? 0 : 2;
}

static struct xdev_ext_xd_probe_msg message(unsigned type, unsigned origin,
                                           int ready)
{
 struct xdev_ext_xd_probe_msg msg = {
  .src_inc = 0x0807060504030201ULL, .dst_inc = 0x1817161514131211ULL,
  .type = type, .channel = 0, .direction = 1, .origin = origin,
 };
 for (unsigned byte = 0; byte < 16; byte++) {
  msg.src_nonce[byte] = 0x21 + byte;
  msg.dst_nonce[byte] = ready ? 0 : 0x41 + byte;
 }
 return msg;
}

static void fields(const struct xdev_ext_xd_probe_msg *msg, unsigned type,
                    unsigned origin, int ready)
{
 CHECK(msg->src_inc == 0x0807060504030201ULL &&
       msg->dst_inc == 0x1817161514131211ULL, "literal little-endian incarnations");
 CHECK(msg->type == type && msg->channel == 0 && msg->direction == 1,
       "literal type/channel/sender direction");
 if (!ready && type <= 2) {
  /* Control messages have no origin field; checked only by data caller. */
  (void)origin;
 }
 for (unsigned byte = 0; byte < 16; byte++) {
  CHECK(msg->src_nonce[byte] == 0x21 + byte, "literal source nonce");
  CHECK(msg->dst_nonce[byte] == (ready ? 0 : 0x41 + byte), "literal destination nonce");
 }
}

static int control(const char *dir)
{
 unsigned char frozen[128], encoded[128], corrupt[128];
 struct xdev_ext_xd_probe_msg decoded;
 for (unsigned type = 1; type <= 2; type++) {
  if (vector(dir, type == 1 ? "ready" : "done", frozen, 128)) return 2;
  struct xdev_ext_xd_probe_msg msg = message(type, 0, type == 1);
  CHECK(xdev_ext_xd_probe_ctl_encode(encoded, &msg, crc) == 0, "encode valid control");
  CHECK(!memcmp(encoded, frozen, 128), "all 128 control bytes match independent frozen vector");
  CHECK(xdev_ext_xd_probe_ctl_decode(frozen, 128, crc, &decoded) == 0,
        "decode independently frozen control");
  fields(&decoded, type, 0, type == 1);
 }
 CHECK(xdev_ext_xd_probe_ctl_decode(frozen, 127, crc, &decoded) == -90,
       "short control is EMSGSIZE");
 CHECK(xdev_ext_xd_probe_ctl_decode(frozen, 129, crc, &decoded) == -90,
       "long control is EMSGSIZE before payload access");
 const unsigned bad_offsets[] = {64, 68, 123};
 for (unsigned i = 0; i < sizeof(bad_offsets) / sizeof(bad_offsets[0]); i++) {
  memcpy(corrupt, frozen, 128); corrupt[bad_offsets[i]] = 1; repair_crc(corrupt, 128);
  CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -71,
        "flags/reserved remain invalid with correct CRC");
 }
 memcpy(corrupt, frozen, 128); corrupt[4] = 2; repair_crc(corrupt, 128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -93,
       "unsupported startup version is EPROTONOSUPPORT");
 memcpy(corrupt, frozen, 128); corrupt[5] = 3; repair_crc(corrupt, 128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -71,
       "unknown startup control type is EPROTO");
 memcpy(corrupt, frozen, 128); corrupt[6] = 4; repair_crc(corrupt, 128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -71,
       "out-of-range channel is EPROTO");
 memcpy(corrupt, frozen, 128); corrupt[7] = 2; repair_crc(corrupt, 128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -71,
       "noncanonical direction is EPROTO");
 memcpy(corrupt, frozen, 128); corrupt[56] = 127; repair_crc(corrupt, 128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -71,
       "control cannot advertise another PING length");
 memcpy(corrupt, frozen, 128); corrupt[61] = 15; repair_crc(corrupt, 128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -71,
       "control cannot advertise another PONG length");
 memcpy(corrupt, frozen, 128); corrupt[125] ^= 1;
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -74,
       "control CRC corruption is EBADMSG");
 /* DONE fixture has dst_nonce; changing only type makes invalid READY. */
 memcpy(corrupt, frozen, 128); corrupt[5] = 1; repair_crc(corrupt, 128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt, 128, crc, &decoded) == -71,
       "READY must have zero destination nonce");
 memcpy(corrupt, frozen, 128); memset(corrupt+24,0,16); repair_crc(corrupt,128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt,128,crc,&decoded)==-74,
       "zero source nonce is a wrong nonce and must report EBADMSG");
 memcpy(corrupt, frozen, 128); memset(corrupt+40,0,16); repair_crc(corrupt,128);
 CHECK(xdev_ext_xd_probe_ctl_decode(corrupt,128,crc,&decoded)==-74,
       "DONE zero destination nonce is a wrong nonce and must report EBADMSG");
 return 0;
}

static int data(const char *dir)
{
 unsigned char frozen[4096], encoded[4096], corrupt[4096];
 struct xdev_ext_xd_probe_msg decoded;
 for (unsigned type = 1; type <= 2; type++) {
  unsigned length = type == 1 ? 128 : 4096;
  unsigned origin = type == 1 ? 1 : 0;
  if (vector(dir, type == 1 ? "ping" : "pong", frozen, length)) return 2;
  struct xdev_ext_xd_probe_msg msg = message(type, origin, 0);
  CHECK(xdev_ext_xd_probe_data_encode(encoded, length, &msg, crc) == 0, "encode valid data");
  CHECK(!memcmp(encoded, frozen, length), "all PING/PONG bytes match independent frozen vector");
  CHECK(xdev_ext_xd_probe_data_decode(frozen, length, crc, &decoded) == 0,
        "decode independently frozen data");
  fields(&decoded, type, origin, 0);
  CHECK(decoded.origin == origin, "challenge origin is literal direction");
  memcpy(corrupt, frozen, length); corrupt[64] ^= 1; repair_crc(corrupt, length);
  CHECK(xdev_ext_xd_probe_data_decode(corrupt, length, crc, &decoded) == -74,
        "pattern corruption with valid recomputed CRC is EBADMSG");
  memcpy(corrupt, frozen, length); corrupt[length-5] ^= 1; repair_crc(corrupt, length);
  CHECK(xdev_ext_xd_probe_data_decode(corrupt, length, crc, &decoded) == -74,
        "last pattern byte is checked independently of CRC");
  memcpy(corrupt, frozen, length); corrupt[length-1] ^= 1;
  CHECK(xdev_ext_xd_probe_data_decode(corrupt, length, crc, &decoded) == -74,
        "data CRC corruption is EBADMSG");
  memcpy(corrupt, frozen, length); corrupt[56] = 1-origin; repair_crc(corrupt, length);
  CHECK(xdev_ext_xd_probe_data_decode(corrupt, length, crc, &decoded) == -71,
        "challenge-origin reflection is EPROTO");
  memcpy(corrupt, frozen, length); corrupt[57] = 1; repair_crc(corrupt, length);
  CHECK(xdev_ext_xd_probe_data_decode(corrupt, length, crc, &decoded) == -71,
        "data reserved field is zero even with valid CRC");
  memcpy(corrupt, frozen, length); corrupt[4] = 2; repair_crc(corrupt, length);
  CHECK(xdev_ext_xd_probe_data_decode(corrupt, length, crc, &decoded) == -93,
        "unsupported data version is EPROTONOSUPPORT");
  CHECK(xdev_ext_xd_probe_data_decode(frozen, length-1, crc, &decoded) == -90,
        "short PING/PONG is EMSGSIZE");
 }
 if (vector(dir, "ping", frozen, 128)) return 2;
 CHECK(xdev_ext_xd_probe_data_decode(frozen, 129, crc, &decoded) == -90,
       "long PING is EMSGSIZE");
 if (vector(dir, "pong", corrupt, 4096)) return 2;
 /* Keep the PING origin valid, so only type/length incompatibility is under
  * test rather than depending on the validation order of two bad fields. */
 corrupt[5] = 1; corrupt[56] = 1; repair_crc(corrupt, 4096);
 CHECK(xdev_ext_xd_probe_data_decode(corrupt, 4096, crc, &decoded) == -90,
       "4096-byte PING cannot masquerade as PONG");
 return 0;
}

int main(int argc, char **argv)
{
 if (argc != 2) return 2;
 CHECK(~crc(~0U, "123456789", 9) == 0xe3069283U, "standard CRC32C check value");
 int setup = control(argv[1]) || data(argv[1]);
 if (setup) { fprintf(stderr, "PROBE_WIRE_SETUP_FAILURE: missing fixed vector\n"); return 2; }
 printf("PROBE_WIRE_ASSERTIONS %u failures=%u\n", assertions, failures);
 return failures ? 1 : 0;
}
