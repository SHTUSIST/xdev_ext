/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SHARED_RECEIVE_NATIVE_PACKETS_H
#define SHARED_RECEIVE_NATIVE_PACKETS_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "xdev_ext_xsk_shared.h"
#define NATIVE_PACKET_MAX 128U
static const unsigned char native_golden[60] = {
 0x02,0,0,0,0,2, 0x02,0,0,0,0,1, 0x08,0,
 0x45,0,0,0x2e,0x12,0x34,0,0,0x40,0x11,0x7c,0x54,
 0xc0,0,2,1,0xc6,0x33,0x64,2,0x30,0x39,0x7a,0x69,0,0x1a,0,0,
 0x12,0x34,0x56,0x78,1,2,3,4,5,6,7,8,9,10,11,12,13,14
};
static bool native_result_ok(unsigned action, const unsigned char *input, size_t input_len,
                             const unsigned char *output, size_t output_len)
{
    return action == 2 && input_len == output_len && !memcmp(input, output, input_len);
}
struct native_case {
    const char *name;
    unsigned char packet[NATIVE_PACKET_MAX];
    size_t length;
    bool flow_present;
    struct xdev_ext_xsk_shared_key key;
    struct xdev_ext_xsk_shared_flow flow;
};
#define NATIVE_CASES_MAX 48U
static void native_ip_checksum(unsigned char *packet)
{
    unsigned sum = 0;
    packet[24] = packet[25] = 0;
    for (unsigned i = 14; i < 34; i += 2) sum += ((unsigned)packet[i] << 8) | packet[i+1];
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    sum = (~sum) & 65535; packet[24] = sum >> 8; packet[25] = sum;
}
static size_t native_cases(struct native_case *cases)
{
    size_t n = 0;
#define ADD(label) do { \
    struct native_case *next = &cases[n++]; \
    *next = (struct native_case){.name=label,.length=60,.flow_present=true, \
        .key={.dst_ipv4=0xc6336402U,.payload_magic=0x12345678U,.dst_port=31337}, \
        .flow={.queue_id=0,.flags=XDEV_EXT_XSK_FILTER_F_DST_IPV4 | \
          XDEV_EXT_XSK_FILTER_F_DST_PORT | XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC}}; \
    memcpy(next->packet,native_golden,60); \
} while (0)
#define LAST cases[n-1]
    ADD("unknown-flow"); LAST.flow_present=false;
    ADD("missing-xsk");
    ADD("other-dst-ip"); LAST.packet[33]^=1; native_ip_checksum(LAST.packet);
    ADD("other-dst-port"); LAST.packet[37]^=1;
    ADD("other-magic"); LAST.packet[45]^=1;
    ADD("wrong-queue"); LAST.flow.queue_id=1;
    ADD("truncated-ethernet-only"); LAST.length=14;
    ADD("truncated-ip"); LAST.length=33;
    ADD("truncated-udp"); LAST.length=41;
    ADD("arp"); LAST.packet[13]=6;
    ADD("ipv6"); LAST.packet[12]=0x86; LAST.packet[13]=0xdd;
    ADD("vlan"); LAST.packet[12]=0x81; LAST.packet[13]=0;
    ADD("qinq"); LAST.packet[12]=0x88; LAST.packet[13]=0xa8;
    ADD("version-six"); LAST.packet[14]=0x65; native_ip_checksum(LAST.packet);
    ADD("ip-options"); LAST.packet[14]=0x46; native_ip_checksum(LAST.packet);
    ADD("ihl-too-small"); LAST.packet[14]=0x44; native_ip_checksum(LAST.packet);
    ADD("more-fragments"); LAST.packet[20]=0x20; native_ip_checksum(LAST.packet);
    ADD("fragment-offset"); LAST.packet[21]=1; native_ip_checksum(LAST.packet);
    ADD("non-udp"); LAST.packet[23]=6; native_ip_checksum(LAST.packet);
    ADD("ip-length-short"); LAST.packet[17]=19; native_ip_checksum(LAST.packet);
    ADD("ip-length-past-end"); LAST.packet[16]=LAST.packet[17]=0xff; native_ip_checksum(LAST.packet);
    ADD("udp-length-short"); LAST.packet[39]=7;
    ADD("udp-length-ip-disagrees"); LAST.packet[39]=25;
    ADD("udp-length-past-ip"); LAST.packet[39]=27;
    ADD("payload-three-bytes"); LAST.length=45; LAST.packet[17]=31; LAST.packet[39]=11; native_ip_checksum(LAST.packet);
    ADD("source-ip-match"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_IPV4; LAST.flow.src_ipv4=0xc0000201U;
    ADD("source-ip-miss"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_IPV4; LAST.flow.src_ipv4=0xc0000202U;
    ADD("source-port-match"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_PORT; LAST.flow.src_port=12345;
    ADD("source-port-miss"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_PORT; LAST.flow.src_port=12346;
    ADD("dest-mac-match"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_DST_MAC; memcpy(LAST.flow.dst_mac,native_golden,6);
    ADD("dest-mac-miss"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_DST_MAC; memcpy(LAST.flow.dst_mac,native_golden,6); LAST.flow.dst_mac[5]^=1;
    ADD("max-len-equal"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_MAX_LEN; LAST.flow.max_len=60;
    ADD("max-len-too-small"); LAST.flow.flags|=XDEV_EXT_XSK_FILTER_F_MAX_LEN; LAST.flow.max_len=59;
    ADD("all-optional-match"); LAST.flow.flags=XDEV_EXT_XSK_FILTER_F_KNOWN; LAST.flow.src_ipv4=0xc0000201U; LAST.flow.src_port=12345; LAST.flow.max_len=60; memcpy(LAST.flow.dst_mac,native_golden,6);
    ADD("all-optional-miss"); LAST.flow.flags=XDEV_EXT_XSK_FILTER_F_KNOWN; LAST.flow.src_ipv4=0xc0000202U; LAST.flow.src_port=12346; LAST.flow.max_len=59; memcpy(LAST.flow.dst_mac,native_golden,6); LAST.flow.dst_mac[5]^=1;
    ADD("literal-zero-key-match"); LAST.key.dst_ipv4=LAST.key.payload_magic=0; memset(LAST.packet+30,0,4); memset(LAST.packet+42,0,4); native_ip_checksum(LAST.packet);
    ADD("literal-zero-key-other-packet"); LAST.key.dst_ipv4=LAST.key.payload_magic=0;
#undef LAST
#undef ADD
    return n;
}
#endif
