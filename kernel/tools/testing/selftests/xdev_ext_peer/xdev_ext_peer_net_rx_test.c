// SPDX-License-Identifier: GPL-2.0
/* NIC receive into device memory (requirement P3): per-device capability,
 * RX buffer admission and completion classification. Pure rules; no NIC.
 */
#include <stdio.h>
#include <stdbool.h>
#include "../../../../io_uring/xdev_ext_peer_net_core.h"
#ifndef XDEV_EXT_PEER_NET_RX
int main(void)
{
 puts("not ok 1 - per-device NET capability (TX/RX hooks) missing; RX bind cannot be refused by device capability");
 puts("not ok 2 - peer RX buffer admission (xdev_ext_peer_net_rx_check) missing");
 puts("not ok 3 - peer RX completion classification (xdev_ext_peer_net_rx_result) missing");
 return 1;
}
#else
static int failures;
#define CHECK(c, text) do { if (!(c)) { printf("not ok - %s (line %d)\n", text, __LINE__); failures++; } } while (0)
int main(void)
{
 bool seq = false;
 int before;
 /* 1. Capability is declared by the device's hooks, once per direction. */
 CHECK(xdev_ext_peer_net_caps(true, true, false, false) == XDEV_EXT_PEER_NET_CAP_TX, "TX-only device (ice today) declares TX");
 CHECK(xdev_ext_peer_net_caps(true, true, true, true) == (XDEV_EXT_PEER_NET_CAP_TX | XDEV_EXT_PEER_NET_CAP_RX), "TX+RX device declares both");
 CHECK(xdev_ext_peer_net_caps(true, false, true, true) == XDEV_EXT_PEER_NET_CAP_RX, "RX-only device declares RX");
 CHECK(xdev_ext_peer_net_caps(true, true, true, false) == XDEV_EXT_PEER_NET_CAP_TX, "RX without flush is not an RX capability (STOP could not reclaim posted buffers)");
 CHECK(xdev_ext_peer_net_caps(false, true, true, true) == 0, "no peer device hook: no capability");
 CHECK(XDEV_EXT_PEER_NET_CAP_TX != XDEV_EXT_PEER_NET_CAP_RX && XDEV_EXT_PEER_NET_CAP_TX && XDEV_EXT_PEER_NET_CAP_RX, "distinct capability bits");
 CHECK(!xdev_ext_peer_net_cap_check(XDEV_EXT_PEER_NET_CAP_TX, false), "TX bind on TX device");
 CHECK(xdev_ext_peer_net_cap_check(XDEV_EXT_PEER_NET_CAP_TX, true) == -EOPNOTSUPP, "RX bind on TX-only device keeps -EOPNOTSUPP");
 CHECK(xdev_ext_peer_net_cap_check(XDEV_EXT_PEER_NET_CAP_RX, false) == -EOPNOTSUPP, "TX bind on RX-only device refused");
 CHECK(!xdev_ext_peer_net_cap_check(XDEV_EXT_PEER_NET_CAP_TX | XDEV_EXT_PEER_NET_CAP_RX, true), "RX bind on TX+RX device");
 CHECK(xdev_ext_peer_net_cap_check(0, true) == -EOPNOTSUPP && xdev_ext_peer_net_cap_check(0, false) == -EOPNOTSUPP, "no hook: both refused");
 if (!failures) puts("ok 1 - NET peer capability comes from the device hooks, one bit per direction");
 /* 2. RX buffers: header slot 14..128 on the host, a full-size packet fits the frame. */
 before = failures;
 CHECK(!xdev_ext_peer_net_rx_check(1500, 42, 1472, 0), "UDP/IPv4 split: 42-byte header slot, 1472-byte frame room");
 CHECK(!xdev_ext_peer_net_rx_check(1500, 14, 65536, 0), "Ethernet-only header slot into a 64 KiB frame");
 CHECK(!xdev_ext_peer_net_rx_check(9000, 128, 8886, 0), "jumbo MTU with the largest header slot");
 CHECK(xdev_ext_peer_net_rx_check(1500, 42, 1471, 0) == -EMSGSIZE, "frame one byte short of a full-size packet refused");
 CHECK(xdev_ext_peer_net_rx_check(1500, 13, 4096, 0) == -EINVAL, "header slot below an Ethernet header refused");
 CHECK(xdev_ext_peer_net_rx_check(1500, 129, 4096, 0) == -EINVAL, "header slot above 128 bytes refused");
 CHECK(xdev_ext_peer_net_rx_check(1500, 42, 0, 0) == -EINVAL, "empty frame refused");
 CHECK(xdev_ext_peer_net_rx_check(65536, 42, 1u << 20, 0) == -EMSGSIZE, "MTU above 65535 refused");
 CHECK(xdev_ext_peer_net_rx_check(100, 128, 4096, 0) == -EMSGSIZE, "header slot larger than a full packet refused");
 CHECK(xdev_ext_peer_net_rx_check(1500, 42, 4096, 1) == -EOPNOTSUPP, "unknown RX flags refused");
 CHECK(xdev_ext_peer_net_check(1500, 82, 1024, 0) == 0 && xdev_ext_peer_net_check(1500, 82, 1024, 1) == -EOPNOTSUPP, "TX admission unchanged");
 if (failures == before) puts("ok 2 - RX buffer admission: host header slot, peer frame holds any packet up to MTU");
 /* 3. Completion: only a quiesced, consistent completion is reusable. */
 before = failures;
 seq = true; CHECK(xdev_ext_peer_net_rx_result(0, true, 42, 42, 1472, 1472, &seq) == 0 && !seq, "full packet: header slot plus payload in frame");
 seq = true; CHECK(xdev_ext_peer_net_rx_result(0, true, 42, 42, 0, 1472, &seq) == 0 && !seq, "header-only packet");
 seq = true; CHECK(xdev_ext_peer_net_rx_result(0, true, 42, 30, 0, 1472, &seq) == 0 && !seq, "runt packet shorter than the header slot");
 seq = false; CHECK(xdev_ext_peer_net_rx_result(0, false, 42, 42, 100, 1472, &seq) == -EIO && seq, "zero status without quiescence fails closed and sequesters");
 seq = false; CHECK(xdev_ext_peer_net_rx_result(-ECANCELED, false, 42, 0, 0, 1472, &seq) == -ECANCELED && seq, "unquiesced flush sequesters");
 seq = true; CHECK(xdev_ext_peer_net_rx_result(-ECANCELED, true, 42, 0, 0, 1472, &seq) == -ECANCELED && !seq, "quiesced flush is a clean error");
 seq = true; CHECK(xdev_ext_peer_net_rx_result(-EMSGSIZE, true, 42, 42, 1472, 1472, &seq) == -EMSGSIZE && !seq, "bounded truncation is a clean error");
 seq = false; CHECK(xdev_ext_peer_net_rx_result(0, true, 42, 43, 10, 1472, &seq) == -EPROTO && seq, "header beyond the slot: impossible placement sequesters");
 seq = false; CHECK(xdev_ext_peer_net_rx_result(0, true, 42, 42, 1473, 1472, &seq) == -EPROTO && seq, "payload beyond the frame sequesters");
 seq = false; CHECK(xdev_ext_peer_net_rx_result(0, true, 42, 20, 10, 1472, &seq) == -EPROTO && seq, "payload with a short header: placement inconsistent");
 if (failures == before) puts("ok 3 - RX completion: reusable only when quiesced and consistent; otherwise errno with sequester decision");
 return failures ? 1 : 0;
}
#endif
