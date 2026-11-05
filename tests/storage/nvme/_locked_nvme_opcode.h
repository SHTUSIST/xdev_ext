/* SPDX-License-Identifier: GPL-2.0 */
/* Whole enum nvme_opcode, copied byte-for-byte from include/linux/nvme.h,
 * Linux 89be9a83ccf1f88522317ce02f854f30d6115c41 (v6.16-rc7).
 * Public host-fixture type fact only; not a production NVMe header.
 * Canonical consumers must match their selected Linux lock. Native trees
 * must use their own include/linux/nvme.h and never this fixture dependency.
 */
enum nvme_opcode {
	nvme_cmd_flush		= 0x00,
	nvme_cmd_write		= 0x01,
	nvme_cmd_read		= 0x02,
	nvme_cmd_write_uncor	= 0x04,
	nvme_cmd_compare	= 0x05,
	nvme_cmd_write_zeroes	= 0x08,
	nvme_cmd_dsm		= 0x09,
	nvme_cmd_verify		= 0x0c,
	nvme_cmd_resv_register	= 0x0d,
	nvme_cmd_resv_report	= 0x0e,
	nvme_cmd_resv_acquire	= 0x11,
	nvme_cmd_io_mgmt_recv	= 0x12,
	nvme_cmd_resv_release	= 0x15,
	nvme_cmd_zone_mgmt_send	= 0x79,
	nvme_cmd_zone_mgmt_recv	= 0x7a,
	nvme_cmd_zone_append	= 0x7d,
	nvme_cmd_vendor_start	= 0x80,
};
