// SPDX-License-Identifier: GPL-2.0
/* Requirement: certified ordinary host dma-bufs have a separate admission
 * policy, without a fabricated BAR owner/topology. This executes the real
 * shared admission rule; coherent/no-bounce mapping certification belongs
 * to importer tests, not this pure-rule test.
 * Break caught: treating all STRUCT_PAGE backing as BAR-only or letting an
 * admin override accept unknown, raw, external or untrusted host backing.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "include/linux/xdev_ext_requester_core.h"

/* Contract value, so the pre-feature rule compiles and gives a behavioral RED.
 * This does not supply an implementation or a substitute admission function. */
#ifndef XDEV_EXT_PEER_BACKING_HOST_SYSTEM
#define XDEV_EXT_PEER_BACKING_HOST_SYSTEM (1U << 5)
#endif
/* Prototype for ASK.70: an exporter that gave no backing facts. */
#ifndef XDEV_EXT_PEER_BACKING_UNDESCRIBED
#define XDEV_EXT_PEER_BACKING_UNDESCRIBED (1U << 6)
#endif

static unsigned failures, cases;

/* Same as check(), and the admitted requester's reachability must be exactly
 * the expected state (an undescribed backing never claims a topology). */
static void check_reach(const char *name, struct xdev_ext_admit_facts f,
			unsigned flags, int wanted, unsigned required_refusal,
			unsigned reachability)
{
	struct xdev_ext_admission out = {0};
	int actual = xdev_ext_admit_decide(&f, flags, &out);
	bool ok = actual == wanted && out.backing == f.backing &&
		  out.reachability == reachability && out.distance == f.distance;

	if (wanted == 0)
		ok = ok && out.refused == 0;
	else
		ok = ok && (out.refused & required_refusal) == required_refusal;
	cases++;
	if (!ok) {
		failures++;
		fprintf(stderr, "not ok %u - %s: errno=%d wanted=%d refused=%#x required=%#x reach=%u wanted=%u\n",
			cases, name, actual, wanted, out.refused, required_refusal,
			out.reachability, reachability);
	} else {
		printf("ok %u - %s\n", cases, name);
	}
}

static void check(const char *name, struct xdev_ext_admit_facts f,
		  unsigned flags, int wanted, unsigned required_refusal)
{
	struct xdev_ext_admission out = {0};
	int actual = xdev_ext_admit_decide(&f, flags, &out);
	bool ok = actual == wanted && out.backing == f.backing;

	if (wanted == 0)
		ok = ok && out.refused == 0;
	else
		ok = ok && (out.refused & required_refusal) == required_refusal;
	cases++;
	if (!ok) {
		failures++;
		fprintf(stderr, "not ok %u - %s: errno=%d wanted=%d refused=%#x required=%#x\n",
			cases, name, actual, wanted, out.refused, required_refusal);
	} else {
		printf("ok %u - %s\n", cases, name);
	}
}

int main(void)
{
	const unsigned host = XDEV_EXT_PEER_BACKING_HOST_SYSTEM |
		XDEV_EXT_PEER_BACKING_STRUCT_PAGE;
	const unsigned override = XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED;
	struct xdev_ext_admit_facts f = {.distance = -1, .backing = host};

	check("certified ordinary host RAM needs no fictitious PCI owner", f, 0, 0, 0);
	f.dma_iommu = true;
	f.dma_ops = true;
	check("host DMA-API addresses may cross an IOMMU", f, 0, 0, 0);
	f.admin = true;
	check("host admission does not need a topology override", f, override, 0, 0);
	f.backing = XDEV_EXT_PEER_BACKING_STRUCT_PAGE;
	check("unknown struct-page exporter remains refused", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_BACKING);
	f.backing = XDEV_EXT_PEER_BACKING_HOST_SYSTEM;
	check("host certificate alone is not ordinary struct-page RAM", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_BACKING);
	f.backing = host | XDEV_EXT_PEER_BACKING_MMIO_BAR;
	check("host RAM cannot also claim BAR backing", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_BACKING);
	f.backing = host | XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR;
	check("raw host address cannot bypass the DMA API", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_IOMMU_RAW_ADDR);
	f.backing = host | XDEV_EXT_PEER_BACKING_COHERENT_C2C;
	check("coherent device aperture is not certified host RAM", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_BACKING);
	f.backing = host | XDEV_EXT_PEER_BACKING_EXTERNAL;
	check("host admission cannot bless external ownership", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_EXTERNAL_OWNER);
	f.backing = host | (1U << 31);
	check("unknown backing flags fail closed", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_BACKING);
	f.backing = host;
	f.untrusted = true;
	check("admin cannot override an untrusted requester", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_UNTRUSTED);
	f.untrusted = false;
	f.swiotlb_force = true;
	check("admin cannot override forced bounce", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_SWIOTLB_FORCE);
	f = (struct xdev_ext_admit_facts){.distance = 0, .owner_known = true,
		.backing = XDEV_EXT_PEER_BACKING_MMIO_BAR};
	check("existing discrete BAR path is preserved", f, 0, 0, 0);
	f.backing |= XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR;
	f.dma_iommu = true;
	check("existing raw BAR plus IOMMU remains refused", f, 0, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_IOMMU_RAW_ADDR);
	f.dma_iommu = false;
	f.backing = XDEV_EXT_PEER_BACKING_MMIO_BAR;
	f.owner_known = false;
	f.admin = true;
	check("host policy cannot admit an ownerless BAR", f, override, -EXDEV,
	      XDEV_EXT_PEER_REFUSE_BACKING);
	/* Prototype for ASK.70: undescribed exporter memory. The exporter's own
	 * per-device mapping is the only fact; no owner, topology or host claim. */
	{
		const unsigned und = XDEV_EXT_PEER_BACKING_UNDESCRIBED;
		f = (struct xdev_ext_admit_facts){.distance = -1, .backing = und};
		check_reach("undescribed exporter admitted with unknown reachability", f, 0, 0, 0,
			    XDEV_EXT_CAP_UNKNOWN);
		f.dma_iommu = true;
		f.dma_ops = true;
		check_reach("undescribed DMA-API mapping may cross an IOMMU", f, 0, 0, 0,
			    XDEV_EXT_CAP_UNKNOWN);
		f.admin = true;
		check_reach("admin override never turns undescribed into a topology claim", f,
			    override, 0, 0, XDEV_EXT_CAP_UNKNOWN);
		f = (struct xdev_ext_admit_facts){.distance = -1, .backing = und, .untrusted = true,
			.admin = true};
		check("undescribed cannot admit an untrusted requester", f, override, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_UNTRUSTED);
		f.untrusted = false;
		f.swiotlb_force = true;
		check("undescribed cannot admit forced bounce", f, override, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_SWIOTLB_FORCE);
		f.swiotlb_force = false;
		f.backing = und | host;
		check("undescribed cannot also claim certified host RAM", f, override, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_BACKING);
		f.backing = und | XDEV_EXT_PEER_BACKING_STRUCT_PAGE;
		check("undescribed cannot also claim struct pages", f, override, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_BACKING);
		f = (struct xdev_ext_admit_facts){.distance = 0, .owner_known = true,
			.backing = und | XDEV_EXT_PEER_BACKING_MMIO_BAR};
		check("undescribed cannot also claim a BAR with a topology", f, 0, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_BACKING);
		f = (struct xdev_ext_admit_facts){.distance = -1, .dma_iommu = true,
			.backing = und | XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR};
		check("undescribed raw bus address cannot cross the IOMMU", f, 0, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_IOMMU_RAW_ADDR | XDEV_EXT_PEER_REFUSE_BACKING);
		f = (struct xdev_ext_admit_facts){.distance = -1,
			.backing = und | XDEV_EXT_PEER_BACKING_EXTERNAL};
		check("undescribed cannot bless external ownership", f, 0, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_EXTERNAL_OWNER | XDEV_EXT_PEER_REFUSE_BACKING);
		f.backing = und | (1U << 31);
		check("undescribed with unknown flags fails closed", f, 0, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_BACKING);
		f = (struct xdev_ext_admit_facts){.distance = -1, .backing = 0};
		check("no backing facts at all remains refused", f, override, -EXDEV,
		      XDEV_EXT_PEER_REFUSE_BACKING);
	}
	printf("%u cases, %u failures\n", cases, failures);
	return failures ? 1 : 0;
}
