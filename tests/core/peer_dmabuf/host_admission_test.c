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

static unsigned failures, cases;

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
	printf("%u cases, %u failures\n", cases, failures);
	return failures ? 1 : 0;
}
