/* SPDX-License-Identifier: GPL-2.0 */
/* Linux 89be9a83ccf1f88522317ce02f854f30d6115c41, v6.16-rc7.
 * The complete DMA direction enum is from include/linux/dma-direction.h.
 * PCI structs below are explicit field projections from include/linux/pci.h,
 * not native layout/ABI declarations. The existing host device boundary is
 * borrowed. Its dev member stays first for the existing to_pci_dev shim.
 * Canonical consumers require their selected matching Linux dependency lock;
 * complete native roots must derive these facts from their own headers.
 */
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

struct pci_bus {
	unsigned char	number;		/* Bus number */
};

struct pci_dev {
	struct device	dev;			/* Generic device interface */
	struct pci_bus	*bus;		/* Bus this device is on */
	unsigned int	devfn;		/* Encoded device & function index */
	unsigned int	untrusted:1;
};
