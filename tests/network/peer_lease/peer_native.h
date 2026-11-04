/* Only native map boundary. Real peer/fd acquire/release bodies follow. */
static const struct file_operations xdev_ext_peer_allocation_fops={1},xdev_ext_peer_authority_fops={2};
static struct xdev_ext_peer_mapping native_mapping;
static struct pci_dev requester_device={.id=17};
static int map_error,map_calls;
int xdev_ext_peer_map(struct xdev_ext_peer_region *r,struct pci_dev *peer,enum dma_data_direction dir,struct xdev_ext_peer_mapping **out){map_calls++;EQ(dir,DMA_BIDIRECTIONAL);if(map_error)return map_error;*out=&native_mapping;return 0;}
