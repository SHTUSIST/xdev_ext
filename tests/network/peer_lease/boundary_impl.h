/* Recording at actual public peer/fd entry, without replacing ownership logic. */
static struct {struct file *file;struct pci_dev *peer;u64 generation,off;u32 len;enum dma_data_direction dir;struct xdev_ext_peer_fd_lease *handle;} acquire_log[128];
static unsigned acquire_calls,release_calls;static bool release_quiesced[128];static struct xdev_ext_peer_fd_lease *release_handle[128];
static int observed_acquire(struct file *f,struct pci_dev *p,u64 gen,u64 off,u32 len,enum dma_data_direction dir,struct xdev_ext_peer_fd_lease *handle){unsigned i=acquire_calls++;assert(i<128);acquire_log[i]=(typeof(acquire_log[0])){f,p,gen,off,len,dir,handle};return xdev_ext_peer_file_acquire(f,p,gen,off,len,dir,handle);}
static void observed_release(struct xdev_ext_peer_fd_lease *h,bool q){unsigned i=release_calls++;assert(i<128);release_handle[i]=h;release_quiesced[i]=q;xdev_ext_peer_fd_release(h,q);}
#define xdev_ext_peer_file_acquire observed_acquire
#define xdev_ext_peer_fd_release observed_release
static int xdev_ext_requester_bind(struct xdev_ext_requester *r,struct xdev_ext_mech_stage *s,struct pci_dev *p,u32 flags){return 0;}static void xdev_ext_requester_unbind(struct xdev_ext_requester *r){}
/* PEER cohort: no requester here maps IOU_UMEM host pages, so the family's host leases are unreachable. */
static int xdev_ext_requester_host_lease(struct xdev_ext_requester *r,u64 off,u32 len,enum dma_data_direction dir,u64 *dma){abort();}
static void xdev_ext_requester_host_release(struct xdev_ext_requester *r,u64 dma,u32 len,bool quiesced){abort();}
static int xdev_ext_requester_bind_host(struct xdev_ext_requester *r,struct xdev_ext_mech_stage *s,struct pci_dev *p){abort();}
static void xdev_ext_requester_unbind_host(struct xdev_ext_requester *r){abort();}
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_dir(u32 a,u32 b,bool c,void(*dead)(void *),void *arg){return (void *)0x101;}
void xdev_ext_peer_net_unbind(struct xdev_ext_peer_net_endpoint *p){}
static unsigned requester_calls;
struct pci_dev *xdev_ext_peer_net_peer(struct xdev_ext_peer_net_endpoint *p){requester_calls++;return &requester_device;}
u32 xdev_ext_peer_net_mtu(struct xdev_ext_peer_net_endpoint *p){return 1500;}
int xdev_ext_peer_net_rx_flush(struct xdev_ext_peer_net_endpoint *p){return 0;}
static int native_post_error,native_inline,native_status;static bool native_quiesced=true;static unsigned native_calls,native_returns;
static struct xdev_ext_net_slot **expected_slotp;static bool native_slot_visible;
static struct xdev_ext_mech_batch *observed_batch;static unsigned inline_publishes_seen;
static struct xdev_ext_peer_tx *tx_chain;static struct xdev_ext_peer_rx *rx_chain;
int xdev_ext_peer_net_post_tx(struct xdev_ext_peer_net_endpoint *p,struct xdev_ext_peer_tx *first){native_calls++;tx_chain=first;if(expected_slotp)native_slot_visible=*expected_slotp && container_of((void *)first,struct xdev_ext_net_elem,dev)->slot==*expected_slotp;if(native_post_error)return native_post_error;if(native_inline)for(struct xdev_ext_peer_tx *x=first;x;x=x->next)x->complete(x,native_status,native_quiesced);if(observed_batch)inline_publishes_seen=observed_batch->publishes;native_returns++;return 0;}
int xdev_ext_peer_net_post_rx(struct xdev_ext_peer_net_endpoint *p,struct xdev_ext_peer_rx *first){native_calls++;rx_chain=first;if(expected_slotp)native_slot_visible=*expected_slotp && container_of((void *)first,struct xdev_ext_net_elem,dev)->slot==*expected_slotp;if(native_post_error)return native_post_error;if(native_inline)for(struct xdev_ext_peer_rx *x=first;x;x=x->next)x->complete(x,native_status,x->header_room,x->len,native_quiesced);if(observed_batch)inline_publishes_seen=observed_batch->publishes;native_returns++;return 0;}
