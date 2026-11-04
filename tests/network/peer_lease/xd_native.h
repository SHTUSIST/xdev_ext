/* Bounded native link/ring envelope, not a replica of XDomain protocol state. */
struct tb_ring{int id;};struct delayed_work{int unused;};
struct xdev_ext_xd_link{spinlock_t lock;bool up,going_away,suspended,gone,nhi_gone,poll_completions,poll_live;u64 poll_wake;struct delayed_work poll_work;u32 data_verified_mask;struct {struct tb_ring *tx,*rx;}chan[2];};
struct xdev_ext_xd_ep{struct xdev_ext_xd_link *xl;u32 chan;bool detached;};
static void *system_long_wq;static void mod_delayed_work(void *wq,struct delayed_work *w,unsigned delay){}
#define BIT(n) (1U<<(n))
#define WARN_ON_ONCE(x) ((void)(x))
static struct ring_frame *ring_log[64];static unsigned ring_calls,ring_notifies;
static int tb_ring_tx_more(struct tb_ring *r,struct ring_frame *f){ring_log[ring_calls++]=f;return 0;}
static int tb_ring_rx_more(struct tb_ring *r,struct ring_frame *f){ring_log[ring_calls++]=f;return 0;}
static void tb_ring_notify(struct tb_ring *r){ring_notifies++;}
