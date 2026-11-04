/* OS/native hardware API boundary. No storage submit/map/lease algorithm. */
enum req_op {REQ_OP_READ=0,REQ_OP_WRITE=1,REQ_OP_DRV_IN=34,REQ_OP_DRV_OUT=35};
#define REQ_FAILFAST_DRIVER 0x200U
#define NVME_CMD_SGL_ALL 0xc0U
#define NVME_REQ_CANCELLED 8U
#define RQF_QUIET 1U
#define RQF_DONTPREP 2U
#define NVME_IO_TIMEOUT 30
#define NVME_ADMIN_TIMEOUT 60
#define PAGE_SHIFT 12
#define offset_in_page(n) ((n)&4095)
#define __aligned(n) __attribute__((aligned(n)))
#define pr_warn(...) ((void)0)
#define pr_warn_once(...) ev('W')
#define MODULE_PARM_DESC(...)
#define module_param_cb(...)
#define XDEV_EXT_LEASE_MIN_SHIFT 12U
#define THIS_MODULE NULL
struct xdev_ext_mech_class_desc { unsigned boundary_unused; };
struct xdev_ext_rel_policy;
static const struct xdev_ext_mech_class_desc xdev_ext_mech_class_decls[16];
static int xdev_ext_mech_session_state(struct xdev_ext_mech_session *s){return s->state;}
static struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch *b){return b->stage;}
static unsigned blk_rq_bytes(struct request *r){return r->residual;}
static int blk_status_to_errno(int s){return s;}
static int nvme_is_write(struct nvme_command *c){return c->common.opcode&1;}
static unsigned claim_calls,publish_calls,complete_traces,release_calls,retire_calls;
static u64 claim_ticket,publish_ticket,complete_ticket;
static int claim_errno,published_status,completed_status;
static bool published_uncertain,early_complete,observe_done;
static int early_native_status,early_transport; static unsigned early_residual;
static unsigned lease_calls; static int lease_error,lease_error_at,lease_len_override=-1;
static u32 lease_max_bytes=4096; static u64 lease_dma[32],lease_offsets[32],lease_generations[32];
static u32 lease_lengths[32]; static enum dma_data_direction lease_directions[32];
static struct pci_dev *lease_requesters[32]; static struct file *lease_authorities[32];
static bool release_quiesced[32];static u64 released_tickets[32];static int release_error;
static bool trace_quiesced; static int trace_status; static unsigned trace_retired;
static bool page_fault; static unsigned copies_to,copies_from,allocated_op;
static unsigned char *publish_payload;static unsigned char published_first;
static struct file authority_file;static struct file *pool_authority=&authority_file;
static u64 pool_generation=5;
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p){(void)p;return pool_authority;}
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p){(void)p;return pool_generation;}
static int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *d,u64 g,u64 off,u32 len,enum dma_data_direction dir,struct xdev_ext_peer_fd_lease *l){
 unsigned i=lease_calls++;assert(i<32);ev('L');lease_authorities[i]=f;lease_requesters[i]=d;lease_generations[i]=g;lease_offsets[i]=off;lease_lengths[i]=len;lease_directions[i]=dir;
 if(lease_error && (!lease_error_at || lease_calls==(unsigned)lease_error_at))return lease_error;
 if(len>lease_max_bytes)return -ERANGE;
 l->file=f;l->lease.mapping=(void *)1;l->lease.ticket=100+i;l->lease.len=lease_len_override>=0?(u32)lease_len_override:len;l->lease.dma_address=lease_dma[i]?lease_dma[i]:0x100000+off;return 0;
}
static int xdev_ext_peer_release(void *vp,u64 ticket,bool q){
 typeof(((struct xdev_ext_peer_fd_lease *)0)->lease) *l=vp;unsigned i=release_calls++;assert(i<32);ev(q?'q':'u');release_quiesced[i]=q;released_tickets[i]=ticket;if(release_error)return release_error;l->mapping=NULL;return 0;
}
static void fput(struct file *f){(void)f;ev('f');}
struct xdev_ext_native_event {const char *phase,*origin;u32 class_id,bytes,aux;u64 cookie;bool accepted;int status;};
static bool trace_native_event_enabled(void){return true;}
static void trace_native_event(struct xdev_ext_native_event *e){ev('t');retire_calls++;trace_quiesced=e->accepted;trace_status=e->status;trace_retired=e->aux;}
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 t){(void)b;claim_calls++;claim_ticket=t;if(observe_done)ev('C');return claim_errno;}
static void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 t,int s){(void)b;complete_traces++;complete_ticket=t;completed_status=s;if(observe_done)ev('T');}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 t,int s,bool u){(void)b;publish_calls++;publish_ticket=t;published_status=s;published_uncertain=u;if(publish_payload)published_first=*publish_payload;if(observe_done)ev('P');}
typedef struct {long long value;} atomic64_t;
static long long atomic64_read(atomic64_t *v){return v->value;}
static void atomic64_inc(atomic64_t *v){v->value++;ev('c');}
struct kernel_param {int unused;};struct kernel_param_ops {int (*set)(const char *,const struct kernel_param *);int (*get)(char *,const struct kernel_param *);};
#define sysfs_emit snprintf_sysfs
static int snprintf_sysfs(char *b,const char *fmt,long long n){return snprintf(b,64,fmt,n);}
static struct page *alloc_page(int f){(void)f;return zalloc(sizeof(struct page));}
static void __free_page(struct page *p){free_mem(p);}
static void memcpy_to_page(struct page *p,u32 off,const void *src,u32 n){copies_to++;memcpy(p->bytes+off,src,n);ev('>');}
static void memcpy_from_page(void *dst,struct page *p,u32 off,u32 n){copies_from++;memcpy(dst,p->bytes+off,n);ev('<');}
static int xdev_ext_mech_class_register(const void *v){(void)v;return 0;}
static void xdev_ext_mech_class_unregister(const void *v){(void)v;}
