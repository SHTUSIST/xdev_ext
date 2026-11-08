/* SPDX-License-Identifier: GPL-2.0 */
/* OS/class services only; the recovery worker and UMEM decisions are actual. */
#define XDEV_EXT_MECH_MAX_FRAMES 32
#define XDEV_EXT_MECH_MAX_STAGES 4
#define XDEV_EXT_MECH_POOL_PEER 3
#define XDEV_EXT_MECH_U32_MAX UINT32_MAX
#define XDEV_EXT_MECH_U64_MAX UINT64_MAX
#define XDEV_EXT_PEER_EPOCH_NONE (~0ULL)
#define BIT(n) (1U << (n))
#define READ_ONCE(x) (x)
#ifndef WRITE_ONCE
#define WRITE_ONCE(x,v) ((x)=(v))
#endif
#define max(a,b) ((a)>(b)?(a):(b))
#define check_add_overflow(a,b,p) __builtin_add_overflow(a,b,p)
#define XDEV_EXT_MECH_CAS_U8(p,old,v) __atomic_compare_exchange_n(p,old,v,false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST)
#define pr_info(...) ((void)0)
#define INIT_LIST_HEAD(p) do {(p)->next=(p);(p)->prev=(p);}while(0)
#define list_empty(p) ((p)->next==(p))
#define list_first_entry(p,t,m) list_entry((p)->next,t,m)
#define list_del_init(p) do {list_del(p);INIT_LIST_HEAD(p);}while(0)
#define list_move_tail(p,h) do {list_del(p);list_add_tail(p,h);}while(0)
static int atomic_read(const atomic_t *a) { return atomic_load(&a->refs); }
struct file { int unused; };
struct work_struct { int unused; };
struct xdev_ext_peer_requester { struct mutex lock; u64 proven; };
/* ACTUAL_PEER */
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops {
    int (*evidence)(struct xdev_ext_mech_stage *);
    int (*evidence_release)(struct xdev_ext_mech_stage *);
    int (*unbind_checked)(struct xdev_ext_mech_stage *);
};
struct xdev_ext_mech_stage { const struct xdev_ext_mech_class_ops *cls; void *priv; };
struct xdev_ext_mech_batch {
    struct xdev_ext_mech_session *s;
    struct { u32 state, stage; bool native_sequester; } bs;
    struct xdev_ext_mech_batch *parent;
    u32 present, nr_frames, life_active;
    __u64 life_token[XDEV_EXT_MECH_MAX_FRAMES];
    bool producing, sequester;
    struct { bool active; } transform;
    struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_mech_session {
    spinlock_t lock;
    struct xdev_ext_mech_sess ss;
    atomic_t native_controls;
    struct list_head quarantine_node;
    u32 nr_stages, nr_bound, depth;
    struct xdev_ext_mech_stage st[XDEV_EXT_MECH_MAX_STAGES];
    struct xdev_ext_mech_pool pool;
    struct xdev_ext_mech_life *life;
    struct xdev_ext_mech_batch *batches;
    u8 *transform_owner;
    void *worker;
    u64 id;
    int last_err;
};
static LIST_HEAD(xdev_ext_mech_quarantined);
static DEFINE_MUTEX(xdev_ext_mech_quarantine_lock);
static struct xdev_ext_mech_quarantine xdev_ext_mech_parked;
static unsigned released_sessions, checked_unbinds;
static int unbind_error, release_error;
static struct xdev_ext_peer_requester requester = {
    .lock = { .native = PTHREAD_MUTEX_INITIALIZER },
};
/* A second real requester prevents a foreign proof from being equivalent
 * to a fixture with no proof anywhere. The class queries only st->priv. */
static struct xdev_ext_peer_requester other_requester = {
    .lock = { .native = PTHREAD_MUTEX_INITIALIZER },
};
static u64 submitted_epoch = 4;
static int class_evidence(struct xdev_ext_mech_stage *st)
{ return xdev_ext_peer_requester_evidence(st->priv, submitted_epoch); }
static int class_release(struct xdev_ext_mech_stage *st)
{ (void)st; return release_error; }
static int class_unbind(struct xdev_ext_mech_stage *st)
{ (void)st; checked_unbinds++; return unbind_error; }
static const struct xdev_ext_mech_class_ops ops = {
    .evidence = class_evidence, .evidence_release = class_release,
    .unbind_checked = class_unbind,
};
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *pool)
{ (void)pool; return NULL; }
static int xdev_ext_peer_file_drainable(struct file *file)
{ (void)file; abort(); }
/* The final destructor boundary: run its real checked-unbind and actual
 * provider release; do not reset lifecycle/custody in the fixture. */
static int xdev_ext_mech_unbind_checked(struct xdev_ext_mech_session *s);
static int xdev_ext_mech_session_release(struct xdev_ext_mech_session *s)
{
    int err = xdev_ext_mech_unbind_checked(s);
    if (err) return err;
    s->pool.ops->release(&s->pool);
    released_sessions++;
    return s->last_err;
}
/* ACTUAL_CORE */
