struct xdev_ext_mech_session {u32 depth;struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;};
struct xdev_ext_mech_batch {u32 slot,nr;u64 id,ticket;void *priv,*cookie;struct xdev_ext_mech_frame frames[4];int claim,published,status;bool sequestered;};
struct xdev_ext_mech_pool*xdev_ext_mech_session_pool(struct xdev_ext_mech_session*s){return &s->pool;}
u32 xdev_ext_mech_session_depth(const struct xdev_ext_mech_session*s){return s->depth;}
const struct xdev_ext_mech_layout*xdev_ext_mech_session_layout(const struct xdev_ext_mech_session*s){return &s->layout;}
u32 xdev_ext_mech_batch_slot(const struct xdev_ext_mech_batch*b){return b->slot;}
u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch*b){return b->id;}
u64 xdev_ext_mech_batch_ticket(const struct xdev_ext_mech_batch*b){return b->ticket;}
u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch*b){return b->nr;}
void*xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch*b){return b->priv;}
void*xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch*b){return b->cookie;}
int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch*b,u32 i,struct xdev_ext_mech_frame*f){if(i>=b->nr)return -ERANGE;*f=b->frames[i];return 0;}
int xdev_ext_mech_batch_frame_claim(const struct xdev_ext_mech_batch*b,u32 pos,u64*o,u64*g){*o=17;*g=23;return 0;}
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch*b,u64 t){if(t!=b->ticket||b->claim)return -ESTALE;b->claim=1;return 0;}
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch*b,u64 t,int e,bool q){b->published++;b->status=e;b->sequestered=q;}
bool xdev_ext_mech_batch_ce_owners_valid(const struct xdev_ext_mech_batch*b,u64 t,const struct xdev_ext_ce_xfer*x,u32 n){return t==b->ticket;}
bool xdev_ext_mech_batch_dma_owners_valid(const struct xdev_ext_mech_batch*b,u64 t,const struct xdev_ext_dma_xfer*x,u32 n){return t==b->ticket;}
int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops*o){return 0;}
