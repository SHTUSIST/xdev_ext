/* SPDX-License-Identifier: GPL-2.0 */
/* Host environment only. No login/link/lifetime policy belongs here. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/types.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef __u64 u64;
typedef uintptr_t dma_addr_t;
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define BITS_TO_LONGS(n) (((n) + 8 * sizeof(long) - 1) / (8 * sizeof(long)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define upper_32_bits(x) ((u32)((u64)(x) >> 32))
#define lower_32_bits(x) ((u32)(x))
#define GFP_KERNEL 0
#define __init
#define __exit
#define THIS_MODULE NULL
#define module_param_named(...)
#define module_param(...)
#define MODULE_PARM_DESC(...)
#define MODULE_DEVICE_TABLE(...)
#define module_init(...)
#define module_exit(...)
#define MODULE_LICENSE(...)
#define MODULE_DESCRIPTION(...)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define UUID_INIT(a,b,c,d,e,f,g,h,i,j,k) {{ \
    (a)>>24, ((a)>>16)&255, ((a)>>8)&255, (a)&255, \
    (b)>>8, (b)&255, (c)>>8, (c)&255, d,e,f,g,h,i,j,k }}
typedef struct { u8 b[16]; } uuid_t;
static bool uuid_equal(const uuid_t *a, const uuid_t *b) { return !memcmp(a,b,16); }
static void uuid_copy(uuid_t *a, const uuid_t *b) { memcpy(a,b,16); }

static void event(const char *name);
static void fixture_lock_event(const void *object, bool locked, bool spin);
struct mutex { int held; };
#define DEFINE_MUTEX(name) struct mutex name = {0}
static void mutex_init(struct mutex *m) { m->held=0; }
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held=1; fixture_lock_event(m,true,false); }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held=0; fixture_lock_event(m,false,false); }
#define lockdep_assert_held(m) assert((m)->held)
typedef struct { int held; } spinlock_t;
static int active_spins;
static void spin_lock_init(spinlock_t *s) { s->held=0; }
static void spin_lock_irq(spinlock_t *s) { assert(!s->held); s->held=1; active_spins++; fixture_lock_event(s,true,true); }
static void spin_unlock_irq(spinlock_t *s) { assert(s->held); s->held=0; active_spins--; fixture_lock_event(s,false,true); }
#define spin_lock_irqsave(s,f) do { (f)=0; spin_lock_irq(s); } while (0)
#define spin_unlock_irqrestore(s,f) do { (void)(f); spin_unlock_irq(s); } while (0)

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(name) struct list_head name = { &name, &name }
static void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev=h->prev; n->next=h; h->prev->next=n; h->prev=n; event("list_add"); }
static void list_del(struct list_head *n)
{ n->prev->next=n->next; n->next->prev=n->prev; event("list_del"); }
static bool list_empty(const struct list_head *h) { return h->next==h; }
#define list_for_each_entry(p,h,m) \
    for ((p)=container_of((h)->next,__typeof__(*(p)),m); &(p)->m!=(h); \
         (p)=container_of((p)->m.next,__typeof__(*(p)),m))
struct kref { int n; };
static void kref_init(struct kref *r) { r->n=1; }
static void kref_get(struct kref *r) { assert(r->n>0); r->n++; }
static void kref_put(struct kref *r, void (*release)(struct kref *))
{ assert(r->n>0); if (!--r->n) release(r); }
typedef struct { int n; } atomic_t;
static int atomic_inc_return(atomic_t *n) { return ++n->n; }
static void atomic_set(atomic_t *n,int value) { n->n=value; }
static int atomic_read(const atomic_t *n) { return n->n; }

struct work_struct { void (*fn)(struct work_struct *); bool pending; unsigned long delay; };
struct delayed_work { struct work_struct work; };
#define INIT_WORK(w,f) do { *(w)=(struct work_struct){.fn=(f)}; } while (0)
#define INIT_DELAYED_WORK(w,f) INIT_WORK(&(w)->work,f)
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
static void *system_long_wq;
static unsigned long msecs_to_jiffies(unsigned long n) { return n; }
static bool queue_work(void *, struct work_struct *);
static bool queue_delayed_work(void *, struct delayed_work *, unsigned long);
static bool mod_delayed_work(void *, struct delayed_work *, unsigned long);
static bool cancel_work_sync(struct work_struct *);
static bool cancel_delayed_work_sync(struct delayed_work *);

struct pci_dev { int refs; };
struct device { void *owner; };
struct nhi { struct pci_dev *pdev; };
struct tb { struct nhi *nhi; };
struct tb_xdomain { u64 route; const uuid_t *local_uuid,*remote_uuid; struct tb *tb; };
struct tb_service { struct device dev; void *drvdata; struct tb_xdomain *parent; u32 prtcstns; };
struct tb_service_id { const char *key; u32 id; };
#define TB_SERVICE(k,i) .key=(k), .id=(i)
struct tb_ring { int unused; };
struct ring_frame { int unused; };
struct tb_property_dir { int unused; };
struct attribute { const char *name; unsigned int mode; };
struct device_attribute {
    struct attribute attr;
    ssize_t (*show)(struct device *,struct device_attribute *,char *);
    ssize_t (*store)(struct device *,struct device_attribute *,const char *,size_t);
};
struct attribute_group { struct attribute **attrs; };
#define DEVICE_ATTR_RO(n) struct device_attribute dev_attr_##n = { \
    .attr={.name=#n,.mode=0444}, .show=n##_show }
#define ATTRIBUTE_GROUPS(n) \
    static const struct attribute_group n##_group = {.attrs=n##_attrs}; \
    static const struct attribute_group *n##_groups[] = {&n##_group,NULL}
#define DEFINE_SIMPLE_DEV_PM_OPS(n,s,r) int n
#define pm_sleep_ptr(p) (p)
struct tb_service_driver {
    struct { void *owner; const char *name; const struct attribute_group **dev_groups; void *pm; } driver;
    int (*probe)(struct tb_service *, const struct tb_service_id *);
    void (*remove)(struct tb_service *);
    const struct tb_service_id *id_table;
};
struct tb_protocol_handler { const uuid_t *uuid; int (*callback)(const void *,size_t,void *); void *data; struct list_head list; };
#define TB_CFG_PKG_XDOMAIN_RESP 1
struct xdev_ext_mech_stage { int id; };
struct xdev_ext_net_dev_ops { int unused; };
static void *kzalloc(size_t n,int g) { (void)g; return calloc(1,n); }
static void kfree(void *);
static u64 get_random_u64(void);
static struct pci_dev *pci_dev_get(struct pci_dev *);
static void pci_dev_put(struct pci_dev *);
static struct tb_service *tb_to_service(struct device *d) { return d->owner; }
static void *tb_service_get_drvdata(struct tb_service *s) { return s->drvdata; }
static void tb_service_set_drvdata(struct tb_service *s,void *p) { s->drvdata=p; }
static struct tb_xdomain *tb_service_parent(struct tb_service *s) { return s->parent; }
static int sysfs_emit(char *buf,const char *fmt,...)
{ va_list ap; va_start(ap,fmt); int n=vsprintf(buf,fmt,ap); va_end(ap); return n; }
static int tb_xdomain_request(struct tb_xdomain *,const void *,size_t,int,void *,size_t,int,unsigned int);
static int tb_xdomain_response(struct tb_xdomain *,const void *,size_t,int);
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *,int);
static struct tb_property_dir *tb_property_create_dir(const uuid_t *);
static int tb_property_add_immediate(struct tb_property_dir *,const char *,u32);
static void tb_property_free_dir(struct tb_property_dir *);
static int tb_register_protocol_handler(struct tb_protocol_handler *);
static void tb_unregister_protocol_handler(struct tb_protocol_handler *);
static int tb_register_property_dir(const char *,struct tb_property_dir *);
static void tb_unregister_property_dir(const char *,struct tb_property_dir *);
static int tb_register_service_driver(struct tb_service_driver *);
static void tb_unregister_service_driver(struct tb_service_driver *);

/* Kernel facilities required by the built-in retention core. */
#define EXPORT_SYMBOL_GPL(n)
#define MAX_ERRNO 4095
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-MAX_ERRNO)
#define WARN_ON_ONCE(x) ({ bool _warn=!!(x); assert(!_warn); _warn; })
#define DEFINE_SPINLOCK(n) spinlock_t n={0}

#include "io_uring/xdomain/xdev_ext_xdomain_early.h"
