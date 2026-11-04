#!/usr/bin/env python3
"""Compile selected actual source; SETUP (2) is distinct from semantic FAIL (1)."""
import argparse, json, pathlib, re, shutil, subprocess, sys, tempfile
HERE = pathlib.Path(__file__).resolve().parent
CE = 'src/compute/io_uring/xdev_ext_mech_ce.c'
DMA = 'src/core/io_uring/xdev_ext_mech_dma.c'
TYPED = 'src/compute/io_uring/xdev_ext_compfam_copy_core.h'
RUNTIME = 'src/compute/io_uring/xdev_ext_compfam_copy.c'
RUNTIME_HEADER = 'src/compute/io_uring/xdev_ext_compfam_copy_runtime.h'

def block(text, name, struct=False):
    pat = (r'^struct\s+' + re.escape(name) + r'\s*\{' if struct else
           r'^(?:static\s+)?(?:inline\s+)?(?:[\w*]+\s+)+\**' + re.escape(name) + r'\s*\([^;]*?\)\s*\{')
    m = re.search(pat, text, re.M)
    if not m: raise RuntimeError('missing actual ' + name)
    start = text.index('{', m.start()); depth = 1; i = start+1
    while depth and i < len(text):
        if text[i] == '{': depth += 1
        elif text[i] == '}': depth -= 1
        i += 1
    if depth: raise RuntimeError('unbalanced actual ' + name)
    return text[m.start():i] + (';' if struct else '') + '\n'

RUNTIME_SHIM = r"""
#include <stddef.h>
#include <pthread.h>
#include "xdev_ext_mech_ce_lease.h"
#include "xdev_ext_mech_native_cookie.h"
#define HAVE_RUNTIME 1
struct mutex { pthread_mutex_t value; };
#define DEFINE_MUTEX(n) struct mutex n={PTHREAD_MUTEX_INITIALIZER}
#define mutex_lock(p) assert(!pthread_mutex_lock(&(p)->value))
#define mutex_unlock(p) assert(!pthread_mutex_unlock(&(p)->value))
#define LIST_HEAD(n) struct list_head n={&(n),&(n)}
#define INIT_LIST_HEAD(h) do {(h)->next=(h);(h)->prev=(h);}while(0)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m);&p->m!=(h);p=container_of(p->m.next,__typeof__(*p),m))
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
static bool list_empty(struct list_head *h){return h->next==h;}
#define struct_size(p,m,n) (sizeof(*(p))+sizeof((p)->m[0])*(n))
#define kvzalloc(n,g) calloc(1,n)
#define kvfree(p) free(p)
#define kmalloc(n,g) malloc(n)
static unsigned fixture_warnings;
static bool fixture_warn(bool bad){if(bad)fixture_warnings++;return bad;}
#define WARN_ON_ONCE(x) fixture_warn(!!(x))
#define WARN_ONCE(x,...) fixture_warn(!!(x))
#define WRITE_ONCE(x,v) ((x)=(v))
#define atomic_read(p) (*(p))
#define atomic_inc(p) (++*(p))
#define ERR_PTR(n) ((void *)(intptr_t)(n))
struct file { const struct file_operations *f_op; };
typedef unsigned refcount_t;
static void refcount_set(refcount_t *p,unsigned n){*p=n;}
static bool refcount_dec_and_test(refcount_t *p){assert(*p);return !--*p;}
static bool refcount_inc_not_zero(refcount_t *p){if(!*p)return false;++*p;return true;}
/* These core/module boundaries are not entered by the transfer-only corpus. */
static bool try_module_get(struct module *m){(void)m;abort();}
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 t){(void)b;(void)t;abort();}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 t,int e,bool q){(void)b;(void)t;(void)e;(void)q;abort();}
static bool xdev_ext_mech_batch_dma_owners_valid(struct xdev_ext_mech_batch *b,u64 t,const struct xdev_ext_dma_xfer *x,u32 n){(void)b;(void)t;(void)x;(void)n;abort();}
static void *fixture_private;
static struct xdev_ext_comp_copy_cookie *fixture_cookie;
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){(void)b;return fixture_private;}
static void *xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch *b){(void)b;return fixture_cookie;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->id;}
"""

RUNTIME_EXERCISE = r"""
/* An invocation supplies fresh core cookie/private storage. Native submit only
 * observes typed adaptation and retains no command or callback. Finish that
 * synchronous boundary with the actual cookie helper before known-fate release.
 * No frame collection, validation, transfer or native adaptation is duplicated. */
static int fixture_stage_xfers(bool dma,void *private,struct xdev_ext_mech_batch *b,void *out) {
 struct xdev_ext_comp_copy_cookie cookie={0};
 struct xdev_ext_comp_copy_stage *copy=dma?&((struct xdev_ext_dma_stage *)private)->copy:&((struct xdev_ext_ce_stage *)private)->copy;
 struct xdev_ext_mech_stage st={.priv=private,.direction=copy->window.direction};
 fixture_private=out;fixture_cookie=&cookie;
 int result=dma?xdev_ext_dma_submit(&st,b):xdev_ext_ce_submit(&st,b);
 if(!result)assert(xdev_ext_window_copy_cookie_finish(&cookie.state));
 if(dma)xdev_ext_dma_batch_release(&st,b,false);else xdev_ext_ce_batch_release(&st,b,false);
 fixture_private=NULL;fixture_cookie=NULL;
 return result;
}
static int fixture_ce_stage_xfers(void *cs,struct xdev_ext_mech_batch *b,struct xdev_ext_ce_batch *out){return fixture_stage_xfers(false,cs,b,out);}
static int fixture_dma_stage_xfers(void *cs,struct xdev_ext_mech_batch *b,struct xdev_ext_dma_batch *out){return fixture_stage_xfers(true,cs,b,out);}
static void fixture_unbind(struct xdev_ext_mech_stage *st,bool dma){EQ(dma?xdev_ext_dma_unbind(st):xdev_ext_ce_unbind(st),0);}
#define fixture_dead(cs) ((cs)->copy.dead)
"""

def table(text, name):
    m=re.search(r'^static const struct xdev_ext_comp_copy_legacy_ops '+re.escape(name)+r' = \{.*?^\};',text,re.M|re.S)
    if not m: raise RuntimeError('missing actual table '+name)
    return m[0]+'\n'

def extract_runtime(root,out,mech,generated):
    header=(root/RUNTIME_HEADER).read_text()
    generated.append(RUNTIME_SHIM)
    for name in ['xdev_ext_comp_copy_member','xdev_ext_comp_copy_registration','xdev_ext_comp_copy_registry','xdev_ext_comp_copy_cookie','xdev_ext_comp_copy_legacy_ops','xdev_ext_comp_copy_stage']:
        # Forward tags are needed by the real function-pointer declarations.
        generated.append('struct xdev_ext_comp_copy_stage; struct xdev_ext_comp_copy_cookie;\n')
        generated.append(block(header,name,True))
    generated.extend(line+'\n' for line in header.splitlines() if line.startswith('XDEV_EXT_NATIVE_COOKIE_ASSERT('))
    for cls,src in [('ce',CE),('dma',DMA)]:
        text=(root/src).read_text()
        if cls=='dma':
            for name in ['xdev_ext_dma_scope_info','xdev_ext_dma_scope_ops']:
                generated.append(block(mech,name,True))
            generated.append(block(text,'xdev_ext_dma_scope',True))
        for suffix in ['lease_group','stage','batch']:
            generated.append(block(text,'xdev_ext_'+cls+'_'+suffix,True))
        generated.append('static DEFINE_MUTEX(xdev_ext_'+cls+'_lease_lock);\nstatic LIST_HEAD(xdev_ext_'+cls+'_lease_groups);\n')
        if cls=='dma':
            for name in ['xdev_ext_dma_scope_create','xdev_ext_dma_scope_ref_put','xdev_ext_dma_scope_owner_put','xdev_ext_dma_scope_get','xdev_ext_dma_scope_put','xdev_ext_dma_stage_scope']:
                generated.append(block(text,name))
        for suffix in (['lease_bind','lease_bind_ready','lease_get','batch_release','lease_cleanup_begin','lease_unbind'] if cls=='ce' else ['lease_bind','lease_get','batch_release','lease_unbind','lease_cleanup','lease_busy']):
            generated.append(block(text,'xdev_ext_'+cls+'_'+suffix))
    generated.append('#include "boundary_impl.h"\n')
    # Keep every actual common function body, including registry, completion,
    # polling and cleanup, in the compiled TU. Only kernel include directives
    # are replaced with the real extracted declarations plus OS boundaries.
    common=(root/RUNTIME).read_text()
    common='\n'.join(line for line in common.splitlines() if not line.startswith('#include '))+'\n'
    (out/'actual-common.c').write_text(common)
    generated.append('#include "actual-common.c"\n')
    for cls,src in [('ce',CE),('dma',DMA)]:
        text=(root/src).read_text()
        callbacks=['lease_get','submit','classify','unbind_begin','unbind_host','unbind_region','unbind_end']+(['poll'] if cls=='dma' else [])+['warn']
        for suffix in callbacks:generated.append(block(text,'xdev_ext_'+cls+'_copy_'+suffix))
        generated.append(table(text,'xdev_ext_'+cls+'_copy_ops'))
        for suffix in ['bind','validate','submit','unbind']:generated.append(block(text,'xdev_ext_'+cls+'_'+suffix))
    generated.append(RUNTIME_EXERCISE)

def extract(root, out):
    mech=(root/'src/core/include/linux/xdev_ext_mech.h').read_text()
    generated=[]
    lines=mech.splitlines(); start=next(i for i,l in enumerate(lines) if l.startswith('#define XDEV_EXT_MECH_OPS_TYPE(')); end=start
    while lines[end].endswith('\\'): end+=1
    generated.append('\n'.join(lines[start:end+1])+'\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_ce_mech_ops);\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_dma_mech_ops);\n')
    for cls, src in [('ce',CE), ('dma',DMA)]:
        text=(root/src).read_text()
        for suffix in ['region','xfer','backend_ops' if cls=='ce' else 'provider_ops']:
            generated.append(block(mech,'xdev_ext_'+cls+'_'+suffix,True))
    if (root/RUNTIME_HEADER).is_file():
        extract_runtime(root,out,mech,generated)
    else:
        # Real stage declarations include only opaque lease/scope pointers; use real key header.
        for cls, src in [('ce',CE), ('dma',DMA)]:
            text=(root/src).read_text()
            for suffix in ['stage','batch']: generated.append(block(text,'xdev_ext_'+cls+'_'+suffix,True))
        generated.append('#include "boundary_impl.h"\n')
        for cls, src in [('ce',CE), ('dma',DMA)]:
            text=(root/src).read_text()
            for suffix in (['copy_claim'] if (root/TYPED).is_file() else []) + ['bind','collect','validate','stage_xfers']:
                generated.append(block(text,'xdev_ext_'+cls+'_'+suffix))
        generated.append('''
#define fixture_ce_stage_xfers xdev_ext_ce_stage_xfers
#define fixture_dma_stage_xfers xdev_ext_dma_stage_xfers
#define fixture_dead(cs) ((cs)->dead)
static void fixture_unbind(struct xdev_ext_mech_stage *st,bool dma){(void)dma;free(st->priv);st->priv=NULL;}
''')
    (out/'actual.h').write_text('\n'.join(generated))

def compile_run(root, phase, out):
    out.mkdir(parents=True,exist_ok=True)
    if phase=='typed' and not (root/TYPED).is_file():
        print('SETUP: typed COPY_WINDOW header absent; no behavioral RED claimed')
        return 2
    extract(root,out)
    source=out/'test.c'
    source.write_text('#include "boundary.h"\n#include "actual.h"\n#include "'+str(HERE/'baseline.c')+'"\n#include "'+str(HERE/'abi.c')+'"\n'+
                      ('#include "'+str(HERE/'typed.c')+'"\n#include "'+str(HERE/'consumers.c')+'"\n' if phase=='typed' else '')+
                      'int main(void) { abi(); fflush(stdout); baseline(); '+('typed(); consumers();' if phase=='typed' else '')+' puts("PASS: '+phase+' actual-source assertions"); return 0; }\n')
    inc=[HERE,out,root/'src/compute/io_uring',root/'src/core/io_uring',root/'src/compute/include/linux',root/'src/core/include/linux']
    cmd=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-MMD','-MF',str(out/'dependencies.d')]
    cmd += ['-I'+str(p) for p in inc]+[str(source),'-o',str(out/'test')]
    p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'compile.log').write_text(p.stdout)
    (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    if p.returncode: print('SETUP: compile failed\n'+p.stdout); return 2
    p=subprocess.run([str(out/'test')],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'run.log').write_text(p.stdout); print(p.stdout,end='')
    abi='\n'.join(line for line in p.stdout.splitlines() if line.startswith('ABI '))+'\n'
    (out/'abi.txt').write_text(abi)
    if p.returncode:
        print('FAIL: runtime assertion/exit',p.returncode,'(ABI comparison withheld)'); return 1
    golden=HERE/'abi.expected.txt'
    if golden.exists() and golden.read_text()!=abi:
        print('FAIL: affected ABI differs from independent baseline'); return 1
    return 0 if p.returncode==0 else 1

def main():
    a=argparse.ArgumentParser(); a.add_argument('--source-root',type=pathlib.Path,required=True); a.add_argument('--phase',choices=['baseline','typed'],default='baseline'); a.add_argument('--output',type=pathlib.Path)
    o=a.parse_args(); root=o.source_root.resolve()
    try:
        if o.output: return compile_run(root,o.phase,o.output.resolve())
        with tempfile.TemporaryDirectory(prefix='copy-window-') as tmp: return compile_run(root,o.phase,pathlib.Path(tmp))
    except (OSError,RuntimeError) as e: print('SETUP:',e); return 2
if __name__=='__main__': sys.exit(main())
