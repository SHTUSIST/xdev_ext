#!/usr/bin/env python3
"""Execute the production stateless entry against explicit lookup/invoke boundaries."""
import pathlib,re,subprocess,tempfile,unittest
ROOT=next(p for p in pathlib.Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech_ops.c').is_file())
class Stateless(unittest.TestCase):
 def test_no_session_rx_rejected_before_lookup(self):
  src=(ROOT/'io_uring/xdev_ext_mech_ops.c').read_text()
  function=re.search(r'^int xdev_ext_mech_call_active\([^;{}]*\)\n\{\n.*?^\}',src,re.M|re.S)[0]
  code=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "include/uapi/linux/xdev_ext_mech.h"
typedef uint32_t u32;typedef int32_t s32;
struct module {int unused;};
struct xdev_ext_mech_call_args {u32 member,callsite,frame_size,hdr_room,batch_frames;uint64_t batch_id;};
struct xdev_ext_mech_target {u32 class_id,frame_size,hdr_room,batch_frames;uint64_t batch_id;};
struct xdev_ext_mech_hold_intent {uint64_t value;};
static unsigned lookup_count,invoke_count,release_count;static bool published=true;
static const void *xdev_ext_mech_ops_get(u32 c,bool *p,struct module **m) {
 (void)c;lookup_count++;*p=true;*m=NULL;return published?(void *)1:NULL;
}
static bool xdev_ext_mech_class_known(u32 c) {return c>0 && c<XDEV_EXT_MECH_CLASS_MAX;}
static int xdev_ext_mech_invoke(const void *o,const struct xdev_ext_mech_target *t,
 const struct xdev_ext_mech_call_args *a,s32 *ret,struct xdev_ext_mech_hold_intent *h) {
 (void)o;(void)t;(void)a;(void)h;invoke_count++;*ret=123;return 0;
}
static void xdev_ext_mech_ops_put(const void *o,bool p,struct module *m) {(void)o;(void)p;(void)m;release_count++;}
/* ACTIVE */
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s lookup_count=%u invoke_count=%u release_count=%u\n",__LINE__,#x,lookup_count,invoke_count,release_count);return 1;}}while(0)
int main(void) {
 const unsigned sites[]={XDEV_EXT_MECH_SITE_RX_GENERIC,XDEV_EXT_MECH_SITE_RX_NATIVE,XDEV_EXT_MECH_SITE_RX_HOLD_RESULT};
 struct xdev_ext_mech_call_args a={.member=XDEV_EXT_MECH_MEMBER_COMPLETE};s32 ret=77;
 struct xdev_ext_mech_hold_intent h={.value=0xabcdef};
 for(unsigned c=1;c<XDEV_EXT_MECH_CLASS_MAX;c++) for(unsigned i=0;i<3;i++) {
  a.callsite=sites[i];CHECK(xdev_ext_mech_call_active(c,&a,&ret,&h)==-EOPNOTSUPP);
  CHECK(!lookup_count && !invoke_count && !release_count && ret==77 && h.value==0xabcdef);
 }
 CHECK(xdev_ext_mech_call_active(1,NULL,&ret,&h)==-EINVAL);
 const unsigned allowed[]={XDEV_EXT_MECH_SITE_WORKER,XDEV_EXT_MECH_SITE_CREATE,XDEV_EXT_MECH_SITE_URING_CMD};
 for(unsigned i=0;i<3;i++) {a.callsite=allowed[i];
  CHECK(!xdev_ext_mech_call_active(XDEV_EXT_MECH_CLASS_NVME,&a,&ret,&h));CHECK(ret==123);
 }
 CHECK(lookup_count==3 && invoke_count==3 && release_count==3);
 published=false;a.callsite=XDEV_EXT_MECH_SITE_WORKER;
 CHECK(xdev_ext_mech_call_active(XDEV_EXT_MECH_CLASS_NVME,&a,&ret,&h)==-ENOENT);
 CHECK(xdev_ext_mech_call_active(99,&a,&ret,&h)==-EINVAL);
 CHECK(invoke_count==3 && release_count==3);
 puts("PASS production call_active: ownerless RX denied before lookup/callback; stateless worker/create/cmd retained");return 0;
}
'''.replace('/* ACTIVE */',function)
  with tempfile.TemporaryDirectory(prefix='xdev-ext-call-active-') as tmp:
   c=pathlib.Path(tmp)/'t.c';c.write_text(code);exe=pathlib.Path(tmp)/'t'
   r=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(ROOT),str(c),'-o',str(exe)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
   r=subprocess.run([str(exe)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr);print(r.stdout.strip())
if __name__=='__main__':unittest.main(verbosity=2)
