/* SPDX-License-Identifier: GPL-2.0 */
static s32 stamp(const struct xdev_ext_mech_ctx *ctx,unsigned tag)
{u8 *p=bpf_xdev_ext_frame_rw(ctx,0,0,8);u64 n=0;if(!p)return -EFAULT;memcpy(&n,p,8);n=(n<<8)|tag;memcpy(p,&n,8);return 0;}
static s32 stamp_a(const struct xdev_ext_mech_ctx *ctx){return stamp(ctx,0x11);}
static s32 stamp_b(const struct xdev_ext_mech_ctx *ctx){return stamp(ctx,0x17);}
static s32 stamp_default(const struct xdev_ext_mech_ctx *ctx){return stamp(ctx,0x2b);}
static int bind_pair(struct xdev_ext_mech_session *s,int a,int b)
{
 struct xdev_ext_mech_create c=request();s->nr_stages=2;s->frames=1;s->layout=c.layout;
 c.nr_stages=2;c.st[0].class_id=XDEV_EXT_MECH_CLASS_CPU;c.st[0].arg0=10;c.st[1]=c.st[0];
 s32 selectors[4]={a,b,-1,-1};s->ss.state=XDEV_EXT_MECH_SESSION_ACTIVE;
 INIT_LIST_HEAD(&s->ring_node);INIT_LIST_HEAD(&s->all_node);INIT_LIST_HEAD(&s->live_node);INIT_LIST_HEAD(&s->free);
 return xdev_ext_mech_session_bind(s,&c,selectors);
}
static int invoke_pair(struct xdev_ext_mech_session *s,u64 want)
{
 u8 bytes[65536];memset(bytes,0xa6,sizeof(bytes));memset(bytes,0,8);
 struct xdev_ext_mech_frame f={.kaddr=bytes,.data_len=4096};u32 out=4096;
 struct xdev_ext_binding_ctx_v2 base={0};struct xdev_ext_mech_batch b={.id=1,.key=3,.bytes=4096};
 struct xdev_ext_mech_call_args a={.member=XDEV_EXT_MECH_MEMBER_COMPUTE,.callsite=XDEV_EXT_MECH_SITE_WORKER,.base=&base,.b=&b,.frames=&f,.nr_frames=1,.out_len=&out};
 s32 value=-1;CHECK(!xdev_ext_mech_call(&s->st[0],&a,&value,NULL)&&value==0);
 CHECK(!xdev_ext_mech_call(&s->st[1],&a,&value,NULL)&&value==0);
 u64 word;memcpy(&word,bytes,8);CHECK(word==want);
 for(unsigned i=8;i<sizeof(bytes);i++)CHECK(bytes[i]==0xa6);
 CHECK(!preempt_depth);return 0;
}
static void retire(struct bpf_link *l)
{assert(!l->detached);l->detached=true;assert(xdev_ext_mech_instance_unregister(l->class_id,l->ops,l));}
static void host_copyout_hook(void)
{if(retire_on_copyout){struct bpf_link *l=retire_on_copyout;retire_on_copyout=NULL;retire(l);}}
static int drop_session(struct xdev_ext_mech_session *s)
{list_del_init(&s->all_node);list_del_init(&s->ring_node);allocated=s;return xdev_ext_mech_session_release(s);}
static int selection_case(void)
{
 reset();programs[0].ops=(struct xdev_ext_nvme_mech_ops){.abi_version=1,.compute=stamp_default};
 programs[1].ops=(struct xdev_ext_nvme_mech_ops){.abi_version=1,.flags=1,.compute=stamp_a};
 programs[2].ops=(struct xdev_ext_nvme_mech_ops){.abi_version=1,.flags=1,.compute=stamp_b};host_default=&programs[0].ops;
 struct bpf_link a={.type=91,.refs=1,.class_id=9,.ops=&programs[1].ops},b={.type=91,.refs=1,.class_id=9,.ops=&programs[2].ops},same=b,again=b;
 host_fds[41]=&a;host_fds[42]=&b;host_fds[43]=&same;host_fds[44]=&again;
 CHECK(!xdev_ext_mech_instance_register(9,a.ops,&a)&&!xdev_ext_mech_instance_register(9,b.ops,&b)&&!xdev_ext_mech_instance_register(9,b.ops,&same));
 struct xdev_ext_mech_session *sa=calloc(1,sizeof(*sa)),*sb=calloc(1,sizeof(*sb)),*sg=calloc(1,sizeof(*sg)),*sc=calloc(1,sizeof(*sc));
 CHECK(sa&&sb&&sg&&sc);CHECK(!bind_pair(sa,41,42)&&!bind_pair(sb,42,41)&&!bind_pair(sg,-1,-1)&&!bind_pair(sc,43,-1));
 CHECK(!sa->ops[9]&&!sb->ops[9]&&default_gets==2);
 CHECK(xdev_ext_mech_stage_has_member(&sa->st[0],XDEV_EXT_MECH_MEMBER_COMPUTE)&&xdev_ext_mech_stage_has_member(&sb->st[1],XDEV_EXT_MECH_MEMBER_COMPUTE));CHECK(programs[1].pins==2&&programs[2].pins==3);
 CHECK(!invoke_pair(sa,0x1117)&&!invoke_pair(sb,0x1711)&&!invoke_pair(sg,0x2b2b)&&!invoke_pair(sc,0x172b));
 /* Private admission/calls do not consult a changed global default. */
 host_default=&programs[3].ops;CHECK(xdev_ext_mech_session_admits(sa)&&xdev_ext_mech_session_admits(sb)&&!xdev_ext_mech_session_admits(sg));CHECK(!invoke_pair(sa,0x1117));host_default=&programs[0].ops;
 list_add_tail(&sa->all_node,&xdev_ext_mech_all);list_add_tail(&sb->all_node,&xdev_ext_mech_all);list_add_tail(&sg->all_node,&xdev_ext_mech_all);list_add_tail(&sc->all_node,&xdev_ext_mech_all);
 retire(&b);CHECK(xdev_ext_mech_stop_reason(sa)==-ECANCELED&&xdev_ext_mech_stop_reason(sb)==-ECANCELED);CHECK(!xdev_ext_mech_session_admits(sa)&&!xdev_ext_mech_session_admits(sb));CHECK(xdev_ext_mech_session_admits(sc)&&xdev_ext_mech_session_admits(sg));
 CHECK(programs[1].pins==2&&programs[2].pins==3);CHECK(!invoke_pair(sc,0x172b)&&!invoke_pair(sg,0x2b2b));
 CHECK(!xdev_ext_mech_instance_register(9,again.ops,&again));struct xdev_ext_mech_session *sn=calloc(1,sizeof(*sn));CHECK(sn&&!bind_pair(sn,44,-1));CHECK(xdev_ext_mech_session_admits(sn)&&!xdev_ext_mech_session_admits(sa));CHECK(!invoke_pair(sn,0x172b));
 /* Existing checked-unbind UNKNOWN must retain every selected pin. */
 checked_err=-EIO;unsigned before=pin_puts;CHECK(drop_session(sa)==-EIO);CHECK(retained==sa&&pin_puts==before&&programs[1].pins==2&&programs[2].pins==4);
 retained=NULL;checked_err=0;CHECK(drop_session(sa)==-ECANCELED);CHECK(programs[1].pins==1&&programs[2].pins==3);
 CHECK(drop_session(sb)==-ECANCELED&&!drop_session(sg)&&!drop_session(sc)&&!drop_session(sn));
 /* Resolving a later invalid selector must precede device/PREPARE effects. */
 struct xdev_ext_mech_session *bad=calloc(1,sizeof(*bad));unsigned d0=describes,p0=prepares;
 CHECK(bad&&bind_pair(bad,41,127)==-EBADF);CHECK(describes==d0&&prepares==p0&&!bad->nr_bound&&programs[1].pins==1);
 CHECK(!drop_session(bad)&&!programs[1].pins);
 /* A real partial PREPARE failure uses the same safe selected-pin release. */
 struct xdev_ext_mech_session *pf=calloc(1,sizeof(*pf));prepare_stage=1;
 CHECK(pf&&bind_pair(pf,41,43)==-EACCES&&pf->nr_bound==2);CHECK(programs[1].pins==1&&programs[2].pins==1);
 checked_err=-EIO;before=pin_puts;CHECK(drop_session(pf)==-EIO&&retained==pf&&pin_puts==before);
 retained=NULL;checked_err=0;prepare_stage=-1;CHECK(drop_session(pf)==-EIO&&!programs[1].pins&&!programs[2].pins);
 /* Deterministic withdrawal while the report is copied, before publication. */
 struct bpf_link window={.type=91,.refs=1,.class_id=9,.ops=&programs[2].ops};host_fds[45]=&window;
 CHECK(!xdev_ext_mech_instance_register(9,window.ops,&window));
 struct sp_create_programs_wire e=selected_request();e.request.create.pool_kind=2;e.request.create.pool_fd=-1;e.request.create.nr_stages=2;
 e.request.create.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=9,.direction=1,.fd=-1,.arg0=10};e.request.create.st[1]=e.request.create.st[0];e.program_fds[0]=41;e.program_fds[1]=45;
 retire_on_copyout=&window;CHECK(!dispatch_selected(&e)&&!e.request.report.result&&e.request.report.session_id==117);
 CHECK(allocated&&!xdev_ext_mech_session_admits(allocated)&&allocated->last_err==-ECANCELED&&xdev_ext_mech_stop_reason(allocated)==-ECANCELED);
 CHECK(drop_session(allocated)==-ECANCELED&&!programs[1].pins&&!programs[2].pins);
 retire(&a);retire(&same);retire(&again);CHECK(pin_gets==pin_puts&&temp_gets==temp_puts&&!programs[1].pins&&!programs[2].pins&&!programs[0].pins);
 printf("SESSION_SELECTION actual-bind/call/invoke/registry/admission/release PASS pins=%u/%u temp=%u/%u\n",pin_gets,pin_puts,temp_gets,temp_puts);return 0;
}
int main(void){return selection_case();}
