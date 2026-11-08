// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "nvme_blocktable.h"
#include "oracle.h"

#define LOG_BYTES (8U * 1024U * 1024U)
struct options { const char *object, *device, *expected, *output; uint64_t slba, nlb; bool guest, have_slba; };
struct program { struct bpf_object *object; struct bpf_link *link; int blocks; };
struct session { int ring; uint64_t id, done, device_rdev; unsigned char *memory; const unsigned char *want; const char *name; };
static struct options opt;
static FILE *events;
static unsigned cases, checks;
#ifndef BLOCKTABLE_PRIVATE_PARALLEL
static const unsigned slots[3][8] = {
    {0,1,2,3,4,5,6,7}, {7,6,5,4,3,2,1,0}, {3,0,6,1,7,4,2,5}
};
static const char *names[3] = {"ordinary", "reverse", "shuffled"};
#endif
static unsigned char expected[8 * BT_GROUP];

static void verdict(int code, const char *reason)
{
    const char *state = code == 2 ? "SETUP_ERROR" : code ? "BEHAVIOR_RED" : "GUEST_CORRECTNESS_PASS";
    if (events) {
        fprintf(events, "verdict state=%s cases=%u checks=%u reason=%s\n", state, cases, checks, reason);
        fflush(events);
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/result.json", opt.output) < (int)sizeof(path)) {
            FILE *f = fopen(path, "wx");
            if (f) {
                fprintf(f, "{\"state\":\"%s\",\"exit\":%d,\"cases\":%u,\"checks\":%u,\"performance\":false,\"physical_dma\":false}\n", state, code, cases, checks);
                fclose(f);
            }
        }
    }
    fprintf(code ? stderr : stdout, "BLOCKTABLE_NATIVE state=%s cases=%u checks=%u reason=%s performance_claim=none\n", state, cases, checks, reason);
    exit(code);
}
#define ASSERT(c) do { checks++; if (!(c)) { fprintf(stderr,"assertion %s:%d %s errno=%d\n",__func__,__LINE__,#c,errno); verdict(1,#c); } } while (0)
#define SETUP(c) do { if (!(c)) { fprintf(stderr,"setup %s:%d %s errno=%d\n",__func__,__LINE__,#c,errno); verdict(2,#c); } } while (0)
static void save(const char *name, const void *data, size_t bytes)
{
    char path[4096];
    SETUP(snprintf(path, sizeof(path), "%s/%s", opt.output, name) < (int)sizeof(path));
    FILE *f = fopen(path, "wx"); SETUP(f);
    SETUP(fwrite(data, 1, bytes, f) == bytes); SETUP(!fclose(f));
}
static int mech(int ring, unsigned op, void *arg)
{
    struct io_uring_xdev_ext_mech m = {.op=op, .arg=(uintptr_t)arg};
    int ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &m, 1);
    return ret < 0 ? -errno : ret;
}
static int stats(struct session *s, struct xdev_ext_mech_stats *st)
{
    memset(st, 0, sizeof(*st)); st->session_id = s->id;
    return mech(s->ring, XDEV_EXT_MECH_OP_STATS, st);
}
static void observe(struct session *s, const char *label, const struct xdev_ext_mech_stats *st)
{
    fprintf(events, "%s %s session=%"PRIu64" done=%llu abort=%llu submitted=%llu completed=%llu published=%llu inflight=%llu rejects=%llu protocol=%llu sequestered=%llu last_err=%d state=%u\n",
        s->name, label, s->id, (unsigned long long)st->batches_done,
        (unsigned long long)st->batches_abort, (unsigned long long)st->submitted[0],
        (unsigned long long)st->completed[0], (unsigned long long)st->published,
        (unsigned long long)st->inflight, (unsigned long long)st->rejects,
        (unsigned long long)st->protocol_err, (unsigned long long)st->sequestered, st->last_err, st->state);
    fflush(events);
}
static void identify_fd(int fd, const char *name, unsigned kind)
{
    char file[128]; uint32_t size;
    if (kind == 0) {
        struct bpf_map_info info = {}; size = sizeof(info);
        SETUP(!bpf_obj_get_info_by_fd(fd, &info, &size));
        snprintf(file, sizeof(file), "%s-map-info.bin", name); save(file, &info, size);
        fprintf(events, "map %s id=%u type=%u key=%u value=%u max=%u\n", name, info.id, info.type, info.key_size, info.value_size, info.max_entries);
        if (!strcmp(name, "blocks")) SETUP(info.type==BPF_MAP_TYPE_HASH && info.key_size==16 && info.value_size==16 && info.max_entries==1024);
    } else if (kind == 1) {
        struct bpf_prog_info info = {}; size = sizeof(info);
        SETUP(!bpf_obj_get_info_by_fd(fd, &info, &size));
        snprintf(file, sizeof(file), "%s-program-info.bin", name); save(file, &info, size);
        fprintf(events, "program %s id=%u type=%u\n", name, info.id, info.type);
    } else {
        struct bpf_link_info info = {}; size = sizeof(info);
        SETUP(!bpf_obj_get_info_by_fd(fd, &info, &size));
        snprintf(file, sizeof(file), "%s-link-info.bin", name); save(file, &info, size);
        fprintf(events, "link %s id=%u type=%u\n", name, info.id, info.type);
    }
}
/* Resolve the original struct_ops member from its genuine BTF, never a guessed offset. */
static void private_flags(struct bpf_object *obj, struct bpf_map *ops)
{
    struct btf *btf = bpf_object__btf(obj); SETUP(btf);
    int id = btf__find_by_name_kind(btf, "xdev_ext_nvme_mech_ops", BTF_KIND_STRUCT);
    SETUP(id > 0);
    const struct btf_type *t = btf__type_by_id(btf, id);
    size_t size = 0; void *value = bpf_map__initial_value(ops, &size);
    SETUP(value && size == t->size);
    unsigned char *copy = malloc(size); SETUP(copy); memcpy(copy, value, size);
    bool found = false;
    for (unsigned n = 0; n < btf_vlen(t); n++) {
        const struct btf_member *member = btf_members(t) + n;
        if (strcmp(btf__name_by_offset(btf, member->name_off), "flags")) continue;
        unsigned bits = btf_member_bit_offset(t, n);
        SETUP(!btf_member_bitfield_size(t, n) && !(bits & 7));
        size_t off = bits / 8; uint32_t flags = 0;
        SETUP(off <= size && sizeof(flags) <= size - off);
        memcpy(&flags, copy + off, sizeof(flags)); SETUP(!flags);
        flags = XDEV_EXT_MECH_OPS_F_PRIVATE; memcpy(copy + off, &flags, sizeof(flags));
        fprintf(events, "struct_ops flags offset=%zu before=0 after=%u only_initial_flags_changed=1\n", off, flags);
        found = true;
    }
    SETUP(found); save("struct-ops-private-initial.bin", copy, size);
    /* Modern libbpf exposes writable struct_ops initial storage. Its generic
     * set_initial_value API is for mmap-backed maps, not struct_ops. */
    memcpy(value, copy, size); free(copy);
}
static struct program load(void)
{
    struct program p = {.blocks=-1};
    char *log = calloc(1, LOG_BYTES); SETUP(log);
    struct bpf_object_open_opts opts = {.sz=sizeof(opts), .kernel_log_buf=log,
        .kernel_log_size=LOG_BYTES, .kernel_log_level=1};
    p.object = bpf_object__open_file(opt.object, &opts);
    SETUP(p.object && !libbpf_get_error(p.object));
    struct bpf_map *ops = bpf_object__find_map_by_name(p.object, "blocktable_ops");
    struct bpf_map *blocks = bpf_object__find_map_by_name(p.object, "blocks");
    SETUP(ops && blocks); private_flags(p.object, ops);
    struct bpf_program *prog;
    struct { struct bpf_program *prog; char *buffer; } logs[2];
    unsigned nr_logs = 0;
    bpf_object__for_each_program(prog, p.object) {
        SETUP(nr_logs < 2);
        logs[nr_logs].prog = prog; logs[nr_logs].buffer = calloc(1, LOG_BYTES);
        SETUP(logs[nr_logs].buffer);
        SETUP(!bpf_program__set_log_buf(prog, logs[nr_logs].buffer, LOG_BYTES));
        SETUP(!bpf_program__set_log_level(prog, 1)); nr_logs++;
    }
    SETUP(nr_logs == 2);
    int ret = bpf_object__load(p.object);
    save("verifier-btf.log", log, strnlen(log, LOG_BYTES)); free(log);
    for (unsigned i = 0; i < nr_logs; i++) {
        char file[128];
        snprintf(file, sizeof(file), "%s-verifier.log", bpf_program__name(logs[i].prog));
        size_t length = strnlen(logs[i].buffer, LOG_BYTES);
        save(file, logs[i].buffer, length); free(logs[i].buffer);
        if (!ret) SETUP(length && length < LOG_BYTES);
    }
    SETUP(!ret);
    p.link = bpf_map__attach_struct_ops(ops); SETUP(p.link && !libbpf_get_error(p.link));
    p.blocks = bpf_map__fd(blocks); SETUP(p.blocks >= 0);
    identify_fd(p.blocks, "blocks", 0);
    identify_fd(bpf_map__fd(ops), "blocktable-ops", 0);
    identify_fd(bpf_link__fd(p.link), "blocktable", 2);
    bpf_object__for_each_program(prog, p.object) identify_fd(bpf_program__fd(prog), bpf_program__name(prog), 1);
    return p;
}
static struct session create(struct program *p, const char *name)
{
    struct session s = {.ring=-1, .name=name};
    struct io_uring_params params = {};
    s.ring = syscall(__NR_io_uring_setup, 8, &params); SETUP(s.ring >= 0);
    s.memory = mmap(NULL, BT_REGISTERED, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
    SETUP(s.memory != MAP_FAILED);
    struct io_uring_xdev_ext_umem_reg reg = {.addr=(uintptr_t)s.memory, .size=BT_REGISTERED, .frame_size=BT_FRAME};
    SETUP(!syscall(__NR_io_uring_register,s.ring,IORING_REGISTER_XDEV_EXT_UMEM,&reg,1));
    int device = open(opt.device, O_RDONLY|O_CLOEXEC); SETUP(device >= 0);
    struct stat ds; SETUP(!fstat(device, &ds) && S_ISCHR(ds.st_mode));
    s.device_rdev = (uint64_t)ds.st_rdev;
    struct xdev_ext_mech_create_programs e = {.size=sizeof(e), .version=XDEV_EXT_MECH_CREATE_PROGRAMS_VERSION,
        .program_fds={bpf_link__fd(p->link), -1, -1, -1}};
    e.request.size = sizeof(e.request); e.request.version = XDEV_EXT_MECH_CREATE_REPORT_VERSION;
    e.request.create = (struct xdev_ext_mech_create){.abi_version=XDEV_EXT_MECH_ABI_VERSION,
        .nr_stages=1,.pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM,.pool_fd=-1,
        .layout={.frame_size=BT_FRAME,.hdr_room=BT_HEADER,.seg_len=BT_GROUP,.group_bytes=BT_GROUP},
        .depth=1,.eventfd=-1};
    e.request.create.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,
        .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=device,.arg0=opt.slba,.arg1=opt.nlb};
    char file[128]; snprintf(file,sizeof(file),"%s-create-before.bin",name); save(file,&e,sizeof(e));
    int ret = mech(s.ring, XDEV_EXT_MECH_OP_CREATE_PROGRAMS, &e);
    snprintf(file,sizeof(file),"%s-create-after.bin",name); save(file,&e,sizeof(e));
    fprintf(events,"%s CREATE return=%d report=%d phase=%u failed_stage=%u cleanup=%u session=%llu device_rdev=%llu device_fd=%d\n",name,ret,e.request.report.result,e.request.report.phase,e.request.report.failed_stage,e.request.report.cleanup,(unsigned long long)e.request.report.session_id,(unsigned long long)ds.st_rdev,device);
    fflush(events);
    SETUP(!ret && !e.request.report.result && e.request.report.size==sizeof(e.request.report) && e.request.report.version==1);
    SETUP(e.request.create.session_id && e.request.create.session_id==e.request.report.session_id);
    s.id=e.request.create.session_id;
    /* The successful subsequent native read must use the session's file pin. */
    SETUP(!close(device)); fprintf(events,"%s closed_original_namespace_fd=%d\n",name,device);
    return s;
}
static void put(struct program *p, struct session *s, uint64_t session, uint64_t key, uint64_t offset, uint32_t length)
{
    struct blocktable_key k = {.session_id=session,.logical_key=key};
    struct blocktable_value v = {.byte_offset=offset,.byte_length=length}, got = {};
    ASSERT(!bpf_map_update_elem(p->blocks,&k,&v,BPF_NOEXIST));
    ASSERT(!bpf_map_lookup_elem(p->blocks,&k,&got)); ASSERT(!memcmp(&v,&got,sizeof(v)));
    fprintf(events,"%s MAP_UPDATE session=%"PRIu64" key=%"PRIu64" offset=%"PRIu64" length=%u reserved=0 readback=exact\n",s->name,session,key,offset,length);
}
static int start(struct session *s, uint64_t key)
{
    uint32_t frame=0;
    struct xdev_ext_mech_start st = {.session_id=s->id,.nr_batches=1,.first_seq=key,
        .flags=XDEV_EXT_MECH_START_F_USER_FRAMES,.nr_user_frames=1,.user_frames=(uintptr_t)&frame};
    int ret=mech(s->ring,XDEV_EXT_MECH_OP_START,&st);
    fprintf(events,"%s START session=%"PRIu64" key=%"PRIu64" frame=0 return=%d\n",s->name,s->id,key,ret); fflush(events);
    return ret;
}
static void batch(struct session *s, uint64_t key, const unsigned char *want, bool negative)
{
    memset(s->memory,BT_POISON,BT_REGISTERED);
    ASSERT(!start(s,key));
    struct xdev_ext_mech_stats st={}; bool finished=false;
    for (unsigned n=0;n<10000;n++) {
        ASSERT(!stats(s,&st));
        if (st.batches_done+st.batches_abort >= s->done+1 && !st.inflight) {finished=true;break;}
        usleep(1000);
    }
    observe(s,"drained",&st); ASSERT(finished);
    char file[128]; snprintf(file,sizeof(file),"%s-key-%"PRIu64"-stats.bin",s->name,key); save(file,&st,sizeof(st));
    snprintf(file,sizeof(file),"%s-key-%"PRIu64"-umem.bin",s->name,key); save(file,s->memory,BT_REGISTERED);
    ASSERT(!st.inflight && !st.sequestered && !st.protocol_err && !st.rejects && !st.timeouts && !st.held);
    for (unsigned i=1;i<XDEV_EXT_MECH_MAX_STAGES;i++) ASSERT(!st.submitted[i]&&!st.completed[i]);
    if (negative) {
        ASSERT(!st.batches_done && st.batches_abort==1 && st.last_err==-ECANCELED);
        ASSERT(!st.submitted[0] && !st.completed[0] && st.published==1);
    } else {
        ASSERT(st.batches_done==s->done+1 && !st.batches_abort && !st.last_err);
        ASSERT(st.submitted[0]==s->done+1 && st.completed[0]==s->done+1 && st.published==s->done+1);
    }
    size_t mismatch=bt_verify(s->memory,want,0);
    if (mismatch!=SIZE_MAX) fprintf(stderr,"%s byte mismatch offset=%zu\n",s->name,mismatch);
    ASSERT(mismatch==SIZE_MAX); s->want=want; s->done++;
}
static void stop(struct session *s, int expected_error)
{
    int ret=mech(s->ring,XDEV_EXT_MECH_OP_STOP,(void *)(uintptr_t)s->id);
    fprintf(events,"%s STOP session=%"PRIu64" return=%d\n",s->name,s->id,ret); fflush(events);
    ASSERT(ret==expected_error);
    struct xdev_ext_mech_stats st; ASSERT(stats(s,&st)==-ENOENT); ASSERT(start(s,900)==-ENOENT);
    ASSERT(bt_verify(s->memory,s->want,0)==SIZE_MAX);
    char file[128]; snprintf(file,sizeof(file),"%s-after-stop-umem.bin",s->name); save(file,s->memory,BT_REGISTERED);
    ASSERT(!close(s->ring)); ASSERT(!munmap(s->memory,BT_REGISTERED)); s->id=0;
}
/* Validate both completed-native snapshots without forbidding STOP state changes. */
static void withdraw_stats(const struct xdev_ext_mech_stats *before,
                           const struct xdev_ext_mech_stats *after)
{
    const struct xdev_ext_mech_stats *snapshots[] = {before, after};
    for (unsigned n = 0; n < 2; n++) {
        const struct xdev_ext_mech_stats *st = snapshots[n];
        ASSERT(!st->held && !st->timeouts && !st->rejects && !st->protocol_err);
        ASSERT(!st->inflight && !st->sequestered);
        ASSERT(st->batches_done==1 && !st->batches_abort && st->published==1);
        ASSERT(st->submitted[0]==1 && st->completed[0]==1);
        for (unsigned i = 1; i < XDEV_EXT_MECH_MAX_STAGES; i++)
            ASSERT(!st->submitted[i] && !st->completed[i]);
    }
    ASSERT(after->recycled==before->recycled);
    ASSERT(after->native_publish==before->native_publish);
    ASSERT(after->last_err==-ECANCELED);
}
#ifdef BLOCKTABLE_PRIVATE_PARALLEL
#include "parallel.h"
#endif
static void runtime(void)
{
#ifdef BLOCKTABLE_PRIVATE_PARALLEL
    parallel_runtime();
#else
    struct program p=load(); uint64_t old_session=0;
    for (unsigned run=0;run<3;run++) {
        struct session s=create(&p,names[run]);
        for(unsigned i=0;i<8;i++) put(&p,&s,s.id,100+i,(uint64_t)slots[run][i]*BT_GROUP,BT_GROUP);
        for(unsigned i=0;i<8;i++) batch(&s,100+i,expected+slots[run][i]*BT_GROUP,false);
        old_session=s.id; stop(&s,0); cases++;
    }
    const char *badnames[]={"missing-entry","outside-window","stale-session","wrong-length"};
    for(unsigned n=0;n<4;n++) {
        struct session s=create(&p,badnames[n]);
        if(n==1) put(&p,&s,s.id,500,8*BT_GROUP,BT_GROUP);
        if(n==2) { ASSERT(old_session!=s.id); put(&p,&s,old_session,500,0,BT_GROUP); }
        if(n==3) put(&p,&s,s.id,500,0,512);
        struct blocktable_key key={s.id,500}; struct blocktable_value value;
        if(n==0||n==2) {errno=0; int ret=bpf_map_lookup_elem(p.blocks,&key,&value); ASSERT(ret<0 && errno==ENOENT);}
        batch(&s,500,NULL,true); stop(&s,-ECANCELED); cases++;
    }
    struct session owner=create(&p,"link-owner"); put(&p,&owner,owner.id,700,2*BT_GROUP,BT_GROUP);
    put(&p,&owner,owner.id,701,4*BT_GROUP,BT_GROUP);
    batch(&owner,700,expected+2*BT_GROUP,false);
    struct xdev_ext_mech_stats before,after; ASSERT(!stats(&owner,&before));
    observe(&owner,"before-link-detach",&before);
    save("link-owner-before-detach-stats.bin",&before,sizeof(before));
    ASSERT(!bpf_link__detach(p.link)); ASSERT(start(&owner,701)==-ESHUTDOWN);
    ASSERT(!stats(&owner,&after)); observe(&owner,"after-link-detach",&after);
    save("link-owner-after-detach-stats.bin",&after,sizeof(after));
    withdraw_stats(&before,&after);
    ASSERT(bt_verify(owner.memory,expected+2*BT_GROUP,0)==SIZE_MAX);
    stop(&owner,-ECANCELED); cases++;
    bpf_link__destroy(p.link); bpf_object__close(p.object);
    verdict(0,"eight-cases-actual-kernel");
#endif
}
static uint64_t number(const char *text)
{
    char *end; errno=0; unsigned long long n=strtoull(text,&end,0);
    if(errno||!*text||*text=='-'||*end) verdict(2,"invalid-integer");
    return n;
}
int main(int argc,char **argv)
{
    static const struct option flags[]={
        {"private-guest",no_argument,NULL,'g'}, {"object",required_argument,NULL,'b'},
        {"device",required_argument,NULL,'d'}, {"window-slba",required_argument,NULL,'s'},
        {"window-nlb",required_argument,NULL,'n'}, {"expected-window",required_argument,NULL,'e'},
        {"output",required_argument,NULL,'o'}, {NULL,0,NULL,0}};
    int c;
    while((c=getopt_long(argc,argv,"",flags,NULL))!=-1) switch(c) {
    case 'g': opt.guest=true;break; case 'b':opt.object=optarg;break; case 'd':opt.device=optarg;break;
    case 's':opt.slba=number(optarg);opt.have_slba=true;break;case 'n':opt.nlb=number(optarg);break;
    case 'e':opt.expected=optarg;break;case 'o':opt.output=optarg;break;default:return 2;
    }
    if(optind!=argc||!opt.guest||!opt.object||!opt.device||!opt.expected||!opt.output||!opt.have_slba||opt.nlb!=64||opt.slba>UINT64_MAX-64) {
        fprintf(stderr,"usage: %s --private-guest --object ORIGINAL.bpf.o --device SOURCE_NG --window-slba N --window-nlb 64 --expected-window FILE --output NEW_DIR\n",argv[0]);
        verdict(2,"explicit-private-guest-and-all-arguments-required");
    }
    SETUP(geteuid()==0);
    /* No device is opened until all input and output checks have succeeded. */
    struct stat st; SETUP(!stat(opt.device,&st) && S_ISCHR(st.st_mode));
    SETUP(!lstat(opt.expected,&st) && S_ISREG(st.st_mode) && st.st_size==(off_t)sizeof(expected));
    FILE *f=fopen(opt.expected,"rb"); SETUP(f); SETUP(fread(expected,1,sizeof(expected),f)==sizeof(expected)); SETUP(!fclose(f));
    for(unsigned i=0;i<8;i++) for(unsigned j=0;j<i;j++) SETUP(memcmp(expected+i*BT_GROUP,expected+j*BT_GROUP,BT_GROUP));
    SETUP(!lstat(opt.object,&st) && S_ISREG(st.st_mode) && st.st_size>0 && st.st_size<16*1024*1024);
    SETUP(!mkdir(opt.output,0700));
    char path[4096]; SETUP(snprintf(path,sizeof(path),"%s/events.log",opt.output)<(int)sizeof(path));
    events=fopen(path,"wx"); SETUP(events); setvbuf(events,NULL,_IOLBF,0);
    save("expected-window.bin",expected,sizeof(expected));
    f=fopen(opt.object,"rb"); SETUP(f); unsigned char *obj=malloc(st.st_size); SETUP(obj);
    SETUP(fread(obj,1,st.st_size,f)==(size_t)st.st_size); SETUP(!fclose(f)); save("original.bpf.o",obj,st.st_size); free(obj);
    struct utsname uts; SETUP(!uname(&uts));
    fprintf(events,"scope=guest-correctness performance=none kernel=%s machine=%s device=%s window_slba=%"PRIu64" window_nlb=%"PRIu64"\n",uts.release,uts.machine,opt.device,opt.slba,opt.nlb);
    runtime(); return 1;
}
