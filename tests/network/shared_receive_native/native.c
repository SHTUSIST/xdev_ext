// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "packets.h"
static int selfcheck(void)
{
    unsigned char output[NATIVE_PACKET_MAX];
    memcpy(output,native_golden,sizeof(native_golden));
    if (!native_result_ok(2,native_golden,sizeof(native_golden),output,sizeof(native_golden))) return 1;
    const unsigned wrong[]={0,1,3,4};
    for(unsigned i=0;i<sizeof(wrong)/sizeof(wrong[0]);i++)
        if(native_result_ok(wrong[i],native_golden,sizeof(native_golden),output,sizeof(native_golden))) {
            fprintf(stderr,"SELFCHECK_RED action=%u incorrectly accepted\n",wrong[i]);return 1;
        }
    if(native_result_ok(2,native_golden,sizeof(native_golden),output,sizeof(native_golden)-1) ||
       native_result_ok(2,native_golden,sizeof(native_golden),output,sizeof(native_golden)+1)) return 1;
    size_t positions[]={0,42,sizeof(native_golden)-1};
    for(unsigned i=0;i<sizeof(positions)/sizeof(positions[0]);i++) {
        output[positions[i]]^=1;
        if(native_result_ok(2,native_golden,sizeof(native_golden),output,sizeof(native_golden))) return 1;
        output[positions[i]]^=1;
    }
    puts("SHARED_XDP_ORACLE_SELFCHECK=PASS rejected_mutations=9 scope=host-output-oracle-only");return 0;
}
#define LOG_BYTES (8U * 1024U * 1024U)
static const char *output_dir;
static FILE *events;
static int xsks=-1, flows=-1, program_fd=-1;
static unsigned passed;
static void finish(int code, const char *reason)
{
    const char *state=code==2?"SETUP_ERROR":code?"BEHAVIOR_RED":"XDP_NATIVE_PASS_PATHS";
    if(program_fd>=0) close(program_fd);
    if(flows>=0) close(flows);
    if(xsks>=0) close(xsks);
    if(events) {
        fprintf(events,"verdict state=%s cases=%u reason=%s\n",state,passed,reason);
        fflush(events);
        char path[4096];
        if(snprintf(path,sizeof(path),"%s/result.json",output_dir)<(int)sizeof(path)) {
            FILE *f=fopen(path,"wx");
            if(f) {
                fprintf(f,"{\"state\":\"%s\",\"exit\":%d,\"cases\":%u,\"positive_redirect\":\"NOT_RUN_NO_BOUND_XSK\",\"optional_filter_selectivity\":\"NOT_OBSERVABLE_WITHOUT_BOUND_XSK\",\"sub_ethernet_frames\":\"NOT_RUN_TEST_RUN_MIN_L2\",\"physical_dma\":false,\"performance\":false}\n",state,code,passed);
                fclose(f);
            }
        }
    }
    fprintf(code?stderr:stdout,"SHARED_XDP_NATIVE state=%s cases=%u reason=%s positive_redirect=NOT_RUN_NO_BOUND_XSK performance=none\n",state,passed,reason);
    exit(code);
}
#define NEED(c,code) do { if(!(c)) {fprintf(stderr,"%s:%d %s errno=%d\n",__func__,__LINE__,#c,errno);finish(code,#c);} } while(0)
static void save(const char *name,const void *data,size_t size)
{
    char path[4096]; NEED(snprintf(path,sizeof(path),"%s/%s",output_dir,name)<(int)sizeof(path),2);
    FILE *f=fopen(path,"wx"); NEED(f,2); NEED(fwrite(data,1,size,f)==size,2); NEED(!fclose(f),2);
}
static struct bpf_map_info map_info(int fd,const char *name,unsigned type,unsigned key,unsigned value)
{
    struct bpf_map_info info={}; uint32_t bytes=sizeof(info);
    NEED(!bpf_obj_get_info_by_fd(fd,&info,&bytes),2);
    NEED(info.type==type && info.id && info.key_size==key && info.value_size==value && info.max_entries==4096,2);
    char file[128]; snprintf(file,sizeof(file),"%s-map-info.bin",name); save(file,&info,bytes);
    fprintf(events,"MAP name=%s fd=%d id=%u type=%u key=%u value=%u max=%u\n",name,fd,info.id,info.type,info.key_size,info.value_size,info.max_entries);
    return info;
}
static void no_flow(void)
{
    struct xdev_ext_xsk_shared_key key;
    errno=0;int ret=bpf_map_get_next_key(flows,NULL,&key);
    NEED(ret<0 && errno==ENOENT,1);
}
static void load_generated(void)
{
    xsks=bpf_map_create(BPF_MAP_TYPE_XSKMAP,"native_xsks",4,4,4096,NULL); NEED(xsks>=0,2);
    flows=bpf_map_create(BPF_MAP_TYPE_HASH,"native_flows",sizeof(struct xdev_ext_xsk_shared_key),sizeof(struct xdev_ext_xsk_shared_flow),4096,NULL); NEED(flows>=0,2);
    struct bpf_map_info xi=map_info(xsks,"xsks",BPF_MAP_TYPE_XSKMAP,4,4);
    struct bpf_map_info fi=map_info(flows,"flows",BPF_MAP_TYPE_HASH,12,24);
    fprintf(events,"XSKMAP empty_by_fresh_creation=1 socket_updates=0 positive_redirect=NOT_RUN_NO_BOUND_XSK\n");
    struct bpf_insn insns[XDEV_EXT_XSK_SHARED_MAX_INSNS]={};size_t count=0;
    int ret=xdev_ext_xsk_shared_build_program(xsks,flows,insns,256,&count);
    fprintf(events,"BUILDER xsk_fd=%d flow_fd=%d capacity=256 return=%d count=%zu\n",xsks,flows,ret,count);
    NEED(!ret && count>0 && count<=256,1); save("generated-insns.bin",insns,count*sizeof(insns[0]));
    char *log=calloc(1,LOG_BYTES); NEED(log,2);
    struct bpf_prog_load_opts opts={.sz=sizeof(opts),.log_buf=log,.log_size=LOG_BYTES,.log_level=1};
    program_fd=bpf_prog_load(BPF_PROG_TYPE_XDP,"shared_rx_check","GPL",insns,count,&opts);
    int load_errno=errno;size_t length=strnlen(log,LOG_BYTES);
    save("verifier.log",log,length);free(log);
    fprintf(events,"PROG_LOAD fd=%d errno=%d verifier_bytes=%zu\n",program_fd,program_fd<0?load_errno:0,length);
    NEED(program_fd>=0,1); NEED(length>0 && length<LOG_BYTES,1);
    uint32_t ids[8]={};struct bpf_prog_info info={.nr_map_ids=8,.map_ids=(uintptr_t)ids};uint32_t bytes=sizeof(info);
    NEED(!bpf_obj_get_info_by_fd(program_fd,&info,&bytes),2);
    save("program-info.bin",&info,bytes); NEED(info.type==BPF_PROG_TYPE_XDP && info.id && info.nr_map_ids<=8,1);
    save("program-map-ids.bin",ids,info.nr_map_ids*sizeof(ids[0]));
    bool have_x=false,have_f=false;
    for(unsigned i=0;i<info.nr_map_ids;i++) {have_x|=ids[i]==xi.id;have_f|=ids[i]==fi.id;}
    NEED(have_x && have_f,1);
    fprintf(events,"PROGRAM id=%u type=%u map_count=%u xsk_id=%u flow_id=%u both_referenced=1\n",info.id,info.type,info.nr_map_ids,xi.id,fi.id);
}
static void run_case(const struct native_case *c)
{
    char file[128]; struct xdev_ext_xsk_shared_flow got={};
    no_flow();
    snprintf(file,sizeof(file),"%s-key.bin",c->name);save(file,&c->key,sizeof(c->key));
    snprintf(file,sizeof(file),"%s-flow.bin",c->name);save(file,&c->flow,sizeof(c->flow));
    if(c->flow_present) {
        NEED(!bpf_map_update_elem(flows,&c->key,&c->flow,BPF_NOEXIST),1);
        NEED(!bpf_map_lookup_elem(flows,&c->key,&got),1);
        NEED(!memcmp(&got,&c->flow,sizeof(got)),1);
        struct xdev_ext_xsk_shared_key first;
        NEED(!bpf_map_get_next_key(flows,NULL,&first),1);NEED(!memcmp(&first,&c->key,sizeof(first)),1);
        struct xdev_ext_xsk_shared_key next;errno=0;int ret=bpf_map_get_next_key(flows,&first,&next);
        NEED(ret<0 && errno==ENOENT,1);
        snprintf(file,sizeof(file),"%s-readback-flow.bin",c->name);save(file,&got,sizeof(got));
    }
    fprintf(events,"CASE name=%s flow_present=%u queue=%u flags=%u bytes=%zu map_update_readback=%s expected_action=2\n",c->name,c->flow_present,c->flow.queue_id,c->flow.flags,c->length,c->flow_present?"exact":"not-inserted");
    unsigned char output[NATIVE_PACKET_MAX];memset(output,0xa6,sizeof(output));
    struct xdp_md context={.data_end=c->length},context_out={};
    struct bpf_test_run_opts opts={.sz=sizeof(opts),.data_in=c->packet,.data_size_in=c->length,
        .data_out=output,.data_size_out=sizeof(output),.ctx_in=&context,.ctx_size_in=sizeof(context),
        .ctx_out=&context_out,.ctx_size_out=sizeof(context_out),.repeat=1};
    snprintf(file,sizeof(file),"%s-input.bin",c->name);save(file,c->packet,c->length);
    snprintf(file,sizeof(file),"%s-context-in.bin",c->name);save(file,&context,sizeof(context));
    int ret=bpf_prog_test_run_opts(program_fd,&opts);int run_errno=errno;
    snprintf(file,sizeof(file),"%s-test-run-opts.bin",c->name);save(file,&opts,sizeof(opts));
    snprintf(file,sizeof(file),"%s-context-out.bin",c->name);save(file,&context_out,sizeof(context_out));
    snprintf(file,sizeof(file),"%s-output.bin",c->name);save(file,output,opts.data_size_out<=sizeof(output)?opts.data_size_out:sizeof(output));
    fprintf(events,"TEST_RUN name=%s return=%d errno=%d retval=%u input=%zu output=%u rx_queue=0 ctx_out=%u\n",c->name,ret,ret?run_errno:0,opts.retval,c->length,opts.data_size_out,opts.ctx_size_out);
    fflush(events);
    NEED(!ret,1); NEED(native_result_ok(opts.retval,c->packet,c->length,output,opts.data_size_out),1);
    if(c->flow_present) {
        NEED(!bpf_map_delete_elem(flows,&c->key),1);errno=0;ret=bpf_map_lookup_elem(flows,&c->key,&got);
        NEED(ret<0 && errno==ENOENT,1);
    }
    no_flow();passed++;
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--selfcheck")) return selfcheck();
    if(argc!=4 || strcmp(argv[1],"--private-guest") || strcmp(argv[2],"--output") || argv[3][0]!='/') {
        fprintf(stderr,"usage: %s --selfcheck | --private-guest --output /absolute/NEW_DIR\n",argv[0]);return 2;
    }
    output_dir=argv[3];NEED(!geteuid(),2);NEED(!mkdir(output_dir,0700),2);
    char path[4096];NEED(snprintf(path,sizeof(path),"%s/events.log",output_dir)<(int)sizeof(path),2);
    events=fopen(path,"wx");NEED(events,2);setvbuf(events,NULL,_IOLBF,0);
    struct utsname u;NEED(!uname(&u),2);
    fprintf(events,"scope=guest-XDP-verifier-test-run kernel=%s machine=%s performance=none\n",u.release,u.machine);
    load_generated();
    struct native_case cases[NATIVE_CASES_MAX]={};size_t count=native_cases(cases);NEED(count==37 && count<=NATIVE_CASES_MAX,2);
    for(size_t i=0;i<count;i++)run_case(&cases[i]);
    finish(0,"all-real-test-run-PASS-paths");return 1;
}
