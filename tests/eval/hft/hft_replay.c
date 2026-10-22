/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "hft_runtime.h"
static void *actor(void *arg)
{
 struct hft_actor *a=arg;
 if(!strcmp(a->c->backend,"posix")) a->result=hft_posix(a);
 else if(!strcmp(a->c->backend,"uring-fixed-zc")) a->result=hft_uring(a);
 else a->result=hft_session(a);
 return NULL;
}
/* Private producer interface, validated a second time after the Python CLI. */
static uint64_t number(const char *s)
{
 char *end;uint64_t n;
 if(!*s) exit(2);
 for(const char *p=s;*p;p++) if(*p<'0'||*p>'9') exit(2);
 errno=0;n=strtoull(s,&end,10);if(errno||*end) exit(2);return n;
}
int main(int argc,char **argv)
{
 struct hft_config c={0};struct hft_actor actors[4]={0};pthread_t threads[4];pthread_barrier_t barrier;
 struct hft_counts sum={0};unsigned made=0;int ret=0;_Atomic int startup_error=0;
 if(argc==3 && !strcmp(argv[1],"--source-info"))return hft_source_info(argv[2]);
 if(argc!=29 && argc!=30) {fprintf(stderr,"private producer: use run.py\n");return 2;}
 c.backend=argv[1];c.reference=argv[2];c.record=number(argv[3]);c.payload=number(argv[4]);
 c.burst=number(argv[5]);c.depth=number(argv[6]);c.bursts=number(argv[7]);c.actors=number(argv[8]);c.seed=number(argv[9]);
 c.peer_ip=argv[10];c.peer_port=number(argv[11]);c.control_ip=argv[12];c.control_port=number(argv[13]);
 c.source_block=*argv[14]?argv[14]:NULL;c.source_ng=*argv[15]?argv[15]:NULL;c.slba=number(argv[16]);c.nlb=number(argv[17]);
 c.ifname=argv[18];c.queue=number(argv[19]);c.local_ip=argv[20];c.local_mac=argv[21];c.peer_mac=argv[22];c.local_port=number(argv[23]);
 c.bpf_object=argv[24];c.kernel_config=argv[25];c.source_offset=number(argv[26]);c.session_base=number(argv[28]);
 c.measured=!strcmp(argv[27],"hardware");c.probe=!strcmp(argv[27],"probe");
 if(argc==30)c.warmup=number(argv[29]);
 if((strcmp(argv[27],"correctness") && !c.measured && !c.probe) || (c.measured && (argc!=30||c.actors!=1||c.warmup>=c.bursts)) || (strcmp(c.backend,"posix")&&strcmp(c.backend,"uring-fixed-zc")&&strcmp(c.backend,"session")) ||
    (c.record!=64&&c.record!=128&&c.record!=256)||(c.payload!=512&&c.payload!=1024&&c.payload!=4096)||c.payload%c.record||
    !c.burst||c.burst>32||!c.depth||c.depth>8||!c.bursts||c.bursts>32||(c.actors!=1&&c.actors!=4)||
    !c.session_base||c.session_base>UINT64_MAX-(c.actors-1)||!c.peer_port||c.peer_port>65535||!c.control_port||c.control_port>65535) return 2;
 if((c.measured||c.probe) && (!c.source_block || c.actors!=1 || (c.probe && strcmp(c.backend,"session")))) {
  fputs("{\"status\":\"not_run_hardware\",\"start_issued\":false,\"diagnostic\":\"physical mode requires raw source and central hardware_measure.py entry\"}\n",stderr);return 4;
 }
 if(c.source_block && hft_source_geometry(&c)) {
  fputs("{\"status\":\"not_run_capability\",\"start_issued\":false,\"diagnostic\":\"explicit source DIO/LBA geometry unavailable\"}\n",stderr);return 4;
 }
 if(!strcmp(c.backend,"session") && hft_session_gate(&c)) {
  fputs("{\"status\":\"not_run_hardware\",\"start_issued\":false,\"diagnostic\":\"native gates unavailable\"}\n",stderr);return 4;
 }
 if(pthread_barrier_init(&barrier,NULL,c.actors)) return 1;
 for(unsigned i=0;i<c.actors;i++) {
  actors[i]=(struct hft_actor){.c=&c,.id=i,.barrier=&barrier,.startup_error=&startup_error};
  if(pthread_create(&threads[i],NULL,actor,&actors[i])) {fputs("actor creation failed\n",stderr);_Exit(1);}
  made++;
 }
 for(unsigned i=0;i<made;i++) {
  pthread_join(threads[i],NULL);
  if(actors[i].result && (!ret||actors[i].result==1)) ret=actors[i].result;
  sum.reads+=actors[i].counts.reads;sum.sends+=actors[i].counts.sends;
  sum.read_cqes+=actors[i].counts.read_cqes;sum.result_cqes+=actors[i].counts.result_cqes;
  sum.notif_cqes+=actors[i].counts.notif_cqes;sum.copied+=actors[i].counts.copied;
  sum.registrations+=actors[i].counts.registrations;
 }
 pthread_barrier_destroy(&barrier);
 if(ret) {
  fprintf(stderr,"{\"status\":\"%s\",\"start_issued\":%s,\"diagnostic\":\"backend failed; no success record\"}\n",ret==4?"not_run_capability":"error",ret==4?"false":"true");return ret;
 }
 printf("{\"read_submissions\":%"PRIu64",\"send_submissions\":%"PRIu64",\"read_cqes\":%"PRIu64",\"send_result_cqes\":%"PRIu64",\"send_notif_cqes\":%"PRIu64",\"zc_copied_packets\":%"PRIu64",\"registration_calls\":%"PRIu64",\"guards_ok\":true,\"local_release_complete\":true",sum.reads,sum.sends,sum.read_cqes,sum.result_cqes,sum.notif_cqes,sum.copied,sum.registrations);
 if(!strcmp(c.backend,"session")) {
  const struct hft_native_stats *s=&actors[0].native;
  printf(",\"stop_ret\":%d,\"session_stats\":{\"batches_done\":%"PRIu64",\"read_submitted\":%"PRIu64",\"read_completed\":%"PRIu64",\"send_submitted\":%"PRIu64",\"send_completed\":%"PRIu64",\"state\":\"%s\",\"batches_abort\":%"PRIu64",\"rejects\":%"PRIu64",\"sequestered\":%"PRIu64",\"timeouts\":%"PRIu64",\"protocol_err\":%"PRIu64",\"last_err\":%d,\"inflight\":%"PRIu64"}",s->stop_ret,s->batches_done,s->read_submitted,s->read_completed,s->send_submitted,s->send_completed,s->state==1?"ACTIVE":"UNKNOWN",s->batches_abort,s->rejects,s->sequestered,s->timeouts,s->protocol_err,s->last_err,s->inflight);
 }
 if(!strcmp(c.backend,"session") && !c.probe) printf(",\"native_runtime\":{\"xdp_zero_copy\":%s,\"strict_create\":%s,\"nvme_map_id\":%u,\"afxdp_map_id\":%u}",actors[0].native_xdp_zc?"true":"false",actors[0].native_create?"true":"false",actors[0].nvme_map_id,actors[0].afxdp_map_id);
 if(c.probe) printf(",\"probe\":{\"xdp_zero_copy\":%s,\"strict_create\":%s,\"nvme_map_id\":%u,\"afxdp_map_id\":%u}",actors[0].native_xdp_zc?"true":"false",actors[0].native_create?"true":"false",actors[0].nvme_map_id,actors[0].afxdp_map_id);
 if(c.measured) {
  const struct hft_timing *t=&actors[0].timing;
  printf(",\"measurements\":{\"clock\":\"CLOCK_MONOTONIC_RAW\",\"setup_started_ns\":%"PRIu64",\"setup_completed_ns\":%"PRIu64",\"teardown_started_ns\":%"PRIu64",\"teardown_completed_ns\":%"PRIu64",\"samples\":[",t->setup_started,t->setup_completed,t->teardown_started,t->teardown_completed);
  for(unsigned b=c.warmup;b<c.bursts;b++) {
   const struct hft_burst_sample *s=&t->samples[b];
   printf("%s{\"burst\":%u,\"first_generation\":%"PRIu64",\"packet_count\":%u,\"validated_packets\":%u,\"validated_bytes\":%u,\"read_submissions\":%"PRIu64",\"send_submissions\":%"PRIu64",\"started_ns\":%"PRIu64",\"local_release_ns\":%"PRIu64",\"peer_receipt_ns\":%"PRIu64",\"completed_ns\":%"PRIu64",\"elapsed_ns\":%"PRIu64",\"local_release_complete\":true,\"receiver_receipt\":true,\"guards_ok\":true}",b==c.warmup?"":",",b-c.warmup,s->first,c.burst,c.burst,c.burst*c.payload,s->reads,s->sends,s->started,s->local_release,s->peer_receipt,s->completed,s->completed-s->started);
  }
  fputs("]}",stdout);
 }
 puts("}");
 return 0;
}
