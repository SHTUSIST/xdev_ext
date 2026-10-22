/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HFT_RUNTIME_H
#define HFT_RUNTIME_H
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>
#include "hft_core.h"
struct hft_config {
 const char *backend,*reference,*source_block,*source_ng,*ifname,*bpf_object,*kernel_config;
 const char *local_ip,*peer_ip,*local_mac,*peer_mac,*control_ip;
 unsigned record,payload,burst,depth,bursts,actors,peer_port,control_port,queue,local_port;
 unsigned measured,probe,warmup;
 uint64_t seed,slba,nlb,source_offset,session_base;
};
struct hft_counts { uint64_t reads,sends,read_cqes,result_cqes,notif_cqes,copied,registrations; };
struct hft_native_stats {
 uint64_t batches_done,batches_abort,rejects,sequestered,timeouts,protocol_err,inflight;
 uint64_t read_submitted,read_completed,send_submitted,send_completed;
 int last_err,state,stop_ret;
};
struct hft_burst_sample {
 uint64_t started,local_release,peer_receipt,completed,first,reads,sends,start_reads,start_sends;
};
struct hft_timing { uint64_t setup_started,setup_completed,teardown_started,teardown_completed;struct hft_burst_sample samples[32]; };
struct hft_actor {
 const struct hft_config *c; unsigned id;
 pthread_barrier_t *barrier;
 _Atomic int *startup_error;
 struct hft_counts counts;
 struct hft_native_stats native;
 struct hft_timing timing;
 unsigned native_xdp_zc,native_create,nvme_map_id,afxdp_map_id;
 int result; /* 0 success, 4 capability, 1 execution error */
};
struct hft_buffer { unsigned char *allocation,*payload; size_t bytes; struct hft_slot life; unsigned group; };
void hft_setup_begin(struct hft_actor *a);
void hft_setup_done(struct hft_actor *a);
void hft_burst_begin(struct hft_actor *a,unsigned burst);
void hft_burst_release(struct hft_actor *a,unsigned burst);
void hft_burst_done(struct hft_actor *a,unsigned burst);
void hft_teardown_begin(struct hft_actor *a);
void hft_teardown_done(struct hft_actor *a);
int hft_source_info(const char *path);
int hft_source_geometry(const struct hft_config *c);
int hft_allocate(struct hft_buffer *b,unsigned index,unsigned payload);
int hft_buffer_ok(const struct hft_buffer *b,unsigned payload);
int hft_encode(struct hft_buffer *b,const struct hft_actor *a,unsigned group);
int hft_data_connect(const struct hft_config *c);
int hft_connect(const char *ip,unsigned port);
int hft_receipt(int fd,const struct hft_actor *a,unsigned first);
int hft_posix(struct hft_actor *a);
int hft_uring(struct hft_actor *a);
int hft_session(struct hft_actor *a);
int hft_session_gate(const struct hft_config *c);
#endif
