// SPDX-License-Identifier: GPL-2.0
#ifndef TP_EVAL_ECHO_DEVICE_H
#define TP_EVAL_ECHO_DEVICE_H
#include "../../../src/compute/cuda/libxdev_ext_cuda.h"
#include <stdint.h>
#include <errno.h>

// Control observations only: no host copy of this state stages payload.
struct tp_eval_echo_gpu_state {
 xdev_ext_cuda_message tx, rx, terminal;
 uint64_t first_sequence, invocation;
 uint64_t tx_base, rx_base, allocation_bytes;
 unsigned group_bytes, frame_size, rank;
 unsigned mismatch;
 int error;
 uint64_t last_tx_ticket, last_rx_ticket, last_terminal_ticket;
};

#if defined(__CUDACC__) || defined(__device__)
static __device__ void tp_echo_fail(tp_eval_echo_gpu_state *s,int error) {
 if(!s->error)s->error=error<0?error:-EIO;
}
static __device__ bool tp_echo_allocations(tp_eval_echo_gpu_state *s) {
 if(!s->tx_base || !s->rx_base || !s->allocation_bytes || !s->frame_size ||
    !s->group_bytes || s->rank>1 ||
    s->tx_base>UINT64_MAX-s->allocation_bytes || s->rx_base>UINT64_MAX-s->allocation_bytes)
  return false;
 return s->tx_base+s->allocation_bytes<=s->rx_base ||
        s->rx_base+s->allocation_bytes<=s->tx_base;
}
static __device__ bool tp_echo_message(tp_eval_echo_gpu_state *s,xdev_ext_cuda_message *m,
                                      uint64_t base,uint64_t *last_ticket) {
 if(m->status || !m->ticket || m->ticket<=*last_ticket ||
    s->invocation>UINT64_MAX-s->first_sequence ||
    m->key!=s->first_sequence+s->invocation ||
    !m->nr_frames || m->nr_frames>XDEV_EXT_MECH_MAX_FRAMES || !tp_echo_allocations(s)) {
  tp_echo_fail(s,m->status<0?m->status:-EPROTO);return false;
 }
 uint64_t total=0;
 for(unsigned i=0;i<m->nr_frames;++i) {
  const auto &f=m->f[i];
  if(!f.data_len || f.umem_addr%s->frame_size || f.data_off>s->frame_size ||
     f.capacity>s->frame_size-f.data_off || f.data_len>f.capacity ||
     f.umem_addr>s->allocation_bytes || s->frame_size>s->allocation_bytes-f.umem_addr) {
   tp_echo_fail(s,-ERANGE);return false;
  }
  uint64_t offset=f.umem_addr+f.data_off;
  if(base>UINT64_MAX-offset || f.capacity>UINT64_MAX-(base+offset) ||
     m->device_address[i]!=base+offset || total>s->group_bytes ||
     f.data_len>s->group_bytes-total) {
   tp_echo_fail(s,-ERANGE);return false;
  }
  total+=f.data_len;
 }
 if(total!=s->group_bytes){tp_echo_fail(s,-EMSGSIZE);return false;}
 *last_ticket=m->ticket;
 return true;
}
static __device__ unsigned char tp_echo_byte(uint64_t offset,uint64_t seed) {
 return static_cast<unsigned char>((seed%251+offset%251)%251);
}
static __device__ void tp_echo_status(tp_eval_echo_gpu_state *s,xdev_ext_cuda_message *m) {
 if(s->error)m->status=s->error;
}
#endif
#endif
