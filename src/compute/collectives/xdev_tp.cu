// SPDX-License-Identifier: GPL-2.0
#include "xdev_tp_device.h"
using namespace xdev_tp_native;
static __device__ int message_spans(xdev_ext_cuda_message *m, Span *s, bool tx) {
 if(m->status) return m->status;
 if(!m->nr_frames || m->nr_frames>XDEV_EXT_MECH_MAX_FRAMES) return -EPROTO;
 for(unsigned i=0;i<m->nr_frames;++i) {
  if(!m->device_address[i] || !m->f[i].data_len || m->f[i].data_len>m->f[i].capacity) return -EPROTO;
  s[i]={m->device_address[i],m->f[i].data_len};
  if(tx)m->f[i].out_len=m->f[i].data_len;
 }
 return 0;
}
extern "C" __global__ void xdev_tp_pack(DeviceWork *w, Runtime *r, Shape shape, uint64_t input, uint64_t output, uint32_t mode) {
 if(blockIdx.x || threadIdx.x)return;
 w->mode=mode;
 if(w->mode==2) {
  w->shape=shape; w->input=input;w->output=output;
  int rc=w->producer.status;
  if(!rc)rc=begin_invocation(r,&w->core,w->producer.key);
  if(!rc) { w->shape.sequence=w->core.sequence; ++w->invocations;
   if(!w->first_sequence)w->first_sequence=w->core.sequence;w->last_sequence=w->core.sequence;
   rc=message_spans(&w->producer,w->tx,true); w->tx_count=w->producer.nr_frames;
  }
  if(rc) { w->producer.status=fail(r,&w->core,rc);++w->failed;return; }
 }
 int rc=pack(w->shape,reinterpret_cast<const unsigned char *>(w->input),w->tx,w->tx_count);
 if(w->mode==2) {
  if(rc) { w->producer.status=fail(r,&w->core,rc);++w->failed; }
  else { advance(r,&w->core,2,0);w->producer.status=0; }
 } else if(rc) { w->core.error=rc; w->core.state=6; }
}
extern "C" __global__ void xdev_tp_result(DeviceWork *w, Runtime *r) {
 if(blockIdx.x || threadIdx.x)return;
 int rc=0;
 if(w->mode==2) {
  rc=w->producer.status;
  if(!rc)rc=message_spans(&w->receiver,w->rx,false);
  if(!rc)rc=receive(r,&w->core,w->receiver.key,w->receiver.ticket);
  w->rx_count=w->receiver.nr_frames;
  if(!rc)++w->rx_delivered;
 }
 if(!rc)rc=apply_result(r,&w->core,w->shape,reinterpret_cast<const unsigned char *>(w->input),
  reinterpret_cast<unsigned char *>(w->output),w->rx,w->rx_count,w->mode==2?w->receiver.key:w->shape.sequence);
 if(rc) { fail(r,&w->core,rc); ++w->failed; }
 if(w->mode==2)w->receiver.status=rc;
}
extern "C" __global__ void xdev_tp_release(DeviceWork *w, Runtime *r) {
 if(blockIdx.x || threadIdx.x)return;
 int rc=r->error;
 if(!rc && w->receiver.status)rc=w->receiver.status;
 if(!rc && w->terminal.status)rc=w->terminal.status;
 if(!rc && w->terminal.key!=w->core.sequence)rc=-EPROTO;
 if(rc) { fail(r,&w->core,rc); ++w->failed; }
 else { advance(r,&w->core,5,0);++w->completed;++w->tx_done;++w->last_use_released; }
}
