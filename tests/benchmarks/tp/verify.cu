// SPDX-License-Identifier: GPL-2.0
// Independent GPU input/result oracle; it does not call TP arithmetic helpers.
#include <cuda_fp16.h>
#include <cuda_bf16.h>
#include <stdint.h>
template<class T> __device__ T cast(float x);
template<> __device__ float cast<float>(float x) { return x; }
template<> __device__ __half cast<__half>(float x) { return __float2half_rn(x); }
template<> __device__ __nv_bfloat16 cast<__nv_bfloat16>(float x) { return __float2bfloat16_rn(x); }
template<class T> __device__ float value(T x) { return float(x); }
__device__ float fixture(uint64_t i, unsigned rank, uint64_t seed) {
 return float((rank+1)*16+(seed%8)+(i%8));
}
template<class T> __device__ void fill(T *p,uint64_t n,unsigned rank,uint64_t seed) {
 for(uint64_t i=blockIdx.x*blockDim.x+threadIdx.x;i<n;i+=blockDim.x*gridDim.x)
  p[i]=cast<T>(fixture(i,rank,seed));
}
template<class T> __device__ void check(const T *p,uint64_t rows,uint64_t width,
 unsigned operation,uint64_t seed,unsigned *bad) {
 uint64_t n=rows*width*(operation==1?1:2);
 for(uint64_t i=blockIdx.x*blockDim.x+threadIdx.x;i<n;i+=blockDim.x*gridDim.x) {
  float expected;
  if(operation==1) expected=fixture(i,0,seed)+fixture(i,1,seed);
  else { uint64_t row=i/(2*width), col=i%(2*width);
   expected=fixture(row*width+col%width,unsigned(col/width),seed); }
  if(value(p[i])!=expected) atomicAdd(bad,1U);
 }
}
extern "C" __global__ void tp_eval_fill(void *input,uint64_t n,unsigned dtype,unsigned rank,uint64_t seed) {
 if(dtype==1)fill((__half*)input,n,rank,seed);
 else if(dtype==2)fill((__nv_bfloat16*)input,n,rank,seed);
 else fill((float*)input,n,rank,seed);
}
extern "C" __global__ void tp_eval_check(const void *output,uint64_t rows,uint64_t width,
 unsigned dtype,unsigned operation,uint64_t seed,unsigned *bad) {
 if(dtype==1)check((const __half*)output,rows,width,operation,seed,bad);
 else if(dtype==2)check((const __nv_bfloat16*)output,rows,width,operation,seed,bad);
 else check((const float*)output,rows,width,operation,seed,bad);
}

// Opaque-message echo oracle, independent of TP headers/arithmetic. Every
// received byte is checked on the GPU against its global message offset.
extern "C" __global__ void tp_eval_echo_fill(unsigned char *p,uint64_t n,uint64_t offset,uint64_t seed) {
 for(uint64_t i=blockIdx.x*blockDim.x+threadIdx.x;i<n;i+=blockDim.x*gridDim.x)
  p[i]=unsigned((seed%251+(offset+i)%251)%251);
}
extern "C" __global__ void tp_eval_echo_check(const unsigned char *p,uint64_t n,uint64_t offset,uint64_t seed,unsigned *bad) {
 for(uint64_t i=blockIdx.x*blockDim.x+threadIdx.x;i<n;i+=blockDim.x*gridDim.x)
  if(p[i]!=unsigned((seed%251+(offset+i)%251)%251))atomicAdd(bad,1U);
}

#include "echo_device.h"
// One thread owns control validation and the complete opaque message. Stream
// ordering gives every native done a completed validation/copy predecessor.
extern "C" __global__ void tp_eval_echo_gpu_begin(tp_eval_echo_gpu_state *s) {
 if(blockIdx.x || threadIdx.x)return;
 s->error=0;s->mismatch=0;
}
extern "C" __global__ void tp_eval_echo_gpu_produce(tp_eval_echo_gpu_state *s) {
 if(blockIdx.x || threadIdx.x)return;
 bool valid=tp_echo_message(s,&s->tx,s->tx_base,&s->last_tx_ticket);
 if(valid && !s->error) {
  uint64_t offset=0;
  for(unsigned i=0;i<s->tx.nr_frames;++i) {
   auto *p=reinterpret_cast<unsigned char *>(s->tx.device_address[i]);
   for(unsigned j=0;j<s->tx.f[i].data_len;++j)p[j]=tp_echo_byte(offset+j,s->invocation);
   offset+=s->tx.f[i].data_len;
  }
 }
 tp_echo_status(s,&s->tx);
}
extern "C" __global__ void tp_eval_echo_gpu_consume(tp_eval_echo_gpu_state *s) {
 if(blockIdx.x || threadIdx.x)return;
 // Validate every RX and TX descriptor before dereferencing any payload.
 bool valid=tp_echo_message(s,&s->rx,s->rx_base,&s->last_rx_ticket);
 if(s->rank==1) {
  bool tx_valid=tp_echo_message(s,&s->tx,s->tx_base,&s->last_tx_ticket);
  valid=valid && tx_valid;
  if(valid) {
   if(s->rx.nr_frames!=s->tx.nr_frames){tp_echo_fail(s,-EMSGSIZE);valid=false;}
   else for(unsigned i=0;i<s->rx.nr_frames;++i)
    if(s->rx.f[i].data_len!=s->tx.f[i].data_len){tp_echo_fail(s,-EMSGSIZE);valid=false;}
  }
 }
 if(valid && !s->error) {
  uint64_t offset=0;
  for(unsigned i=0;i<s->rx.nr_frames;++i) {
   const auto *p=reinterpret_cast<const unsigned char *>(s->rx.device_address[i]);
   for(unsigned j=0;j<s->rx.f[i].data_len;++j)
    if(p[j]!=tp_echo_byte(offset+j,s->invocation))++s->mismatch;
   offset+=s->rx.f[i].data_len;
  }
  if(s->mismatch)tp_echo_fail(s,-EILSEQ);
  if(s->rank==1 && !s->error) {
   for(unsigned i=0;i<s->rx.nr_frames;++i) {
    const auto *r=reinterpret_cast<const unsigned char *>(s->rx.device_address[i]);
    auto *t=reinterpret_cast<unsigned char *>(s->tx.device_address[i]);
    for(unsigned j=0;j<s->rx.f[i].data_len;++j)t[j]=r[j];
   }
  }
 }
 tp_echo_status(s,&s->rx);
 // rank0's producer is already done; only rank1 still owns this TX control.
 if(s->rank==1)tp_echo_status(s,&s->tx);
}
extern "C" __global__ void tp_eval_echo_gpu_terminal(tp_eval_echo_gpu_state *s) {
 if(blockIdx.x || threadIdx.x)return;
 tp_echo_message(s,&s->terminal,s->tx_base,&s->last_terminal_ticket);
 // A done kernel can itself reject an earlier control publication.
 if(s->tx.status)tp_echo_fail(s,s->tx.status);
 if(s->rx.status)tp_echo_fail(s,s->rx.status);
 if(!s->error && s->invocation==UINT64_MAX)tp_echo_fail(s,-EOVERFLOW);
 tp_echo_status(s,&s->terminal);
 if(!s->error)++s->invocation;
}
