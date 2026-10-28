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
