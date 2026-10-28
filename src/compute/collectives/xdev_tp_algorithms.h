/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_TP_ALGORITHMS_H
#define XDEV_TP_ALGORITHMS_H
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include "xdev_tp_wire.h"
#ifdef __CUDACC__
#define TP_HD __host__ __device__
#else
#define TP_HD
#endif
namespace xdev_tp_native {
struct Shape {
 uint64_t communicator_id, epoch, sequence, rows, width;
 uint32_t operation, dtype, rank, world_size, dst_rank;
 uint64_t elements, payload_bytes, output_bytes, wire_bytes;
};
struct Span { uint64_t address, bytes; };
struct MemoryFacts {
 uint64_t address, bytes, allocation_base, allocation_bytes, context;
 uint32_t device_memory, managed;
};
struct Qualification {
 uint64_t context, stream_context, sequence, next_sequence, max_payload, slot_capacity;
 uint32_t mode, depth, capturing;
 MemoryFacts input, output;
};
struct TraceRecord {
 uint64_t sequence, timestamp, payload_bytes, wire_bytes, logical_inflight;
 uint32_t rank, kind, clock, operation;
 int32_t error;
 uint32_t reserved;
};
struct Runtime {
 uint64_t next_sequence, invocations, completed, failed, first_sequence, last_sequence;
 uint64_t inflight, high_water, last_rx_ticket;
 int32_t error;
 uint64_t trace_address, trace_count, trace_dropped;
 uint32_t trace_capacity;
};
struct WorkCore { uint32_t state; int32_t error; uint64_t sequence; };
TP_HD inline uint32_t item_size(uint32_t dtype) { return dtype == 3 ? 4 : dtype == 1 || dtype == 2 ? 2 : 0; }
TP_HD inline int product(uint64_t a, uint64_t b, uint64_t *out) {
 if (b && a > UINT64_MAX / b) return -EOVERFLOW;
 *out = a * b; return 0;
}
TP_HD inline int shape_validate(Shape *s, uint64_t max_payload, uint64_t slot_capacity) {
 if (!s || !s->communicator_id || !s->epoch || !s->sequence || s->rank > 1 || s->world_size != 2 ||
     !item_size(s->dtype) || s->operation < 1 || s->operation > 3 ||
     (s->operation == 1 && s->rows != 1) || (s->operation == 2 && s->dst_rank > 1)) return -EINVAL;
 uint64_t output_elements;
 int rc = product(s->rows, s->width, &s->elements);
 if (!rc) rc = product(s->elements, item_size(s->dtype), &s->payload_bytes);
 if (!rc) rc = product(s->elements, s->operation == 1 ? 1 : 2, &output_elements);
 if (!rc) rc = product(output_elements, item_size(s->dtype), &s->output_bytes);
 if (rc) return rc;
 if (s->payload_bytes > UINT32_MAX || s->payload_bytes > UINT64_MAX - 64) return -EOVERFLOW;
 s->wire_bytes = 64 + s->payload_bytes;
 if (s->payload_bytes > max_payload || s->wire_bytes > slot_capacity) return -EMSGSIZE;
 return 0;
}
TP_HD inline int memory_validate(const MemoryFacts &m, uint64_t bytes, uint64_t context) {
 if (!bytes) return 0;
 if (!m.address || !m.device_memory || m.managed || m.context != context ||
     m.address < m.allocation_base || m.address - m.allocation_base > m.allocation_bytes ||
     bytes > m.allocation_bytes - (m.address - m.allocation_base) || bytes > m.bytes ||
     m.address > UINT64_MAX - bytes) return -EINVAL;
 return 0;
}
TP_HD inline int qualify(Shape *s, const Qualification &q) {
 if (!q.context || q.stream_context != q.context || q.sequence != q.next_sequence || s->sequence != q.sequence ||
     !q.depth || (q.mode != 1 && q.mode != 2)) return -EINVAL;
 if (q.mode == 1 && (q.capturing || q.depth != 1)) return -EOPNOTSUPP;
 int rc = shape_validate(s, q.max_payload, q.slot_capacity);
 if (rc) return rc;
 if ((rc = memory_validate(q.input, s->payload_bytes, q.context))) return rc;
 bool output_needed = s->operation != 2 || s->rank == s->dst_rank;
 if (output_needed && (rc = memory_validate(q.output, s->output_bytes, q.context))) return rc;
 if (q.output.address && s->output_bytes) {
  if ((rc = memory_validate(q.output, s->output_bytes, q.context))) return rc;
  if (s->payload_bytes && q.input.address < q.output.address + s->output_bytes &&
      q.output.address < q.input.address + s->payload_bytes) return -EINVAL;
 }
 return 0;
}
TP_HD inline void put_le(unsigned char *p, uint64_t x, unsigned n) { for (unsigned i=0;i<n;++i) p[i]=(unsigned char)(x>>(8*i)); }
TP_HD inline uint64_t get_le(const unsigned char *p, unsigned n) { uint64_t x=0; for(unsigned i=0;i<n;++i)x|=uint64_t(p[i])<<(8*i); return x; }
TP_HD inline void encode_header(const Shape &s, unsigned char *h) {
 put_le(h, XDEV_TP_WIRE_MAGIC,8); put_le(h+8,s.communicator_id,8); put_le(h+16,s.epoch,8);
 put_le(h+24,s.sequence,8); put_le(h+32,s.rows,8); put_le(h+40,s.width,8); put_le(h+48,s.payload_bytes,4);
 put_le(h+52,1,2); put_le(h+54,64,2); h[56]=(unsigned char)s.operation; h[57]=(unsigned char)s.dtype;
 h[58]=(unsigned char)s.rank; h[59]=2; put_le(h+60,0,4);
}
TP_HD inline int validate_header(const Shape &local, const unsigned char *h) {
 if (get_le(h,8)!=XDEV_TP_WIRE_MAGIC || get_le(h+8,8)!=local.communicator_id ||
 get_le(h+16,8)!=local.epoch || get_le(h+24,8)!=local.sequence || get_le(h+32,8)!=local.rows ||
 get_le(h+40,8)!=local.width || get_le(h+48,4)!=local.payload_bytes || get_le(h+52,2)!=1 ||
 get_le(h+54,2)!=64 || h[56]!=local.operation || h[57]!=local.dtype || h[58]!=(local.rank^1) ||
 h[59]!=2 || get_le(h+60,4)) return -EPROTO;
 return 0;
}
TP_HD inline int span_capacity(const Span *spans, uint32_t count, uint64_t *bytes) {
 *bytes=0; if (!spans || !count) return -EINVAL;
 for(uint32_t i=0;i<count;++i) {
  if (!spans[i].address || spans[i].address>UINT64_MAX-spans[i].bytes || *bytes>UINT64_MAX-spans[i].bytes) return -EOVERFLOW;
  *bytes+=spans[i].bytes;
 }
 return 0;
}
TP_HD inline unsigned char *span_address(const Span *spans, uint32_t count, uint64_t offset) {
 for(uint32_t i=0;i<count;++i) { if(offset<spans[i].bytes) return reinterpret_cast<unsigned char *>(spans[i].address+offset); offset-=spans[i].bytes; }
 return nullptr;
}
/* Prefix bounds are prepared once per real message. Payload lanes use at most
 * log2(32)+1 comparisons per span lookup rather than rescanning all frames. */
constexpr uint32_t max_spans = 32;
struct SpanIndex {
 uint64_t end[max_spans], bytes;
 uint32_t count;
};
TP_HD inline int index_spans(const Span *spans, uint32_t count, SpanIndex *index) {
 if (!index || count > max_spans) return -E2BIG;
 uint64_t bytes;
 int rc = span_capacity(spans, count, &bytes);
 if (rc) return rc;
 index->bytes = bytes;
 index->count = count;
 uint64_t end = 0;
 for (uint32_t i = 0; i < count; ++i) {
  end += spans[i].bytes;
  index->end[i] = end;
 }
 return 0;
}
TP_HD inline unsigned char *indexed_address(const Span *spans,
 const SpanIndex &index, uint64_t offset) {
 uint32_t low = 0, high = index.count;
 while (low < high) {
  uint32_t mid = low + (high - low) / 2;
  if (offset < index.end[mid]) high = mid;
  else low = mid + 1;
 }
 if (low == index.count) return nullptr;
 uint64_t start = low ? index.end[low - 1] : 0;
 return reinterpret_cast<unsigned char *>(spans[low].address + offset - start);
}
TP_HD inline int prepare_pack(const Shape &s, const unsigned char *input,
 const Span *spans, uint32_t count, SpanIndex *index) {
 int rc = index_spans(spans, count, index);
 if (rc) return rc;
 if (index->bytes < s.wire_bytes || (s.payload_bytes && !input)) return -EMSGSIZE;
 unsigned char header[64];
 encode_header(s, header);
 for (unsigned i = 0; i < 64; ++i)
  *indexed_address(spans, *index, i) = header[i];
 return 0;
}
TP_HD inline void pack_partition(const Shape &s, const unsigned char *input,
 const Span *spans, const SpanIndex &index, uint64_t lane, uint64_t lanes) {
 if (!lanes || lane >= lanes || lane > UINT64_MAX - 64) return;
 uint64_t offset = 64 + lane;
 while (offset < index.bytes) {
  *indexed_address(spans, index, offset) =
   offset < s.wire_bytes ? input[offset - 64] : 0;
  if (index.bytes - offset <= lanes) break;
  offset += lanes;
 }
}
TP_HD inline int pack(const Shape &s, const unsigned char *input,
 const Span *spans, uint32_t count) {
 SpanIndex index{};
 int rc = prepare_pack(s, input, spans, count, &index);
 if (!rc) pack_partition(s, input, spans, index, 0, 1);
 return rc;
}
union FloatBits { float f; uint32_t u; };
TP_HD inline float decode(uint32_t dtype, uint32_t bits) {
 FloatBits v{};
 if(dtype==3) { v.u=bits; return v.f; }
 if(dtype==2) { v.u=bits<<16; return v.f; }
 uint32_t sign=(bits&0x8000)<<16, exp=(bits>>10)&31, frac=bits&1023;
 if(!exp) { if(!frac) v.u=sign; else { int e=-14; while(!(frac&1024)){frac<<=1;--e;} v.u=sign|uint32_t(e+127)<<23|(frac&1023)<<13; } }
 else if(exp==31) v.u=sign|0x7f800000U|(frac<<13);
 else v.u=sign|((exp+112)<<23)|(frac<<13);
 return v.f;
}
TP_HD inline uint32_t encode(uint32_t dtype, float f) {
 FloatBits v{}; v.f=f; uint32_t bits=v.u;
 if(dtype==3) return bits;
 if(dtype==2) { if((bits&0x7fffffff)>0x7f800000U) return (bits>>16)|0x40U; return (bits+0x7fffU+((bits>>16)&1))>>16; }
 uint32_t sign=(bits>>16)&0x8000U, abs=bits&0x7fffffff;
 if(abs>=0x7f800000U) return sign|0x7c00U|(abs>0x7f800000U?0x200U:0);
 if(abs>=0x477ff000U) return sign|0x7c00U;
 if(abs<0x33000000U) return sign;
 int exp=int((abs>>23)&255)-127;
 uint32_t mant=(abs&0x7fffffU)|0x800000U;
 unsigned shift=exp < -14 ? unsigned(-exp-1) : 13;
 uint32_t truncated=mant>>shift, mask=(uint32_t(1)<<shift)-1, rem=mant&mask, half=uint32_t(1)<<(shift-1);
 if(rem>half || (rem==half && (truncated&1))) ++truncated;
 if(exp < -14) return sign|truncated;
 return sign | (uint32_t(exp + 14) * 1024 + truncated);
}
TP_HD inline uint32_t sum_element(uint32_t dtype, uint32_t a, uint32_t b) { return encode(dtype,decode(dtype,a)+decode(dtype,b)); }
TP_HD inline uint64_t gather_index(uint64_t row, uint64_t column, uint64_t width, uint32_t rank) { return row*(2*width)+rank*width+column; }
/* Preparation is a separate CUDA stream phase. A rejected complete header
 * prevents every later payload lane from reading peer data or writing output. */
TP_HD inline int prepare_result(const Shape &s, const unsigned char *input,
 unsigned char *output, const Span *remote, uint32_t count, uint64_t rx_key,
 SpanIndex *index) {
 int rc = index_spans(remote, count, index);
 if (rc) return rc;
 if (index->bytes < s.wire_bytes || rx_key != s.sequence) return -EPROTO;
 unsigned char header[64];
 for (unsigned i = 0; i < 64; ++i)
  header[i] = *indexed_address(remote, *index, i);
 if ((rc = validate_header(s, header))) return rc;
 if (s.operation == 2 && s.rank != s.dst_rank) return 0;
 if (s.output_bytes && (!output || !input)) return -EINVAL;
 return 0;
}
TP_HD inline void result_partition(const Shape &s, const unsigned char *input,
 unsigned char *output, const Span *remote, const SpanIndex &index,
 uint64_t lane, uint64_t lanes) {
 if (!lanes || lane >= lanes || (s.operation == 2 && s.rank != s.dst_rank)) return;
 unsigned size = item_size(s.dtype);
 uint64_t i = lane;
 while (i < s.elements) {
  uint32_t a = 0, b = 0;
  for (unsigned j = 0; j < size; ++j) {
   a |= uint32_t(input[i * size + j]) << (8 * j);
   b |= uint32_t(*indexed_address(remote, index, 64 + i * size + j)) << (8 * j);
  }
  if (s.operation == 1) put_le(output + i * size, sum_element(s.dtype, a, b), size);
  else {
   uint64_t row = i / s.width, column = i % s.width;
   put_le(output + gather_index(row, column, s.width, s.rank) * size, a, size);
   put_le(output + gather_index(row, column, s.width, s.rank ^ 1) * size, b, size);
  }
  if (s.elements - i <= lanes) break;
  i += lanes;
 }
}
TP_HD inline int result(const Shape &s, const unsigned char *input,
 unsigned char *output, const Span *remote, uint32_t count, uint64_t rx_key) {
 SpanIndex index{};
 int rc = prepare_result(s, input, output, remote, count, rx_key, &index);
 if (!rc) result_partition(s, input, output, remote, index, 0, 1);
 return rc;
}
TP_HD inline int fail(Runtime *r, WorkCore *w, int error) {
 if(error>=0)error=-EIO;
 if(!r->error)r->error=error;
 if(w->state!=6)++r->failed;
 w->error=r->error;
 w->state=6;
 return r->error;
}
TP_HD inline int begin_invocation(Runtime *r, WorkCore *w, uint64_t key) {
 if(r->error)return r->error;
 if(!key || key!=r->next_sequence || key==UINT64_MAX) return fail(r,w,-EPROTO);
 w->state=1; w->sequence=key; w->error=0; ++r->invocations; ++r->inflight;
 if(r->inflight>r->high_water)r->high_water=r->inflight;
 if(!r->first_sequence)r->first_sequence=key;
 r->last_sequence=key;
 ++r->next_sequence;
 return 0;
}
TP_HD inline int advance(Runtime *r, WorkCore *w, uint32_t state, int status) {
 if(r->error)return r->error;
 if(status)return fail(r,w,status);
 if(state!=w->state+1 || state>5)return fail(r,w,-EPROTO);
 w->state=state; if(state==5){--r->inflight;++r->completed;} return 0;
}
TP_HD inline int receive(Runtime *r, WorkCore *w, uint64_t key, uint64_t ticket) {
 if(key!=w->sequence || !ticket || ticket==r->last_rx_ticket) return fail(r,w,-EPROTO);
 int rc=advance(r,w,3,0); if(!rc)r->last_rx_ticket=ticket; return rc;
}
TP_HD inline int apply_result(Runtime *r, WorkCore *w, const Shape &s,
 const unsigned char *input, unsigned char *output, const Span *remote,
 uint32_t count, uint64_t rx_key) {
 if (r->error) return r->error;
 int rc=result(s,input,output,remote,count,rx_key);
 return rc?fail(r,w,rc):advance(r,w,4,0);
}
TP_HD inline int query(const WorkCore &w) { return w.error?w.error:w.state==5?0:1; }
TP_HD inline int destroyable(const WorkCore &w, bool graph_live) { return graph_live?-EBUSY:w.state==5?0:w.error?w.error:-EBUSY; }
} // namespace xdev_tp_native
#undef TP_HD
#endif
