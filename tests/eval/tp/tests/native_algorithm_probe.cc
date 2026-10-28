// SPDX-License-Identifier: GPL-2.0
// Independent observation adapter. Arithmetic, matching, layout and state live
// exclusively in the production header called by the actual CUDA kernels.
#include "../xdev_tp_algorithms.h"
#include <sys/mman.h>
#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
using namespace xdev_tp_native;
using Bytes = std::vector<unsigned char>;
static uint64_t number(const char *s) { return std::stoull(s, nullptr, 0); }
static Bytes unhex(const std::string &s) {
 if(s.size()%2)throw std::runtime_error("odd hex");
 Bytes b; for(size_t i=0;i<s.size();i+=2)b.push_back(std::stoul(s.substr(i,2),nullptr,16)); return b;
}
static std::string hex(const unsigned char *b,size_t n) {
 std::ostringstream out;out<<std::hex<<std::setfill('0');for(size_t i=0;i<n;++i)out<<std::setw(2)<<unsigned(b[i]);return out.str();
}
static std::string bits(const unsigned char *b,size_t n) {
 std::ostringstream out;out<<std::hex<<std::setfill('0');for(size_t i=n;i>0;--i)out<<std::setw(2)<<unsigned(b[i-1]);return out.str();
}
static void print_bits(const Bytes &b,unsigned size) {
 std::cout<<"[";for(size_t i=0;i<b.size();i+=size){if(i)std::cout<<",";std::cout<<"\""<<bits(b.data()+i,size)<<"\"";}std::cout<<"]";
}
static Shape shape(char **a) {
 Shape s{};s.communicator_id=number(a[0]);s.epoch=number(a[1]);s.sequence=number(a[2]);s.rows=number(a[3]);s.width=number(a[4]);s.operation=number(a[5]);s.dtype=number(a[6]);s.rank=number(a[7]);s.world_size=number(a[8]);s.dst_rank=number(a[9]);
 return s;
}
static std::vector<Span> spans(const std::string &s,Bytes &allocation) {
 std::vector<Span> out;std::istringstream in(s);std::string part;
 while(std::getline(in,part,',')){auto colon=part.find(':');uint64_t offset=std::stoull(part.substr(0,colon)),len=std::stoull(part.substr(colon+1));if(offset>allocation.size()||len>allocation.size()-offset)throw std::runtime_error("span out of adapter allocation");out.push_back({reinterpret_cast<uint64_t>(allocation.data()+offset),len});}return out;
}
static std::vector<Span> guarded(const std::vector<Span> &in) {
 // Each actual message span retains its byte order/length. Payload pages are
 // unreadable, so a wrong early payload read crashes this separate probe.
 size_t page=sysconf(_SC_PAGESIZE);uint64_t logical=0;std::vector<Span> out;
 for(const auto &s:in){void *base=mmap(nullptr,page*3,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(base==MAP_FAILED)throw std::runtime_error("mmap");uint64_t header=logical>=64?0:64-logical;unsigned char *address=static_cast<unsigned char*>(base)+(header<s.bytes?page-header:0);for(uint64_t i=0;i<s.bytes;++i)address[i]=reinterpret_cast<unsigned char*>(s.address)[i];if(header<s.bytes&&mprotect(static_cast<unsigned char*>(base)+page,page*2,PROT_NONE))throw std::runtime_error("mprotect");out.push_back({reinterpret_cast<uint64_t>(address),s.bytes});logical+=s.bytes;}
 return out;
}
int main(int argc,char **argv) {
 try {
 if(argc<2)return 64;
 std::string action=argv[1];
 if(action=="sum") {
  if(argc!=5)return 64;
  unsigned dtype=number(argv[2]),size=item_size(dtype);Bytes a=unhex(argv[3]),b=unhex(argv[4]),out(a.size());if(!size||a.size()!=b.size()||a.size()%size)return 64;
  for(size_t i=0;i<a.size();i+=size){uint32_t x=0,y=0;for(unsigned j=0;j<size;++j){x|=uint32_t(a[i+j])<<(8*j);y|=uint32_t(b[i+j])<<(8*j);}uint32_t result=sum_element(dtype,x,y);for(unsigned j=0;j<size;++j)out[i+j]=result>>(8*j);}
  std::cout<<"{\"status\":0,\"output_bits\":";print_bits(out,size);std::cout<<"}\n";return 0;
 }
 if(action=="gather") {
  if(argc!=9)return 64;
  Shape s{};s.communicator_id=7;s.epoch=9;s.sequence=23;s.rows=number(argv[4]);s.width=number(argv[5]);s.operation=3;s.dtype=number(argv[2]);s.rank=number(argv[3]);s.world_size=2;
  int rc=shape_validate(&s,UINT64_MAX,UINT64_MAX);if(rc)return 65;
  Bytes rank0=unhex(argv[6]),rank1=unhex(argv[7]);if(rank0.size()!=s.payload_bytes||rank1.size()!=s.payload_bytes)return 64;
  Bytes &local=s.rank?rank1:rank0,&peer=s.rank?rank0:rank1;Bytes wire(s.wire_bytes),out(s.output_bytes,0xcd);Shape remote=s;remote.rank^=1;encode_header(remote,wire.data());for(size_t i=0;i<peer.size();++i)wire[64+i]=peer[i];Span span{reinterpret_cast<uint64_t>(wire.data()),wire.size()};
  rc=result(s,local.data(),out.data(),&span,1,23);std::cout<<"{\"status\":"<<rc<<",\"output_bits\":";print_bits(out,item_size(s.dtype));std::cout<<"}\n";return 0;
 }
 if(action=="pack") {
  if(argc!=17)return 64;
  Shape s=shape(argv+2);int rc=shape_validate(&s,UINT64_MAX,UINT64_MAX);if(rc)return 65;
  Bytes input=unhex(argv[12]);Bytes allocation(number(argv[13]),number(argv[14]));auto ss=spans(argv[15],allocation);rc=pack(s,input.data(),ss.data(),ss.size());uint64_t cap=0;span_capacity(ss.data(),ss.size(),&cap);Bytes wire;for(const auto&sp:ss)for(uint64_t i=0;i<sp.bytes;++i)wire.push_back(reinterpret_cast<unsigned char*>(sp.address)[i]);
  std::cout<<"{\"status\":"<<rc<<",\"allocation_hex\":\""<<hex(allocation.data(),allocation.size())<<"\",\"logical_wire_hex\":\""<<hex(wire.data(),wire.size())<<"\",\"payload_bytes\":"<<s.payload_bytes<<",\"header_bytes\":64,\"padding_bytes\":"<<cap-s.wire_bytes<<",\"wire_bytes\":"<<cap<<"}\n";return 0;
 }
 if(action=="receive") {
  if(argc!=19)return 64;
  Shape s=shape(argv+2);int rc=shape_validate(&s,UINT64_MAX,UINT64_MAX);if(rc)return 65;
  Bytes input=unhex(argv[12]),output=unhex(argv[13]),allocation=unhex(argv[14]);auto ss=spans(argv[15],allocation);bool guard=number(argv[18]);if(guard)ss=guarded(ss);
  Runtime r{};r.next_sequence=s.sequence;WorkCore w{};begin_invocation(&r,&w,s.sequence);advance(&r,&w,2,0);receive(&r,&w,s.sequence,1);
  s.sequence=number(argv[17]);rc=apply_result(&r,&w,s,input.data(),output.data(),ss.data(),ss.size(),number(argv[16]));
  std::cout<<"{\"status\":"<<rc<<",\"output_hex\":\""<<hex(output.data(),output.size())<<"\",\"output_bits\":";print_bits(output,item_size(s.dtype));std::cout<<",\"communicator_poisoned\":"<<(r.error?"true":"false");if(guard)std::cout<<",\"payload_read_count\":0";std::cout<<"}\n";return 0;
 }
 return 64;
 } catch(const std::exception &e){std::cerr<<e.what()<<"\n";return 70;}
}
