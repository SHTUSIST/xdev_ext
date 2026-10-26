// SPDX-License-Identifier: GPL-2.0
#include "native_trace_owner.h"
#include <cerrno>
#include <climits>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>
namespace tb {
namespace {
uint64_t now_ns() {
 struct timespec t{};
 if (clock_gettime(CLOCK_MONOTONIC, &t)) throw std::runtime_error("clock");
 return uint64_t(t.tv_sec) * 1000000000ULL + uint64_t(t.tv_nsec);
}
std::string read_at(int dir, const std::string &path, size_t cap) {
 int fd = openat(dir, path.c_str(), O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
 if (fd < 0) throw std::runtime_error("trace read " + path);
 std::string out; char buf[8192];
 for (;;) {
  ssize_t n = read(fd, buf, sizeof(buf));
  if (n < 0 && errno == EINTR) continue;
  if (n < 0) { close(fd); throw std::runtime_error("trace read"); }
  if (!n) break;
  if (size_t(n) > cap - out.size()) { close(fd); throw std::length_error("trace capacity"); }
  out.append(buf, size_t(n));
 }
 close(fd); return out;
}
void write_at(int dir, const std::string &path, const std::string &value, bool create=false) {
 int fd = openat(dir, path.c_str(), O_WRONLY|O_CLOEXEC|O_NOFOLLOW|(create?O_CREAT|O_TRUNC:O_TRUNC),0600);
 if (fd < 0) throw std::runtime_error("trace write " + path);
 size_t off=0;
 while (off < value.size()) {
  auto n=write(fd,value.data()+off,value.size()-off);
  if (n < 0 && errno==EINTR) continue;
  if (n<=0) {close(fd); throw std::runtime_error("trace write");}
  off+=size_t(n);
 }
 if (create && fsync(fd)) {close(fd); throw std::runtime_error("trace evidence fsync");}
 close(fd);
}
std::string strip(std::string s) {
 while (!s.empty() && (s.back()=='\n'||s.back()==' '||s.back()=='\t')) s.pop_back();
 return s;
}
uint64_t scalar(const std::string &v) {
 auto s=strip(v); size_t p=s.find_first_not_of(" \t");
 if (p==std::string::npos) throw std::runtime_error("empty counter");
 s=s.substr(p);
 if(s.find_first_not_of("0123456789")!=std::string::npos) throw std::runtime_error("counter syntax");
 return std::stoull(s);
}
}
struct NativeTraceCapture::Impl {
 std::string root,evidence,name,path,format,clock;
 int fd=-1, evidence_fd=-1;
 uint64_t begin=0;
 bool owned=false,started=false,sealed=false,closed=false;
 Impl(std::string r,std::string e,std::string n):root(std::move(r)),evidence(std::move(e)),name(std::move(n)),path(root+"/instances/"+name){}
 uint64_t loss(std::string *raw) {
  int pc=openat(fd,"per_cpu",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
  if(pc<0) throw std::runtime_error("missing per CPU stats");
  DIR *d=fdopendir(pc);
  if(!d) {close(pc);throw std::runtime_error("per CPU stats directory");}
  uint64_t total=0; unsigned cpus=0;
  try {
   while(auto *entry=readdir(d)) {
    std::string cpu=entry->d_name;
    if(cpu.size()<=3 || cpu.substr(0,3)!="cpu" || cpu.substr(3).find_first_not_of("0123456789")!=std::string::npos) continue;
    auto s=read_at(fd,"per_cpu/"+cpu+"/stats",65536);
    if(raw->size()+cpu.size()+2+s.size()>1024*1024)throw std::length_error("trace stats capacity");
    *raw+=cpu+":\n"+s;
    std::map<std::string,uint64_t> counters;
    std::istringstream lines(s); std::string line;
    while(std::getline(lines,line)) {
     auto colon=line.find(':'); if(colon==std::string::npos) continue;
     auto key=strip(line.substr(0,colon));
     if(key=="overrun"||key=="commit overrun"||key=="dropped events") {
      if(!counters.emplace(key,scalar(line.substr(colon+1))).second) throw std::runtime_error("duplicate trace loss counter");
     }
    }
    if(counters.size()!=3) throw std::runtime_error("unknown trace loss");
    for(const auto &c:counters) {if(c.second>UINT64_MAX-total) throw std::runtime_error("loss overflow");total+=c.second;}
    ++cpus;
   }
  } catch(...) {closedir(d);throw;}
  closedir(d); if(!cpus) throw std::runtime_error("no CPU stats"); return total;
 }
};
NativeTraceCapture::NativeTraceCapture(std::string r,std::string e,std::string n):p_(new Impl(std::move(r),std::move(e),std::move(n))){}
NativeTraceCapture::~NativeTraceCapture() = default; // Numeric FDs and active kernel instance deliberately retained.
std::string NativeTraceCapture::instance_path() const {return p_->path;}
int NativeTraceCapture::start() {
 auto &p=*p_;
 if(p.owned||p.started||p.closed) return -EALREADY;
 if(p.name.empty()||p.name.size()>96||p.name=="."||p.name==".."||p.name.find("..")!=std::string::npos) return -EINVAL;
 for(unsigned char c:p.name) if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.')) return -EINVAL;
 if(mkdir(p.path.c_str(),0700)) return -errno;
 p.owned=true;
 try {
  p.fd=open(p.path.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
  p.evidence_fd=open(p.evidence.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
  if(p.fd<0||p.evidence_fd<0) throw std::runtime_error("trace directories");
  write_at(p.fd,"tracing_on","0\n");
  write_at(p.fd,"current_tracer","nop\n");
  if(strip(read_at(p.fd,"current_tracer",4096))!="nop") throw std::runtime_error("trace tracer readback");
  write_at(p.fd,"trace_clock","mono\n");
  p.clock=read_at(p.fd,"trace_clock",4096);
  if(strip(p.clock)!="mono" && p.clock.find("[mono]")==std::string::npos) throw std::runtime_error("trace clock readback");
  write_at(p.fd,"buffer_size_kb","4096\n");
  auto kb=scalar(read_at(p.fd,"buffer_size_kb",4096));
  if(kb<4096||kb>4099) throw std::runtime_error("trace buffer readback");
  p.format=read_at(p.fd,"events/xdev_ext/native_event/format",65536);
  if(p.format.empty()) throw std::runtime_error("native event format missing");
  write_at(p.fd,"events/xdev_ext/native_event/enable","1\n");
  if(scalar(read_at(p.fd,"events/xdev_ext/native_event/enable",4096))!=1) throw std::runtime_error("native event enable readback");
  std::string stats; if(p.loss(&stats)) throw std::runtime_error("initial trace loss");
  p.begin=now_ns();
  write_at(p.fd,"tracing_on","1\n");
  if(scalar(read_at(p.fd,"tracing_on",4096))!=1) throw std::runtime_error("trace enable readback");
  write_at(p.evidence_fd,p.name+".format",p.format,true);
  p.started=true; return 0;
 }catch(...) {return -EIO;}
}
int NativeTraceCapture::snapshot(NativeTraceSnapshot *out,bool seal) {
 auto &p=*p_; if(!out||!p.started||p.closed) return -EINVAL;
 try {
  if(seal&&!p.sealed) {
   write_at(p.fd,"tracing_on","0\n");
   write_at(p.fd,"events/xdev_ext/native_event/enable","0\n");
   if(scalar(read_at(p.fd,"tracing_on",4096))||scalar(read_at(p.fd,"events/xdev_ext/native_event/enable",4096))) throw std::runtime_error("trace seal readback");
   p.sealed=true;
  }
  NativeTraceSnapshot s{}; s.begin_ns=p.begin;s.event_format=p.format;s.trace_clock=p.clock;s.sealed=p.sealed;
  s.raw_trace=read_at(p.fd,"trace",1024*1024);
  s.lost_events=p.loss(&s.stats);s.end_ns=now_ns();s.captured_monotonic_ns=now_ns();
  write_at(p.evidence_fd,p.name+".trace",s.raw_trace,true);
  write_at(p.evidence_fd,p.name+".stats",s.stats,true);
  *out=std::move(s); return 0;
 }catch(const std::length_error &) {return -E2BIG;}catch(...) {return -EIO;}
}
int NativeTraceCapture::close_safe() {
 auto &p=*p_; if(!p.owned||p.closed) return -EINVAL;
 if(p.started&&!p.sealed) {NativeTraceSnapshot s{};int rc=snapshot(&s,true);if(rc)return rc;}
 if(rmdir(p.path.c_str()))return -errno;
 if(p.fd>=0)close(p.fd);
 if(p.evidence_fd>=0)close(p.evidence_fd);
 p.fd=p.evidence_fd=-1;p.closed=true;return 0;
}
}
