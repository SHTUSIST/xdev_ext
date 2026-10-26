// SPDX-License-Identifier: GPL-2.0
// Resource owner for the real GPU/peer/mechanism path. No CPU payload access.
#include "agent_supervisor.h"
#include "epoch_control.h"
#include "gpu_adapter.h"
#include "observer_contract.h"
#include "native_trace_owner.h"
#include <algorithm>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cuda.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <linux/xdev_ext_peer.h>
#include <map>
#include <regex>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <vector>

extern char **environ;

namespace tb {
// The private wire parser is shared with supervisor; there is one parser body.
std::string agent_json_get(const std::string &, const std::string &);
std::string agent_json_string(const std::string &);
std::string agent_json_quote(const std::string &);
std::vector<std::string> agent_json_array(const std::string &);
bool agent_durable_append(int, const std::string &);
} // namespace tb
namespace {
using tb::agent_json_array;
static_assert(sizeof(tb_xd_observer_cqe) == sizeof(xdev_ext_xdomain_mech_cqe),
              "CQE size");
#define CQE_OFFSET(field)                                                      \
  static_assert(offsetof(tb_xd_observer_cqe, field) ==                         \
                    offsetof(xdev_ext_xdomain_mech_cqe, field),                \
                "CQE " #field)
CQE_OFFSET(status);
CQE_OFFSET(outcome);
CQE_OFFSET(remote);
CQE_OFFSET(elems_done);
CQE_OFFSET(group);
CQE_OFFSET(bytes);
CQE_OFFSET(crc_errors);
CQE_OFFSET(rsvd);
CQE_OFFSET(tag);
#undef CQE_OFFSET
using tb::agent_json_get;
using tb::agent_json_quote;
using tb::agent_json_string;
using Fields = std::map<std::string, std::string>;
std::string obj(const Fields &fields) {
  std::string s = "{";
  bool first = true;
  for (const auto &v : fields) {
    if (!first)
      s += ',';
    first = false;
    s += agent_json_quote(v.first) + ':' + v.second;
  }
  return s + '}';
}
std::string arr(const std::vector<std::string> &items) {
  std::string s = "[";
  bool first = true;
  for (const auto &v : items) {
    if (!first)
      s += ',';
    first = false;
    s += v;
  }
  return s + ']';
}
std::string number(uint64_t n) { return std::to_string(n); }
std::string boolean(bool b) { return b ? "true" : "false"; }
std::string string_at(const std::string &j, const std::string &p) {
  return agent_json_string(agent_json_get(j, p));
}
uint64_t uint_at(const std::string &j, const std::string &p) {
  auto s = agent_json_get(j, p);
  if (s.empty() || s[0] == '-')
    throw std::runtime_error("unsigned scalar");
  size_t n = 0;
  auto u = std::stoull(s, &n);
  if (n != s.size())
    throw std::runtime_error("unsigned scalar");
  return u;
}
bool bool_at(const std::string &j, const std::string &p) {
  auto s = agent_json_get(j, p);
  if (s != "true" && s != "false")
    throw std::runtime_error("boolean scalar");
  return s == "true";
}
uint64_t mono_ns() {
  struct timespec t{};
  if(clock_gettime(CLOCK_MONOTONIC,&t))throw std::runtime_error("CLOCK_MONOTONIC unavailable");
  return static_cast<uint64_t>(t.tv_sec)*1000000000ULL+static_cast<uint64_t>(t.tv_nsec);
}
std::string read_file(const std::string &path, size_t cap = 4 * 1024 * 1024) {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    throw std::runtime_error("read " + path + ": " + strerror(errno));
  std::string result;
  char buf[8192];
  for (;;) {
    auto n = read(fd, buf, sizeof(buf));
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0) {
      close(fd);
      throw std::runtime_error("read " + path);
    }
    if (!n)
      break;
    if (result.size() + static_cast<size_t>(n) > cap) {
      close(fd);
      throw std::runtime_error("file bound: " + path);
    }
    result.append(buf, static_cast<size_t>(n));
  }
  close(fd);
  return result;
}
void persist_metadata(const std::string &path,const std::string &data) {
  int fd=open(path.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
  if(fd<0)throw std::runtime_error("raw metadata evidence open");
  size_t off=0;
  while(off<data.size()) {
    auto n=write(fd,data.data()+off,data.size()-off);
    if(n<0&&errno==EINTR)continue;
    if(n<=0){close(fd);throw std::runtime_error("raw metadata evidence write");}
    off+=size_t(n);
  }
  int error=fsync(fd);close(fd);
  if(error)throw std::runtime_error("raw metadata evidence fsync");
}
std::string trim(std::string v) {
  while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
    v.pop_back();
  return v;
}
std::vector<std::string> list_dir(const std::string &path) {
  DIR *d = opendir(path.c_str());
  if (!d)
    throw std::runtime_error("listing " + path);
  std::vector<std::string> out;
  while (auto *e = readdir(d)) {
    if (e->d_name[0] != '.')
      out.emplace_back(e->d_name);
  }
  closedir(d);
  std::sort(out.begin(), out.end());
  return out;
}
std::string hex(const void *data, size_t bytes) {
  const auto *p = static_cast<const unsigned char *>(data);
  const char *digits = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < bytes; i++) {
    s += digits[p[i] >> 4];
    s += digits[p[i] & 15];
  }
  return s;
}
std::string running_build_id() {
  auto notes = read_file("/sys/kernel/notes");
  size_t pos = 0;
  std::string id;
  while (pos < notes.size()) {
    if (notes.size() - pos < sizeof(Elf64_Nhdr))
      throw std::runtime_error("kernel note header");
    Elf64_Nhdr n{};
    memcpy(&n, notes.data() + pos, sizeof(n));
    pos += sizeof(n);
    size_t name = (static_cast<size_t>(n.n_namesz) + 3) & ~size_t(3),
           desc = (static_cast<size_t>(n.n_descsz) + 3) & ~size_t(3);
    if (name > notes.size() - pos || desc > notes.size() - pos - name)
      throw std::runtime_error("kernel note bound");
    if (n.n_type == NT_GNU_BUILD_ID && n.n_namesz == 4 &&
        !memcmp(notes.data() + pos, "GNU\0", 4)) {
      if (!id.empty() || !n.n_descsz)
        throw std::runtime_error("ambiguous build id");
      id = hex(notes.data() + pos + name, n.n_descsz);
    }
    pos += name + desc;
  }
  if (id.empty())
    throw std::runtime_error("running kernel has no GNU build-id");
  return id;
}
// Fixed read-only local metadata helper; no shell, CUDA, or cleanup authority.
std::string metadata_helper(const std::string &helpers, const std::string &input,
                            uint64_t deadline) {
  static const char code[] = R"PY(import json, sys, time
sys.path.insert(0,sys.argv[1])
q=json.load(sys.stdin)
if q['op']=='platform':
 from platform_facts import collect_platform_facts
 r=collect_platform_facts(q['log'],q['receipt'],q['expected'])
 if r['status']=='complete':
  needed={c['begin_seq'] for c in r['credits']}
  found=set()
  binding=' token=%d local_inc=%d remote_inc=%d ' % (q['expected']['link_token'],q['local_inc'],q['remote_inc'])
  with open(q['log'],'rb') as stream:
   total=0
   while True:
    line=stream.readline(65537)
    if not line: break
    total+=len(line)
    if len(line)>65536 or total>16*1024*1024: raise ValueError('C1 recheck capacity')
    row=json.loads(line)
    if row['seq'] in needed:
     if binding not in row['message']: raise ValueError('C1 current incarnation mismatch')
     found.add(row['seq'])
  if found!=needed: raise ValueError('C1 selected PATH evidence missing')
else:
 from native_barrier import qualify_native_barrier
 r=qualify_native_barrier(q['raw_trace'],q['receipt'],q['expected'],now_ns=time.monotonic_ns(),action=q.get('action'))
print(json.dumps(r,separators=(',',':')),flush=True)
)PY";
  int in[2], out[2];
  if(pipe2(in,O_CLOEXEC)) throw std::runtime_error("helper input pipe");
  if(pipe2(out,O_CLOEXEC)) {close(in[0]);close(in[1]);throw std::runtime_error("helper output pipe");}
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions,in[0],STDIN_FILENO);
  posix_spawn_file_actions_adddup2(&actions,out[1],STDOUT_FILENO);
  char *argv[]={const_cast<char *>("/usr/bin/python3"),const_cast<char *>("-I"),
                const_cast<char *>("-c"),const_cast<char *>(code),
                const_cast<char *>(helpers.c_str()),nullptr};
  pid_t pid=0;
  int rc=posix_spawn(&pid,argv[0],&actions,nullptr,argv,environ);
  posix_spawn_file_actions_destroy(&actions);
  close(in[0]);close(out[1]);
  if(rc) {close(in[1]);close(out[0]);throw std::runtime_error("metadata helper spawn");}
  fcntl(in[1],F_SETFL,O_NONBLOCK);fcntl(out[0],F_SETFL,O_NONBLOCK);
  size_t offset=0;std::string result;bool eof=false;int status=0;bool exited=false;
  for(;;) {
    if(mono_ns()>=deadline) // Keep unknown child and pipes retained; no kill/reap.
      throw std::runtime_error("metadata helper deadline; retained pid="+std::to_string(pid));
    pollfd fds[2]={{in[1],POLLOUT,0},{out[0],POLLIN,0}};
    if(poll(fds,2,10)<0&&errno!=EINTR) throw std::runtime_error("metadata poll");
    if(in[1]>=0&&(fds[0].revents&(POLLOUT|POLLERR|POLLHUP))) {
      auto n=write(in[1],input.data()+offset,input.size()-offset);
      if(n>0)offset+=size_t(n);
      else if(n<0&&errno!=EAGAIN&&errno!=EINTR)throw std::runtime_error("metadata input");
      if(offset==input.size()){close(in[1]);in[1]=-1;}
    }
    if(!eof&&(fds[1].revents&(POLLIN|POLLHUP|POLLERR))) {
      char b[8192];auto n=read(out[0],b,sizeof(b));
      if(n>0){if(result.size()+size_t(n)>TB_MAX_JSON)throw std::runtime_error("metadata capacity");result.append(b,size_t(n));}
      else if(!n){eof=true;close(out[0]);out[0]=-1;}
      else if(errno!=EAGAIN&&errno!=EINTR)throw std::runtime_error("metadata output");
    }
    if(!exited){auto w=waitpid(pid,&status,WNOHANG);if(w==pid)exited=true;else if(w<0&&errno!=EINTR)throw std::runtime_error("metadata child");}
    if(exited&&eof)break;
  }
  if(in[1]>=0)close(in[1]);
  if(!WIFEXITED(status)||WEXITSTATUS(status)||result.empty())throw std::runtime_error("metadata helper failed");
  return trim(result);
}
struct LinkState {
  uint64_t token = 0, local_inc = 0, remote_inc = 0, channels = 0;
  bool up = false, closing = false, nhi_gone = false;
  std::string service, nhi;
};
LinkState find_link(uint64_t wanted, std::vector<std::string> *listing) {
  auto entries = list_dir("/sys/bus/thunderbolt/devices");
  *listing = entries;
  LinkState found;
  unsigned matches = 0;
  for (const auto &entry : entries) {
    std::string base = "/sys/bus/thunderbolt/devices/" + entry;
    auto attributes = list_dir(base);
    if (std::find(attributes.begin(), attributes.end(), "xdev_ext_link") ==
        attributes.end())
      continue;
    auto raw = trim(read_file(base + "/xdev_ext_link", 4096));
    size_t used = 0;
    auto token = std::stoull(raw, &used);
    if (used != raw.size() || token != wanted)
      continue;
    if (std::find(attributes.begin(), attributes.end(),
                  "xdev_ext_link_state") == attributes.end())
      throw std::runtime_error("link lacks incarnation snapshot");
    auto state = trim(read_file(base + "/xdev_ext_link_state", 4096));
    std::istringstream in(state);
    std::map<std::string, uint64_t> values;
    std::string item;
    while (in >> item) {
      auto split = item.find('=');
      if (split == std::string::npos)
        throw std::runtime_error("link state syntax");
      auto key = item.substr(0, split), v = item.substr(split + 1);
      if (v.empty() || v.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("link state scalar");
      size_t n = 0;
      auto value = std::stoull(v, &n);
      if (n != v.size() || !values.emplace(key, value).second)
        throw std::runtime_error("link state duplicate");
    }
    std::set<std::string> keys;
    for (const auto &kv : values)
      keys.insert(kv.first);
    if (keys != std::set<std::string>{"version", "token", "local_inc",
                                      "remote_inc", "up", "closing", "nhi_gone",
                                      "channels"} ||
        values.at("version") != 1 || values.at("token") != wanted ||
        !values.at("local_inc") || !values.at("remote_inc") ||
        values.at("up") != 1 || values.at("closing") || values.at("nhi_gone") ||
        !values.at("channels") || values.at("channels") > UINT32_MAX)
      throw std::runtime_error("link state not usable");
    char path[4096];
    if (!realpath(base.c_str(), path))
      throw std::runtime_error("service realpath");
    std::string resolved(path);
    std::regex bdf("[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\\.[0-7]");
    std::string nhi;
    for (std::sregex_iterator i(resolved.begin(), resolved.end(), bdf), end;
         i != end; ++i)
      nhi = i->str();
    if (nhi.empty())
      throw std::runtime_error("NHI identity absent");
    found = {wanted,
             values.at("local_inc"),
             values.at("remote_inc"),
             values.at("channels"),
             true,
             false,
             false,
             base,
             nhi};
    ++matches;
  }
  if (matches != 1)
    throw std::runtime_error("requires one actual service token");
  return found;
}
std::string
query_visibility(const std::string &bdf, const std::function<void()> &check,
                 const std::function<void(const char *, int)> &observed,
                 Fields *capabilities) {
  CUdevice device;
  check();
  auto status = cuInit(0);
  observed("cuInit", status);
  check();
  if (status != CUDA_SUCCESS)
    throw std::runtime_error("CUDA initialization unavailable");
  status = cuDeviceGetByPCIBusId(&device, bdf.c_str());
  observed("cuDeviceGetByPCIBusId", status);
  check();
  if (status != CUDA_SUCCESS)
    throw std::runtime_error("CUDA device unavailable");
  int supported = 0, ordering = 0, options = 0;
  status = cuDeviceGetAttribute(
      &supported, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED, device);
  observed("cuDeviceGetAttribute(GPU_DIRECT_RDMA_SUPPORTED)", status);
  check();
  if (status == CUDA_SUCCESS)
    (*capabilities)["cuda_rdma_supported"] = std::to_string(supported);
  if (status != CUDA_SUCCESS)
    throw std::runtime_error("CUDA RDMA support query failed");
  status = cuDeviceGetAttribute(
      &ordering, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WRITES_ORDERING, device);
  observed("cuDeviceGetAttribute(GPU_DIRECT_RDMA_WRITES_ORDERING)", status);
  check();
  if (status == CUDA_SUCCESS)
    (*capabilities)["cuda_writes_ordering"] = std::to_string(ordering);
  if (status != CUDA_SUCCESS)
    throw std::runtime_error("CUDA RDMA ordering query failed");
  status = cuDeviceGetAttribute(
      &options, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_FLUSH_WRITES_OPTIONS,
      device);
  observed("cuDeviceGetAttribute(GPU_DIRECT_RDMA_FLUSH_WRITES_OPTIONS)",
           status);
  check();
  if (status == CUDA_SUCCESS)
    (*capabilities)["cuda_flush_options"] = std::to_string(options);
  if (status != CUDA_SUCCESS)
    throw std::runtime_error("CUDA RDMA flush query failed");
  if (!supported)
    throw std::runtime_error("CUDA RDMA unsupported");
  if (ordering == CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER ||
      ordering == CU_GPU_DIRECT_RDMA_WRITES_ORDERING_ALL_DEVICES)
    return "NATIVE_OWNER";
  if (ordering != CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE)
    throw std::runtime_error("unknown CUDA RDMA ordering");
  if (!(options & CU_FLUSH_GPU_DIRECT_RDMA_WRITES_OPTION_HOST))
    throw std::runtime_error("no supported host flush route");
  return "HOST_FLUSH_OWNER";
}
bool mps_absent(std::vector<std::string> *processes) {
  for (const auto &pid : list_dir("/proc")) {
    if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos)
      continue;
    try {
      auto cmd = read_file("/proc/" + pid + "/cmdline", 1024 * 1024);
      std::string executable = cmd.substr(0, cmd.find('\0'));
      auto slash = executable.rfind('/');
      if (slash != std::string::npos)
        executable = executable.substr(slash + 1);
      std::replace(cmd.begin(), cmd.end(), '\0', ' ');
      if (executable == "nvidia-cuda-mps-server" ||
          executable == "nvidia-cuda-mps-control") {
        processes->push_back(pid + ":" + cmd);
        return false;
      }
    } catch (const std::exception &) {
      if (access(("/proc/" + pid).c_str(), F_OK) == 0)
        throw std::runtime_error("MPS process inventory unreadable");
    }
  }
  return true;
}
Fields stats_fields(const xdev_ext_mech_stats &s) {
  Fields f;
#define SF(name) f[#name] = number(s.name)
  SF(session_id);
  SF(batches_done);
  SF(batches_abort);
  SF(rejects);
  SF(recycled);
  SF(held);
  SF(sequestered);
  SF(timeouts);
  SF(inflight);
  SF(native_publish);
  SF(protocol_err);
  SF(published);
  SF(state);
#undef SF
  std::vector<std::string> submitted, completed;
  for (unsigned i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++) {
    submitted.push_back(number(s.submitted[i]));
    completed.push_back(number(s.completed[i]));
  }
  f["submitted"] = arr(submitted);
  f["completed"] = arr(completed);
  f["last_err"] = std::to_string(s.last_err);
  return f;
}
std::string transport_json(const xdev_ext_mech_transport_stats_v4 &t) {
  const auto &v1 = t.v3.v2.v1;
  Fields a, b, c, p;
#define F(dst, src, name) dst[#name] = number(src.name)
  F(a, v1, size);
  F(a, v1, version);
  F(a, v1, session_id);
  F(a, v1, native_controls);
  F(a, v1, pending_acks);
  F(a, v1, uncertain_controls);
  F(a, v1, rsvd);
  b["v1"] = obj(a);
  F(b, t.v3.v2, retransmits);
  F(b, t.v3.v2, dup_suppressed);
  F(b, t.v3.v2, held_acks);
  F(b, t.v3.v2, held_unacked);
  F(b, t.v3.v2, rsvd2);
  c["v2"] = obj(b);
  F(c, t.v3, nic_copy_ops);
  F(c, t.v3, nic_copy_bytes);
  F(c, t.v3, nic_zc_ops);
  F(c, t.v3, nic_zc_bytes);
  F(p, t.rel_policy, version);
  F(p, t.rel_policy, size);
  F(p, t.rel_policy, window);
  F(p, t.rel_policy, initial_credit);
  F(p, t.rel_policy, rto_ns);
  F(p, t.rel_policy, rto_max_ns);
  F(p, t.rel_policy, backoff);
  F(p, t.rel_policy, max_attempts);
  F(p, t.rel_policy, ack_rule);
  F(p, t.rel_policy, ack_every);
  F(p, t.rel_policy, ack_delay_ns);
  F(p, t.rel_policy, resend_order);
  F(p, t.rel_policy, flags);
  F(p, t.rel_policy, bad_field);
  F(p, t.rel_policy, rsvd0);
#undef F
  std::vector<std::string> reserved;
  for (auto v : t.rel_policy.rsvd)
    reserved.push_back(number(v));
  p["rsvd"] = arr(reserved);
  return obj({{"v3", obj(c)}, {"rel_policy", obj(p)}});
}
Fields terminal_fields(const tb_epoch_result &r) {
  return {
      {"stats_valid", boolean(r.stats_valid)},
      {"stats", r.stats_valid ? obj(stats_fields(r.stats)) : "{}"},
      {"transport_valid", boolean(r.transport_valid)},
      {"transport", r.transport_valid ? transport_json(r.transport) : "{}"}};
}

class PhysicalOwner final : public tb::Owner {
  tb_guard *guard_;
  tb::Identity identity_;
  std::string kernel_receipt_, thunderbolt_log_, thunderbolt_receipt_, helpers_, evidence_dir_;
  std::string boot_id_, build_id_, clock_domain_, native_name_, pending_identity_;
  std::unique_ptr<tb::NativeTraceCapture> native_trace_;
  uint64_t create_begin_ns_=0, create_end_ns_=0, native_max_age_ms_=1000;
  int prepare_error_=0;
  Fields response_evidence_;
  bool exclusive_;
  int durable_;
  std::string visibility_;
  tb_gpu *gpu_ = nullptr;
  tb_epoch epoch_{};
  struct tb_gpu_registration registration_{};
  int control_ = -1, allocation_ = -1;
  uint64_t groups_ = 0, first_seq_ = 0, seed_ = 0, local_stop_request_ = 0;
  tb_geometry geometry_{};
  LinkState link_;
  std::string prepared_identity_, prepared_payload_, preflight_payload_;
  bpf_object *observer_ = nullptr;
  bpf_link *ops_ = nullptr;
  bool preflight_ok_ = false, prepared_ = false;
  void record(const std::string &event, const Fields &facts) {
    Fields f = facts;
    f["event"] = agent_json_quote(event);
    f["owner_pid"] = number(getpid());
    f["monotonic_ns"] = number(mono_ns());
    if (!tb::agent_durable_append(durable_, obj(f))) {
      tb_guard_hold(guard_, TB_HOLD_PROTOCOL);
      throw std::runtime_error("durable write/fsync failed");
    }
  }
  void gpu_diagnostic(const char *public_call, int status) {
    struct tb_gpu_diagnostic diagnostic{};
    diagnostic.size = sizeof(diagnostic);
    diagnostic.version = TB_GPU_DIAGNOSTIC_VERSION;
    int error = tb_gpu_last_diagnostic(&diagnostic);
    if (error) {
      record("gpu-diagnostic-unavailable",
             {{"public_call", agent_json_quote(public_call)},
              {"status", std::to_string(status)},
              {"diagnostic_error", std::to_string(error)}});
      tb_guard_hold(guard_, TB_HOLD_PROTOCOL);
      throw std::runtime_error("GPU diagnostic snapshot failed");
    }
    const char *end = static_cast<const char *>(
        memchr(diagnostic.operation, 0, sizeof(diagnostic.operation)));
    std::string operation(diagnostic.operation,
                          end ? static_cast<size_t>(end - diagnostic.operation)
                              : sizeof(diagnostic.operation));
    record("gpu-diagnostic",
           {{"public_call", agent_json_quote(public_call)},
            {"status", std::to_string(status)},
            {"size", number(diagnostic.size)},
            {"version", number(diagnostic.version)},
            {"cuda_result", std::to_string(diagnostic.cuda_result)},
            {"system_errno", std::to_string(diagnostic.system_errno)},
            {"guard_error", std::to_string(diagnostic.guard_error)},
            {"flags", number(diagnostic.flags)},
            {"operation", agent_json_quote(operation)}});
    if (!end || diagnostic.size != sizeof(diagnostic) ||
        diagnostic.version != TB_GPU_DIAGNOSTIC_VERSION ||
        (diagnostic.flags &
         ~(TB_GPU_DIAG_CUDA | TB_GPU_DIAG_SYSTEM | TB_GPU_DIAG_GUARD))) {
      tb_guard_hold(guard_, TB_HOLD_PROTOCOL);
      throw std::runtime_error("invalid GPU diagnostic snapshot");
    }
  }
  void check_guard() {
    struct tb_guard_snapshot s{};
    tb_guard_snapshot(guard_, &s);
    if (s.held)
      throw std::runtime_error("HELD owner cannot advance");
  }
  int admitted(tb_operation operation, const std::function<int()> &effect,
               bool require_peer_permission = false) {
    struct tb_guard_snapshot before{};
    tb_guard_snapshot(guard_, &before);
    if (require_peer_permission &&
        !(before.cleanup_permissions & TB_CLEANUP_PEER_FD))
      throw std::runtime_error("peer cleanup permission missing");
    uint64_t ticket = 0;
    if (tb_guard_begin(guard_, operation, &ticket))
      throw std::runtime_error("owner operation admission refused");
    int result = 0;
    try {
      result = effect();
    } catch (...) {
      tb_guard_end(guard_, ticket, before.phase, before.native_safe,
                   before.gpu_safe);
      throw;
    }
    int end = tb_guard_end(guard_, ticket, before.phase, before.native_safe,
                           before.gpu_safe);
    record("owner-operation-return", {{"operation", number(operation)},
                                      {"ticket", number(ticket)},
                                      {"result", std::to_string(result)},
                                      {"guard_result", std::to_string(end)}});
    if (end)
      throw std::runtime_error("owner operation returned after HELD");
    return result;
  }
  int control(const std::function<int()> &effect) {
    return admitted(TB_OP_CONTROL, effect);
  }
  void cleanup(const std::function<int()> &effect) {
    int result = admitted(TB_OP_EPOCH_CLOSE, effect, true);
    if (result) {
      tb_guard_hold(guard_, TB_HOLD_PROTOCOL);
      throw std::runtime_error("cleanup result unknown");
    }
  }
  tb::OwnerResult finish(const tb::Command &c, int error,
                         const Fields &payload) {
    struct tb_guard_snapshot s{};
    tb_guard_snapshot(guard_, &s);
    auto wire=payload;
    if(!response_evidence_.empty()) {wire["__owner_evidence"]=obj(response_evidence_);response_evidence_.clear();}
    return {c.request_id, error, s.phase, epoch_.stop_proved, obj(wire)};
  }
  tb_geometry geometry(const std::string &p) {
    auto g = agent_json_get(p, "geometry");
    tb_geometry out{};
    out.allocation_bytes = uint_at(g, "allocation_bytes");
    out.group_bytes = uint_at(g, "group_bytes");
    for (const char *name : {"frame_size", "seg_len", "depth", "native_elems"})
      if (uint_at(g, name) > UINT32_MAX)
        throw std::runtime_error("geometry width");
    out.frame_size = static_cast<uint32_t>(uint_at(g, "frame_size"));
    out.seg_len = static_cast<uint32_t>(uint_at(g, "seg_len"));
    out.depth = static_cast<uint32_t>(uint_at(g, "depth"));
    out.native_elems = static_cast<uint32_t>(uint_at(g, "native_elems"));
    if (tb_geometry_validate(&out))
      throw std::runtime_error("unsupported geometry");
    return out;
  }
  Fields preflight(const tb::Command &c, const std::string &p) {
    geometry_ = geometry(p);
    std::string reason;
    Fields raw, device, link, kernel;
    try {
      if (!exclusive_)
        throw std::runtime_error("exclusive-creator prerequisite not attested");
      auto receipt = read_file(kernel_receipt_);
      auto build_id = running_build_id();
      build_id_=build_id;
      boot_id_=trim(read_file("/proc/sys/kernel/random/boot_id",256));
      clock_domain_=boot_id_+":CLOCK_MONOTONIC";
      struct utsname u{};
      if (uname(&u))
        throw std::runtime_error("uname");
      if (string_at(receipt, "source_commit") != identity_.sha ||
          string_at(receipt, "kernel_build_id") != build_id ||
          string_at(receipt, "kernel_release") != u.release)
        throw std::runtime_error("running kernel receipt identity mismatch");
      auto config = string_at(receipt, "config_text");
      if (config.empty())
        throw std::runtime_error("empty kernel config receipt");
      kernel = {{"sha", agent_json_quote(string_at(receipt, "source_commit"))},
                {"config", agent_json_quote(config)}};
      raw["kernel_receipt"] = receipt;
      raw["running_build_id"] = agent_json_quote(build_id);
      raw["kernel_release"] = agent_json_quote(u.release);
      std::vector<std::string> listing;
      link_ = find_link(uint_at(p, "link_token"), &listing);
      std::vector<std::string> listed;
      for (auto &s : listing)
        listed.push_back(agent_json_quote(s));
      raw["service_listing"] = arr(listed);
      link = {{"link_token", number(link_.token)},
              {"channel", number(uint_at(p, "channel"))},
              {"local_inc", number(link_.local_inc)},
              {"remote_inc", number(link_.remote_inc)}};
      if (uint_at(p, "channel") >= link_.channels)
        throw std::runtime_error("link channel");
      char actual_service[4096];
      if(!realpath(link_.service.c_str(),actual_service))throw std::runtime_error("service ancestry");
      std::smatch domain_match;std::string service_path(actual_service);
      if(!std::regex_search(service_path,domain_match,std::regex("/domain([0-9]+)(/|$)")))throw std::runtime_error("actual NHI domain absent");
      auto platform_expected=obj({{"identity",agent_json_get(c.bounded_json,"identity")},
          {"nhi_bdf",agent_json_quote(link_.nhi)},{"domain",domain_match[1].str()},
          {"link_token",number(link_.token)},{"channel",number(uint_at(p,"channel"))},
          {"max_log_age_ms","120000"}});
      auto platform=metadata_helper(helpers_,obj({{"op",agent_json_quote("platform")},
          {"log",agent_json_quote(thunderbolt_log_)},{"receipt",agent_json_quote(thunderbolt_receipt_)},
          {"expected",platform_expected},{"local_inc",number(link_.local_inc)},
          {"remote_inc",number(link_.remote_inc)}}),c.deadline_ns);
      raw["platform_facts"]=platform;
      raw["boot_id"]=agent_json_quote(boot_id_);raw["clock_domain"]=agent_json_quote(clock_domain_);
      raw["observed_monotonic_ns"]=number(mono_ns());raw["nhi_bdf"]=agent_json_quote(link_.nhi);
      if(string_at(platform,"status")!="complete" || string_at(platform,"identity.boot_id")!=boot_id_ ||
         string_at(platform,"identity.kernel_build_id")!=build_id_ || string_at(platform,"identity.nhi_bdf")!=link_.nhi ||
         uint_at(platform,"identity.link_token")!=link_.token || uint_at(platform,"identity.channel")!=uint_at(p,"channel"))
        throw std::runtime_error("current C1 prerequisite collection incomplete");
      if(identity_.case_id=="idle-suspend-resume"||identity_.case_id=="idle-module-unload")
        raw["idle"]=obj({{"scope",agent_json_quote("this-owner")},{"prepared",boolean(prepared_)},
                         {"session_id",number(epoch_.session_id)},{"native_payload_owners",number(epoch_.start_accepted?1:0)}});
      auto bdf = string_at(p, "gpu_bdf"), node = string_at(p, "nvidia_node");
      struct stat st{};
      if (stat(node.c_str(), &st) || !S_ISCHR(st.st_mode))
        throw std::runtime_error("NVIDIA node unavailable");
      auto pci = list_dir("/sys/bus/pci/devices/" + bdf);
      raw["gpu_sysfs_listing"] = arr([&]() {
        std::vector<std::string> v;
        for (auto &s : pci)
          v.push_back(agent_json_quote(s));
        return v;
      }());
      if (trim(read_file("/sys/bus/pci/devices/" + bdf + "/vendor", 256)) !=
          "0x10de")
        throw std::runtime_error("GPU vendor mismatch");
      visibility_ = query_visibility(
          bdf, [&]() { check_guard(); },
          [&](const char *operation, int result) {
            record("cuda-preflight-return",
                   {{"operation", agent_json_quote(operation)},
                    {"cuda_result", std::to_string(result)}});
          },
          &raw);
      check_guard();
      device = {{"gpu_bdf", agent_json_quote(bdf)},
                {"nvidia_node", agent_json_quote(node)},
                {"backing", agent_json_quote("gpu")}};
      std::vector<std::string> processes;
      if (!mps_absent(&processes))
        throw std::runtime_error("MPS server is active");
      raw["mps_process_inventory"] = arr(processes);
      raw["exclusive_creator_attestation"] = boolean(exclusive_);
      raw["exclusive_creator_basis"] =
          agent_json_quote("operator-attested prerequisite; flock serializes "
                           "cooperating creators only");
      raw["nhi_bdf"] = agent_json_quote(link_.nhi);
      int kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
      if (kmsg < 0)
        throw std::runtime_error("kmsg diagnostic unavailable");
      close(kmsg);
      preflight_payload_ = p;
      preflight_ok_ = true;
    } catch (const std::exception &e) {
      reason = e.what();
      preflight_ok_ = false;
    }
    record("preflight", {{"available", boolean(preflight_ok_)},
                         {"reason", agent_json_quote(reason)},
                         {"raw_evidence", obj(raw)}});
    return {{"available", boolean(preflight_ok_)},
            {"reason", agent_json_quote(reason)},
            {"device_identity", obj(device)},
            {"link_identity", obj(link)},
            {"kernel_identity", obj(kernel)},
            {"visibility", agent_json_quote(visibility_)},
            {"raw_evidence", obj(raw)}};
  }
  // Observer methods are defined against the shared D declaration below.
  int observer_open(const std::string &path);
  int observer_configure();
  Fields observe(uint64_t first, uint64_t limit);
  Fields prepare(const tb::Command &c, const std::string &p);
  Fields verify(const tb::Command &c, const std::string &p);
  void validate_stop_pair(const std::string &,bool require_complete);
  Fields close_resources(const std::string &);
  Fields native_wait(const tb::Command &, const std::string &);

public:
  PhysicalOwner(tb_guard *g, const tb::Identity &id, const std::string &receipt,
                bool exclusive, int durable, const std::string &log,
                const std::string &tb_receipt, const std::string &helpers,
                const std::string &evidence)
      : guard_(g), identity_(id), kernel_receipt_(receipt),
        thunderbolt_log_(log), thunderbolt_receipt_(tb_receipt), helpers_(helpers),
        evidence_dir_(evidence), exclusive_(exclusive), durable_(durable) {
    int r = tb_epoch_init(&epoch_, guard_, nullptr);
    if (r)
      throw std::runtime_error("epoch initialization");
  }
  ~PhysicalOwner() override =
      default; // No automatic destruction of GPU, fd, BPF, or epoch resources.
  tb::OwnerResult execute(const tb::Command &c) override {
    try {
      check_guard();
      auto p = agent_json_get(c.bounded_json, "payload");
      if (c.command == "preflight") {
        auto result = preflight(c,p);
        return finish(c, preflight_ok_ ? 0 : -ENODEV, result);
      }
      if (c.command == "prepare") {
        auto result=prepare(c,p);return finish(c,prepare_error_,result);
      }
      if (c.command == "start") {
        if (!prepared_ || uint_at(p, "groups") != groups_ ||
            uint_at(p, "first_seq") != first_seq_)
          throw std::runtime_error("START differs from prepare");
        int error = tb_epoch_start(&epoch_, groups_, first_seq_);
        return finish(
            c, error,
            {{"start_accepted", boolean(epoch_.start_accepted)},
             {"arm_error",
              std::to_string(
                  epoch_.arm_attempted && !epoch_.start_attempted ? error : 0)},
             {"start_error",
              std::to_string(epoch_.start_attempted ? error : 0)}});
      }
      if(c.command=="wait"&&p!="{}")return finish(c,0,native_wait(c,p));
      if (c.command == "wait" || c.command == "stop") {
        tb_epoch_result r{};
        auto action_begin=mono_ns();
        int error = c.command == "wait"
                        ? tb_epoch_wait(&epoch_, c.deadline_ns, &r)
                        : tb_epoch_stop(&epoch_, c.deadline_ns, &r);
        auto action_end=mono_ns();
        auto f = terminal_fields(r);
        if (c.command == "stop") {
          response_evidence_["stop_action"]=obj({{"started_monotonic_ns",number(action_begin)},
              {"finished_monotonic_ns",number(action_end)},{"boot_id",agent_json_quote(boot_id_)},
              {"clock_domain",agent_json_quote(clock_domain_)}});
          f["stop_proved"] = boolean(r.stop_proved);
          f["first_error"] = std::to_string(r.first_error);
          f["stop_error"] = std::to_string(r.stop_error);
          if (!error && r.stop_proved)
            local_stop_request_ = c.request_id;
        }
        return finish(c, error, f);
      }
      if (c.command == "observe")
        return finish(
            c, 0, observe(uint_at(p, "first_ordinal"), uint_at(p, "limit")));
      if (c.command == "verify")
        return finish(c, 0, verify(c, p));
      if (c.command == "close")
        return finish(c, 0, close_resources(p));
      throw std::runtime_error("owner command refused");
    } catch (const std::exception &e) {
      record("owner-error", {{"reason", agent_json_quote(e.what())},
                             {"command", agent_json_quote(c.command)}});
      return finish(c, -EIO, {});
    }
  }
};
struct KmsgWindow {
  int lock = -1, fd = -1;
  uint64_t cursor = 0, begin = 0, end = 0;
  bool lost = false, complete = false;
  std::vector<std::string> records;
  size_t captured_bytes = 0;
  bool drain(bool capture) {
    char buffer[65536];
    for (unsigned count = 0; count < 65536; count++) {
      ssize_t n = read(fd, buffer, sizeof(buffer));
      if (n < 0 && errno == EINTR) {
        --count;
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return true;
      if (n < 0 && errno == EPIPE) {
        lost = true;
        continue;
      }
      if (n <= 0)
        return false;
      std::string raw(buffer, static_cast<size_t>(n));
      auto semi = raw.find(';');
      if (semi == std::string::npos)
        return false;
      std::istringstream prefix(raw.substr(0, semi));
      std::string token;
      std::vector<std::string> parts;
      while (std::getline(prefix, token, ','))
        parts.push_back(token);
      if (parts.size() != 4 && parts.size() != 5)
        return false;
      size_t used = 0;
      auto seq = std::stoull(parts[1], &used);
      if (used != parts[1].size())
        return false;
      auto us = std::stoull(parts[2], &used);
      if (used != parts[2].size() || us > UINT64_MAX / 1000)
        return false;
      if (capture) {
        captured_bytes += raw.size();
        if (captured_bytes > 8 * 1024 * 1024)
          return false;
        std::string message=trim(raw.substr(semi+1));
        auto marker=message.find("XDEV_EXT_XDOMAIN_ADMIT ");
        if(marker!=std::string::npos) {
          // Preserve raw printk bytes, expose only the canonical diagnostic body.
          auto end=message.find('\n',marker);
          message=message.substr(marker,end==std::string::npos?end:end-marker);
        }
        records.push_back(
            obj({{"seq", number(seq)},
                 {"monotonic_ns", number(us * 1000)},
                 {"message", agent_json_quote(message)},
                 {"raw",agent_json_quote(raw)}}));
      } else
        cursor = std::max<uint64_t>(cursor, seq);
    }
    return false;
  }
  void open_window() {
    if (mkdir("/root/xdev_ext/runtime", 0700) && errno != EEXIST)
      throw std::runtime_error("project runtime directory");
    struct stat parent{};
    if (lstat("/root/xdev_ext/runtime", &parent) || !S_ISDIR(parent.st_mode) ||
        parent.st_uid != geteuid() || (parent.st_mode & 0777) != 0700)
      throw std::runtime_error("unsafe project runtime directory");
    lock = open("/root/xdev_ext/runtime/xdomain-create.lock",
                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0)
      throw std::runtime_error("CREATE lock unavailable");
    struct stat st{};
    if (fstat(lock, &st) || st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
        !S_ISREG(st.st_mode))
      throw std::runtime_error("unsafe CREATE lock");
    if (flock(lock, LOCK_EX | LOCK_NB))
      throw std::runtime_error("another CREATE collector holds the lock");
    fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
      throw std::runtime_error("kmsg unavailable");
    if (!drain(false) || lost)
      throw std::runtime_error("cannot establish kmsg cursor");
    begin = mono_ns();
  }
  std::string capture() {
    end = mono_ns();
    complete = drain(true);
    return obj({{"records", arr(records)},
                {"window", obj({{"cursor_seq", number(cursor)},
                                {"begin_ns", number(begin)},
                                {"end_ns", number(end)},
                                {"exclusive_creator", "true"},
                                {"lock_held", "true"},
                                {"complete", boolean(complete)},
                                {"kmsg_lost", boolean(lost)},
                                {"readable", "true"}})}});
  }
  void close_metadata() {
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
    if (lock >= 0) {
      flock(lock, LOCK_UN);
      close(lock);
      lock = -1;
    }
  }
};

Fields PhysicalOwner::prepare(const tb::Command &c, const std::string &p) {
  if (!preflight_ok_ || prepared_)
    throw std::runtime_error("prepare requires matching successful preflight");
  for (const char *key :
       {"gpu_bdf", "nvidia_node", "link_token", "channel", "geometry", "flags"})
    if (agent_json_get(p, key) != agent_json_get(preflight_payload_, key))
      throw std::runtime_error(
          "prepare changed preflight identity/configuration");
  auto g = geometry(p);
  if (memcmp(&g, &geometry_, sizeof(g)))
    throw std::runtime_error("geometry changed after preflight");
  auto mode = string_at(p, "mode");
  groups_ = uint_at(p, "groups");
  first_seq_ = uint_at(p, "first_seq");
  seed_ = uint_at(p, "seed");
  if (!groups_ || groups_ > TB_MAX_GROUPS ||
      first_seq_ > UINT64_MAX - groups_ + 1 ||
      (mode == "single-group" && (groups_ != 1 || g.depth != 1)))
    throw std::runtime_error("mode/group bounds");
  std::vector<std::string> listing;
  auto current = find_link(uint_at(p, "link_token"), &listing);
  if (current.token != link_.token || current.local_inc != link_.local_inc ||
      current.remote_inc != link_.remote_inc || current.nhi != link_.nhi)
    throw std::runtime_error("link changed since preflight");
  if (uint_at(p, "flags") & ~XDEV_EXT_XDOMAIN_KNOWN_FLAGS ||
      uint_at(p, "channel") >= link_.channels)
    throw std::runtime_error("XDOMAIN flags/channel");
  // Every post-blocking-call continuation checks the same supervisor guard.
  std::string bdf = string_at(p, "gpu_bdf"), node = string_at(p, "nvidia_node"),
              ptx = string_at(p, "ptx_path");
  tb_gpu_request request{bdf.c_str(), node.c_str(), ptx.c_str(),
                         g.allocation_bytes};
  int status = tb_gpu_open(&gpu_, guard_, &request);
  gpu_diagnostic("tb_gpu_open", status);
  check_guard();
  if (status != TB_GPU_OK)
    throw std::runtime_error("GPU open status " + std::to_string(status));
  status = tb_gpu_fill(gpu_, seed_, identity_.role == "rx");
  gpu_diagnostic("tb_gpu_fill", status);
  check_guard();
  if (status != TB_GPU_OK)
    throw std::runtime_error("GPU fill status " + std::to_string(status));
  status = tb_gpu_registration(gpu_, &registration_);
  gpu_diagnostic("tb_gpu_registration", status);
  check_guard();
  if (status || registration_.registered_bytes != g.allocation_bytes)
    throw std::runtime_error("GPU registration identity");
  control([&]() {
    control_ = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    return control_ < 0 ? -errno : 0;
  });
  if (control_ < 0)
    throw std::runtime_error("peer control open");
  xdev_ext_peer_register registration{};
  registration.gpu_fd = registration_.nvidia_fd;
  registration.gpu_va = registration_.registered_address;
  registration.len = registration_.registered_bytes;
  check_guard();
  control([&]() {
    allocation_ = ioctl(control_, XDEV_EXT_PEER_REGISTER, &registration);
    return allocation_ < 0 ? -errno : 0;
  });
  check_guard();
  if (allocation_ < 0)
    throw std::runtime_error("peer REGISTER failed");
  record("peer-registered", {{"allocation_fd", std::to_string(allocation_)},
                             {"generation", number(registration.generation)},
                             {"registered_bytes", number(registration.len)}});
  status = observer_open(string_at(p, "observer_object"));
  check_guard();
  if (status)
    throw std::runtime_error("observer object load/attach failed: " +
                             std::to_string(status));
  xdev_ext_mech_create create{};
  create.abi_version = XDEV_EXT_MECH_ABI_VERSION;
  create.nr_stages = 1;
  create.pool_kind = XDEV_EXT_MECH_POOL_PEER;
  create.pool_fd = allocation_;
  create.layout = {g.frame_size, 0, g.seg_len,
                   static_cast<uint32_t>(g.group_bytes)};
  create.depth = g.depth;
  create.eventfd = -1;
  create.st[0].class_id = XDEV_EXT_MECH_CLASS_XDOMAIN;
  create.st[0].direction = identity_.role == "tx"
                               ? XDEV_EXT_MECH_DIR_TO_DEVICE
                               : XDEV_EXT_MECH_DIR_FROM_DEVICE;
  create.st[0].fd = control_;
  create.st[0].flags = static_cast<uint32_t>(uint_at(p, "flags"));
  create.st[0].arg0 = link_.token;
  create.st[0].arg1 = uint_at(p, "channel");
  auto *window = new KmsgWindow;
  control([&]() {
    window->open_window();
    return 0;
  });
  check_guard();
  control([&]() {
    native_name_="xdomain-"+std::to_string(getpid())+"-"+std::to_string(mono_ns());
    native_trace_.reset(new tb::NativeTraceCapture("/sys/kernel/tracing",evidence_dir_,native_name_));
    int rc=native_trace_->start();
    record("native-trace-instance",{{"instance_path",agent_json_quote(native_trace_->instance_path())},
                                  {"start_error",std::to_string(rc)}});
    if(rc)throw std::runtime_error("native trace start: "+std::to_string(rc));
    return rc;
  });
  check_guard();
  if(!native_trace_)throw std::runtime_error("native trace unavailable");
  tb::NativeTraceSnapshot before_create{};
  if(native_trace_->snapshot(&before_create))throw std::runtime_error("native trace pre-CREATE snapshot unavailable");
  create_begin_ns_=mono_ns();
  int error = tb_epoch_open(&epoch_, &create);
  create_end_ns_=mono_ns();
  auto diagnostic = window->capture();
  record("create-admission",
         {{"capture", diagnostic},
          {"create_error", std::to_string(error)},
          {"observed_session_id", number(epoch_.session_id)},
          {"requester", agent_json_quote(link_.nhi)}});
  auto admission=obj({{"records",agent_json_get(diagnostic,"records")},
      {"window",agent_json_get(diagnostic,"window")},
      {"expected",obj({{"requester",agent_json_quote(link_.nhi)},{"stage","0"},{"errno",std::to_string(error)}})}});
  if(error) {
    struct tb_guard_snapshot actual{};tb_guard_snapshot(guard_,&actual);
    if(epoch_.created || !(actual.hold_reasons & TB_HOLD_CREATE_UNKNOWN))
      throw std::runtime_error("pre-CREATE setup or post-CREATE authority failed: "+std::to_string(error));
    prepare_error_=error;
    return {{"session_id","0"},{"registration_bytes",number(registration_.registered_bytes)},
      {"producer_sync_proved",boolean(identity_.role=="tx")},{"guard_sync_proved",boolean(identity_.role=="rx")},
      {"create_error",std::to_string(error)},{"stop_proved","false"},{"stage_caps","null"},{"admission",admission}};
  }
  if (!window->complete || window->lost)
    throw std::runtime_error("incomplete CREATE diagnostic window");
  // These diagnostic-only fds are retained if CREATE became uncertain.
  if (!error)
    control([&]() {
      window->close_metadata();
      return 0;
    });
  check_guard();
  xdev_ext_mech_stage_caps caps{};
  caps.size = sizeof(caps);
  caps.version = XDEV_EXT_MECH_STAGE_CAPS_VERSION;
  caps.session_id = epoch_.session_id;
  caps.stage = 0;
  error = epoch_.io.mech(epoch_.io.opaque, epoch_.ring_fd,
                         XDEV_EXT_MECH_OP_STAGE_CAPS, &caps);
  check_guard();
  if (error || caps.size != sizeof(caps) ||
      caps.version != XDEV_EXT_MECH_STAGE_CAPS_VERSION ||
      caps.session_id != epoch_.session_id || caps.stage ||
      caps.family != XDEV_EXT_FAMILY_NETWORK)
    throw std::runtime_error("actual STAGE_CAPS failed");
  Fields facts;
#define CAP(name) facts[#name] = number(caps.name)
  CAP(size);
  CAP(version);
  CAP(session_id);
  CAP(stage);
  CAP(family);
  CAP(export_authority);
  CAP(reachability);
  CAP(requester_mapping);
  CAP(native_queue);
  CAP(producer_visibility);
  CAP(last_use_quiescence);
  CAP(invalidation);
  CAP(backing);
  CAP(refused);
#undef CAP
  facts["p2p_distance"] = std::to_string(caps.p2p_distance);
  record("stage-caps", facts);
  if (caps.refused && (caps.refused & ~XDEV_EXT_PEER_REFUSE_NO_P2P_PATH))
    throw std::runtime_error("unoverridable admission refusal");
  if (caps.reachability == XDEV_EXT_CAP_UNVERIFIED_FORCED &&
      !(uint_at(p, "flags") & XDEV_EXT_XDOMAIN_F_ALLOW_UNVERIFIED))
    throw std::runtime_error("unrequested forced admission");
  status = observer_configure();
  if (status)
    throw std::runtime_error("observer config failed");
  prepared_ = true;
  prepared_identity_ = agent_json_get(c.bounded_json, "identity");
  prepared_payload_ = p;
  return {{"session_id", number(epoch_.session_id)},
          {"registration_bytes", number(registration_.registered_bytes)},
          {"producer_sync_proved", boolean(identity_.role == "tx")},
          {"guard_sync_proved", boolean(identity_.role == "rx")},
          {"create_error", "0"},
          {"stop_proved", "false"},{"stage_caps",obj(facts)},{"admission",admission}};
}

Fields PhysicalOwner::native_wait(const tb::Command &c,const std::string &p) {
  const auto until=string_at(p,"until");
  const bool continued=until=="native-action-evidence";
  if(!native_trace_||!prepared_||!epoch_.start_accepted)throw std::runtime_error("native wait requires actual START");
  auto identity=agent_json_get(c.bounded_json,"identity");
  std::string action="null";
  if(continued) {
    if(pending_identity_.empty())throw std::runtime_error("continued evidence has no owner pending sample");
    action=agent_json_get(p,"action");
    if(agent_json_get(action,"identity")!=pending_identity_)throw std::runtime_error("continued action differs from original pending identity");
    identity=pending_identity_;
  }else {
    if(until!="accepted-native-inflight")throw std::runtime_error("native WAIT discriminator");
    native_max_age_ms_=uint_at(p,"max_age_ms");
    if(!native_max_age_ms_||native_max_age_ms_>120000)throw std::runtime_error("native sample age");
  }
  for(;;) {
    check_guard();
    if(mono_ns()>=c.deadline_ns) {tb_guard_hold(guard_,TB_HOLD_DEADLINE);throw std::runtime_error("native WAIT deadline");}
    struct tb_guard_snapshot before{};tb_guard_snapshot(guard_,&before);
    uint64_t ticket=0;
    if(!continued&&tb_guard_begin(guard_,TB_OP_WAIT,&ticket))throw std::runtime_error("native WAIT admission");
    tb::NativeTraceSnapshot sample{};
    int error=native_trace_->snapshot(&sample,continued);
    if(!continued&&tb_guard_end(guard_,ticket,before.phase,before.native_safe,before.gpu_safe))throw std::runtime_error("native WAIT returned after HELD");
    if(error)throw std::runtime_error("native trace snapshot: "+std::to_string(error));
    auto boot=trim(read_file("/proc/sys/kernel/random/boot_id",256));
    if(boot!=boot_id_||running_build_id()!=build_id_)throw std::runtime_error("native capture boot/build changed");
    if(!continued) {
      std::vector<std::string> listing;auto current=find_link(link_.token,&listing);
      if(current.local_inc!=link_.local_inc||current.remote_inc!=link_.remote_inc||current.nhi!=link_.nhi)throw std::runtime_error("native capture incarnation changed");
    }
    const auto raw_path=evidence_dir_+"/"+native_name_+"-request-"+number(c.request_id)+".trace";
    persist_metadata(raw_path,sample.raw_trace);
    auto receipt=obj({{"version","1"},{"identity",identity},{"boot_id",agent_json_quote(boot_id_)},
        {"kernel_build_id",agent_json_quote(build_id_)},{"source_commit",agent_json_quote(identity_.sha)},
        {"clock",agent_json_quote("CLOCK_MONOTONIC")},{"clock_domain",agent_json_quote(clock_domain_)},
        {"nhi_bdf",agent_json_quote(link_.nhi)},{"link_token",number(link_.token)},
        {"local_inc",number(link_.local_inc)},{"remote_inc",number(link_.remote_inc)},
        {"create_begin_ns",number(create_begin_ns_)},{"create_end_ns",number(create_end_ns_)},
        {"capture_begin_ns",number(sample.begin_ns)},{"capture_end_ns",number(sample.end_ns)},
        {"captured_monotonic_ns",number(sample.captured_monotonic_ns)},{"trace_dropped",number(sample.lost_events)},
        {"formats",obj({{"native_event",agent_json_quote(sample.event_format)}})},
        {"raw_path",agent_json_quote(raw_path)}});
    auto expected=obj({{"identity",identity},{"boot_id",agent_json_quote(boot_id_)},
        {"kernel_build_id",agent_json_quote(build_id_)},{"source_commit",agent_json_quote(identity_.sha)},
        {"clock_domain",agent_json_quote(clock_domain_)},{"nhi_bdf",agent_json_quote(link_.nhi)},
        {"link_token",number(link_.token)},{"local_inc",number(link_.local_inc)},{"remote_inc",number(link_.remote_inc)},
        {"session_id",number(epoch_.session_id)},{"stage","0"},{"batch_key",number(first_seq_)},
        {"direction",number(identity_.role=="tx"?XDEV_EXT_MECH_DIR_TO_DEVICE:XDEV_EXT_MECH_DIR_FROM_DEVICE)},
        {"group_bytes",number(geometry_.group_bytes)},{"max_age_ms",number(native_max_age_ms_)}});
    Fields payload={{"native_trace",obj({{"raw_trace",agent_json_quote(sample.raw_trace)},
                                        {"receipt",receipt},{"expected",expected}})}};
    if(obj(payload).size()>TB_MAX_JSON-16384)throw std::runtime_error("native trace wire capacity");
    auto qualification=metadata_helper(helpers_,obj({{"op",agent_json_quote("native")},
       {"raw_trace",agent_json_quote(sample.raw_trace)},{"receipt",receipt},{"expected",expected},
       {"action",action}}),c.deadline_ns);
    check_guard();
    record("native-trace-qualification",{{"request_id",number(c.request_id)},{"result",qualification},
           {"receipt",receipt},{"expected",expected},
           {"acceptance_seq_basis",agent_json_quote("one-based raw ledger row coordinate; not a kernel counter")}});
    if(continued) {
      tb_epoch_result terminal{};
      (void)tb_epoch_snapshot(&epoch_,&terminal);
      payload["terminal"]=obj(terminal_fields(terminal));
      try {
        std::vector<std::string> listing;auto current=find_link(link_.token,&listing);
        response_evidence_["link_up"]=boolean(current.up&&current.local_inc==link_.local_inc&&current.remote_inc==link_.remote_inc);
      }catch(const std::exception &) {response_evidence_["link_up"]="false";}
      return payload; // Qualification remains independently checked by coordinator.
    }
    if(string_at(qualification,"status")=="ready") {pending_identity_=identity;return payload;}
    poll(nullptr,0,5);
  }
}

void PhysicalOwner::validate_stop_pair(const std::string &p,bool require_complete) {
  struct tb_guard_snapshot snap{};
  tb_guard_snapshot(guard_, &snap);
  if (snap.phase != TB_PHASE_DRAINED_SAFE || !epoch_.stop_proved ||
      !local_stop_request_)
    throw std::runtime_error("paired cleanup requires local successful STOP");
  auto receipts = agent_json_array(agent_json_get(p, "stop_receipts"));
  if (receipts.size() != 2)
    throw std::runtime_error("two STOP receipts required");
  std::set<std::string> roles;
  for (const auto &receipt : receipts) {
    auto i = agent_json_get(receipt, "identity");
    auto role = string_at(i, "role");
    if ((role != "tx" && role != "rx") || !roles.insert(role).second ||
        uint_at(i, "version") != TB_CHECK_VERSION ||
        string_at(i, "run_id") != identity_.run_id ||
        string_at(i, "sha") != identity_.sha ||
        string_at(i, "case") != identity_.case_id ||
        string_at(i, "direction") != identity_.direction ||
        uint_at(i, "epoch") != identity_.epoch || !uint_at(i, "request_id"))
      throw std::runtime_error("STOP receipt identity");
    if (string_at(receipt, "command") != "stop" ||
        string_at(receipt, "phase") != "DRAINED_SAFE" ||
        string_at(receipt, "fate") != "SAFE" ||
        agent_json_get(receipt, "error") != "0" || bool_at(receipt, "held") ||
        uint_at(receipt, "part_index") || uint_at(receipt, "part_count") != 1 ||
        !bool_at(receipt, "payload.stop_proved") ||
        agent_json_get(receipt, "payload.first_error") != "0" ||
        agent_json_get(receipt, "payload.stop_error") != "0" ||
        !bool_at(receipt, "payload.stats_valid") ||
        !bool_at(receipt, "payload.transport_valid"))
      throw std::runtime_error("STOP receipt not successful");
    if (role == identity_.role &&
        (uint_at(i, "request_id") != local_stop_request_ ||
         uint_at(receipt, "payload.stats.session_id") != epoch_.session_id))
      throw std::runtime_error("STOP local request mismatch");
    // Safe release is also needed for no-START bringup and override. Only
    // payload verification requires completion of every requested group.
    const auto completed=uint_at(receipt, "payload.stats.batches_done");
    if ((require_complete && completed != groups_) || completed > groups_)
      throw std::runtime_error("STOP group count");
    for (auto key : {"batches_abort", "rejects", "held", "sequestered",
                     "timeouts", "inflight", "protocol_err"})
      if (uint_at(receipt, std::string("payload.stats.") + key))
        throw std::runtime_error("STOP not settled");
    if (agent_json_get(receipt, "payload.stats.last_err") != "0")
      throw std::runtime_error("STOP last error");
    for (auto key : {"native_controls", "pending_acks", "uncertain_controls"})
      if (uint_at(receipt, std::string("payload.transport.v3.v2.v1.") + key))
        throw std::runtime_error("STOP transport pending");
    if (uint_at(receipt, "payload.transport.v3.v2.v1.size") !=
            sizeof(xdev_ext_mech_transport_stats_v4) ||
        uint_at(receipt, "payload.transport.v3.v2.v1.version") !=
            XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4 ||
        uint_at(receipt, "payload.transport.v3.v2.v1.session_id") !=
            uint_at(receipt, "payload.stats.session_id"))
      throw std::runtime_error("STOP transport identity");
  }
  check_guard();
  if (tb_guard_pair_stopped(guard_))
    throw std::runtime_error("pair STOP proof rejected");
}

Fields PhysicalOwner::verify(const tb::Command &c, const std::string &p) {
  (void)c;
  validate_stop_pair(p,true);
  auto raw = agent_json_array(agent_json_get(p, "extents"));
  if (identity_.role == "tx" &&
      (raw.size() != 1 || uint_at(raw[0], "dst_off") != 0 ||
       uint_at(raw[0], "src_off") != 0 ||
       uint_at(raw[0], "len") != geometry_.allocation_bytes ||
       uint_at(raw[0], "seed") != seed_ ||
       uint_at(raw[0], "kind") != TB_EXPECT_PAYLOAD))
    throw std::runtime_error(
        "TX verify must cover unchanged sender allocation");
  if (raw.empty() || raw.size() != uint_at(p, "extent_count") ||
      raw.size() > geometry_.allocation_bytes / TB_NATIVE_TILE)
    throw std::runtime_error("extent count");
  std::vector<tb_verify_extent> extents;
  extents.reserve(raw.size());
  uint64_t cursor = 0;
  for (const auto &e : raw) {
    tb_verify_extent v{uint_at(e, "dst_off"),
                       uint_at(e, "src_off"),
                       uint_at(e, "len"),
                       uint_at(e, "seed"),
                       static_cast<uint32_t>(uint_at(e, "kind")),
                       static_cast<uint32_t>(uint_at(e, "reserved"))};
    if (!v.len || v.dst_off != cursor ||
        v.dst_off > geometry_.allocation_bytes ||
        v.len > geometry_.allocation_bytes - v.dst_off ||
        v.src_off > geometry_.allocation_bytes ||
        v.len > geometry_.allocation_bytes - v.src_off ||
        (v.kind != TB_EXPECT_PAYLOAD && v.kind != TB_EXPECT_GUARD) ||
        v.reserved || v.dst_off % TB_NATIVE_TILE ||
        v.src_off % TB_NATIVE_TILE || v.len % TB_NATIVE_TILE ||
        (v.kind == TB_EXPECT_PAYLOAD && v.seed != seed_) ||
        (v.kind == TB_EXPECT_GUARD &&
         (v.seed != (seed_ ^ UINT64_C(0xd6e8feb86659fd93)) ||
          v.src_off != v.dst_off)))
      throw std::runtime_error("invalid complete allocation expectation");
    cursor += v.len;
    extents.push_back(v);
  }
  if (cursor != geometry_.allocation_bytes)
    throw std::runtime_error("expectations omit guards");
  auto cookie = uint_at(p, "launch_cookie");
  if (!cookie)
    throw std::runtime_error("zero launch cookie");
  check_guard();
  if (tb_guard_pair_stopped(guard_))
    throw std::runtime_error("pair STOP proof rejected");
  int status = tb_gpu_receive_visible(gpu_);
  gpu_diagnostic("tb_gpu_receive_visible", status);
  check_guard();
  if (status != TB_GPU_OK)
    throw std::runtime_error("receive visibility failed");
  tb_verify_result summary{};
  status =
      tb_gpu_verify(gpu_, extents.data(), extents.size(), cookie, &summary);
  gpu_diagnostic("tb_gpu_verify", status);
  check_guard();
  if (status != TB_GPU_OK || summary.bytes != geometry_.allocation_bytes ||
      summary.mismatches || summary.first_bad != UINT64_MAX ||
      summary.launch_cookie != cookie)
    throw std::runtime_error("GPU verification failed or sentinel unchanged");
  return {{"bytes", number(summary.bytes)},
          {"mismatches", number(summary.mismatches)},
          {"first_bad", number(summary.first_bad)},
          {"launch_cookie", number(summary.launch_cookie)},
          {"visibility",
           agent_json_quote(registration_.visibility == TB_GPU_NATIVE_OWNER
                                ? "NATIVE_OWNER"
                                : "HOST_FLUSH_OWNER")},
          {"visibility_error", "0"}};
}

Fields PhysicalOwner::close_resources(const std::string &p) {
  check_guard();
  if ((identity_.case_id != "functional-epochs" && identity_.case_id != "bulk-static") || p != "{}")
    validate_stop_pair(p,false);
  uint32_t permissions = tb_guard_cleanup_permissions(guard_);
  uint32_t required = TB_CLEANUP_EPOCH_FDS | TB_CLEANUP_PEER_FD |
                      TB_CLEANUP_GPU_FREE | TB_CLEANUP_CONTEXT_DESTROY;
  if ((permissions & required) != required)
    throw std::runtime_error("cleanup not permitted");
  if (tb_epoch_close(&epoch_))
    throw std::runtime_error("epoch close refused");
  check_guard();
  if (ops_) {
    cleanup([&]() { return bpf_link__destroy(ops_); });
    ops_ = nullptr;
  }
  if (observer_) {
    cleanup([&]() {
      bpf_object__close(observer_);
      return 0;
    });
    observer_ = nullptr;
  }
  if (allocation_ >= 0) {
    cleanup([&]() { return close(allocation_) ? -errno : 0; });
    allocation_ = -1;
  }
  if (control_ >= 0) {
    cleanup([&]() { return close(control_) ? -errno : 0; });
    control_ = -1;
  }
  if (native_trace_)
    cleanup([&]() { return native_trace_->close_safe(); });
  check_guard();
  int status = tb_gpu_close(gpu_);
  gpu_diagnostic("tb_gpu_close", status);
  check_guard();
  if (status != TB_GPU_OK)
    throw std::runtime_error("GPU close refused");
  gpu_ = nullptr;
  return {{"closed", "true"}, {"retained_resources", "[]"}};
}

int PhysicalOwner::observer_open(const std::string &path) {
  check_guard();
  long error = control([&]() {
    observer_ = bpf_object__open_file(path.c_str(), nullptr);
    if (!observer_)
      return errno ? -errno : -EIO;
    return static_cast<int>(libbpf_get_error(observer_));
  });
  if (error) {
    observer_ = nullptr;
    return static_cast<int>(error);
  }
  check_guard();
  error = control([&]() { return bpf_object__load(observer_); });
  check_guard();
  if (error)
    return static_cast<int>(error);
  auto *config =
      bpf_object__find_map_by_name(observer_, TB_XD_OBSERVER_CONFIG_MAP);
  auto *records =
      bpf_object__find_map_by_name(observer_, TB_XD_OBSERVER_RECORD_MAP);
  auto *ops = bpf_object__find_map_by_name(observer_, TB_XD_OBSERVER_OPS_MAP);
  if (!config || !records || !ops ||
      bpf_map__type(config) != BPF_MAP_TYPE_ARRAY ||
      bpf_map__key_size(config) != sizeof(uint32_t) ||
      bpf_map__value_size(config) != sizeof(tb_xd_observer_config) ||
      bpf_map__max_entries(config) != 1 ||
      bpf_map__type(records) != BPF_MAP_TYPE_ARRAY ||
      bpf_map__key_size(records) != sizeof(uint32_t) ||
      bpf_map__value_size(records) != sizeof(tb_xd_observer_record) ||
      bpf_map__max_entries(records) != TB_XD_OBSERVER_MAX_GROUPS ||
      bpf_map__type(ops) != BPF_MAP_TYPE_STRUCT_OPS)
    return -EPROTO;
  check_guard();
  error = control([&]() {
    ops_ = bpf_map__attach_struct_ops(ops);
    if (!ops_)
      return errno ? -errno : -EIO;
    return static_cast<int>(libbpf_get_error(ops_));
  });
  if (error) {
    ops_ = nullptr;
    return static_cast<int>(error);
  }
  check_guard();
  return 0;
}
int PhysicalOwner::observer_configure() {
  tb_xd_observer_config config{};
  config.size = sizeof(config);
  config.version = TB_XD_OBSERVER_VERSION;
  config.session_id = epoch_.session_id;
  config.first_seq = first_seq_;
  config.groups = groups_;
  config.epoch = identity_.epoch;
  config.allocation_bytes = registration_.registered_bytes;
  config.direction = identity_.role == "tx" ? XDEV_EXT_MECH_DIR_TO_DEVICE
                                            : XDEV_EXT_MECH_DIR_FROM_DEVICE;
  config.stage = 0;
  auto *map =
      bpf_object__find_map_by_name(observer_, TB_XD_OBSERVER_CONFIG_MAP);
  if (!map)
    return -ENOENT;
  uint32_t zero = 0;
  check_guard();
  int error = control([&]() {
    return bpf_map_update_elem(bpf_map__fd(map), &zero, &config, BPF_ANY)
               ? -errno
               : 0;
  });
  check_guard();
  return error ? -errno : 0;
}
Fields PhysicalOwner::observe(uint64_t first, uint64_t limit) {
  struct tb_guard_snapshot snap{};
  tb_guard_snapshot(guard_, &snap);
  if (snap.phase != TB_PHASE_DRAINED_SAFE || !epoch_.stop_proved ||
      !observer_ || !limit || limit > 32 || first >= groups_)
    throw std::runtime_error(
        "observation requires successful STOP and bounded page");
  auto *map =
      bpf_object__find_map_by_name(observer_, TB_XD_OBSERVER_RECORD_MAP);
  auto *errors =
      bpf_object__find_map_by_name(observer_, TB_XD_OBSERVER_ERROR_MAP);
  if (!map || !errors || bpf_map__type(errors) != BPF_MAP_TYPE_ARRAY ||
      bpf_map__key_size(errors) != sizeof(uint32_t) ||
      bpf_map__value_size(errors) != sizeof(tb_xd_observer_errors) ||
      bpf_map__max_entries(errors) != 1)
    throw std::runtime_error("observer global error map unavailable");
  uint32_t zero = 0;
  tb_xd_observer_errors error_state{};
  check_guard();
  if (bpf_map_lookup_elem(bpf_map__fd(errors), &zero, &error_state))
    throw std::runtime_error("observer global errors unavailable");
  uint64_t error_bits = error_state.error_bits;
  if (error_state.observations_lost)
    throw std::runtime_error("observer lost observations");
  std::vector<std::string> records;
  auto end = std::min(groups_, first + limit);
  for (uint64_t ordinal = first; ordinal < end; ordinal++) {
    uint32_t index = static_cast<uint32_t>(ordinal);
    tb_xd_observer_record record{};
    check_guard();
    if (bpf_map_lookup_elem(bpf_map__fd(map), &index, &record))
      throw std::runtime_error("observer record unavailable");
    if (record.size != sizeof(record) ||
        record.version != TB_XD_OBSERVER_VERSION ||
        record.session_id != epoch_.session_id ||
        record.key != first_seq_ + ordinal || record.epoch != identity_.epoch ||
        !record.build_attempts || record.cqe_seen != 1 || !record.nr_spans ||
        record.nr_spans > TB_XD_OBSERVER_MAX_SPANS ||
        record.local_inc != link_.local_inc ||
        record.remote_inc != link_.remote_inc)
      throw std::runtime_error("observer record identity/completeness");
    error_bits |= record.error_bits;
    std::vector<std::string> spans;
    for (uint32_t i = 0; i < record.nr_spans; i++)
      spans.push_back(
          obj({{"allocation_off", number(record.spans[i].allocation_off)},
               {"data_off", number(record.spans[i].data_off)},
               {"len", number(record.spans[i].len)}}));
    const auto &q = record.completion;
    Fields cqe = {{"status", std::to_string(q.status)},
                  {"outcome", number(q.outcome)},
                  {"remote", number(q.remote)},
                  {"elems_done", number(q.elems_done)},
                  {"group", number(q.group)},
                  {"bytes", number(q.bytes)},
                  {"crc_errors", number(q.crc_errors)},
                  {"rsvd", number(q.rsvd)},
                  {"tag", agent_json_quote(hex(q.tag, sizeof(q.tag)))}};
    Fields r = {{"session_id", number(record.session_id)},
                {"batch_id", number(record.batch_id)},
                {"key", number(record.key)},
                {"epoch", number(record.epoch)},
                {"generation", number(record.generation)},
                {"local_inc", number(record.local_inc)},
                {"remote_inc", number(record.remote_inc)},
                {"direction", number(record.direction)},
                {"channel", number(record.channel)},
                {"build_attempts", number(record.build_attempts)},
                {"cqe_seen", number(record.cqe_seen)},
                {"error_bits", number(record.error_bits)},
                {"spans", arr(spans)},
                {"tag", agent_json_quote(hex(record.tag, sizeof(record.tag)))},
                {"completion", obj(cqe)}};
    records.push_back(obj({{"ordinal", number(ordinal)}, {"record", obj(r)}}));
  }
  return {{"records", arr(records)},
          {"next_ordinal", end < groups_ ? number(end) : "null"},
          {"total", number(groups_)},
          {"error_bits", number(error_bits)}};
}

} // namespace

int main(int argc, char **argv) {
  std::string identity_path, evidence_dir, kernel_receipt, thunderbolt_log, thunderbolt_receipt, helpers;
  char executable[4096];auto executable_bytes=readlink("/proc/self/exe",executable,sizeof(executable)-1);
  if(executable_bytes>0){executable[executable_bytes]=0;helpers=executable;helpers=helpers.substr(0,helpers.rfind('/'));}
  bool exclusive = false;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--exclusive-creator") {
      exclusive = true;
      continue;
    }
    if (i + 1 >= argc) {
      fprintf(stderr, "missing agent option value\n");
      return 2;
    }
    if (arg == "--identity")
      identity_path = argv[++i];
    else if (arg == "--evidence-dir")
      evidence_dir = argv[++i];
    else if (arg == "--kernel-receipt")
      kernel_receipt = argv[++i];
    else if(arg=="--thunderbolt-log")thunderbolt_log=argv[++i];
    else if(arg=="--thunderbolt-receipt")thunderbolt_receipt=argv[++i];
    else if(arg=="--helpers-dir")helpers=argv[++i];
    else {
      fprintf(stderr, "unknown agent option\n");
      return 2;
    }
  }
  if (identity_path.empty() || evidence_dir.empty() || kernel_receipt.empty()) {
    fprintf(stderr, "usage: xdomain_agent --identity FILE --evidence-dir DIR "
                    "--kernel-receipt FILE [--exclusive-creator]\n");
    return 2;
  }
  try {
    auto input = read_file(identity_path, 16384);
    tb::Identity identity{
        string_at(input, "run_id"),    string_at(input, "sha"),
        string_at(input, "role"),      string_at(input, "case"),
        string_at(input, "direction"), uint_at(input, "epoch")};
    if (uint_at(input, "version") != TB_CHECK_VERSION)
      throw std::runtime_error("identity version");
    if (setsid() < 0 && errno != EPERM)
      throw std::runtime_error("agent independent session");
    std::string durable_path;
    int durable =
        tb::open_durable_record(evidence_dir, identity, &durable_path);
    if (durable < 0)
      throw std::runtime_error("durable evidence unavailable before acquire");
    tb_guard *guard = nullptr;
    if (tb_guard_new(TB_BACKING_GPU, &guard))
      throw std::runtime_error("guard allocation");
    auto *owner =
        new PhysicalOwner(guard, identity, kernel_receipt, exclusive, durable,
                          thunderbolt_log,thunderbolt_receipt,helpers,evidence_dir);
    int result = tb::run_agent(STDIN_FILENO, STDOUT_FILENO, durable, identity,
                               guard, *owner);
    if (result)
      return 1;
    struct tb_guard_snapshot snapshot{};
    tb_guard_snapshot(guard, &snapshot);
    if (snapshot.held || snapshot.phase != TB_PHASE_CLOSED) {
      tb_guard_hold(guard, TB_HOLD_PROTOCOL);
      for (;;)
        pause();
    }
    close(durable);
    delete owner;
    tb_guard_delete(guard);
    return 0;
  } catch (const std::exception &e) {
    fprintf(stderr, "agent setup unavailable: %s\n", e.what());
    return 1;
  }
}
