// SPDX-License-Identifier: GPL-2.0
#include "agent_supervisor.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <regex>
#include <set>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace tb {
namespace {
struct Json {
  enum Type { Null, Bool, Number, String, Array, Object } type = Null;
  std::string text;
  std::vector<Json> array;
  std::map<std::string, Json> object;
  static Json str(const std::string &s) {
    Json j;
    j.type = String;
    j.text = s;
    return j;
  }
  static Json num(uint64_t n) {
    Json j;
    j.type = Number;
    j.text = std::to_string(n);
    return j;
  }
  static Json signed_num(int n) {
    Json j;
    j.type = Number;
    j.text = std::to_string(n);
    return j;
  }
  static Json boolean(bool b) {
    Json j;
    j.type = Bool;
    j.text = b ? "true" : "false";
    return j;
  }
  static Json obj() {
    Json j;
    j.type = Object;
    return j;
  }
  static Json list() {
    Json j;
    j.type = Array;
    return j;
  }
  const Json &at(const std::string &k) const {
    if (type != Object || !object.count(k))
      throw std::runtime_error("missing field: " + k);
    return object.at(k);
  }
  uint64_t u() const {
    if (type != Number || text.empty() || text[0] == '-')
      throw std::runtime_error("unsigned integer");
    size_t n = 0;
    auto r = std::stoull(text, &n);
    if (n != text.size())
      throw std::runtime_error("integer");
    return r;
  }
  std::string s() const {
    if (type != String)
      throw std::runtime_error("string");
    return text;
  }
};
void utf8(std::string &s, unsigned cp) {
  if (cp <= 0x7f)
    s += static_cast<char>(cp);
  else if (cp <= 0x7ff) {
    s += static_cast<char>(0xc0 | (cp >> 6));
    s += static_cast<char>(0x80 | (cp & 63));
  } else if (cp <= 0xffff) {
    s += static_cast<char>(0xe0 | (cp >> 12));
    s += static_cast<char>(0x80 | ((cp >> 6) & 63));
    s += static_cast<char>(0x80 | (cp & 63));
  } else {
    s += static_cast<char>(0xf0 | (cp >> 18));
    s += static_cast<char>(0x80 | ((cp >> 12) & 63));
    s += static_cast<char>(0x80 | ((cp >> 6) & 63));
    s += static_cast<char>(0x80 | (cp & 63));
  }
}
void check_utf8(const std::string &s) {
  for (size_t i = 0; i < s.size();) {
    unsigned c = static_cast<unsigned char>(s[i++]);
    if (c < 128)
      continue;
    unsigned count = 0, cp = 0, min = 0;
    if (c >= 0xc2 && c <= 0xdf) {
      count = 1;
      cp = c & 31;
      min = 128;
    } else if (c >= 0xe0 && c <= 0xef) {
      count = 2;
      cp = c & 15;
      min = 2048;
    } else if (c >= 0xf0 && c <= 0xf4) {
      count = 3;
      cp = c & 7;
      min = 65536;
    } else
      throw std::runtime_error("UTF-8");
    while (count--) {
      if (i == s.size())
        throw std::runtime_error("UTF-8 truncation");
      c = static_cast<unsigned char>(s[i++]);
      if ((c & 0xc0) != 0x80)
        throw std::runtime_error("UTF-8 continuation");
      cp = (cp << 6) | (c & 63);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
      throw std::runtime_error("UTF-8 scalar");
  }
}
class Parser {
  const std::string &s;
  size_t p = 0, nodes = 0;
  void ws() {
    while (p < s.size() &&
           (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n'))
      ++p;
  }
  char take() {
    if (p == s.size())
      throw std::runtime_error("truncated JSON");
    return s[p++];
  }
  unsigned hex4() {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
      char c = take();
      v <<= 4;
      if (c >= '0' && c <= '9')
        v += c - '0';
      else if (c >= 'a' && c <= 'f')
        v += c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        v += c - 'A' + 10;
      else
        throw std::runtime_error("unicode escape");
    }
    return v;
  }
  std::string string() {
    if (take() != '"')
      throw std::runtime_error("string expected");
    std::string v;
    for (;;) {
      char c = take();
      if (c == '"')
        break;
      if (static_cast<unsigned char>(c) < 32)
        throw std::runtime_error("string control");
      if (c == '\\') {
        c = take();
        switch (c) {
        case '"':
        case '\\':
        case '/':
          v += c;
          break;
        case 'b':
          v += '\b';
          break;
        case 'f':
          v += '\f';
          break;
        case 'n':
          v += '\n';
          break;
        case 'r':
          v += '\r';
          break;
        case 't':
          v += '\t';
          break;
        case 'u': {
          unsigned cp = hex4();
          if (cp >= 0xd800 && cp <= 0xdbff) {
            if (take() != '\\' || take() != 'u')
              throw std::runtime_error("surrogate");
            unsigned lo = hex4();
            if (lo < 0xdc00 || lo > 0xdfff)
              throw std::runtime_error("surrogate");
            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
          } else if (cp >= 0xdc00 && cp <= 0xdfff)
            throw std::runtime_error("surrogate");
          utf8(v, cp);
          break;
        }
        default:
          throw std::runtime_error("string escape");
        }
      } else
        v += c;
    }
    check_utf8(v);
    return v;
  }
  Json value(unsigned depth) {
    if (depth > 32 || ++nodes > 2500000)
      throw std::runtime_error("JSON bounds");
    ws();
    if (p == s.size())
      throw std::runtime_error("empty JSON");
    Json j;
    char c = s[p];
    if (c == '{') {
      ++p;
      j = Json::obj();
      ws();
      if (p < s.size() && s[p] == '}') {
        ++p;
        return j;
      }
      for (;;) {
        ws();
        auto key = string();
        ws();
        if (take() != ':')
          throw std::runtime_error("colon");
        auto v = value(depth + 1);
        if (!j.object.emplace(key, std::move(v)).second)
          throw std::runtime_error("duplicate key");
        ws();
        char end = take();
        if (end == '}')
          break;
        if (end != ',')
          throw std::runtime_error("object separator");
      }
      return j;
    }
    if (c == '[') {
      ++p;
      j = Json::list();
      ws();
      if (p < s.size() && s[p] == ']') {
        ++p;
        return j;
      }
      for (;;) {
        j.array.push_back(value(depth + 1));
        if (j.array.size() > 262144)
          throw std::runtime_error("array bound");
        ws();
        char end = take();
        if (end == ']')
          break;
        if (end != ',')
          throw std::runtime_error("array separator");
      }
      return j;
    }
    if (c == '"')
      return Json::str(string());
    if (c == 't' || c == 'f' || c == 'n') {
      std::string word = c == 't' ? "true" : c == 'f' ? "false" : "null";
      if (s.compare(p, word.size(), word))
        throw std::runtime_error("literal");
      p += word.size();
      return c == 'n' ? Json() : Json::boolean(c == 't');
    }
    j.type = Json::Number;
    size_t first = p;
    if (c == '-')
      ++p;
    size_t digits = p;
    if (p == s.size() || !std::isdigit(static_cast<unsigned char>(s[p])))
      throw std::runtime_error("integer expected");
    while (p < s.size() && std::isdigit(static_cast<unsigned char>(s[p])))
      ++p;
    if (p - digits > 1 && s[digits] == '0')
      throw std::runtime_error("leading zero");
    j.text = s.substr(first, p - first);
    if (j.text[0] == '-') {
      size_t used = 0;
      std::stoll(j.text, &used);
      if (used != j.text.size())
        throw std::runtime_error("integer");
    } else
      j.u();
    return j;
  }

public:
  explicit Parser(const std::string &v) : s(v) {}
  Json parse() {
    auto j = value(0);
    ws();
    if (p != s.size())
      throw std::runtime_error("trailing JSON");
    return j;
  }
};
std::string quote(const std::string &s) {
  std::string o = "\"";
  const char *hex = "0123456789abcdef";
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') {
      o += '\\';
      o += static_cast<char>(c);
    } else if (c < 32) {
      o += "\\u00";
      o += hex[c >> 4];
      o += hex[c & 15];
    } else
      o += static_cast<char>(c);
  }
  return o + '"';
}
std::string dump(const Json &j) {
  switch (j.type) {
  case Json::Null:
    return "null";
  case Json::Bool:
  case Json::Number:
    return j.text;
  case Json::String:
    return quote(j.text);
  case Json::Array: {
    std::string s = "[";
    bool first = true;
    for (const auto &v : j.array) {
      if (!first)
        s += ',';
      first = false;
      s += dump(v);
    }
    return s + ']';
  }
  case Json::Object: {
    std::string s = "{";
    bool first = true;
    for (const auto &kv : j.object) {
      if (!first)
        s += ',';
      first = false;
      s += quote(kv.first) + ':' + dump(kv.second);
    }
    return s + '}';
  }
  }
  throw std::runtime_error("JSON type");
}
void exact(const Json &j, std::initializer_list<const char *> names) {
  if (j.type != Json::Object || j.object.size() != names.size())
    throw std::runtime_error("schema fields");
  for (auto n : names)
    j.at(n);
}
uint64_t bounded(const Json &j, uint64_t lo, uint64_t hi) {
  auto n = j.u();
  if (n < lo || n > hi)
    throw std::runtime_error("integer bound");
  return n;
}
uint64_t now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}
const char *phase_name(tb_phase p) {
  static const char *names[] = {"NEW",
                                "GPU_BUSY",
                                "GPU_READY",
                                "EXTERNAL_READY",
                                "CREATE_ATTEMPTED",
                                "SESSION_CREATED",
                                "START_ACCEPTED",
                                "TRANSPORT_DONE",
                                "DRAINED_SAFE",
                                "VERIFYING",
                                "VERIFIED",
                                "CLOSED",
                                "FAILED_SAFE",
                                "HELD"};
  if (p < TB_PHASE_NEW || p > TB_PHASE_HELD)
    return "HELD";
  return names[p];
}
Json identity_json(const Identity &id, uint64_t request) {
  Json i = Json::obj();
  i.object = {
      {"version", Json::num(1)},       {"run_id", Json::str(id.run_id)},
      {"sha", Json::str(id.sha)},      {"role", Json::str(id.role)},
      {"case", Json::str(id.case_id)}, {"direction", Json::str(id.direction)},
      {"epoch", Json::num(id.epoch)},  {"request_id", Json::num(request)}};
  return i;
}
void signals_setup() {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGINT);
  if (pthread_sigmask(SIG_BLOCK, &mask, nullptr))
    throw std::runtime_error("signal mask");
  struct sigaction sa{};
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGPIPE, &sa, nullptr))
    throw std::runtime_error("SIGPIPE");
}
Json inventory() {
  Json f = Json::list();
  DIR *d = opendir("/proc/self/fd");
  if (!d)
    return f;
  while (auto *e = readdir(d)) {
    if (!std::isdigit(static_cast<unsigned char>(e->d_name[0])))
      continue;
    int fd = std::stoi(e->d_name);
    if (fd == dirfd(d))
      continue;
    Json item = Json::obj();
    item.object["fd"] = Json::num(static_cast<uint64_t>(fd));
    char target[4096];
    std::string path = "/proc/self/fd/" + std::string(e->d_name);
    ssize_t n = readlink(path.c_str(), target, sizeof(target));
    item.object["target"] = Json::str(
        n >= 0 ? std::string(target, static_cast<size_t>(n)) : "unknown");
    f.array.push_back(std::move(item));
  }
  closedir(d);
  return f;
}
std::mutex durable_lock;
bool append_record(int fd, const Json &j) {
  std::lock_guard<std::mutex> lock(durable_lock);
  std::string line = dump(j) + '\n';
  size_t off = 0;
  while (off < line.size()) {
    ssize_t n = write(fd, line.data() + off, line.size() - off);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    off += static_cast<size_t>(n);
  }
  return fsync(fd) == 0;
}
Json durable_base(const Identity &id, const char *event, tb_guard *guard) {
  struct tb_guard_snapshot s{};
  if (guard)
    tb_guard_snapshot(guard, &s);
  Json j = Json::obj();
  j.object = {{"event", Json::str(event)},
              {"type", Json::str(event)},
              {"identity", identity_json(id, 0)},
              {"owner_pid", Json::num(getpid())},
              {"pid", Json::num(getpid())},
              {"phase", Json::str(guard ? phase_name(s.phase) : "NEW")},
              {"held", Json::boolean(s.held)},
              {"hold_reasons", Json::num(s.hold_reasons)},
              {"cleanup_permissions", Json::num(s.cleanup_permissions)},
              {"operation_ticket", Json::num(s.operation_ticket)},
              {"monotonic_ns", Json::num(now_ns())},
              {"resource_inventory", inventory()},
              {"retained_resources", inventory()},
              {"recovery", Json::str(s.held ? "manual" : "none")}};
  std::ifstream boot("/proc/sys/kernel/random/boot_id");
  std::string boot_id;
  std::getline(boot, boot_id);
  j.object["boot_id"] = Json::str(boot_id);
  std::ifstream stat("/proc/self/stat");
  std::string proc;
  std::getline(stat, proc);
  auto end = proc.rfind(')');
  std::istringstream fields(end == std::string::npos ? ""
                                                     : proc.substr(end + 1));
  std::string value;
  for (int n = 3; n <= 22 && fields >> value; n++)
    if (n == 22)
      j.object["proc_starttime"] = Json::num(std::stoull(value));
  return j;
}
void request_validate(const Json &r, const Identity &id) {
  exact(r, {"identity", "command", "deadline_ms", "part_index", "part_count",
            "payload"});
  const auto &i = r.at("identity");
  exact(i, {"version", "run_id", "sha", "role", "case", "direction", "epoch",
            "request_id"});
  if (i.at("version").u() != 1 || i.at("run_id").s() != id.run_id ||
      i.at("sha").s() != id.sha || i.at("role").s() != id.role ||
      i.at("case").s() != id.case_id || i.at("direction").s() != id.direction ||
      i.at("epoch").u() != id.epoch)
    throw std::runtime_error("identity mismatch");
  for (auto name : {"run_id", "sha", "role", "case", "direction"}) {
    if (i.at(name).s().empty() || i.at(name).s().size() > 128)
      throw std::runtime_error("identity string");
  }
  if (!std::regex_match(id.sha, std::regex("([0-9a-f]{40}|[0-9a-f]{64})")) ||
      (id.role != "tx" && id.role != "rx") ||
      (id.direction != "a-to-b" && id.direction != "b-to-a"))
    throw std::runtime_error("identity enum");
  i.at("request_id").u();
  bounded(r.at("deadline_ms"), 1, 120000);
  auto count = bounded(r.at("part_count"), 1, 262146);
  bounded(r.at("part_index"), 0, count - 1);
  const auto c = r.at("command").s();
  const auto &p = r.at("payload");
  if (c != "verify" && (count != 1 || r.at("part_index").u() != 0))
    throw std::runtime_error("multipart command");
  if (c == "wait" || c == "stop" || c == "close")
    exact(p, {});
  else if (c == "start") {
    exact(p, {"groups", "first_seq"});
    auto groups = bounded(p.at("groups"), 1, 10000);
    if (p.at("first_seq").u() > UINT64_MAX - groups + 1)
      throw std::runtime_error("sequence overflow");
  } else if (c == "cancel") {
    exact(p, {"reason"});
    if (p.at("reason").s().empty() || p.at("reason").s().size() > 128)
      throw std::runtime_error("reason");
  } else if (c == "observe") {
    exact(p, {"first_ordinal", "limit"});
    bounded(p.at("first_ordinal"), 0, 9999);
    bounded(p.at("limit"), 1, 32);
  } else if (c == "preflight" || c == "prepare") {
    if (c == "preflight")
      exact(p, {"gpu_bdf", "nvidia_node", "link_token", "channel", "geometry",
                "flags"});
    else {
      exact(p, {"mode", "groups", "first_seq", "seed", "gpu_bdf", "nvidia_node",
                "link_token", "channel", "geometry", "flags", "observer_object",
                "ptx_path"});
      bounded(p.at("groups"), 1, 10000);
      p.at("first_seq").u();
      p.at("seed").u();
      auto mode = p.at("mode").s();
      if (mode != "single-group" && mode != "bulk-static")
        throw std::runtime_error("mode");
      p.at("observer_object").s();
      p.at("ptx_path").s();
    }
    p.at("gpu_bdf").s();
    p.at("nvidia_node").s();
    p.at("link_token").u();
    p.at("channel").u();
    p.at("flags").u();
    const auto &g = p.at("geometry");
    exact(g, {"allocation_bytes", "group_bytes", "frame_size", "seg_len",
              "depth", "native_elems"});
    for (const auto &kv : g.object)
      bounded(kv.second, 1, UINT64_MAX);
  } else if (c == "verify") {
    auto kind = p.at("kind").s();
    if (kind == "begin") {
      exact(p, {"kind", "launch_cookie", "extent_count", "stop_receipts"});
      bounded(p.at("launch_cookie"), 1, UINT64_MAX);
      bounded(p.at("extent_count"), 1, 262144);
      if (p.at("stop_receipts").type != Json::Array ||
          p.at("stop_receipts").array.size() != 2)
        throw std::runtime_error("stop receipts");
    } else if (kind == "extents") {
      exact(p, {"kind", "first_extent", "extents"});
      p.at("first_extent").u();
      const auto &es = p.at("extents");
      if (es.type != Json::Array || es.array.empty() || es.array.size() > 1024)
        throw std::runtime_error("extents count");
      for (const auto &e : es.array) {
        exact(e, {"dst_off", "src_off", "len", "seed", "kind", "reserved"});
        e.at("dst_off").u();
        e.at("src_off").u();
        bounded(e.at("len"), 1, UINT64_MAX);
        e.at("seed").u();
        bounded(e.at("kind"), 1, 2);
        bounded(e.at("reserved"), 0, 0);
      }
    } else if (kind == "end") {
      exact(p, {"kind", "extent_count"});
      bounded(p.at("extent_count"), 1, 262144);
    } else
      throw std::runtime_error("verify kind");
  } else
    throw std::runtime_error("unknown command");
}
struct Shared {
  std::mutex lock;
  Command command;
  OwnerResult result{};
  bool ready = false, done = false;
  int wake = -1, owner_error = 0;
};
} // namespace
// Private translation-unit bridge for the resource owner, without a JSON
// library ABI.
std::string agent_json_get(const std::string &text, const std::string &path) {
  Json j = Parser(text).parse();
  std::istringstream p(path);
  std::string field;
  while (std::getline(p, field, '.')) {
    Json next = j.at(field);
    j = std::move(next);
  }
  return dump(j);
}
std::string agent_json_string(const std::string &text) {
  return Parser(text).parse().s();
}
std::string agent_json_quote(const std::string &text) { return quote(text); }
std::vector<std::string> agent_json_array(const std::string &text) {
  auto j = Parser(text).parse();
  if (j.type != Json::Array)
    throw std::runtime_error("array expected");
  std::vector<std::string> result;
  result.reserve(j.array.size());
  for (const auto &element : j.array)
    result.push_back(dump(element));
  return result;
}

bool agent_durable_append(int fd, const std::string &json) {
  return append_record(fd, Parser(json).parse());
}

int open_durable_record(const std::string &private_dir, const Identity &id,
                        std::string *absolute_path) {
  try {
    signals_setup();
    if (private_dir.empty() || private_dir[0] != '/')
      return -EINVAL;
    if (mkdir(private_dir.c_str(), 0700) && errno != EEXIST)
      return -errno;
    int dir = open(private_dir.c_str(),
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0)
      return -errno;
    struct stat st{};
    if (fstat(dir, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700) {
      close(dir);
      return -EPERM;
    }
    std::string name = "owner-" + std::to_string(getpid()) + '-' +
                       std::to_string(now_ns()) + ".jsonl";
    int fd = openat(
        dir, name.c_str(),
        O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
      int e = errno;
      close(dir);
      return -e;
    }
    Json initial = durable_base(id, "initial", nullptr);
    std::ifstream boot("/proc/sys/kernel/random/boot_id");
    std::string line;
    std::getline(boot, line);
    initial.object["boot_id"] = Json::str(line);
    std::ifstream stat("/proc/self/stat");
    std::getline(stat, line);
    size_t end = line.rfind(')');
    std::istringstream fields(end == std::string::npos ? ""
                                                       : line.substr(end + 1));
    std::string field;
    for (int n = 3; n <= 22 && fields >> field; n++)
      if (n == 22)
        initial.object["proc_starttime"] = Json::num(std::stoull(field));
    bool ok = append_record(fd, initial) && fsync(dir) == 0;
    close(dir);
    if (!ok) {
      close(fd);
      return -EIO;
    }
    if (absolute_path)
      *absolute_path = private_dir + '/' + name;
    return fd;
  } catch (const std::exception &) {
    return -EINVAL;
  }
}

int run_agent(int input_fd, int output_fd, int durable_fd,
              const Identity &identity, tb_guard *guard, Owner &owner) {
  try {
    signals_setup();
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    int sigfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sigfd < 0)
      return -errno;
    if (fcntl(input_fd, F_SETFL, fcntl(input_fd, F_GETFL) | O_NONBLOCK) < 0 ||
        fcntl(output_fd, F_SETFL, fcntl(output_fd, F_GETFL) | O_NONBLOCK) < 0) {
      close(sigfd);
      return -errno;
    }
    auto *shared = new Shared;
    shared->wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (shared->wake < 0) {
      close(sigfd);
      return -errno;
    }
    // The dedicated owner thread is deliberately never canceled or joined while
    // unproved.
    std::thread([shared, &owner, guard]() {
      for (;;) {
        Command c;
        {
          std::unique_lock<std::mutex> lk(shared->lock);
          if (!shared->ready) {
            lk.unlock();
            struct pollfd pfd{shared->wake, POLLIN, 0};
            poll(&pfd, 1, 20);
            continue;
          }
          c = shared->command;
          shared->ready = false;
        }
        OwnerResult result{};
        auto hold_owner_error = [&](int error) {
          std::lock_guard<std::mutex> lk(shared->lock);
          if (!shared->owner_error)
            shared->owner_error = error;
          tb_guard_hold(guard, TB_HOLD_PROTOCOL);
        };
        try {
          result = owner.execute(c);
        } catch (...) {
          hold_owner_error(-EIO);
          result.request_id = c.request_id;
          result.error = -EIO;
          result.phase = TB_PHASE_HELD;
        }
        if (result.error) {
          struct tb_guard_snapshot actual{};
          tb_guard_snapshot(guard, &actual);
          if (actual.phase != TB_PHASE_NEW &&
              actual.phase != TB_PHASE_FAILED_SAFE &&
              actual.phase != TB_PHASE_CLOSED)
            hold_owner_error(result.error);
        }
        {
          std::lock_guard<std::mutex> lk(shared->lock);
          shared->result = std::move(result);
          shared->done = true;
        } // Separate completion state is polled without asking owner to return
          // on cancel.
      }
    }).detach();
    std::string input;
    std::deque<std::string> output;
    size_t output_offset = 0, queued = 0;
    bool input_open = true, output_open = true, busy = false,
         held_written = false, closing = false;
    int terminal_error = 0;
    uint64_t last_request = 0, active_request = 0, deadline = 0;
    std::string active_command, inflight_command;
    Json active_wire;
    Json multipart;
    uint64_t next_part = 0, part_count = 0;
    size_t multipart_bytes = 0;
    auto enqueue = [&](const Json &j) {
      std::string body = dump(j);
      if (body.size() > TB_MAX_JSON ||
          queued + body.size() + 4 > 2 * TB_MAX_JSON)
        throw std::runtime_error("bounded supervisor output queue exhausted");
      uint32_t n = static_cast<uint32_t>(body.size());
      std::string frame;
      for (int shift = 24; shift >= 0; shift -= 8)
        frame += static_cast<char>((n >> shift) & 255);
      frame += body;
      queued += frame.size();
      output.push_back(std::move(frame));
    };
    auto response = [&](int error, const std::string &payload) {
      struct tb_guard_snapshot snap{};
      tb_guard_snapshot(guard, &snap);
      if (!output_open)
        return;
      if (snap.held) {
        // Preserve a partially emitted frame, then retain only the newest
        // terminal notification. A blocked reader cannot grow the queue.
        while (output.size() > 1) {
          queued -= output.back().size();
          output.pop_back();
        }
        if (!output.empty() && output_offset == 0) {
          queued -= output.front().size();
          output.pop_front();
        }
      }
      Json j = Json::obj();
      const char *fate = snap.held                             ? "HELD"
                         : snap.phase == TB_PHASE_FAILED_SAFE  ? "FAILED_SAFE"
                         : snap.phase >= TB_PHASE_DRAINED_SAFE ? "SAFE"
                         : snap.phase >= TB_PHASE_SESSION_CREATED ? "ACTIVE"
                                                                  : "EMPTY";
      j.object = {
          {"identity", identity_json(identity, active_request)},
          {"command",
           Json::str(active_command.empty() ? "cancel" : active_command)},
          {"phase", Json::str(phase_name(snap.phase))},
          {"fate", Json::str(fate)},
          {"error", Json::signed_num(error)},
          {"held", Json::boolean(snap.held)},
          {"cleanup_permissions", Json::num(snap.cleanup_permissions)},
          {"evidence", Json::obj()},
          {"payload", Parser(payload.empty() ? "{}" : payload).parse()},
          {"part_index", Json::num(0)},
          {"part_count", Json::num(1)}};
      j.object["evidence"].object = {
          {"owner_pid", Json::num(getpid())},
          {"hold_reasons", Json::num(snap.hold_reasons)}};
      if (snap.held && active_command == "cancel") {
        Json retained = inventory();
        Json opaque = Json::obj();
        opaque.object = {
            {"kind", Json::str("opaque-owner")},
            {"state",
             Json::str("authority retained; no GPU query or reclamation")}};
        retained.array.push_back(std::move(opaque));
        j.object["payload"] = Json::obj();
        j.object["payload"].object = {
            {"hold_reasons", Json::num(snap.hold_reasons)},
            {"retained_resources", std::move(retained)}};
      }
      char path[4096];
      auto n = readlink(("/proc/self/fd/" + std::to_string(durable_fd)).c_str(),
                        path, sizeof(path));
      if (n >= 0)
        j.object["evidence"].object["durable_path"] =
            Json::str(std::string(path, static_cast<size_t>(n)));
      enqueue(j);
    };
    auto hold = [&](uint32_t reason) {
      if (!terminal_error) {
        std::lock_guard<std::mutex> lk(shared->lock);
        terminal_error = shared->owner_error ? shared->owner_error : -ECANCELED;
      }
      tb_guard_hold(guard, reason);
      auto j = durable_base(identity, "held", guard);
      j.object["error"] = Json::signed_num(terminal_error);
      std::ifstream boot("/proc/sys/kernel/random/boot_id");
      std::string boot_id;
      std::getline(boot, boot_id);
      j.object["boot_id"] = Json::str(boot_id);
      std::ifstream stat("/proc/self/stat");
      std::string proc;
      std::getline(stat, proc);
      std::istringstream fields(proc.substr(proc.rfind(')') + 1));
      std::string start;
      for (int n = 3; n <= 22 && fields >> start; n++)
        if (n == 22)
          j.object["proc_starttime"] = Json::num(std::stoull(start));
      j.object["inflight_operation"] = Json::str(busy        ? inflight_command
                                                 : next_part ? "verify-assembly"
                                                             : "none");
      Json opaque = Json::obj();
      opaque.object = {
          {"kind", Json::str("opaque-owner")},
          {"state",
           Json::str(busy ? "may hold GPU/context/stream/native resources; "
                            "blocked owner inventory unavailable"
                          : "retained owner state; authority not reclaimed")}};
      j.object["retained_resources"].array.push_back(std::move(opaque));
      j.object["request_id"] = Json::num(active_request);
      j.object["retained_fds"] = inventory();
      append_record(durable_fd, j);
      held_written = true;
      response(terminal_error, "{}");
    };
    auto dispatch = [&](Json r) {
      if (deadline && now_ns() >= deadline) {
        hold(TB_HOLD_DEADLINE);
        return;
      }
      active_request = r.at("identity").at("request_id").u();
      active_command = r.at("command").s();
      auto j = durable_base(identity, "intent", guard);
      j.object["command"] = Json::str(active_command);
      j.object["request_id"] = Json::num(active_request);
      if (!append_record(durable_fd, j)) {
        hold(TB_HOLD_PROTOCOL);
        return;
      }
      Command c{identity, active_request, deadline, active_command, dump(r)};
      {
        std::lock_guard<std::mutex> lk(shared->lock);
        shared->command = std::move(c);
        shared->ready = true;
      }
      busy = true;
      inflight_command = active_command;
    };
    for (;;) {
      struct tb_guard_snapshot snap{};
      tb_guard_snapshot(guard, &snap);
      if (snap.held && !held_written)
        hold(snap.hold_reasons ? snap.hold_reasons
                               : static_cast<uint32_t>(TB_HOLD_CUDA_UNKNOWN));
      if (deadline && !snap.held && now_ns() >= deadline)
        hold(TB_HOLD_DEADLINE);
      {
        std::unique_lock<std::mutex> lk(shared->lock);
        if (shared->done) {
          auto result = std::move(shared->result);
          shared->done = false;
          lk.unlock();
          busy = false;
          deadline = 0;
          tb_guard_snapshot(guard, &snap);
          auto j = durable_base(identity, snap.held ? "late_result" : "result",
                                guard);
          j.object["error"] = Json::signed_num(result.error);
          j.object["request_id"] = Json::num(result.request_id);
          append_record(durable_fd, j);
          if (!snap.held) {
            if (result.request_id != active_request) {
              hold(TB_HOLD_PROTOCOL);
            } else {
              response(result.error, result.bounded_json);
              if (active_command == "close" && !result.error &&
                  result.phase == TB_PHASE_CLOSED)
                closing = true;
            }
          }
        }
      }
      if (closing && output.empty()) {
        close(sigfd);
        return 0;
      }
      struct pollfd fds[3] = {
          {input_open ? input_fd : -1, POLLIN, 0},
          {output_open && !output.empty() ? output_fd : -1, POLLOUT, 0},
          {sigfd, POLLIN, 0}};
      int timeout = 10;
      if (deadline && !snap.held) {
        auto now = now_ns();
        if (now >= deadline)
          timeout = 0;
        else
          timeout = static_cast<int>(
              std::min<uint64_t>(10, (deadline - now + 999999) / 1000000));
      }
      int polled = poll(fds, 3, timeout);
      if (polled < 0) {
        if (errno == EINTR)
          continue;
        hold(TB_HOLD_PROTOCOL);
        continue;
      }
      if (fds[2].revents & POLLIN) {
        struct signalfd_siginfo si;
        while (read(sigfd, &si, sizeof(si)) == sizeof(si))
          hold(TB_HOLD_SIGNAL);
      }
      if (fds[1].revents & (POLLOUT | POLLERR | POLLHUP)) {
        while (!output.empty()) {
          auto &frame = output.front();
          ssize_t n = write(output_fd, frame.data() + output_offset,
                            frame.size() - output_offset);
          if (n < 0 && errno == EINTR)
            continue;
          if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          if (n <= 0) {
            output_open = false;
            output.clear();
            queued = 0;
            output_offset = 0;
            hold(TB_HOLD_EPIPE);
            break;
          }
          output_offset += static_cast<size_t>(n);
          queued -= static_cast<size_t>(n);
          if (output_offset == frame.size()) {
            output.pop_front();
            output_offset = 0;
          }
        }
      }
      if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
        char buffer[65536];
        for (;;) {
          ssize_t n = read(input_fd, buffer, sizeof(buffer));
          if (n < 0 && errno == EINTR)
            continue;
          if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          if (n <= 0) {
            input_open = false;
            hold(TB_HOLD_EOF);
            break;
          }
          input.append(buffer, static_cast<size_t>(n));
          if (input.size() > TB_MAX_JSON + 65540) {
            hold(TB_HOLD_PROTOCOL);
            input.clear();
          }
          break;
        }
        for (;;) {
          if (input.size() < 4)
            break;
          uint32_t n = 0;
          for (unsigned i = 0; i < 4; i++)
            n = (n << 8) | static_cast<unsigned char>(input[i]);
          if (!n || n > TB_MAX_JSON) {
            hold(TB_HOLD_PROTOCOL);
            input.clear();
            break;
          }
          if (input.size() < n + 4)
            break;
          auto body = input.substr(4, n);
          input.erase(0, n + 4);
          try {
            Json r = Parser(body).parse();
            request_validate(r, identity);
            auto request = r.at("identity").at("request_id").u();
            auto command = r.at("command").s();
            if (command == "cancel") {
              if (request > last_request)
                last_request = request;
              active_request = request;
              active_command = command;
              hold(TB_HOLD_CANCEL);
              continue;
            }
            tb_guard_snapshot(guard, &snap);
            if (snap.held) {
              response(-EPERM, "{}");
              continue;
            }
            if (busy)
              throw std::runtime_error("outstanding command");
            if (command == "verify") {
              auto index = r.at("part_index").u();
              auto count = r.at("part_count").u();
              auto kind = r.at("payload").at("kind").s();
              if (!next_part) {
                if (index || kind != "begin" || request <= last_request ||
                    count < 3)
                  throw std::runtime_error("verify begin");
                last_request = request;
                active_request = request;
                active_command = command;
                deadline = now_ns() + r.at("deadline_ms").u() * 1000000;
                active_wire = r;
                multipart = r.at("payload");
                multipart.object["extents"] = Json::list();
                next_part = 1;
                part_count = count;
                multipart_bytes = body.size();
              } else {
                if (request != active_request || index != next_part ||
                    count != part_count ||
                    dump(r.at("identity")) !=
                        dump(active_wire.at("identity")) ||
                    r.at("deadline_ms").u() !=
                        active_wire.at("deadline_ms").u())
                  throw std::runtime_error("verify sequence");
                multipart_bytes += body.size();
                if (multipart_bytes > 64 * 1024 * 1024)
                  throw std::runtime_error("verify metadata bound");
                if (index == count - 1) {
                  if (kind != "end" ||
                      r.at("payload").at("extent_count").u() !=
                          multipart.at("extent_count").u() ||
                      multipart.at("extents").array.size() !=
                          multipart.at("extent_count").u())
                    throw std::runtime_error("verify end count");
                  Json assembled = active_wire;
                  multipart.object.erase("kind");
                  assembled.object["payload"] = std::move(multipart);
                  assembled.object["part_index"] = Json::num(0);
                  assembled.object["part_count"] = Json::num(1);
                  next_part = 0;
                  dispatch(std::move(assembled));
                } else {
                  const auto &p = r.at("payload");
                  if (kind != "extents" ||
                      p.at("first_extent").u() !=
                          multipart.at("extents").array.size())
                    throw std::runtime_error("verify extent sequence");
                  auto &dst = multipart.object["extents"].array;
                  const auto &src = p.at("extents").array;
                  if (dst.size() + src.size() >
                      multipart.at("extent_count").u())
                    throw std::runtime_error("verify extent overflow");
                  dst.insert(dst.end(), src.begin(), src.end());
                  ++next_part;
                }
              }
            } else {
              if (next_part || request <= last_request)
                throw std::runtime_error("request sequence");
              last_request = request;
              active_request = request;
              active_command = command;
              deadline = now_ns() + r.at("deadline_ms").u() * 1000000;
              dispatch(std::move(r));
            }
          } catch (const std::exception &error) {
            auto failure = durable_base(identity, "protocol-error", guard);
            failure.object["reason"] = Json::str(error.what());
            failure.object["input_prefix"] = Json::str(body.substr(0, 512));
            append_record(durable_fd, failure);
            hold(TB_HOLD_PROTOCOL);
          }
        }
      }
    }
  } catch (const std::exception &) {
    tb_guard_hold(guard, TB_HOLD_PROTOCOL);
    auto j = durable_base(identity, "held", guard);
    append_record(durable_fd, j);
    for (;;)
      poll(nullptr, 0, 1000);
  }
}
} // namespace tb
