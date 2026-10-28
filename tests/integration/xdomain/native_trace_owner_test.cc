/* SPDX-License-Identifier: GPL-2.0 */
// Independent filesystem-boundary tests; wrappers model tracefs virtual files.
#include "native_trace_owner.h"
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <time.h>
namespace fs = std::filesystem;
static std::string mode;
static bool removing = false;
static void put(const fs::path &p, const std::string &s) {
 std::ofstream f(p, std::ios::binary); f << s;
 if (!f) throw std::runtime_error("fixture write failed");
}
static std::string get(const fs::path &p) {
 std::ifstream f(p, std::ios::binary);
 return std::string(std::istreambuf_iterator<char>(f), {});
}
static void need(bool ok, const char *why) {
 if (!ok) throw std::runtime_error(why);
}
static uint64_t mono() {
 timespec t{}; need(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "clock");
 return uint64_t(t.tv_sec) * 1000000000ULL + t.tv_nsec;
}
extern "C" int __real_mkdir(const char *, mode_t);
extern "C" int __real_rmdir(const char *);
extern "C" int __wrap_mkdir(const char *name, mode_t perms) {
 int result = __real_mkdir(name, perms);
 fs::path p(name);
 if (result || p.parent_path().filename() != "instances") return result;
 // The kernel creates these pseudo-files when a trace instance is created.
 fs::create_directories(p / "events/xdev_ext/native_event");
 fs::create_directories(p / "per_cpu/cpu0");
 fs::create_directories(p / "per_cpu/cpu1");
 put(p / "current_tracer", "nop\n"); put(p / "trace_clock", "mono\n");
 put(p / "buffer_size_kb", "4096\n"); put(p / "tracing_on", "0\n");
 put(p / "trace", "# initial raw trace\n");
 put(p / "events/xdev_ext/native_event/enable", "0\n");
 put(p / "events/xdev_ext/native_event/format", "name: native_event\nID: 900\nformat:\n field:u64 ts_ns; offset:0; size:8; signed:0;\nprint fmt: abi=xdev-native-v1-nvme-xsk-batch\n");
 const std::string stats = "entries: 0\noverrun: 0\ncommit overrun: 0\nbytes: 0\noldest event ts: 0\nnow ts: 0\ndropped events: 0\nread events: 0\n";
 put(p / "per_cpu/cpu0/stats", stats); put(p / "per_cpu/cpu1/stats", stats);
 return result;
}
extern "C" int __wrap_rmdir(const char *name) {
 fs::path p(name);
 if (removing || p.parent_path().filename() != "instances") return __real_rmdir(name);
 // tracefs removes its pseudo-files atomically with the instance directory.
 removing = true;
 std::error_code ec;
 for (const auto &entry : fs::directory_iterator(p, ec)) fs::remove_all(entry.path(), ec);
 removing = false;
 return __real_rmdir(name);
}
static void unchanged(const fs::path &root) {
 need(get(root / "trace") == "SHARED TRACE MUST SURVIVE\n", "shared trace changed");
 need(get(root / "tracing_on") == "1\n", "shared tracing state changed");
 need(get(root / "instances/other/trace") == "OTHER INSTANCE\n", "other instance changed");
}
int main(int argc, char **argv) {
 try {
  need(argc == 3, "usage case root"); mode = argv[1]; fs::path base(argv[2]);
  auto root = base / "tracefs", evidence = base / "evidence";
  fs::create_directories(root / "instances/other"); fs::create_directories(evidence);
  put(root / "trace", "SHARED TRACE MUST SURVIVE\n"); put(root / "tracing_on", "1\n");
  put(root / "instances/other/trace", "OTHER INSTANCE\n");
  if (mode == "names") {
   for (const std::string &name : {std::string(""), std::string("../escape"), std::string("slash/name"), std::string(97,'a'), std::string("bad name")}) {
    try {
     tb::NativeTraceCapture c(root.string(), evidence.string(), name);
     need(c.start() != 0, "invalid name started capture");
    } catch (const std::invalid_argument &) {}
   }
   tb::NativeTraceCapture first(root.string(), evidence.string(), "owned");
   need(first.start() == 0, "first start");
   put(root / "instances/owned/trace", "owned raw bytes\n");
   tb::NativeTraceCapture second(root.string(), evidence.string(), "owned");
   need(second.start() != 0, "existing instance reused");
   need(get(root / "instances/owned/trace") == "owned raw bytes\n", "failed start cleared original");
   unchanged(root); std::cout << "PASS names\n"; return 0;
  }
  if (mode == "unavailable") {
   tb::NativeTraceCapture c((base / "absent").string(), evidence.string(), "owned");
   need(c.start() != 0, "unavailable tracefs was silently created");
   unchanged(root); std::cout << "PASS unavailable\n"; return 0;
  }
  const auto before = mono();
  const auto instance = root / "instances/owned";
  if (mode == "destructor") {
   {
    tb::NativeTraceCapture c(root.string(), evidence.string(), "owned");
    need(c.start() == 0, "start");
    put(instance / "trace", "retained bytes\n");
   }
   need(fs::is_directory(instance), "destructor removed active instance");
   need(get(instance / "tracing_on").find('1') != std::string::npos, "destructor disabled retained tracing");
   need(get(instance / "events/xdev_ext/native_event/enable").find('1') != std::string::npos, "destructor disabled event");
   need(get(instance / "trace") == "retained bytes\n", "destructor cleared bytes");
   unchanged(root); std::cout << "PASS destructor\n"; return 0;
  }
  tb::NativeTraceCapture c(root.string(), evidence.string(), "owned");
  need(c.start() == 0, "start");
  need(c.instance_path() == instance.string(), "wrong owned instance path");
  tb::NativeTraceSnapshot s{};
  if (mode == "missing-stats") {
   fs::remove(instance / "per_cpu/cpu1/stats");
   need(c.snapshot(&s) != 0, "missing CPU loss counter treated as zero");
  } else if (mode == "loss") {
   put(instance / "per_cpu/cpu1/stats", "overrun: 2\ncommit overrun: 1\ndropped events: 3\n");
   int result = c.snapshot(&s);
   need(result != 0 || s.lost_events == 6, "positive trace loss hidden");
  } else if (mode == "oversize") {
   put(instance / "trace", std::string(1024 * 1024 + 1, 'x'));
   need(c.snapshot(&s) != 0, "oversize trace silently truncated");
   need(get(instance / "trace").size() == 1024 * 1024 + 1, "reader modified raw evidence");
  } else if (mode == "setup" || mode == "seal") {
   need(get(instance / "current_tracer").find("nop") != std::string::npos, "not nop tracer");
   need(get(instance / "trace_clock").find("mono") != std::string::npos, "not monotonic trace clock");
   unsigned kb = std::stoul(get(instance / "buffer_size_kb"));
   need(kb >= 4096 && kb <= 4099, "bad configured buffer");
   const std::string raw = "# preserved comment\nworker [001] raw-native-line\n";
   put(instance / "trace", raw);
   need(c.snapshot(&s, mode == "seal") == 0, "snapshot");
   const auto after = mono();
   need(s.raw_trace == raw, "snapshot did not preserve complete raw bytes");
   need(s.event_format == get(instance / "events/xdev_ext/native_event/format"), "format not actual readback");
   need(s.trace_clock.find("mono") != std::string::npos, "snapshot clock");
   need(s.stats.find("overrun") != std::string::npos, "raw CPU statistics absent");
   need(s.lost_events == 0, "zero trace loss misreported");
   need(before <= s.begin_ns && s.begin_ns <= s.end_ns && s.end_ns <= s.captured_monotonic_ns && s.captured_monotonic_ns <= after, "not real ordered CLOCK_MONOTONIC samples");
   need(s.sealed == (mode == "seal"), "seal state");
   if (mode == "seal") {
    need(get(instance / "tracing_on").find('0') != std::string::npos, "seal left own tracing active");
    need(get(instance / "events/xdev_ext/native_event/enable").find('0') != std::string::npos, "seal left own event enabled");
    need(c.close_safe() == 0, "explicit safe close failed");
    need(!fs::exists(instance), "explicit close did not remove owned instance");
   } else need(get(instance / "tracing_on").find('1') != std::string::npos, "provisional snapshot disabled capture");
  } else throw std::runtime_error("unknown test case");
  unchanged(root); std::cout << "PASS " << mode << '\n'; return 0;
 } catch (const std::exception &e) {
  std::cerr << "FAIL " << e.what() << '\n'; return 1;
 }
}
