/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_NATIVE_TRACE_OWNER_H
#define XDEV_EXT_NATIVE_TRACE_OWNER_H
#include <cstdint>
#include <memory>
#include <string>
namespace tb {
struct NativeTraceSnapshot {
 std::string raw_trace, event_format, trace_clock, stats;
 uint64_t begin_ns, end_ns, captured_monotonic_ns, lost_events;
 bool sealed;
};
class NativeTraceCapture {
public:
 NativeTraceCapture(std::string tracefs_root, std::string evidence_dir,
                    std::string instance_name);
 ~NativeTraceCapture();
 int start();
 int snapshot(NativeTraceSnapshot *, bool seal = false);
 int close_safe();
 std::string instance_path() const;
private:
 struct Impl;
 std::unique_ptr<Impl> p_;
};
}
#endif
