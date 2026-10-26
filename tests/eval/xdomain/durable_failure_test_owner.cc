/* SPDX-License-Identifier: GPL-2.0 */
/* Independent test-only eventfd owner. No device resources are acquired. */
#include "agent_supervisor.h"
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/eventfd.h>
#include <thread>
#include <unistd.h>

namespace {
int write_all(int fd, const std::string &line) {
  size_t off = 0;
  while (off < line.size()) {
    auto n = write(fd, line.data() + off, line.size() - off);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    off += static_cast<size_t>(n);
  }
  return 0;
}
class FailureOwner final : public tb::Owner {
  tb_guard *guard_;
  int durable_, probe_release_, probe_output_, resource_ = -1;
public:
  FailureOwner(tb_guard *guard, int durable, int release, int output)
      : guard_(guard), durable_(durable), probe_release_(release),
        probe_output_(output) {}
  tb::OwnerResult execute(const tb::Command &command) override {
    if (command.command != "prepare") _exit(90);
    resource_ = eventfd(0, EFD_CLOEXEC);
    uint64_t ticket = 0;
    if (resource_ < 0 ||
        tb_guard_begin(guard_, TB_OP_GPU_OPEN, &ticket) ||
        tb_guard_end(guard_, ticket, TB_PHASE_GPU_READY, true, true) ||
        tb_guard_begin(guard_, TB_OP_GPU_FILL, &ticket) ||
        tb_guard_end(guard_, ticket, TB_PHASE_GPU_READY, true, true) ||
        tb_guard_begin(guard_, TB_OP_CREATE, &ticket) ||
        tb_guard_end(guard_, ticket, TB_PHASE_SESSION_CREATED, false, true))
      _exit(91);
    // Fail precisely the result append after the already-persisted intent.
    int full = open("/dev/full", O_WRONLY | O_CLOEXEC);
    if (full < 0 || dup2(full, durable_) < 0) _exit(92);
    close(full);
    std::thread([this]() {
      char byte;
      ssize_t n;
      do { n = read(probe_release_, &byte, 1); } while (n < 0 && errno == EINTR);
      if (n != 1) _exit(93);
      struct tb_guard_snapshot state{};
      tb_guard_snapshot(guard_, &state);
      int fd_alive = fcntl(resource_, F_GETFD) >= 0;
      uint64_t t = 0;
      int control = tb_guard_begin(guard_, TB_OP_CONTROL, &t);
      if (!control)
        tb_guard_end(guard_, t, state.phase, state.native_safe, state.gpu_safe);
      int start = tb_guard_begin(guard_, TB_OP_START, &t);
      if (!start)
        tb_guard_end(guard_, t, TB_PHASE_START_ACCEPTED, false, true);
      int free_op = tb_guard_begin(guard_, TB_OP_GPU_CLOSE, &t);
      std::string report = "{\"held\":" + std::to_string(state.held) +
          ",\"permissions\":" + std::to_string(state.cleanup_permissions) +
          ",\"hold_reasons\":" + std::to_string(state.hold_reasons) +
          ",\"resource_fd_alive\":" + std::to_string(fd_alive) +
          ",\"control_admission\":" + std::to_string(control) +
          ",\"start_admission\":" + std::to_string(start) +
          ",\"free_admission\":" + std::to_string(free_op) + "}\n";
      if (write_all(probe_output_, report)) _exit(94);
    }).detach();
    return {command.request_id, 0, TB_PHASE_SESSION_CREATED, false,
            "{\"session_id\":1,\"registration_bytes\":65536,"
            "\"producer_sync_proved\":true,\"guard_sync_proved\":false,"
            "\"create_error\":0,\"stop_proved\":false}"};
  }
};
} // namespace
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  tb::Identity identity{"durable-failure", std::string(40, 'a'), "tx",
                        "functional-epochs", "a-to-b", 3};
  std::string path;
  int durable = tb::open_durable_record(argv[1], identity, &path);
  tb_guard *guard = nullptr;
  if (durable < 0 || tb_guard_new(TB_BACKING_GPU, &guard)) return 3;
  auto *owner = new FailureOwner(guard, durable, std::atoi(argv[2]),
                                std::atoi(argv[3]));
  return tb::run_agent(STDIN_FILENO, STDOUT_FILENO, durable, identity, guard,
                       *owner);
}
