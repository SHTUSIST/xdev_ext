// SPDX-License-Identifier: GPL-2.0
// Test-only blocking resource owner. Links the real supervisor and A guard.
#include "agent_supervisor.h"
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <string>
#include <utility>

static int ledger_fd = -1;
static void note(const std::string &line)
{
 const std::string out = line + "\n";
 const ssize_t n = write(ledger_fd, out.data(), out.size());
 if (n != static_cast<ssize_t>(out.size()) || fsync(ledger_fd)) _exit(91);
}

class SurrogateResources final {
 tb_guard *guard_;
 int fd_;
public:
 explicit SurrogateResources(tb_guard *guard) : guard_(guard), fd_(eventfd(0, EFD_CLOEXEC))
 { if (fd_ < 0) _exit(92); note("resource_acquired fd=" + std::to_string(fd_)); }
 ~SurrogateResources()
 {
  note("destructor_entered");
  if (tb_guard_cleanup_permissions(guard_) & TB_CLEANUP_GPU_FREE) {
   note("FREE"); close(fd_); note("CONTEXT_DESTROY");
  } else note("explicit_destructor_retained");
 }
};

class BlockingOwner final : public tb::Owner {
 tb_guard *guard_;
 int release_;
 SurrogateResources *resources_;
public:
 BlockingOwner(tb_guard *guard, int release) : guard_(guard), release_(release),
  resources_(new SurrogateResources(guard)) {}
 ~BlockingOwner() override
 {
  // HELD must not unwind this owner. If it does, ledger shows the violation.
  note("OWNER_DESTRUCTOR_ENTERED");
  if (resources_) delete resources_;
 }
 tb::OwnerResult execute(const tb::Command &cmd) override
 {
  note("command=" + cmd.command);
  if (std::getenv("TB_TEST_VERIFY_MODE") && cmd.command == "verify") {
   note("verify_metadata_bytes=" + std::to_string(cmd.bounded_json.size()));
   uint64_t verify_ticket = 0;
   const int admitted = tb_guard_begin(guard_, TB_OP_GPU_VERIFY, &verify_ticket);
   if (admitted) return {cmd.request_id, admitted, TB_PHASE_DRAINED_SAFE, true, "{}"};
   const int result = tb_guard_end(guard_, verify_ticket, TB_PHASE_VERIFIED, true, true);
   note("verify_executed");
   return {cmd.request_id, result, TB_PHASE_VERIFIED, true,
     "{\"bytes\":73728000,\"mismatches\":0,\"first_bad\":18446744073709551615,"
     "\"launch_cookie\":42,\"visibility\":\"NATIVE_OWNER\",\"visibility_error\":0}"};
  }
  if (cmd.command != "prepare") {
   note("UNEXPECTED_OWNER_COMMAND=" + cmd.command);
   return {cmd.request_id, -EPERM, TB_PHASE_HELD, false, "{}"};
  }
  uint64_t ticket = 0;
  if (tb_guard_begin(guard_, TB_OP_GPU_OPEN, &ticket)) _exit(93);
  if (tb_guard_end(guard_, ticket, TB_PHASE_GPU_READY, true, true)) _exit(94);
  if (tb_guard_begin(guard_, TB_OP_GPU_FILL, &ticket)) _exit(95);
  note("owner_blocked ticket=" + std::to_string(ticket));
  char release_byte = 0;
  ssize_t count;
  do { count = read(release_, &release_byte, 1); } while (count < 0 && errno == EINTR);
  if (count != 1) _exit(96);
  const int result = tb_guard_end(guard_, ticket, TB_PHASE_GPU_READY, true, true);
  note("late_result=" + std::to_string(result));
  for (const auto &probe : {std::pair<tb_operation, const char *>{TB_OP_CREATE, "CREATE"},
       {TB_OP_START, "START"}, {TB_OP_GPU_FILL, "REUSE"},
       {TB_OP_GPU_CLOSE, "GPU_CLOSE"}, {TB_OP_EPOCH_CLOSE, "EPOCH_CLOSE"}}) {
   const int admitted = tb_guard_begin(guard_, probe.first, &ticket);
   note(std::string("probe_") + probe.second + "=" + std::to_string(admitted));
   if (!admitted) note(std::string("SIDE_EFFECT_") + probe.second);
  }
  note("delete=" + std::to_string(tb_guard_delete(guard_)));
  // Test-only explicit destructor request on the actual eventfd resource owner.
  // Its storage and fd remain retained after permission refusal; no delete.
  resources_->~SurrogateResources();
  resources_ = nullptr;
  struct tb_guard_snapshot snapshot{};
  tb_guard_snapshot(guard_, &snapshot);
  note("snapshot_held=" + std::to_string(snapshot.held));
  note("snapshot_reasons=" + std::to_string(snapshot.hold_reasons));
  note("snapshot_permissions=" + std::to_string(snapshot.cleanup_permissions));
  return {cmd.request_id, result, snapshot.phase, false, "{}"};
 }
};

int main(int argc, char **argv)
{
 if (argc != 4) return 80;
 if (setsid() < 0) return 81;
 sigset_t blocked;
 sigemptyset(&blocked);
 sigaddset(&blocked, SIGTERM); sigaddset(&blocked, SIGHUP); sigaddset(&blocked, SIGINT);
 if (pthread_sigmask(SIG_BLOCK, &blocked, nullptr)) return 82;
 struct sigaction ignore{};
 ignore.sa_handler = SIG_IGN;
 if (sigaction(SIGPIPE, &ignore, nullptr)) return 83;
 ledger_fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
 if (ledger_fd < 0) return 84;
 tb::Identity id{"independent-c", std::string(40, 'a'), "tx",
                  "functional-epochs", "a-to-b", 3};
 std::string durable_path;
 const int durable = tb::open_durable_record(argv[1], id, &durable_path);
 if (durable < 0) return 85;
 note("durable=" + durable_path);
 tb_guard *guard = nullptr;
 if (tb_guard_new(TB_BACKING_GPU, &guard)) return 86;
 if (std::getenv("TB_TEST_VERIFY_MODE")) {
  // Only the resource boundary is a surrogate. Actual guard owns every proof.
  const std::pair<tb_operation, tb_phase> steps[] = {
   {TB_OP_GPU_OPEN, TB_PHASE_GPU_READY}, {TB_OP_GPU_FILL, TB_PHASE_GPU_READY},
   {TB_OP_CREATE, TB_PHASE_SESSION_CREATED}, {TB_OP_START, TB_PHASE_START_ACCEPTED},
   {TB_OP_WAIT, TB_PHASE_TRANSPORT_DONE}, {TB_OP_STOP, TB_PHASE_DRAINED_SAFE}};
  for (const auto &step : steps) {
   uint64_t ticket = 0;
   if (tb_guard_begin(guard, step.first, &ticket) ||
       tb_guard_end(guard, ticket, step.second, true, true)) return 88;
  }
  if (tb_guard_pair_stopped(guard)) return 89;
  uint64_t ticket = 0;
  if (tb_guard_begin(guard, TB_OP_VISIBLE, &ticket) ||
      tb_guard_end(guard, ticket, TB_PHASE_DRAINED_SAFE, true, true)) return 90;
  note("verify_ready");
 }
 BlockingOwner owner(guard, std::atoi(argv[3]));
 const int result = tb::run_agent(STDIN_FILENO, STDOUT_FILENO, durable, id, guard, owner);
 note("SUPERVISOR_RETURNED=" + std::to_string(result));
 return 87; // A HELD supervisor must stay parked instead of reaching here.
}
