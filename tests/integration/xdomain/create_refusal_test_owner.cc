// SPDX-License-Identifier: GPL-2.0
// Independent eventfd-only owner: no CUDA, provider, CREATE syscall or cleanup.
#include "agent_supervisor.h"
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/eventfd.h>
#include <unistd.h>
class RefusalOwner final : public tb::Owner {
 tb_guard *guard_; std::string mode_; int release_, ready_, resource_;
public:
 RefusalOwner(tb_guard *g, std::string m, int r, int n):guard_(g),mode_(std::move(m)),release_(r),ready_(n),resource_(eventfd(0,EFD_CLOEXEC)) {if(resource_<0)_exit(70);}
 tb::OwnerResult execute(const tb::Command &c) override {
  tb_guard_hold(guard_, TB_HOLD_CREATE_UNKNOWN);
  if(mode_=="additional")tb_guard_hold(guard_,TB_HOLD_PROTOCOL);
  struct tb_guard_snapshot s{};tb_guard_snapshot(guard_,&s);
  std::string probe="{\"held\":"+std::to_string(s.held)+",\"permissions\":"+std::to_string(s.cleanup_permissions)+",\"fd\":"+std::to_string(resource_)+"}\n";
  if(write(ready_,probe.data(),probe.size())!=ssize_t(probe.size()))_exit(71);
  char b;ssize_t n;do{n=read(release_,&b,1);}while(n<0&&errno==EINTR);if(n!=1)_exit(72);
  if(mode_=="throw")throw std::runtime_error("independent uncertain CREATE owner exception");
  const std::string payload=mode_=="refusal"?"{\"session_id\":0,\"registration_bytes\":65536,\"producer_sync_proved\":true,\"guard_sync_proved\":false,\"create_error\":-18,\"stop_proved\":false,\"stage_caps\":null,\"admission\":{\"records\":[],\"window\":{\"complete\":false},\"expected\":{\"requester\":\"0000:01:00.0\",\"stage\":0,\"errno\":-18}}}":"{}";
  return {c.request_id,mode_=="refusal"?-EXDEV:-EIO,TB_PHASE_HELD,false,payload};
 }
};
int main(int argc,char **argv) {
 if(argc!=5)return 2;
 tb::Identity id{"create-refusal-regression",std::string(40,'a'),"tx","functional-epochs","a-to-b",3};
 tb_guard *guard=nullptr;if(tb_guard_new(TB_BACKING_GPU,&guard))return 3;
 int durable=tb::open_durable_record(argv[2],id,nullptr);if(durable<0)return 4;
 auto *owner=new RefusalOwner(guard,argv[1],std::atoi(argv[3]),std::atoi(argv[4]));
 return tb::run_agent(0,1,durable,id,guard,*owner);
}
