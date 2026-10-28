/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_AGENT_SUPERVISOR_H
#define XDEV_EXT_AGENT_SUPERVISOR_H
#include "check_contract.h"
#include <string>
#include <cstdint>
namespace tb {
struct Identity {
 std::string run_id, sha, role, case_id, direction;
 uint64_t epoch;
};
struct Command {
 Identity id;
 uint64_t request_id, deadline_ns;
 std::string command;       // exact allowed commands in section 7
 std::string bounded_json;  // already schema-validated UTF-8
};
struct OwnerResult {
 uint64_t request_id;
 int error;
 tb_phase phase;
 bool stop_proved;
 std::string bounded_json;
};
class Owner {
public:
 virtual ~Owner() = default;  // resource subclass must not clean HELD resources
 virtual OwnerResult execute(const Command &) = 0;
};
/* owner executes in one dedicated thread; supervisor never invokes CUDA. */
int run_agent(int input_fd, int output_fd, int durable_fd,
              const Identity &, tb_guard *, Owner &);
int open_durable_record(const std::string &private_dir,
                        const Identity &, std::string *absolute_path);
}

#endif /* XDEV_EXT_AGENT_SUPERVISOR_H */
