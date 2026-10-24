# SPDX-License-Identifier: GPL-2.0
"""Run real U NVMe terminal end_io, before any user CQE publication."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
SOURCE=Path(os.environ.get('NATIVE_TRACE_URING_SOURCE',ROOT/'kernel/drivers/nvme/host/ioctl.c'))
PREFIX=r'''
#include <stdint.h>
#include <errno.h>
typedef int blk_status_t;
#define NVME_REQ_CANCELLED 1
#define le64_to_cpu(v) (v)
enum rq_end_io_ret { RQ_END_IO_FREE };
struct nvme_uring_cmd_pdu { int status; uint64_t result; };
struct async { void *op_data; };
struct io_uring_cmd { struct nvme_uring_cmd_pdu pdu; struct async async; };
struct nvme_xdev_ext_sidecar { struct { int request_allocated; } resources; };
struct request { void *end_io_data; struct { int flags,status;struct { uint64_t u64; } result; } nvme; };
#define nvme_req(r) (&(r)->nvme)
static unsigned traces,sequence,trace_order,task_order;static int seen_status;
static struct nvme_uring_cmd_pdu *nvme_uring_cmd_pdu(struct io_uring_cmd *cmd) { return &cmd->pdu; }
static struct async *io_uring_cmd_get_async_data(struct io_uring_cmd *cmd) { return &cmd->async; }
static int blk_status_to_errno(int err) { return err; }
static void __attribute__((unused)) nvme_uring_native_trace(struct request *req,const char *phase,int status)
{ (void)req;(void)phase; traces++; seen_status=status; trace_order=++sequence; }
static void nvme_uring_task_cb(void) {}
static void io_uring_cmd_do_in_task_lazy(struct io_uring_cmd *cmd,void (*cb)(void))
{ (void)cmd;(void)cb; task_order=++sequence; }
'''
SUFFIX=r'''
int main(void) {
 for(int mode=0;mode<4;mode++) {
  struct nvme_xdev_ext_sidecar side={.resources={.request_allocated=1}};
  struct io_uring_cmd cmd={.async={.op_data=&side}};
  struct request req={.end_io_data=&cmd}; int err=0,expected=0;
  traces=sequence=trace_order=task_order=0;req.nvme.result.u64=991;
  if(mode==1) expected=req.nvme.status=129;
  if(mode==2) {req.nvme.flags=NVME_REQ_CANCELLED;expected=-EINTR;}
  if(mode==3) expected=err=-EIO;
  if(nvme_uring_cmd_end_io(&req,err)!=RQ_END_IO_FREE) return 1;
  if(traces!=1 || seen_status!=expected || cmd.pdu.status!=expected) return 2;
  if(!trace_order || task_order<=trace_order || cmd.pdu.result!=991) return 3;
  if(side.resources.request_allocated) return 4;
 }
 return 0;
}
'''
class UringCompletion(unittest.TestCase):
 def test_success_nvme_error_cancel_block_error_before_user_completion(self):
  text=SOURCE.read_text();a=text.index('static enum rq_end_io_ret nvme_uring_cmd_end_io(');b=text.index('{',a);n=1;end=b+1
  while n:
   n+=(text[end]=='{')-(text[end]=='}');end+=1
  with tempfile.TemporaryDirectory() as tmp:
   c=Path(tmp)/'test.c';c.write_text(PREFIX+text[a:end]+SUFFIX);binary=Path(tmp)/'test'
   build=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
   self.assertEqual(build.returncode,0,build.stderr)
   self.assertEqual(subprocess.run([str(binary)]).returncode,0,'U native completion missing/resolved incorrectly/after task CQE publication')
if __name__=='__main__':unittest.main()
