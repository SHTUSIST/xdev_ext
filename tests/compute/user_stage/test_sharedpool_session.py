#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""RED for actual sharedpool utility observation verdicts, no kernel model.

These are pure verdict components over public USER observations. The actual
two-session cases must subsequently run through real io_uring/libxdev_ext in
the project kernel. No syscall, ioctl or device is replaced in this test.
"""
from pathlib import Path
import re
import sys
import unittest

for _parent in Path(__file__).resolve().parents:
    if (_parent / "tools/layout.py").is_file():
        sys.path.insert(0, str(_parent / "tools"))
        break
else:
    raise RuntimeError("owned project layout is unavailable")
from layout import canonical_root
ROOT = canonical_root(Path(__file__))
sys.path.insert(0, str(ROOT / "tests/support/benchmarks"))
from ce_vmm_contract import COMMON, Compiled, function, structure


def actual_verdicts():
    path = ROOT / "tests/compute/user_stage/guest/sharedpool_session_guest.c"
    if not path.is_file():
        return None
    source = path.read_text()
    valid = function(source, "sp_hold_valid", optional=True)
    equal = function(source, "sp_held_equal", optional=True)
    if not valid or not equal:
        return None
    text = COMMON.replace("#define XDEV_EXT_MECH_MAX_FRAMES 32U", "")
    text += '#include "' + str(ROOT / "src/core/include/uapi/linux/xdev_ext_mech.h") + '"\n'
    public = (ROOT / "src/lib/libxdev_ext.h").read_text()
    text += structure(public, "xdev_ext_user_batch") + "\n"
    # Only the utility's scalar layout constants, never another verdict.
    for match in re.finditer(r"(?m)^#define\s+SP_[A-Z0-9_]+[^\n]*", source):
        text += match.group() + "\n"
    text += structure(source, "sp_hold_snapshot") + "\n" + valid + "\n" + equal + "\n"
    return Compiled(text + MAIN)


MAIN = r'''
int main(void)
{
    struct sp_hold_snapshot a={0}, b;
    unsigned byte_checks=0, byte_rejected=0, metadata_checks=0, metadata_rejected=0;
    unsigned invalid_checks=0, invalid_rejected=0;
    a.batch.slot=0; a.batch.nr_frames=2; a.batch.ticket=17;
    a.batch.batch_id=99; a.batch.key=1;
    a.batch.f[0].umem_addr=4096; a.batch.f[1].umem_addr=4*4096;
    for (unsigned i=0;i<2;i++) {
        a.batch.f[i].data_off=64;
        a.batch.f[i].data_len=i?64:4032;
        a.batch.f[i].capacity=4032;
        a.batch.f[i].out_len=a.batch.f[i].data_len;
        a.batch.data[i]=(void *)(uintptr_t)(0x100000+a.batch.f[i].umem_addr+64);
    }
    a.stats.session_id=7001; a.stats.state=XDEV_EXT_MECH_SESSION_ACTIVE;
    a.stats.inflight=1; a.stats.submitted[0]=1;
    a.live_ticket=a.batch.ticket;
    a.ready_prod=a.ready_cons=1;
    for (size_t i=0;i<sizeof(a.frame_bytes);i++)
        a.frame_bytes[i]=(unsigned char)(i*73+(i>>5)+0x5a);
    b=a;
    int initial_valid=sp_hold_valid(&a), equal_control=sp_held_equal(&a,&b);
    for (size_t i=0;i<sizeof(a.frame_bytes);i++) {
        b=a; b.frame_bytes[i]^=0x80; byte_checks++;
        if (!sp_held_equal(&a,&b)) byte_rejected++;
    }
#define CHANGED(expr) do { b=a; expr; metadata_checks++; \
    if (!sp_held_equal(&a,&b)) metadata_rejected++; } while (0)
    CHANGED(b.batch.ticket++); CHANGED(b.batch.batch_id++);
    CHANGED(b.batch.key++); CHANGED(b.batch.arg++); CHANGED(b.batch.slot++);
    CHANGED(b.batch.nr_frames--); CHANGED(b.live_ticket++);
    CHANGED(b.ready_prod++); CHANGED(b.ready_cons++);
    CHANGED(b.done_prod++); CHANGED(b.done_cons++);
    for (unsigned i=0;i<2;i++) {
        CHANGED(b.batch.f[i].umem_addr+=4096);
        CHANGED(b.batch.f[i].data_off+=8);
        CHANGED(b.batch.f[i].data_len--);
        CHANGED(b.batch.f[i].capacity--);
        CHANGED(b.batch.f[i].out_len--);
        CHANGED(b.batch.data[i]=(void *)((uintptr_t)b.batch.data[i]+8));
    }
    CHANGED(b.stats.session_id++); CHANGED(b.stats.batches_done++);
    CHANGED(b.stats.batches_abort++); CHANGED(b.stats.rejects++);
    CHANGED(b.stats.recycled++); CHANGED(b.stats.held++);
    CHANGED(b.stats.sequestered++); CHANGED(b.stats.timeouts++);
    CHANGED(b.stats.inflight--); CHANGED(b.stats.native_publish++);
    CHANGED(b.stats.protocol_err++); CHANGED(b.stats.published++);
    CHANGED(b.stats.last_err=-EIO); CHANGED(b.stats.state=XDEV_EXT_MECH_SESSION_STOPPED);
    for (unsigned i=0;i<XDEV_EXT_MECH_MAX_STAGES;i++) {
        CHANGED(b.stats.submitted[i]++); CHANGED(b.stats.completed[i]++);
    }
#undef CHANGED
#define INVALID(expr) do { b=a; expr; invalid_checks++; \
    if (!sp_hold_valid(&b) && !sp_held_equal(&b,&b)) invalid_rejected++; } while (0)
    INVALID(b.batch.ticket=0; b.live_ticket=0);
    INVALID(b.live_ticket++);
    INVALID(b.batch.nr_frames=1);
    INVALID(b.ready_prod++);
    INVALID(b.done_prod++);
    INVALID(b.stats.inflight=0);
    INVALID(b.stats.batches_done=1);
    INVALID(b.stats.published=2);
    INVALID(b.stats.completed[0]=1);
    INVALID(b.stats.last_err=-EIO);
    INVALID(b.stats.sequestered=1);
    INVALID(b.stats.batches_abort=1);
    INVALID(b.stats.state=XDEV_EXT_MECH_SESSION_STOPPED);
#undef INVALID
    printf("{\"valid\":%d,\"equal\":%d,\"frame_bytes\":%zu,"
           "\"byte_checks\":%u,\"byte_rejected\":%u,"
           "\"metadata_checks\":%u,\"metadata_rejected\":%u,"
           "\"invalid_checks\":%u,\"invalid_rejected\":%u}\n",
           initial_valid,equal_control,sizeof(a.frame_bytes),byte_checks,byte_rejected,
           metadata_checks,metadata_rejected,invalid_checks,invalid_rejected);
    return 0;
}
'''


class ActualSharedpoolVerdicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = actual_verdicts()
        cls.record = cls.actual.run() if cls.actual is not None else None
        if cls.actual is not None:
            cls.addClassCleanup(cls.actual.close)

    def observation(self):
        self.assertIsNotNone(self.record,
                             "missing actual sharedpool_session_guest sp_hold_valid/sp_held_equal: feature RED")
        return self.record

    def test_valid_same_live_hold_is_accepted(self):
        r=self.observation()
        self.assertEqual((r["valid"],r["equal"]),(1,1))

    def test_every_payload_and_guard_byte_is_compared(self):
        r=self.observation()
        self.assertEqual((r["frame_bytes"],r["byte_checks"],r["byte_rejected"]),(8192,8192,8192))

    def test_batch_frame_live_ticket_ready_and_stats_changes_are_rejected(self):
        r=self.observation()
        self.assertGreaterEqual(r["metadata_checks"],40)
        self.assertEqual(r["metadata_rejected"],r["metadata_checks"])

    def test_equal_but_released_duplicate_ready_or_invalid_snapshots_cannot_pass(self):
        r=self.observation()
        self.assertGreaterEqual(r["invalid_checks"],10)
        self.assertEqual(r["invalid_rejected"],r["invalid_checks"])


if __name__ == "__main__":
    unittest.main()
