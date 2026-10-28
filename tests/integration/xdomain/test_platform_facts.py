# SPDX-License-Identifier: GPL-2.0
"""Independent C1 requirements tests; no physical execution is asserted.

Source grammar: pinned drivers/thunderbolt/{tb.c,icm.c,tb.h,tunnel.c},
xdomain.c public device naming, and root freeze 19:10 UTC in the closure plan.
The future collector is intentionally not used to construct any expectation.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest

try:
    from platform_facts import collect_platform_facts
except ModuleNotFoundError as exc:
    if exc.name != "platform_facts":
        raise
    collect_platform_facts = None


IDENTITY = {
    "version": 1, "run_id": "c1-independent", "sha": "7" * 40,
    "role": "tx", "case": "functional-epochs", "direction": "a-to-b",
    "epoch": 2, "request_id": 9,
}
BOOT = "00112233-4455-6677-8899-aabbccddeeff"
BUILD = "00112233445566778899aabbccddeeff00112233"
NHI = "0000:03:00.0"
PREFIX = "thunderbolt 0000:03:00.0: "
RESULT_KEYS = {"status", "reason", "identity", "software_cm", "credits", "iommu", "acs", "evidence"}


class Capture:
    """Small hand-authored raw evidence tree, independent of collector code."""
    def __init__(self, root):
        self.root = Path(root)
        self.sys = self.root / "sys"
        self.proc = self.root / "proc"
        self.nhi = self.sys / "devices/pci0000:00/0000:00:01.0" / NHI
        self.parent = self.nhi.parent
        self.domain = self.nhi / "domain0"
        self.router = self.domain / "0-0"
        self.xdomain = self.router / "0-1"
        self.xdomain.mkdir(parents=True)
        for name, target in ((NHI, self.nhi), ("0000:00:01.0", self.parent)):
            self.link(self.sys / "bus/pci/devices" / name, target)
        for name, target in (("domain0", self.domain), ("0-0", self.router), ("0-1", self.xdomain)):
            self.link(self.sys / "bus/thunderbolt/devices" / name, target)
        self.group = self.sys / "kernel/iommu_groups/17"
        self.group.mkdir(parents=True)
        (self.group / "type").write_text("DMA\n")
        self.link(self.nhi / "iommu_group", self.group)
        self.link(self.group / "devices" / NHI, self.nhi)
        self.proc.joinpath("sys/kernel/random").mkdir(parents=True)
        self.proc.joinpath("sys/kernel/random/boot_id").write_text(BOOT + "\n")
        # ELF32/64 note headers have the same 3x32-bit layout. GNU type3 build-id.
        self.sys.joinpath("kernel/notes").write_bytes(bytes.fromhex(
            "040000001400000003000000474e5500"
            "00112233445566778899aabbccddeeff00112233"))
        cfg = bytearray(4096)
        cfg[0x100:0x108] = bytes.fromhex("0d0001003f000500")
        self.nhi_config = bytes(cfg)
        self.nhi.joinpath("config").write_bytes(cfg)
        self.parent.joinpath("config").write_bytes(bytes(4096))
        self.base = (time.monotonic_ns() - 2_000_000_000) // 1000 * 1000
        self.records = [
            self.record(90, -10, PREFIX + "using software connection manager"),
            self.record(101, 1, self.marker("BEGIN", 501, "data", 3)),
            self.record(102, 2, PREFIX + "0:1: reserving 6 credits for DMA path"),
            self.record(103, 3, PREFIX + "0:2: reserving 9 credits for DMA path"),
            self.record(104, 4, PREFIX + "0:2: reserving 7 credits for DMA path"),
            self.record(105, 5, self.marker("END", 501, "data", 3) + " result=0"),
            self.record(106, 6, self.marker("BEGIN", 502, "control", 0)),
            self.record(107, 7, PREFIX + "0:3: reserving 3 credits for DMA path"),
            self.record(108, 8, self.marker("END", 502, "control", 0) + " result=0"),
        ]
        self.expected = {
            "identity": copy.deepcopy(IDENTITY), "nhi_bdf": NHI, "domain": 0,
            "link_token": 19, "channel": 3, "max_log_age_ms": 120000,
        }
        self.receipt = {
            "version": 1, "identity": copy.deepcopy(IDENTITY), "boot_id": BOOT,
            "kernel_build_id": BUILD, "nhi_bdf": NHI, "domain": 0,
            "cursor_seq": 100, "begin_ns": self.base,
            "end_ns": self.base + 20_000_000,
            "captured_monotonic_ns": self.base + 30_000_000,
            "complete": True, "kmsg_lost": 0, "log_sha256": "",
        }
        self.log = self.root / "kmsg.jsonl"
        self.receipt_path = self.root / "receipt.json"
        self.write()

    @staticmethod
    def link(path, target):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)

    @staticmethod
    def marker(phase, scope, role, channel):
        return (PREFIX + f"XDEV_EXT_XDOMAIN_PATH phase={phase} scope={scope} "
                f"token=19 local_inc=21 remote_inc=22 xdomain=0-1 role={role} channel={channel}")

    def record(self, seq, offset_ms, message):
        ns = self.base + offset_ms * 1_000_000
        priority = 6 if "XDEV_EXT_XDOMAIN_PATH" in message else 7
        return {"seq": seq, "monotonic_ns": ns, "message": message,
                "raw": f"{priority},{seq},{ns // 1000},-;{message}\n"}

    def replace_message(self, index, message):
        old = self.records[index]
        self.records[index] = self.record(old["seq"], (old["monotonic_ns"] - self.base) // 1_000_000, message)

    def write(self):
        self.log.write_text("".join(json.dumps(r) + "\n" for r in self.records))
        self.rehash()

    def rehash(self):
        digest = hashlib.sha256()
        with self.log.open("rb") as stream:
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
        self.receipt["log_sha256"] = digest.hexdigest()
        self.receipt_path.write_text(json.dumps(self.receipt))


class PlatformFactsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(collect_platform_facts,
                             "C1 API absent: implement platform_facts.collect_platform_facts")
        self.tmp = tempfile.TemporaryDirectory(prefix="c1-facts-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Capture(self.tmp.name)

    def collect(self):
        return collect_platform_facts(str(self.f.log), str(self.f.receipt_path),
                                      copy.deepcopy(self.f.expected),
                                      sysfs_root=str(self.f.sys), proc_root=str(self.f.proc))

    def incomplete(self):
        result = self.collect()
        self.assertEqual(result["status"], "incomplete", result)
        self.assertIsInstance(result["reason"], str)
        self.assertTrue(result["reason"], result)
        self.assertNotIn("physical_pass", result)
        return result

    def test_golden_raw_notes_ancestry_all_observed_reservations(self):
        """Catches default14, loss of repeated ports, and favorable fabricated facts."""
        r = self.collect()
        self.assertEqual(set(r), RESULT_KEYS)
        self.assertEqual(r["status"], "complete", r)
        self.assertEqual(r["identity"], {"run": IDENTITY, "boot_id": BOOT,
            "kernel_build_id": BUILD, "nhi_bdf": NHI, "domain": 0,
            "link_token": 19, "channel": 3})
        self.assertEqual(set(r["software_cm"]), {"proved", "records"})
        self.assertIs(r["software_cm"]["proved"], True)
        self.assertEqual(r["software_cm"]["records"], [self.f.records[0]])
        self.assertEqual(r["credits"], [
            {"scope":501,"role":"data","channel":3,"port":1,"reserved":6,"begin_seq":101,"end_seq":105,"record_seq":102},
            {"scope":501,"role":"data","channel":3,"port":2,"reserved":9,"begin_seq":101,"end_seq":105,"record_seq":103},
            {"scope":501,"role":"data","channel":3,"port":2,"reserved":7,"begin_seq":101,"end_seq":105,"record_seq":104},
            {"scope":502,"role":"control","channel":0,"port":3,"reserved":3,"begin_seq":106,"end_seq":108,"record_seq":107},
        ])
        self.assertEqual(set(r["iommu"]), {"group", "type", "raw"})
        self.assertEqual(r["iommu"]["group"], "17")
        self.assertEqual(r["iommu"]["type"], "DMA")
        self.assertIn("DMA", r["iommu"]["raw"])
        by_bdf = {item["bdf"]: item for item in r["acs"]}
        self.assertEqual(set(by_bdf), {NHI, "0000:00:01.0"})
        self.assertEqual(by_bdf[NHI], {"bdf":NHI,"capability":63,"control":5,
                                     "raw_config_hex":self.f.nhi_config.hex()})
        self.assertEqual(by_bdf["0000:00:01.0"], {"bdf":"0000:00:01.0",
            "capability":None,"control":None,"raw_config_hex":bytes(4096).hex()})
        self.assertEqual(r["evidence"], {"log_path":str(self.f.log),
            "receipt_path":str(self.f.receipt_path),"log_sha256":self.f.receipt["log_sha256"]})

    def test_every_receipt_run_identity_field_binds(self):
        for key, wrong in (("run_id","other"),("sha","8"*40),("role","rx"),
                           ("case","bulk-static"),("direction","b-to-a"),
                           ("epoch",3),("request_id",10),("version",2)):
            with self.subTest(key=key):
                self.f.receipt["identity"] = dict(IDENTITY, **{key:wrong})
                self.f.write()
                self.incomplete()

    def test_receipt_boot_and_running_build_are_not_caller_claims(self):
        for key, wrong in (("boot_id","11112233-4455-6677-8899-aabbccddeeff"),
                           ("kernel_build_id","ff"*20),("nhi_bdf","0000:04:00.0"),("domain",1)):
            with self.subTest(key=key):
                original = self.f.receipt[key]
                self.f.receipt[key] = wrong
                self.f.write()
                self.incomplete()
                self.f.receipt[key] = original

    def test_current_boot_or_gnu_build_note_missing_is_unknown(self):
        for path in (self.f.sys/"kernel/notes", self.f.proc/"sys/kernel/random/boot_id"):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.unlink()
                self.incomplete()
                path.write_bytes(original)
        self.f.sys.joinpath("kernel/notes").write_bytes(bytes.fromhex("ffffffffffffffff03000000474e5500"))
        self.incomplete()

    def test_hash_requires_original_capture_bytes(self):
        with self.f.log.open("a") as stream:
            stream.write("\n")
        self.incomplete()

    def test_raw_kmsg_and_json_metadata_must_agree(self):
        original = copy.deepcopy(self.f.records[2])
        for key, bad in (("seq",999),("monotonic_ns",self.f.base+9000),
                         ("message",PREFIX+"0:1: reserving 14 credits for DMA path"),
                         ("raw","7,102,0,-;fabricated\n")):
            with self.subTest(key=key):
                self.f.records[2] = dict(original, **{key:bad})
                self.f.write()
                self.incomplete()
        self.f.records[2] = original

    def test_incomplete_loss_and_duplicate_sequences_refuse(self):
        for key, bad in (("complete",False),("kmsg_lost",1)):
            with self.subTest(key=key):
                original = self.f.receipt[key]
                self.f.receipt[key] = bad
                self.f.write()
                self.incomplete()
                self.f.receipt[key] = original
        self.f.records.insert(3, copy.deepcopy(self.f.records[2]))
        self.f.write()
        self.incomplete()

    def test_postcursor_sequence_gap_refuses_even_with_complete_receipt(self):
        # Root review freeze: complete/lost=0 cannot override observable loss
        # inside the postcursor capture. Precursor CM sideband gaps are valid.
        self.assertEqual(self.collect()["status"], "complete")
        self.assertEqual(self.f.records[0]["seq"], 90)
        self.assertEqual(self.f.receipt["cursor_seq"], 100)
        del self.f.records[3]  # seq103; other positive reservations remain.
        self.f.write()  # Hash agrees with original remaining capture bytes.
        self.assertIs(self.f.receipt["complete"], True)
        self.assertEqual(self.f.receipt["kmsg_lost"], 0)
        self.incomplete()

    def test_later_same_device_failure_other_token_invalidates_old_success(self):
        # Root review freeze: a changed token is not permission to reuse the
        # prior same-device/role/channel success; another device is independent.
        original = copy.deepcopy(self.f.records)
        for role, channel in (("data", 3), ("control", 0)):
            with self.subTest(role=role, channel=channel):
                self.f.records = copy.deepcopy(original)
                self.f.records.extend([
                    self.f.record(109, 9, self.f.marker("BEGIN", 503, role, channel).replace("token=19", "token=20")),
                    self.f.record(110, 10, self.f.marker("END", 503, role, channel).replace("token=19", "token=20") + " result=-5"),
                ])
                self.f.write()
                self.incomplete()
        other = self.f.router / "0-2"
        other.mkdir()
        self.f.link(self.f.sys / "bus/thunderbolt/devices/0-2", other)
        self.f.records = copy.deepcopy(original)
        self.f.records.extend([
            self.f.record(109, 9, self.f.marker("BEGIN", 503, "data", 3).replace("token=19", "token=20").replace("xdomain=0-1", "xdomain=0-2")),
            self.f.record(110, 10, self.f.marker("END", 503, "data", 3).replace("token=19", "token=20").replace("xdomain=0-1", "xdomain=0-2") + " result=-5"),
        ])
        self.f.write()
        self.assertEqual(self.collect()["status"], "complete")

    def test_window_and_cursor_apply_to_actual_paths(self):
        for key, bad in (("cursor_seq",101),("begin_ns",self.f.base+2_000_000),
                         ("end_ns",self.f.base+7_000_000)):
            with self.subTest(key=key):
                original = self.f.receipt[key]
                self.f.receipt[key] = bad
                self.f.write()
                self.incomplete()
                self.f.receipt[key] = original

    def test_capture_must_be_fresh_not_future_and_after_window(self):
        for captured in (self.f.base-1, time.monotonic_ns()+30_000_000_000):
            with self.subTest(captured=captured):
                self.f.receipt["captured_monotonic_ns"] = captured
                self.f.write()
                self.incomplete()
        # Coherent but old capture: all raw and parsed times are old together.
        self.f.base -= 180_000_000_000
        self.f.records = [self.f.record(r["seq"], i, r["message"]) for i,r in enumerate(self.f.records)]
        self.f.receipt.update(begin_ns=self.f.base, end_ns=self.f.base+20_000_000,
                              captured_monotonic_ns=self.f.base+30_000_000)
        self.f.write()
        self.incomplete()

    def test_expected_unsigned_types_bounds_and_age(self):
        for key, bad in (("domain",-1),("domain",1<<32),("channel",1<<32),
                         ("link_token",1<<64),("link_token",True),
                         ("max_log_age_ms",0),("max_log_age_ms",120001)):
            with self.subTest(key=key,bad=bad):
                original = self.f.expected[key]
                self.f.expected[key] = bad
                self.incomplete()
                self.f.expected[key] = original
        del self.f.expected["identity"]["request_id"]
        self.incomplete()

    def test_unsigned_receipt_and_raw_overflows_refuse(self):
        for key in ("cursor_seq","begin_ns","end_ns","captured_monotonic_ns"):
            with self.subTest(key=key):
                original = self.f.receipt[key]
                self.f.receipt[key] = 1<<64
                self.f.write()
                self.incomplete()
                self.f.receipt[key] = original
        self.f.replace_message(1, self.f.records[1]["message"].replace("scope=501","scope=18446744073709551616"))
        self.f.write()
        self.incomplete()

    def test_global_or_foreign_nhi_cm_cannot_authorize(self):
        original = self.f.records[0]["message"]
        for bad in ("using software connection manager", original.replace(NHI,"0000:04:00.0")):
            with self.subTest(message=bad):
                self.f.replace_message(0,bad)
                self.f.write()
                self.incomplete()

    def test_last_same_nhi_connection_manager_decides(self):
        self.f.records.append(self.f.record(109,9,PREFIX+"using firmware connection manager"))
        self.f.write()
        self.incomplete()
        self.f.records.append(self.f.record(110,10,PREFIX+"using software connection manager"))
        self.f.write()
        self.assertEqual(self.collect()["status"],"complete")

    def test_scopes_bind_nhi_token_device_role_channel_incarnations(self):
        original = copy.deepcopy(self.f.records)
        for before, after in ((NHI,"0000:04:00.0"),("token=19","token=20"),
                              ("xdomain=0-1","xdomain=1-1"),("role=data","role=unknown"),
                              ("channel=3","channel=4"),("local_inc=21","local_inc=18446744073709551616"),
                              ("remote_inc=22","remote_inc=18446744073709551616")):
            with self.subTest(field=before):
                self.f.records = copy.deepcopy(original)
                self.f.replace_message(1,self.f.records[1]["message"].replace(before,after))
                self.f.replace_message(5,self.f.records[5]["message"].replace(before,after))
                self.f.write()
                self.incomplete()

    def test_matching_sysfs_name_without_nhi_domain_ancestry_refuses(self):
        alias = self.f.sys/"bus/thunderbolt/devices/0-1"
        alias.unlink()
        foreign = self.f.sys/"devices/pci0000:00/0000:00:02.0/0000:04:00.0/domain0/0-1"
        foreign.mkdir(parents=True)
        alias.symlink_to(foreign)
        self.incomplete()

    def test_fake_default14_and_unscoped_credits_never_observe(self):
        self.f.records = [r for r in self.f.records if "reserving " not in r["message"]]
        self.f.records.append(self.f.record(109,9,PREFIX+"configured DMA credits=14"))
        self.f.write()
        self.incomplete()
        self.f.records.append(self.f.record(110,10,PREFIX+"0:1: reserving 14 credits for DMA path"))
        self.f.write()
        self.incomplete()

    def test_zero_foreign_nhi_and_nonexistent_router_credit_refuse(self):
        original = copy.deepcopy(self.f.records)
        for before, after in (("reserving 3","reserving 0"),(NHI,"0000:04:00.0"),
                              ("0:3:","ff:3:")):
            with self.subTest(field=before):
                self.f.records = copy.deepcopy(original)
                self.f.replace_message(7,self.f.records[7]["message"].replace(before,after))
                self.f.write()
                self.incomplete()

    def test_both_data_and_control_success_are_required(self):
        original = copy.deepcopy(self.f.records)
        for indexes in ((6,7,8),(1,2,3,4,5)):
            with self.subTest(removed=indexes):
                self.f.records = [r for i,r in enumerate(original) if i not in indexes]
                self.f.write()
                self.incomplete()
        self.f.records = copy.deepcopy(original)
        self.f.replace_message(8,self.f.records[8]["message"].replace("result=0","result=-5"))
        self.f.write()
        self.incomplete()

    def test_later_failed_or_unterminated_attempt_supersedes_success(self):
        original = copy.deepcopy(self.f.records)
        for ended in (False,True):
            with self.subTest(ended=ended):
                self.f.records = copy.deepcopy(original)
                self.f.records.append(self.f.record(109,9,self.f.marker("BEGIN",503,"data",3)))
                if ended:
                    self.f.records.append(self.f.record(110,10,self.f.marker("END",503,"data",3)+" result=-28"))
                self.f.write()
                self.incomplete()

    def test_later_complete_attempt_replaces_old_reservations(self):
        self.f.records.extend([
            self.f.record(109,9,self.f.marker("BEGIN",503,"data",3)),
            self.f.record(110,10,PREFIX+"0:1: reserving 11 credits for DMA path"),
            self.f.record(111,11,self.f.marker("END",503,"data",3)+" result=0"),
            self.f.record(112,12,self.f.marker("BEGIN",504,"control",0)),
            self.f.record(113,13,PREFIX+"0:3: reserving 4 credits for DMA path"),
            self.f.record(114,14,self.f.marker("END",504,"control",0)+" result=0")])
        self.f.write()
        r = self.collect()
        self.assertEqual(r["status"],"complete",r)
        data = [c for c in r["credits"] if c["role"] == "data"]
        self.assertEqual(data,[{"scope":503,"role":"data","channel":3,"port":1,
            "reserved":11,"begin_seq":109,"end_seq":111,"record_seq":110}])

    def test_new_data_cannot_stitch_old_control_or_other_incarnation(self):
        original = copy.deepcopy(self.f.records)
        self.f.records.extend([
            self.f.record(109,9,self.f.marker("BEGIN",503,"data",3)),
            self.f.record(110,10,PREFIX+"0:1: reserving 11 credits for DMA path"),
            self.f.record(111,11,self.f.marker("END",503,"data",3)+" result=0")])
        self.f.write()
        self.incomplete()
        self.f.records = original
        for index in (6,8):
            self.f.replace_message(index,self.f.records[index]["message"].replace("remote_inc=22","remote_inc=23"))
        self.f.write()
        self.incomplete()

    def test_nested_or_interleaved_scopes_are_ambiguous(self):
        self.f.records.insert(3,self.f.record(103,3,self.f.marker("BEGIN",900,"control",0)))
        # Keep raw/parsed sequences coherent and unique: ambiguity alone must fail.
        self.f.records = [self.f.record(90 if i==0 else 100+i,i,r["message"]) for i,r in enumerate(self.f.records)]
        self.f.write()
        self.incomplete()

    def test_iommu_or_config_unreadable_never_implies_isolation(self):
        for path in (self.f.nhi/"iommu_group",self.f.group/"type",self.f.nhi/"config",self.f.parent/"config"):
            with self.subTest(path=path):
                if path.is_symlink():
                    target = path.readlink(); path.unlink()
                    self.incomplete(); path.symlink_to(target)
                else:
                    data = path.read_bytes(); path.unlink()
                    self.incomplete(); path.write_bytes(data)

    def test_extended_capability_chain_is_followed_and_loops_refuse(self):
        cfg = bytearray(self.f.nhi_config)
        cfg[0x100:0x104] = struct.pack("<I",(0x120<<20)|(1<<16)|1)
        cfg[0x120:0x128] = bytes.fromhex("0d00010012000200")
        self.f.nhi.joinpath("config").write_bytes(cfg)
        r = self.collect()
        self.assertEqual(r["status"],"complete",r)
        actual = next(a for a in r["acs"] if a["bdf"]==NHI)
        self.assertEqual((actual["capability"],actual["control"]),(18,2))
        cfg[0x120:0x124] = struct.pack("<I",(0x100<<20)|(1<<16)|2)
        self.f.nhi.joinpath("config").write_bytes(cfg)
        self.incomplete()

    def test_missing_malformed_unknown_keys_and_duplicate_json_keys_refuse(self):
        original_log = self.f.log.read_bytes()
        original_receipt = self.f.receipt_path.read_bytes()
        for path in (self.f.log,self.f.receipt_path):
            with self.subTest(missing=path):
                data = path.read_bytes(); path.unlink()
                self.incomplete(); path.write_bytes(data)
        for bad in (b'{broken\n', b'{"seq":1,"seq":2}\n'):
            with self.subTest(raw=bad):
                self.f.log.write_bytes(bad); self.f.rehash(); self.incomplete()
        self.f.log.write_bytes(original_log)
        self.f.receipt_path.write_bytes(original_receipt)
        self.f.receipt["extra"] = True
        self.f.write(); self.incomplete()
        del self.f.receipt["extra"]
        self.f.records[2]["extra"] = True
        self.f.write(); self.incomplete()
        del self.f.records[2]["extra"]
        self.f.write()
        receipt = self.f.receipt_path.read_text()
        self.f.receipt_path.write_text('{"version":1,' + receipt[1:])
        self.incomplete()

    def test_capture_line_and_total_size_are_bounded(self):
        self.f.replace_message(2,"X"*(2*1024*1024))
        self.f.write(); self.incomplete()
        # Valid irrelevant records preserve the good paths. Only the total-size
        # bound (16 MiB), not missing credits/malformed JSON, should refuse them.
        self.f.replace_message(2,PREFIX + "0:1: reserving 6 credits for DMA path")
        self.f.write()
        with self.f.log.open("a") as stream:
            for seq in range(109,4309):
                stream.write(json.dumps(self.f.record(seq,9,"noise:"+"x"*4096))+"\n")
        self.assertGreater(self.f.log.stat().st_size,32*1024*1024)
        self.f.rehash(); self.incomplete()
        self.f.write()
        # Large but otherwise exactly valid receipt JSON must also be bounded.
        receipt = self.f.receipt_path.read_bytes()
        self.f.receipt_path.write_bytes(b" "*(65537-len(receipt))+receipt)
        self.incomplete()

    def test_record_count_is_bounded_within_capture_size_limit(self):
        # 100001 coherent records fit below 16 MiB; each line is below 64 KiB.
        with self.f.log.open("a") as stream:
            for seq in range(109,100101):
                stream.write(json.dumps(self.f.record(seq,9,"x"))+"\n")
        self.assertLess(self.f.log.stat().st_size,16*1024*1024)
        self.f.rehash(); self.incomplete()


if __name__ == "__main__":
    unittest.main()
