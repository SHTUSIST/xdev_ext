# SPDX-License-Identifier: GPL-2.0
"""TP driver host-frame selection: the actual driver.cc parser, handshake and
metadata statements compiled against options.h. No device, owner or run."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'tests/benchmarks/tp/driver.cc'


def extractor():
    spec = importlib.util.spec_from_file_location(
        'tp_driver_extract', ROOT / 'tests/compute/cuda/early_selection/test_driver.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.function


def metadata_statements(text):
    statements, offset, marker = [], 0, r'printf("{\"record\":\"metadata\"'
    while True:
        start = text.find(marker, offset)
        if start < 0:
            return statements
        depth, quoted, escaped = 0, False, False
        for at in range(text.index('(', start), len(text)):
            char = text[at]
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    break
        statements.append(text[start:at + 1] + ';')
        offset = at + 1


class DriverFramesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        function = extractor()
        text = DRIVER.read_text()
        start = text.index('for(int i=1;i<argc;++i)')
        end = text.index('NATIVE(tp_eval_geometry(o));', start) + len('NATIVE(tp_eval_geometry(o));')
        statements = metadata_statements(text)
        assert len(statements) == 2
        source = '\n'.join([
            '#include <cerrno>', '#include <climits>', '#include <cstdio>', '#include <cstdlib>',
            '#include <cstring>', '#include <stdexcept>', '#include <string>', '#include <time.h>',
            '#include "tests/benchmarks/tp/options.h"',
            'struct xdev_ext_cuda_peer_programs_opts {size_t size;unsigned version,flags;'
            'const char *tx_stage_pins[3],*rx_stage_pins[2];};',
            'static void native_check(int rc){if(rc)throw std::runtime_error(std::to_string(rc));}',
            '#define NATIVE(call) native_check(call)',
            '\n'.join(function(text, n) for n in ('now_ns', 'number', 'small')),
            function(text, 'handshake'),
            'static tp_eval_options parse(int argc,char **argv){tp_eval_options o;'
            'const char *node=nullptr,*bpf=nullptr,*user_bpf=nullptr,*tp_ptx=nullptr,*oracle=nullptr,'
            '*address=nullptr;xdev_ext_cuda_peer_programs_opts programs{};bool selected_programs=false;'
            'unsigned port=0;bool have_rank=false;(void)node;(void)bpf;(void)user_bpf;(void)tp_ptx;'
            '(void)oracle;(void)address;(void)port;(void)have_rank;(void)selected_programs;(void)programs;'
            + text[start:end] + 'return o;}',
            'static void metadata(const tp_eval_options &o,bool echo){struct {unsigned long long '
            'trace_dropped=0,logical_inflight_high_water=1,completed=2,gpu_invocations=0,'
            'host_control_calls=4;} stats;if(echo){' + statements[0] + '}else{' + statements[1] + '}}',
            'int main(int argc,char **argv){',
            ' std::string kind=argv[1];',
            ' if(kind=="parse"){try{auto o=parse(argc-2,argv+2);std::printf("%u %s\\n",o.frames,'
            'o.ce_bpf_object?o.ce_bpf_object:"-");}catch(const std::exception &e){std::printf("error\\n");}return 0;}',
            ' tp_eval_options o;o.operation=1;o.communicator=7;o.epoch=9;o.first_sequence=23;',
            ' o.iterations=2;o.elements=16;o.frames=unsigned(std::atoi(argv[2]));',
            ' if(kind=="handshake"){std::printf("%s\\n",handshake(o).c_str());return 0;}',
            ' metadata(o,kind=="echo");return 0;}'])
        cls.directory = tempfile.TemporaryDirectory()
        probe = Path(cls.directory.name) / 'probe.cc'
        probe.write_text(source)
        cls.exe = Path(cls.directory.name) / 'probe'
        build = subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Wno-unused-function',
                                '-I' + str(ROOT), str(probe), '-o', str(cls.exe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise AssertionError('driver extraction did not compile:\n' + build.stderr[-3000:])

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_probe(self, *args):
        result = subprocess.run([str(self.exe), *args], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_parser_selects_host_frames_and_ce_program(self):
        self.assertEqual(self.run_probe('parse', 'driver', '--mode', 'd1'), '0 -')
        self.assertEqual(self.run_probe('parse', 'driver', '--frames', 'host',
                                        '--ce-bpf-object', '/x/tp_ce_place.bpf.o'),
                         '1 /x/tp_ce_place.bpf.o')
        self.assertEqual(self.run_probe('parse', 'driver', '--frames', 'peer'), '0 -')
        self.assertEqual(self.run_probe('parse', 'driver', '--frames', 'gpu'), 'error')
        self.assertEqual(self.run_probe('parse', 'driver', '--frames', 'host', '--mode', 'd2'), 'error')

    def test_handshake_carries_frames_only_when_host(self):
        peer, host = self.run_probe('handshake', '0'), self.run_probe('handshake', '1')
        self.assertEqual(len(peer), len(host))
        # The PEER bytes stay those the EARLY fixture freezes; host sets bit 30.
        self.assertIn(':00000001:00000001:00000003:00000001:', peer)
        self.assertIn(':40000001:00000001:00000003:00000001:', host)

    def test_metadata_records_frames(self):
        for branch in ('echo', 'collective'):
            for frames, name in (('0', 'peer'), ('1', 'host')):
                record = json.loads(self.run_probe(branch, frames))
                self.assertEqual(record['frames'], name)


if __name__ == '__main__':
    unittest.main()
