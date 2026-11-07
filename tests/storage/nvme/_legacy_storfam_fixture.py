# SPDX-License-Identifier: GPL-2.0
"""Whole-owner assembly for the adjacent, public legacy storage fixtures.

This module never guesses a dependency root from a source filename or a hint.
Only fixture text is adapted; selected production definitions remain verbatim.
"""
from pathlib import Path
import re
import runpy
import posixpath
import hashlib

_ROOT = next(p for p in Path(__file__).resolve().parents
             if (p / 'source-layout.json').is_file())
_API = runpy.run_path(str(_ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py'))
N = 'drivers/nvme/host/xdev_ext_mech_nvme.c'
B = 'io_uring/family/xdev_ext_storfam_block.c'
R = 'io_uring/family/xdev_ext_storfam.c'
H = 'include/linux/xdev_ext_storfam_block.h'
I = 'drivers/nvme/host/nvme.h'
Q = 'io_uring/family/xdev_ext_requester.c'
P = 'drivers/nvme/host/xdev_ext_peer_nvme_core.h'
T = 'drivers/nvme/host/xdev_ext_native_peer_trace.h'


# A fixture stage file is always the namespace file, never an LBA window
# handle (tests/storage/nvme/window_handle covers handles): the namespace-file
# branch of the two helpers nvme_xdev_ext_member_bind calls, as fixture text.
WINDOW_NAMESPACE_FILE = '''static struct file *nvme_xdev_ext_window_target(struct file *file)
{
\treturn file;
}

static int nvme_xdev_ext_window_admit(const struct xdev_ext_mech_stage *st, bool write)
{
\t(void)st;
\t(void)write;
\treturn 0;
}'''
WINDOW_FLAG_MACROS = ('NVME_XDEV_EXT_WINDOW_F_READ', 'NVME_XDEV_EXT_WINDOW_F_WRITE')


def _balanced(text, start):
    """Return one complete C brace body, ignoring comments and literals."""
    depth, quote, comment, escaped = 0, None, None, False
    i = start
    while i < len(text):
        c, n = text[i], text[i + 1:i + 2]
        if comment == 'line':
            if c == '\n':
                comment = None
        elif comment == 'block':
            if c == '*' and n == '/':
                comment = None
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == quote:
                quote = None
        elif c == '/' and n == '/':
            comment = 'line'
            i += 1
        elif c == '/' and n == '*':
            comment = 'block'
            i += 1
        elif c in ('"', "'"):
            quote = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError('SETUP incomplete production definition')


def adapt_fixture(raw, edits):
    value, records = raw, []
    for edit in edits:
        required = {'old', 'new', 'count', 'reason', 'source_owner'}
        if not required <= edit.keys():
            raise ValueError('SETUP incomplete fixture edit')
        old, new, count = edit['old'], edit['new'], edit['count']
        if not isinstance(old, str) or not old or not isinstance(new, str):
            raise ValueError('SETUP invalid fixture edit text')
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError('SETUP fixture count must be positive')
        if not edit['reason'] or not edit['source_owner']:
            raise ValueError('SETUP fixture edit lacks attribution')
        starts = [m.start() for m in re.finditer(re.escape(old), value)]
        if len(starts) != count:
            raise ValueError('SETUP fixture anchor count %d != %d: %s' %
                             (len(starts), count, old))
        before, replacements, shift = len(value), [], 0
        before_digest=hashlib.sha256(value.encode()).hexdigest()
        for start in starts:
            offset = start + shift
            value = value[:offset] + new + value[offset + len(old):]
            replacements.append({'offset': offset, 'old': old, 'new': new})
            shift += len(new) - len(old)
        records.append({**edit, 'before_length': before,
                        'after_length': len(value), 'replacements': replacements,
                        'before_sha256':before_digest,
                        'after_sha256':hashlib.sha256(value.encode()).hexdigest()})
    if restore_fixture(value, records) != raw:
        raise ValueError('SETUP fixture inverse differs')
    return value, records


def restore_fixture(generated, records):
    value = generated
    for record in reversed(records):
        if len(value) != record['after_length']:
            raise ValueError('SETUP fixture inverse length mismatch')
        if hashlib.sha256(value.encode()).hexdigest()!=record['after_sha256']:
            raise ValueError('SETUP fixture inverse postimage mismatch')
        if len(record['replacements']) != record['count']:
            raise ValueError('SETUP fixture inverse count mismatch')
        for replacement in reversed(record['replacements']):
            offset, old, new = (replacement[k] for k in ('offset', 'old', 'new'))
            if old != record['old'] or new != record['new']:
                raise ValueError('SETUP fixture inverse record mismatch')
            if value[offset:offset + len(new)] != new:
                raise ValueError('SETUP fixture inverse bytes mismatch')
            value = value[:offset] + old + value[offset + len(new):]
        if len(value) != record['before_length']:
            raise ValueError('SETUP fixture inverse preimage length mismatch')
        if hashlib.sha256(value.encode()).hexdigest()!=record['before_sha256']:
            raise ValueError('SETUP fixture inverse preimage bytes mismatch')
    return value


class LegacySelection:
    GROUPS = ('validate', 'submit', 'pool', 'bind', 'poll')
    PROFILES = ('strict', 'bounce')

    def __init__(self, root):
        try:
            self._selection = _API['SourceSelection'](Path(root))
        except (AssertionError, RuntimeError) as error:
            raise ValueError(str(error)) from error
        self.root = self._selection.root
        self._bytes = {}
        self._definitions = {}
        self._source_facts = {}
        self._declarations = None
        self._closures = {}
        self._common_observers = []
        self._dependency_projections = []

    def read(self, native):
        if not isinstance(native, str) or native.startswith('/') or '..' in Path(native).parts:
            raise ValueError('SETUP invalid selected native path')
        try:
            self._selection.read(native)
            payload=self._selection.file(native).read_bytes()
            previous=self._bytes.setdefault(native,payload)
            if previous!=payload:
                raise ValueError('SETUP selected source bytes changed: '+native)
            return payload.decode('utf-8')
        except (AssertionError, RuntimeError) as error:
            raise ValueError(str(error)) from error

    def verify(self):
        try:
            self._selection.verify()
            for native,payload in self._bytes.items():
                if self._selection.file(native).read_bytes()!=payload:
                    raise ValueError('SETUP selected dependency bytes changed: '+native)
        except (AssertionError, RuntimeError) as error:
            raise ValueError(str(error)) from error

    def _locked_native_owner(self, native, public):
        """Keep selected native facts inside this utility's invalid-input API."""
        try:
            owner = self._selection.locked_native_owner(native, public)
            if self._selection.mapping is not None:
                self.read(self._selection.mapping.manifest.get(
                    'dependency_lock', 'third_party/sources.lock.json'))
            self.read(owner)
            return owner
        except (AssertionError, RuntimeError, OSError) as error:
            raise ValueError(str(error)) from error

    def _record(self, native, symbol, start, end, *, purpose=None):
        text = self.read(native)
        if start < 0 or end <= start or end > len(text):
            raise ValueError('SETUP invalid production span')
        offset = len(text[:start].encode())
        length = len(text[start:end].encode())
        key = (native, symbol, offset, length)
        record = dict(native=native, symbol=symbol, offset=offset, length=length)
        if purpose is None:
            self._definitions[key] = record
        elif purpose == 'profile-inspection-only':
            self._source_facts[key] = dict(record, purpose=purpose)
        else:
            raise ValueError('SETUP unsupported source fact purpose')
        return text[start:end]

    def definition(self, native, symbol, kind='function', *, purpose=None):
        text = self.read(native)
        if kind == 'struct':
            pattern = r'^struct ' + re.escape(symbol) + r'\s*\{'
        elif kind == 'enum':
            pattern = r'^enum ' + re.escape(symbol) + r'\s*\{'
        elif kind == 'object':
            pattern = r'^static const [^;{}]*\b' + re.escape(symbol) + r'\s*=\s*\{'
        else:
            pattern = (r'^[A-Za-z_][^;{}]*\b' + re.escape(symbol) +
                       r'\([^;{}]*\)\s*\{')
        matches = list(re.finditer(pattern, text, re.M))
        if len(matches) != 1:
            raise ValueError('SETUP production definition count %d: %s:%s' %
                             (len(matches), native, symbol))
        match = matches[0]
        end = _balanced(text, text.index('{', match.start()))
        if kind != 'function':
            suffix = re.match(r'\s*(?:__aligned\([0-9]+\)\s*)?;', text[end:])
            if suffix is None:
                raise ValueError('SETUP incomplete declaration suffix: ' + symbol)
            if symbol=='xdev_ext_stor_command' and not re.fullmatch(r'\s*__aligned\(8\)\s*;',suffix[0]):
                raise ValueError('SETUP command declaration must retain aligned(8) suffix')
            end += suffix.end()
        return self._record(native, symbol, match.start(), end, purpose=purpose)

    def _portable(self, native, visited=None):
        """Snapshot actual portable includes, without a foreign-root fallback."""
        visited = set() if visited is None else visited
        if native in visited:
            return
        visited.add(native)
        text = self.read(native)
        for dependency in re.findall(r'^#include [<"]([^>"]+)[>"]', text, re.M):
            if dependency.startswith(('linux/xdev_ext_', 'uapi/linux/xdev_ext_')):
                self._portable('include/' + dependency, visited)
            elif dependency.startswith(('linux/nvme_xdev_ext_', 'uapi/linux/nvme_ioctl')):
                self._portable('include/' + dependency, visited)
            elif dependency.startswith(('.', 'xdev_ext_')):
                child=posixpath.normpath(posixpath.join(posixpath.dirname(native),dependency))
                if child.startswith('include/') or child.startswith('drivers/nvme/host/xdev_ext_'):
                    self._portable(child,visited)

    def _validate_portable_declarations(self):
        """Validate whole required types; selected headers still deliver them."""
        passthru = 'include/linux/nvme_xdev_ext_passthru.h'
        text = self.read(passthru)
        resource = ('nvme_xdev_ext_resource_state',)
        if re.search(r'^#define[ \t]+nvme_xdev_ext_lifecycle\b', text, re.M):
            # Actual compatibility aliases select the shared type owner;
            # the original included headers still supply every helper body.
            for old, new in (
                    ('nvme_xdev_ext_lifecycle', 'xdev_ext_cmd_lifecycle'),
                    ('nvme_xdev_ext_cleanup_action', 'xdev_ext_cmd_cleanup_action'),
                    ('nvme_xdev_ext_resource_state', 'xdev_ext_cmd_resource_state')):
                matches = list(re.finditer(r'^#define[ \t]+' + re.escape(old) +
                                          r'[ \t]+' + re.escape(new) + r'[ \t]*$', text, re.M))
                if len(matches) != 1:
                    raise ValueError('SETUP selected command alias count: ' + old)
                match = matches[0]
                self._record(passthru, old, match.start(), match.end())
            generic = 'include/linux/xdev_ext_cmd_lifecycle.h'
            for symbol in ('xdev_ext_cmd_lifecycle', 'xdev_ext_cmd_cleanup_action'):
                self.definition(generic, symbol, 'enum')
            self.definition(generic, 'xdev_ext_cmd_resource_state', 'struct')
            resource = ()
        else:
            self.definition(passthru, 'nvme_xdev_ext_lifecycle', 'enum')
        required = {
            'include/linux/xdev_ext_storfam_core.h': (
                'xdev_ext_stor_window', 'xdev_ext_stor_rw',
                'xdev_ext_stor_queue_caps', 'xdev_ext_stor_seg_walk',
                'xdev_ext_stor_extent'),
            'include/linux/xdev_ext_storfam_runtime.h': (
                'xdev_ext_stor_slot', 'xdev_ext_stor_pool',
                'xdev_ext_stor_completion'),
            'include/uapi/linux/xdev_ext_mech.h': (
                'xdev_ext_mech_layout', 'xdev_ext_nvme_mech_cqe',
                'xdev_ext_mech_stage_uapi'),
            'include/linux/xdev_ext_desc_schema.h': ('xdev_ext_desc_schema16',),
            'include/linux/nvme_xdev_ext_passthru.h': (
                'nvme_xdev_ext_admission', 'nvme_xdev_ext_decoded',
                'nvme_xdev_ext_mech_bounds', 'nvme_xdev_ext_identity') + resource,
        }
        for native, symbols in required.items():
            for symbol in symbols:
                self.definition(native, symbol, 'struct')

    def _hook_declarations(self):
        """Actual hook types, native bounds and object, in dependency order."""
        pieces = [self.definition('include/linux/xdev_ext_mech.h',
                                  'xdev_ext_family_hooks_hdr', 'struct'),
                  self.definition('include/linux/xdev_ext_storfam.h',
                                  'xdev_ext_stor_hooks', 'struct')]
        native = self.read(N)
        for name in ('NVME_XDEV_EXT_PEER_MAX_PIECES',
                     'NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT'):
            matches = list(re.finditer(r'^#define ' + name + r'[^\n]*', native, re.M))
            if not matches and name == 'NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT':
                owned = [native]
                shared = re.search(r'\bnvme_xdev_ext_peer_build_cmd\s*\(', native)
                if shared or re.search(r'^#include\s+[<"]' + re.escape(posixpath.basename(P)) + r'[>"]', native, re.M):
                    owned.append(self.read(P))
                if shared:
                    owned.append(self.read('drivers/nvme/host/core.c'))
                if any(re.search(r'\b' + name + r'\b', text) for text in owned):
                    raise ValueError('SETUP unresolved selected native bound: ' + name)
                continue
            if len(matches) != 1:
                raise ValueError('SETUP native bound count: ' + name)
            match = matches[0]
            pieces.append(self._record(N, name, match.start(), match.end()))
        pieces.append(self.definition(N, 'nvme_xdev_ext_stor_hooks', 'object'))
        # Retain the exact object even in validate-only/poll-only fixture units.
        pieces.append('static const void *const fixture_stor_hooks_reference '
                      '__attribute__((used)) = &nvme_xdev_ext_stor_hooks;')
        return '\n\n'.join(pieces)

    def requester_profile(self):
        return 'struct xdev_ext_requester requester;' in self.read(H)

    def requester_stage(self):
        """Whole selected declaration, including authentic caps/report fields."""
        self._portable('include/uapi/linux/xdev_ext_mech.h')
        return self.definition('include/linux/xdev_ext_mech.h', 'xdev_ext_mech_stage', 'struct')

    def requester_native_types(self):
        owner = self._locked_native_owner('include/linux/dma-direction.h',
                                          _API['LOCKED_REQUESTER_NATIVE'])
        dma = self.definition(owner, 'dma_data_direction', 'enum')
        if self._selection.mapping is not None:
            return dma, '\n'.join(self.definition(owner, n, 'struct') for n in ('pci_bus', 'pci_dev'))
        native = 'include/linux/pci.h'
        def fields(symbol, patterns):
            body = self.definition(native, symbol, 'struct')
            source = self.read(native)
            start = source.index(body)
            values = []
            for pattern in patterns:
                matches = list(re.finditer(pattern, body, re.M))
                if len(matches) != 1:
                    raise ValueError('SETUP selected native PCI field count: ' + symbol)
                match = matches[0]
                values.append(self._record(native, symbol + '.field',
                              start + match.start(), start + match.end()))
            return 'struct ' + symbol + ' {\n' + '\n'.join(values) + '\n};'
        bus = fields('pci_bus', (r'^\s*unsigned char\s+number;[^\n]*',))
        pci = fields('pci_dev', (r'^\s*struct device\s+dev;[^\n]*',
            r'^\s*struct pci_bus\s*\*bus;[^\n]*', r'^\s*unsigned int\s+devfn;[^\n]*',
            r'^\s*unsigned int\s+untrusted:1;[^\n]*'))
        return dma, bus + '\n' + pci

    def requester_type_projection(self, raw):
        """Only external native field/type facts; record their full inverse."""
        dma, pci = self.requester_native_types()
        dma_matches = list(re.finditer(r'^enum dma_data_direction \{[^\n]+\};', raw, re.M))
        pci_matches = list(re.finditer(r'^struct pci_dev \{[^\n]+\};', raw, re.M))
        if len(dma_matches) != 1 or len(pci_matches) != 1:
            raise ValueError('SETUP external requester type projection count')
        edits = [dict(old=dma_matches[0][0],new=dma,count=1,
                      reason='genuine selected DMA direction enum',source_owner='selected native type owner'),
                 dict(old=pci_matches[0][0],new=pci,count=1,
                      reason='explicit authentic PCI field projection, no native layout claim',source_owner='selected native type owner')]
        value, records = adapt_fixture(raw, edits)
        self._dependency_projections.append(dict(kind='requester-native-types',records=records))
        return value

    def opcode_boundary_projection(self, raw):
        """Remove old external macro aliases, without changing native policy."""
        edits = []
        for line in ('#define nvme_cmd_write 1\n', '#define nvme_cmd_read 2\n',
                     '#define nvme_cmd_vendor_start 0xc0\n'):
            edits.append(dict(old=line,new='',count=1,reason='actual whole native opcode enum owns policy',
                              source_owner='selected native opcode owner'))
        value, records = adapt_fixture(raw, edits)
        self._dependency_projections.append(dict(kind='native-opcode-macro-removal',records=records))
        return value

    def poll_header_projection(self, native_raw, types_raw):
        """Preserve public raw headers; project only their current type boundary."""
        self.definition('include/uapi/linux/xdev_ext_mech.h','xdev_ext_mech_pool_kind','enum')
        split = '#else\n#ifndef STORAGE_POLL_CONSUMER_TYPES_H'
        if types_raw.count(split) != 1:
            raise ValueError('SETUP poll current header profile count')
        original = types_raw[:types_raw.index(split)]
        current = self.requester_type_projection(original)
        stages = re.findall(r'^struct xdev_ext_mech_stage \{[^\n]+\};', current, re.M)
        if len(stages) != 1:
            raise ValueError('SETUP poll current stage declaration count')
        requester = ('#include "include/linux/xdev_ext_requester_core.h"\n' +
                     self.definition('include/linux/xdev_ext_requester.h','xdev_ext_requester','struct') + '\n')
        current, inner = adapt_fixture(current,[
            dict(old=stages[0],new=self.requester_stage(),count=1,
                 reason='whole actual selected stage and typed reporting fields',source_owner='include/linux/xdev_ext_mech.h'),
            dict(old='#define XDEV_EXT_MECH_POOL_PEER 2\n',new='',count=1,
                 reason='symbolic PEER setup uses genuine UAPI pool enum instead of historical external value 2',
                 source_owner='include/uapi/linux/xdev_ext_mech.h'),
            dict(old='#include <linux/xdev_ext_storfam_block.h>',
                 new=requester+'#include <linux/xdev_ext_storfam_block.h>',count=1,
                 reason='complete actual requester before embedding family stage',source_owner='include/linux/xdev_ext_requester.h')])
        self._dependency_projections.append(dict(kind='poll-header-inner-types',records=inner))
        types, types_records = adapt_fixture(types_raw,[dict(old=original,new=current,count=1,
            reason='current-only external native and stage declaration projection',source_owner='selected current source owner')])
        prototypes = []
        for name in ('xdev_ext_requester_bind','xdev_ext_requester_unbind'):
            body = self.definition(Q,name)
            prototypes.append(body[:body.index('{')].rstrip()+';')
        anchor = 'int __wrap_xdev_ext_stor_block_poll_check(bool,struct request*);'
        native, native_records = adapt_fixture(native_raw,[dict(old=anchor,
            new=anchor+'\n'+'\n'.join(prototypes),count=1,
            reason='prototypes derived from actual requester bodies linked by matching utility TU',source_owner=Q)])
        return ((types,types_records),(native,native_records))

    def _native_command_declarations(self):
        """Exact selected command policy and page bounds for each fixture TU."""
        pieces = []
        if 'nvme_xdev_ext_peer_build_cmd(' in self.definition(
                N, 'nvme_xdev_ext_member_encode_dptr', purpose='profile-inspection-only'):
            owner = self._locked_native_owner('include/linux/nvme.h', _API['LOCKED_NVME_OPCODE'])
            pieces.append(self.definition(owner, 'nvme_opcode', 'enum'))
            nvme_header = self.read(I)
            for name in ('NVME_CTRL_PAGE_SHIFT', 'NVME_CTRL_PAGE_SIZE'):
                matches = list(re.finditer(r'^#define ' + name + r'\s+[^\n]+$', nvme_header, re.M))
                if len(matches) != 1:
                    raise ValueError('SETUP actual native page constant count: ' + name)
                match = matches[0]
                pieces.append(self._record(I, name, match.start(), match.end()))
        return pieces

    def declarations(self):
        self.verify()
        if self._declarations is not None:
            return self._declarations
        for native in ('include/linux/nvme_xdev_ext_passthru.h',
                       'include/linux/xdev_ext_storfam_runtime.h',
                       'include/linux/xdev_ext_storfam_core.h'):
            self._portable(native)
        self._validate_portable_declarations()
        prelude = ('#include "include/linux/nvme_xdev_ext_passthru.h"\n'
                   '#include "include/linux/xdev_ext_storfam_runtime.h"\n'
                   '#ifndef __aligned\n#define __aligned(n) __attribute__((aligned(n)))\n#endif\n'
                   'struct request; struct request_queue; struct bio; struct page;\n'
                   'struct block_device;\n'
                   'struct device; struct pci_dev; struct xdev_ext_peer_fd_lease;\n'
                   'struct xdev_ext_mech_stage; struct xdev_ext_mech_stage_uapi;\n'
                   'struct xdev_ext_mech_batch; struct xdev_ext_stor_stage;\n'
                   'struct xdev_ext_stor_io; struct xdev_ext_stor_peer_resources;\n')
        names = ('xdev_ext_stor_poll_view', 'xdev_ext_stor_command',
                 'xdev_ext_stor_geometry', 'xdev_ext_stor_dev_ops',
                 'xdev_ext_stor_io', 'xdev_ext_stor_peer_io',
                 'xdev_ext_stor_stage', 'xdev_ext_stor_batch')
        pieces = [prelude]
        if 'struct xdev_ext_requester requester;' in self.read(H):
            self._portable('include/linux/xdev_ext_requester_core.h')
            pieces += ['#include "include/linux/xdev_ext_requester_core.h"',
                       self.definition('include/linux/xdev_ext_requester.h',
                                       'xdev_ext_requester', 'struct'),
                       self.definition('include/linux/xdev_ext_peer.h',
                                       'xdev_ext_peer_backing', 'struct')]
        pieces += self._native_command_declarations()
        dev_ops = self.definition(H, 'xdev_ext_stor_dev_ops', 'struct')
        if re.search(r'\bhost_path\s*;', dev_ops):
            if len(re.findall(r'^\s*enum xdev_ext_stor_host_path\s+host_path\s*;',
                              dev_ops, re.M)) != 1:
                raise ValueError('SETUP unexpected storage host_path declaration')
            pieces.append(self.definition(H, 'xdev_ext_stor_host_path', 'enum'))
        pieces += [self.definition(H, name, 'struct') for name in names]
        block = self.read(B)
        constant = re.search(r'^#define XDEV_EXT_STOR_PEER_MAX_SPANS[^\n]*', block, re.M)
        if not constant:
            raise ValueError('SETUP missing peer resource bound')
        pieces += [self.definition('include/linux/xdev_ext_peer.h', 'xdev_ext_peer_lease', 'struct'),
                   self.definition('include/linux/xdev_ext_peer.h', 'xdev_ext_peer_fd_lease', 'struct'),
                   self.definition('include/trace/events/xdev_ext.h', 'xdev_ext_native_event', 'struct'),
                   self._record(B, 'XDEV_EXT_STOR_PEER_MAX_SPANS', constant.start(), constant.end()),
                   self.definition(B, 'xdev_ext_stor_peer_resources', 'struct'),
                   self.definition(T, 'nvme_xdev_ext_peer_trace', 'struct')]
        pieces += [self.definition(N, name, 'struct') for name in
                   ('nvme_xdev_ext_mech_stage', 'nvme_xdev_ext_mech_batch',
                    'nvme_xdev_ext_peer_slot')]
        assertions = self._native_assertions()
        if len(assertions) == 0:
            raise ValueError('SETUP missing native ABI assertions')
        pieces += assertions
        pieces.append(self._hook_declarations())
        self.verify()
        self._declarations = '\n\n'.join(pieces) + '\n'
        return self._declarations

    def _native_assertions(self):
        """N's file-scope ABI assertions, verbatim. The window handle flags they
        compare are UAPI macros, recorded verbatim from their header first."""
        native = self.read(N)
        assertions = list(re.finditer(r'^static_assert\([^;]*\);', native, re.M))
        pieces = []
        if any('NVME_XDEV_EXT_WINDOW_F_' in m[0] for m in assertions):
            uapi = 'include/uapi/linux/nvme_ioctl.h'
            header = self.read(uapi)
            for macro in WINDOW_FLAG_MACROS:
                match = re.search(r'^#define ' + macro + r'\b[^\n]*', header, re.M)
                if not match:
                    raise ValueError('SETUP window flag macro missing: ' + macro)
                pieces.append(self._record(uapi, macro, match.start(), match.end()))
        if not assertions:
            return []
        return pieces + [self._record(N, 'static_assert', m.start(), m.end()) for m in assertions]

    def _bounce(self):
        text = self.read(B)
        anchor = '#if !defined(CONFIG_XDEV_EXT_MECH_ZEROCOPY) && defined(CONFIG_XDEV_EXT_MECH_KVM_BOUNCE)\n#define XDEV_EXT_STOR_BOUNCE_AVAILABLE'
        if text.count(anchor) != 1:
            raise ValueError('SETUP bounce region anchor count')
        start = text.index(anchor)
        end_anchor = '#endif /* !XDEV_EXT_STOR_BOUNCE_AVAILABLE */'
        end = text.index(end_anchor, start) + len(end_anchor)
        region = text[start:end]
        # Conditional alternatives are distinct source spans with the same symbol.
        for symbol in ('xdev_ext_storfam_bounce_copy', 'xdev_ext_storfam_bounce',
                       'xdev_ext_storfam_bounce_release'):
            matches = list(re.finditer(r'^static [^;{}]*\b' + symbol +
                                      r'\([^;{}]*\)\s*\{', region, re.M))
            expected = 1 if symbol.endswith('_copy') else 2
            if len(matches) != expected:
                raise ValueError('SETUP bounce alternatives missing: ' + symbol)
            for match in matches:
                lo = start + match.start()
                hi = _balanced(text, text.index('{', lo))
                self._record(B, symbol, lo, hi)
        return region

    def closure(self, group, profile):
        if group not in self.GROUPS or profile not in self.PROFILES:
            raise ValueError('SETUP unsupported legacy closure/profile')
        self.verify()
        if (group, profile) in self._closures:
            return self._closures[group, profile]
        self.declarations()
        items = [(N, 'nvme_xdev_ext_member_decode'),
                 (B, 'xdev_ext_storfam_validate'),
                 (N, 'nvme_xdev_ext_class_validate')]
        extra, bounce = [], ''
        if group != 'validate':
            self._portable('include/linux/xdev_ext_requester_core.h')
            extra.append('#include "include/linux/xdev_ext_requester_core.h"')
            self._portable(P)
            extra.append(self.definition(P, 'xdev_ext_peer_nvme_plan', 'struct'))
            peer_header = self.read(P)
            for macro in ('XDEV_EXT_PEER_NVME_DPTR', 'xdev_ext_peer_nvme_seg'):
                match = re.search(r'^#define ' + macro + r'[^\n]*', peer_header, re.M)
                if not match:
                    raise ValueError('SETUP portable macro missing: ' + macro)
                extra.append(self._record(P, macro, match.start(), match.end()))
            items += [(P, n) for n in ('xdev_ext_peer_nvme_plan',
                                      'xdev_ext_peer_nvme_sgl_build',
                                      'xdev_ext_peer_nvme_prp_build')]
            if 'nvme_xdev_ext_peer_build_cmd(' in self.definition(
                    N, 'nvme_xdev_ext_member_encode_dptr', purpose='profile-inspection-only'):
                items.append(('drivers/nvme/host/core.c', 'nvme_xdev_ext_peer_build_cmd'))
            if 'xdev_ext_stor_leases_retire(' in self.definition(B, 'xdev_ext_storfam_peer_put'):
                items.append((R, 'xdev_ext_stor_leases_retire'))
            items += [(R, n) for n in ('xdev_ext_stor_slot_add', 'xdev_ext_stor_slot_get',
                                      'xdev_ext_stor_slot_put', 'xdev_ext_stor_done')]
            items += [(Q, 'xdev_ext_peer_lease_split'), (I, 'nvme_xdev_ext_capture_identity')]
            items += [(B, n) for n in (
                'xdev_ext_stor_block_caps', 'xdev_ext_stor_block_walk',
                'xdev_ext_stor_block_preflight', 'xdev_ext_stor_block_append',
                'xdev_ext_stor_block_poll_check', 'xdev_ext_stor_block_poll_arm',
                'xdev_ext_storfam_host_get', 'xdev_ext_storfam_host_put',
                'xdev_ext_storfam_peer_io', 'xdev_ext_storfam_peer_get',
                'xdev_ext_storfam_peer_put', 'xdev_ext_storfam_peer_map',
                'xdev_ext_storfam_host_map', 'xdev_ext_storfam_submit_check',
                'xdev_ext_storfam_submit', 'xdev_ext_storfam_host_ready',
                'xdev_ext_storfam_consume')]
            # New family routes still compile their whole real callees, even
            # when these original NVMe cases select the native-request route.
            for caller, callee in (
                    ('xdev_ext_stor_block_append', 'xdev_ext_stor_block_fill'),
                    ('xdev_ext_storfam_submit', 'xdev_ext_storfam_submit_bio')):
                if re.search(r'\b' + re.escape(callee) + r'\s*\(',
                             self.definition(B, caller)):
                    items.append((B, callee))
            items += [(N, n) for n in (
                'nvme_xdev_ext_member_requester', 'nvme_xdev_ext_member_queue',
                'nvme_xdev_ext_member_identity', 'nvme_xdev_ext_member_encode',
                'nvme_xdev_ext_member_encode_dptr', 'nvme_xdev_ext_member_request_init',
                'nvme_xdev_ext_member_post', 'nvme_xdev_ext_member_retire_peer',
                'nvme_xdev_ext_class_complete', 'nvme_xdev_ext_class_end_io',
                'nvme_xdev_ext_peer_complete', 'nvme_xdev_ext_peer_end_io',
                'nvme_xdev_ext_class_submit', 'nvme_xdev_ext_stage_fill_cqe')]
            items += [(T, 'nvme_xdev_ext_peer_trace_release'),
                      (H, 'xdev_ext_stor_block_poll_opf')]
            bounce = self._bounce() if group != 'poll' else ''
            if profile == 'bounce':
                extra.append('#define NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE\n'
                             'static atomic64_t nvme_xdev_ext_mech_bounces;')
        if group in ('pool', 'bind', 'poll'):
            items += [(B, n) for n in ('xdev_ext_storfam_host_resources_free',
                                      'xdev_ext_storfam_host_resources_init')]
        if group == 'pool':
            items.append(('block/blk-mq.c', 'blk_complete_request'))
        if group in ('bind', 'poll'):
            if self.requester_profile():
                self._portable('include/linux/xdev_ext_requester_core.h')
                self.definition('include/linux/xdev_ext_requester_core.h', 'xdev_ext_admit_decide')
                items += [(Q, n) for n in ('xdev_ext_requester_bind', 'xdev_ext_requester_unbind')]
            items += [('drivers/nvme/host/ioctl.c', n) for n in
                      ('nvme_cmd_allowed', 'nvme_xdev_ext_mech_cmd_allowed')]
            items += [(N, n) for n in ('nvme_xdev_ext_class_ns', 'nvme_xdev_ext_member_bind',
                                      'nvme_xdev_ext_member_unbind', 'nvme_xdev_ext_member_poll',
                                      'nvme_xdev_ext_class_bind', 'nvme_xdev_ext_class_unbind',
                                      'nvme_xdev_ext_class_poll', 'nvme_xdev_ext_class_mark_dead')]
            items += [(B, n) for n in ('xdev_ext_stor_block_poll_capable',
                                      'xdev_ext_stor_block_poll',
                                      'xdev_ext_storfam_peer_resources_free',
                                      'xdev_ext_storfam_peer_resources_init',
                                      'xdev_ext_storfam_bind', 'xdev_ext_storfam_unbind',
                                      'xdev_ext_storfam_poll', 'xdev_ext_storfam_mark_dead')]
            extra.append('static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops;')
            if 'nvme_xdev_ext_window_admit(' in self.definition(
                    N, 'nvme_xdev_ext_member_bind', purpose='profile-inspection-only'):
                extra.append(WINDOW_NAMESPACE_FILE)
        if group == 'poll':
            items.append((I,'nvme_req_op'))
        # Select once in this translation unit. poll links the exact separate B TU.
        items = list(dict.fromkeys(items))
        if group == 'poll':
            self.definition(H,'xdev_ext_stor_block_poll_opf')
            items = [(owner, name) for owner, name in items if owner not in (B,H)]
            self.read(B)
        bodies = [self.definition(owner, name) for owner, name in items]
        prototypes = [body[:body.index('{')].rstrip() + ';' for body in bodies]
        if bounce:
            prototypes += [
                'static int xdev_ext_storfam_bounce(struct xdev_ext_stor_stage *, struct xdev_ext_mech_batch *, struct request *, struct xdev_ext_stor_batch *);',
                'static void xdev_ext_storfam_bounce_release(struct xdev_ext_mech_batch *, struct xdev_ext_stor_batch *, bool);']
        code = '\n\n'.join(extra + prototypes + ([bounce] if bounce else []) + bodies)
        if group in ('bind', 'poll'):
            code += '\n' + self.definition(N, 'nvme_xdev_ext_member_ops', 'object')
        elif group in ('submit', 'pool'):
            initializer = self.definition(N, 'nvme_xdev_ext_member_ops', 'object')
            fields = ('identity', 'requester', 'queue', 'decode', 'encode', 'encode_dptr',
                      'request_init', 'post', 'retire_peer', 'peer_slot_bytes', 'peer_native_offset')
            selected_fields = []
            for field in fields:
                matches = re.findall(r'^\s*\.' + field + r' = [^\n]+,$', initializer, re.M)
                if len(matches) != 1:
                    raise ValueError('SETUP member initializer field missing: ' + field)
                selected_fields.append(matches[0])
            code += '\nstatic const struct xdev_ext_stor_dev_ops fixture_member_ops = {\n' + '\n'.join(selected_fields) + '\n};\n'
        self.verify()
        self._closures[group, profile] = code + '\n'
        return self._closures[group, profile]

    def report(self):
        self.verify()
        return {'root': str(self.root), 'inputs': sorted(self._selection.inputs),
                'definitions': list(self._definitions.values()),
                'source_facts': list(self._source_facts.values()),
                'dependency_projections':list(self._dependency_projections),
                'common_observers':list(self._common_observers)}

    def headers(self, output):
        """Only dependencies actually selected by this private assembly."""
        output=Path(output)
        self.verify()
        for native,value in tuple(self._bytes.items()):
            if native.endswith('.h'):
                target=output/native
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(value)
        return output

    def poll_declarations(self):
        self.declarations()
        pieces=self._native_command_declarations()+[
                self.definition('include/trace/events/xdev_ext.h','xdev_ext_native_event','struct'),
                self.definition(B,'xdev_ext_stor_peer_resources','struct'),
                self.definition(T,'nvme_xdev_ext_peer_trace','struct')]
        pieces += [self.definition(N,n,'struct') for n in
                   ('nvme_xdev_ext_mech_stage','nvme_xdev_ext_mech_batch','nvme_xdev_ext_peer_slot')]
        pieces += self._native_assertions()
        pieces.append(self._hook_declarations())
        return '\n\n'.join(pieces)+'\n'

    def poll_common_source(self):
        """The whole B TU, with observers placed between complete definitions."""
        source=self.read(B)
        original=source
        insertions=[]
        observers={
            'xdev_ext_storfam_host_get': '#define xdev_ext_storfam_host_get(ss,sb) (fixture_before_slot(false,ss,sb), fixture_slot_result((xdev_ext_storfam_host_get)(ss,sb)))',
            'xdev_ext_storfam_peer_get': '#define xdev_ext_storfam_peer_get(ss,sb) (fixture_before_slot(true,ss,sb), fixture_slot_result((xdev_ext_storfam_peer_get)(ss,sb)))',
            'xdev_ext_storfam_host_put': '#define xdev_ext_storfam_host_put(ss,sb) (fixture_before_put(false,ss,sb), (xdev_ext_storfam_host_put)(ss,sb))',
            'xdev_ext_storfam_peer_put': '#define xdev_ext_storfam_peer_put(ss,sb) (fixture_before_put(true,ss,sb), (xdev_ext_storfam_peer_put)(ss,sb))',
            'xdev_ext_storfam_host_map': '#define xdev_ext_storfam_host_map(ss,b,r,sb) (fixture_before_map(false), (xdev_ext_storfam_host_map)(ss,b,r,sb))',
            'xdev_ext_storfam_peer_map': '#define xdev_ext_storfam_peer_map(ss,b,io,n) (fixture_before_map(true), (xdev_ext_storfam_peer_map)(ss,b,io,n))',
            'xdev_ext_stor_block_poll_check': '#define xdev_ext_stor_block_poll_check(p,r) __wrap_xdev_ext_stor_block_poll_check(p,r)',
        }
        for symbol,observer in observers.items():
            body=self.definition(B,symbol)
            if source.count(body)!=1:
                raise ValueError('SETUP common observer placement count: '+symbol)
            insertions.append((source.index(body)+len(body),'\n'+observer+'\n'))
        # Record every complete common body, including both guarded alternatives.
        for match in re.finditer(r'^[A-Za-z_][^;{}]*\b(xdev_ext_\w+)\([^;{}]*\)\s*\{',source,re.M):
            end=_balanced(source,source.index('{',match.start()))
            self._record(B,match.group(1),match.start(),end)
        records=[];shift=0
        for position,addition in sorted(insertions):
            target=position+shift
            source=source[:target]+addition+source[target:]
            records.append(dict(native=B,offset=target,new=addition,
                reason='observer inserted after complete actual body; body is unchanged'))
            shift+=len(addition)
        restored=source
        for record in reversed(records):
            start=record['offset'];addition=record['new']
            if restored[start:start+len(addition)]!=addition:
                raise ValueError('SETUP common observer inverse mismatch')
            restored=restored[:start]+restored[start+len(addition):]
        if restored!=original:
            raise ValueError('SETUP common observer inverse changed production bytes')
        self._common_observers=records
        return source


# The external command boundary mirrors Linux's 64-byte command ABI. All
# command contents are still set/read by the selected production functions.
COMMAND_BOUNDARY = r'''
struct nvme_sgl_desc { u64 addr; u32 length; u8 reserved[3], type; };
struct nvme_command {
 union {
  struct { u8 opcode,flags; u16 command_id; u32 nsid; u64 rsvd2,metadata;
   union { struct nvme_sgl_desc sgl; struct { u64 prp1,prp2; }; } dptr;
   u64 slba; u16 length,control; u32 dsmgmt,reftag; u16 apptag,appmask; } rw;
  struct { u8 opcode,flags; u16 command_id; u32 nsid; u32 cdw2[2]; u64 metadata;
   union { struct nvme_sgl_desc sgl; struct { u64 prp1,prp2; }; } dptr;
   u32 cdw10,cdw11,cdw12,cdw13,cdw14,cdw15; } common;
  struct { u8 opcode,flags; u16 command_id; u32 nsid; u32 cdw2[2]; u64 metadata;
   u64 prp1,prp2; u8 cns; u8 reserved[23]; } identify;
  u8 bytes[64];
 };
} __attribute__((aligned(8)));
#ifndef static_assert
#define static_assert _Static_assert
#endif
'''


def selected_source(root, source_file=None):
    """Validate a file selector before reading any selected dependencies."""
    selected = LegacySelection(root)
    if source_file is not None:
        actual = Path(source_file).resolve(strict=True)
        expected = selected._selection.file(N).resolve(strict=True)
        if actual != expected:
            raise ValueError('SETUP source file does not belong to selected dependency root')
    return selected


HOST_TYPES = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include "include/linux/nvme_xdev_ext_passthru.h"
#include "include/linux/xdev_ext_storfam_runtime.h"
typedef __u8 u8; typedef __u16 u16; typedef __u32 u32; typedef __u64 u64;
typedef int atomic_t; typedef long long atomic64_t; typedef u64 dma_addr_t;
typedef int blk_status_t; typedef u64 sector_t;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define ERR_CAST(p) ((void *)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PAGE_SHIFT 12
#define PAGE_SIZE (1U<<PAGE_SHIFT)
#define BIO_MAX_INLINE_VECS 256
#define SECTOR_SHIFT 9
#define SZ_4K 4096U
#define GFP_KERNEL 0
#define BLK_MQ_REQ_NOWAIT 1
#define NVME_REQ_USERCMD 1
#define NVME_REQ_XDEV_EXT_ZC 2
#define NVME_REQ_CANCELLED 4
#define NVME_REQ_XDEV_EXT_PEER 32
#define NVME_CMD_SGL_METABUF 0x40
#define NVME_SGL_FMT_DATA_DESC 0
#define NVME_SGL_FMT_LAST_SEG_DESC 3
#define NVME_CTRL_LIVE 1
#define NVME_NS_READY 0
#define NVME_NS_REMOVING 1
#define REQ_FAILFAST_MASK 0x700U
#define REQ_OP_READ 0
#define REQ_OP_WRITE 1U
#define REQ_OP_DRV_IN 34U
#define REQ_OP_DRV_OUT 35U
#define REQ_POLLED (1U<<21)
#define atomic_read(p) (*(p))
#define atomic_set(p,v) (*(p)=(v))
#define atomic64_inc(p) (++*(p))
#define pr_warn_once(...) ((void)0)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define WARN_ON_ONCE(x) (!!(x))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(t,a,b) ((t)min(a,b))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define offset_in_page(x) ((x)&(PAGE_SIZE-1))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
typedef unsigned blk_opf_t;
struct page { u8 data[PAGE_SIZE]; };
/* Linux block-layer fields used by the real ordinary-BIO callee. Original
 * NVMe fixture counters and services remain unchanged. */
struct bio { unsigned bi_inline_vecs[256], used, capacity, bytes; struct bio *bi_next;
 struct { sector_t bi_sector; unsigned bi_size; } bi_iter; };
struct blk_mq_hw_ctx { unsigned type,queue_num; };
struct blk_mq_queue_map { unsigned nr_queues; };
struct blk_mq_tag_set { unsigned nr_maps; struct blk_mq_queue_map *map; };
struct request_queue { struct { unsigned features; } limits; struct blk_mq_tag_set *tag_set; };
#define BLK_FEAT_POLL 1U
#define HCTX_TYPE_POLL 2
struct file { unsigned f_mode; };
struct device { bool is_pci; };
struct pci_dev { struct device dev; };
#define dev_is_pci(d) ((d)->is_pci)
#define to_pci_dev(d) ((struct pci_dev *)(d))
struct nvme_ctrl_ops { const char *name; void *peer_rw; };
struct nvme_ctrl { struct nvme_ctrl_ops *ops; struct device *dev; int state; };
struct nvme_ns_head { u32 ns_id; u8 lba_shift,pi_type; u16 ms,pi_size;
 struct { u8 csi,eui64[8],nguid[16],uuid[16]; } ids; };
struct gendisk { u64 capacity,diskseq; bool ro; };
struct nvme_ns { struct request_queue *queue; struct nvme_ctrl *ctrl;
 struct nvme_ns_head *head; struct gendisk *disk; unsigned long flags; };
'''

HOST_OS = r'''
unsigned long queue_virt_boundary(struct request_queue *q) { (void)q; return 0; }
#define blk_lim_dma_alignment_and_pad(l) ((void)(l),0U)
u32 queue_max_segments(struct request_queue *q) { (void)q; return 256; }
u32 queue_max_segment_size(struct request_queue *q) { (void)q; return 1U<<20; }
u32 queue_max_hw_sectors(struct request_queue *q) { (void)q; return 2048; }
sector_t get_capacity(struct gendisk *d) { return d->capacity; }
bool get_disk_ro(struct gendisk *d) { return d->ro; }
bool test_bit(unsigned bit,const unsigned long *p) { return !!(*p&(1UL<<bit)); }
int nvme_ctrl_state(struct nvme_ctrl *c) { return c->state; }
bool nvme_ctrl_sgl_supported(struct nvme_ctrl *c) { (void)c; return true; }
int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 gen,u64 off,u32 len,
 enum dma_data_direction dir,struct xdev_ext_peer_fd_lease *lease)
{ (void)f;(void)p;(void)gen;(void)off;(void)len;(void)dir;(void)lease;abort(); }
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *l,bool q)
{ (void)l;(void)q;abort(); }
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p)
{ (void)p;abort(); }
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p)
{ (void)p;abort(); }
bool trace_native_event_enabled(void) { return false; }
void trace_native_event(const struct xdev_ext_native_event *e) { (void)e;abort(); }
void memcpy_to_page(struct page *p,u32 off,const void *src,u32 len)
{ assert(off+len<=PAGE_SIZE);memcpy(p->data+off,src,len); }
void memcpy_from_page(void *dst,struct page *p,u32 off,u32 len)
{ assert(off+len<=PAGE_SIZE);memcpy(dst,p->data+off,len); }
'''

NOWAIT_OS = r'''
enum rq_end_io_ret { RQ_END_IO_FREE };
struct request {
 struct { unsigned flags; unsigned short status; union { u64 u64; } result;
  struct nvme_command *cmd; struct nvme_xdev_ext_peer_trace *peer_trace; } nvme;
 struct blk_mq_hw_ctx *mq_hctx; unsigned cmd_flags,residual; struct bio *bio;
 enum rq_end_io_ret (*end_io)(struct request *,blk_status_t); void *end_io_data;
};
#define nvme_req(r) (&(r)->nvme)
struct xdev_ext_mech_pool { unsigned kind,frame_size; struct page page; };
struct xdev_ext_mech_stage { struct nvme_xdev_ext_mech_stage *priv; void *s; bool poll; unsigned direction; };
struct xdev_ext_mech_batch { struct nvme_xdev_ext_mech_batch priv; bool claimed; };
struct xdev_ext_mech_frame { void *kaddr; u64 umem_addr; u32 index,data_off,data_len; void *pool_priv; };
#define XDEV_EXT_MECH_POOL_PEER 3
static struct xdev_ext_mech_pool host_pool={.kind=2,.frame_size=4096};
static const char *mode;
static unsigned alloc_flags;
static int tag_calls,simulated_block,done_allocs,maps,handoffs,completions;
static struct request native_request;
struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(void *s) { (void)s;return &host_pool; }
const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(void *s)
{ static const struct xdev_ext_mech_layout l={.group_bytes=4096};(void)s;return &l; }
u32 xdev_ext_mech_session_state(void *s) { (void)s;return 0; }
void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { return &b->priv; }
u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { (void)b;return 4096; }
u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { (void)b;return 1; }
u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { (void)b;return 7; }
u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { (void)b;return 0x100000001ULL; }
struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch *b) { (void)b;abort(); }
int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *f)
{ (void)b;if(pos)return -ERANGE;*f=(struct xdev_ext_mech_frame){.kaddr=host_pool.page.data,.data_len=4096};return 0; }
struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *page_off,u32 *len)
{ (void)f;*page_off=off%PAGE_SIZE;*len=PAGE_SIZE-*page_off;return &p->page; }
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket)
{ if(ticket!=0x100000001ULL||b->claimed)return -ESTALE;b->claimed=true;return 0; }
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool uncertain)
{ (void)b;assert(ticket==0x100000001ULL);assert(!status&&!uncertain); }
void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b,u64 cookie,u64 lba,u32 bytes,u32 plan)
{ (void)b;(void)cookie;(void)lba;(void)bytes;(void)plan; }
void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status)
{ (void)b;(void)ticket;(void)status; }
void xdev_ext_mech_trace_plan(struct xdev_ext_mech_batch *b,u64 lba,u32 bytes,u32 plan,int status)
{ (void)b;(void)lba;(void)bytes;(void)plan;(void)status; }
void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int ret) { (void)st;(void)ret;abort(); }
struct request *blk_mq_alloc_request(void *queue,int op,unsigned flags)
{ (void)queue;tag_calls++;alloc_flags=flags;native_request.cmd_flags=op;
 if(!strcmp(mode,"full")){if(flags&BLK_MQ_REQ_NOWAIT)return ERR_PTR(-EWOULDBLOCK);simulated_block++;return ERR_PTR(-ETIMEDOUT);}
 if (!strcmp(mode, "nodev")) {
  return ERR_PTR(-ENODEV);
 }
 return &native_request;
}
void nvme_init_request(struct request *r,struct nvme_command *cmd) { r->nvme.cmd=cmd; }
void blk_mq_free_request(struct request *r) { (void)r; }
bool blk_rq_is_poll(struct request *r) { (void)r;abort(); }
u32 blk_rq_bytes(struct request *r) { return r->residual; }
int blk_status_to_errno(int e) { return e?-EIO:0; }
void bio_init(struct bio *b,void *dev,void *vecs,unsigned n,unsigned flags)
{ (void)dev;(void)vecs;(void)flags;b->used=b->bytes=0;b->capacity=n; }
void bio_uninit(struct bio *b) { b->used=0; }
unsigned bio_add_page(struct bio *b,struct page *p,unsigned len,unsigned off)
{ (void)p;(void)off;if(b->used==b->capacity)return 0;b->used++;b->bytes+=len;return len; }
int blk_rq_append_bio(struct request *r,struct bio *b) { maps++;r->bio=b;return 0; }
void blk_execute_rq_nowait(struct request *r,bool at_head)
{ (void)at_head;handoffs++;completions++;r->end_io(r,0); }
'''


def nowait_fixture(selected, raw):
    main_start = raw.index('int main(int argc, char **argv)')
    prefix = raw[:main_start]
    production = selected.closure('submit', 'strict')
    init = r'''
static void fixture_worker_init(struct nvme_xdev_ext_mech_stage *p,struct xdev_ext_mech_stage *st)
{
 static struct nvme_ns_head head={.ns_id=7,.lba_shift=9};
 static struct gendisk disk={.capacity=32,.diskseq=1};
 static struct request_queue q; static struct bio bio; static struct xdev_ext_stor_io io;
 p->ns->head=&head;p->ns->disk=&disk;p->ns->queue=&q;p->ns->flags=1;
 p->family.st=st;p->family.dev=&fixture_member_ops;p->family.member=p;
 p->family.geometry=(struct xdev_ext_stor_geometry){.capacity_lbas=32,.lba_shift=9};
 p->family.slots=&io;p->family.nr_slots=1;p->family.nr_vecs=1;io.bio=&bio;
 xdev_ext_stor_slot_add(&p->family.pool,&io.runtime);
 if(nvme_xdev_ext_capture_identity(p->ns,&p->identity,&p->head,&p->disk,&p->queue))abort();
}
static void *const fixture_reached[] __attribute__((used)) = {
 (void *)nvme_xdev_ext_stage_fill_cqe,
 (void *)xdev_ext_storfam_peer_io,
};
'''
    new_prefix = ('#define FIXTURE_MEMBER_FAMILY 1\n' + HOST_TYPES + COMMAND_BOUNDARY +
                  selected.declarations() + NOWAIT_OS + HOST_OS + production + init)
    return adapt_fixture(raw, [dict(old=prefix, new=new_prefix, count=1,
        reason='replace obsolete native OS boundary with complete current external objects; whole owners follow',
        source_owner='external OS boundary and selected whole-owner closure')])


def pool_fixture(selected, raw, profile):
    edits = []
    def edit(old, new, count=1, reason='external OS object or embedded family lvalue'):
        edits.append(dict(old=old,new=new,count=count,reason=reason,source_owner='public pool fixture OS boundary'))
    prefix = raw[:raw.index('#define XDEV_EXT_MECH_POOL_PEER 3')]
    edit(prefix, HOST_TYPES + COMMAND_BOUNDARY + selected.declarations())
    edit('unsigned int kind; };', 'unsigned int kind,frame_size; };')
    edit('bool poll; };', 'bool poll; unsigned direction; };')
    edit('static struct nvme_xdev_ext_mech_batch *xdev_ext_mech_batch_priv(',
         'static void *xdev_ext_mech_batch_priv(',
         reason='external accessor uses actual void-pointer ABI; native batch retains common prefix')
    edit('struct { unsigned int flags; unsigned short status; struct { u64 u64; } result; } nvme;',
         'struct { unsigned int flags; unsigned short status; struct { u64 u64; } result; struct nvme_command *cmd; struct nvme_xdev_ext_peer_trace *peer_trace; } nvme;')
    edit('/* Host-page pool tests must never execute the separately tested GPU branch. */',
         '#define nvme_req(r) (&(r)->nvme)\n/* Host-page pool tests must never execute the separately tested GPU branch. */')
    caps_start = raw.index('static struct nvme_xdev_ext_queue_caps nvme_xdev_ext_class_caps(')
    caps_end = raw.index('/* External block-layer services only;',caps_start)
    edit(raw[caps_start:caps_end], '')
    edit('static int nvme_req_op(struct nvme_command *cmd) { (void)cmd;return 0; }\n','')
    edit('static void nvme_init_request(struct request *req,struct nvme_command *cmd) { (void)req;(void)cmd; }',
         'static void nvme_init_request(struct request *req,struct nvme_command *cmd) { req->nvme.cmd=cmd; }')
    edit('static const char *mode;', 'static struct xdev_ext_mech_stage *fixture_active_stage;\nstatic const char *mode;')
    edit('.index=pos,.data_off=384,.data_len=512',
         '.kaddr=fixture_active_stage->s->pool.pages[pos].data,.index=pos,.data_off=384,.data_len=512')
    edit('/* BLOCK_BATCH_COMPLETION */','static void blk_complete_request(struct request *req);')
    # These are external page bytes and stage facts; copy/ready/release remain actual.
    setup = r'''
static struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch *b)
{ (void)b;return fixture_active_stage; }
'''
    init = r'''
static void fixture_worker_init(struct nvme_xdev_ext_mech_stage *p,struct xdev_ext_mech_stage *st)
{
 static struct nvme_ns_head head={.ns_id=7,.lba_shift=9};
 static struct gendisk disk={.capacity=32,.diskseq=1};static struct request_queue q;
 fixture_active_stage=st;st->direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;st->s->pool.frame_size=4096;
 p->ns->head=&head;p->ns->disk=&disk;p->ns->queue=&q;p->ns->flags=1;
 p->family.st=st;p->family.dev=&fixture_member_ops;p->family.member=p;
 p->family.geometry=(struct xdev_ext_stor_geometry){.capacity_lbas=32,.lba_shift=9};
 if(nvme_xdev_ext_capture_identity(p->ns,&p->identity,&p->head,&p->disk,&p->queue))abort();
}
'''
    edit('/* PRODUCTION_FUNCTIONS */',HOST_OS+setup+selected.closure('pool',profile)+init)
    edit('/* POOL_INIT */','rc = xdev_ext_storfam_host_resources_init(&p.family);')
    edit('/* POOL_COUNT */','for(i=0;i<p.family.nr_slots;i++)retained+=p.family.slots[i].runtime.busy;')
    edit('/* POOL_FREE */','xdev_ext_storfam_host_resources_free(&p.family);')
    edit('nvme_xdev_ext_class_fill_cqe(', 'nvme_xdev_ext_stage_fill_cqe(', 3,
         'actual worker completion consumer owner')
    return adapt_fixture(raw, edits)


def _fixture_function(raw, name):
    matches = list(re.finditer(r'^static [^;{}]*\b' + re.escape(name) +
                              r'\([^;{}]*\)\s*\{', raw, re.M))
    if len(matches) != 1:
        raise ValueError('SETUP obsolete fixture definition count: ' + name)
    match = matches[0]
    return raw[match.start():_balanced(raw,raw.index('{',match.start()))]


BIND_OS = r'''
#define kzalloc(n,f) ((void)(f),calloc(1,n))
#define kfree free
#define kvfree free
void *kcalloc(size_t n,size_t size,int flags) { (void)flags;return calloc(n,size); }
void *kvcalloc(size_t n,size_t size,int flags) { (void)flags;return calloc(n,size); }
void *dma_alloc_coherent(struct device *dev,size_t bytes,dma_addr_t *dma,int flags)
{ (void)dev;(void)flags;void *p=calloc(1,bytes);*dma=(uintptr_t)p;return p; }
void dma_free_coherent(struct device *dev,size_t bytes,void *cpu,dma_addr_t dma)
{ (void)dev;(void)bytes;assert((uintptr_t)cpu==dma);free(cpu); }
struct bio *bio_kmalloc(u16 n,int flags) { (void)n;(void)flags;abort(); }
void bio_uninit(struct bio *bio) { (void)bio;abort(); }
void bio_init(struct bio *bio,void *d,void *v,unsigned n,unsigned op)
{ (void)bio;(void)d;(void)v;(void)n;(void)op;abort(); }
unsigned bio_add_page(struct bio *bio,struct page *p,unsigned len,unsigned off)
{ (void)bio;(void)p;(void)len;(void)off;abort(); }
int blk_rq_append_bio(struct request *r,struct bio *b) { (void)r;(void)b;abort(); }
struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *len)
{ (void)p;(void)f;(void)off;(void)po;(void)len;abort(); }
u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { (void)b;abort(); }
int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *f)
{ (void)b;(void)pos;(void)f;abort(); }
void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { (void)b;abort(); }
u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { (void)b;abort(); }
u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { (void)b;abort(); }
u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s) { return s->depth; }
u32 xdev_ext_mech_session_state(struct xdev_ext_mech_session *s) { (void)s;return 0; }
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 t) { (void)b;(void)t;abort(); }
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 t,int e,bool u)
{ (void)b;(void)t;(void)e;(void)u;abort(); }
void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 t,int e)
{ (void)b;(void)t;(void)e;abort(); }
void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b,u64 c,u64 l,u32 n,u32 p)
{ (void)b;(void)c;(void)l;(void)n;(void)p;abort(); }
struct request *blk_mq_alloc_request(struct request_queue *q,blk_opf_t op,unsigned flags)
{ (void)q;(void)op;(void)flags;abort(); }
void blk_mq_free_request(struct request *r) { (void)r;abort(); }
bool blk_rq_is_poll(struct request *r) { (void)r;abort(); }
void nvme_init_request(struct request *r,struct nvme_command *c) { (void)r;(void)c;abort(); }
void blk_execute_rq_nowait(struct request *r,bool head) { (void)r;(void)head;abort(); }
u32 blk_rq_bytes(struct request *r) { return r->bytes; }
int blk_status_to_errno(int e) { return e; }
struct inode { void *i_cdev; };
int nvme_ns_chr_uring_cmd(void) { abort(); }
static const struct file_operations fixture_fops={.uring_cmd=nvme_ns_chr_uring_cmd};
struct inode *file_inode(struct file *file)
{ static struct inode inode;(void)file;inode.i_cdev=&ns.cdev;return &inode; }
'''

# Explicit dependency responses, not provider policy/cache/region execution.
# Admission, authority capture and requester binding remain the real bodies.
REQUESTER_DEPENDENCY_FACTS = r'''
struct fixture_requester_dependency_facts {
 struct pci_dev *owner;
 u32 backing;
 int distance, describe_error, premap_error, domain;
 bool bounce, dma_iommu, dma_ops;
};
static struct pci_dev fixture_backing_owner={.dev={.is_pci=true}};
static struct fixture_requester_dependency_facts fixture_requester_dependencies = {
 .owner=&fixture_backing_owner,
 .backing=XDEV_EXT_PEER_BACKING_MMIO_BAR|XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR,
 .distance=0,
};
static unsigned fixture_pci_references;
static struct pci_dev *pci_dev_get(struct pci_dev *p)
{ assert(p && fixture_pci_references<64);fixture_pci_references++;return p; }
static void pci_dev_put(struct pci_dev *p)
{ assert(p && fixture_pci_references);fixture_pci_references--; }
static int pci_domain_nr(struct pci_bus *bus)
{ assert(bus);return fixture_requester_dependencies.domain; }
static int pci_p2pdma_distance(struct pci_dev *owner,struct device *client,bool verbose)
{ assert(owner==fixture_requester_dependencies.owner && client && verbose);return fixture_requester_dependencies.distance; }
static bool is_swiotlb_force_bounce(struct device *dev)
{ assert(dev);return fixture_requester_dependencies.bounce; }
static bool use_dma_iommu(struct device *dev)
{ assert(dev);return fixture_requester_dependencies.dma_iommu; }
struct dma_map_ops;
static const struct dma_map_ops *get_dma_ops(struct device *dev)
{ static char identity;assert(dev);return fixture_requester_dependencies.dma_ops?(const void *)&identity:NULL; }
int xdev_ext_peer_file_describe(struct file *authority,struct pci_dev *requester,struct xdev_ext_peer_backing *out)
{
 assert(authority && requester && out);
 if(fixture_requester_dependencies.describe_error)return fixture_requester_dependencies.describe_error;
 *out=(struct xdev_ext_peer_backing){.owner=fixture_requester_dependencies.owner,.flags=fixture_requester_dependencies.backing};
 return 0;
}
int xdev_ext_peer_file_premap(struct file *authority,struct pci_dev *requester)
{ assert(authority && requester);return fixture_requester_dependencies.premap_error; }
'''

REQUESTER_BIND_AUTHORITY = r'''
static struct file fixture_allocation_authority;
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *pool)
{ assert(pool->kind==XDEV_EXT_MECH_POOL_PEER);return &fixture_allocation_authority; }
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *pool)
{ assert(pool->kind==XDEV_EXT_MECH_POOL_PEER);return 1; }
'''


def _preserve_legacy_vendor_inputs(raw, edit):
    """Keep concrete old 0xc0 test inputs separate from the real native enum."""
    lines = [line for line in raw.splitlines(keepends=True)
             if re.search(r'\bnvme_cmd_vendor_start\b', line) and
             not line.startswith('#define nvme_cmd_vendor_start ')]
    for line in dict.fromkeys(lines):
        edit(line, re.sub(r'\bnvme_cmd_vendor_start\b', '0xc0', line), raw.count(line),
             reason='preserve original concrete vendor test input while actual policy uses genuine enum')


def bind_fixture(selected, raw):
    prefix = raw[:raw.index('static struct nvme_ops ops=')]
    policy = raw[raw.index('#define CAP_SYS_RAWIO'):raw.index('struct nvme_command {')]
    types = HOST_TYPES.replace('struct file { unsigned f_mode; };',
        'struct file_operations { int (*uring_cmd)(void); };\nstruct file { unsigned f_mode; bool native_ns; const struct file_operations *f_op; };')
    types = types.replace('void *peer_rw;', 'bool peer_rw;')
    types = types.replace('unsigned long flags; };', 'unsigned long flags; void *cdev; };')
    requester = selected.requester_profile()
    if requester:
        types = selected.requester_type_projection(types)
        policy = selected.opcode_boundary_projection(policy)
    boundary = r'''
enum rq_end_io_ret { RQ_END_IO_FREE };
struct request { struct blk_mq_hw_ctx *mq_hctx; unsigned cmd_flags,bytes;
 struct bio *bio; enum rq_end_io_ret (*end_io)(struct request *,blk_status_t); void *end_io_data;
 struct { unsigned flags; u16 status; union {u64 u64;} result; struct nvme_command *cmd; struct nvme_xdev_ext_peer_trace *peer_trace; } nvme; };
#define nvme_req(r) (&(r)->nvme)
struct xdev_ext_mech_pool { unsigned kind,frame_size; };
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout; struct xdev_ext_mech_pool pool; unsigned depth; };
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct file *file; unsigned direction; bool poll; unsigned arg0,arg1; void *priv; };
struct xdev_ext_mech_batch { void *priv; };
struct xdev_ext_mech_frame { void *kaddr;u64 umem_addr;u32 index,data_off,data_len;void *pool_priv; };
'''
    if requester:
        old_stage = 'struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct file *file; unsigned direction; bool poll; unsigned arg0,arg1; void *priv; };'
        boundary, records = adapt_fixture(boundary,[dict(old=old_stage,new=selected.requester_stage(),count=1,
            reason='whole actual stage caps and reporting declaration; old zeroed fixtures stay nonreporting',
            source_owner='include/linux/xdev_ext_mech.h')])
        selected._dependency_projections.append(dict(kind='bind-stage-type',records=records))
    code = selected.closure('bind','strict')
    observer = selected.definition(B,'xdev_ext_storfam_host_resources_init')
    if code.count(observer) != 1:
        raise ValueError('SETUP resource observer placement count')
    code = code.replace(observer,observer+'\n#define xdev_ext_storfam_host_resources_init(p) (resources++, (xdev_ext_storfam_host_resources_init)(p))\n',1)
    capture = selected.definition(I,'nvme_xdev_ext_capture_identity')
    if code.count(capture) != 1:
        raise ValueError('SETUP capture observer placement count')
    code = code.replace(capture,capture+'\n#define nvme_xdev_ext_capture_identity(n,...) (fixture_capture_observe(n), (nvme_xdev_ext_capture_identity)(n,__VA_ARGS__))\n',1)
    code = '#define nvme_xdev_ext_mech_bind_identity(i,w,bytes) (fixture_bind_observe(i,bytes), (nvme_xdev_ext_mech_bind_identity)(i,w,bytes))\n'+code
    edits = [dict(old=prefix,new=types+COMMAND_BOUNDARY+policy+selected.declarations()+boundary,count=1,
                  reason='complete external native objects and actual declarations',source_owner='external bind boundary')]
    def edit(old,new,count=1,reason='external bind object boundary'):
        edits.append(dict(old=old,new=new,count=count,reason=reason,source_owner='public bind fixture'))
    edit('static struct nvme_ops ops=', 'static struct nvme_ctrl_ops ops=')
    for name in ('nvme_xdev_ext_class_ns','xdev_ext_stor_block_poll_capable','bio_uninit',
                 'dma_free_coherent','nvme_xdev_ext_class_resources_init','nvme_xdev_ext_peer_resources_init'):
        edit(_fixture_function(raw,name),'')
    edit('#define WARN_ON_ONCE(v) (v)\n','')
    # Define the external file/inode facts before compiling the actual class_ns.
    host_os = HOST_OS
    if requester:
        old_authority = ('struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p)\n'
                         '{ (void)p;abort(); }\n'
                         'u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p)\n'
                         '{ (void)p;abort(); }')
        host_os, records = adapt_fixture(host_os,[dict(old=old_authority,new=REQUESTER_BIND_AUTHORITY,count=1,
            reason='explicit external allocation authority/generation facts, real requester captures them',
            source_owner='public bind fixture dependency boundary')])
        selected._dependency_projections.append(dict(kind='bind-authority-facts',records=records))
    requester_deps = REQUESTER_DEPENDENCY_FACTS if requester else ''
    edit('/* PRODUCTION */', host_os+BIND_OS+requester_deps+code)
    edit('struct file f={FMODE_READ,true};','struct file f={.f_mode=FMODE_READ,.native_ns=true};')
    edit('int rc=nvme_xdev_ext_class_bind(st,u);',
         'static struct pci_dev pci={.dev={.is_pci=true}}; st->file->f_op=st->file->native_ns?&fixture_fops:NULL; ctrl.dev=&pci.dev; ctrl.state=NVME_CTRL_LIVE; st->s->depth=1; st->s->layout.seg_len=4096; st->s->layout.frame_size=4096; st->s->pool.frame_size=4096; int rc=nvme_xdev_ext_class_bind(st,u);')
    edit('free(st->priv); st->priv=NULL;',
         'struct nvme_xdev_ext_mech_stage *member=st->priv; assert(xdev_ext_storfam_unbind(&member->family)); free(st->priv); st->priv=NULL;',
         reason='actual successful resource cleanup before original member free')
    if requester:
        _preserve_legacy_vendor_inputs(raw[len(prefix):], edit)
    return adapt_fixture(raw,edits),code


POLL_OS = r'''
static void no_work(void);
#define CAP_SYS_ADMIN 21
#define NVME_IOCTL_PARTITION 2
#define NVME_CMD_EFFECTS_CSUPP 1
#define NVME_CMD_EFFECTS_LBCC 2
#define NVME_CMD_EFFECTS_UUID_SEL 4
#define NVME_CMD_EFFECTS_SCOPE_MASK 8
#define nvme_cmd_write 1
#define nvme_cmd_read 2
#define nvme_cmd_vendor_start 0xc0
#define nvme_fabrics_command 0x7f
#define nvme_admin_identify 6
#define NVME_ID_CNS_NS 0
#define NVME_ID_CNS_CS_NS 1
#define NVME_ID_CNS_NS_CS_INDEP 2
#define NVME_ID_CNS_CS_CTRL 3
#define NVME_ID_CNS_CTRL 4
static bool capable(int cap){(void)cap;return false;}
static unsigned nvme_command_effects(struct nvme_ctrl *c,struct nvme_ns *n,unsigned opcode)
{(void)c;(void)n;(void)opcode;event(ALLOW);return allowed?NVME_CMD_EFFECTS_CSUPP:0;}
static bool nvme_is_write(struct nvme_command *cmd){return cmd->common.opcode==1;}
struct inode {void *i_cdev;};
static int nvme_ns_chr_uring_cmd(void){abort();}
static const struct file_operations fixture_fops={.uring_cmd=nvme_ns_chr_uring_cmd};
static struct inode *file_inode(struct file *f)
{static struct inode inode;event(NS);EQ("namespace-file",f==&file,1);inode.i_cdev=&ns.cdev;return &inode;}
static struct pci_dev fixture_pci={.dev={.is_pci=true}};
static struct bio fixture_bio;
static struct page fixture_page;
static struct xdev_ext_peer_fd_lease fixture_leases[2];
static u64 fixture_list[512];
static void fixture_bind_facts(void)
{file.f_op=namespace_present?&fixture_fops:NULL;ctrl.dev=&fixture_pci.dev;session.depth=1;session.layout.seg_len=512;session.layout.frame_size=4096;session.pool.frame_size=4096;}
static void fixture_reset_resources(bool peer)
{
 fixture_bind_facts();queue.segments=4;queue.segment_size=PAGE_SIZE;memset(&fixture_bio,0,sizeof(fixture_bio));memset(fixture_leases,0,sizeof(fixture_leases));
 member.family.window=(struct xdev_ext_stor_window){.slba=0,.nlb=4096,.capacity_lbas=4096,.lba_shift=9};
 member.family.geometry=(struct xdev_ext_stor_geometry){.capacity_lbas=4096,.lba_shift=9};
 member.family.slots=&host_slot;member.family.nr_slots=1;member.family.nr_vecs=4;host_slot.bio=&fixture_bio;
 member.family.peer=&peer_res;peer_res.dma_dev=&fixture_pci.dev;peer_res.max_pieces=2;
 peer_slot.common.io.leases=fixture_leases;peer_slot.common.io.spans=peer_slot.common.spans;
 peer_slot.common.io.list_cpu=fixture_list;peer_slot.common.io.list_dma=0x20000;
 peer_slot.common.io.peer_native=&peer_slot.trace;
 xdev_ext_stor_slot_add(&member.family.pool,&host_slot.runtime);
 xdev_ext_stor_slot_add(&peer_res.pool,&peer_slot.common.io.runtime);
 (void)peer;
}
void fixture_before_slot(bool peer,struct xdev_ext_stor_stage *ss,struct xdev_ext_stor_batch *sb)
{(void)ss;if(slot_error){assert(slot_error==-EBUSY);if(peer)sb->peer_io=&peer_slot.common.io;else sb->host_io=&host_slot;}}
struct xdev_ext_stor_io *fixture_slot_result(struct xdev_ext_stor_io *actual)
{
 event(SLOT);
 if(stage.poll && !production_blk_rq_is_poll(&request)) {
  unsigned before=failures;no_work();
  if(failures==before){fputs("SETUP invalid-hctx observer did not trigger original no_work assertions\n",stderr);exit(90);}
  fprintf(stderr,"FIXTURE_ASSERTION_STOP actual-SLOT invalid-hctx original-no_work failures=%u\n",failures-before);
  exit(1);
 }
 return actual;
}
void fixture_before_put(bool peer,struct xdev_ext_stor_stage *ss,struct xdev_ext_stor_batch *sb)
{(void)peer;(void)ss;(void)sb;event(PUT);}
void fixture_before_map(bool peer){(void)peer;event(MAP);}
void *kcalloc(size_t nr,size_t size,int flags){(void)flags;return calloc(nr,size);}
void *kvcalloc(size_t nr,size_t size,int flags){(void)flags;return calloc(nr,size);}
void kvfree(void *p){free(p);}
struct bio *bio_kmalloc(u16 n,int flags){(void)flags;struct bio *b=calloc(1,sizeof(*b));if(b)b->capacity=n;return b;}
void bio_init(struct bio *b,void *d,void *v,u32 n,u32 op){(void)d;(void)v;(void)op;b->used=b->bytes=0;b->capacity=n;}
void bio_uninit(struct bio *b){b->used=0;}
int bio_add_page(struct bio *b,struct page *p,u32 len,u32 off){(void)p;(void)off;if(map_error||b->used==b->capacity)return 0;b->used++;b->bytes+=len;return len;}
int blk_rq_append_bio(struct request *r,struct bio *b){r->bio=b;r->bytes=b->bytes;return 0;}
u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch *b){(void)b;return 1;}
int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *f)
{(void)b;if(pos)return -ERANGE;*f=(struct xdev_ext_mech_frame){.kaddr=session.pool.kind==XDEV_EXT_MECH_POOL_PEER?NULL:fixture_page.data,.data_len=512};return 0;}
struct page *xdev_ext_mech_frame_page(const struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *len)
{(void)p;(void)f;*po=off%PAGE_SIZE;*len=PAGE_SIZE-*po;return &fixture_page;}
u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){return s->depth;}
u32 xdev_ext_mech_session_state(struct xdev_ext_mech_session *s){return s->state;}
struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch *b){(void)b;return &stage;}
void *dma_alloc_coherent(struct device *d,size_t n,dma_addr_t *dma,int flags)
{(void)d;(void)flags;void *p=calloc(1,n);*dma=(uintptr_t)p;return p;}
void dma_free_coherent(struct device *d,size_t n,void *cpu,dma_addr_t dma)
{(void)d;(void)n;assert((uintptr_t)cpu==dma);free(cpu);}
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p){(void)p;return &file;}
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p){(void)p;return 1;}
int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 gen,u64 off,u32 len,enum dma_data_direction dir,struct xdev_ext_peer_fd_lease *l)
{(void)p;(void)gen;(void)dir;if(map_error)return map_error;*l=(struct xdev_ext_peer_fd_lease){.file=f,.lease={.dma_address=0x40000+off,.len=len}};return 0;}
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *l,bool q){(void)q;l->file=NULL;l->lease.mapping=NULL;}
static bool trace_native_event_enabled(void){return false;}
static void trace_native_event(const struct xdev_ext_native_event *e){(void)e;abort();}
'''


def poll_fixture(selected, raw, consumers=False):
    edits=[]
    def edit(old,new,count=1,reason='embedded current family fixture lvalue'):
        edits.append(dict(old=old,new=new,count=count,reason=reason,source_owner='public family poll fixture'))
    if not consumers:
        edit('struct nvme_xdev_ext_mech_slot','struct xdev_ext_stor_io')
        edit('struct nvme_xdev_ext_peer_res','struct xdev_ext_stor_peer_resources',2)
        edit('.ns=&ns,.slots=host,.nr_slots=0,.peer=&peer_res',
             '.ns=&ns,.family={.slots=host,.nr_slots=0,.peer=&peer_res}')
        edit('member.nr_slots','member.family.nr_slots',9)
        edit('member.slots','member.family.slots')
        edit('member.peer','member.family.peer',9)
        edit('peer[0].done','peer[0].common.io.done',2)
        edit('peer[i].done','peer[i].common.io.done',2)
        return adapt_fixture(raw,edits)
    # Remove only obsolete successful native algorithm substitutes. Their raw
    # bytes stay frozen on disk and every suppression has an inverse record.
    removed=('nvme_xdev_ext_class_ns','nvme_xdev_ext_mech_cmd_allowed',
             'bio_uninit','dma_free_coherent','nvme_xdev_ext_class_resources_init',
             'nvme_xdev_ext_peer_resources_init','nvme_req_op',
             'nvme_xdev_ext_class_slot_get','nvme_xdev_ext_peer_slot_get',
             'nvme_xdev_ext_class_slot_put','nvme_xdev_ext_peer_slot_put',
             'nvme_xdev_ext_class_map','nvme_xdev_ext_peer_map')
    for name in removed:
        edit(_fixture_function(raw,name),'',reason='obsolete native owner replaced by whole actual common owner')
    edit('#define WARN_ON_ONCE(v) (v)\n','')
    edit('#define kvfree free\n','')
    edit('struct nvme_xdev_ext_mech_slot host_slot','struct xdev_ext_stor_io host_slot')
    edit('struct nvme_xdev_ext_peer_res peer_res','struct xdev_ext_stor_peer_resources peer_res')
    edit('(struct nvme_xdev_ext_peer_res){','(struct xdev_ext_stor_peer_resources){')
    edit('member.peer','member.family.peer')
    edit('member.slots','member.family.slots')
    edit('member.nr_slots','member.family.nr_slots')
    edit('peer_slot.done','peer_slot.common.io.done',2)
    edit('peer_slot.runtime','peer_slot.common.io.runtime')
    # One of the two original runtime accesses was in a suppressed stub.
    edit('static void reset(bool peer){','static void fixture_reset_resources(bool);\nstatic void reset(bool peer){')
    edit('active_done=peer?&peer_slot.common.io.done:&host_slot.done;',
         'active_done=peer?&peer_slot.common.io.done:&host_slot.done;fixture_reset_resources(peer);')
    edit('static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(',
         'struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(')
    edit('static void *xdev_ext_mech_batch_priv(', 'void *xdev_ext_mech_batch_priv(')
    edit('static u64 xdev_ext_mech_batch_ticket(', 'u64 xdev_ext_mech_batch_ticket(')
    edit('static void *kzalloc(', 'void *kzalloc(')
    edit('static void kfree(', 'void kfree(')
    edit('static struct request *blk_mq_alloc_request(', 'struct request *blk_mq_alloc_request(')
    edit('static void blk_mq_free_request(', 'void blk_mq_free_request(')
    trace=_fixture_function(raw,'xdev_ext_mech_trace_plan')
    edit(trace,trace.replace('abort();',''),reason='external observation must allow actual native validation')
    edit('#include "actual_stor_done.inc"','')
    includes='\n'.join('#include "'+name+'"' for name in (
        'actual_old_poll.inc','actual_member_callbacks.inc','nvme_xdev_ext_class_bind.inc',
        'nvme_xdev_ext_class_complete.inc','nvme_xdev_ext_class_ready.inc',
        'nvme_xdev_ext_class_end_io.inc','nvme_xdev_ext_peer_complete.inc','nvme_xdev_ext_peer_end_io.inc'))
    poll_os = POLL_OS
    if selected.requester_profile():
        poll_os = selected.opcode_boundary_projection(poll_os)
        owner = 'include/linux/xdev_ext_mech.h'
        header = selected.read(owner)
        prototypes = []
        for name in ('xdev_ext_peer_mech_pool_file', 'xdev_ext_peer_mech_pool_generation'):
            matches = list(re.finditer(r'^[^;{}\n]*\b' + name + r'\([^;{}]*\);', header, re.M))
            if len(matches) != 1:
                raise ValueError('SETUP actual pool accessor declaration count: ' + name)
            match = matches[0]
            prototypes.append(selected._record(owner, name, match.start(), match.end()))
        anchor = 'static void no_work(void);'
        poll_os, records = adapt_fixture(poll_os,[dict(old=anchor,
            new=anchor+'\n'+'\n'.join(prototypes),count=1,
            reason='actual pool accessor declarations before already-bound requester setup calls',
            source_owner=owner)])
        selected._dependency_projections.append(dict(kind='poll-authority-declarations',records=records))
        anchor = ' member.family.geometry=(struct xdev_ext_stor_geometry){.capacity_lbas=4096,.lba_shift=9};'
        poll_os, records = adapt_fixture(poll_os,[dict(old=anchor,new=anchor+'\n'
            ' member.family.requester.pdev=&fixture_pci;\n'
            ' member.family.requester.authority=xdev_ext_peer_mech_pool_file(&session.pool);\n'
            ' member.family.requester.generation=xdev_ext_peer_mech_pool_generation(&session.pool);',count=1,
            reason='explicit already-bound requester facts at existing resource injection only; not CREATE coverage',
            source_owner='public poll fixture setup boundary')])
        selected._dependency_projections.append(dict(kind='poll-already-bound-facts',records=records))
        poll_os += REQUESTER_DEPENDENCY_FACTS
    edit(includes,poll_os+selected.closure('poll','strict')+
         '\n#define nvme_xdev_ext_class_bind(s,u) (fixture_bind_facts(), (nvme_xdev_ext_class_bind)(s,u))\n')
    edit('#define __KERNEL__ 1\n#include <xdev_ext_peer_nvme_core.h>\n#undef __KERNEL__','')
    edit('#include "nvme_xdev_ext_peer_submit.inc"','')
    edit('#include "nvme_xdev_ext_class_submit.inc"','')
    edit('kfree(stage.priv);',
         'if (!xdev_ext_storfam_unbind(\n'
         '        &((struct nvme_xdev_ext_mech_stage *)stage.priv)->family)) {\n'
         ' abort();\n'
         '}\n'
         'kfree(stage.priv);',2,
         'clean actual CREATE resources before original member free')
    setup=r'''
static void fixture_direction(bool write)
{
 native_opf=write?35U:34U;member.write=write;
 stage.direction=write?XDEV_EXT_MECH_DIR_TO_DEVICE:XDEV_EXT_MECH_DIR_FROM_DEVICE;
 member.family.window.write=write;
}
static int submit(bool peer)
{
 u8 sqe[64]={0};sqe[0]=member.write?1:2;sqe[40]=2;
 (void)peer;
 if(nvme_xdev_ext_class_validate(&stage,&batch,sqe,1))abort();
 return nvme_xdev_ext_class_submit(&stage,&batch);
}
'''
    edit(_fixture_function(raw,'submit'),setup,reason='actual validator and common HOST/PEER selector')
    edit('native_opf=UINT32_C(0x80000003)','native_opf=34U',reason='root-qualified current native READ opcode')
    edit('for(unsigned poll=0;poll<2;poll++)for(unsigned err=0;err<2;err++){',
         'for(unsigned write=0;write<2;write++)for(unsigned poll=0;poll<2;poll++)for(unsigned err=0;err<2;err++){',
         reason='root-qualified READ and WRITE variants preserve all original success assertions')
    edit('reset(peer);stage.poll=poll;early=true;',
         'reset(peer);fixture_direction(write);stage.poll=poll;early=true;')
    edit('EQ("actual-alloc-opf",allocation_opf,native_opf|(poll?REQ_POLLED:0));',
         'EQ("actual-alloc-opf",allocation_opf,(write?35U:34U)|(poll?REQ_POLLED:0));EQ("actual-command-opcode",captured.rw.opcode,write?1:2);',
         reason='root-qualified independent literal command and request opcodes')
    edit('EQ("plain-existing-POLLED-submit",submit(peer),0);EQ("plain-keeps-existing-POLLED",allocation_opf,native_opf);',
         'EQ("plain-existing-POLLED-submit",xdev_ext_stor_block_poll_opf(false,34U|REQ_POLLED),34U|REQ_POLLED);EQ("plain-keeps-existing-POLLED",xdev_ext_stor_block_poll_opf(false,native_opf),native_opf);',
         reason='root qualification: unreachable native injected bits retained as helper-only property')
    if selected.requester_profile():
        _preserve_legacy_vendor_inputs(raw, edit)
    return adapt_fixture(raw,edits)
