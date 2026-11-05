# SPDX-License-Identifier: GPL-2.0
"""Selected production transform definitions and their real core accessors.

The caller owns source-layout/snapshot selection. Historical monolithic sources
stay monolithic; an advertised split requires all actual dependency files.
"""
import re
from pathlib import Path
import sys
import json
import os
import posixpath


def _anchor(path):
    path = Path(path).absolute()
    if not path.exists():
        raise RuntimeError('missing owned anchor: ' + str(path))
    if path.is_file():
        path = path.parent
    for parent in (path, *path.parents):
        if (parent / 'view.json').is_file() or (parent / 'source-layout.json').is_file():
            return parent
    raise RuntimeError('missing owned checkout/view for ' + str(path))


def _plain(root, relative):
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in ('.', '..', '.git') for p in parts):
        raise RuntimeError('invalid owned dependency: ' + str(relative))
    current = Path(root)
    for part in parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError('symlinked owned dependency: ' + str(current))
    if not current.is_file():
        raise RuntimeError('missing owned dependency: ' + str(current))
    return current


_BASE = _anchor(__file__)
_RECEIPT = None
if (_BASE / 'view.json').is_file():
    _RECEIPT = json.loads(_plain(_BASE, 'view.json').read_bytes())
    if _RECEIPT.get('schema') != 1 or _RECEIPT.get('kind') != 'host-source-view':
        raise RuntimeError('invalid owned view receipt')
    _OWNER = Path(_RECEIPT['canonical_root']).resolve()
    _MANIFEST = json.loads(_plain(_OWNER, 'source-layout.json').read_bytes())
    if (_RECEIPT.get('manifest') != _MANIFEST or
            json.loads(_plain(_BASE, 'source-layout.json').read_bytes()) != _MANIFEST):
        raise RuntimeError('stale owned view manifest')
    # These are ordinary logical identities, including this helper's sole row.
    for _identity in ('tests/compute/transform_source.py', 'tools/layout.py'):
        _copy = _plain(_BASE, _identity)
        if (_RECEIPT.get('source_origins', {}).get(_identity) != _identity or
                _copy.stat().st_nlink != 1 or
                _copy.read_bytes() != _plain(_OWNER, _identity).read_bytes()):
            raise RuntimeError('altered or foreign owned bootstrap: ' + _identity)
else:
    _OWNER = _BASE
sys.path.insert(0, str(_plain(_BASE, 'tools/layout.py').parent))
import layout  # noqa: E402


_CONTEXTS = {}


def _context(anchor):
    base = _anchor(anchor)
    if base in _CONTEXTS:
        return _CONTEXTS[base]
    receipt = None
    if (base / 'view.json').is_file():
        receipt = json.loads(_plain(base, 'view.json').read_bytes())
        if receipt.get('schema') != 1 or receipt.get('kind') != 'host-source-view':
            raise RuntimeError('invalid owned view receipt')
        owner = Path(receipt['canonical_root']).resolve()
    else:
        owner = base.resolve()
    if owner != _OWNER:
        raise RuntimeError('foreign owned dependency root')
    try:
        selected = layout.load_layout(owner)
    except layout.LayoutError as error:
        raise RuntimeError(str(error)) from error
    if receipt is not None:
        if (receipt.get('manifest') != selected.manifest or
                json.loads(_plain(base, 'source-layout.json').read_bytes()) != selected.manifest or
                receipt.get('source_origins') != selected.by_logical or
                receipt.get('revision') != layout.provenance(owner)['revision']):
            raise RuntimeError('stale or foreign owned view receipt')
    if ('XDEV_EXT_CANONICAL_ROOT' in os.environ and
            Path(os.environ['XDEV_EXT_CANONICAL_ROOT']).resolve() != owner):
        raise RuntimeError('foreign canonical root environment')
    if (receipt is not None and 'XDEV_EXT_SOURCE_VIEW' in os.environ and
            Path(os.environ['XDEV_EXT_SOURCE_VIEW']).resolve() != base.resolve()):
        raise RuntimeError('foreign source view environment')
    _CONTEXTS[base] = (base, owner, selected, receipt)
    return _CONTEXTS[base]


def owned_dependency(anchor, identity):
    base, owner, selected, receipt = _context(anchor)
    if identity not in selected.by_source:
        raise RuntimeError('unmapped owned dependency: ' + identity)
    try:
        original = layout.safe_file(owner, identity)
        if receipt is None:
            return original
        copied = layout.safe_file(base, selected.logical(identity))
    except layout.LayoutError as error:
        raise RuntimeError(str(error)) from error
    if copied.stat().st_nlink != 1 or copied.read_bytes() != original.read_bytes():
        raise RuntimeError('stale or altered owned dependency: ' + identity)
    return copied


def source_root(anchor, explicit=None):
    expected = _context(anchor)
    chosen = _context(explicit) if explicit is not None else expected
    if expected[3] is not None and chosen[0] != expected[0]:
        raise RuntimeError('source root leaves the executing owned view')
    return chosen[0] / 'kernel' if chosen[3] is not None else chosen[1]


def verify_entry(anchor, identity):
    if Path(anchor).resolve() != owned_dependency(anchor, identity).resolve():
        raise RuntimeError('foreign owned entry: ' + identity)


# Validate this actual helper/caller context before exposing source readers.
if Path(layout.__file__).resolve() != _plain(_BASE, 'tools/layout.py').resolve():
    raise RuntimeError('foreign layout module')
owned_dependency(__file__, 'tests/compute/transform_source.py')


def native_path(root, relative):
    """Resolve an actual worktree input through the existing layout authority.

    Unlike read_native's sparse mode, a missing source never reads old HEAD.
    View copies are required; their canonical owners are validation inputs only.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise RuntimeError('missing selected source root: ' + str(root))
    try:
        _, owner, selected, _ = _context(root)
        identity = selected.source('linux', relative).relative_to(owner).as_posix()
        return owned_dependency(root, identity)
    except layout.LayoutError as error:
        raise RuntimeError(str(error)) from error


def read_native(root, relative):
    return native_path(root, relative).read_bytes().decode()


def compiler_headers(root, directory, text, reader=None, search=('',)):
    """Stage only the actual mapped include closure in a new ordinary tree.

    Validate all selected input bytes before creating the compiler tree. The
    selected view is never materialized, rewritten or used as a repair target.
    System headers and the fixtures' explicit OS boundary headers stay external.
    """
    _, _, selected, _ = _context(root)
    reader = reader or (lambda native: read_native(root, native))
    include = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)
    headers = {}

    def references(body, parent=''):
        found = []
        for delimiter, target in include.findall(body):
            candidates = ([posixpath.normpath(posixpath.join(parent, target))]
                          if delimiter == '"' else [])
            candidates += [posixpath.normpath(posixpath.join(prefix, target)) for prefix in search]
            candidates.append('include/' + target)
            mapped = next((name for name in candidates
                           if ('linux', name) in selected.by_native), None)
            if mapped is not None:
                if not mapped.endswith('.h'):
                    raise RuntimeError('non-header mapped compiler input: ' + mapped)
                found.append(mapped)
            elif 'xdev_ext' in target:
                raise RuntimeError('unmapped project compiler header: ' + target)
        return found

    pending = references(text)
    while pending:
        native = pending.pop()
        if native in headers:
            continue
        data = reader(native)
        if isinstance(data, str):
            data = data.encode()
        headers[native] = data
        pending.extend(references(data.decode(), posixpath.dirname(native)))
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    for native, data in sorted(headers.items()):
        target = directory / native
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    return directory


def select_core(root, override=None):
    """Keep monolithic history explicit; bind split overrides to one owner."""
    if override is None:
        return read_native(root, 'io_uring/xdev_ext_mech.c')
    supplied = Path(override)
    core = supplied.read_bytes().decode()
    if TransformSource.dependencies(core):
        selected = native_path(root, 'io_uring/xdev_ext_mech.c')
        if supplied.resolve() != selected.resolve() or core != selected.read_bytes().decode():
            raise RuntimeError('split core override is not the selected source owner')
    return core


def structure(text, name):
    matches = list(re.finditer(r'^struct ' + re.escape(name) + r'\s*\{\n.*?^\};',
                               text, re.M | re.S))
    if len(matches) != 1:
        raise RuntimeError('missing or ambiguous production structure: ' + name)
    return matches[0][0]


def field(text, owner, name):
    """An actual core storage declaration required by an authentic accessor."""
    block = structure(text, owner)
    matches = re.findall(r'^\s*[^;{}\n]*\b' + re.escape(name) +
                         r'(?:\[[^\]\n]*\])?\s*;[^\n]*$', block, re.M)
    if len(matches) != 1:
        raise RuntimeError('missing or ambiguous production field: ' + owner + '.' + name)
    return matches[0]


class TransformSource:
    @staticmethod
    def dependencies(core):
        return (('io_uring/xdev_ext_compfam_transform.c',
                 'io_uring/xdev_ext_compfam_transform.h',
                 'io_uring/xdev_ext_mech_compute_internal.h')
                if '#include "xdev_ext_compfam_transform.h"' in core else ())

    MOVED = ('xdev_ext_mech_transform_alias_free', 'xdev_ext_mech_transform_reserve',
             'xdev_ext_mech_transform_unreserve', 'xdev_ext_mech_transform_alias',
             'xdev_ext_mech_batch_transform_begin', 'xdev_ext_mech_batch_transform_complete',
             'xdev_ext_mech_batch_transform_produced', 'xdev_ext_mech_transform_undo',
             'xdev_ext_mech_transform_handoff', 'xdev_ext_mech_transform_landed',
             'xdev_ext_mech_batch_cpu_length', 'xdev_ext_mech_batch_compute')
    ACCESSORS = ('xdev_ext_mech_compute_session_access',
                 'xdev_ext_mech_compute_batch_access',
                 'xdev_ext_mech_compute_transform_state',
                 'xdev_ext_mech_batch_session', 'xdev_ext_mech_batch_stage',
                 'xdev_ext_mech_batch_status', 'xdev_ext_mech_batch_bytes')

    def __init__(self, core, read, definition):
        self.core, self.definition = core, definition
        dependencies = self.dependencies(core)
        self.split = bool(dependencies)
        self.types = ''
        self.text = core
        if self.split:
            inputs = {path: read(path) for path in dependencies}
            state = inputs['io_uring/xdev_ext_compfam_transform.h']
            access = inputs['io_uring/xdev_ext_mech_compute_internal.h']
            self.types = '\n'.join((structure(state, 'xdev_ext_mech_transform_state'),
                                    structure(access, 'xdev_ext_mech_compute_session_access'),
                                    structure(access, 'xdev_ext_mech_compute_batch_access')))
            self.text += '\n' + inputs['io_uring/xdev_ext_compfam_transform.c']
            for name in self.MOVED:
                self.unique(self.text, name)

    @staticmethod
    def unique(text, name):
        pattern = r'^[A-Za-z_][^;{}]*?\b' + re.escape(name) + r'\([^;{}]*\)\s*\{'
        if len(list(re.finditer(pattern, text, re.M))) != 1:
            raise RuntimeError('missing or ambiguous production function: ' + name)

    def helpers(self, bodies):
        """Select complete actual getters called by the selected definitions."""
        if not self.split:
            return []
        selected = []
        for name in self.ACCESSORS:
            if any(re.search(r'\b' + name + r'\s*\(', body) for body in bodies):
                self.unique(self.core, name)
                selected.append(self.definition(self.core, name))
        return selected

    def storage(self, fixture):
        """Name the original fixture's embedded state with its authentic type."""
        if not self.split:
            return fixture
        anonymous = (r'struct \{struct xdev_ext_mech_frame dst\[XDEV_EXT_MECH_MAX_FRAMES\];'
                     r'u64 token\[XDEV_EXT_MECH_MAX_FRAMES\];u32 nr,produced;bool active;\} transform;')
        fixture, count = re.subn(anonymous, 'struct xdev_ext_mech_transform_state transform;', fixture)
        if count != 1:
            raise RuntimeError('missing or ambiguous fixture transform storage')
        return fixture
