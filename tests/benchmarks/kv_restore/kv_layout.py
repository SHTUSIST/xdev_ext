#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""KV objects on the host-1 NVMe namespace and the restore plan of one request.

A KV object is one contiguous LBA extent holding the KV cache of a context in
token-chunk order, so a P-token prefix is the first P * bytes_per_token bytes.
The host-1 session reads the KV window with the key-based NVMe program: batch
key k reads slot (k mod slots) of the window. A restore with ordinal r uses
keys r * slots + slot0 .. + groups - 1, so key i reads the object's group i and
later restores always use larger keys. Host 2 receives group i into frames
dst_frame0 + i * frames_per_group .. of its device-memory pool (ordered user
frames), so the KV lands contiguously at frame offset dst_frame0.

An object may carry a vLLM block layout ("kv"): the bytes are then ordered
by vLLM block, and within a block by attention layer, each (block, layer)
page being the layer's [H, N, C] page of that block as vLLM 0.33.0 views it
(H KV heads, N tokens per block, C = (head_size + head_size_v) * dtype bytes;
vllm/v1/kv_cache_interface.py). A P-token prefix with P a multiple of the
block size is still the first P * bytes_per_token bytes, and the restore
groups of such a prefix cover whole pages, so the scatter into vLLM's paged
buffer copies whole pages. An object may also name a payload file (real KV
dumped by kv_dump.py) that prepare-nvme writes instead of the pattern.

The prefix index maps a prefix hash (prefix_hashes) to the object, byte
offset, length and token count of a stored prefix; it is a text file so the
C worker reads the same file (kv_index.h).

Every limit below is a kernel or library rule the plan must meet; the C
driver (kv_plan.h) applies the same arithmetic and test_plan_crosscheck.py
compares the two.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import NamedTuple

MODELS = {
    # Bytes of K and V per token, from the K-KV experiment design.
    'qwen3-14b': 163840,
    'qwen3-8b-bf16': 147456,
}
PREFIX_TOKENS = (4096, 16384, 32768)


class KVArch(NamedTuple):
    """Attention geometry from the model's Hugging Face config.json."""
    layers: int          # num_hidden_layers
    kv_heads: int        # num_key_value_heads
    head_size: int       # head_dim
    dtype_bytes: int     # KV cache dtype (BF16: 2)

    @property
    def bytes_per_token(self):
        return self.layers * self.kv_heads * 2 * self.head_size * self.dtype_bytes


ARCH = {
    'qwen3-14b': KVArch(40, 8, 128, 2),
    'qwen3-8b-bf16': KVArch(36, 8, 128, 2),
}

BLOCK = 4096                       # pattern block and NHI frame size
NHI_FRAME = 4096                   # XDEV_EXT_XDOMAIN_MAX_FRAME
NHI_MAX_ELEMS = 64                 # XDEV_EXT_XDOMAIN_MAX_ELEMS
MAX_FRAMES_PER_BATCH = 32          # XDEV_EXT_MECH_MAX_FRAMES
PEER_FRAME_MIN, PEER_FRAME_MAX = 4096, 2 << 20   # XDEV_EXT_MECH_PEER_FRAME_MIN/MAX
MAX_DEPTH = 64                     # XDEV_EXT_MECH_MAX_DEPTH, XDEV_EXT_XD_MAX_DEPTH
MAX_WINDOW = 32                    # XDEV_EXT_XDOMAIN_MAX_WINDOW
MAX_NLB = 65536                    # XDEV_EXT_MP_NVME_MAX_NLB
LIB_MAX_START_FRAMES = 65536       # libxdev_ext start_frames index limit
U64 = (1 << 64) - 1
MAX_MANIFEST_BYTES = 1 << 20


class LayoutError(ValueError):
    pass


def _int(value, what, minimum=0, maximum=U64):
    if type(value) is not int or value < minimum or value > maximum:
        raise LayoutError(f'{what} must be an integer in [{minimum}, {maximum}]: {value!r}')
    return value


def _pow2(value):
    return value > 0 and not value & (value - 1)


def kv_bytes(model, tokens):
    if model not in MODELS:
        raise LayoutError(f'unknown model {model!r}; known: {sorted(MODELS)}')
    return MODELS[model] * _int(tokens, 'tokens', 1, 1 << 32)


@dataclass(frozen=True)
class BlockLayout:
    """vLLM block order: page (b, l) holds layer l of block b, H * N * C bytes."""
    block_size: int      # N: tokens per vLLM block
    layers: int          # attention layers, in model order
    heads: int           # H: KV head slots of the page
    state_bytes: int     # C: bytes per (head, token) cell, K and V together

    @classmethod
    def for_model(cls, model, block_size):
        if model not in ARCH:
            raise LayoutError(f'no architecture for model {model!r}; known: {sorted(ARCH)}')
        a = ARCH[model]
        return cls(block_size, a.layers, a.kv_heads, 2 * a.head_size * a.dtype_bytes)

    @property
    def page_bytes(self):
        return self.heads * self.block_size * self.state_bytes

    @property
    def block_bytes(self):
        return self.layers * self.page_bytes

    @property
    def bytes_per_token(self):
        return self.layers * self.heads * self.state_bytes

    def check(self):
        for what in ('block_size', 'layers', 'heads', 'state_bytes'):
            _int(getattr(self, what), what, 1, 1 << 20)

    def validate(self, group_bytes):
        """A restore group never splits a page and a block is whole groups (or v.v.)."""
        self.check()
        p, b, g = self.page_bytes, self.block_bytes, group_bytes
        if g % p and p % g:
            raise LayoutError(f'{g}-byte groups split {p}-byte pages')
        if g % b and b % g:
            raise LayoutError(f'{g}-byte groups do not tile {b}-byte blocks')

    def page_offset(self, block, layer):
        _int(block, 'block')
        _int(layer, 'layer', 0, self.layers - 1)
        return (block * self.layers + layer) * self.page_bytes

    def group_pages(self, group, group_bytes):
        """(block, layer, offset in page, length, offset in group) of each page piece."""
        start, end = group * group_bytes, (group + 1) * group_bytes
        out, at = [], start
        while at < end:
            page, off = divmod(at, self.page_bytes)
            n = min(self.page_bytes - off, end - at)
            out.append((page // self.layers, page % self.layers, off, n, at - start))
            at += n
        return out

    def to_json(self):
        return dict(order='block-layer', block_size=self.block_size, layers=self.layers,
                    heads=self.heads, state_bytes=self.state_bytes)


class Payload(NamedTuple):
    file: str            # relative to the manifest's directory unless absolute
    sha256: str


@dataclass(frozen=True)
class KVObject:
    name: str
    model: str
    tokens: int
    seed: int
    slba: int
    nlb: int
    kv: BlockLayout = None
    payload: Payload = None

    @property
    def bytes_per_token(self):
        return MODELS[self.model]

    @property
    def bytes(self):
        return kv_bytes(self.model, self.tokens)


@dataclass(frozen=True)
class Manifest:
    lba_bytes: int
    window_slba: int
    window_nlb: int
    objects: tuple

    def object(self, name):
        for o in self.objects:
            if o.name == name:
                return o
        raise LayoutError(f'no KV object named {name!r}')


def _keys(obj, allowed, what, optional=()):
    if not isinstance(obj, dict):
        raise LayoutError(f'{what} must be an object')
    extra = set(obj) - set(allowed) - set(optional)
    missing = set(allowed) - set(obj)
    if extra or missing:
        raise LayoutError(f'{what}: unknown keys {sorted(extra)}, missing {sorted(missing)}')


def _parse_kv(raw, model, what):
    _keys(raw, ('order', 'block_size', 'layers', 'heads', 'state_bytes'), what)
    if raw['order'] != 'block-layer':
        raise LayoutError(f'{what}: order must be "block-layer"')
    kv = BlockLayout(*(_int(raw[k], f'{what}.{k}', 1, 1 << 20)
                       for k in ('block_size', 'layers', 'heads', 'state_bytes')))
    if kv.bytes_per_token != MODELS[model]:
        raise LayoutError(f'{what}: {kv.bytes_per_token} bytes per token, '
                          f'model {model} has {MODELS[model]}')
    return kv


_SHA256 = re.compile(r'[0-9a-f]{64}')


def _parse_payload(raw, what):
    _keys(raw, ('file', 'sha256'), what)
    f, h = raw['file'], raw['sha256']
    if not isinstance(f, str) or not f or len(f) > 4096 or '\0' in f:
        raise LayoutError(f'{what}: file must be a nonempty path')
    if not isinstance(h, str) or not _SHA256.fullmatch(h):
        raise LayoutError(f'{what}: sha256 must be 64 lowercase hex digits')
    return Payload(f, h)


def parse_manifest(data):
    _keys(data, ('schema', 'kind', 'lba_bytes', 'window', 'objects'), 'manifest')
    if data['schema'] != 1 or data['kind'] != 'kv-layout':
        raise LayoutError('manifest must have schema 1 and kind "kv-layout"')
    lba = _int(data['lba_bytes'], 'lba_bytes', 512, 65536)
    if not _pow2(lba):
        raise LayoutError(f'lba_bytes must be a power of two: {lba}')
    _keys(data['window'], ('slba', 'nlb'), 'window')
    wslba = _int(data['window']['slba'], 'window.slba')
    wnlb = _int(data['window']['nlb'], 'window.nlb', 1)
    if wnlb > U64 - wslba:
        raise LayoutError('window wraps the LBA space')
    if not isinstance(data['objects'], list) or not data['objects']:
        raise LayoutError('objects must be a nonempty list')
    objects, names = [], set()
    for i, raw in enumerate(data['objects']):
        _keys(raw, ('name', 'model', 'tokens', 'seed', 'slba', 'nlb'), f'objects[{i}]',
              ('kv', 'payload'))
        name = raw['name']
        if not isinstance(name, str) or not name or len(name) > 128 or \
                any(c in name for c in ' \t\r\n"\\') or name in names:
            raise LayoutError(f'objects[{i}]: invalid or duplicate name {name!r}')
        names.add(name)
        if raw['model'] not in MODELS:
            raise LayoutError(f'objects[{i}]: unknown model {raw["model"]!r}')
        kv = _parse_kv(raw['kv'], raw['model'], f'objects[{i}].kv') if 'kv' in raw else None
        payload = _parse_payload(raw['payload'], f'objects[{i}].payload') \
            if 'payload' in raw else None
        o = KVObject(name, raw['model'], _int(raw['tokens'], 'tokens', 1, 1 << 32),
                     _int(raw['seed'], 'seed'), _int(raw['slba'], 'slba'),
                     _int(raw['nlb'], 'nlb', 1), kv, payload)
        if kv and o.tokens % kv.block_size:
            raise LayoutError(f'object {name}: {o.tokens} tokens are not whole '
                              f'{kv.block_size}-token blocks')
        if o.slba < wslba or o.nlb > wslba + wnlb - o.slba:
            raise LayoutError(f'object {name} lies outside the window')
        if o.nlb * lba < o.bytes:
            raise LayoutError(f'object {name}: extent of {o.nlb * lba} bytes < {o.bytes} KV bytes')
        objects.append(o)
    ordered = sorted(objects, key=lambda o: o.slba)
    for a, b in zip(ordered, ordered[1:]):
        if a.slba + a.nlb > b.slba:
            raise LayoutError(f'objects {a.name} and {b.name} overlap')
    return Manifest(lba, wslba, wnlb, tuple(objects))


def load_manifest(path):
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size > MAX_MANIFEST_BYTES:
        raise LayoutError(f'manifest must be a regular file of at most 1 MiB: {p}')
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise LayoutError('duplicate JSON key')
        return dict(pairs)
    try:
        data = json.loads(p.read_text(), object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as error:
        raise LayoutError(f'manifest is not JSON: {error}') from None
    return parse_manifest(data)


@dataclass(frozen=True)
class Geometry:
    group_bytes: int
    frame_bytes: int
    depth: int
    window: int
    early: bool

    def validate(self, lba_bytes):
        f = _int(self.frame_bytes, 'frame_bytes', PEER_FRAME_MIN, PEER_FRAME_MAX)
        if not _pow2(f):
            raise LayoutError(f'frame_bytes must be a power of two: {f}')
        g = _int(self.group_bytes, 'group_bytes', f, 1 << 31)
        if g % f:
            raise LayoutError('group_bytes must be a multiple of frame_bytes')
        if g // f > MAX_FRAMES_PER_BATCH:
            raise LayoutError(f'{g // f} frames per group exceed {MAX_FRAMES_PER_BATCH}')
        if g // NHI_FRAME > NHI_MAX_ELEMS:
            raise LayoutError(f'{g // NHI_FRAME} NHI elements per group exceed {NHI_MAX_ELEMS}')
        if g % lba_bytes or g // lba_bytes > MAX_NLB:
            raise LayoutError('group_bytes must be whole LBAs and at most 65536 of them')
        d = _int(self.depth, 'depth', 1, MAX_DEPTH)
        _int(self.window, 'window', 1, min(MAX_WINDOW, d))
        if type(self.early) is not bool:
            raise LayoutError('early must be a boolean')


@dataclass(frozen=True)
class RestorePlan:
    object: KVObject
    prefix_tokens: int
    bytes: int
    groups: int
    geometry: Geometry
    lba_bytes: int
    window_slba: int
    window_nlb: int
    slots: int
    slot0: int
    ordinal: int
    first_seq: int
    host2_dst_frame0: int
    host2_pool_frames: int
    host2_ring: bool = False

    @property
    def kv_blocks(self):
        """vLLM blocks the restore carries (None for an object without a block layout)."""
        kv = self.object.kv
        return self.prefix_tokens // kv.block_size if kv else None

    @property
    def frames_per_group(self):
        return self.geometry.group_bytes // self.geometry.frame_bytes

    @property
    def blocks_per_group(self):
        return self.geometry.group_bytes // self.lba_bytes

    @property
    def host1_pool_frames(self):
        return self.geometry.depth * self.frames_per_group

    @property
    def host1_indices(self):
        return list(range(min(self.groups, self.geometry.depth) * self.frames_per_group))

    @property
    def host2_indices(self):
        """Frame indices host 2's START lends: the destination, or a recycled ring."""
        if self.host2_ring:
            return self.host1_indices
        n = self.groups * self.frames_per_group
        return list(range(self.host2_dst_frame0, self.host2_dst_frame0 + n))

    def group_slba(self, i):
        if not 0 <= i < self.groups:
            raise LayoutError('group index out of range')
        slot = (self.first_seq + i) % self.slots
        return self.window_slba + slot * self.blocks_per_group

    def to_json(self):
        g = self.geometry
        return {
            'object': self.object.name, 'model': self.object.model, 'seed': self.object.seed,
            'object_slba': self.object.slba, 'prefix_tokens': self.prefix_tokens,
            'bytes': self.bytes, 'groups': self.groups, 'group_bytes': g.group_bytes,
            'frame_bytes': g.frame_bytes, 'frames_per_group': self.frames_per_group,
            'lba_bytes': self.lba_bytes, 'window_slba': self.window_slba,
            'window_nlb': self.window_nlb, 'slots': self.slots, 'slot0': self.slot0,
            'ordinal': self.ordinal, 'first_seq': self.first_seq, 'depth': g.depth,
            'window': g.window, 'early': g.early,
            'host1_pool_frames': self.host1_pool_frames,
            'host1_recycle_frames': len(self.host1_indices),
            'host2_dst_frame0': self.host2_dst_frame0,
            'host2_frames': self.groups * self.frames_per_group,
            'host2_pool_frames': self.host2_pool_frames,
            'host2_ring': self.host2_ring,
            'host2_start_frames': len(self.host2_indices),
            'kv_blocks': self.kv_blocks,
        }


def plan_restore(manifest, name, prefix_tokens, geometry, ordinal, dst_frame0=0,
                 pool_frames=None, host2_ring=False):
    """host2_ring: CE VMM destination; host 2 lends a recycled ring of host frames."""
    obj = manifest.object(name)
    geometry.validate(manifest.lba_bytes)
    prefix = _int(prefix_tokens, 'prefix_tokens', 1, obj.tokens)
    size = kv_bytes(obj.model, prefix)
    g = geometry.group_bytes
    if obj.kv:
        obj.kv.validate(g)
        if prefix % obj.kv.block_size:
            raise LayoutError(f'a restore moves whole {obj.kv.block_size}-token vLLM blocks: '
                              f'{prefix} tokens')
    if size % g:
        raise LayoutError(f'{size} KV bytes are not whole {g}-byte groups')
    groups = size // g
    blocks = g // manifest.lba_bytes
    slots = manifest.window_nlb // blocks
    rel = obj.slba - manifest.window_slba
    if rel % blocks:
        raise LayoutError(f'object {name} does not start on a {g}-byte slot of the window')
    slot0 = rel // blocks
    if slot0 + groups > slots:
        raise LayoutError('restore runs past the last whole slot of the window')
    _int(ordinal, 'ordinal', 1)
    if ordinal > (U64 - slot0 - groups) // slots:
        raise LayoutError('restore keys would overflow 64 bits')
    first = ordinal * slots + slot0
    fpg = g // geometry.frame_bytes
    dst0 = _int(dst_frame0, 'dst_frame0', 0, (1 << 32) - 1)
    frames = groups * fpg
    if not host2_ring and frames > LIB_MAX_START_FRAMES:
        raise LayoutError(f'{frames} destination frames exceed the {LIB_MAX_START_FRAMES} '
                          'frame indices one START can lend; use larger frames')
    need = dst0 + frames
    pool = need if pool_frames is None else _int(pool_frames, 'pool_frames', 1, (1 << 32) - 1)
    if pool < need:
        raise LayoutError(f'destination pool of {pool} frames < {need} needed')
    return RestorePlan(obj, prefix, size, groups, geometry, manifest.lba_bytes,
                       manifest.window_slba, manifest.window_nlb, slots, slot0, ordinal,
                       first, dst0, pool, bool(host2_ring))


# ---- prefix index -----------------------------------------------------------

PREFIX_DOMAIN = b'xdev-kv-prefix\x001\x00'
INDEX_HEADER = 'xdev-kv-index 1'
MAX_INDEX_BYTES = 16 << 20
U32 = (1 << 32) - 1


def prefix_hashes(model, layout, token_ids):
    """(tokens, hex) after each whole block of token_ids.

    h0 = SHA-256(b'xdev-kv-prefix\\0' b'1\\0' model b'\\0' le32(block_size, layers,
    heads, state_bytes)); h(i+1) = SHA-256(h(i) || le32 token ids of block i).
    A partial last block has no hash: vLLM blocks are restored whole.
    """
    layout.check()
    bs = layout.block_size
    for t in token_ids:
        if type(t) is not int or t < 0 or t > U32:
            raise LayoutError(f'token ids must be integers in [0, {U32}]: {t!r}')
    h = hashlib.sha256(PREFIX_DOMAIN + model.encode() + b'\x00' +
                       struct.pack('<4I', bs, layout.layers, layout.heads,
                                   layout.state_bytes)).digest()
    out = []
    for i in range(len(token_ids) // bs):
        h = hashlib.sha256(h + struct.pack(f'<{bs}I', *token_ids[i * bs:(i + 1) * bs])).digest()
        out.append(((i + 1) * bs, h.hex()))
    return out


class IndexEntry(NamedTuple):
    hash: str            # prefix_hashes() value of the stored prefix
    object: str          # manifest object holding it
    slba: int            # the object's first LBA (checked against the manifest)
    offset: int          # byte offset of the prefix in the object (whole blocks)
    bytes: int           # tokens * bytes_per_token
    tokens: int
    fnv1a: int = None    # FNV-1a 64 of the prefix bytes, for verification (optional)

    def line(self):
        text = (f'prefix {self.hash} object={self.object} slba={self.slba} '
                f'offset={self.offset} bytes={self.bytes} tokens={self.tokens}')
        if self.fnv1a is not None:
            text += f' fnv1a=0x{self.fnv1a:016x}'
        return text


def resolve(entry, lba_bytes):
    """(object_slba, bytes) of the restore request for an index entry."""
    if entry.offset % lba_bytes:
        raise LayoutError(f'index offset {entry.offset} is not whole {lba_bytes}-byte LBAs')
    return entry.slba + entry.offset // lba_bytes, entry.bytes


class PrefixIndex:
    def __init__(self, entries, manifest):
        self.entries = tuple(entries)
        self._by_hash = {}
        for e in self.entries:
            self._check(e, manifest)
            if e.hash in self._by_hash:
                raise LayoutError(f'index repeats prefix {e.hash}')
            self._by_hash[e.hash] = e

    @staticmethod
    def _check(e, m):
        if not isinstance(e.hash, str) or not _SHA256.fullmatch(e.hash):
            raise LayoutError(f'index hash must be 64 lowercase hex digits: {e.hash!r}')
        try:
            o = m.object(e.object)
        except LayoutError:
            raise LayoutError(f'index entry names unknown object {e.object!r}') from None
        if not o.kv:
            raise LayoutError(f'index entry names {o.name}, which has no vLLM block layout')
        if e.slba != o.slba:
            raise LayoutError(f'index says {o.name} starts at LBA {e.slba}, manifest {o.slba}')
        _int(e.tokens, 'tokens', 1)
        _int(e.offset, 'offset')
        if e.tokens % o.kv.block_size or e.bytes != e.tokens * o.kv.bytes_per_token:
            raise LayoutError(f'index entry {e.hash}: {e.tokens} tokens are not whole blocks '
                              f'of {e.bytes} bytes')
        if e.offset % o.kv.block_bytes or e.offset % m.lba_bytes:
            raise LayoutError(f'index entry {e.hash}: offset {e.offset} is not on a block')
        if e.offset + e.bytes > o.bytes:
            raise LayoutError(f'index entry {e.hash} runs past object {o.name}')
        if e.fnv1a is not None:
            _int(e.fnv1a, 'fnv1a')

    def get(self, digest):
        return self._by_hash.get(digest)

    def longest_match(self, model, layout, token_ids, max_tokens=None):
        """The entry of the longest stored prefix of token_ids, or None."""
        best = None
        for tokens, digest in prefix_hashes(model, layout, token_ids):
            if max_tokens is not None and tokens > max_tokens:
                break
            hit = self._by_hash.get(digest)
            if hit:
                best = hit
        return best


_INDEX_KEYS = ('object', 'slba', 'offset', 'bytes', 'tokens')
_NUMBER = re.compile(r'0x[0-9a-fA-F]+|[0-9]+')


def _index_line(text, lineno):
    words = text.split()
    if words[0] != 'prefix' or len(words) < 2 or len(text) >= 511 or \
            not _SHA256.fullmatch(words[1]):
        raise LayoutError(f'index line {lineno}: unknown record {words[0]!r}')
    fields = {}
    for w in words[2:]:
        k, eq, v = w.partition('=')
        if not eq or k not in _INDEX_KEYS + ('fnv1a',) or k in fields or not v or \
                (k == 'object' and len(v) > 128):
            raise LayoutError(f'index line {lineno}: bad or repeated field {w!r}')
        fields[k] = v
    if set(_INDEX_KEYS) - set(fields):
        raise LayoutError(f'index line {lineno}: missing {sorted(set(_INDEX_KEYS) - set(fields))}')
    nums = {}
    for k in ('slba', 'offset', 'bytes', 'tokens', 'fnv1a'):
        if k in fields:
            if not _NUMBER.fullmatch(fields[k]):
                raise LayoutError(f'index line {lineno}: {k} is not a number')
            v = fields[k]
            nums[k] = _int(int(v[2:], 16) if v.startswith('0x') else int(v, 10), k)
    if not nums['tokens'] or not nums['bytes']:
        raise LayoutError(f'index line {lineno}: empty prefix')
    return IndexEntry(words[1], fields['object'], nums['slba'], nums['offset'], nums['bytes'],
                      nums['tokens'], nums.get('fnv1a'))


def write_index(path, entries):
    p = Path(path)
    tmp = p.with_name(p.name + '.tmp')
    tmp.write_text('\n'.join([INDEX_HEADER] + [e.line() for e in entries]) + '\n')
    tmp.replace(p)


def load_index(path, manifest):
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size > MAX_INDEX_BYTES:
        raise LayoutError(f'index must be a regular file of at most 16 MiB: {p}')
    return PrefixIndex(parse_index_text(p.read_text()), manifest)


def parse_index_text(text):
    """Entries of an index file, syntax and repeats only (kv_index.h's checks)."""
    lines = text.splitlines()
    if not lines or lines[0].rstrip('\r') != INDEX_HEADER:
        raise LayoutError(f'index must start with {INDEX_HEADER!r}')
    entries = [_index_line(line, n) for n, line in enumerate(lines[1:], 2)
               if line.strip() and not line.lstrip().startswith('#')]
    if len({e.hash for e in entries}) != len(entries):
        raise LayoutError('index repeats a prefix')
    return entries


# ---- deterministic payload --------------------------------------------------

GOLDEN = 0x9E3779B97F4A7C15
SALT_TAG = 0x53414C54 << 32
BLOCK_MUL = 0xD1342543DE82EF95
_REPLICATE = sum(1 << (64 * j) for j in range(BLOCK // 8))


def mix64(x):
    """SplitMix64 output for state x (the reference next() after x += GOLDEN)."""
    z = (x + GOLDEN) & U64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & U64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & U64
    return z ^ (z >> 31)


_salt_cache = {}


def _salt(seed):
    salt = _salt_cache.get(seed)
    if salt is None:
        salt = sum(mix64(seed ^ SALT_TAG ^ j) << (64 * j) for j in range(BLOCK // 8))
        if len(_salt_cache) > 64:
            _salt_cache.clear()
        _salt_cache[seed] = salt
    return salt


def pattern_block(seed, block):
    """Object-relative 4 KiB block: word j = salt_j XOR mix64(seed XOR block*BLOCK_MUL)."""
    _int(seed, 'seed')
    _int(block, 'block')
    word = mix64(seed ^ ((block * BLOCK_MUL) & U64))
    return (_salt(seed) ^ (word * _REPLICATE)).to_bytes(BLOCK, 'little')


FNV_OFFSET, FNV_PRIME = 0xCBF29CE484222325, 0x100000001B3


def fnv1a64(data, h=FNV_OFFSET):
    """FNV-1a 64 as kv_pattern.h's kv_fnv1a (the workers' record digests)."""
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & U64
    return h


def pattern_bytes(seed, offset, length):
    _int(offset, 'offset')
    _int(length, 'length', 0, 1 << 34)
    first, last = offset // BLOCK, (offset + length + BLOCK - 1) // BLOCK
    data = b''.join(pattern_block(seed, b) for b in range(first, last))
    start = offset - first * BLOCK
    return data[start:start + length]
