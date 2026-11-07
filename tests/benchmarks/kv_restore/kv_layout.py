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

Every limit below is a kernel or library rule the plan must meet; the C
driver (kv_plan.h) applies the same arithmetic and test_plan_crosscheck.py
compares the two.
"""
from dataclasses import dataclass
import json
from pathlib import Path

MODELS = {
    # Bytes of K and V per token, from the K-KV experiment design.
    'qwen3-14b': 163840,
    'qwen3-8b-bf16': 147456,
}
PREFIX_TOKENS = (4096, 16384, 32768)

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
class KVObject:
    name: str
    model: str
    tokens: int
    seed: int
    slba: int
    nlb: int

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


def _keys(obj, allowed, what):
    if not isinstance(obj, dict):
        raise LayoutError(f'{what} must be an object')
    extra = set(obj) - set(allowed)
    missing = set(allowed) - set(obj)
    if extra or missing:
        raise LayoutError(f'{what}: unknown keys {sorted(extra)}, missing {sorted(missing)}')


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
        _keys(raw, ('name', 'model', 'tokens', 'seed', 'slba', 'nlb'), f'objects[{i}]')
        name = raw['name']
        if not isinstance(name, str) or not name or len(name) > 128 or \
                any(c in name for c in ' \t\r\n"\\') or name in names:
            raise LayoutError(f'objects[{i}]: invalid or duplicate name {name!r}')
        names.add(name)
        if raw['model'] not in MODELS:
            raise LayoutError(f'objects[{i}]: unknown model {raw["model"]!r}')
        o = KVObject(name, raw['model'], _int(raw['tokens'], 'tokens', 1, 1 << 32),
                     _int(raw['seed'], 'seed'), _int(raw['slba'], 'slba'),
                     _int(raw['nlb'], 'nlb', 1))
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
        }


def plan_restore(manifest, name, prefix_tokens, geometry, ordinal, dst_frame0=0,
                 pool_frames=None, host2_ring=False):
    """host2_ring: CE VMM destination; host 2 lends a recycled ring of host frames."""
    obj = manifest.object(name)
    geometry.validate(manifest.lba_bytes)
    prefix = _int(prefix_tokens, 'prefix_tokens', 1, obj.tokens)
    size = kv_bytes(obj.model, prefix)
    g = geometry.group_bytes
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


def pattern_bytes(seed, offset, length):
    _int(offset, 'offset')
    _int(length, 'length', 0, 1 << 34)
    first, last = offset // BLOCK, (offset + length + BLOCK - 1) // BLOCK
    data = b''.join(pattern_block(seed, b) for b in range(first, last))
    start = offset - first * BLOCK
    return data[start:start + length]
