# SPDX-License-Identifier: GPL-2.0
"""Prefix index: the stored KV extent of a prompt prefix.

Same format as the K-KV benchmark's writer (tests/benchmarks/kv_restore
kv_layout.py prefix_hashes / write_index). The hash chains SHA-256 over whole
blocks of u32 token ids, starting from a domain block that names the model key
and canonical tensor dtype and staging layout (block size, layers, heads, cell bytes): the hashes of
a P-token prefix are the first P / block_size hashes of any longer prompt that
starts with it, and a stored prefix of another model key or layout never
matches. One text line per stored prefix:

    xdev-kv-index 2 dtype=bfloat16
    prefix HASH object=NAME slba=N offset=N bytes=N tokens=N [fnv1a=0xHEX]

slba is the object's first LBA, offset the prefix's byte offset inside the
object, bytes = tokens * bytes_per_token. A restore of the prefix reads
object_slba = slba + offset / lba_bytes.
"""
import hashlib
from pathlib import Path
import re
import struct
from typing import NamedTuple, Optional
from .layout import canonical_dtype

HEADER = 'xdev-kv-index 2 dtype='
DOMAIN = b'xdev-kv-prefix\x002\x00'
MAX_INDEX_BYTES = 64 << 20
_HASH = re.compile(r'[0-9a-f]{64}')
_NAME = re.compile(r'[^\s"\\=]{1,128}')
_DIGEST = re.compile(r'0x[0-9a-f]{16}')
_KEYS = ('object', 'slba', 'offset', 'bytes', 'tokens')


class PrefixIndexError(ValueError):
    pass


class Entry(NamedTuple):
    hash: str
    object: str
    slba: int
    offset: int
    bytes: int
    tokens: int
    fnv1a: Optional[int]


def prefix_hashes(model, staging, tokens, max_tokens=None):
    """[(tokens covered, hex hash)] for every whole block of tokens[:max_tokens]."""
    bs = staging.block_size
    limit = len(tokens) if max_tokens is None else min(len(tokens), max_tokens)
    dtype = canonical_dtype(staging.dtype)
    h = hashlib.sha256(DOMAIN + model.encode() + b'\x00' + dtype.encode() + b'\x00' + struct.pack(
        '<4I', bs, staging.layers, staging.heads, staging.state_bytes)).digest()
    out = []
    for i in range(limit // bs):
        block = tokens[i * bs:(i + 1) * bs]
        if any(type(t) is not int or not 0 <= t < 1 << 32 for t in block):
            raise PrefixIndexError('token ids must be integers in [0, 2^32)')
        h = hashlib.sha256(h + struct.pack(f'<{bs}I', *block)).digest()
        out.append(((i + 1) * bs, h.hex()))
    return out


def resolve(entry, lba_bytes):
    """(object_slba, bytes) of the restore that reads the whole stored prefix."""
    return entry.slba + entry.offset // lba_bytes, entry.bytes


def _parse_line(text, number):
    words = text.split()
    if len(words) < 2 or words[0] != 'prefix' or not _HASH.fullmatch(words[1]):
        raise PrefixIndexError(f'line {number}: not a prefix record')
    fields = {}
    for word in words[2:]:
        key, sep, value = word.partition('=')
        if not sep or key in fields or key not in _KEYS + ('fnv1a',):
            raise PrefixIndexError(f'line {number}: bad or repeated field {word!r}')
        fields[key] = value
    if set(_KEYS) - set(fields):
        raise PrefixIndexError(f'line {number}: missing {sorted(set(_KEYS) - set(fields))}')
    if not _NAME.fullmatch(fields['object']):
        raise PrefixIndexError(f'line {number}: bad object name')
    numbers = {}
    for key in ('slba', 'offset', 'bytes', 'tokens'):
        if not fields[key].isdigit():
            raise PrefixIndexError(f'line {number}: {key} is not a number')
        numbers[key] = int(fields[key])
    digest = None
    if 'fnv1a' in fields:
        if not _DIGEST.fullmatch(fields['fnv1a']):
            raise PrefixIndexError(f'line {number}: fnv1a must be 0x and 16 hex digits')
        digest = int(fields['fnv1a'], 16)
    return Entry(words[1], fields['object'], numbers['slba'], numbers['offset'],
                 numbers['bytes'], numbers['tokens'], digest)


class PrefixIndex:
    def __init__(self, entries, model, staging, lba_bytes):
        self.model, self.staging, self.lba_bytes = model, staging, lba_bytes
        self._by_hash = {}
        for e in entries:
            if e.tokens < 1 or e.tokens % staging.block_size:
                raise PrefixIndexError(f'{e.hash}: {e.tokens} tokens are not whole blocks')
            if e.bytes != e.tokens * staging.bytes_per_token:
                raise PrefixIndexError(f'{e.hash}: {e.bytes} bytes for {e.tokens} tokens of '
                                       f'{staging.bytes_per_token} bytes')
            if e.offset % staging.block_bytes or e.offset % lba_bytes:
                raise PrefixIndexError(f'{e.hash}: offset {e.offset} is not on a block')
            if e.hash in self._by_hash:
                raise PrefixIndexError(f'{e.hash}: stored twice')
            self._by_hash[e.hash] = e

    @classmethod
    def load(cls, path, model, staging, lba_bytes):
        p = Path(path)
        if not p.is_file() or p.stat().st_size > MAX_INDEX_BYTES:
            raise PrefixIndexError(f'index must be a regular file of at most 64 MiB: {p}')
        lines = p.read_text().splitlines()
        expected = HEADER + canonical_dtype(staging.dtype)
        if not lines or lines[0].strip() != expected:
            raise PrefixIndexError(f'{p}: need {expected!r}; legacy or mismatched index must be '
                                   'rebuilt from a dump with verified dtype (keep original files)')
        entries = [_parse_line(line, n) for n, line in enumerate(lines[1:], 2)
                   if line.strip() and not line.lstrip().startswith('#')]
        return cls(entries, model, staging, lba_bytes)

    def __len__(self):
        return len(self._by_hash)

    def matches(self, tokens, max_tokens=None):
        """Entries of the stored prefixes of tokens (at most max_tokens), longest first."""
        for _, h in reversed(prefix_hashes(self.model, self.staging, tokens, max_tokens)):
            e = self._by_hash.get(h)
            if e is not None:
                yield e

    def longest_match(self, tokens, max_tokens=None):
        """The entry of the longest stored prefix of tokens (at most max_tokens), or None."""
        return next(self.matches(tokens, max_tokens), None)
