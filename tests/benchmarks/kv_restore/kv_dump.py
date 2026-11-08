#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Dump real KV from a vLLM run into the block-ordered layout of kv_layout.py.

  vllm   run vLLM (pinned VLLM_VERSION) offline on token-id prompts with
         XdevExtDumpConnector as a kv_producer connector; each prompt's KV,
         truncated to whole vLLM blocks, becomes one object file
         NAME.kv (pages in BlockLayout order), NAME.tokens (u32 LE token ids)
         and NAME.json (model, layout, layer names, sha256)
  pack   place dumped objects in host 1's KV window (each on a group slot) and
         write the manifest (objects with "kv" and "payload") and the prefix
         index (one entry per requested prefix length and per whole prompt,
         with the FNV-1a of the prefix bytes); run.py prepare-nvme then writes
         the payload files to the namespace

The connector dumps a request once its whole prompt has been prefilled: the
scheduler side follows the request's blocks over chunked-prefill steps and
hands the block ids and token ids to the worker side in the step's metadata;
the worker side reads each (block, layer) page from the registered per-layer
caches after that step's forward (wait_for_save) and writes it at
BlockLayout.page_offset. vLLM 0.33.0 views each layer's cache as
[B, H, N, C] (vllm/v1/worker/utils.py, vllm/v1/kv_cache_interface.py), so a
page is cache[block_id], H * N * C bytes; read_page refuses any other size.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from typing import NamedTuple

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_layout', HERE / 'kv_layout.py')
kl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kl)

VLLM_VERSION = '0.33.0'     # the version the dump connector is written against
CHUNK = 64 << 20

try:
    from vllm.distributed.kv_transfer.kv_connector.v1.base import (
        KVConnectorBase_V1, KVConnectorMetadata, KVConnectorRole)
    _VLLM_SEEN = getattr(sys.modules.get('vllm'), '__version__', None)
except ImportError:
    KVConnectorBase_V1 = KVConnectorMetadata = KVConnectorRole = None
    _VLLM_SEEN = None


def check_vllm_version(version):
    if version != VLLM_VERSION:
        raise SystemExit(f'kv_dump is written against vLLM {VLLM_VERSION}, found {version}')


# ---- writing one object -------------------------------------------------------

class LayoutWriter:
    """One object file of nblocks blocks; every page written exactly once."""

    def __init__(self, path, layout, nblocks):
        layout.check()
        self.path, self.layout, self.nblocks = Path(path), layout, nblocks
        self._done = set()
        self._fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.ftruncate(self._fd, nblocks * layout.block_bytes)

    def put_page(self, block, layer, data):
        if not 0 <= block < self.nblocks:
            raise kl.LayoutError(f'block {block} outside the {self.nblocks}-block object')
        if len(data) != self.layout.page_bytes:
            raise kl.LayoutError(f'page of {len(data)} bytes, layout has {self.layout.page_bytes}')
        if (block, layer) in self._done:
            raise kl.LayoutError(f'page ({block}, {layer}) written twice')
        off = self.layout.page_offset(block, layer)
        if os.pwrite(self._fd, data, off) != len(data):
            raise OSError(f'short write at {off}')
        self._done.add((block, layer))

    def finish(self):
        """Close the file and return its SHA-256; every page must have been written."""
        missing = self.nblocks * self.layout.layers - len(self._done)
        if missing:
            raise kl.LayoutError(f'{missing} pages of {self.path.name} were never written')
        os.fsync(self._fd)
        os.close(self._fd)
        self._fd = None
        return sha256_file(self.path)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK), b''):
            h.update(chunk)
    return h.hexdigest()


def prefix_fnv1a(path, lengths, tool=None):
    """FNV-1a 64 of the first n bytes for each n, in one pass (C tool if given)."""
    want = sorted(set(lengths))
    if tool:
        r = subprocess.run([str(tool), 'fnv', str(path)] + [str(n) for n in want],
                           capture_output=True, text=True, check=True)
        got = json.loads(r.stdout)['fnv1a']
        return {n: int(v, 16) for n, v in zip(want, got)}
    out, h, pos, i = {}, kl.FNV_OFFSET, 0, 0
    with open(path, 'rb') as f:
        while i < len(want):
            chunk = f.read(min(CHUNK, want[-1] - pos))
            if not chunk:
                raise kl.LayoutError(f'{path} is shorter than {want[-1]} bytes')
            at = 0
            while i < len(want) and want[i] <= pos + len(chunk):
                h = kl.fnv1a64(chunk[at:want[i] - pos], h)
                at = want[i] - pos
                out[want[i]] = h
                i += 1
            h = kl.fnv1a64(chunk[at:], h)
            pos += len(chunk)
    return out


def write_tokens(path, token_ids):
    Path(path).write_bytes(struct.pack(f'<{len(token_ids)}I', *token_ids))


def read_tokens(path):
    data = Path(path).read_bytes()
    if len(data) % 4:
        raise kl.LayoutError(f'{path} is not whole u32 token ids')
    return list(struct.unpack(f'<{len(data) // 4}I', data))


_LAYER = re.compile(r'(?:^|\.)(\d+)(?:\.|$)')


def layer_order(names):
    """Attention layer names in model order (by their layer number)."""
    keyed = {}
    for n in names:
        m = _LAYER.search(n)
        if not m:
            raise kl.LayoutError(f'no layer number in {n!r}')
        if int(m.group(1)) in keyed:
            raise kl.LayoutError(f'layer {m.group(1)} named twice')
        keyed[int(m.group(1))] = n
    return [keyed[k] for k in sorted(keyed)]


def dump_object(out_dir, model, layout, layer_names, caches, read_page, block_ids, token_ids,
                vllm_version):
    """Write one object (whole blocks of token_ids) and its sidecar; returns the sidecar."""
    if layout.dtype is None:
        raise kl.LayoutError('dump needs an explicit, validated KV dtype')
    for name in layer_names:
        if kl.canonical_dtype(getattr(caches[name], 'dtype', None)) != layout.dtype:
            raise kl.LayoutError(f'{name}: actual tensor dtype disagrees with dump layout dtype')
    nblocks = len(token_ids) // layout.block_size
    tokens = token_ids[:nblocks * layout.block_size]
    digest = kl.prefix_hashes(model, layout, tokens)[-1][1]
    name = f'{model}-{digest[:16]}'
    out = Path(out_dir)
    for suffix in ('.kv', '.tokens', '.json'):
        if (out / (name + suffix)).exists():
            raise kl.LayoutError(f'{name}{suffix} exists: this prompt was dumped already')
    w = LayoutWriter(out / f'{name}.kv', layout, nblocks)
    try:
        for b in range(nblocks):
            for layer, lname in enumerate(layer_names):
                w.put_page(b, layer, read_page(caches[lname], block_ids[b]))
        sha = w.finish()
    except BaseException:
        if w._fd is not None:
            os.close(w._fd)
        (out / f'{name}.kv').unlink()
        raise
    write_tokens(out / f'{name}.tokens', tokens)
    meta = {'schema': 1, 'kind': 'kv-dump', 'name': name, 'model': model,
            'vllm': vllm_version, 'kv': layout.to_json(), 'layers': list(layer_names),
            'tokens': len(tokens), 'bytes': nblocks * layout.block_bytes,
            'file': f'{name}.kv', 'tokens_file': f'{name}.tokens', 'sha256': sha,
            'prefix_hash': digest, 'source': 'vllm-kv-connector'}
    tmp = out / f'{name}.json.tmp'
    tmp.write_text(json.dumps(meta, indent=1) + '\n')
    tmp.replace(out / f'{name}.json')
    return meta


def torch_page_bytes(cache, block_id):
    """Page block_id of one layer's [B, H, N, C] cache, in logical [H, N, C] byte order."""
    import torch
    return cache[block_id].contiguous().view(torch.uint8).cpu().numpy().tobytes()


# ---- the vLLM connector ---------------------------------------------------------

class DumpJob(NamedTuple):
    req_id: str
    block_ids: list
    token_ids: list


if KVConnectorBase_V1 is not None:
    class DumpMetadata(KVConnectorMetadata):
        def __init__(self, jobs):
            self.jobs = jobs

    class XdevExtDumpConnector(KVConnectorBase_V1):
        """kv_producer connector: dumps each prompt's KV once it is prefilled.

        kv_connector_extra_config: out_dir (existing directory), model (a
        kv_layout.ARCH key). Loads nothing (get_num_new_matched_tokens is 0).
        """

        def __init__(self, vllm_config, role, kv_cache_config=None):
            super().__init__(vllm_config, role, kv_cache_config)
            extra = vllm_config.kv_transfer_config.kv_connector_extra_config or {}
            self.out_dir = Path(extra['out_dir'])
            self.model = extra['model']
            dtype = kl.resolved_dtype(vllm_config, extra.get('kv_dtype'))
            if dtype not in ('bfloat16', 'float16'):
                raise kl.LayoutError(f'the approved model layout needs BF16 or FP16, got {dtype}')
            self.layout = kl.BlockLayout.for_model(self.model,
                                                   vllm_config.cache_config.block_size, dtype)
            self.layout.check()
            self.read_page = torch_page_bytes
            self._track = {}
            self._caches = self._layers = None

        # scheduler side
        def get_num_new_matched_tokens(self, request, num_computed_tokens):
            return 0, False

        def update_state_after_alloc(self, request, blocks, num_external_tokens):
            return None

        def build_connector_meta(self, scheduler_output):
            so = scheduler_output
            for new in so.scheduled_new_reqs:
                self._track[new.req_id] = {
                    'tokens': list(new.prompt_token_ids or []),
                    'blocks': list(new.block_ids[0]),
                    'done': getattr(new, 'num_computed_tokens', 0) +
                    so.num_scheduled_tokens.get(new.req_id, 0),
                    'dumped': False}
            cached = so.scheduled_cached_reqs
            for i, rid in enumerate(cached.req_ids):
                st = self._track.get(rid)
                if st is None:
                    continue
                nb = cached.new_block_ids[i]
                if rid in cached.resumed_req_ids:
                    st['blocks'] = list(nb[0]) if nb else []
                elif nb:
                    st['blocks'] += list(nb[0])
                st['done'] = cached.num_computed_tokens[i] + so.num_scheduled_tokens.get(rid, 0)
            jobs = []
            bs = self.layout.block_size
            for rid, st in self._track.items():
                whole = len(st['tokens']) // bs
                if st['dumped'] or not whole or st['done'] < len(st['tokens']):
                    continue
                st['dumped'] = True
                jobs.append(DumpJob(rid, st['blocks'][:whole], st['tokens'][:whole * bs]))
            return DumpMetadata(jobs)

        def request_finished(self, request, block_ids):
            self._track.pop(request.request_id, None)
            return False, None

        # worker side
        def register_kv_caches(self, kv_caches):
            names = layer_order(list(kv_caches))
            if len(names) != self.layout.layers:
                raise kl.LayoutError(f'{len(names)} attention layers, {self.model} has '
                                     f'{self.layout.layers}')
            for name in names:
                if kl.canonical_dtype(getattr(kv_caches[name], 'dtype', None)) != self.layout.dtype:
                    raise kl.LayoutError(f'{name}: cache tensor dtype disagrees with resolved '
                                         f'{self.layout.dtype}')
            self._caches, self._layers = kv_caches, names

        def start_load_kv(self, forward_context, **kwargs):
            return None

        def wait_for_layer_load(self, layer_name):
            return None

        def save_kv_layer(self, layer_name, kv_layer, attn_metadata, **kwargs):
            return None

        def wait_for_save(self):
            for job in self._get_connector_metadata().jobs:
                dump_object(self.out_dir, self.model, self.layout, self._layers, self._caches,
                            self.read_page, job.block_ids, job.token_ids,
                            _VLLM_SEEN or VLLM_VERSION)


# ---- pack: manifest and prefix index -------------------------------------------

def _load_dump(path):
    meta = json.loads(Path(path).read_text())
    if not isinstance(meta, dict) or meta.get('kind') != 'kv-dump' or meta.get('schema') != 1:
        return None
    model = meta['model']
    if model not in kl.MODELS:
        raise kl.LayoutError(f'{path}: unknown model {model!r}')
    layout = kl._parse_kv(meta['kv'], model, f'{path}: kv')
    f = Path(path).parent / meta['file']
    if f.stat().st_size != meta['bytes'] or meta['bytes'] != meta['tokens'] * layout.bytes_per_token \
            or meta['tokens'] % layout.block_size:
        raise kl.LayoutError(f'{f}: size does not match {meta["tokens"]} tokens')
    if sha256_file(f) != meta['sha256']:
        raise kl.LayoutError(f'{f}: SHA-256 differs from the dump record')
    tokens = read_tokens(Path(path).parent / meta['tokens_file'])
    if len(tokens) != meta['tokens']:
        raise kl.LayoutError(f'{path}: token file holds {len(tokens)} ids')
    hashes = dict(kl.prefix_hashes(model, layout, tokens))
    if meta.get('prefix_hash') != hashes.get(meta['tokens']):
        raise kl.LayoutError(f'{path}: prefix hash disagrees with tokens/layout/dtype metadata')
    return meta, layout, f, tokens


def pack(dump_dirs, manifest_path, index_path, window_slba, window_nlb, lba_bytes, group_bytes,
         prefixes, fnv_tool=None):
    dumps = []
    for d in dump_dirs:
        for p in sorted(Path(d).glob('*.json')):
            got = _load_dump(p)
            if got:
                dumps.append(got)
    if not dumps:
        raise kl.LayoutError('no kv-dump records found')
    manifest_dir = Path(manifest_path).resolve().parent
    bpg = group_bytes // lba_bytes
    if group_bytes % lba_bytes:
        raise kl.LayoutError('group_bytes must be whole LBAs')
    cur, end = window_slba, window_slba + window_nlb
    objects, entries = [], []
    for meta, layout, f, tokens in dumps:
        if layout.dtype is None:
            raise kl.LayoutError('legacy dump missing KV dtype; re-dump with dtype validation; '
                                 'keep the original files')
        if objects and layout.dtype != objects[0]['kv']['dtype']:
            raise kl.LayoutError('one typed index cannot mix KV dtypes')
        layout.validate(group_bytes)
        if meta['bytes'] % group_bytes:
            raise kl.LayoutError(f'{meta["name"]}: whole prompt must be whole restore groups '
                                 f'({meta["bytes"]} bytes, group_bytes={group_bytes})')
        nlb = -(-meta['bytes'] // group_bytes) * bpg
        if cur + nlb > end:
            raise kl.LayoutError(f'the window ends before {meta["name"]} fits')
        objects.append({'name': meta['name'], 'model': meta['model'], 'tokens': meta['tokens'],
                        'seed': 0, 'slba': cur, 'nlb': nlb, 'kv': layout.to_json(),
                        'payload': {'file': os.path.relpath(f.resolve(), manifest_dir),
                                    'sha256': meta['sha256']}})
        bs, bpt = layout.block_size, layout.bytes_per_token
        lengths = sorted({p for p in prefixes
                          if 0 < p <= meta['tokens'] and not p % bs and not p * bpt % group_bytes}
                         | {meta['tokens']})
        hashes = dict(kl.prefix_hashes(meta['model'], layout, tokens))
        digests = prefix_fnv1a(f, [n * bpt for n in lengths], fnv_tool)
        entries += [kl.IndexEntry(hashes[n], meta['name'], cur, 0, n * bpt, n, digests[n * bpt])
                    for n in lengths]
        cur += nlb
    data = {'schema': 1, 'kind': 'kv-layout', 'lba_bytes': lba_bytes,
            'window': {'slba': window_slba, 'nlb': window_nlb}, 'objects': objects}
    tmp = Path(str(manifest_path) + '.tmp')
    tmp.write_text(json.dumps(data, indent=1) + '\n')
    tmp.replace(manifest_path)
    m = kl.load_manifest(manifest_path)
    kl.write_index(index_path, entries, kv_dtype=objects[0]['kv']['dtype'])
    kl.load_index(index_path, m)
    return m


# ---- the vLLM driver ------------------------------------------------------------

def read_prompts(path):
    out = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        rec = json.loads(line)
        ids = rec.get('token_ids')
        if not isinstance(rec.get('name'), str) or not isinstance(ids, list) or not ids or \
                any(type(t) is not int or t < 0 or t > kl.U32 for t in ids):
            raise kl.LayoutError(f'{path}:{n}: need "name" and "token_ids" (u32 list)')
        out.append((rec['name'], ids))
    return out


def cmd_vllm(args):
    import vllm
    check_vllm_version(vllm.__version__)
    from vllm import LLM, SamplingParams
    from vllm.config import KVTransferConfig
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    prompts = read_prompts(args.prompts)
    layout = kl.BlockLayout.for_model(args.model, args.block_size, args.kv_dtype)
    names = {name: f'{args.model}-{kl.prefix_hashes(args.model, layout, ids)[-1][1][:16]}'
             for name, ids in prompts if len(ids) >= args.block_size}
    (out / 'prompts.json').write_text(json.dumps(names, indent=1) + '\n')
    os.environ['PYTHONPATH'] = os.pathsep.join(
        [str(HERE)] + [p for p in os.environ.get('PYTHONPATH', '').split(os.pathsep) if p])
    sys.path.insert(0, str(HERE))
    llm = LLM(model=args.hf_model, dtype=args.kv_dtype, kv_cache_dtype=args.kv_dtype,
              block_size=args.block_size, enable_prefix_caching=False,
              max_model_len=args.max_model_len,
              kv_transfer_config=KVTransferConfig(
                  kv_connector='XdevExtDumpConnector', kv_connector_module_path='kv_dump',
                  kv_role='kv_producer',
                  kv_connector_extra_config={'out_dir': str(out.resolve()), 'model': args.model,
                                             'kv_dtype': args.kv_dtype}))
    llm.generate([{'prompt_token_ids': ids} for _, ids in prompts],
                 SamplingParams(max_tokens=1, temperature=0.0))
    missing = [n for n, obj in names.items() if not (out / f'{obj}.json').is_file()]
    if missing:
        raise SystemExit(f'no dump for prompts {missing}')
    print(json.dumps({'out': str(out), 'objects': names}))
    return 0


def cmd_pack(args):
    m = pack(args.dumps, args.manifest, args.index, args.window_slba, args.window_nlb,
             args.lba_bytes, args.group_bytes, args.prefixes, args.fnv_tool)
    print(json.dumps({'manifest': args.manifest, 'index': args.index,
                      'objects': [o.name for o in m.objects]}))
    return 0


def _ints(text):
    return [int(v) for v in text.split(',') if v]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    v = sub.add_parser('vllm')
    v.add_argument('--hf-model', required=True, help='Hugging Face id or local path')
    v.add_argument('--model', required=True, choices=sorted(kl.ARCH))
    v.add_argument('--prompts', required=True, help='JSONL: {"name": ..., "token_ids": [...]}')
    v.add_argument('--out', required=True)
    v.add_argument('--block-size', type=int, default=16)
    v.add_argument('--kv-dtype', choices=('bfloat16', 'float16'), default='bfloat16')
    v.add_argument('--max-model-len', type=int, default=None)
    k = sub.add_parser('pack')
    k.add_argument('--dumps', nargs='+', required=True)
    k.add_argument('--manifest', required=True)
    k.add_argument('--index', required=True)
    k.add_argument('--window-slba', type=int, required=True)
    k.add_argument('--window-nlb', type=int, required=True)
    k.add_argument('--lba-bytes', type=int, default=512)
    k.add_argument('--group-bytes', type=int, default=128 << 10)
    k.add_argument('--prefixes', type=_ints, default=list(kl.PREFIX_TOKENS))
    k.add_argument('--fnv-tool', help='build/kv_plan_cli, for fast FNV-1a of large objects')
    args = p.parse_args(argv)
    return cmd_vllm(args) if args.cmd == 'vllm' else cmd_pack(args)


if __name__ == '__main__':
    sys.exit(main())
