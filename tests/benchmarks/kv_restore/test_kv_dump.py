#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""kv_dump.py: real KV from a vLLM run into the block-ordered layout, then the
manifest and prefix index that prepare-nvme, kv_restore and the connector use.

No GPU and no vLLM here: a fake model writes deterministic pages (a function
of the layer and the block's token ids) into fake per-layer caches, and a fake
``vllm`` package supplies only the KVConnectorBase_V1 surface the dump
connector uses (vLLM 0.33.0 base.py). The fake engine drives the connector the
way vLLM's scheduler and worker call it: scheduler-side build_connector_meta
per step, worker-side register_kv_caches once and wait_for_save after each
forward, with a chunked prefill and blocks allocated over two steps.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
KIB = 1 << 10


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_fake_vllm():
    """Just the names kv_dump imports from vllm, shaped like vLLM 0.33.0."""
    class KVConnectorRole:
        SCHEDULER = 0
        WORKER = 1

    class KVConnectorMetadata:
        pass

    class KVConnectorBase_V1:
        def __init__(self, vllm_config, role, kv_cache_config):
            self._vllm_config = vllm_config
            self._kv_transfer_config = vllm_config.kv_transfer_config
            self._kv_cache_config = kv_cache_config
            self._role = role
            self._connector_metadata = None

        def bind_connector_metadata(self, meta):
            self._connector_metadata = meta

        def clear_connector_metadata(self):
            self._connector_metadata = None

        def _get_connector_metadata(self):
            assert self._connector_metadata is not None
            return self._connector_metadata

    base = types.ModuleType('vllm.distributed.kv_transfer.kv_connector.v1.base')
    base.KVConnectorBase_V1 = KVConnectorBase_V1
    base.KVConnectorMetadata = KVConnectorMetadata
    base.KVConnectorRole = KVConnectorRole
    names = ['vllm', 'vllm.distributed', 'vllm.distributed.kv_transfer',
             'vllm.distributed.kv_transfer.kv_connector',
             'vllm.distributed.kv_transfer.kv_connector.v1']
    saved = {n: sys.modules.get(n) for n in names + [base.__name__]}
    for n in names:
        sys.modules[n] = types.ModuleType(n)
    sys.modules['vllm'].__version__ = '0.33.0'
    sys.modules[base.__name__] = base
    return saved


def restore_modules(saved):
    for n, m in saved.items():
        if m is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = m


_saved = install_fake_vllm()
try:
    kd = load('kv_dump')
finally:
    restore_modules(_saved)
kl = kd.kl

LAYOUT = kl.BlockLayout.for_model('qwen3-8b-bf16', 16)
LAYER_NAMES = [f'model.layers.{i}.self_attn.attn' for i in range(LAYOUT.layers)]


def fake_page(layer, block_tokens):
    """What the fake model's attention writes for one layer of one block."""
    seed = hashlib.sha256(f'{layer}:{block_tokens}'.encode()).digest()
    return (seed * (LAYOUT.page_bytes // len(seed) + 1))[:LAYOUT.page_bytes]


class FakeLayerCache:
    """One layer's paged cache: block id -> page bytes."""

    def __init__(self):
        self.pages = {}


def read_fake_page(cache, block_id):
    return cache.pages.get(block_id, b'\0' * LAYOUT.page_bytes)


def forward(caches, tokens, blocks, start, count):
    """The fake model computes KV for tokens [start, start + count)."""
    for b in range(start // 16, (start + count) // 16):
        for layer, name in enumerate(LAYER_NAMES):
            caches[name].pages[blocks[b]] = fake_page(layer, tuple(tokens[b * 16:(b + 1) * 16]))


def ns(**kw):
    return types.SimpleNamespace(**kw)


class Engine:
    """A scheduler-side and a worker-side connector driven like vLLM's steps."""

    def __init__(self, out_dir, model='qwen3-8b-bf16'):
        transfer = ns(kv_role='kv_producer', is_kv_producer=True,
                      kv_connector_extra_config={'out_dir': str(out_dir), 'model': model})
        config = ns(kv_transfer_config=transfer, cache_config=ns(block_size=16))
        self.sched = kd.XdevExtDumpConnector(config, kd.KVConnectorRole.SCHEDULER, None)
        self.work = kd.XdevExtDumpConnector(config, kd.KVConnectorRole.WORKER, None)
        self.work.read_page = read_fake_page
        self.caches = {n: FakeLayerCache() for n in reversed(LAYER_NAMES)}
        self.work.register_kv_caches(self.caches)

    def step(self, out, work=()):
        meta = self.sched.build_connector_meta(out)
        for args in work:
            forward(self.caches, *args)
        self.work.bind_connector_metadata(meta)
        self.work.wait_for_save()
        self.work.clear_connector_metadata()
        return meta


def tokens_of(n, base=1000):
    return [base + (i * 7919) % 50000 for i in range(n)]


class Writer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-dump-')
        self.path = Path(self.tmp.name) / 'obj.kv'

    def tearDown(self):
        self.tmp.cleanup()

    def test_pages_land_at_their_offsets(self):
        w = kd.LayoutWriter(self.path, LAYOUT, 2)
        for b in (1, 0):
            for layer in reversed(range(LAYOUT.layers)):
                w.put_page(b, layer, fake_page(layer, (b,)))
        sha = w.finish()
        data = self.path.read_bytes()
        self.assertEqual(len(data), 2 * LAYOUT.block_bytes)
        off = LAYOUT.page_offset(1, 5)
        self.assertEqual(data[off:off + LAYOUT.page_bytes], fake_page(5, (1,)))
        self.assertEqual(sha, hashlib.sha256(data).hexdigest())

    def test_refusals(self):
        w = kd.LayoutWriter(self.path, LAYOUT, 1)
        with self.assertRaises(kl.LayoutError):
            w.put_page(0, 0, b'x' * (LAYOUT.page_bytes - 1))
        with self.assertRaises(kl.LayoutError):
            w.put_page(1, 0, fake_page(0, ()))
        w.put_page(0, 0, fake_page(0, ()))
        with self.assertRaises(kl.LayoutError):
            w.put_page(0, 0, fake_page(0, ()))
        with self.assertRaises(kl.LayoutError):
            w.finish()                                  # 35 pages missing
        with self.assertRaises(FileExistsError):
            kd.LayoutWriter(self.path, LAYOUT, 1)

    def test_layer_order(self):
        names = ['model.layers.10.self_attn.attn', 'model.layers.2.self_attn.attn',
                 'model.layers.0.self_attn.attn']
        self.assertEqual(kd.layer_order(names), sorted(names, key=lambda n: int(n.split('.')[2])))
        for bad in (['attn'], ['model.layers.1.a', 'model.layers.1.b']):
            with self.subTest(bad=bad), self.assertRaises(kl.LayoutError):
                kd.layer_order(bad)


class Connector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-dump-conn-')
        self.out = Path(self.tmp.name) / 'dumps'
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_chunked_prefill_dumps_whole_blocks_in_order(self):
        e = Engine(self.out)
        prompt = tokens_of(52)                         # 3 whole blocks + 4 tokens
        blocks = [7, 3, 9, 12]
        self.assertEqual(e.sched.get_num_new_matched_tokens(ns(request_id='a'), 0), (0, False))
        new = ns(req_id='a', prompt_token_ids=prompt, block_ids=([7, 3],),
                 num_computed_tokens=0)
        m1 = e.step(ns(scheduled_new_reqs=[new], num_scheduled_tokens={'a': 32},
                       scheduled_cached_reqs=ns(req_ids=[], resumed_req_ids=set(),
                                                new_block_ids=[], num_computed_tokens=[])),
                    [(prompt, blocks, 0, 32)])
        self.assertEqual(m1.jobs, [], 'nothing until the prompt is prefilled')
        self.assertEqual(list(self.out.iterdir()), [])
        m2 = e.step(ns(scheduled_new_reqs=[], num_scheduled_tokens={'a': 20},
                       scheduled_cached_reqs=ns(req_ids=['a'], resumed_req_ids=set(),
                                                new_block_ids=[([9, 12],)],
                                                num_computed_tokens=[32])),
                    [(prompt, blocks, 32, 16)])
        self.assertEqual(len(m2.jobs), 1)
        self.assertEqual(m2.jobs[0].block_ids, [7, 3, 9])
        self.assertEqual(m2.jobs[0].token_ids, prompt[:48])
        meta, = (json.loads(p.read_text()) for p in self.out.glob('*.json'))
        self.assertEqual((meta['kind'], meta['model'], meta['tokens'], meta['vllm']),
                         ('kv-dump', 'qwen3-8b-bf16', 48, '0.33.0'))
        self.assertEqual(meta['kv'], LAYOUT.to_json())
        self.assertEqual(meta['layers'], LAYER_NAMES)
        data = (self.out / meta['file']).read_bytes()
        self.assertEqual(len(data), 3 * LAYOUT.block_bytes)
        for b in range(3):
            for layer in (0, 17, 35):
                off = LAYOUT.page_offset(b, layer)
                self.assertEqual(data[off:off + LAYOUT.page_bytes],
                                 fake_page(layer, tuple(prompt[b * 16:(b + 1) * 16])), (b, layer))
        self.assertEqual(kd.read_tokens(self.out / meta['tokens_file']), prompt[:48])
        # A later step does not dump the same request again.
        m3 = e.step(ns(scheduled_new_reqs=[], num_scheduled_tokens={'a': 1},
                       scheduled_cached_reqs=ns(req_ids=['a'], resumed_req_ids=set(),
                                                new_block_ids=[None], num_computed_tokens=[52])))
        self.assertEqual(m3.jobs, [])
        self.assertEqual(e.sched.request_finished(ns(request_id='a'), blocks), (False, None))

    def test_wrong_page_size_or_layers_refused(self):
        e = Engine(self.out)
        e.work.read_page = lambda cache, block: b'short'
        prompt = tokens_of(16)
        new = ns(req_id='b', prompt_token_ids=prompt, block_ids=([1],), num_computed_tokens=0)
        with self.assertRaises(kl.LayoutError):
            e.step(ns(scheduled_new_reqs=[new], num_scheduled_tokens={'b': 16},
                      scheduled_cached_reqs=ns(req_ids=[], resumed_req_ids=set(),
                                               new_block_ids=[], num_computed_tokens=[])),
                   [(prompt, [1], 0, 16)])
        w = Engine(self.out).work
        with self.assertRaises(kl.LayoutError):
            w.register_kv_caches({n: FakeLayerCache() for n in LAYER_NAMES[:-1]})

    def test_short_prompt_has_nothing_to_dump(self):
        e = Engine(self.out)
        new = ns(req_id='c', prompt_token_ids=tokens_of(15), block_ids=([1],),
                 num_computed_tokens=0)
        m = e.step(ns(scheduled_new_reqs=[new], num_scheduled_tokens={'c': 15},
                      scheduled_cached_reqs=ns(req_ids=[], resumed_req_ids=set(),
                                               new_block_ids=[], num_computed_tokens=[])))
        self.assertEqual(m.jobs, [])


class Pack(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-pack-')
        self.root = Path(self.tmp.name)
        self.out = self.root / 'dumps'
        self.out.mkdir()
        self.prompts = {'a': tokens_of(64, 1), 'b': tokens_of(48, 2)}
        e = Engine(self.out)
        for rid, prompt in self.prompts.items():
            blocks = list(range(100 * len(rid) + len(prompt), 100 * len(rid) + len(prompt) + 4))
            blocks = [b + (0 if rid == 'a' else 500) for b in blocks]
            new = ns(req_id=rid, prompt_token_ids=prompt, block_ids=(blocks,),
                     num_computed_tokens=0)
            e.step(ns(scheduled_new_reqs=[new], num_scheduled_tokens={rid: len(prompt)},
                      scheduled_cached_reqs=ns(req_ids=[], resumed_req_ids=set(),
                                               new_block_ids=[], num_computed_tokens=[])),
                   [(prompt, blocks, 0, len(prompt))])

    def tearDown(self):
        self.tmp.cleanup()

    def test_pack_writes_manifest_and_index(self):
        manifest, index = self.root / 'kv.json', self.root / 'kv.index'
        kd.pack([self.out], manifest, index, window_slba=2048, window_nlb=1 << 24, lba_bytes=512,
                group_bytes=128 * KIB, prefixes=[16, 32, 40])
        m = kl.load_manifest(manifest)
        self.assertEqual(len(m.objects), 2)
        for o in m.objects:
            self.assertEqual(o.kv, LAYOUT)
            self.assertEqual((o.slba - 2048) % (128 * KIB // 512), 0, 'objects start on a slot')
            self.assertEqual(o.bytes, o.tokens * LAYOUT.bytes_per_token)
            self.assertEqual(hashlib.sha256((manifest.parent / o.payload.file).read_bytes())
                             .hexdigest(), o.payload.sha256)
        idx = kl.load_index(index, m)
        # Prefixes 16 and 32 of both prompts plus each whole prompt; 40 is not whole blocks.
        self.assertEqual(sorted(e.tokens for e in idx.entries), [16, 16, 32, 32, 48, 64])
        for rid, prompt in self.prompts.items():
            hit = idx.longest_match('qwen3-8b-bf16', LAYOUT, prompt + [5, 6])
            self.assertEqual(hit.tokens, len(prompt))
            o = m.object(hit.object)
            data = (manifest.parent / o.payload.file).read_bytes()
            self.assertEqual(hit.fnv1a, kl.fnv1a64(data[:hit.bytes]))
            short = idx.longest_match('qwen3-8b-bf16', LAYOUT, prompt[:40])
            self.assertEqual((short.object, short.tokens), (hit.object, 32))
            self.assertEqual(short.fnv1a, kl.fnv1a64(data[:short.bytes]))
            slba, nbytes = kl.resolve(hit, m.lba_bytes)
            plan = kl.plan_restore(m, o.name, hit.tokens, kl.Geometry(128 * KIB, 4096, 32, 32, True),
                                   1, host2_ring=True)
            self.assertEqual((plan.object.slba, plan.bytes), (slba, nbytes))
            self.assertEqual(plan.kv_blocks, len(prompt) // 16)

    def test_pack_refuses_a_changed_dump(self):
        f = next(self.out.glob('*.kv'))
        with open(f, 'r+b') as fh:
            fh.write(b'\xff')
        with self.assertRaises(kl.LayoutError):
            kd.pack([self.out], self.root / 'kv.json', self.root / 'kv.index', window_slba=2048,
                    window_nlb=1 << 24, lba_bytes=512, group_bytes=128 * KIB, prefixes=[])

    def test_pack_refuses_a_small_window(self):
        with self.assertRaises(kl.LayoutError):
            kd.pack([self.out], self.root / 'kv.json', self.root / 'kv.index', window_slba=2048,
                    window_nlb=LAYOUT.block_bytes * 4 // 512, lba_bytes=512,
                    group_bytes=128 * KIB, prefixes=[])


class Digests(unittest.TestCase):
    def test_prefix_digests_in_one_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'f'
            data = bytes(range(256)) * 1000
            p.write_bytes(data)
            got = kd.prefix_fnv1a(p, [1, 4096, 100000, len(data)])
            self.assertEqual(got, {n: kl.fnv1a64(data[:n]) for n in (1, 4096, 100000, len(data))})
            self.assertEqual(kl.fnv1a64(b''), 0xCBF29CE484222325)
            self.assertEqual(kl.fnv1a64(b'a'), 0xAF63DC4C8601EC8C)   # FNV-1a 64 test vector


class VllmDriver(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(kd.VLLM_VERSION, '0.33.0')
        with self.assertRaises(SystemExit):
            kd.check_vllm_version('0.10.2')
        kd.check_vllm_version('0.33.0')

    def test_prompt_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'p.jsonl'
            p.write_text(json.dumps({'name': 'c1', 'token_ids': [1, 2, 3]}) + '\n')
            self.assertEqual(kd.read_prompts(p), [('c1', [1, 2, 3])])
            p.write_text(json.dumps({'name': 'c1', 'token_ids': [1, -2]}) + '\n')
            with self.assertRaises(kl.LayoutError):
                kd.read_prompts(p)


if __name__ == '__main__':
    unittest.main()
