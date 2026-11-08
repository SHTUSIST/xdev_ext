# SPDX-License-Identifier: GPL-2.0
"""Correctness hook: greedy first tokens after a restore must equal those of recompute.

    python -m xdev_kv_vllm.verify generate --model M --prompts prompts.json \
        --out restored.json --kv-transfer-config '{...XdevExtConnector...}' --stats-file S
    python -m xdev_kv_vllm.verify generate --model M --prompts prompts.json --out recompute.json
    python -m xdev_kv_vllm.verify compare --restored restored.json --recompute recompute.json

prompts.json: {"prompts": [{"id": ..., "token_ids": [...], "prefix_tokens": P}]},
P being the stored prefix the restored run must load. generate runs vLLM
offline at temperature 0, one prompt at a time, and records each prompt's
output token ids and the connector's load rows (xdev_ext.stats_file) written
while it ran. compare passes a prompt only when the restored run loaded exactly
P tokens with no failed load (a silent fallback to recompute is not a pass)
and the first N tokens (default 16) are identical; it exits 1 otherwise.
"""
import argparse
import json
from pathlib import Path
import sys


def _problem(restored, recompute, n):
    loads = restored.get('loads') or []
    if any(not row.get('ok') for row in loads):
        return 'a load failed', None
    if not any(row.get('ok') and row.get('end_token') == restored.get('prefix_tokens')
               for row in loads):
        return f'prefix of {restored.get("prefix_tokens")} tokens not loaded', None
    a, b = restored['output_token_ids'][:n], recompute['output_token_ids'][:n]
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return f'token {i} differs: {x} != {y}', i
    if len(a) != len(b):
        return f'{len(a)} != {len(b)} tokens', min(len(a), len(b))
    return '', None


def compare(restored_runs, recompute_runs, n=16):
    restored = {r['id']: r for r in restored_runs}
    recompute = {r['id']: r for r in recompute_runs}
    verdict = {'ok': bool(restored) and restored.keys() == recompute.keys(), 'tokens': n,
               'checked': 0, 'prompts': {}}
    if restored.keys() != recompute.keys():
        verdict['missing'] = sorted(restored.keys() ^ recompute.keys())
    for pid in sorted(restored.keys() & recompute.keys()):
        problem, first = _problem(restored[pid], recompute[pid], n)
        verdict['prompts'][pid] = {'ok': not problem, 'problem': problem, 'first_mismatch': first}
        verdict['checked'] += 1
        verdict['ok'] = verdict['ok'] and not problem
    return verdict


def _stats_rows(path, start):
    if not path or not Path(path).exists():
        return [], start
    with open(path, 'rb') as f:
        f.seek(start)
        data = f.read()
    return [json.loads(line) for line in data.decode().splitlines() if line.strip()], start + len(data)


def generate(args):
    from vllm import LLM, SamplingParams
    from vllm.inputs import TokensPrompt
    prompts = json.loads(Path(args.prompts).read_text())['prompts']
    kw = dict(model=args.model, enable_prefix_caching=True, max_model_len=args.max_model_len,
              gpu_memory_utilization=args.gpu_memory_utilization)
    if args.kv_transfer_config:
        kw['kv_transfer_config'] = json.loads(args.kv_transfer_config)
    llm = LLM(**kw)
    params = SamplingParams(temperature=0.0, max_tokens=args.tokens)
    runs, offset = [], _stats_rows(args.stats_file, 0)[1]
    for p in prompts:
        out = llm.generate([TokensPrompt(prompt_token_ids=p['token_ids'])], params, use_tqdm=False)
        loads, offset = _stats_rows(args.stats_file, offset)
        runs.append({'id': p['id'], 'prefix_tokens': p.get('prefix_tokens'),
                     'output_token_ids': list(out[0].outputs[0].token_ids), 'loads': loads})
    Path(args.out).write_text(json.dumps({'model': args.model, 'runs': runs}, indent=1))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    g = sub.add_parser('generate')
    g.add_argument('--model', required=True)
    g.add_argument('--prompts', required=True)
    g.add_argument('--out', required=True)
    g.add_argument('--kv-transfer-config')
    g.add_argument('--stats-file')
    g.add_argument('--tokens', type=int, default=16)
    g.add_argument('--max-model-len', type=int, default=None)
    g.add_argument('--gpu-memory-utilization', type=float, default=0.8)
    c = sub.add_parser('compare')
    c.add_argument('--restored', required=True)
    c.add_argument('--recompute', required=True)
    c.add_argument('--tokens', type=int, default=16)
    args = p.parse_args(argv)
    if args.cmd == 'generate':
        return generate(args)
    verdict = compare(json.loads(Path(args.restored).read_text())['runs'],
                      json.loads(Path(args.recompute).read_text())['runs'], args.tokens)
    print(json.dumps(verdict, indent=1))
    return 0 if verdict['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
