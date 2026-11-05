"""Counted, reversible fixture facts for the explicit typed DATA contract.

This module neither imports production/extractors nor implements a device algorithm.
The complete immutable raw fixture is the only accepted migration input.
"""
import hashlib
import re

CONTRACT = 'typed-data-v1'
TRANSFORM_VERSION = 'count-typed-data-v1'
RAW_SHA256 = '1efa6aa4cd946dd5bfeaa8d37ed794ce1e69933aff14157181502c92f9fdb8f2'
GOLDEN_BYTES = 90093
GOLDEN_SHA256 = '66b024a622d5b206786011a26c81fd01747fdd724da1e65bf0bb2e28cf34f11e'


class FixtureContractError(Exception):
    """A source/receipt mismatch is setup failure, never semantic acceptance."""


# Exact CONTRACT.md spans, scoped to the complete named raw function.
TRANSFORMS = (
    ('T1', 'reliable_enqueue_cases',
     b'  for(int i=0;i<count;i++){d[i]=(struct xdp_desc){22,58,0};}\n'
     b'  tb.control=control;observed_provider=NULL;\n',
     b'  for(int i=0;i<count;i++){d[i]=(struct xdp_desc){control ? 22 : (u64)i*4096+22,58,0};}\n'
     b'  if (!control) {\n'
     b'   tb.batch=&batch;batch.nr_frames=count;\n'
     b'   for(u32 i=0;i<(u32)count;i++)\n'
     b'    batch.f[i]=(struct xdev_ext_mech_frame){.kaddr=public_chunks[i],.umem_addr=(u64)i*4096,.index=i,.data_off=64,.data_len=16,.pool_priv=&public_heads[i]};\n'
     b'  }\n'
     b'  tb.control=control;observed_provider=NULL;\n'),
    ('T2', 'reliable_enqueue_cases',
     b'  CHECK("reliable_terminal_once",reliable_done_count==1&&!callbacks&&!count_ops&&p.ring.cons==(u32)count);snapshot("complete");\n',
     b'  CHECK("reliable_terminal_once",reliable_done_count==1&&!callbacks&&count_ops==(control?0:count)&&count_bytes==(control?0:16*count)&&p.ring.cons==(u32)count);snapshot("complete");\n'),
    ('T3', 'public_wrap_mixed',
     b' struct xsk_xdev_ext_mech_tx_batch a={0},b={.control=true};struct xdp_desc pair[2]={{22,58,0},{4118,58,0}};\n',
     b' struct xsk_xdev_ext_mech_tx_batch a={.batch=&batch},b={.control=true};struct xdp_desc pair[2]={{22,58,0},{4118,58,0}};\n'),
    ('T4', 'public_wrap_mixed',
     b' good_reset("public_u32_origin_translation");observed_provider=NULL;p.ring.prod=p.ring.issued=p.ring.cons=UINT32_MAX-1;a=(struct xsk_xdev_ext_mech_tx_batch){0};\n',
     b' good_reset("public_u32_origin_translation");observed_provider=NULL;p.ring.prod=p.ring.issued=p.ring.cons=UINT32_MAX-1;a=(struct xsk_xdev_ext_mech_tx_batch){.batch=&batch};\n'),
)


def _sha(source):
    return hashlib.sha256(source).hexdigest()


def _function_bounds(source, name):
    # Same comment/string-aware balanced delimiter rule as the public extractor.
    declaration = re.compile(rb'^static void ' + re.escape(name.encode('ascii')) +
                             rb'\(void\)\s*\{', re.M)
    matches = list(declaration.finditer(source))
    if len(matches) != 1:
        raise FixtureContractError('expected one complete function: ' + name)
    start = matches[0].start()
    brace = source.index(b'{', start)
    token = re.compile(rb'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for match in token.finditer(source, brace):
        if match.group() == b'{':
            depth += 1
        elif match.group() == b'}':
            depth -= 1
            if depth == 0:
                return start, match.end()
    raise FixtureContractError('unbalanced function: ' + name)


def _replace_scoped(source, transform_id, function, before, after):
    start, end = _function_bounds(source, function)
    body = source[start:end]
    before_count, after_count = body.count(before), body.count(after)
    if before_count != 1 or after_count != 0:
        raise FixtureContractError(transform_id + ': expected one old and zero new scoped spans')
    offset = start + body.index(before)
    changed = body.replace(before, after, 1)
    if changed.count(before) != 0 or changed.count(after) != 1:
        raise FixtureContractError(transform_id + ': replacement counts disagree')
    record = {
        'id': transform_id, 'function': function, 'scope_start': start,
        'scope_end': end, 'offset': offset,
        'before': before.decode('ascii'), 'after': after.decode('ascii'),
        'before_count': before_count, 'after_count': after_count,
        'result_before_count': changed.count(before),
        'result_after_count': changed.count(after),
    }
    return source[:start] + changed + source[end:], record


def _apply(source, reverse=False):
    records = []
    entries = reversed(TRANSFORMS) if reverse else TRANSFORMS
    for transform_id, function, before, after in entries:
        if reverse:
            before, after = after, before
        source, record = _replace_scoped(source, transform_id, function, before, after)
        records.append(record)
    if len(records) != 4:
        raise FixtureContractError('expected exactly four fixture transformations')
    return source, records


def _receipt(raw, generated, forward, inverse):
    return {
        'fixture_contract': CONTRACT, 'transform_version': TRANSFORM_VERSION,
        'raw_bytes': len(raw), 'raw_sha256': _sha(raw),
        'generated_bytes': len(generated), 'generated_sha256': _sha(generated),
        'forward_count': len(forward), 'inverse_count': len(inverse),
        'forward': forward, 'inverse': inverse, 'inverse_byte_equality': True,
    }


def migrate(raw):
    """Return the four-transform fixture and its complete forward/inverse receipt."""
    if _sha(raw) != RAW_SHA256:
        raise FixtureContractError('immutable raw fixture SHA256 mismatch')
    generated, forward = _apply(raw)
    restored, inverse = _apply(generated, reverse=True)
    if restored != raw:
        raise FixtureContractError('full inverse differs from immutable raw fixture')
    return generated, _receipt(raw, generated, forward, inverse)


def invert(generated, receipt):
    """Reject changed source/receipt and restore the exact immutable raw bytes."""
    if not isinstance(receipt, dict) or receipt.get('fixture_contract') != CONTRACT:
        raise FixtureContractError('wrong fixture receipt contract')
    if receipt.get('generated_sha256') != _sha(generated):
        raise FixtureContractError('generated fixture SHA256 mismatch')
    raw, inverse = _apply(generated, reverse=True)
    if _sha(raw) != RAW_SHA256:
        raise FixtureContractError('inverse immutable raw fixture SHA256 mismatch')
    rebuilt, forward = _apply(raw)
    if rebuilt != generated or receipt != _receipt(raw, generated, forward, inverse):
        raise FixtureContractError('fixture receipt or full inverse equality mismatch')
    return raw
