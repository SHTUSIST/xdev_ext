"""Closed root-frozen expected-byte gates; never imports a producer/extractor.

The complete old-byte/field inverse and exact current bytes are checked before
any producer invocation. Candidate output cannot repair any expectation.
"""
import base64
import binascii
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from typed_fixture import GOLDEN_BYTES, GOLDEN_SHA256

CONTRACT = 'typed-control-v2'
OUTER = (
    ('retained-prefix', 1, 256), ('C01', 256, 261), ('C02', 261, 328),
    ('retained-middle', 328, 400), ('C03', 400, 406), ('C04', 406, 411),
    ('C05', 411, 416), ('C06/peek3pending1', 416, 427),
    ('C06/tail', 427, 438), ('C06/head2', 438, 449),
    ('C06/control', 449, 460), ('C07/wrapped3', 460, 471),
    ('C07/across_hole', 471, 482), ('C07/done', 482, 493),
    ('C08/before_stop', 493, 504), ('C08/stopped', 504, 516),
    ('retained-suffix', 516, 761),
)
TOP_KEYS = set('arbitrary_row_masks changed_groups current_candidate_executed expected inserted_rows old old_rows outer_parts profile retired_rows role schema version'.split())
PART_KEYS = set('current_end current_start end expected_b64 first_line id mode next_line old_b64 rows start'.split())
ROW_KEYS = set('current_end current_start disposition expected_b64 fields kind old_b64 old_end old_line old_start'.split())
ATOM_KEYS = set('clause current_local_end current_local_start expected_b64 mode name old_b64 old_end old_start'.split())
SEMANTIC_KEYS = 'id ret preserved packet_ok ring state busy uncertain meta refs completion cas_try cas_ok return_ok puts dev cpu ops payload_bytes dead'.split()
PUBLIC_RECORD_IDS = tuple('''publication.control0 C01/complete C02/refused
C03/control_done C04/control_done C05/control_done C06/peek3pending1 C06/tail
C06/head2 C06/control C07/wrapped3 C07/across_hole C07/done C08/before_stop
C08/stopped C10/count2 C10/count32 C10/count0 C11/foreign C11/detached C12/stage
C12/batch C12/false-helper C13/busy C13/uncertain C13/lease C14/state C14/index
C14/partition C14/window C15/payload C15/header58 C16/layout C16/105 C16/4097
C17/options C17/105 C17/107 C17/below C17/u32 C17/offset C17/other-span
C18/device C18/socket C18/head C19/vaddr C19/size C19/kaddr C20/inflight
C20/free C20/sequestered C21/full C21/fatal C21/stopped C22/refused C24/complete
C24/late C25/error C25/late C26/stop C23/helper C23/enqueue C26/late C27/overcount
C27/late C28/set-only C28/complete C28/late C29/single C29/late C30/direct
C30/late C32/stopped C32/late C29/companion C31/stopped C33/one-field
C33/historical'''.split())
FIELD_SCHEMA_KEYS = set('metadata_only old_line_inventory outer_ids outer_parts profile schema version'.split())
FIELD_PART_KEYS = {'id', 'mode', 'rows'}
FIELD_ROW_KEYS = set('atoms disposition insertion_ordinal kind old_line row_ordinal'.split())
FIELD_ATOM_KEYS = set('category clause component format_ordinal mode name ordinal parent'.split())
RECEIPT_SCHEMA_KEYS = set('schema profile placement jsonl_key_order record_ids serialization records max_line_bytes max_file_bytes tri_state owner_id ring completion_per_control meta_per_control dma_tuple counter_scope ret preserved packet_ok unknown_missing_extra_reordered'.split())
REQUIRED_ARTIFACTS = {'control_preproducer.json', 'partition-and-fields.json',
                      'field-schema.json', 'receipt-schema.json',
                      'typed-control-v2.expected.stdout', 'typed-data-v1.inverse.stdout',
                      'semantic-receipts.expected.jsonl', 'semantic-records.json',
                      'control_vectors.h'}


class ExpectedSetupError(Exception):
    pass


def _require(condition, message):
    if not condition:
        raise ExpectedSetupError('PREPRODUCER_PARTITION_UNFROZEN: ' + message)


def _b64(value):
    _require(isinstance(value, str), 'literal base64 string required')
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ExpectedSetupError('PREPRODUCER_MISSING: invalid literal base64') from error


def _keys(value, keys, label):
    _require(isinstance(value, dict) and set(value) == keys, label + ' closed key set')


def _integer(value):
    return type(value) is int


def _range(start, end, limit, label):
    _require(_integer(start) and _integer(end) and 0 <= start <= end <= limit, label + ' bounded range')


def _root_hashes(source):
    """Load only the ROOT-owned SOURCE pin module, never a data manifest pin."""
    source = Path(source)
    try:
        _require(source.is_file(), 'ROOT control_freeze.py missing')
        spec = importlib.util.spec_from_file_location('_count_control_root_freeze', source)
        _require(spec is not None and spec.loader is not None, 'ROOT freeze SOURCE loader missing')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pins = module.ARTIFACT_SHA256
    except ExpectedSetupError:
        raise
    except Exception as error:
        raise ExpectedSetupError('PREPRODUCER_PARTITION_UNFROZEN: ROOT control_freeze.py invalid: ' + str(error)) from error
    _require(isinstance(pins, dict) and set(pins) == REQUIRED_ARTIFACTS, 'ROOT artifact pin inventory missing/extra/unknown')
    for name, digest in pins.items():
        _require(isinstance(name, str) and Path(name).name == name and name not in ('', '.', '..'), 'ROOT artifact basename required')
        _require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) is not None, 'ROOT artifact SHA256 identity required')
    return dict(pins)


def _trusted_artifacts(directory):
    pins = _root_hashes(Path(__file__).with_name('control_freeze.py'))
    artifacts = {}
    for name, digest in pins.items():
        try:
            content = (Path(directory) / name).read_bytes()
        except OSError as error:
            raise ExpectedSetupError('PREPRODUCER_PARTITION_UNFROZEN: pinned artifact missing: ' + name) from error
        _require(hashlib.sha256(content).hexdigest() == digest, 'ROOT-pinned artifact hash mismatch: ' + name)
        artifacts[name] = content
    return artifacts


def _canonical_json(raw, label):
    try:
        text = raw.decode('utf-8')
        doc = json.loads(text)
    except (UnicodeError, ValueError) as error:
        raise ExpectedSetupError('PREPRODUCER_PARTITION_UNFROZEN: invalid ' + label) from error
    _require(json.dumps(doc, sort_keys=True, indent=2) + '\n' == text, 'canonical sorted-key ' + label)
    return doc


def _receipt_metadata(doc):
    _keys(doc, RECEIPT_SCHEMA_KEYS, 'receipt schema')
    arrays = {'jsonl_key_order', 'record_ids', 'ring', 'completion_per_control', 'meta_per_control', 'dma_tuple'}
    numbers = {'records', 'max_line_bytes', 'max_file_bytes'}
    dictionaries = {'tri_state', 'owner_id'}
    for key in RECEIPT_SCHEMA_KEYS - arrays - numbers - dictionaries:
        _require(isinstance(doc[key], str) and doc[key], 'receipt string ' + key)
    for key in arrays:
        _require(isinstance(doc[key], list) and all(isinstance(value, str) and value for value in doc[key]) and len(set(doc[key])) == len(doc[key]), 'receipt ordered string array ' + key)
    for key in numbers:
        _require(_integer(doc[key]) and doc[key] > 0, 'receipt positive integer ' + key)
    for key in dictionaries:
        _require(isinstance(doc[key], dict) and doc[key] and all(isinstance(name, str) and name and isinstance(value, str) for name, value in doc[key].items()), 'ROOT-pinned receipt closed string dictionary ' + key)
    _keys(doc['tri_state'], {'-1', '0', '1'}, 'receipt tri-state meanings')
    _keys(doc['owner_id'], {'0', '1', '2'}, 'receipt owner identities')
    _require(doc['profile'] == CONTRACT and doc['jsonl_key_order'] == SEMANTIC_KEYS, 'receipt profile/key order')
    _require(tuple(doc['record_ids']) == PUBLIC_RECORD_IDS and doc['records'] == len(PUBLIC_RECORD_IDS), 'complete receipt schema/public input ID equality')
    for name, width in (('ring', 6), ('completion_per_control', 7), ('meta_per_control', 6), ('dma_tuple', 3)):
        _require(len(doc[name]) == width, 'receipt fixed tuple shape ' + name)
    return tuple(doc['record_ids'])


def _row(row, old, expected, old_at, current_at, line, part_first):
    _keys(row, ROW_KEYS, 'row')
    _require(row['disposition'] in ('field_exact', 'named_insertion', 'explicit_count32_refusal_no_counterpart'), 'row disposition')
    _require(isinstance(row['kind'], str) and row['kind'], 'row kind')
    new_bytes = _b64(row['expected_b64'])
    _range(row['current_start'], row['current_end'], len(expected), 'current row')
    _require(row['current_start'] == current_at and expected[current_at:row['current_end']] == new_bytes, 'current row contiguity/identity')
    inserted = row['old_line'] is None
    if inserted:
        _require(row['old_start'] is None and row['old_end'] is None and row['old_b64'] is None and row['disposition'] == 'named_insertion', 'named insertion old coordinates')
        original = b''
    else:
        _require(_integer(row['old_line']), 'integer original line')
        _range(row['old_start'], row['old_end'], len(old), 'old row')
        original = _b64(row['old_b64'])
        _require(row['old_line'] == line and row['old_start'] == old_at and old[old_at:row['old_end']] == original and original.endswith(b'\n') and original.count(b'\n') == 1, 'old exact row/line contiguity')
    _require(isinstance(row['fields'], list) and row['fields'], 'complete row atoms required')
    atom_old, atom_current = old_at, 0
    for atom in row['fields']:
        _keys(atom, ATOM_KEYS, 'atom')
        _require(isinstance(atom['name'], str) and atom['name'] and isinstance(atom['clause'], str) and atom['clause'], 'named source clause/field')
        _require(atom['mode'] in ('old_byte_equal', 'independent_literal', 'named_insertion', 'explicit_count32_refusal_no_counterpart'), 'atom mode')
        if atom['old_start'] is None:
            _require(atom['old_end'] is None and atom['old_b64'] is None and atom['mode'] == 'named_insertion', 'insertion atom old coordinates')
            before = None
        else:
            _range(atom['old_start'], atom['old_end'], len(old), 'old atom')
            before = _b64(atom['old_b64'])
            _require(not inserted and atom['old_start'] == atom_old and old[atom_old:atom['old_end']] == before and atom['old_end'] <= row['old_end'], 'old atom contiguity/identity')
            atom_old = atom['old_end']
        if atom['current_local_start'] is None:
            _require(atom['current_local_end'] is None and atom['expected_b64'] is None and atom['mode'] == 'explicit_count32_refusal_no_counterpart' and part_first == 261, 'explicit C02 retirement atom')
            after = None
        else:
            _range(atom['current_local_start'], atom['current_local_end'], len(new_bytes), 'current atom')
            after = _b64(atom['expected_b64'])
            _require(atom['current_local_start'] == atom_current and new_bytes[atom_current:atom['current_local_end']] == after, 'current atom contiguity/identity')
            atom_current = atom['current_local_end']
        if atom['mode'] == 'old_byte_equal':
            _require(before is not None and after is not None and before == after, 'retained atom literal equality')
    _require(atom_current == len(new_bytes) and (inserted or atom_old == row['old_end']), 'no row atom remainder')
    if row['disposition'] == 'explicit_count32_refusal_no_counterpart':
        _require(part_first == 261 and not new_bytes, 'only declared C02 rows retire')
    return (old_at if inserted else row['old_end'], row['current_end'], line if inserted else line + 1)


def _semantic(raw, expected_ids=PUBLIC_RECORD_IDS):
    _require(raw.endswith(b'\n') and len(raw) <= 262144, 'complete bounded semantic LF stream')
    ids = []
    for line in raw.splitlines(keepends=True):
        try:
            record = json.loads(line)
        except (ValueError, UnicodeError) as error:
            raise ExpectedSetupError('invalid independent semantic JSONL') from error
        _keys(record, set(SEMANTIC_KEYS), 'semantic receipt')
        _require(list(record) == SEMANTIC_KEYS and json.dumps(record, separators=(',', ':')).encode('ascii') + b'\n' == line, 'fixed compact semantic key order/bytes')
        _require(isinstance(record['id'], str) and record['id'] not in ids, 'unique semantic ID')
        ids.append(record['id'])
        _require(record['ret'] is None or _integer(record['ret']), 'integer-or-null actual return')
        for name in ('preserved', 'packet_ok'):
            _require(_integer(record[name]) and record[name] in (-1, 0, 1), 'tri-state ' + name)
        for name, width in (('ring', 6), ('state', 2), ('busy', 2), ('uncertain', 2), ('refs', 2), ('puts', 2)):
            _require(isinstance(record[name], list) and len(record[name]) == width and all(_integer(x) for x in record[name]), 'integer vector ' + name)
        for name, width in (('meta', 6), ('completion', 7)):
            _require(isinstance(record[name], list) and len(record[name]) == 2 and all(isinstance(row, list) and len(row) == width and all(_integer(x) for x in row) for row in record[name]), 'per-owner vector ' + name)
        for name in ('dev', 'cpu'):
            _require(isinstance(record[name], list) and all(isinstance(row, list) and len(row) == 3 and all(_integer(x) for x in row) for row in record[name]), 'DMA vector ' + name)
        for name in ('cas_try', 'cas_ok', 'return_ok', 'ops', 'payload_bytes'):
            _require(_integer(record[name]) and record[name] >= 0, 'counter ' + name)
        _require(isinstance(record['dead'], list) and all(_integer(x) for x in record['dead']), 'ordered actual notification statuses')
    _require(tuple(ids) == tuple(expected_ids) == PUBLIC_RECORD_IDS, 'complete closed ordered semantic ID inventory')
    return ids


def _match_field_metadata(part, closed):
    """Compare candidate byte-manifest metadata to trusted independent metadata.

    Category/parent/component/format identities are themselves hash-pinned SOURCE
    facts. The byte manifest carries their exact ordered name/mode/clause tuple;
    it cannot rename a field or replace a component row with a whole-row atom.
    """
    _keys(closed, FIELD_PART_KEYS, 'closed field outer')
    _require(part['id'] == closed['id'] and part['mode'] == closed['mode'], 'closed outer identity/disposition')
    _require(isinstance(part['rows'], list) and isinstance(closed['rows'], list) and len(part['rows']) == len(closed['rows']), 'closed row inventory length')
    insertion = 0
    for index, (row, exact) in enumerate(zip(part['rows'], closed['rows'])):
        _keys(row, ROW_KEYS, 'byte row')
        _keys(exact, FIELD_ROW_KEYS, 'closed field row')
        inserted = row['old_line'] is None
        _require(exact['row_ordinal'] == index and _integer(exact['row_ordinal']), 'closed row ordinal')
        _require((row['old_line'], row['kind'], row['disposition']) == (exact['old_line'], exact['kind'], exact['disposition']), 'closed old line/kind/disposition')
        _require(exact['insertion_ordinal'] == (insertion if inserted else None), 'closed insertion ordinal')
        if inserted:
            _require(_integer(exact['insertion_ordinal']), 'integer insertion identity')
            insertion += 1
        _require(isinstance(row['fields'], list) and isinstance(exact['atoms'], list) and len(row['fields']) == len(exact['atoms']), 'closed ordered atom inventory length')
        format_index = 0
        for ordinal, (atom, fixed) in enumerate(zip(row['fields'], exact['atoms'])):
            _keys(atom, ATOM_KEYS, 'byte atom')
            _keys(fixed, FIELD_ATOM_KEYS, 'closed field atom')
            _require(fixed['ordinal'] == ordinal and _integer(fixed['ordinal']), 'closed atom ordinal')
            _require((atom['name'], atom['mode'], atom['clause']) == (fixed['name'], fixed['mode'], fixed['clause']), 'closed atom name/mode/source clause')
            _require(fixed['category'] in ('format', 'identity', 'tuple_component', 'value') and isinstance(fixed['parent'], str) and fixed['parent'], 'closed atom category/parent')
            if fixed['category'] == 'format':
                _require(fixed['name'] == '$format' and fixed['component'] is None and fixed['format_ordinal'] == format_index and _integer(fixed['format_ordinal']), 'closed exact format ordinal')
                format_index += 1
            else:
                _require(fixed['format_ordinal'] is None, 'nonformat atom identity')
                if fixed['category'] == 'tuple_component':
                    _require(isinstance(fixed['component'], str) and fixed['component'], 'closed tuple component identity')
                else:
                    _require(fixed['component'] is None, 'nontuple component identity')


def _field_metadata(doc, manifest):
    _keys(doc, FIELD_SCHEMA_KEYS, 'field schema')
    _require(doc['metadata_only'] is True and doc['profile'] == CONTRACT and isinstance(doc['schema'], str) and doc['schema'] and isinstance(doc['version'], str) and doc['version'], 'independent metadata-only field schema identity')
    _require(doc['old_line_inventory'] == list(range(1, 761)) and all(_integer(n) for n in doc['old_line_inventory']), 'closed complete old line inventory')
    _require(isinstance(doc['outer_ids'], list) and all(isinstance(identifier, str) and identifier for identifier in doc['outer_ids']) and doc['outer_ids'] == [part['id'] for part in manifest['outer_parts']] and len(set(doc['outer_ids'])) == len(OUTER), 'closed complete outer ID order')
    _require(isinstance(doc['outer_parts'], list) and len(doc['outer_parts']) == len(OUTER), 'closed field outer inventory length')
    for part, fixed in zip(manifest['outer_parts'], doc['outer_parts']):
        _match_field_metadata(part, fixed)


def load_frozen(path):
    """Read only root-supplied frozen bytes; called before producer generation."""
    path = Path(path)
    _require(path.name == 'control_preproducer.json', 'unknown artifact basename')
    # All bytes are SHA-checked against trusted SOURCE before JSON/field use.
    artifacts = _trusted_artifacts(path.parent)
    doc = _canonical_json(artifacts['control_preproducer.json'], 'byte manifest')
    vectors = artifacts['control_vectors.h']
    stdout = artifacts['typed-control-v2.expected.stdout']
    semantic = artifacts['semantic-receipts.expected.jsonl']
    field_schema = _canonical_json(artifacts['field-schema.json'], 'field schema')
    receipt_schema = _canonical_json(artifacts['receipt-schema.json'], 'receipt schema')
    record_ids = _receipt_metadata(receipt_schema)
    _require(artifacts['partition-and-fields.json'] == artifacts['control_preproducer.json'], 'descriptive byte-manifest alias identity')
    _keys(doc, TOP_KEYS, 'manifest')
    _require(doc['schema'] == 'count-control-preproducer-v2' and doc['profile'] == CONTRACT and doc['arbitrary_row_masks'] is False and doc['current_candidate_executed'] is False, 'source-only independent manifest identity/no masks')
    _require(isinstance(doc['role'], str) and doc['role'] and isinstance(doc['version'], str) and doc['version'], 'manifest role/version')
    _keys(doc['old'], {'bytes', 'lines', 'sha256'}, 'old identity')
    _keys(doc['expected'], {'bytes', 'lines', 'sha256', 'stdout_b64'}, 'expected identity')
    _require(doc['old'] == {'bytes': GOLDEN_BYTES, 'lines': 760, 'sha256': GOLDEN_SHA256}, 'immutable old identity')
    expected = _b64(doc['expected']['stdout_b64'])
    _require(stdout == expected and len(expected) == doc['expected']['bytes'] and expected.count(b'\n') == doc['expected']['lines'] and hashlib.sha256(expected).hexdigest() == doc['expected']['sha256'] and expected.endswith(b'\n'), 'complete independent expected bytes/identity')
    parts = doc['outer_parts']
    _require(isinstance(parts, list) and len(parts) == len(OUTER), 'seventeen outer parts')
    for part in parts:
        _keys(part, PART_KEYS, 'outer part')
    old = b''.join(_b64(part['old_b64']) for part in parts)
    _require(len(old) == GOLDEN_BYTES and old.count(b'\n') == 760 and hashlib.sha256(old).hexdigest() == GOLDEN_SHA256, 'complete old byte inverse/identity')
    _require(artifacts['typed-data-v1.inverse.stdout'] == old, 'ROOT-pinned complete old inverse sidecar')
    _field_metadata(field_schema, doc)
    boundaries = [0]
    for line in old.splitlines(keepends=True):
        boundaries.append(boundaries[-1] + len(line))
    old_at = current_at = inserted = retired = 0
    seen = set()
    for part, (label, first, end) in zip(parts, OUTER):
        _keys(part, PART_KEYS, 'outer part')
        _require(isinstance(part['id'], str) and part['id'] not in seen, 'unique outer ID')
        seen.add(part['id'])
        original, changed = _b64(part['old_b64']), _b64(part['expected_b64'])
        _range(part['start'], part['end'], len(old), 'outer old')
        _range(part['current_start'], part['current_end'], len(expected), 'outer current')
        _require((part['first_line'], part['next_line'], part['start'], part['end']) == (first, end, boundaries[first-1], boundaries[end-1]) and part['start'] == old_at and original == old[old_at:part['end']], 'exact old outer anchor ' + label)
        _require(_integer(part['first_line']) and _integer(part['next_line']), 'integer outer line boundaries')
        _require(part['current_start'] == current_at and changed == expected[current_at:part['current_end']], 'exact current outer coverage ' + label)
        _require(part['mode'] == ('retain' if label.startswith('retained-') else 'field_contract'), 'outer disposition ' + label)
        if part['mode'] == 'retain':
            _require(original == changed, 'retained outer byte equality ' + label)
        _require(isinstance(part['rows'], list) and part['rows'], 'complete outer rows')
        line = first
        for row in part['rows']:
            old_at, current_at, line = _row(row, old, expected, old_at, current_at, line, first)
            inserted += row['old_line'] is None
            retired += row['disposition'] == 'explicit_count32_refusal_no_counterpart'
        _require((old_at, current_at, line) == (part['end'], part['current_end'], end), 'outer row remainder ' + label)
    _require(old_at == len(old) and current_at == len(expected), 'no full-stream remainder')
    _require(doc['old_rows'] == 760 and doc['changed_groups'] == 14 and all(_integer(doc[k]) and doc[k] >= 0 for k in ('old_rows', 'changed_groups', 'inserted_rows', 'retired_rows')), 'declared inventory counts')
    _require(doc['inserted_rows'] == inserted and doc['retired_rows'] == retired and 760 + inserted - retired == doc['expected']['lines'], 'complete row insertion/retirement counts')
    _require(vectors and b'count_control_v2_ordinary_expected_backing' in vectors and b'count_control_v2_reliable_expected_backing' in vectors, 'independent literal vector header missing')
    _require(len(semantic) <= receipt_schema['max_file_bytes'] and all(len(line) <= receipt_schema['max_line_bytes'] for line in semantic.splitlines(keepends=True)), 'ROOT-pinned receipt byte bounds')
    ids = _semantic(semantic, record_ids)
    return {'expected_stdout': expected, 'expected_semantic': semantic,
            'vectors_header': vectors, 'semantic_ids': ids, 'manifest': doc}


def compare_stdout(observed, frozen):
    expected = frozen['expected_stdout']
    if observed == expected:
        return []
    limit = min(len(observed), len(expected))
    at = next((i for i in range(limit) if observed[i] != expected[i]), limit)
    return ['independent current/retained bytes differ at byte %d (observed=%d expected=%d)' %
            (at, len(observed), len(expected))]
