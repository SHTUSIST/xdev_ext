"""Pure host admission/oracle helpers. These do not attest physical hardware."""
import re

REVISION = '315fadfc5c5c018a64596157bfac94ecbb7d87a2'
U64 = (1 << 64) - 1

def uint(value, name, positive=True):
    if type(value) is not int or value < int(positive) or value > U64:
        raise ValueError(name + ': invalid unsigned 64-bit integer')
    return value

def plan_io(total_bytes, page_size, lba_size, region_start_lba, region_blocks):
    for name, value in locals().copy().items():
        uint(value, name, positive=name != 'region_start_lba')
    if page_size % lba_size or total_bytes % lba_size:
        raise ValueError('unaligned length')
    if page_size & (page_size - 1) or lba_size & (lba_size - 1):
        raise ValueError('page/LBA sizes must be powers of two')
    if region_start_lba > U64 - region_blocks or region_blocks > U64 // lba_size:
        raise ValueError('region overflow')
    if total_bytes > region_blocks * lba_size or page_size // lba_size > 65536:
        raise ValueError('transfer exceeds approved region or NVMe NLB')
    return [dict(offset=o, bytes=min(page_size,total_bytes-o),
                 lba=region_start_lba+o//lba_size,
                 blocks=min(page_size,total_bytes-o)//lba_size)
            for o in range(0,total_bytes,page_size)]

def verify_image(expected, actual, prefix, suffix):
    return (isinstance(expected, (bytes, bytearray)) and
            isinstance(actual, (bytes, bytearray)) and expected == actual and
            prefix == b'\xa5'*32 and suffix == b'\xa5'*32)

def qualify(receipt):
    if not isinstance(receipt, dict):
        raise ValueError('qualification must be an object')
    r = receipt.copy()
    for key in ('approved', 'exclusive', 'gpu_initiated', 'above_4g'):
        if r.get(key) is not True:
            raise ValueError(key + ' must be explicitly true')
    for key, value in dict(schema_version=1, upstream_revision=REVISION,
                           backend='bam-native', execution='physical',
                           iommu='disabled', acs='disabled').items():
        if type(r.get(key)) is not type(value) or r.get(key) != value:
            raise ValueError('invalid ' + key)
    if not isinstance(r.get('controller'), str) or not re.fullmatch(r'/dev/libnvm[0-9]+',r['controller']):
        raise ValueError('controller must be /dev/libnvmN')
    if not isinstance(r.get('gpu_uuid'), str) or not r['gpu_uuid'].startswith('GPU-') or len(r['gpu_uuid']) <= 4:
        raise ValueError('missing selected GPU UUID')
    for key in ('namespace_id','namespace_blocks','lba_size','page_size','region_blocks','cuda_capability'):
        uint(r.get(key), key)
    uint(r.get('region_start_lba'), 'region_start_lba', False)
    if r['page_size'] > 65536 or r['lba_size'] > 65536:
        raise ValueError('native adapter page/LBA size exceeds 64 KiB')
    if r['namespace_id'] > 0xfffffffe or r['cuda_capability'] < 70:
        raise ValueError('invalid namespace or pre-Volta GPU')
    if r.get('direction') not in ('read','write') or type(r.get('allow_write')) is not bool:
        raise ValueError('missing direction/write decision')
    if r['direction'] == 'write' and r['allow_write'] is not True:
        raise ValueError('separate explicit write permission required')
    if r.get('timeout_policy','none') != 'none' or r.get('timeout_seconds') is not None:
        raise ValueError('bounded cancellation/drain unsupported: timeout rejected')
    if r['region_start_lba'] > r['namespace_blocks'] - r['region_blocks']:
        raise ValueError('region exceeds namespace capacity')
    # Validate geometry without allocating a plan for an arbitrarily large region.
    plan_io(r['lba_size'],r['page_size'],r['lba_size'],r['region_start_lba'],r['region_blocks'])
    return r

def completion_policy(state):
    if state not in ('unknown','accepted','error','success'):
        raise ValueError('invalid completion state')
    return dict(reclaim=state in ('error','success'), resubmit=False, success=state=='success')
