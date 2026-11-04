"""Bounded local processes and fixed-source Mooncake evidence qualification."""
from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
import uuid

CONTRACT = 'mooncake-executor-v3'
REVISION = 'd01447808d10af78011e9203d53796a15a032a03'
STREAM_LIMIT = 64 << 20
NATIVE_LIMIT = 1 << 20
TERM_GRACE_SECONDS = 5
U64 = (1 << 64) - 1
I32 = (1 << 31) - 1


@dataclass(frozen=True)
class ExecutionContext:
    kind: str
    profile: str
    qualified_receipt: dict
    endpoint: str


@dataclass(frozen=True)
class ProcessOutcome:
    returncode: int | None
    termination: str
    stdout_file: str
    stderr_file: str
    elapsed_monotonic_ns: int
    cleanup_complete: bool
    signals: tuple = ()
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    error: str = ''
    native_bytes: int = 0


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def pairs_unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate JSON key: ' + key)
        obj[key] = value
    return obj


def read_bytes(path, limit=NATIVE_LIMIT):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(Path(path), flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('evidence must be a bounded ordinary file: ' + str(path))
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('evidence exceeds byte limit')
    return data


def read_json(path):
    def invalid_constant(value):
        raise ValueError('nonfinite JSON number: ' + value)
    obj = json.loads(read_bytes(path), object_pairs_hook=pairs_unique,
                     parse_constant=invalid_constant)
    if not isinstance(obj, dict):
        raise ValueError('evidence must be a JSON object')
    return obj


def _integer(value, name, minimum=1, maximum=U64):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('invalid integer: ' + name)
    return value


def validate_cell(cell):
    shape = cell['shape']
    block, batch = cell['block_bytes'], cell['batch_requests']
    _integer(block, 'block_bytes'); _integer(batch, 'batch_requests', maximum=I32)
    if shape['block_bytes'] != [block] or shape['batch_requests'] != [batch]:
        raise ValueError('scalar cell disagrees with shape')
    if shape.get('experiment', cell['experiment']) != cell['experiment']:
        raise ValueError('experiment disagrees with shape')
    _integer(shape['worker_threads'], 'worker_threads', maximum=I32)
    _integer(shape['duration_seconds'], 'duration_seconds', maximum=I32)
    return shape


def qualify_native(native_path, cell, expected_segment):
    """Qualify one exact native target_metrics row; never synthesize metrics."""
    try:
        shape = validate_cell(cell)
        raw = read_bytes(native_path)
        if not raw.endswith(b'\n') or len(raw.splitlines()) != 1 or not raw.strip():
            raise ValueError('native JSONL must contain exactly one complete line')
        row = read_json(native_path)
        root_keys = {'schema_version','record_type','backend','op_type','block_size',
                     'batch_size','num_threads','aggregate_operations',
                     'aggregate_transferred_bytes','aggregate_throughput_gbps','targets'}
        target_keys = {'index','segment_name','threads','operations','transferred_bytes',
                       'total_duration_us','throughput_gbps','avg_latency_us','avg_transfer_us',
                       'p99_us','p999_us','avg_instant_gbps'}
        if set(row) != root_keys:
            raise ValueError('native root keys differ from fixed source')
        _integer(row['schema_version'], 'schema_version')
        if (row['schema_version'],row['record_type'],row['backend']) != (1,'target_metrics','tent'):
            raise ValueError('wrong native schema/type/backend')
        wanted_op = 'read' if cell['experiment'] == 'e4' else 'write'
        if row['op_type'] != wanted_op:
            raise ValueError('wrong native operation')
        for key, wanted in (('block_size',cell['block_bytes']),
                            ('batch_size',cell['batch_requests']),
                            ('num_threads',shape['worker_threads'])):
            _integer(row[key], key, maximum=I32 if key == 'num_threads' else U64)
            if row[key] != wanted:
                raise ValueError('wrong native ' + key)
        if not isinstance(row['targets'], list) or len(row['targets']) != 1:
            raise ValueError('one target required')
        target = row['targets'][0]
        if not isinstance(target, dict) or set(target) != target_keys:
            raise ValueError('native target keys differ from fixed source')
        _integer(target['index'], 'index', minimum=0)
        _integer(target['threads'], 'threads', maximum=I32)
        if target['index'] != 0 or target['segment_name'] != expected_segment or target['threads'] != shape['worker_threads']:
            raise ValueError('wrong target identity or threads')
        for key in ('operations','transferred_bytes'):
            _integer(target[key], key)
            _integer(row['aggregate_' + key], 'aggregate_' + key)
            if target[key] != row['aggregate_' + key]:
                raise ValueError('aggregate target disagreement')
        count = target['operations'] * row['block_size'] * row['batch_size']
        if count > U64 or count != target['transferred_bytes']:
            raise ValueError('completed batch byte arithmetic disagrees')
        for obj, keys in ((target, ('total_duration_us','throughput_gbps','avg_latency_us',
                                  'avg_transfer_us','p99_us','p999_us','avg_instant_gbps')),
                          (row, ('aggregate_throughput_gbps',))):
            for key in keys:
                val = obj[key]
                if type(val) not in (int,float) or not math.isfinite(val) or val < 0:
                    raise ValueError('invalid finite metric: ' + key)
        duration = target['total_duration_us']
        if duration < shape['duration_seconds'] * 1000000 or target['throughput_gbps'] <= 0 or row['aggregate_throughput_gbps'] <= 0:
            raise ValueError('native duration/throughput does not establish progress')
        if target['p999_us'] < target['p99_us']:
            raise ValueError('native quantiles out of order')
        values = [(target['throughput_gbps'],count / (1000 * duration)),
                  (target['avg_latency_us'],duration * target['threads'] / target['operations']),
                  (row['aggregate_throughput_gbps'],target['throughput_gbps'])]
        if any(not math.isclose(a,b,rel_tol=1e-9,abs_tol=1e-9) for a,b in values):
            raise ValueError('native derived metric arithmetic disagrees')
        return {'result_qualification':'qualified','ratio_eligible':False,'native':row,'errors':[]}
    except (OSError,ValueError,TypeError,KeyError,OverflowError,RecursionError) as error:
        return {'result_qualification':'failed','ratio_eligible':False,'errors':[str(error)]}


class ReadyParser:
    """Incremental bounded-line banner reader; unrelated raw bytes remain raw."""
    def __init__(self):
        self.offset=0
        self.pending=bytearray()
        self.names=set()

    def _line(self, raw):
        clean=re.sub(rb'\x1b\[[0-9;]*m',b'',raw.rstrip(b'\r\n'))
        prefix=b'  ./tebench --target_seg_name='
        suffix=b' --seg_type=VRAM --backend=tent'
        if b'./tebench --target_seg_name=' not in clean:return
        try:line=clean.decode('utf-8')
        except UnicodeDecodeError as error:raise ValueError('required ready line is not UTF-8') from error
        if not clean.startswith(prefix):return
        if not clean.endswith(suffix):raise ValueError('malformed required target-ready line')
        value=line[len(prefix):-len(suffix)]
        if not value or any(c.isspace() or ord(c)<32 or ord(c)==127 or c in ',{}$`\\' for c in value):
            raise ValueError('invalid target segment token')
        self.names.add(value)
        if len(self.names)>1:raise ValueError('ambiguous target-ready banner')

    def update(self, path, final=False):
        fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>STREAM_LIMIT or info.st_size<self.offset:
                raise ValueError('invalid raw ready evidence size/type')
            stream.seek(self.offset)
            while True:
                chunk=stream.read(65536)
                if not chunk:break
                self.offset+=len(chunk)
                if self.offset>STREAM_LIMIT:raise ValueError('ready evidence exceeds byte bound')
                start=0
                while start<len(chunk):
                    end=chunk.find(b'\n',start)
                    stop=end+1 if end>=0 else len(chunk)
                    self.pending.extend(chunk[start:stop])
                    if len(self.pending)>NATIVE_LIMIT:raise ValueError('ready line exceeds parse bound')
                    if end>=0:
                        self._line(bytes(self.pending));self.pending.clear()
                    start=stop
        if final and self.pending:
            if self.pending.lstrip().startswith(b'./tebench --target_seg_name='):
                raise ValueError('incomplete required target-ready line')
        return next(iter(self.names)) if self.names else None


def parse_target_ready(stdout_path):
    segment=ReadyParser().update(stdout_path,final=True)
    if segment is None:raise ValueError('missing target-ready banner')
    return segment


def _private_directory(path):
    path = Path(path).absolute()
    for item in (path,*path.parents):
        if item.is_symlink():
            raise ValueError('output path contains a symlink')
    if path == Path('/'):
        raise ValueError('unsafe output directory')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    allowed = {'command.json','config.json','target-config.json'}
    if any(item.name not in allowed or item.is_symlink() or not item.is_file() for item in path.iterdir()):
        raise ValueError('existing execution artifacts are preserved')
    return path


def child_environment(command, context):
    env = {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
    supplied = command.get('env', {})
    if not isinstance(supplied, dict) or set(supplied)-{'MC_TENT_CONF','CUFILE_FORCE_COMPAT_MODE'}:
        raise ValueError('unsupported command environment')
    for key,value in supplied.items():
        if not isinstance(value,str) or '\x00' in value:
            raise ValueError('invalid environment value')
        env[key] = value
    dirs = context.qualified_receipt.get('library_search_dirs', [])
    if dirs:
        if not isinstance(dirs,list) or any(not isinstance(p,str) or ':' in p or 'stubs' in Path(p).parts for p in dirs):
            raise ValueError('invalid qualified runtime directories')
        env['LD_LIBRARY_PATH'] = ':'.join(dirs)
    return env


class Capture:
    """Own one process group and stream both pipes without unbounded buffering."""
    def __init__(self, argv, env, directory, timeout_seconds, native_path=None):
        if (not isinstance(argv,list) or not argv or
                any(not isinstance(x,str) or '\x00' in x for x in argv)):
            raise ValueError('argv must be a nonempty string array')
        if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError('finite positive process deadline required')
        self.directory = Path(directory)
        self.started = time.monotonic_ns()
        self.deadline = time.monotonic() + timeout_seconds
        self.native_path = native_path
        self.files = {}
        self.counts = {'stdout':0,'stderr':0}
        self.selector = selectors.DefaultSelector()
        self.process = None
        self.termination = 'exited'
        self.error = ''
        self.signals = []
        self.closed = False
        self.native_bytes = 0
        self.term_at = None
        self.kill_at = None
        self._io_lock=threading.RLock()
        self._finish_lock=threading.Lock()
        self._done=threading.Event()
        self._collector=None
        self._finished_outcome=None
        try:
            for name in self.counts:
                self.files[name] = (self.directory/(name+'.raw')).open('xb',buffering=0)
            self.process = subprocess.Popen(argv,cwd=self.directory,env=env,stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                            shell=False,start_new_session=True,close_fds=True)
            for name,pipe in (('stdout',self.process.stdout),('stderr',self.process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe,selectors.EVENT_READ,name)
        except (OSError,ValueError) as error:
            self.termination='spawn_error';self.error=str(error)
            if self.process is not None:
                self.terminate('spawn_error')
            else:
                self._close()

    def _signal(self, number):
        if self.process is not None:
            try:
                os.killpg(self.process.pid,number)
                self.signals.append(signal.Signals(number).name)
            except ProcessLookupError:
                pass

    def terminate(self, reason):
        with self._io_lock:
            if self.closed:return
            if self.termination == 'exited':self.termination=reason
            if self.term_at is None:
                self.term_at=time.monotonic()
                self._signal(signal.SIGTERM)

    def start_background(self):
        with self._io_lock:
            if self._collector is not None:raise ValueError('collector already started')
            self._collector=threading.Thread(target=self._collect,name='mooncake-owned-capture')
            self._collector.start()

    def _collect(self):
        try:
            while not self.closed:self.pump()
        except BaseException as error:
            self.error='capture collector failure: '+str(error)
            self._abort_owned('capture_error')

    def _abort_owned(self, reason):
        # Last-resort failure handling owns only this process group and always reaps.
        self.terminate(reason)
        if self.process is not None:
            try:self.process.wait(timeout=TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:pass
            self._signal(signal.SIGKILL)
            try:self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:self.error+='; failed to reap owned child'
        with self._io_lock:self._close()

    def pump(self, wait=.05):
        collector=self._collector
        if collector is not None and threading.current_thread() is not collector:
            self._done.wait(max(0,min(wait,.1)))
            return
        with self._io_lock:self._pump_once(wait)

    def _pump_once(self, wait=.05):
        if self.closed:
            return
        now=time.monotonic()
        if now >= self.deadline:
            self.terminate('timeout')
        self._check_native()
        if self.term_at is not None and now-self.term_at >= TERM_GRACE_SECONDS and self.kill_at is None:
            self._signal(signal.SIGKILL);self.kill_at=now
        for key,_ in self.selector.select(max(0,min(wait,.1))):
            pipe,name=key.fileobj,key.data
            try:
                data=os.read(pipe.fileno(),65536)
            except BlockingIOError:
                continue
            if not data:
                self.selector.unregister(pipe);pipe.close();continue
            before=self.counts[name];self.counts[name]+=len(data)
            remain=max(0,STREAM_LIMIT-before)
            if remain:
                self.files[name].write(data[:remain])
            if self.counts[name]>STREAM_LIMIT:
                self.terminate('output_limit')
        if self.process is not None:
            code=self.process.poll()
            self._check_native()
            if code is not None and not self.selector.get_map():
                # Clean up a surviving owned descendant even if it closed its pipes.
                try:
                    os.killpg(self.process.pid,0)
                except ProcessLookupError:
                    self._close();return
                self.terminate('descendants_remaining')
            if self.kill_at is not None and now-self.kill_at>2:
                self._close()

    def _check_native(self):
        if self.native_path is None:return
        try:
            info=self.native_path.lstat()
            if stat.S_ISREG(info.st_mode):self.native_bytes=max(self.native_bytes,info.st_size)
            if not stat.S_ISREG(info.st_mode) or info.st_size>NATIVE_LIMIT:
                self.terminate('output_limit')
        except FileNotFoundError:
            pass

    def _close(self):
        if self.closed:return
        for key in list(self.selector.get_map().values()):
            self.selector.unregister(key.fileobj);key.fileobj.close()
        self.selector.close()
        for stream in self.files.values():stream.close()
        self.closed=True
        self._done.set()

    def finish(self, reason=None):
        with self._finish_lock:
            if self._finished_outcome is not None:return self._finished_outcome
            if reason:self.terminate(reason)
            interrupted=None
            try:
                if self._collector is not None:
                    remaining=(TERM_GRACE_SECONDS+3 if self.term_at is not None else
                               max(0,self.deadline-time.monotonic())+TERM_GRACE_SECONDS+3)
                    self._collector.join(remaining)
                    if self._collector.is_alive():
                        self._abort_owned('capture_error')
                        self._collector.join(1)
                else:
                    while not self.closed:self.pump()
            except BaseException as error:
                interrupted=error
                self._abort_owned('interrupted' if isinstance(error,KeyboardInterrupt) else 'capture_error')
                if self._collector is not None:self._collector.join(1)
            code=None
            if self.process is not None:
                try:code=self.process.wait(timeout=.5)
                except subprocess.TimeoutExpired:self.error='failed to reap owned child'
            with self._io_lock:
                self._check_native()
                if self.native_path is not None and self.native_bytes>NATIVE_LIMIT and code is not None:
                    fd=os.open(self.native_path,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|os.O_NONBLOCK)
                    try:
                        if stat.S_ISREG(os.fstat(fd).st_mode):os.ftruncate(fd,NATIVE_LIMIT)
                    finally:os.close(fd)
            joined=self._collector is None or not self._collector.is_alive()
            self._finished_outcome=ProcessOutcome(code,self.termination,'stdout.raw','stderr.raw',
                                  time.monotonic_ns()-self.started,
                                  joined and (self.process is None or code is not None),
                                  tuple(self.signals),self.counts['stdout'],self.counts['stderr'],self.error,self.native_bytes)
            if interrupted is not None:raise interrupted
            return self._finished_outcome


def inspect_process(argv, directory, env=None, timeout_seconds=10):
    """Shared bounded capture for fixed read-only Git/readelf tools."""
    directory=Path(directory);directory.mkdir(parents=True,mode=0o700)
    capture=Capture(argv,env or {'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'},directory,timeout_seconds)
    result=capture.finish()
    write_json(directory/'process.json',asdict(result))
    return result


def _logs(directory):
    warning=[];failure=[];pool=[]
    def report(items, raw):
        if len(items)<32:items.append(raw.decode('utf-8',errors='replace').rstrip()[:4096])
    bad=(b'Failed to allocate transfer batch',b'Failed to submit transfer:',
         b'Failed to poll transfer:',b'Failed transfer detected',b'Skipped for block_size',
         b'target range is smaller than one operation',b'opened in Buffered I/O mode',
         b'no pinned staging pool',b'no free pinned staging slot',b'using a pageable buffer',
         b'staging with pageable buffers')
    pool_source=b'IOUringTransport: pinned staging pool of '
    for name in ('stdout.raw','stderr.raw'):
        with (Path(directory)/name).open('rb') as stream:
            while True:
                raw=stream.readline(NATIVE_LIMIT+1)
                if not raw:break
                if len(raw)>NATIVE_LIMIT:
                    failure.append('log line exceeds parse bound');break
                # ASCII disposition markers are meaningful even beside opaque raw bytes.
                if any(fragment in raw for fragment in bad):report(failure,raw)
                if re.match(rb'^[EF][0-9]{4} ',raw) or b'FATAL' in raw or raw.startswith(b'ERROR'):
                    report(failure,raw)
                if re.match(rb'^W[0-9]{4} ',raw) or b'WARNING' in raw:report(warning,raw)
                if pool_source in raw:
                    try:line=raw.decode('utf-8')
                    except UnicodeDecodeError:
                        failure.append('required pinned evidence line is not UTF-8');continue
                    match=re.search(r'^(?:I[0-9]{4,8} [0-9:.]+[ \t]+[0-9]+ [^\]\r\n]{1,256}\][ \t]+)?IOUringTransport: pinned staging pool of ([0-9]{1,20}) x ([0-9]{1,20}) KiB[ \t]*\r?\n?$',line)
                    if match:
                        dimensions=(int(match[1]),int(match[2]))
                        if dimensions not in pool and len(pool)<2:pool.append(dimensions)
    return warning,failure,pool


def _route(directory, cell, context):
    warnings,errors,pools=_logs(directory)
    shape=cell['shape'];arm=cell['arm']
    if arm=='iouring-pinned':
        slot=((shape['pinned_slot_kib']*1024+4095)//4096*4096)//1024
        if not pools or any(p!=(shape['pinned_slots'],slot) for p in pools):
            errors.append('missing or inconsistent pinned pool success evidence')
    elif arm=='iouring-default' and pools:
        errors.append('default route unexpectedly allocated a pinned pool')
    if warnings:errors.append('warnings require route review')
    if arm in ('gds-compat','tcp') and context.qualified_receipt.get('route_qualified') is not True:
        errors.append('route evidence is not qualified')
    return {'route_qualification':'route_unqualified' if errors else 'qualified',
            'warnings':warnings,'errors':errors}


def _context(cell, context):
    validate_cell(cell)
    if not isinstance(context,ExecutionContext) or context.kind not in ('physical','contract-fixture'):
        raise ValueError('invalid execution context')
    if not isinstance(context.qualified_receipt,dict):raise ValueError('context receipt must be an object')
    if context.profile!=cell['profile']:
        raise ValueError('context profile does not match cell')
    if context.kind=='physical' and context.qualified_receipt.get('qualified') is not True:
        raise ValueError('physical context requires checked qualification')


def _record_command(directory, command, argv, env, cell, target=False):
    path=directory/'command.json'
    if path.exists():
        prepared=read_json(path)
        if target:prepared=prepared.get('target_command',prepared)
        old=list(prepared.get('argv',[]))
        if not target:
            old=[('--target_seg_name='+cell['expected_segment'])
                 if value=='--target_seg_name={FRESH_TARGET_SEGMENT_NAME}' else value for value in old]
        if old!=command['argv'] or prepared.get('env',{})!=command.get('env',{}):
            raise ValueError('prepared command does not match selected execution')
    final=dict(command,argv=argv,env=env)
    if path.exists():
        pending=directory/'command.pending'
        write_json(pending,final)
        os.replace(pending,path)
    else:write_json(path,final)


def execute_cell(command, cell, context, output_dir, timeout_seconds):
    _context(cell,context)
    directory=_private_directory(output_dir)
    native=directory/'native.jsonl'
    argv=list(command['argv'])
    paths=[v.split('=',1)[1] for v in argv if v.startswith('--result_output_jsonl=')]
    if context.kind=='physical' and (len(paths)!=1 or Path(paths[0]).absolute()!=native):
        raise ValueError('native output must be the selected cell file')
    if any(Path(p).absolute()!=native for p in paths):
        raise ValueError('native output outside cell directory')
    env=child_environment(command,context)
    if argv[0]=='taskset':argv[0]='/usr/bin/taskset'
    _record_command(directory,command,argv,env,cell)
    capture=Capture(argv,env,directory,timeout_seconds,native)
    try:process=capture.finish()
    except KeyboardInterrupt:process=capture.finish('interrupted')
    write_json(directory/'process.json',asdict(process))
    native_result=qualify_native(native,cell,cell['expected_segment'])
    route=_route(directory,cell,context)
    ok=(process.termination=='exited' and process.returncode==0 and process.cleanup_complete
        and native_result['result_qualification']=='qualified' and not route['errors'])
    receipt=dict(schema_version=1,contract_version=CONTRACT,cell_id=cell['cell_id'],
                 profile=cell['profile'],experiment=cell['experiment'],arm=cell['arm'],
                 source_revision=REVISION,mode='run',
                 completion_contract='tebench-batch-completed',
                 access_contract='batch-random-with-replacement' if cell['experiment']=='e4' else 'fixed-target-write',
                 residency_qualification='retained-evidence-declared' if context.kind=='physical' else 'not_applicable',
                 execution=context.kind,status=('fixture_completed' if context.kind=='contract-fixture' else 'completed') if ok else 'failed',
                 performance_claim='standalone-baseline-only' if ok and context.kind=='physical' else 'none',
                 ratio_eligible=False,exit_code=0 if ok else 1,command_argv=argv,command_env=env,
                 shape=cell['shape'],rig_identity=cell.get('rig_identity',{}),process=asdict(process),
                 result_qualification=native_result['result_qualification'],
                 correctness_scope='executor-contract-only' if context.kind=='contract-fixture' else 'separate-upstream-roundtrip',
                 raw_evidence=['stdout.raw','stderr.raw','native.jsonl','process.json'],
                 route_requested=cell['arm'],route_qualification=route['route_qualification'],
                 warnings=route['warnings'],errors=native_result['errors']+route['errors'],
                 removed_environment_variables=sorted(key for key in os.environ
                     if key.startswith(('MC_','MOONCAKE_','CUDA_','CUFILE_','GFLAGS_','LD_')) and key not in env),
                 qualification=context.qualified_receipt)
    if process.termination!='exited' or process.returncode!=0 or not process.cleanup_complete:
        receipt['errors'].append('child disposition: '+process.termination+' returncode='+str(process.returncode))
    source_pending=ok and cell['experiment']=='e7'
    if source_pending:
        receipt.update(status='source_completed',performance_claim='none',
                       e7_qualification='awaiting_destination_final',target_lifetime_qualification='pending')
    if native_result['result_qualification']=='qualified':
        write_json(directory/'parsed-native.json',dict(execution=context.kind,performance_claim=receipt['performance_claim'],native=native_result['native']))
        if ok and context.kind=='physical' and not source_pending:receipt['native_metrics']=native_result['native']
    write_json(directory/'receipt.json',receipt)
    return receipt


@dataclass
class TargetHandle:
    process: subprocess.Popen
    ready_receipt: dict
    capture: object
    output_dir: Path
    cell: dict
    context: ExecutionContext


def start_target(command, cell, context, output_dir):
    _context(cell,context)
    if context.endpoint!='destination' or cell['experiment']!='e7':
        raise ValueError('target requires an E7 destination context')
    directory=_private_directory(output_dir)
    actual=command.get('target_command',command)
    argv=list(actual['argv'])
    if argv[0]=='taskset':argv[0]='/usr/bin/taskset'
    env=child_environment(actual,context)
    _record_command(directory,actual,argv,env,cell,target=True)
    target_config=read_json(Path(env['MC_TENT_CONF'])) if 'MC_TENT_CONF' in env else {}
    destination=cell.get('rig_identity',{}).get('endpoints',{}).get('destination',{})
    if 'MC_TENT_CONF' in env and target_config!={'rpc_server_hostname':destination.get('address')}:
        raise ValueError('target config differs from current destination address')
    if context.kind=='physical' and not target_config:
        raise ValueError('physical target requires its actual generated configuration')
    capture=Capture(argv,env,directory,120)
    parser=ReadyParser()
    try:
        segment=None
        while not capture.closed:
            capture.pump()
            if capture.process is None or capture.process.poll() is not None:break
            try:segment=parser.update(directory/'stdout.raw')
            except FileNotFoundError:continue
            if segment is not None:break
        if segment is None or capture.process is None or capture.process.poll() is not None:
            raise ValueError('target failed before ready')
        shape=cell['shape'];rig=cell.get('rig_identity',{})
        ready=dict(schema_version=1,campaign_id=cell['campaign_id'],cell_id=cell['cell_id'],
                   profile=cell['profile'],host_id=cell['destination_host_id'],launch_id=str(uuid.uuid4()),
                   stdout_file='stdout.raw',segment_name=segment,ready_monotonic_ns=time.monotonic_ns(),
                   target_alive=True,command_argv=argv,target_config=target_config,gpu_uuid=rig.get('gpu_uuid',''),
                   gpu_pci_bdf=rig.get('gpu_pci_bdf',''),execution=context.kind,
                   allocation_receipt=dict(scope='upstream-target-ready-banner',buffer_bytes=shape['buffer_bytes'],
                                           gpu_ordinal=shape['gpu_ordinal'],residency='VRAM'))
        capture.deadline=capture.started/1e9+shape['duration_seconds']+240
        capture.start_background()
        write_json(directory/'target-ready.json',ready)
        return TargetHandle(capture.process,ready,capture,directory,cell,context)
    except BaseException:
        outcome=capture.finish('target_not_ready')
        write_json(directory/'process.json',asdict(outcome))
        raise


def validate_ready(ready, cell, context):
    required={'schema_version','campaign_id','cell_id','profile','host_id','launch_id','stdout_file',
              'segment_name','ready_monotonic_ns','target_alive','command_argv','gpu_uuid',
              'gpu_pci_bdf','allocation_receipt','target_config'}
    if not isinstance(ready,dict) or not required<=set(ready):raise ValueError('incomplete ready receipt')
    matches={'schema_version':1,'campaign_id':cell['campaign_id'],'cell_id':cell['cell_id'],
             'profile':cell['profile'],'host_id':cell['destination_host_id'],'target_alive':True}
    if any(ready.get(k)!=v or type(ready.get(k)) is not type(v) for k,v in matches.items()):
        raise ValueError('ready identity disagrees with current campaign')
    if not isinstance(ready['launch_id'],str):raise ValueError('launch identity must be a UUID string')
    uuid.UUID(ready['launch_id'])
    _integer(ready['ready_monotonic_ns'],'ready time')
    if (not isinstance(ready['command_argv'],list) or not ready['command_argv'] or
            any(not isinstance(value,str) or '\x00' in value for value in ready['command_argv'])):
        raise ValueError('ready has no target command')
    destination=cell.get('rig_identity',{}).get('endpoints',{}).get('destination',{})
    argv=ready['command_argv'];shape=cell['shape']
    if (len(argv)<4 or argv[0] not in ('taskset','/usr/bin/taskset','/bin/taskset') or
            argv[1]!='--cpu-list' or argv[2]!=destination.get('cpuset') or
            not Path(argv[3]).is_absolute()):
        raise ValueError('ready destination taskset/binary binding mismatch')
    expected_flags={'backend':'tent','metadata_type':'p2p','xport_type':'tcp','seg_type':'VRAM',
                    'local_gpu_id':str(shape['gpu_ordinal']),'total_buffer_size':str(shape['buffer_bytes']),
                    'rpc_server_port':str(destination.get('rpc_port'))}
    flags={}
    for value in argv[4:]:
        if not value.startswith('--') or '=' not in value:raise ValueError('invalid target command argument')
        key,value=value[2:].split('=',1)
        if key in flags:raise ValueError('duplicate target command flag')
        flags[key]=value
    if flags!=expected_flags:raise ValueError('ready target command semantics mismatch')
    if ready['target_config']!={'rpc_server_hostname':destination.get('address')} or not destination.get('address'):
        raise ValueError('ready destination configuration/address mismatch')
    segment=ready['segment_name']
    if not isinstance(segment,str) or not segment or any(c.isspace() or ord(c)<32 or c in ',{}$`\\' for c in segment):
        raise ValueError('invalid ready segment')
    for k in ('gpu_uuid','gpu_pci_bdf'):
        if ready[k]!=cell['rig_identity'].get(k,''):raise ValueError('ready GPU identity mismatch')
    allocation=ready['allocation_receipt'];shape=cell['shape']
    if not isinstance(allocation,dict) or any(allocation.get(k)!=v or type(allocation.get(k)) is not type(v) for k,v in
            {'scope':'upstream-target-ready-banner','buffer_bytes':shape['buffer_bytes'],
             'gpu_ordinal':shape['gpu_ordinal'],'residency':'VRAM'}.items()):
        raise ValueError('ready allocation mismatch')
    if 'execution' in ready and ready['execution']!=context.kind:raise ValueError('ready execution scope mismatch')
    return segment


def stop_target(handle, source_receipt):
    errors=[];ready=handle.ready_receipt;cell=handle.cell
    expected=dict(schema_version=1,campaign_id=cell['campaign_id'],cell_id=cell['cell_id'],
                  profile=cell['profile'],destination_host_id=cell['destination_host_id'],
                  launch_id=ready['launch_id'],segment_name=ready['segment_name'],
                  source_host_id=cell['source_host_id'],endpoint='source',execution=handle.context.kind,
                  status='source_completed',source_returncode=0,source_cleanup_complete=True)
    if not isinstance(source_receipt,dict):errors.append('missing source completion')
    else:
        for key,val in expected.items():
            if source_receipt.get(key)!=val or type(source_receipt.get(key)) is not type(val):errors.append('source completion mismatch: '+key)
        if not isinstance(source_receipt.get('source_receipt'),str) or not source_receipt['source_receipt']:
            errors.append('missing source evidence reference')
    alive=handle.process.poll() is None
    if not alive:errors.append('target exited before source completion')
    process=handle.capture.finish('target_stop')
    # Requested single TERM with upstream's clean exit0 is normal target shutdown.
    normal=process.returncode==0 and process.cleanup_complete and process.termination=='target_stop' and 'SIGKILL' not in process.signals
    if not normal:errors.append('target did not stop cleanly')
    try:
        if parse_target_ready(handle.output_dir/'stdout.raw') != ready['segment_name']:
            errors.append('target segment changed after readiness')
    except (OSError, ValueError):
        errors.append('final target banner is incomplete or ambiguous')
    route=_route(handle.output_dir,cell,handle.context);errors+=route['errors']
    ok=not errors
    result=dict(schema_version=1,contract_version=CONTRACT,cell_id=cell['cell_id'],profile=cell['profile'],
                campaign_id=cell['campaign_id'],execution=handle.context.kind,
                status=('fixture_completed' if handle.context.kind=='contract-fixture' else 'completed') if ok else 'failed',
                exit_code=0 if ok else 1,performance_claim='none',ratio_eligible=False,
                target_alive_through_source_completion=alive,process=asdict(process),errors=errors,
                route_qualification=route['route_qualification'],source_completion=source_receipt,
                e7_qualification='destination_lifetime_qualified' if ok else 'failed',
                qualification_scope='matched-source-receipt-and-owned-target-lifetime')
    write_json(handle.output_dir/'process.json',asdict(process))
    write_json(handle.output_dir/'receipt.json',result)
    return result
