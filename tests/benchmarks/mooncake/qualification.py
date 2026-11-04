"""Minimal fixed-source/static-runtime checks for the public Mooncake CLI.

Existing route, correctness and CPU evidence is declared evidence, never a
hardware observation made by this checker. No loader or device API is run.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

from executor import (ExecutionContext, inspect_process, read_bytes, read_json,
                      NATIVE_LIMIT, STREAM_LIMIT)

REVISION='d01447808d10af78011e9203d53796a15a032a03'


class SetupRefused(ValueError):
    pass


def _path(value, base):
    if not isinstance(value,str) or not value or len(value.encode())>4096 or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('evidence reference must be a bounded path string')
    p=Path(value)
    if '..' in p.parts:raise ValueError('evidence parent traversal refused')
    if not p.is_absolute():p=base/p
    if p==Path('/dev') or Path('/dev') in p.parents:raise ValueError('device evidence paths refused')
    return p.absolute()


def _ordinary(path, limit=None):
    try:info=path.lstat()
    except OSError as error:raise SetupRefused('missing evidence: '+str(path)) from error
    if not stat.S_ISREG(info.st_mode) or info.st_size==0 or (limit is not None and info.st_size>limit):
        raise SetupRefused('missing/empty/nonregular/oversized evidence: '+str(path))
    return info


def _load(path):
    _ordinary(path,NATIVE_LIMIT)
    return read_json(path)


def _hash(path):
    _ordinary(path)
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            data=stream.read(1<<20)
            if not data:break
            digest.update(data)
    return digest.hexdigest()


def _need(condition, message):
    if not condition:raise SetupRefused(message)


def _same(actual, expected, message):
    _need(type(actual) is type(expected) and actual==expected,message)


def _evidence(paths, base, facts):
    _need(isinstance(paths,list) and bool(paths),'retained raw evidence paths are missing')
    _need(len(paths)<=4096,'too many retained evidence files')
    loaded=[]
    for value in paths:
        path=_path(value,base);_ordinary(path,STREAM_LIMIT)
        facts.append(str(path));loaded.append(path)
    return loaded


def _rig_receipt(value, base, rig, facts, shape=None, endpoint=None):
    if isinstance(value,str):
        path=_path(value,base);_ordinary(path,STREAM_LIMIT);facts.append(str(path))
        if path.suffix=='.json':obj=_load(path);obj_base=path.parent
        else:return
    elif isinstance(value,dict) and value:
        obj=value;obj_base=base
    else:raise SetupRefused('rig receipt must reference actual retained evidence')
    refs=obj.get('evidence')
    _evidence(refs,obj_base,facts)
    for key in ('input_file','gpu_uuid','gpu_pci_bdf','namespace_identity'):
        if key in obj:_same(obj[key],rig.get(key),'rig evidence identity mismatch: '+key)
    if endpoint is not None:
        for key in ('host_id','address','interface','rpc_port'):
            if key in obj:_same(obj[key],endpoint.get(key),'recorded endpoint identity mismatch: '+key)
        for role in ('source','destination'):
            key=role+'_host_id'
            if key in obj:
                _same(obj[key],rig.get('endpoints',{}).get(role,{}).get('host_id'),
                      'recorded endpoint pair mismatch: '+key)
    if shape is not None:
        for key in ('target_offset','target_bytes'):
            if key in obj:_same(obj[key],shape[key],'recorded input range mismatch: '+key)
    if 'input_file' in rig:
        current=Path(rig['input_file']).lstat()
        for recorded in (obj,obj.get('stat',{}),obj.get('input_stat',{})):
            if not isinstance(recorded,dict):raise ValueError('recorded input stat must be an object')
            for key in ('st_dev','st_ino','st_size','st_mtime_ns'):
                if key in recorded:_same(recorded[key],getattr(current,key),'recorded input stat mismatch: '+key)


def _needed(lines):
    names=[]
    if not isinstance(lines,list):raise SetupRefused('missing build linked-library evidence')
    for line in lines:
        if not isinstance(line,str):raise ValueError('needed entries must be text')
        match=re.search(r'Shared library: \[([^\]]{1,255})\]',line)
        if match:names.append(match[1])
        elif line and '[' not in line:names.append(line)
    _need(bool(names) and len(names)==len(set(names)),'missing/duplicate DT_NEEDED metadata')
    return names


def validate_qualification(path, args, shape, rig, cell):
    """Return checked/declared facts; malformed syntax raises ValueError."""
    checked=[];declared=[];missing=[];dirs=[];tool_counter=0
    root=Path(args.output_dir)/'qualification-tools'
    def tool(argv, env=None):
        nonlocal tool_counter
        directory=root/str(tool_counter);tool_counter+=1
        result=inspect_process(argv,directory,env=env,timeout_seconds=10)
        _need(result.returncode==0 and result.termination=='exited' and result.cleanup_complete,
              'read-only qualification tool failed: '+argv[0])
        return read_bytes(directory/'stdout.raw',STREAM_LIMIT).decode('utf-8')
    def elf(binary):
        text=tool(['/usr/bin/readelf','--wide','--file-header','--program-headers','--dynamic',str(binary)])
        fields={'needed':[],'runpath':[],'soname':None,'interpreter':None}
        _need('ELF64' in text and 'little endian' in text and 'Advanced Micro Devices X86-64' in text,
              'unsupported current ELF class/data/machine')
        for line in text.splitlines():
            _need(len(line)<=NATIVE_LIMIT,'oversized readelf line')
            if '(NEEDED)' in line:fields['needed']+=_needed([line])
            if '(SONAME)' in line:
                m=re.search(r'\[([^\]]{1,255})\]',line);_need(m is not None,'missing SONAME');fields['soname']=m[1]
            if '(RUNPATH)' in line or '(RPATH)' in line:
                m=re.search(r'\[([^\]]{0,16384})\]',line);_need(m is not None,'invalid RUNPATH')
                for value in m[1].split(':'):
                    _need(bool(value),'empty runtime search component')
                    value=value.replace('${ORIGIN}',str(binary.parent)).replace('$ORIGIN',str(binary.parent))
                    _need('$' not in value,'unsupported dynamic runtime search variable')
                    fields['runpath'].append(value)
            if '[Requesting program interpreter:' in line:
                fields['interpreter']=line.split('[Requesting program interpreter:',1)[1].rstrip(']').strip()
        for value in fields['runpath']:_need('stubs' not in Path(value).parts,'CUDA-stub RUNPATH refused')
        return fields
    try:
        path=Path(path).absolute();q=_load(path)
        if set(q)!={'schema_version','build_receipt','runtime_receipt','correctness_receipt','budget_receipt'}:
            raise ValueError('qualification must contain the exact five-key schema')
        if type(q['schema_version']) is not int or q['schema_version']!=1:raise ValueError('qualification schema_version must be 1')
        paths={key:_path(q[key],path.parent) for key in q if key!='schema_version'}
        build=_load(paths['build_receipt']);runtime=_load(paths['runtime_receipt'])
        for key in ('source','source_worktree','compiler','cuda_compiler','submodules'):
            if key in build and not isinstance(build[key],dict):raise ValueError('build '+key+' must be an object')
        correct=_load(paths['correctness_receipt']);budget=_load(paths['budget_receipt'])
        _same(build.get('source',{}).get('exit'),0,'build source query failed')
        _same(build.get('source',{}).get('stdout'),REVISION+'\n','build source revision mismatch')
        _same(build.get('source_worktree',{}).get('exit'),0,'build clean query failed')
        _same(build.get('source_worktree',{}).get('stdout'),'','build source tree not clean')
        _same(build.get('source_unchanged'),True,'build source change not excluded')
        for key in ('compiler','cuda_compiler'):
            _same(build.get(key,{}).get('exit'),0,'build compiler evidence missing')
            _need(isinstance(build[key].get('stdout'),str) and bool(build[key]['stdout']),'build compiler identity missing')
        cache=build.get('selected_cmake_cache',[])
        _need('USE_TENT:BOOL=ON' in cache and 'USE_CUDA:BOOL=ON' in cache,'TENT/CUDA build features absent')
        built_needed=_needed(build.get('needed'))
        _need(any(name.startswith('liburing.so') for name in built_needed),'linked liburing evidence missing')
        if cell['arm']=='gds-compat':_need(any(name.startswith('libcufile.so') for name in built_needed),'linked cuFile evidence missing')
        source=Path(args.source_root)
        git_env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0'}
        prefix=['/usr/bin/git','-c','core.fsmonitor=false','-C',str(source)]
        _same(tool(prefix+['rev-parse','HEAD'],git_env).strip(),REVISION,'current source revision mismatch')
        _same(tool(prefix+['status','--porcelain','--untracked-files=normal'],git_env),'','current source tree dirty')
        link=tool(prefix+['ls-tree','HEAD','extern/pybind11'],git_env).strip().split()
        _need(len(link)==4 and link[0]=='160000' and link[1]=='commit','pybind11 gitlink unavailable')
        _same(tool(['/usr/bin/git','-c','core.fsmonitor=false','-C',str(source/'extern/pybind11'),'rev-parse','HEAD'],git_env).strip(),link[2],'current pybind11 revision mismatch')
        recorded=build.get('submodules',{})
        _same(recorded.get('exit'),0,'build submodule evidence missing')
        _need(isinstance(recorded.get('stdout'),str) and any(line.startswith(' '+link[2]+' extern/pybind11') for line in recorded['stdout'].splitlines()),'recorded pybind11 gitlink mismatch')
        checked.append('current fixed Git source, clean worktree and pybind11 gitlink')
        binary=Path(args.tebench);info=_ordinary(binary)
        _need(os.access(binary,os.X_OK),'current tebench is not executable')
        _same(build.get('bytes'),info.st_size,'current tebench size differs from build')
        digest=_hash(binary)
        _same(build.get('sha256'),digest,'current tebench digest differs from build')
        checked.append('current critical tebench bytes/sha256')
        required={'schema_version','source_revision','tebench_sha256','profile','endpoint','kernel_release','libraries','library_search_dirs','evidence'}
        optional={'gpu_uuid','gpu_pci_bdf','nvidia_driver_version','cuda_version','cufile_version'}
        if not required<=set(runtime) or set(runtime)-required-optional:raise ValueError('runtime receipt keys violate schema')
        _same(runtime['schema_version'],1,'runtime schema version mismatch')
        _same(runtime['source_revision'],REVISION,'runtime source revision mismatch')
        _same(runtime['tebench_sha256'],digest,'runtime binary identity mismatch')
        _same(runtime['profile'],args.profile,'runtime profile mismatch')
        _same(runtime['endpoint'],args.endpoint,'runtime endpoint mismatch')
        _same(runtime['kernel_release'],os.uname().release,'current kernel differs from runtime receipt')
        endpoint=rig if args.experiment=='e4' else rig.get('endpoints',{}).get(args.endpoint,{})
        _same(endpoint.get('kernel_release'),runtime['kernel_release'],'local rig kernel differs from current kernel')
        for key in ('gpu_uuid','gpu_pci_bdf','nvidia_driver_version','cuda_version'):
            _need(isinstance(rig.get(key),str) and bool(rig[key]),'rig identity missing: '+key)
            _same(runtime.get(key),rig[key],'runtime/rig identity differs: '+key)
        if cell['arm']=='gds-compat':_same(runtime.get('cufile_version'),rig.get('cufile_version'),'cuFile version mismatch')
        _same(rig.get('source_revision'),REVISION,'rig source revision mismatch')
        _same(rig.get('execution'),'physical','rig does not describe physical execution')
        raw_paths=_evidence(runtime['evidence'],paths['runtime_receipt'].parent,declared)
        dirs=runtime['library_search_dirs']
        if not isinstance(dirs,list) or not dirs:raise ValueError('explicit runtime library directories required')
        _need(all(isinstance(value,str) and 'stubs' not in Path(value).parts for value in dirs),'declared CUDA-stub runtime directory refused')
        dirs=[str(_path(value,paths['runtime_receipt'].parent).resolve()) for value in dirs]
        _need(all(Path(value).is_dir() and 'stubs' not in Path(value).parts and ':' not in value for value in dirs),'unsafe runtime library directory')
        binary_elf=elf(binary)
        _need(set(binary_elf['needed'])==set(built_needed),'current DT_NEEDED differs from build')
        _need(binary_elf['interpreter'] is not None,'missing current ELF interpreter')
        libraries=runtime['libraries']
        if not isinstance(libraries,list) or not libraries or len(libraries)>4096:raise ValueError('runtime libraries must be a bounded list')
        found={}
        for lib in libraries:
            if not isinstance(lib,dict) or not {'needed','path'}<=set(lib) or set(lib)-{'needed','path','sha256'}:raise ValueError('invalid runtime library entry')
            name=lib['needed']
            if not isinstance(name,str) or '/' in name or not name or name in found:raise ValueError('duplicate/invalid needed library')
            actual=_path(lib['path'],paths['runtime_receipt'].parent).resolve();_ordinary(actual)
            _need('stubs' not in actual.parts,'resolved CUDA stub library refused')
            current=elf(actual);_same(current['soname'],name,'runtime SONAME mismatch')
            candidates=[Path(directory)/name for directory in dirs+binary_elf['runpath']]
            first=next((p.resolve() for p in candidates if p.is_file()),None)
            _same(str(first),str(actual),'runtime search order differs from declared resolution')
            critical=name=='libcuda.so.1' or name.startswith('libcudart.so') or (cell['arm']=='gds-compat' and name.startswith('libcufile.so'))
            if critical:
                _need(isinstance(lib.get('sha256'),str),'key runtime artifact digest missing')
                _same(_hash(actual),lib['sha256'],'key runtime artifact digest mismatch')
            found[name]=str(actual)
        _need(set(found)==set(binary_elf['needed']),'runtime direct library coverage mismatch')
        resolver={name:set() for name in found}
        resolver_names={name.encode('utf-8') for name in resolver}
        for raw in raw_paths:
            # Match retained loader output line-wise; never concatenate large logs.
            if raw.suffix=='.json':continue
            with raw.open('rb') as stream:
                while True:
                    line=stream.readline(NATIVE_LIMIT+1)
                    if not line:break
                    _need(len(line)<=NATIVE_LIMIT,'oversized retained loader line')
                    line=line.strip()
                    _need(not (line.startswith(b'ERROR') or b'FATAL' in line or
                               re.match(rb'^[EF][0-9]{4} ',line) or
                               b'error while loading shared libraries' in line),
                          'retained loader evidence contains an error')
                    name,separator,rest=line.partition(b' => ')
                    if separator and name in resolver_names:
                        try:line=line.decode('utf-8')
                        except UnicodeDecodeError as error:
                            raise SetupRefused('required retained loader mapping is not UTF-8') from error
                        name,separator,rest=line.partition(' => ')
                        candidate=rest.split(' (',1)[0].strip()
                        if candidate.startswith('/'):
                            resolver[name].add(str(Path(candidate).resolve()))
                        else:resolver[name].add('unresolved')
                        _need(len(resolver[name])<=2,'ambiguous retained loader evidence')
        for name,actual in found.items():
            _need(resolver[name]=={actual},'retained loader map missing/ambiguous: '+name)
        checked.append('current ELF/DT_NEEDED/SONAME/non-stub runtime and key runtime hashes')
        for obj, label in ((correct,'correctness'),(budget,'budget')):
            _same(obj.get('source_revision'),REVISION,label+' source revision mismatch')
            _same(obj.get('profile'),args.profile,label+' profile mismatch')
            _evidence(obj.get('evidence'),paths[label+'_receipt'].parent,declared)
        _same(correct.get('status'),'passed','existing correctness evidence did not pass')
        _same(correct.get('scope'),'separate-upstream-roundtrip','wrong correctness scope')
        _same(correct.get('experiment'),args.experiment,'correctness experiment mismatch')
        _same(correct.get('arm'),cell['arm'],'correctness route mismatch')
        covered=correct.get('shape',{})
        if not isinstance(covered,dict):raise ValueError('correctness shape must be an object')
        for key,wanted in (('block_bytes',cell['block_bytes']),('batch_requests',cell['batch_requests'])):
            _need(isinstance(covered.get(key),list) and wanted in covered[key] and all(type(x) is int for x in covered[key]),'correctness geometry coverage mismatch')
        _same(covered.get('worker_threads'),shape['worker_threads'],'correctness worker mismatch')
        identities=correct.get('rig_identity',{})
        if not isinstance(identities,dict):raise ValueError('correctness rig identity must be an object')
        for key in ('gpu_uuid','gpu_pci_bdf','nvidia_driver_version','cuda_version'):
            _same(identities.get(key),rig.get(key),'correctness rig identity mismatch: '+key)
        if args.experiment=='e4':_same(identities.get('input_file'),rig.get('input_file'),'correctness input mismatch')
        else:
            _same(identities.get('endpoints'),rig.get('endpoints'),'correctness endpoint identities mismatch')
        _same(budget.get('endpoint'),args.endpoint,'budget endpoint mismatch')
        for key in ('cpuset','cpu_budget_description'):_same(budget.get(key),endpoint.get(key),'budget/rig mismatch: '+key)
        if args.experiment=='e4':
            p=Path(rig.get('input_file',''))
            info=_ordinary(p)
            _need(info.st_size>=shape['target_offset']+shape['target_bytes'],'input file range exceeds size')
            _need(os.access(p,os.R_OK|os.W_OK),'input needs read/write access for upstream O_RDWR')
            _same(rig.get('input_initialized'),True,'input initialization evidence missing')
            for key in ('input_validation_receipt','file_extent_receipt','exclusive_window_receipt'):
                _rig_receipt(rig.get(key),Path(args.rig).parent,rig,declared,shape)
            checked.append('current ordinary input stat/range/access (contents not reread)')
        else:
            endpoints=rig.get('endpoints',{})
            _need(endpoints.get('source',{}).get('host_id')!=endpoints.get('destination',{}).get('host_id'),'E7 distinct endpoint identity missing')
            for ep in ('source','destination'):
                endpoint=endpoints.get(ep,{})
                for key in ('route_receipt','usb4_link_receipt'):
                    _rig_receipt(endpoint.get(key),Path(args.rig).parent,rig,declared,endpoint=endpoint)
        route_qualified=cell['arm']!='gds-compat'
        if cell['arm']=='gds-compat':
            for raw in raw_paths:
                if raw.suffix=='.json':
                    obj=_load(raw)
                    if obj.get('route_requested')=='gds-compat' and obj.get('compatibility_mode') is True and obj.get('cufile_batch_api_supported') is True:
                        route_qualified=True
            _need(route_qualified,'retained GDS compatibility/batch API evidence missing')
        declared.append('existing roundtrip correctness, GPU/residency/route and all-thread CPU observations; not rerun')
        return dict(qualified=True,status='setup_qualified',missing=[],mechanically_checked=checked,
                    evidence_declared=declared,library_search_dirs=dirs,route_qualified=route_qualified,
                    profile=args.profile,endpoint=args.endpoint,ratio_eligible=False,
                    execution='none',performance_claim='none')
    except (SetupRefused,OSError) as error:
        missing.append(str(error))
        return dict(qualified=False,status='setup_refused',missing=missing,mechanically_checked=checked,
                    evidence_declared=declared,library_search_dirs=dirs,route_qualified=False,
                    profile=args.profile,endpoint=args.endpoint,ratio_eligible=False,
                    execution='none',performance_claim='none')


def context_from_qualification(verdict):
    if not isinstance(verdict,dict) or verdict.get('qualified') is not True:
        raise ValueError('successful qualification verdict required')
    return ExecutionContext('physical',verdict['profile'],verdict,verdict['endpoint'])
