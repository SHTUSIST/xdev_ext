#!/usr/bin/env python3
"""Independent SOURCE FIXTURE setup checks. Never native execution evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).absolute().parent
PRODUCT = None
ARTIFACTS = None
BASELINE_PREFIX = None


def discover_product(selected=None):
    """Find canonical tooling from an explicit root, file location or view."""
    def canonical(path):
        path = Path(path).expanduser().absolute()
        if not (path / 'source-layout.json').is_file():
            raise ValueError(f'No canonical source-layout.json at {path}')
        for name in ('tools/layout.py', 'tools/build/prepare_sources.py'):
            if not (path / name).is_file():
                raise ValueError(f'Missing product tooling: {path / name}')
        return path.resolve()

    def inspect(path):
        receipt = path / 'view.json'
        if receipt.is_file():
            data = json.loads(receipt.read_text())
            if data.get('kind') == 'host-source-view':
                return canonical(data['canonical_root'])
        if (path / 'source-layout.json').is_file():
            return canonical(path)
        return None

    if selected is not None:
        found = inspect(Path(selected).expanduser().absolute())
        if found is None:
            raise ValueError(f'--product/PRODUCT must name a canonical root or logical view: {selected}')
        return found
    for start in (HERE, Path.cwd()):
        for path in (start, *start.parents):
            found = inspect(path)
            if found is not None:
                return found
    raise ValueError('Cannot discover canonical product; pass --product or set PRODUCT')


def default_runner():
    """Use the existing product layout API rather than a private path."""
    name = '_poll_source_setup_layout'
    spec = importlib.util.spec_from_file_location(name, PRODUCT / 'tools/layout.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.load_layout(PRODUCT).source('linux', POLL_NATIVE)
POLL_NATIVE = 'tools/testing/selftests/xdev_ext_mech/poll/poll_kvm.sh'
SPEC_NATIVE = 'Documentation/userspace-api/xdev_ext-poll.rst'
PROVIDER_NATIVE = 'tools/testing/selftests/xdev_ext_mech/provider/'
CONFIGS = 'MODULES MODULE_UNLOAD XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY XDEV_EXT_MECH_DMA BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF XDP_SOCKETS VIRTIO_NET NET_RX_BUSY_POLL PCI_MSI SERIAL_8250_CONSOLE DEBUG_FS'.split()
REQUIRED = ('build/.config', 'build/arch/x86/boot/bzImage', 'build/vmlinux', 'tools/xdev_ext_mech_ctl', 'tools/nvme_s0.bpf.o', 'tools/nxp_mech.bpf.o', 'tools/dma-provider/xdev_ext_dma_provider_sim.ko', 'tools/dma-provider/dma_poll_runtime', 'tools/dma-provider/dma_provider_pair.bpf.o')

def limits():
    resource.setrlimit(resource.RLIMIT_AS, (768*1024**2, 768*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8*1024**2, 8*1024**2))

def run(args, cwd=None, env=None, check=True):
    p = subprocess.run([str(x) for x in args], cwd=cwd, env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, preexec_fn=limits)
    if len(p.stdout)+len(p.stderr) > 1024**2:
        raise RuntimeError('bounded subprocess output exceeded')
    if check and p.returncode:
        raise RuntimeError(f'{args}: {p.returncode}\n{p.stdout}\n{p.stderr}')
    return p

def put(path, value, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    path.chmod(mode)

def git(repo, *args):
    return run(['git', '-C', repo, *args]).stdout.strip()

def commit(repo, msg):
    git(repo, 'add', '-A');git(repo, 'commit', '-qm', msg)
    return git(repo, 'rev-parse', 'HEAD')

class Fixture:
    def __init__(self, root):
        self.root=root;self.repo=root/'canonical';self.native=root/'custom-native';self.build=root/'build';self.tools=root/'tools';self.bin=root/'bin';self.scratch=root/'scratch'
        for p in (self.repo,self.native,self.build,self.tools,self.bin,self.scratch):p.mkdir()
        self.scratch.chmod(0o700)
        git(self.repo,'init','-q');git(self.repo,'config','user.name','source-fixture');git(self.repo,'config','user.email','source-fixture@example.invalid')
        for n in ('tools/layout.py','tools/build/prepare_sources.py'):
            target=self.repo/n;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(PRODUCT/n,target)
        upstream=root/'upstream';upstream.mkdir();git(upstream,'init','-q');git(upstream,'config','user.name','fixture');git(upstream,'config','user.email','fixture@example.invalid')
        for n in ('Makefile','Kconfig','scripts/Makefile.build','include/linux/types.h'):
            put(upstream/n,'SOURCE FIXTURE upstream '+n+'\n')
        upstream_sha=commit(upstream,'source fixture upstream')
        cache=root/'cache';cache.mkdir();run(['git','clone','-q','--bare',upstream,cache/'linux.git'])
        self.mapping={POLL_NATIVE:'tests/core/poll/poll_kvm.sh',SPEC_NATIVE:'docs/reference/xdev_ext-poll.rst',PROVIDER_NATIVE+'dma_poll_runtime.c':'tests/core/provider/dma_poll_runtime.c',PROVIDER_NATIVE+'xdev_ext_dma_provider_sim.c':'tests/core/provider/xdev_ext_dma_provider_sim.c','drivers/xdev_fixture.c':'src/core/xdev_fixture.c'}
        for native,source in self.mapping.items():put(self.repo/source,'SOURCE FIXTURE '+native+'\n')
        files=[{'source':source,'component':'linux','native_path':native} for native,source in self.mapping.items()]
        for n in ('tools/layout.py','tools/build/prepare_sources.py'):files.append({'source':n,'logical_path':n})
        put(self.repo/'source-layout.json',json.dumps({'schema':1,'dependency_lock':'third_party/sources.lock.json','files':files}))
        put(self.repo/'third_party/sources.lock.json',json.dumps({'schema':2,'components':{'linux':{'url':'source-fixture-local-only','ref':'refs/heads/master','commit':upstream_sha}}}))
        self.sha=commit(self.repo,'canonical source fixture')
        run([sys.executable,'-B',self.repo/'tools/build/prepare_sources.py','--component','linux','--cache',cache,'--output',self.native,'--offline'])
        self.view=root/'logical-view'
        run([sys.executable,'-B',self.repo/'tools/layout.py','view','--root',self.repo,'--output',self.view])
        (self.build/'source').symlink_to(self.native, target_is_directory=True)
        put(self.build/'xdev-ext-source.commit',self.sha+'\n')
        for name in REQUIRED:put(root/name,'SOURCE FIXTURE ARTIFACT '+name+'\n')
        put(self.build/'.config',''.join('CONFIG_'+s+'=y\n' for s in CONFIGS))
        put(self.build/'include/config/kernel.release','source-fixture-release\n')
        for n in ('xdev_ext_mech_ctl','dma-provider/dma_poll_runtime'):(self.tools/n).chmod(0o755)
        for name in ('dma_poll_runtime.c','xdev_ext_dma_provider_sim.c'):
            shutil.copy2(self.repo/('tests/core/provider/'+name),self.tools/('dma-provider/'+name))
        self.receipt()
        put(self.bin/'modinfo','#!/bin/sh\nprintf "%s\\n" "$*" >> "$METADATA_LOG"\nprintf "%s SMP\\n" "${FIXTURE_VERMAGIC:-source-fixture-release}"\n',0o755)
        for n in ('make','gcc','gcc-14','cc','clang','qemu-system-x86_64','qemu-img','insmod','modprobe','rmmod','ssh','scp','curl','wget','mkfs.ext4','cpio','mount','sudo','dd'):
            put(self.bin/n,'#!/bin/sh\necho "FORBIDDEN '+n+' $*" >> "$FORBIDDEN_LOG"\nexit 99\n',0o755)
        self.env={**os.environ,'PATH':str(self.bin)+':/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1','METADATA_LOG':str(root/'modinfo.log'),'FORBIDDEN_LOG':str(root/'forbidden.log'),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_LAZY_FETCH':'1'}
        self.selected=self.repo;self.red=0;self.cwd=self.repo
    def receipt(self, paths=None):
        paths=[self.root/n for n in REQUIRED] if paths is None else paths
        put(self.build/'xdev-ext-artifacts.sha256',''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p)+'\n' for p in paths))
    def prepare_check(self):
        run([sys.executable,'-B',self.repo/'tools/build/prepare_sources.py','--component','linux','--output',self.native,'--check'])
    def update(self, path):
        put(self.repo/path,(self.repo/path).read_text()+'committed descendant\n')
        commit(self.repo,'descendant '+path)
        # Real prepare API updates copied overlays after canonical source commit.
        run([sys.executable,'-B',self.repo/'tools/build/prepare_sources.py','--component','linux','--cache',self.root/'cache','--output',self.native,'--offline'])
    def invoke(self, defs=None, old=False, artifacts=True):
        if old:
            script=BASELINE_PREFIX.read_text()
            args=['bash','-c',script,'old-prefix','--scratch',self.scratch,'--source',self.selected,'--build',self.build,'--tools',self.tools]
        else:
            assignments={'SOURCE':self.selected,'BUILD':self.build,'TOOLS':self.tools,'EV':self.scratch/'evidence','RED':self.red}
            (self.scratch/'evidence').mkdir(exist_ok=True)
            definition_file=self.root/'isolated-setup-functions.sh'
            if self.cwd==self.view:
                definition_file=self.view/('kernel/'+POLL_NATIVE)
            put(definition_file,defs)
            script='set -euo pipefail\n'+''.join(k+'='+shlex.quote(str(v))+'\n' for k,v in assignments.items())+'source '+shlex.quote(str(definition_file))+'\nresolve_poll_source\n'
            if artifacts:script+='verify_poll_artifacts\n'
            script+='printf "RESOLVED|%s|%s|%s|%s|%s|%s|%s\\n" "$SOURCE_GIT_ROOT" "$HEAD_SHA" "$NATIVE_SOURCE" "$POLL_SOURCE" "$POLL_SPEC" "$PROVIDER_SOURCE" "$BUILD_SHA"\n'
            args=['bash','-c',script]
        p=run(args,cwd=self.cwd,env=self.env,check=False)
        if (self.root/'forbidden.log').exists():raise AssertionError((self.root/'forbidden.log').read_text())
        return p

def source_defs(path):
    """Extract only named whole functions; never execute or inspect guest tail."""
    # Functions are isolated through bash's own definition printer. Reading stops
    # immediately after the second top-level closing brace following frozen names.
    lines=path.open(); selected=[];collect=False;found=[]
    for line in lines:
        if re.match(r'^(?:function\s+)?(?:resolve_poll_source|verify_poll_artifacts)\s*\(\)',line):
            collect=True;found.append(line.split('(')[0].replace('function','').strip())
        if collect:selected.append(line)
        if collect and line.rstrip() == '}':
            syntax=run(['bash','-n','-c',''.join(selected)],check=False)
            if syntax.returncode == 0:
                collect=False
                if set(found)=={'resolve_poll_source','verify_poll_artifacts'}:break
    if set(found)!={'resolve_poll_source','verify_poll_artifacts'}:return None
    return ''.join(selected)

def reject_marker(f,key,value):
    p=f.native/'.xdev-ext-source.json';d=json.loads(p.read_text());d[key]=value;put(p,json.dumps(d))

def rm(path):path.unlink()

def append(path):put(path,path.read_text()+'CHANGED SOURCE FIXTURE\n',path.stat().st_mode & 0o777)

def replace_source(f,target):
    rm(f.build/'source');(f.build/'source').symlink_to(target,target_is_directory=True)

def move_source(f):
    f.selected=f.native

def prelayout_history(f, change, supported=True):
    # Build a real historical revision containing the documented schema-1 lock,
    # then the current schema-1 canonical manifest as its descendant. No runner
    # implementation or existing independent test contributes expected paths.
    git(f.repo, 'checkout', '--orphan', 'legacy')
    git(f.repo, 'rm', '-rf', '.')
    for native in (POLL_NATIVE, SPEC_NATIVE):
        put(f.repo/('kernel/'+native), 'SOURCE FIXTURE historical '+native+'\n')
    put(f.repo/'sources.lock.json', json.dumps({'schema':1 if supported else 99,'components':{'linux':{'path':'kernel'}}}))
    historical=commit(f.repo,'pre-layout source fixture')
    git(f.repo,'checkout','-q','master')
    # Preserve the canonical fixture as a second-parent descendant, without
    # introducing a tree diff beyond the test inputs/metadata migration.
    git(f.repo,'merge','-s','ours','--allow-unrelated-histories','--no-edit','legacy')
    # Testing migration as a whole must refuse (manifest/tool/production paths).
    put(f.build/'xdev-ext-source.commit',historical+'\n')
    if change: f.update(change)


def source_cases():
    cases=[]
    def add(name,fn,ok=False,artifact=True):cases.append((name,fn,ok,artifact))
    add('canonical-positive',lambda f:None,True)
    add('assembly-positive',move_source,True)
    add('view-launch-explicit-canonical-positive',lambda f:setattr(f,'cwd',f.view),True)
    add('view-launch-explicit-assembly-positive',lambda f:(setattr(f,'cwd',f.view),move_source(f)),True)
    add('poll-only-descendant-positive',lambda f:f.update('tests/core/poll/poll_kvm.sh'),True)
    add('spec-only-descendant-positive',lambda f:f.update('docs/reference/xdev_ext-poll.rst'),True)
    add('dirty-tracked',lambda f:append(f.repo/'src/core/xdev_fixture.c'))
    add('staged-tracked',lambda f:(append(f.repo/'src/core/xdev_fixture.c'),git(f.repo,'add','src/core/xdev_fixture.c')))
    add('untracked',lambda f:put(f.repo/'untracked','source fixture'))
    for path in ('source-layout.json','tools/layout.py','tools/build/prepare_sources.py','third_party/sources.lock.json','src/core/xdev_fixture.c'):
        add('missing-'+path,lambda f,p=path:rm(f.repo/p))
        add('untracked-'+path,lambda f,p=path:git(f.repo,'rm','--cached',p))
    add('bare-logical-view',lambda f:setattr(f,'selected',f.view))
    add('nested-owner-archive',lambda f:(setattr(f,'selected',f.repo/'nested'),shutil.copytree(f.view,f.repo/'nested'),git(f.repo,'add','nested'),git(f.repo,'commit','-qm','nested archive')))
    add('missing-marker',lambda f:rm(f.native/'.xdev-ext-source.json'))
    for key,value in [('schema',1),('kind','host-source-view'),('component','nvidia'),('canonical_root','relative/owner'),('output','/wrong/output'),('commit','0'*40),('source_origins',{})]:
        add('marker-'+key,lambda f,k=key,v=value:reject_marker(f,k,v))
    add('overlay-bytes',lambda f:append(f.native/'drivers/xdev_fixture.c'))
    add('upstream-required-missing',lambda f:rm(f.native/'Kconfig'))
    add('compact-view-buildsource',lambda f:replace_source(f,f.view))
    add('missing-buildsource',lambda f:rm(f.build/'source'))
    add('broken-buildsource',lambda f:replace_source(f,f.root/'missing'))
    add('wrong-buildsource',lambda f:replace_source(f,f.repo))
    add('explicit-assembly-buildsource-mismatch',lambda f:(move_source(f),replace_source(f,f.repo)))
    add('selected-root-symlink',lambda f:((f.root/'alias').symlink_to(f.repo,target_is_directory=True),setattr(f,'selected',f.root/'alias')))
    add('selected-parent-symlink',lambda f:((f.root/'parent-alias').symlink_to(f.root,target_is_directory=True),setattr(f,'selected',f.root/'parent-alias/canonical')))
    add('marker-symlink',lambda f:((f.root/'marker').write_bytes((f.native/'.xdev-ext-source.json').read_bytes()),rm(f.native/'.xdev-ext-source.json'),(f.native/'.xdev-ext-source.json').symlink_to(f.root/'marker')))
    add('unavailable-buildsha',lambda f:put(f.build/'xdev-ext-source.commit','0'*40+'\n'))
    def nonancestor(f):
        git(f.repo,'checkout','--orphan','other');git(f.repo,'commit','-qm','unrelated tree');other=git(f.repo,'rev-parse','HEAD');git(f.repo,'checkout','-q','master');put(f.build/'xdev-ext-source.commit',other+'\n')
    add('nonancestor-buildsha',nonancestor)
    add('production-descendant',lambda f:f.update('src/core/xdev_fixture.c'))
    add('manifest-descendant',lambda f:(put(f.repo/'source-layout.json',(f.repo/'source-layout.json').read_text()+'\n'),commit(f.repo,'manifest whitespace')))
    def git_fail(f,needle):
        put(f.bin/'git','#!/bin/sh\ncase " $* " in *" '+needle+' "*) echo "source-fixture forced Git failure" >&2; exit 73;; esac\nexec /usr/bin/git "$@"\n',0o755)
    add('failed-diff',lambda f:git_fail(f,'diff'))
    add('failed-status',lambda f:git_fail(f,'status'))
    add('prelayout-migration-refused',lambda f:prelayout_history(f,None))
    add('unsupported-prelayout-refused',lambda f:prelayout_history(f,None,False))
    def remapped_history(f):
        # Both endpoints have valid manifests: a source rename unrelated to
        # POLL cannot gain permission because the new path merely looks allowed.
        old=f.repo/'src/core/xdev_fixture.c';new=f.repo/'tests/core/poll/production.c'
        new.parent.mkdir(parents=True,exist_ok=True);old.rename(new)
        p=f.repo/'source-layout.json';d=json.loads(p.read_text())
        for entry in d['files']:
            if entry['source']=='src/core/xdev_fixture.c':entry['source']='tests/core/poll/production.c'
        put(p,json.dumps(d));commit(f.repo,'remap production under poll name')
        run([sys.executable,'-B',f.repo/'tools/build/prepare_sources.py','--component','linux','--cache',f.root/'cache','--output',f.native,'--offline'])
    add('revision-specific-remap-refused',remapped_history)
    def red_old(f):
        f.update('src/core/xdev_fixture.c');f.red=1
    add('red-older-production-positive',red_old,True)
    add('red-dirty-refused',lambda f:(red_old(f),append(f.repo/'src/core/xdev_fixture.c')))
    add('red-buildsource-refused',lambda f:(red_old(f),rm(f.build/'source')))
    add('red-marker-refused',lambda f:(red_old(f),rm(f.native/'.xdev-ext-source.json')))
    def missing_mapping(f):
        p=f.repo/'source-layout.json';d=json.loads(p.read_text());d['files']=[e for e in d['files'] if e.get('native_path')!=SPEC_NATIVE];put(p,json.dumps(d));commit(f.repo,'remove spec mapping')
        # Use a fresh, actually prepared output because overlay membership moved.
        f.native=f.root/'fresh-native'
        run([sys.executable,'-B',f.repo/'tools/build/prepare_sources.py','--component','linux','--cache',f.root/'cache','--output',f.native,'--offline'])
        replace_source(f,f.native);put(f.build/'xdev-ext-source.commit',git(f.repo,'rev-parse','HEAD')+'\n')
    add('missing-required-mapping',missing_mapping)
    def mismatched_lock(f):
        p=f.repo/'third_party/sources.lock.json';d=json.loads(p.read_text());d['components']['linux']['commit']='0'*40;put(p,json.dumps(d));commit(f.repo,'different lock');put(f.build/'xdev-ext-source.commit',git(f.repo,'rev-parse','HEAD')+'\n')
    add('lock-identity',mismatched_lock)
    return cases

def artifact_cases():
    cases=[]
    def add(name,fn,ok=False):cases.append((name,fn,ok,True))
    receipt=lambda f:f.build/'xdev-ext-artifacts.sha256'
    add('missing-receipt',lambda f:rm(receipt(f)))
    add('empty-receipt',lambda f:put(receipt(f),''))
    add('unrelated-receipt',lambda f:(put(f.root/'other','source fixture'),f.receipt([f.root/'other'])))
    for name in REQUIRED:
        add('missing-member-'+name,lambda f,n=name:f.receipt([f.root/p for p in REQUIRED if p!=n]))
        add('altered-bytes-'+name,lambda f,n=name:append(f.root/n))
        add('empty-artifact-'+name,lambda f,n=name:put(f.root/n,''))
    add('wrong-path-same-basename',lambda f:(put(f.root/'dma_poll_runtime','unrelated'),f.receipt([f.root/n for n in REQUIRED if n!='tools/dma-provider/dma_poll_runtime']+[f.root/'dma_poll_runtime'])))
    add('duplicate-required',lambda f:put(receipt(f),receipt(f).read_text()+receipt(f).read_text().splitlines()[0]+'\n'))
    add('conflicting-required',lambda f:put(receipt(f),receipt(f).read_text()+'0'*64+'  '+str(f.build/'.config')+'\n'))
    add('malformed-required-digest',lambda f:put(receipt(f),'g'*64+receipt(f).read_text()[64:]))
    def extra_missing(f):
        p=f.root/'extra';put(p,'source fixture');f.receipt([f.root/n for n in REQUIRED]+[p]);rm(p)
    add('complete-receipt-missing-extra',extra_missing)
    add('complete-receipt-bad-extra',lambda f:(put(f.root/'extra','source fixture'),f.receipt([f.root/n for n in REQUIRED]+[f.root/'extra']),append(f.root/'extra')))
    add('missing-vmlinux',lambda f:rm(f.build/'vmlinux'))
    for name in ('dma_poll_runtime.c','xdev_ext_dma_provider_sim.c'):
        add('missing-provider-copy-'+name,lambda f,n=name:rm(f.tools/('dma-provider/'+n)))
        add('changed-provider-copy-'+name,lambda f,n=name:append(f.tools/('dma-provider/'+n)))
    add('module-vermagic',lambda f:f.env.update(FIXTURE_VERMAGIC='wrong-release'))
    add('nonexecutable-controller',lambda f:(f.tools/'xdev_ext_mech_ctl').chmod(0o644))
    add('nonexecutable-runtime',lambda f:(f.tools/'dma-provider/dma_poll_runtime').chmod(0o644))
    add('config-required',lambda f:(put(f.build/'.config',(f.build/'.config').read_text().replace('CONFIG_MODULES=y','CONFIG_MODULES=n')),f.receipt()))
    add('red-vermagic-exception-positive',lambda f:(setattr(f,'red',1),f.env.update(FIXTURE_VERMAGIC='older-release')),True)
    add('red-missing-receipt-refused',lambda f:(setattr(f,'red',1),rm(receipt(f))))
    return cases

def execute(cases,defs,base):
    results=[]
    for i,(name,change,want,artifact) in enumerate(cases):
        with tempfile.TemporaryDirectory(prefix=f"case-{i:03d}-space ' quoted-",dir=base) as temp:
            f=Fixture(Path(temp))
            # Each mutation starts from a real independently checked prepared
            # assembly; prerequisite fixture validity is not inferred from DUT.
            f.prepare_check()
            change(f)
            is_artifact=any(x[0]==name for x in artifact_cases())
            prerequisite=f.invoke(defs,artifacts=False) if is_artifact else None
            p=f.invoke(defs,artifacts=artifact if want or is_artifact else False)
            match=re.search(r'^RESOLVED\|(.+)$',p.stdout,re.M)
            good=(p.returncode==0)==want
            if want:
                expected=[str(f.repo),git(f.repo,'rev-parse','HEAD'),str(f.native),str(f.repo/'tests/core/poll'),str(f.repo/'docs/reference/xdev_ext-poll.rst'),str(f.repo/'tests/core/provider'),(f.build/'xdev-ext-source.commit').read_text().strip()]
                good=good and bool(match) and match.group(1).split('|')==expected
                if artifact:
                    metadata=f.root/'modinfo.log'
                    expected_metadata='-F vermagic '+str(f.tools/'dma-provider/xdev_ext_dma_provider_sim.ko')
                    good=good and metadata.is_file() and expected_metadata in metadata.read_text().splitlines()
                if f.red:good=good and not re.search(r'\bPASS\b',p.stdout)
            else:
                # Named case is applied to a previously independently checked
                # positive assembly. Do not count shell syntax/command errors.
                good=good and p.returncode not in (2,99,126,127) and bool(p.stdout+p.stderr)
                if prerequisite is not None:good=good and prerequisite.returncode==0
                output=(p.stdout+'\n'+p.stderr).lower()
                # Assert the named gate family; generic shell errors cannot
                # count as a successful refusal. Exact prose is not frozen.
                if is_artifact:
                    tokens = ('receipt','artifact','sha256','checksum','hash','missing','prebuilt','rebuild','config','vermagic','release','provider','executable','permission','differ','mismatch')
                else:
                    tokens = ('source','canonical','assembly','marker','layout','git','dirty','tracked','build','revision','commit','diff','symlink','poll','lock','mapping','overlay','native','status')
                good=good and any(t in output for t in tokens)
            row={'case':name,'expected':'accept' if want else 'refuse','status':'PASS' if good else 'FAIL','returncode':p.returncode,'stdout':p.stdout[-12000:],'stderr':p.stderr[-12000:]}
            results.append(row);print(row['status'],name,flush=True)
    return results

def baseline(base):
    rows=[]
    for legacy in (False,True):
        with tempfile.TemporaryDirectory(prefix='baseline-',dir=base) as tmp:
            f=Fixture(Path(tmp))
            if legacy:
                # A genuinely tracked historical tree, not symlink path aliases.
                for native,source in f.mapping.items():put(f.repo/('kernel/'+native),(f.repo/source).read_text())
                f.sha=commit(f.repo,'old layout source fixture');put(f.build/'xdev-ext-source.commit',f.sha+'\n')
                f.receipt([f.root/n for n in REQUIRED if n!='tools/dma-provider/dma_poll_runtime'])
            p=f.invoke(old=True)
            good=p.returncode==0 if legacy else p.returncode!=0 and 'kernel/tools/testing/selftests/xdev_ext_mech/provider/dma_poll_runtime.c' in p.stdout+p.stderr
            rows.append({'case':'old-receipt-runtime-omission-accepted' if legacy else 'old-canonical-legacy-path-failure','observed':good,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
            print('OBSERVED' if good else 'BASELINE-FAIL',rows[-1]['case'])
    return rows

def main():
    global PRODUCT, ARTIFACTS, BASELINE_PREFIX
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product', type=Path, help='canonical product root or logical view (default: PRODUCT or discovery)')
    parser.add_argument('--artifacts', type=Path, help='fixture and JSON output directory (default: ARTIFACTS or PRODUCT/build/poll-source-setup)')
    parser.add_argument('--runner',type=Path, help='runner to extract setup functions from (default: native-path product mapping)')
    parser.add_argument('--baseline',action='store_true')
    parser.add_argument('--baseline-prefix',type=Path, help='explicit historical source-only prefix, required with --baseline')
    parser.add_argument('--mutations',action='store_true')
    parser.add_argument('--only',default='')
    parser.add_argument('--fixture-check',action='store_true')
    args=parser.parse_args()
    if args.baseline and args.baseline_prefix is None:
        parser.error('--baseline requires an explicit --baseline-prefix; historical evidence is not bundled')
    try:
        PRODUCT=discover_product(args.product or os.environ.get('PRODUCT'))
        ARTIFACTS=Path(args.artifacts or os.environ.get('ARTIFACTS') or PRODUCT/'build/poll-source-setup').expanduser().absolute()
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        BASELINE_PREFIX=args.baseline_prefix
        if BASELINE_PREFIX is not None:
            BASELINE_PREFIX=BASELINE_PREFIX.expanduser().absolute()
            if not BASELINE_PREFIX.is_file():
                raise ValueError(f'Missing explicit historical prefix: {BASELINE_PREFIX}')
        args.runner=args.runner or default_runner()
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    with tempfile.TemporaryDirectory(prefix='source-fixture-run-',dir=ARTIFACTS) as temp:
        base=Path(temp)
        if args.baseline:
            rows=baseline(base);put(ARTIFACTS/'baseline.json',json.dumps({'claim':'SOURCE FIXTURE ONLY; not native proof','results':rows},indent=2)+'\n');return 0 if all(x['observed'] for x in rows) else 1
        if args.fixture_check:
            cases=source_cases()+artifact_cases()
            for i,(name,change,want,artifact) in enumerate(cases):
                with tempfile.TemporaryDirectory(prefix=f'fixture-{i:03d}-',dir=base) as tmp:
                    f=Fixture(Path(tmp));f.prepare_check();change(f)
                print('FIXTURE',name,flush=True)
            print(str(len(cases))+' real fixture constructions checked; no DUT executed')
            return 0
        defs=source_defs(args.runner)
        if defs is None:
            print('SETUP: frozen future setup functions absent; not behavioral RED');return 3
        cases=source_cases()+artifact_cases()
        if args.only:cases=[c for c in cases if args.only in c[0]]
        rows=execute(cases,defs,base)
        report={'claim':'SOURCE FIXTURE ONLY; not native proof','results':rows}
        if args.mutations:
            # Execute permissive substitutions in extracted SOURCE COPIES only.
            # One preserves all real source work but bypasses artifacts; the
            # other supplies valid resolved paths while bypassing source gates.
            artifact_bypass=defs+'\nverify_poll_artifacts() { :; }\n'
            mr=execute([x for x in artifact_cases() if x[0]=='missing-receipt'],artifact_bypass,base)
            source_bypass=defs+'''\nresolve_poll_source() {
 SOURCE_GIT_ROOT=$SOURCE
 HEAD_SHA=$(git -C "$SOURCE" rev-parse HEAD)
 NATIVE_SOURCE=$(readlink -f "$BUILD/source")
 POLL_SOURCE=$SOURCE/tests/core/poll
 POLL_SPEC=$SOURCE/docs/reference/xdev_ext-poll.rst
 PROVIDER_SOURCE=$SOURCE/tests/core/provider
 BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
}
'''
            sr=execute([x for x in source_cases() if x[0]=='untracked'],source_bypass,base)
            report['mutation_sensitivity']={'artifact_validation_bypass_caught':mr[0]['status']=='FAIL','source_validation_bypass_caught':sr[0]['status']=='FAIL','raw':mr+sr}
        put(ARTIFACTS/'results.json',json.dumps(report,indent=2)+'\n')
        failed=sum(x['status']=='FAIL' for x in rows)
        print(f'{len(rows)} cases; {failed} failures; SOURCE FIXTURE ONLY')
        return int(bool(failed) or bool(args.mutations and not all(v for k,v in report['mutation_sensitivity'].items() if k!='raw')))

if __name__=='__main__':sys.exit(main())
