"""Local-first Mod manager. No arbitrary package scripts; no save inspection.

Transactions rebuild the requested combination from immutable per-file bases.
State/journal files are validated before use. Crash recovery never trusts only
the journal phase: it verifies the bytes on both sides before restoring them.
"""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
import copy, hashlib, json, os, re, shutil, socket, stat, struct, subprocess, time, uuid, zipfile
from resources import Pack, build_pack, record_read, digest

VERSION='0.2.0'
HOST_SHA='e5e647530d312fb571f98c59ee1bda688f9b321962862a8df034c19f47abf6c4'
DEMO_EXE=b'A9MOD_MANAGER_ISOLATED_DEMO_NOT_A_GAME\n'
DEMO_SHA=digest(DEMO_EXE)
MANAGED='.a9mod-manager'
PUBLIC=('main.pack','gin.pack','mdc.pack','mde.pack','tex.pack','dinput8.dll','a9emu/profile.py','a9emu/business.py','a9emu/cardb.py','a9emu/gamedata/A9-business.gdb','a9emu/gamedata/car_ids.json')
PUBLIC=PUBLIC+('a9emu/a9mod_runtime.py','a9emu/gamedata/A9-mod-retired.gdb')
BASE_REQUIRED=('main.pack','gin.pack','mdc.pack','mde.pack','tex.pack','a9emu/server.py','a9emu/core.py','a9emu/httpd.py','a9emu/career.py')
HEX=re.compile(r'^[0-9a-f]{64}$');ID=re.compile(r'^[a-z0-9][a-z0-9._-]{0,79}$')
PRIVATE={'data','profiles','profile','saves','save','logs','backups','original','accounts','preferences','settings'}
RESERVED={'con','prn','aux','nul',*[f'com{i}' for i in range(1,10)],*[f'lpt{i}' for i in range(1,10)]}
MAX_PAYLOAD=4*1024**3;MAX_TOTAL=16*1024**3

class ModError(ValueError): pass
def need(v,message):
    if not v: raise ModError(message)
def now(): return datetime.now(timezone.utc).isoformat()
def sha_file(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''): h.update(b)
    return h.hexdigest()
def json_read(p):
    need(Path(p).stat().st_size<=8*1024*1024,'JSON文件过大')
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d,'JSON包含重复字段');d[k]=v
        return d
    return json.loads(Path(p).read_text(encoding='utf-8-sig'),object_pairs_hook=pairs)
def atomic_json(p,value):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        with tmp.open('x',encoding='utf-8') as f: json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        if tmp.exists(): tmp.unlink()
def relative(name):
    need(isinstance(name,str) and name and len(name)<=240,'无效路径')
    need(not any(ord(c)<32 or ord(c)==127 for c in name) and not any(c in name for c in '\\:<>"|?*'),'不安全路径')
    p=PurePosixPath(name)
    need(not p.is_absolute() and p.as_posix()==name,'路径必须为规范相对路径')
    for part in p.parts:
        need(part not in ('.','..','') and not part.endswith((' ','.')) and part.split('.')[0].casefold() not in RESERVED,'不安全路径名称')
    return name
def safe_path(root,name):
    relative(name);root=Path(root).absolute();dest=root.joinpath(*PurePosixPath(name).parts)
    need(dest.resolve().is_relative_to(root.resolve()),'路径超出所选目录')
    for p in (dest,*dest.parents):
        try: info=p.lstat()
        except FileNotFoundError: info=None
        if info: need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'拒绝符号链接或目录联接')
        if p==root: break
    return dest
def target_name(name,demo=False):
    relative(name)
    allowed=set(PUBLIC)|({'demo/a.txt','demo/b.txt','demo/new.txt'} if demo else set())
    need(name in allowed,'不允许修改此位置：'+name)
    return name
def verify_row(p,row):
    if row is None: need(not p.exists(),'预期不存在的文件已经出现：'+p.name)
    else: need(p.is_file() and p.stat().st_size==row['bytes'] and sha_file(p)==row['sha256'],'文件被修改或缺失：'+p.name)
def file_row(p): return {'sha256':sha_file(p),'bytes':p.stat().st_size} if p.is_file() else None

def patch_resource_pins(raw,profile,main_sha,gin_sha):
    need(all(isinstance(h,str) and HEX.fullmatch(h) for h in (main_sha,gin_sha)),'新资源摘要无效')
    offsets=[profile['main_offset'],profile['gin_offset']];checksum=profile['checksum_offset']
    need(all(type(o) is int and 0<=o<=len(raw)-32 for o in offsets) and abs(offsets[0]-offsets[1])>=32,'资源校验布局无效')
    need(type(checksum) is int and 0<=checksum<=len(raw)-4 and struct.unpack_from('<I',raw,checksum)[0]==0,'不支持此PE校验布局')
    for name,o in zip(('main.pack','gin.pack'),offsets):need(raw[o:o+32].hex()==profile[name] and raw.count(bytes.fromhex(profile[name]))==1,'基础加载器校验槽不匹配')
    out=bytearray(raw)
    for o,h in zip(offsets,(main_sha,gin_sha)):out[o:o+32]=bytes.fromhex(h)
    allowed=set(range(offsets[0],offsets[0]+32))|set(range(offsets[1],offsets[1]+32))
    need(all(i in allowed for i,(a,b) in enumerate(zip(raw,out,strict=True)) if a!=b),'加载器功能代码发生变化')
    return bytes(out)

class Package:
    def __init__(self,path):
        self.path=Path(path).resolve(strict=True)
        need(self.path.is_file(),'Mod包不存在')
        with zipfile.ZipFile(self.path) as z:
            infos=z.infolist();need(0<len(infos)<=10000,'包内文件数量异常');names=set();total=0
            for info in infos:
                name=info.filename[:-1] if info.is_dir() else info.filename
                relative(name);need(name.casefold() not in names,'包内路径重复或大小写冲突');names.add(name.casefold())
                mode=info.external_attr>>16
                need(not stat.S_ISLNK(mode) and not info.flag_bits&1,'不支持链接或加密ZIP')
                need(info.file_size<=MAX_PAYLOAD,'包内单文件超限');total+=info.file_size
            need(total<=MAX_TOTAL,'包内展开大小超限')
            candidates=[i.filename for i in infos if not i.is_dir() and PurePosixPath(i.filename).name=='manifest.json']
            need(len(candidates)==1,'需要唯一的manifest.json；技术资料包不能当安装包使用')
            name=candidates[0];self.prefix=name[:-len('manifest.json')]
            need(z.getinfo(name).file_size<=4*1024*1024,'Mod清单过大')
            raw=z.read(name);self.manifest_hash=digest(raw)
            m=json.loads(raw.decode('utf-8-sig'));self.official=False
            if m.get('schema')=='A9MOD_GROUP_PACKAGE_V2':
                from group_packages import initialise
                initialise(self,m,z);return
            self.legacy=str(m.get('schema','')).startswith('A9_SHARE_MOD')
            if self.legacy:
                need(set(m.get('required_executable',{}))=={'path','sha256'} and m['required_executable']['path']=='Asphalt9_emu.exe','旧包缺少目标程序校验')
                self.id='legacy.'+re.sub('[^a-z0-9._-]','-',str(m.get('version','unknown')).lower())
                self.version=str(m['version']);self.title='整合包 '+self.version;self.description='旧版整套覆盖包：只能整体安装／卸载，不能拆分其中车辆。'
                self.host=m['required_executable']['sha256'];self.requires=[];self.conflicts=[]
                self.ops=[]
                for row in m['files']:
                    matches=[self.prefix+'files/'+row['path'],self.prefix+'payload/'+row['path'],self.prefix+row['path']]
                    found=[n for n in matches if n in z.namelist()]
                    need(len(found)==1,'旧包缺少唯一payload：'+row['path'])
                    self.ops.append(dict(kind='file',target=row['path'],source=found[0][len(self.prefix):],sha256=row['sha256'],bytes=row['bytes'],base_sha256='adopt'))
            else:
                need(m.get('schema')=='A9MOD_PACKAGE_V1','该ZIP是资料包或尚不支持的Mod格式')
                self.id=m.get('id');self.version=m.get('version');self.title=m.get('title');self.description=m.get('description','')
                self.host=m.get('host_sha256');self.requires=m.get('requires',[]);self.conflicts=m.get('conflicts',[]);self.ops=m.get('operations')
            need(isinstance(self.id,str) and ID.fullmatch(self.id),'Mod编号无效')
            need(isinstance(self.version,str) and 0<len(self.version)<=80 and isinstance(self.title,str) and 0<len(self.title)<=160,'Mod名称或版本无效')
            need(isinstance(self.description,str) and len(self.description)<=16000,'Mod说明无效')
            need(isinstance(self.host,str) and HEX.fullmatch(self.host),'缺少目标EXE指纹')
            for lst in (self.requires,self.conflicts): need(isinstance(lst,list) and all(isinstance(x,str) and ID.fullmatch(x) for x in lst),'依赖或冲突编号无效')
            need(isinstance(self.ops,list) and 0<len(self.ops)<=4096,'操作清单为空或过大')
            self.demo=self.host==DEMO_SHA
            for op in self.ops:
                need(isinstance(op,dict) and op.get('kind') in ('file','resource','record'),'不支持的操作；禁止执行包内脚本')
                target_name(op.get('target'),self.demo);relative(op.get('source'))
                need(isinstance(op.get('sha256'),str) and HEX.fullmatch(op['sha256']),'payload缺少SHA256')
                need(type(op.get('bytes')) is int and 0<=op['bytes']<=MAX_PAYLOAD,'payload大小无效')
                before=op.get('base_sha256')
                need(before is None or isinstance(before,str) and (HEX.fullmatch(before) or self.legacy and before=='adopt'),'缺少原始内容校验')
                item=z.getinfo(self.prefix+op['source']);need(not item.is_dir() and item.file_size==op['bytes'],'payload缺失或长度不同')
                if op['kind']!='file':
                    need(op['target'] in ('main.pack','mdc.pack','mde.pack','tex.pack'),'首版仅支持这些原生资源包；gin内部压缩布局暂未开放')
                    need(isinstance(op.get('logical_path'),str) and op['logical_path'].startswith('/') and len(op['logical_path'])<=4096,'缺少资源逻辑路径')
                    need(before is not None,'此版资源操作只支持替换现有内容')
                if op['kind']=='record':
                    for k in ('uid','record_type'): need(isinstance(op.get(k),str) and re.fullmatch('[0-9a-f]{16}',op[k]),'记录身份无效')
            self.payload_bytes=sum(o['bytes'] for o in self.ops)
            self.summary={'id':self.id,'version':self.version,'title':self.title,'description':self.description,'host_sha256':self.host,'requires':self.requires,'conflicts':self.conflicts,'legacy':self.legacy,'demo':self.demo,'operations':len(self.ops),'payload_bytes':self.payload_bytes}
    def reference(self): return {'archive':str(self.path),'manifest_sha256':self.manifest_hash,'id':self.id,'version':self.version}
    def verify_reference(self,ref): need(self.reference()==ref,'Mod包被移动、替换或清单变化，请重新导入：'+self.title)
    def verify_payloads(self):
        if self.official:
            from group_packages import verify
            return verify(self)
        with zipfile.ZipFile(self.path) as z:
            for op in self.ops:
                h=hashlib.sha256();size=0
                with z.open(self.prefix+op['source']) as f:
                    for b in iter(lambda:f.read(4*1024*1024),b''): h.update(b);size+=len(b)
                need(size==op['bytes'] and h.hexdigest()==op['sha256'],'Mod内容校验失败：'+op['source'])
    def payload(self,op):
        need(op['bytes']<=64*1024*1024,'资源操作超过64MiB界限')
        with zipfile.ZipFile(self.path) as z: b=z.read(self.prefix+op['source'])
        need(len(b)==op['bytes'] and digest(b)==op['sha256'],'Mod素材变化');return b
    def copy_payload(self,op,dest):
        with zipfile.ZipFile(self.path) as z,z.open(self.prefix+op['source']) as src,Path(dest).open('xb') as out: shutil.copyfileobj(src,out,4*1024*1024)
        need(sha_file(dest)==op['sha256'],'复制后的Mod内容校验失败')

class Manager:
    def __init__(self,root,*,demo=False):
        self.root=Path(root).absolute();self.demo=demo
        need(self.root.is_dir(),'游戏目录不存在');safe_path(self.root,'Asphalt9_emu.exe')
        self.host=sha_file(self.root/'Asphalt9_emu.exe')
        need(self.host==(DEMO_SHA if demo else HOST_SHA),'此版仅支持已确认的国际服离线4.7.0d；演示目录须用演示模式打开')
        self.store=safe_path(self.root,MANAGED)
    def load(self):
        p=safe_path(self.store,'state.json')
        if not p.exists(): return {'schema':'A9MOD_STATE_V1','host_sha256':self.host,'mods':[],'files':{},'previous_mods':[]}
        s=json_read(p);need(s.get('schema')=='A9MOD_STATE_V1' and s.get('host_sha256')==self.host,'管理状态与游戏不匹配')
        need(isinstance(s.get('files'),dict) and isinstance(s.get('mods'),list) and isinstance(s.get('previous_mods'),list),'管理状态无效')
        for name,r in s['files'].items():
            target_name(name,self.demo);need(set(r)=={'base','current'},'资源状态无效')
            for row in r.values():
                need(row is None or isinstance(row,dict) and set(row)=={'sha256','bytes'} and isinstance(row['sha256'],str) and HEX.fullmatch(row['sha256']) and type(row['bytes']) is int and row['bytes']>=0,'资源状态摘要无效')
        for ref in s['mods']+s['previous_mods']:
            need(set(ref)=={'archive','manifest_sha256','id','version'} and isinstance(ref['manifest_sha256'],str) and HEX.fullmatch(ref['manifest_sha256']) and ID.fullmatch(ref['id']),'已装Mod引用无效')
        return s
    def object(self,sha):
        need(isinstance(sha,str) and HEX.fullmatch(sha),'恢复对象摘要无效');return safe_path(self.store,'objects/'+sha+'.bin')
    def base_path(self,name,state):
        if name in state['files']:
            row=state['files'][name]['base']
            if row is None: return None
            p=self.object(row['sha256']);verify_row(p,row);return p
        p=safe_path(self.root,name);return p if p.exists() else None
    def inspect(self):
        s=self.load();differences=[]
        for name,r in s['files'].items():
            try: verify_row(safe_path(self.root,name),r['current']);self.base_path(name,s)
            except (ModError,OSError) as e: differences.append(str(e))
        missing=[] if self.demo else [n for n in BASE_REQUIRED if not safe_path(self.root,n).is_file()]
        return {'version':VERSION,'supported_host':True,'managed':bool(s['files']),'installed':[{'id':r['id'],'version':r['version']} for r in s['mods']],'differences':differences,'missing_base_files':missing,'recovery_required':(self.store/'transaction.json').exists(),'base_files':len(s['files']),'base_bytes':sum((r['base'] or {}).get('bytes',0) for r in s['files'].values())}
    def _busy(self):
        if self.demo: return
        if os.name=='nt':
            result=subprocess.run(['tasklist.exe','/FI','IMAGENAME eq Asphalt9_emu.exe','/FO','CSV','/NH'],capture_output=True,text=True,errors='replace',creationflags=0x08000000,timeout=10)
            need(result.returncode==0,'无法检查游戏进程，请稍后重试')
            need('asphalt9_emu.exe' not in result.stdout.lower(),'请先关闭游戏，再安装或卸载Mod')
        for port in (18080,18081):
            with socket.socket() as sock:
                sock.settimeout(.2);need(sock.connect_ex(('127.0.0.1',port))!=0,'请先关闭离线服务端，再安装或卸载Mod')
    @contextmanager
    def lock(self):
        self.store.mkdir(exist_ok=True);p=safe_path(self.store,'operation.lock')
        f=p.open('a+b')
        try:
            if os.name=='nt':
                import msvcrt
                if p.stat().st_size==0: f.write(b'0');f.flush()
                f.seek(0)
                try: msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
                except OSError: raise ModError('另一个管理器正在操作此游戏')
            else:
                import fcntl
                try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except OSError: raise ModError('另一个管理器正在操作此游戏')
            yield
        finally: f.close()
    def packages(self,refs):
        result=[]
        for ref in refs:
            p=Package(ref['archive']);p.verify_reference(ref);result.append(p)
        return result
    def plan(self,packages):
        need(not (self.store/'transaction.json').exists(),'检测到上次操作中断，请先执行“恢复中断操作”')
        state=self.load();inspection=self.inspect();need(not inspection['differences'],'已管理的资源或恢复材料有变化；请先检查，不能直接覆盖')
        need(not inspection['missing_base_files'],'缺少底包文件：'+', '.join(inspection['missing_base_files'])+'。Mod包不能补齐完整离线底包。')
        need(sha_file(self.root/'Asphalt9_emu.exe')==self.host,'目标程序已经变化')
        if any(p.official for p in packages):
            from official207 import make_plan
            return make_plan(self,packages,state)
        ids=[p.id for p in packages];need(len(ids)==len(set(ids)),'同一个Mod不能同时安装两个版本')
        if any(p.legacy for p in packages): need(len(packages)==1,'旧版整合包必须单独使用；它不能与独立模块叠加')
        grouped={};claims={}
        for p in packages:
            need(p.host==self.host,'Mod适用游戏版本不一致：'+p.title)
            need(set(p.requires)<=set(ids),'缺少依赖：'+', '.join(sorted(set(p.requires)-set(ids))))
            need(not set(p.conflicts)&set(ids),'Mod声明冲突：'+p.title)
            for op in p.ops:
                name=op['target'];identity=(name,op.get('logical_path'),op.get('uid'),op.get('record_type'))
                for prev,owner in claims.items():
                    if prev[0]==name and (prev[1] is None or identity[1] is None or prev[1]==identity[1] and (prev[2] is None or identity[2] is None or prev[2:]==identity[2:])):
                        raise ModError(f'修改冲突：{owner} / {p.title} → {name} {op.get("logical_path","")} {op.get("uid","")}')
                claims[identity]=p.title;grouped.setdefault(name,[]).append((p,op))
        candidates=set(grouped)|{n for n,r in state['files'].items() if r['current']!=r['base']}
        if any(n in ('main.pack','gin.pack') and any(o['kind']!='file' for _,o in ops) for n,ops in grouped.items()) and not self.demo:candidates.add('dinput8.dll')
        expected_current={name:state['files'][name]['current'] if name in state['files'] else file_row(safe_path(self.root,name)) for name in candidates}
        for name,row in expected_current.items():verify_row(safe_path(self.root,name),row)
        for name,ops in grouped.items():
            base=self.base_path(name,state);pack=None
            try:
                for p,op in ops:
                    before=op['base_sha256']
                    if op['kind']=='file':
                        actual=sha_file(base) if base else None
                    else:
                        need(base is not None,'基础资源包不存在：'+name)
                        if pack is None: pack=Pack(base,name.split('.')[0])
                        raw=pack.read(op['logical_path'])
                        if op['kind']=='record': raw=record_read(raw,op['uid'],op['record_type'])
                        actual=digest(raw)
                    need(before=='adopt' and p.legacy or before==actual,'Mod所需的基础内容不匹配：'+p.title+' → '+name)
            finally:
                if pack: pack.close()
        affected=set(grouped)|{n for n,r in state['files'].items() if r['current']!=r['base']}
        native=any(name in ('main.pack','gin.pack') and any(o['kind']!='file' for _,o in ops) for name,ops in grouped.items())
        if native and not self.demo:
            need('dinput8.dll' not in grouped,'资源组合中的加载器由管理器统一生成，不能叠加DLL覆盖')
            self._pin_profile(state);affected.add('dinput8.dll')
        base_bytes=sum(self.base_path(n,state).stat().st_size if self.base_path(n,state) else 0 for n in affected)
        new_base=sum((self.base_path(n,state).stat().st_size if self.base_path(n,state) else 0) for n in affected if n not in state['files'])
        payload=sum(p.payload_bytes for p in packages)
        required=new_base+base_bytes+payload+64*1024*1024
        free=shutil.disk_usage(self.root).free
        need(set(expected_current)==affected,'计划资源集合在校验过程中变化')
        for name,row in expected_current.items():verify_row(safe_path(self.root,name),row)
        return {'state':state,'packages':packages,'grouped':grouped,'affected':sorted(affected),'native':native,'new_base_bytes':new_base,'estimated_temporary_bytes':required,'free_bytes':free,'space_ok':free>=required,'base_bytes':base_bytes,'expected_current_rows':expected_current}
    def _pin_profile(self,state):
        from baseline_profiles import PROFILES
        p=self.base_path('dinput8.dll',state);need(p is not None,'缺少匹配的基础加载器')
        h=sha_file(p);need(h in PROFILES,'当前加载器尚未登记资源校验布局；请更新管理器或使用完整匹配包')
        profile=PROFILES[h];raw=p.read_bytes()
        for name,offset in (('main.pack',profile['main_offset']),('gin.pack',profile['gin_offset'])):
            base=self.base_path(name,state);need(base is not None and sha_file(base)==profile[name],'加载器与基础资源校验不匹配')
            need(raw[offset:offset+32].hex()==profile[name] and raw.count(bytes.fromhex(profile[name]))==1,'加载器校验位置验证失败')
        return raw,profile
    def _save_base(self,name,state,expected):
        verify_row(safe_path(self.root,name),expected)
        if name in state['files']: return
        src=safe_path(self.root,name);row=expected
        if row:
            dest=self.object(row['sha256']);dest.parent.mkdir(exist_ok=True)
            if not dest.exists():
                temp=dest.with_suffix('.'+uuid.uuid4().hex+'.tmp')
                try: shutil.copyfile(src,temp);verify_row(temp,row);os.replace(temp,dest)
                finally:
                    if temp.exists(): temp.unlink()
            verify_row(dest,row)
        verify_row(src,expected)
        state['files'][name]={'base':row,'current':row}
    def apply(self,packages,progress=lambda s:None,fail_after=None):
        self._busy()
        with self.lock():
            plan=self.plan(packages);need(plan['space_ok'],'空间不足：需要约 %.2f GiB，当前 %.2f GiB'%(plan['estimated_temporary_bytes']/1024**3,plan['free_bytes']/1024**3))
            for p in packages: progress('校验素材：'+p.title);p.verify_payloads()
            previous=self.load();state=copy.deepcopy(previous)
            need(previous==plan['state'],'管理状态在预览后变化，请重新检查')
            for name,row in plan['expected_current_rows'].items():verify_row(safe_path(self.root,name),row)
            for name in plan['affected']: progress('保留唯一基础副本：'+name);self._save_base(name,state,plan['expected_current_rows'][name])
            token=uuid.uuid4().hex;area=safe_path(self.store,'transactions/'+token);stage=area/'stage';old=area/'old';stage.mkdir(parents=True);old.mkdir()
            rows=[]
            try:
                if plan.get('official'):
                    from official207 import stage_combination
                    stage_combination(self,plan,stage,state,progress)
                for name in plan['affected']:
                    if plan.get('official'):continue
                    progress('生成所选组合：'+name);dest=safe_path(stage,name);dest.parent.mkdir(parents=True,exist_ok=True);ops=plan['grouped'].get(name,[])
                    if name=='dinput8.dll' and plan['native'] and not self.demo: continue
                    if ops:
                        if ops[0][1]['kind']=='file': ops[0][0].copy_payload(ops[0][1],dest)
                        else:
                            ownership={id(o):p for p,o in ops}
                            build_pack(self.base_path(name,state),dest,[o for _,o in ops],lambda o:ownership[id(o)].payload(o))
                    else:
                        base=self.base_path(name,state)
                        if base: shutil.copyfile(base,dest)
                if plan['native'] and not self.demo:
                    progress('生成匹配资源校验的公共加载器');raw,profile=self._pin_profile(state);pins=[]
                    for name,key in (('main.pack','main_offset'),('gin.pack','gin_offset')):
                        selected=safe_path(stage,name)
                        if not selected.exists(): selected=safe_path(self.root,name)
                        pins.append(sha_file(selected))
                    d=safe_path(stage,'dinput8.dll')
                    with d.open('xb') as stream:stream.write(patch_resource_pins(raw,profile,*pins))
                for name in plan['affected']:
                    candidate=safe_path(stage,name)
                    if candidate.exists():
                        with candidate.open('r+b') as stream:os.fsync(stream.fileno())
                    before=plan['expected_current_rows'][name];after=file_row(safe_path(stage,name));rows.append({'target':name,'before':before,'after':after});state['files'][name]['current']=after
                state['previous_mods']=previous['mods'];state['mods']=[p.reference() for p in packages];state['updated_utc']=now()
                if not plan.get('official'):state.pop('module_profile',None)
                journal={'schema':'A9MOD_TRANSACTION_V1','token':token,'phase':'prepared','before_state':previous,'after_state':state,'rows':rows,'created_utc':now()}
                if plan.get('official'):journal['composition_proof']=plan['composition_proof']
                for r in rows:verify_row(safe_path(self.root,r['target']),r['before'])
                atomic_json(self.store/'transaction.json',journal)
                self._busy();need(self.load()==previous,'管理状态在准备阶段变化')
                for r in rows: verify_row(safe_path(self.root,r['target']),r['before'])
                for i,r in enumerate(rows):
                    name=r['target'];current=safe_path(self.root,name);saved=safe_path(old,name);candidate=safe_path(stage,name)
                    current.parent.mkdir(parents=True,exist_ok=True);saved.parent.mkdir(parents=True,exist_ok=True)
                    verify_row(current,r['before'])
                    if r['before'] is not None: os.replace(current,saved)
                    if r['after'] is not None: os.replace(candidate,current)
                    verify_row(current,r['after']);progress('提交：'+name)
                    if fail_after is not None and i+1==fail_after: raise RuntimeError('TEST simulated interruption')
                atomic_json(self.store/'state.json',state);journal['phase']='committed';atomic_json(self.store/'transaction.json',journal)
                self._cleanup(journal);progress('完成：当前组合已校验；存档未读取或覆盖')
                return self.inspect()
            except BaseException:
                if (self.store/'transaction.json').exists(): self._recover_locked(progress)
                else: self._discard_area(area)
                raise
    def _discard_area(self,area):
        need(area.parent==self.store/'transactions' and area.resolve().is_relative_to((self.store/'transactions').resolve()) and re.fullmatch('[0-9a-f]{32}',area.name),'临时目录边界不符')
        last=None
        for delay in (0,.05,.15,.35,.75):
            if delay:time.sleep(delay)
            if not area.exists():return
            # Recheck the application-owned boundary on every short retry.
            safe_path(self.store,'transactions/'+area.name)
            for p in area.rglob('*'):safe_path(area,p.relative_to(area).as_posix())
            try:shutil.rmtree(area);return
            except OSError as e:
                if getattr(e,'winerror',None) not in (5,32,145):raise
                last=e
        raise last
    def _validate_journal(self,j):
        need(j.get('schema')=='A9MOD_TRANSACTION_V1' and isinstance(j.get('token'),str) and re.fullmatch('[0-9a-f]{32}',j['token']),'中断记录无效')
        need(j.get('phase') in ('prepared','committed') and isinstance(j.get('rows'),list) and len(j['rows'])<=len(PUBLIC)+3,'中断记录范围无效')
        seen=set()
        for r in j['rows']:
            name=target_name(r['target'],self.demo);need(name not in seen,'中断记录重复');seen.add(name)
            for v in (r['before'],r['after']):
                need(v is None or isinstance(v,dict) and set(v)=={'bytes','sha256'} and type(v['bytes']) is int and v['bytes']>=0 and isinstance(v['sha256'],str) and HEX.fullmatch(v['sha256']),'中断记录摘要无效')
        for k in ('before_state','after_state'):
            s=j[k];need(s.get('schema')=='A9MOD_STATE_V1' and s.get('host_sha256')==self.host,'中断记录目标不符')
        need(set(j['after_state']['files'])>=seen,'中断记录状态缺失')
        for r in j['rows']: need(j['after_state']['files'][r['target']]['current']==r['after'],'中断记录新状态不匹配')
    def _cleanup(self,j):
        self._discard_area(safe_path(self.store,'transactions/'+j['token']));(self.store/'transaction.json').unlink(missing_ok=True)
    def _recover_locked(self,progress):
        p=safe_path(self.store,'transaction.json');need(p.is_file(),'没有待恢复的中断操作');j=json_read(p);self._validate_journal(j)
        if self.load()==j['after_state']:
            for r in j['rows']: verify_row(safe_path(self.root,r['target']),r['after'])
            self._cleanup(j);progress('已确认上次提交完整，清理临时材料');return
        need(self.load()==j['before_state'],'管理状态有外部变化，停止自动恢复')
        old=safe_path(self.store,'transactions/'+j['token']+'/old')
        # Validate every restoration before making any restoration mutation.
        for r in j['rows']:
            current=safe_path(self.root,r['target']);saved=safe_path(old,r['target']);actual=file_row(current)
            need(actual in (r['before'],r['after'],None),'资源被外部改动，保留现场并停止恢复：'+r['target'])
            if r['before'] is not None and actual!=r['before']: verify_row(saved,r['before'])
            if saved.exists(): verify_row(saved,r['before'])
        for r in reversed(j['rows']):
            current=safe_path(self.root,r['target']);saved=safe_path(old,r['target'])
            if r['before'] is None:
                if current.exists(): current.unlink()
            elif file_row(current)!=r['before']: os.replace(saved,current)
            verify_row(current,r['before'])
        self._cleanup(j);progress('已恢复到操作前；存档未读取或覆盖')
    def recover(self,progress=lambda s:None):
        self._busy()
        with self.lock(): self._recover_locked(progress)
        return self.inspect()
    def clear_recovery_cache(self,progress=lambda s:None):
        """Clear only content-addressed public snapshots after full withdrawal.

        This never traverses a player's data or recursively deletes a game
        folder. An interrupted cleanup can be retried against restored files.
        """
        if not self.store.exists():return {'cleared_bytes':0,'files':0}
        with self.lock():
            need(not (self.store/'transaction.json').exists(),'请先恢复中断操作')
            state=self.load();need(not state['mods'],'尚有模块或公共核心启用，不能删除恢复副本')
            for name,row in state['files'].items():
                need(row['current']==row['base'],'请先撤回到接管前，再清理副本')
                verify_row(safe_path(self.root,name),row['base'])
            folder=safe_path(self.store,'objects');cleared=0;count=0
            registered={row['base']['sha256'] for row in state['files'].values() if row['base'] is not None}
            if folder.exists():
                files=list(folder.iterdir())
                for path in files:
                    need(path.is_file() and re.fullmatch(r'[0-9a-f]{64}\.bin',path.name),'恢复目录中存在未登记文件，停止清理')
                    need(path.stem in registered,'恢复目录中存在未登记对象，保留现场并停止清理')
                    checked=safe_path(self.store,'objects/'+path.name);need(sha_file(checked)==path.stem,'恢复文件摘要不符，停止清理')
                for path in files:
                    checked=safe_path(self.store,'objects/'+path.name);size=checked.stat().st_size
                    checked.unlink();cleared+=size;count+=1;progress('清理已撤回的恢复副本：'+str(count))
            safe_path(self.store,'state.json').unlink(missing_ok=True)
            return {'cleared_bytes':cleared,'files':count,'game_files_modified':False,'personal_data_opened':False}

def public_probe(root):
    m=Manager(root);report=m.inspect();report['public_files']={}
    for name in PUBLIC:
        p=safe_path(m.root,name);report['public_files'][name]=file_row(p)
    report['private_files_opened']=False;report['game_files_modified']=False
    return report
