"""Trusted four-group driver. Inputs are data from validated package files.

Every selection is rebuilt from one immutable adopted installation. Canonical
core banks remove inactive registration and old orphan bodies; owned pack paths
are pruned before enabled resources are added. No source path in a recipe is
interpreted as a local developer path and no package Python is executed.
"""
from pathlib import Path
import hashlib,json,re,shutil
from engine import need,file_row,sha_file,safe_path,PUBLIC,HEX
from group_packages import GROUPS,read_data
from composition import compose_bank,compose_pack,parse_bank
from c9_packaged_resource_index import ManifestEntry
from idb207 import compose_idb
from filter207 import compose_filter
from loader207 import effective_mask,repin_loader
from server207 import compose_result,SOURCE_SHA256
from trusted207 import RUNTIME_SOURCE,NATIVE_TEMPLATES

BASE_PUBLIC=PUBLIC[:11]
SERVER_OUTPUT=set(SOURCE_SHA256)|{'a9emu/a9mod_runtime.py','a9emu/gamedata/A9-mod-retired.gdb'}
MOUNTS=('main','mdc','mde','tex')

def _entry(value):
    need(isinstance(value,dict) and set(value)=={'field0','field1','logical_path','compression_flags','size_value','encryption_flags','stream_password','storage_name'},'原生资源描述字段不符')
    return ManifestEntry(**value)

def _check_payload_ref(p,row):
    need(isinstance(row,dict) and row.get('source') in p.inventory,'未登记的配方素材引用')
    actual=p.inventory[row['source']]
    need(row.get('sha256')==actual['sha256'] and row.get('bytes')==actual['bytes'],'配方与素材清单不一致')
    return read_data(p,row['source'])

def _validate_recipes(core,packages):
    r=core.recipe;need(r.get('protocol')=='A9_FOUR_GROUPS_207','核心协议不受支持')
    need(isinstance(r.get('banks'),list) and len(r['banks'])==8,'核心银行数量不符')
    names=[b['bank'] for b in r['banks']];need(len(set(names))==8 and 'CarDef.gdb' in names and 'Asphalt9.idb' in names,'核心银行缺失或重复')
    bankmap={b['bank']:b for b in r['banks']}
    for p in packages:
        for row in p.recipe.get('records',[]):
            need(row.get('bank') in bankmap and row.get('logical')==bankmap[row['bank']]['logical'],'模块记录归属银行未知')
            for k in ('uid','type'):need(isinstance(row.get(k),str) and re.fullmatch('[0-9a-f]{16}',row[k]),'模块记录身份无效')
            need(type(row.get('source_ordinal')) is int and 0<=row['source_ordinal']<=1000000,'模块记录顺序无效')
            need(row.get('source') in p.inventory,'模块记录素材缺失')
        need(len(p.recipe.get('records',[]))<=4000 and len(p.recipe.get('resources',[]))<=2000 and len(p.recipe.get('groups',[]))<=100,'模块配方数量超限')
        for row in p.recipe.get('resources',[]):
            need(row.get('mount') in MOUNTS and row.get('source') in p.inventory,'模块资源挂载不受支持')
            need(_entry(row['entry']).logical_path==row['logical'],'资源路径不一致')
    return bankmap

def make_plan(manager,packages,state):
    need(all(p.official for p in packages),'四组模块暂不与旧整合包或其他格式模块混装，请先撤回原管理器模块')
    ids=[p.id for p in packages];need(len(ids)==len(set(ids)) and 'a9.core' in ids,'缺少公共核心或模块重复')
    need(all(p.host==manager.host for p in packages),'模块主程序版本不符')
    core=next(p for p in packages if p.id=='a9.core');_validate_recipes(core,packages)
    need(all(p.recipe['core_contract']==core.recipe['core_contract'] for p in packages),'模块与公共核心版本不匹配，请更新成套的包')
    actual={}
    for name in BASE_PUBLIC:
        path=manager.base_path(name,state);actual[name]=file_row(path) if path else None
    matches=[]
    for variant in core.recipe.get('baselines',[]):
        need(set(variant['files'])==set(BASE_PUBLIC),'核心底包指纹集合异常')
        if actual==variant['files']:matches.append(variant['name'])
    need(len(matches)==1,'当前公共文件不匹配已登记的 r200／r203／r206 整合版；本版不会把未知或不完整安装直接当作模块基线')
    for name in SERVER_OUTPUT-set(BASE_PUBLIC):
        if name not in state['files']:need(not safe_path(manager.root,name).exists(),'已有未登记公共运行文件，停止接管：'+name)
    active=sorted(c for p in packages for c in GROUPS[p.id]);need(len(active)==len(set(active)),'模块车型编号重复')
    target_gin=core.recipe['gin']['target_sha256'];gin=actual['gin.pack'];need(gin is not None,'缺少GIN资源包')
    upgrade=gin['sha256']!=target_gin
    if upgrade:need(gin['sha256']==core.recipe['gin'].get('upgrade_from_sha256'),'GIN不匹配已登记的公共图纸底座')
    mask=effective_mask(career='a9.career-restart'in ids,cn='a9.cn-four-cars'in ids)
    affected={m+'.pack' for m in MOUNTS}|SERVER_OUTPUT|{'dinput8.dll'}
    if upgrade:affected.add('gin.pack')
    affected|={n for n,row in state['files'].items() if row['current']!=row['base']}
    base_bytes=0;new_base=0
    for name in affected:
        path=manager.base_path(name,state);size=path.stat().st_size if path else 0;base_bytes+=size
        if name not in state['files']:new_base+=size
    payload=sum(p.payload_bytes for p in packages)
    required=new_base+base_bytes+payload*2+128*1024*1024;free=shutil.disk_usage(manager.root).free
    current={name:state['files'][name]['current'] if name in state['files'] else actual.get(name) for name in affected}
    return {'official':True,'native':False,'state':state,'packages':packages,'grouped':{},'affected':sorted(affected),'new_base_bytes':new_base,'target_directory':str(manager.root),
        'base_bytes':base_bytes,'estimated_temporary_bytes':required,'free_bytes':free,'space_ok':free>=required,
        'expected_current_rows':current,
        'official_meta':{'baseline':matches[0],'active_cids':active,'loader_mask':mask,'gin_upgrade':upgrade},
        'warnings':['首次接管会将既有整合版按当前选择重新合成；未选组的新增车型登记和独占资源会撤回。','旧整合版作为一次性恢复基础保留；模块卸载不会删除玩家已获得的车辆进度。','模块组合的游戏内效果仍需人工验收；氮气采用已验收的兼容版，不含204—206实验。']}

def compose_data(packages):
    """Small-bank/server composition. Used for all16 real-data selections."""
    core=next(p for p in packages if p.id=='a9.core');bankmap=_validate_recipes(core,packages)
    need(all(p.recipe['core_contract']==core.recipe['core_contract'] for p in packages),'模块与公共核心版本不匹配')
    bankdata={name:_check_payload_ref(core,row) for name,row in bankmap.items()}
    for name,base in list(bankdata.items()):
        if name=='Asphalt9.idb':
            additions=[row for p in packages for row in p.recipe.get('idb_rows',[])]
            bankdata[name]=compose_idb(base,additions);continue
        contributions=[]
        base_groups={g['uid']:g for g in parse_bank(base)[1]}
        for p in sorted(packages,key=lambda x:x.id):
            rows=[]
            for r in p.recipe.get('records',[]):
                if r['bank']==name:rows.append({'uid':r['uid'],'type':r['type'],'body':_check_payload_ref(p,r),'source_ordinal':r['source_ordinal']})
            groups=[]
            for g in p.recipe.get('groups',[]):
                if g['bank']==name:
                    previous=base_groups.get(g['uid'],{'list0':[],'list1':[]})
                    need(g['base_lists']=={k:previous[k] for k in ('list0','list1')},'模块所需基础分组不匹配：'+g['uid'])
                    groups.append({'uid':g['uid'],'list0':g['add0'],'list1':g['add1'],'source_ordinal':int(g['uid'],16)})
            contributions.append({'records':rows,'groups':groups})
        bankdata[name]=compose_bank(base,contributions)
    ids={p.id for p in packages};active=sorted(c for p in packages for c in GROUPS[p.id])
    public={name:_check_payload_ref(core,ref) for name,ref in core.recipe['server_inputs'].items()}
    result=compose_result(public,active,runtime_source=RUNTIME_SOURCE)
    need(set(result['relative_files'])==SERVER_OUTPUT,'服务端输出越过公共白名单')
    filter_ref=core.recipe['stock_filter'];garage_ref=core.recipe['garage_bank']
    selected=[]
    for group,name in [('a9.fastest-car','hidden1003'),('a9.cn-four-cars','cn'),('a9.alu-two-cars','alu')]:
        if group in ids:selected.append(name)
    filter_data,proof=compose_filter(_check_payload_ref(core,filter_ref),bankdata['CarDef.gdb'],_check_payload_ref(core,garage_ref),selected,expected_stock_filter_sha256=filter_ref['sha256'])
    return {'core':core,'bankmap':bankmap,'banks':bankdata,'server':result,'filter_bytes':filter_data,'filter_proof':proof,'active_cids':active}

def collect_updates(packages,data):
    core=data['core'];updates={m:[] for m in MOUNTS}
    for name,raw in data['banks'].items():updates['main'].append((_entry(data['bankmap'][name]['entry']),raw))
    updates['main'].append((_entry(core.recipe['stock_filter']['entry']),data['filter_bytes']))
    updates['main'].append((_entry(core.recipe['business_entry']),data['server']['main_business_bytes']))
    # GARAGE and the UI banks are shared layout/registration data. DLL mask
    # determines whether the career/nitro subsystem is mounted at runtime.
    for row in core.recipe.get('shared_main_banks',[]):updates['main'].append((_entry(row['entry']),_check_payload_ref(core,row)))
    for p in sorted(packages,key=lambda x:x.id):
        for row in p.recipe.get('resources',[]):updates[row['mount']].append((_entry(row['entry']),_check_payload_ref(p,row)))
    return updates

def stage_combination(manager,plan,stage,state,progress):
    packages=plan['packages'];progress('合成所选模块的记录、车型列表和服务端登记')
    data=compose_data(packages);core=data['core'];updates=collect_updates(packages,data);packproof=[]
    for mount in MOUNTS:
        progress('重建并校验 '+mount+'.pack')
        packproof.append(compose_pack(manager.base_path(mount+'.pack',state),safe_path(stage,mount+'.pack'),mount,core.recipe['remove_paths'].get(mount,[]),updates[mount],progress))
    meta=plan['official_meta'];gin_spec=core.recipe['gin']
    if meta['gin_upgrade']:
        progress('升级公共图纸／界面底座（仅一次）')
        values=[(_entry(r['entry']),_check_payload_ref(core,r)) for r in gin_spec['updates']]
        packproof.append(compose_pack(manager.base_path('gin.pack',state),safe_path(stage,'gin.pack'),'gin',[],values,progress))
        gin_sha=sha_file(safe_path(stage,'gin.pack'))
        need(gin_sha==gin_spec['target_sha256'],'公共GIN升级整包摘要不符，停止安装')
    else:
        source=manager.base_path('gin.pack',state);need(sha_file(source)==gin_spec['target_sha256'],'GIN基础在合成阶段变化');gin_sha=gin_spec['target_sha256']
    for name,raw in data['server']['relative_files'].items():
        path=safe_path(stage,name);path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(raw)
    variant=core.recipe['loader_variants'][str(meta['loader_mask'])];template=_check_payload_ref(core,variant)
    dll,loaderproof=repin_loader(template,NATIVE_TEMPLATES[meta['loader_mask']],mask=meta['loader_mask'],main_sha256=sha_file(safe_path(stage,'main.pack')),gin_sha256=gin_sha)
    with safe_path(stage,'dinput8.dll').open('xb') as stream:stream.write(dll)
    state['module_profile']={'baseline':meta['baseline'],'active_cids':meta['active_cids'],'loader_mask':meta['loader_mask'],'gin_upgraded':meta['gin_upgrade']}
    plan['composition_proof']={'pack_checks':packproof,'loader':loaderproof,'filter':data['filter_proof'],'active_cids':data['active_cids'],'business_main_and_server_sha256':data['server']['main_business_sha256'],'personal_save_files_opened':False}
