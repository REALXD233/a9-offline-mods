"""Data-only official four-group package schema. No package code is imported."""
import hashlib,json,re,zipfile

GROUPS={
 'a9.core':(),
 'a9.career-restart':(),
 'a9.fastest-car':(1003,),
 'a9.cn-four-cars':(5018,5002,5021,5009),
 'a9.alu-two-cars':(294,345),
}

def initialise(package,manifest,archive):
    from engine import need,relative,HOST_SHA,DEMO_SHA,HEX
    m=manifest;p=package
    need(m.get('schema')=='A9MOD_GROUP_PACKAGE_V2','未知的模块协议')
    need(m.get('id') in GROUPS and isinstance(m.get('version'),str) and 0<len(m['version'])<=80,'未知模块或版本')
    need(isinstance(m.get('title'),str) and 0<len(m['title'])<=160,'模块名称无效')
    need(m.get('host_sha256') in (HOST_SHA,DEMO_SHA),'模块主程序指纹不受支持')
    p.id=m['id'];p.version=m['version'];p.title=m['title'];p.description=m.get('description','')
    need(isinstance(p.description,str) and len(p.description)<=16000,'模块说明过长')
    p.host=m['host_sha256'];p.demo=p.host==DEMO_SHA;p.legacy=False;p.official=True
    p.requires=[] if p.id=='a9.core' else ['a9.core'];p.conflicts=[]
    need(m.get('requires',[])==p.requires and tuple(m.get('vehicle_ids',[]))==GROUPS[p.id],'模块依赖或车型集合被改动')
    need(m.get('recipe')=='recipe.json','模块配方位置无效')
    rows=m.get('files');need(isinstance(rows,list) and 1<=len(rows)<=4000,'模块文件清单为空或过大')
    p.inventory={}
    for row in rows:
        need(set(row)=={'path','bytes','sha256'},'模块文件描述字段异常');name=relative(row['path'])
        need(name not in p.inventory and name!='manifest.json','模块素材清单重复')
        need(type(row['bytes']) is int and 0<=row['bytes']<=64*1024*1024,'单项模块素材超过64MiB')
        need(isinstance(row['sha256'],str) and HEX.fullmatch(row['sha256']),'模块素材摘要无效')
        info=archive.getinfo(p.prefix+name);need(not info.is_dir() and info.file_size==row['bytes'],'模块文件缺失或长度不同')
        p.inventory[name]=row
    need('recipe.json' in p.inventory and p.inventory['recipe.json']['bytes']<=4*1024*1024,'缺少有界模块配方')
    raw=archive.read(p.prefix+'recipe.json');need(hashlib.sha256(raw).hexdigest()==p.inventory['recipe.json']['sha256'],'模块配方摘要不同')
    p.recipe=json.loads(raw.decode('utf-8'))
    need(isinstance(p.recipe,dict) and p.recipe.get('schema')=='A9_FOUR_GROUPS_RECIPE_207_V1' and p.recipe.get('id')==p.id,'模块配方身份不符')
    validate_recipe(p)
    p.ops=[];p.payload_bytes=sum(r['bytes'] for r in rows)
    p.summary={'id':p.id,'version':p.version,'title':p.title,'description':p.description,'host_sha256':p.host,'requires':p.requires,'conflicts':[],
        'legacy':False,'official':True,'hidden':p.id=='a9.core','vehicle_ids':list(GROUPS[p.id]),'demo':p.demo,'operations':len(p.recipe.get('records',[]))+len(p.recipe.get('resources',[])),
        'payload_bytes':p.payload_bytes}

def validate_recipe(p):
    from engine import need,HEX
    uid=lambda v:isinstance(v,str) and re.fullmatch('[0-9a-f]{16}',v)
    need(isinstance(p.recipe.get('core_contract'),str) and HEX.fullmatch(p.recipe['core_contract']),'模块核心版本契约缺失')
    def array(name,limit):
        value=p.recipe.get(name,[]);need(isinstance(value,list) and len(value)<=limit,'模块配方字段必须为有界数组：'+name)
        need(all(isinstance(x,dict) for x in value),'模块配方数组成员必须为对象：'+name);return value
    def payload(row):
        need(isinstance(row,dict) and row.get('source') in p.inventory,'模块配方引用不存在的素材')
        r=p.inventory[row['source']];need(row.get('bytes')==r['bytes'] and row.get('sha256')==r['sha256'],'模块配方素材摘要或长度不一致')
    def entry(e):
        fields={'field0','field1','logical_path','compression_flags','size_value','encryption_flags','stream_password','storage_name'}
        need(isinstance(e,dict) and set(e)==fields,'资源条目字段不完整')
        need(all(type(e[k]) is int and 0<=e[k]<2**64 for k in ('field0','field1')),'资源lookup必须为uint64')
        path=e['logical_path'];need(isinstance(path,str) and path.startswith('/') and 1<len(path)<=4096 and not any(c in path for c in '\r\n\0:'),'资源逻辑路径无效')
        need(isinstance(e['storage_name'],str) and re.fullmatch('[0-9A-F]{16}',e['storage_name']),'资源存储名无效')
        need(e['compression_flags'] in ('C','NC') and e['encryption_flags'] in ('X','NX'),'资源编解码标志无效')
        need(e['size_value'] is None or type(e['size_value']) is int and 0<=e['size_value']<2**64,'资源长度字段无效')
        if e['compression_flags']=='C':need(type(e['size_value']) is int and 0<=e['size_value']<=64*1024*1024,'压缩资源展开长度不受支持')
        key=e['stream_password'];need(isinstance(key,str) and (key=='-' or key.isascii() and key.isdecimal() and len(key)<=20 and int(key)<2**64),'资源密码字段无效')
        if e['encryption_flags']=='X':need(key!='-','加密资源缺少密钥字段')
    for row in array('records',4000):
        need(isinstance(row.get('bank'),str) and isinstance(row.get('logical'),str),'记录银行字段缺失')
        need(uid(row.get('uid')) and uid(row.get('type')),'记录UID或类型无效')
        need(type(row.get('source_ordinal')) is int and 0<=row['source_ordinal']<=1000000,'记录来源顺序无效');payload(row)
    for row in array('groups',100):
        need(isinstance(row.get('bank'),str) and uid(row.get('uid')),'分组银行或UID无效')
        for field in ('add0','add1'):
            v=row.get(field);need(isinstance(v,list) and len(v)<=100000 and all(uid(x) for x in v) and len(v)==len(set(v)),'分组成员列表无效')
        base=row.get('base_lists');need(isinstance(base,dict) and set(base)=={'list0','list1'},'分组基础成员描述无效')
        for v in base.values():need(isinstance(v,list) and len(v)<=100000 and all(uid(x) for x in v) and len(v)==len(set(v)),'分组基础列表无效')
    for row in array('idb_rows',100):
        need(set(row)=={'key','names','source_ordinal'} and uid(row['key']),'IDB贡献字段无效')
        need(type(row['source_ordinal']) is int and 0<=row['source_ordinal']<=1000000,'IDB贡献顺序无效')
        need(isinstance(row['names'],list) and len(row['names'])<=1000 and all(isinstance(n,str) and 0<len(n.encode('utf-8'))<4096 and '\0' not in n for n in row['names']),'IDB库名无效')
    for row in array('resources',2000):
        need(row.get('mount') in ('main','mdc','mde','tex'),'模块资源挂载位置无效');entry(row.get('entry'));need(row.get('logical')==row['entry']['logical_path'],'模块资源路径不一致');payload(row)
    if p.id=='a9.core':
        need(p.recipe.get('protocol')=='A9_FOUR_GROUPS_207','公共核心协议错误')
        for row in array('banks',8)+array('shared_main_banks',30):
            payload(row);entry(row.get('entry'));need(row.get('logical')==row['entry']['logical_path'],'核心银行路径不同')
        for name in ('stock_filter','garage_bank'):payload(p.recipe.get(name));entry(p.recipe[name].get('entry'))
        entry(p.recipe.get('business_entry'))
        from server207 import SOURCE_SHA256
        server=p.recipe.get('server_inputs');need(isinstance(server,dict) and set(server)==set(SOURCE_SHA256),'核心服务端输入缺失')
        for row in server.values():payload(row)
        from trusted207 import NATIVE_TEMPLATES
        variants=p.recipe.get('loader_variants');need(isinstance(variants,dict) and set(variants)=={'0','1','2','3'},'缺少四种加载器模板')
        for key,row in variants.items():payload(row);need(row['sha256']==NATIVE_TEMPLATES[int(key)]['sha256'],'加载器模板不是已认证版本')
        gin=p.recipe.get('gin');need(isinstance(gin,dict) and isinstance(gin.get('target_sha256'),str) and HEX.fullmatch(gin['target_sha256']),'GIN核心摘要缺失')
        need(isinstance(gin.get('updates'),list) and len(gin['updates'])<=100,'GIN升级清单无效')
        for row in gin['updates']:payload(row);entry(row.get('entry'))
        removals=p.recipe.get('remove_paths');need(isinstance(removals,dict) and set(removals)=={'main','mdc','mde','tex'},'资源撤回清单挂载无效')
        for values in removals.values():need(isinstance(values,list) and len(values)<=5000 and all(isinstance(x,str) and x.startswith('/') and len(x)<=4096 for x in values),'资源撤回路径清单无效')
        from engine import PUBLIC
        baselines=p.recipe.get('baselines');need(isinstance(baselines,list) and 1<=len(baselines)<=20,'缺少已验证底包清单')
        names=set()
        for b in baselines:
            need(isinstance(b,dict) and isinstance(b.get('name'),str) and b['name'] not in names,'底包名称缺失或重复');names.add(b['name'])
            need(isinstance(b.get('files'),dict) and set(b['files'])==set(PUBLIC[:11]),'底包公共文件集合不符')
            for v in b['files'].values():need(isinstance(v,dict) and set(v)=={'bytes','sha256'} and type(v['bytes']) is int and v['bytes']>0 and isinstance(v['sha256'],str) and HEX.fullmatch(v['sha256']),'底包摘要或大小无效')

def read_data(package,name):
    from engine import need
    need(name in package.inventory,'配方引用未登记的素材：'+str(name));row=package.inventory[name]
    with zipfile.ZipFile(package.path) as z:data=z.read(package.prefix+name)
    need(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'模块素材内容变化：'+name)
    return data

def verify(package):
    from engine import need
    with zipfile.ZipFile(package.path) as z:
        for name,row in package.inventory.items():
            h=hashlib.sha256();size=0
            with z.open(package.prefix+name) as stream:
                for block in iter(lambda:stream.read(4*1024*1024),b''):size+=len(block);h.update(block)
            need(size==row['bytes'] and h.hexdigest()==row['sha256'],'模块素材校验失败：'+name)
