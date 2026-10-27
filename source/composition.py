"""Pure canonical-bank and native-pack composition for declared module data.

No game mutation. A package cannot provide executable callbacks. Public bank
bodies stay opaque, including duplicate stock typed identities and their order.
"""
from dataclasses import replace
from pathlib import Path
import copy,hashlib,struct,zipfile,zlib
from resources import Pack
from c9_packaged_resource_index import DEFAULT_MANIFEST_KEY,ManifestEntry,parse_manifest,decrypt_stream
from c9_port_pack_writer_124 import encode_entry,encrypt_stream,manifest_line,without_zip64_extra
from c9_classic32_directory_136 import validate_classic32_pack
from native_aliases207 import verify_native_aliases

def need(value,message):
    if not value:raise ValueError(message)
def sha(b):return hashlib.sha256(b).hexdigest()

def parse_bank(data):
    need(32<=len(data)<=64*1024*1024,'银行长度异常')
    header,start,end=struct.unpack_from('<QQQ',data);need(start==24 and start<=end<len(data),'银行头布局异常');at=end
    def take(fmt):
        nonlocal at
        n=struct.calcsize(fmt);need(at+n<=len(data),'银行索引截断');v=struct.unpack_from(fmt,data,at);at+=n;return v
    def count():
        n,=take('<I');need(n<=100000,'银行计数超限');return n
    groups=[]
    for _ in range(count()):
        uid,=take('<Q');lists=[[f'{take("<Q")[0]:016x}' for _ in range(count())] for _ in range(2)]
        groups.append({'uid':f'{uid:016x}','list0':lists[0],'list1':lists[1]})
    rows=[]
    for ordinal in range(count()):
        uid,offset,size,kind=take('<QQQQ');need(24<=offset<=end and size<=end-offset,'银行body越界')
        rows.append({'uid':f'{uid:016x}','type':f'{kind:016x}','body':data[offset:offset+size],'ordinal':ordinal})
    need(at==len(data),'银行索引尾部未知');need(len({g['uid'] for g in groups})==len(groups),'银行分组重复')
    return header,groups,rows

def write_bank(header,groups,rows):
    out=bytearray(struct.pack('<QQQ',header,24,0));indexed=[]
    for r in rows:
        raw=r['body'];need(isinstance(raw,bytes) and raw,'空或非二进制银行记录')
        indexed.append((int(r['uid'],16),len(out),len(raw),int(r['type'],16)));out.extend(raw)
    struct.pack_into('<Q',out,16,len(out));out.extend(struct.pack('<I',len(groups)))
    for g in groups:
        out.extend(struct.pack('<Q',int(g['uid'],16)))
        for k in ('list0','list1'):
            keys=g[k];need(len(keys)==len(set(keys)),'银行分组成员重复')
            out.extend(struct.pack('<I',len(keys)));out.extend(b''.join(struct.pack('<Q',int(x,16)) for x in keys))
    out.extend(struct.pack('<I',len(indexed)))
    for row in indexed:out.extend(struct.pack('<QQQQ',*row))
    output=bytes(out);h,gs,rs=parse_bank(output)
    need(h==header and gs==groups,'银行分组往返不同')
    need([(r['uid'],r['type'],r['body']) for r in rs]==[(r['uid'],r['type'],r['body']) for r in rows],'银行记录往返不同')
    return output

def compose_bank(base,contributions,reference_groups=None):
    """Append owned records and union group membership against one core base.

    contributions: records[{uid,type,body,source_ordinal}],
    groups[{uid,list0,list1,source_ordinal}]. Reference group lists carry the
    certified source order; installation order never determines the result.
    """
    header,groups,rows=parse_bank(base);stock_count=len(rows);added={};extra_groups={};groupmap={g['uid']:copy.deepcopy(g) for g in groups}
    for c in contributions:
        for row in c.get('records',[]):
            key=(row['uid'],row['type']);body=row['body'];old=[r for r in rows if (r['uid'],r['type'])==key]
            if old:
                need(all(r['body']==body for r in old),'模块不能覆盖核心既有记录：'+row['uid']);continue
            if key in added:need(added[key]['body']==body,'模块记录冲突：'+row['uid'])
            else:added[key]=dict(row)
        for g in c.get('groups',[]):
            if g['uid'] not in groupmap:
                groupmap[g['uid']]={'uid':g['uid'],'list0':[],'list1':[]};extra_groups[g['uid']]=g.get('source_ordinal',2**63)
            dest=groupmap[g['uid']]
            for k in ('list0','list1'):
                for uid in g.get(k,[]):
                    if uid not in dest[k]:dest[k].append(uid)
    rows.extend(sorted(added.values(),key=lambda r:(r.get('source_ordinal',2**63),r['uid'],r['type'])))
    group_order=[g['uid'] for g in groups]+sorted(extra_groups,key=lambda k:(extra_groups[k],k))
    final=[]
    for uid in group_order:
        g=groupmap[uid]
        for k in ('list0','list1'):
            if reference_groups and uid in reference_groups:
                reference=reference_groups[uid][k];members=set(g[k]);need(members<=set(reference),'分组有不在认证来源中的成员：'+uid)
                g[k]=[x for x in reference if x in members]
            elif uid in extra_groups:g[k]=sorted(g[k],key=lambda x:int(x,16))
            else:
                old=next(x for x in groups if x['uid']==uid)[k]
                if set(g[k])!=set(old):
                    need(old==sorted(old,key=lambda x:int(x,16)),'未认证的非排序核心分组需要显式顺序')
                    g[k]=sorted(set(g[k]),key=lambda x:int(x,16))
                else:g[k]=old
        final.append(g)
    output=write_bank(header,final,rows);_,_,after=parse_bank(output)
    need([(r['uid'],r['type'],r['body']) for r in after[:stock_count]]==[(r['uid'],r['type'],r['body']) for r in parse_bank(base)[2]],'核心原有记录顺序或内容变化')
    return output

def read_entry(pack,entry):
    """Allow 64MiB only for the authenticated GIN bank's documented layout."""
    if pack.mount!='gin' or entry.logical_path!='/gin/Asphalt9.ginproject/|/Asphalt9.gdb':return pack.read(entry.logical_path)
    info=pack.z.getinfo(entry.storage_name);need(info.file_size<=64*1024*1024+12,'GIN成员过大')
    raw=pack.z.read(info);data=decrypt_stream(raw,entry.stream_password.encode('ascii')) if entry.encryption_flags=='X' else raw
    if entry.compression_flags=='C':
        expected=entry.size_value;need(type(expected) is int and 0<expected<=64*1024*1024,'GIN声明长度异常')
        d=zlib.decompressobj(-15);data=d.decompress(data,expected+1);need(len(data)==expected and d.eof and not d.unused_data and not d.unconsumed_tail,'GIN压缩边界异常')
    return data

def compose_pack(source,dest,mount,remove_paths,updates,progress=lambda s:None):
    """Build one ZIP32 pack, pruning only declared owned paths.

    updates: list[(ManifestEntry, decoded bytes)]. Source ZIP_STORED payloads
    are copied byte for byte. No manifest/resource names are guessed.
    """
    source=Path(source);dest=Path(dest);need(not dest.exists(),'目标资源包已存在');pack=Pack(source,mount)
    try:
        need(source.stat().st_size<0xffffffff,'输入资源包超过ZIP32上限')
        need(all((i.compress_type==zipfile.ZIP_STORED or i.filename==pack.manifest_name and i.compress_type==zipfile.ZIP_DEFLATED) and not i.flag_bits&8 for i in pack.z.infolist()),'源ZIP成员布局不在验证范围')
        remove=set(remove_paths);entries=[e for e in pack.entries if e.logical_path not in remove]
        positions={e.logical_path:i for i,e in enumerate(entries)};encoded={};decoded={}
        for entry,plain in updates:
            need(isinstance(entry,ManifestEntry) and isinstance(plain,bytes),'更新不是已校验资源数据')
            if entry.logical_path in decoded:need(decoded[entry.logical_path]==plain,'多个模块覆盖同一资源：'+entry.logical_path);continue
            old=pack.z.read(entry.storage_name) if entry.storage_name in pack.names else None
            updated,data=encode_entry(entry,plain,old);encoded[entry.storage_name]=data;decoded[entry.logical_path]=plain
            if entry.logical_path in positions:entries[positions[entry.logical_path]]=updated
            else:positions[entry.logical_path]=len(entries);entries.append(updated)
        need(len({e.storage_name for e in entries})==len(entries),'输出资源成员名称冲突')
        verify_native_aliases(entries)
        newline='\r\n' if b'\r\n' in pack.manifest else '\n'
        text=newline.join(manifest_line(e) for e in entries).encode('utf-8')
        if pack.manifest.endswith((b'\r',b'\n')):text+=newline.encode('ascii')
        need(parse_manifest(text)==entries,'输出清单往返校验失败')
        iv=struct.unpack_from('<I',pack.z.read(pack.manifest_name))[0];encoded[pack.manifest_name]=encrypt_stream(text,DEFAULT_MANIFEST_KEY,iv)
        retained={e.storage_name for e in entries}|{pack.manifest_name};old_names=set(pack.z.namelist())
        limit=zipfile.ZIP64_LIMIT
        try:
            zipfile.ZIP64_LIMIT=0xffffffff
            with dest.open('xb') as target:
                target.write(b'\0\0')
                with zipfile.ZipFile(target,'w',allowZip64=True) as out:
                    out.comment=pack.z.comment
                    for info in pack.z.infolist():
                        if info.filename not in retained:continue
                        metadata=copy.copy(info);metadata.extra=without_zip64_extra(info.extra)
                        out.writestr(metadata,encoded.get(info.filename,pack.z.read(info)))
                    for entry in sorted(entries,key=lambda e:e.storage_name):
                        if entry.storage_name not in old_names:
                            info=zipfile.ZipInfo(entry.storage_name,(2026,10,22,0,0,0));info.compress_type=zipfile.ZIP_STORED
                            out.writestr(info,encoded[entry.storage_name])
        finally:zipfile.ZIP64_LIMIT=limit
        need(dest.stat().st_size<0xffffffff,'生成资源包超过ZIP32上限')
        validate_classic32_pack(dest);check=Pack(dest,mount)
        try:
            need(check.entries==entries and check.z.testzip() is None,'输出资源包CRC或索引不符')
            verify_native_aliases(check.entries)
            for logical,plain in decoded.items():need(read_entry(check,check.by_path[logical])==plain,'输出资源解码不符：'+logical)
            untouched=[i for i in pack.z.infolist() if i.filename in retained and i.filename not in encoded]
            for info in untouched:need(pack.z.read(info)==check.z.read(info.filename),'未修改资源变化')
            return {'mount':mount,'entries':len(entries),'removed_paths_present':sum(e.logical_path in remove for e in pack.entries),'decoded_updates':len(decoded),'unmodified_payloads_verified':len(untouched),'CRC':True,'classic32':True}
        finally:check.close()
    finally:pack.close()
