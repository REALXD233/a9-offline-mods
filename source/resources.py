"""Bounded resource composition, using the previously verified local codecs."""
from pathlib import Path
import hashlib, struct, sys, zipfile
sys.path.insert(0, str(Path(__file__).resolve().parent/'vendor'))
from c9_packaged_resource_index import DEFAULT_MANIFEST_KEY, decrypt_stream, parse_manifest, resource_name, decode_resource
from c9_port_pack_writer_124 import prepare_members
from c9_classic32_directory_136 import write_classic32_pack, validate_classic32_pack

def digest(b): return hashlib.sha256(b).hexdigest()

class Pack:
    def __init__(self, path, mount):
        self.path=Path(path); self.mount=mount; self.z=zipfile.ZipFile(path)
        try:
            with self.path.open('rb') as stream:
                if stream.read(6)!=b'\0\0PK\x03\x04': raise ValueError('资源包头不受支持')
            self.manifest_name=resource_name(mount,'__manifest_X_100__')
            self.manifest=decrypt_stream(self.z.read(self.manifest_name),DEFAULT_MANIFEST_KEY)
            self.entries=parse_manifest(self.manifest); self.names=set(self.z.namelist())
            self.by_path={e.logical_path:e for e in self.entries}
            if len(self.names)!=len(self.z.namelist()) or len(self.by_path)!=len(self.entries): raise ValueError('资源包存在重复条目')
            if any(e.storage_name not in self.names for e in self.entries): raise ValueError('资源清单指向缺失文件')
        except BaseException:
            self.z.close(); raise
    def read(self,path): return decode_resource(self,self.by_path[path],self.mount)[0]
    def getinfo(self,name): return self.z.getinfo(name.rsplit('/',1)[-1])
    def open(self,name): return self.z.open(name if isinstance(name,zipfile.ZipInfo) else name.rsplit('/',1)[-1])
    def close(self): self.z.close()

def records(data):
    if len(data)<32: raise ValueError('GDB过短')
    head,start,end=struct.unpack_from('<QQQ',data)
    if start!=24 or not start<=end<len(data): raise ValueError('GDB头不匹配')
    at=end
    def take(fmt):
        nonlocal at
        size=struct.calcsize(fmt)
        if at+size>len(data): raise ValueError('GDB索引截断')
        result=struct.unpack_from(fmt,data,at);at+=size;return result
    def count():
        n,=take('<I')
        if n>100000: raise ValueError('GDB计数超限')
        return n
    for _ in range(count()):
        take('<Q')
        for _ in range(2):
            for _ in range(count()): take('<Q')
    rows=[]
    for _ in range(count()):
        pos=at;key,offset,size,kind=take('<QQQQ')
        if offset<24 or offset+size>end: raise ValueError('GDB记录越界')
        rows.append((f'{key:016x}',f'{kind:016x}',offset,size,pos))
    if at!=len(data): raise ValueError('GDB索引尾部未知')
    return end,rows

def record_read(data,uid,kind):
    _,rows=records(data);matches=[r for r in rows if r[:2]==(uid,kind)]
    if len(matches)!=1: raise ValueError('GDB记录缺失或重复：'+uid)
    r=matches[0];return data[r[2]:r[2]+r[3]]

def patch_records(data,changes):
    end,rows=records(data);body=bytearray(data[:end]);tail=bytearray(data[end:]);seen=set()
    for uid,kind,off,size,pos in rows:
        if (uid,kind) in changes:
            if (uid,kind) in seen: raise ValueError('重复的GDB身份')
            seen.add((uid,kind));payload=changes[(uid,kind)]
            struct.pack_into('<QQ',tail,pos-end+8,len(body),len(payload));body.extend(payload)
    if seen!=set(changes): raise ValueError('不能在此格式中新增未知GDB记录')
    struct.pack_into('<Q',body,16,len(body));out=bytes(body+tail)
    for uid,kind,off,size,_ in rows:
        if record_read(out,uid,kind)!=changes.get((uid,kind),data[off:off+size]): raise ValueError('GDB保留校验失败')
    return out

def build_pack(base,dest,operations,read_payload):
    # Base snapshots are content-addressed .bin files, so use the declared mount.
    mount=operations[0]['target'].split('.')[0]
    pack=Pack(base,mount)
    try:
        replacements={};grouped={}
        for op in operations: grouped.setdefault(op['logical_path'],[]).append(op)
        for logical,ops in grouped.items():
            original=pack.read(logical)
            if ops[0]['kind']=='resource':
                if len(ops)!=1: raise ValueError('同资源的整项替换冲突')
                replacements[logical]=read_payload(ops[0])
            else:
                replacements[logical]=patch_records(original,{(o['uid'],o['record_type']):read_payload(o) for o in ops})
        modified,entries,_=prepare_members(pack,replacements)
        write_classic32_pack(base,dest,modified)
    finally: pack.close()
    after=Pack(dest,mount)
    try:
        if after.entries!=entries or after.z.testzip() is not None: raise ValueError('新资源包清单或CRC不匹配')
        for logical,data in replacements.items():
            if after.read(logical)!=data: raise ValueError('资源重新解码校验失败')
        validate_classic32_pack(dest)
    finally: after.close()
