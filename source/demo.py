"""Synthetic native-format pack: never includes game assets or a working EXE."""
from pathlib import Path
import json,struct,zipfile
from engine import DEMO_EXE,DEMO_SHA,digest,Package
from resources import resource_name,DEFAULT_MANIFEST_KEY
from c9_packaged_resource_index import ManifestEntry
from c9_port_pack_writer_124 import encrypt_stream,manifest_line,encode_entry

LOGICAL='/manager-demo/|/Example.gdb'
UID_A='0000000000000011';UID_B='0000000000000022';KIND='0000000080cb4747'
def bank():
    a=b'original-A';b=b'original-B';end=24+len(a)+len(b)
    return struct.pack('<QQQ',123,24,end)+a+b+struct.pack('<II',0,2)+struct.pack('<QQQQ',int(UID_A,16),24,len(a),int(KIND,16))+struct.pack('<QQQQ',int(UID_B,16),24+len(a),len(b),int(KIND,16))
def write_package(path,ident,title,ops,payloads,requires=()):
    m={'schema':'A9MOD_PACKAGE_V1','id':ident,'version':'1.0.0','title':title,'description':'仅用于隔离演示，不含游戏素材，不能安装到真实游戏。','host_sha256':DEMO_SHA,'requires':list(requires),'conflicts':[],'operations':ops}
    with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest.json',json.dumps(m,ensure_ascii=False,indent=2).encode('utf-8'))
        for name,data in payloads.items(): z.writestr(name,data)
    return Package(path)
def create(root):
    root=Path(root);root.mkdir(exist_ok=False);game=root/'DemoGame';mods=root/'Mods';game.mkdir();mods.mkdir();(game/'Asphalt9_emu.exe').write_bytes(DEMO_EXE)
    (game/'demo').mkdir();(game/'demo/a.txt').write_bytes(b'base-a');(game/'demo/b.txt').write_bytes(b'base-b')
    e=ManifestEntry(1,0,LOGICAL,'C',len(bank()),'X','123456','1111111111111111');e,payload=encode_entry(e,bank())
    manifest=(manifest_line(e)+'\n').encode()
    with (game/'main.pack').open('xb') as f:
        f.write(b'\0\0')
        with zipfile.ZipFile(f,'w') as z:
            z.writestr(resource_name('main','__manifest_X_100__'),encrypt_stream(manifest,DEFAULT_MANIFEST_KEY));z.writestr(e.storage_name,payload)
    packages=[]
    for uid,orig,new,ident,title in ((UID_A,b'original-A',b'MOD-A-ENABLED','demo.module-a','演示模块 A：修改记录 A'),(UID_B,b'original-B',b'MOD-B-ENABLED','demo.module-b','演示模块 B：修改记录 B')):
        op={'kind':'record','target':'main.pack','logical_path':LOGICAL,'uid':uid,'record_type':KIND,'source':'payload/record.bin','sha256':digest(new),'bytes':len(new),'base_sha256':digest(orig)}
        packages.append(write_package(mods/(ident+'.a9mod.zip'),ident,title,[op],{'payload/record.bin':new}))
    return game,packages
