"""Public HTTPS catalog and verified, resumable module downloads.

No credentials, package scripts, or game files are used. A custom transport is
accepted only as a Python test seam; the GUI always uses the HTTPS transport.
"""
from pathlib import Path
import hashlib,json,os,re,shutil,urllib.request
from engine import need,HEX,Package,safe_path,sha_file
from group_packages import GROUPS

DEFAULT_CATALOG='https://raw.githubusercontent.com/REALXD233/a9-offline-mods/main/catalog/index.json'

def https_url(value):
    from urllib.parse import urlsplit
    need(isinstance(value,str) and 0<len(value)<=4096 and not any(ord(c)<32 for c in value),'下载地址无效')
    p=urlsplit(value);need(p.scheme=='https' and p.hostname and p.username is None and p.password is None,'只允许无内嵌凭据的HTTPS下载地址')
    return value

class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        https_url(newurl);return super().redirect_request(req,fp,code,msg,headers,newurl)

def transport(request):return urllib.request.build_opener(Redirect()).open(request,timeout=30)

def validate_catalog(catalog):
    need(isinstance(catalog,dict) and catalog.get('schema')=='A9MOD_REMOTE_CATALOG_V2','在线目录格式不受支持')
    rows=catalog.get('modules');need(isinstance(rows,list) and len(rows)==5,'在线目录必须包含四组和公共核心')
    ids=set()
    for r in rows:
        need(isinstance(r,dict) and r.get('id') in GROUPS and r['id'] not in ids,'在线目录模块重复或未知');ids.add(r['id'])
        need(isinstance(r.get('version'),str) and 0<len(r['version'])<=80 and isinstance(r.get('title'),str) and 0<len(r['title'])<=160,'在线目录模块标题或版本无效')
        need(type(r.get('bytes')) is int and 0<r['bytes']<2*1024**3,'下载文件大小不受支持')
        for k in ('sha256','manifest_sha256'):need(isinstance(r.get(k),str) and HEX.fullmatch(r[k]),'下载完整性信息缺失')
        https_url(r.get('url'))
        need(r.get('requires')==([] if r['id']=='a9.core' else ['a9.core']),'在线依赖信息无效')
        need(tuple(r.get('vehicle_ids',[]))==GROUPS[r['id']],'在线车型编号与分组不同')
        need(isinstance(r.get('description',''),str) and len(r.get('description',''))<=16000,'在线模块说明过长')
    return catalog

def fetch_catalog(url=DEFAULT_CATALOG,*,open_request=transport):
    request=urllib.request.Request(https_url(url),headers={'User-Agent':'A9ModManager/0.2.0','Accept':'application/json'})
    with open_request(request) as response:
        data=response.read(1024*1024+1);need(len(data)<=1024*1024,'在线目录超过1MiB')
    return validate_catalog(json.loads(data.decode('utf-8-sig')))

def cache_path(folder,row):
    need(isinstance(row.get('sha256'),str) and HEX.fullmatch(row['sha256']),'缓存摘要无效')
    return safe_path(folder,row['sha256']+'.a9mod.zip')

def verify_download(path,row):
    need(path.is_file() and path.stat().st_size==row['bytes'] and sha_file(path)==row['sha256'],'下载内容SHA256或大小不符')
    p=Package(path);need(p.official and p.id==row['id'] and p.version==row['version'] and p.manifest_hash==row['manifest_sha256'],'下载包与在线目录身份不同')
    return p

def download(row,folder,progress=lambda s:None,*,open_request=transport):
    need(type(row.get('bytes')) is int and 0<row['bytes']<2*1024**3,'下载大小无效');https_url(row.get('url'))
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True);dest=cache_path(folder,row)
    if dest.exists() and dest.stat().st_size==row['bytes'] and sha_file(dest)==row['sha256']:return verify_download(dest,row)
    partial=safe_path(folder,row['sha256']+'.partial');offset=partial.stat().st_size if partial.is_file() else 0
    if offset>=row['bytes']:offset=0
    need(shutil.disk_usage(folder).free>=row['bytes']-offset+16*1024*1024,'下载缓存所在磁盘空间不足')
    headers={'User-Agent':'A9ModManager/0.2.0','Accept':'application/octet-stream'}
    if offset:headers['Range']='bytes=%d-'%offset
    request=urllib.request.Request(row['url'],headers=headers)
    with open_request(request) as response:
        status=getattr(response,'status',None) or response.getcode()
        if status==206:
            match=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',response.headers.get('Content-Range',''))
            need(match and int(match[1])==offset and int(match[2])==row['bytes']-1 and int(match[3])==row['bytes'],'续传区间与模块大小不符')
        else:need(status==200,'服务器返回非下载状态');offset=0
        expected=row['bytes']-offset;length=response.headers.get('Content-Length')
        if length is not None:need(length.isdecimal() and int(length)==expected,'下载响应长度不符')
        count=offset;next_notice=count
        with partial.open('ab' if offset else 'wb') as out:
            while True:
                b=response.read(min(1024*1024,row['bytes']-count+1))
                if not b:break
                count+=len(b);need(count<=row['bytes'],'下载返回数据超出模块大小');out.write(b)
                if count>=next_notice:progress('下载 '+row['title']+'：%.1f / %.1f MiB'%(count/1024**2,row['bytes']/1024**2));next_notice=count+4*1024*1024
            out.flush();os.fsync(out.fileno())
    need(count==row['bytes'],'下载中断，已保留续传数据')
    try:verify_download(partial,row)
    except Exception:
        # A complete but incorrect partial must not cause an endless 416 resume.
        with partial.open('wb'):pass
        raise
    os.replace(partial,dest);progress('已核对下载：'+row['title']);return verify_download(dest,row)
