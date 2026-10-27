"""Build a reviewable public checkout and two verified portable archives.

Run after building/testing the EXE. No game installation is opened or changed.
All inputs/outputs are explicit; repeated publication never overwrites a ZIP.
"""
from pathlib import Path
import argparse,importlib.metadata,json,shutil,sys,zipfile
from engine import Package,atomic_json,sha_file,digest,need
from network207 import validate_catalog

SOURCE=Path(__file__).resolve().parent
RUNTIME_FILES=('app.py','engine.py','resources.py','demo.py','baseline_profiles.py',
 'selftest.py','check_ui_workflow.py','composition.py','filter207.py','group_packages.py',
 'idb207.py','loader207.py','native_aliases207.py','network207.py','official207.py',
 'server207.py','trusted207.py','vendor-provenance.json','package_release207.py')
VENDOR=('c9_packaged_resource_index.py','c9_port_pack_writer_124.py','c9_classic32_directory_136.py')

def load(path):return json.loads(Path(path).read_bytes())

def licenses():
    result={'Python.txt':Path(sys.base_prefix)/'LICENSE.txt'}
    for distribution,name,filename in [('pyinstaller','PyInstaller.txt','COPYING.txt'),('Pillow','Pillow.txt','LICENSE')]:
        d=importlib.metadata.distribution(distribution)
        matches=[d.locate_file(f) for f in d.files if str(f).endswith('/licenses/'+filename)]
        need(len(matches)==1,'Missing license: '+distribution);result[name]=Path(matches[0])
    for part in ('tcl8.6','tk8.6'):
        path=Path(sys.base_prefix)/'tcl'/part/'license.terms'
        if path.is_file():result[part+'.txt']=path
        else:
            # Some official Python Windows installs carry the complete Tcl/Tk
            # notices in LICENSE.txt instead of shipping tcl8.6/license.terms.
            need('Scriptics Corporation' in result['Python.txt'].read_text(encoding='utf-8'),'Missing Tcl/Tk notice')
    need(all(p.is_file() for p in result.values()),'Missing runtime license')
    return result

def archive(target,files,scratch):
    need(not target.exists(),'Refuse to overwrite published archive: '+target.name)
    manifest={'schema':'A9MOD_MANAGER_RELEASE_SHA256_V1','files':[{'path':n,'bytes':p.stat().st_size,'sha256':sha_file(p)} for n,p in sorted(files.items())]}
    atomic_json(scratch,manifest);allfiles={**files,'SHA256SUMS.json':scratch}
    with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,path in sorted(allfiles.items()):
            need(not any(part in {'ManagerData','__pycache__','.a9mod-manager','.git'} for part in Path(name).parts),'Unsafe archive path')
            z.write(path,'A9-Mod-Manager/'+name,compress_type=zipfile.ZIP_STORED if name.endswith('.zip') else zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(target) as z:
        need(z.testzip() is None,'Archive CRC failed')
        need(set(z.namelist())=={'A9-Mod-Manager/'+n for n in allfiles},'Archive member list differs')
        for row in manifest['files']:
            data=z.read('A9-Mod-Manager/'+row['path'])
            need(len(data)==row['bytes'] and digest(data)==row['sha256'],'Archive content differs')
    return {'file':target.name,'bytes':target.stat().st_size,'sha256':sha_file(target)}

def build(work,modules,repository,tag):
    work=Path(work).resolve();modules=Path(modules).resolve()
    release=work/'release';public=work/'public-repository';kit=work/'portable-files'
    need(not release.exists() or not list(release.iterdir()),'Release assets already exist; choose a new work area')
    need(not (public/'.git').exists(),'Public checkout already initialized; refuse to change it')
    license_files=licenses()
    exe=work/'standalone/A9ModManager.exe';need(exe.is_file(),'Build EXE first')
    checks={}
    for name in ('final-source-tests.json','standalone-tests.json','final-ui-workflow.json','actual-module-matrix.json','physical-all-four-check.json','r200-gin-upgrade-physical-check.json','standalone-ui.json'):
        value=load(work/name)
        need(value.get('passed',value.get('window_created',False)),'Validation did not pass: '+name)
        checks[name]={'sha256':sha_file(work/name),'passed':True}
        for key in ('tests','skipped','visible_module_rows','core_hidden'):
            if key in value:checks[name][key]=value[key]
    need(load(work/'standalone-ui.json')['visible_module_rows']==4,'Expected four visible modules')
    need(load(work/'standalone-ui.json')['core_hidden'],'Core should be automatic')
    for path in (release,public,kit):path.mkdir(parents=True,exist_ok=True)
    local=load(modules/'catalog.json');rows=[];zipfiles={}
    for row in local['modules']:
        path=modules/row['path'];need(path.stat().st_size==row['bytes'] and sha_file(path)==row['sha256'],'Module archive differs')
        p=Package(path);need(p.id==row['id'] and p.manifest_hash==row['manifest_sha256'],'Module identity differs')
        rows.append({key:row[key] for key in ('id','title','version','bytes','sha256','manifest_sha256')})
        rows[-1].update(description=p.description,requires=p.requires,vehicle_ids=p.summary['vehicle_ids'],url=f'https://github.com/{repository}/releases/download/{tag}/{path.name}')
        zipfiles[row['path']]=path
    remote={'schema':'A9MOD_REMOTE_CATALOG_V2','channel':'public_alpha','release':tag,'runtime_accepted':False,'modules':rows}
    validate_catalog(remote);atomic_json(public/'catalog/index.json',remote)
    for name in ('README.md','FORMAT.md','release_notes.md'):
        shutil.copy2(SOURCE/name,public/name);shutil.copy2(SOURCE/name,kit/name)
    for name in ('Verify-Files.ps1','00-Check-Files.cmd','01-Open-Demo.cmd'):
        shutil.copy2(SOURCE/name,kit/name)
    for name in RUNTIME_FILES:
        out=public/'source'/name;out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(SOURCE/name,out)
    for name in VENDOR:
        out=public/'source/vendor'/name;out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(SOURCE/'vendor'/name,out)
    for name,path in license_files.items():
        for folder in (public,kit):
            out=folder/'licenses'/name;out.parent.mkdir(exist_ok=True);shutil.copy2(path,out)
    (public/'.gitignore').write_text('__pycache__/\n*.pyc\nManagerData/\n.a9mod-manager/\n*.pack\n*.zip\n*.exe\n*.dll\nbuild/\ndist/\n',encoding='utf-8')
    (public/'source/requirements-build.txt').write_text('PyInstaller==6.22.3\nPillow>=11\n',encoding='utf-8')
    validation={'schema':'A9MOD_MANAGER_PUBLIC_ALPHA_VALIDATION_V1','release':tag,'EXE_sha256':sha_file(exe),
        'checks':checks,'source_SHA256':{n:sha_file(SOURCE/n) for n in RUNTIME_FILES},
        'real_game_modified':False,'personal_data_read':False,'runtime_accepted':False,
        'supported_adopted_baselines':['r200','r203','r206'],'module_bytes':sum(r['bytes'] for r in rows),
        'limits':['Static and isolated tests do not replace manual game acceptance.','Only known integrated baselines accepted.','Hashes check integrity; publisher signatures are not implemented.']}
    atomic_json(public/'validation.json',validation);atomic_json(kit/'validation.json',validation)
    basefiles={str(p.relative_to(kit)).replace('\\','/'):p for p in kit.rglob('*') if p.is_file()}
    basefiles['A9ModManager.exe']=exe
    online=archive(release/'A9-Mod-Manager-0.2.0-alpha.1.zip',basefiles,work/'online-SHA256SUMS.json')
    offline_catalog={**local,'channel':'public_alpha_offline','online_published':True}
    atomic_json(work/'offline-catalog.json',offline_catalog)
    offline=archive(release/'A9-Mod-Manager-0.2.0-alpha.1-Offline.zip',{**basefiles,**zipfiles,'catalog.json':work/'offline-catalog.json'},work/'offline-SHA256SUMS.json')
    assets=[online,offline]+[{'file':p.name,'bytes':p.stat().st_size,'sha256':sha_file(p)} for p in zipfiles.values()]
    checksum=''.join(r['sha256']+'  '+r['file']+'\n' for r in assets)
    (release/'SHA256SUMS.txt').write_text(checksum,encoding='ascii')
    shutil.copy2(public/'validation.json',release/'validation.json')
    atomic_json(work/'publication-files-check.json',{'passed':True,'repository':repository,'release':tag,'assets':assets,'public_code_files':len(list(public.rglob('*'))),'game_or_personal_files_in_git':False})
    print(json.dumps({'passed':True,'repository_checkout':str(public),'release':str(release),'assets':assets},ensure_ascii=False))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--modules',type=Path,required=True)
    p.add_argument('--repository',default='REALXD233/a9-offline-mods');p.add_argument('--tag',default='v0.2.0-alpha.1');a=p.parse_args()
    build(a.work,a.modules,a.repository,a.tag)
