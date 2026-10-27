"""Portable Tk client for the four-group offline mod manager."""
from pathlib import Path
import argparse,json,os,queue,sys,threading,time,traceback
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from engine import Manager,Package,ModError,VERSION,DEMO_SHA,sha_file,atomic_json,public_probe
from group_packages import GROUPS
from network207 import DEFAULT_CATALOG,fetch_catalog,validate_catalog,cache_path,download
import demo

def app_home(): return Path(sys.executable).parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parent
def data_home():
    p=app_home()/'ManagerData'
    try:p.mkdir(exist_ok=True);return p
    except PermissionError:
        p=Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'A9ModManager';p.mkdir(exist_ok=True);return p
def gib(n): return '%.2f GiB'%(n/1024**3)

class App:
    def __init__(self,root,home,initial=None):
        self.root=root;self.home=Path(home);self.home.mkdir(exist_ok=True);self.library_path=self.home/'library.json';self.events=queue.Queue();self.busy=False;self.last_report={};self.rows={};self.desired_groups=None
        self.library=[]
        self.remote_rows={}
        remote_cache=self.home/'online-catalog.json'
        if remote_cache.is_file():
            try:self.remote_rows={r['id']:r for r in validate_catalog(json.loads(remote_cache.read_bytes()))['modules']}
            except Exception:pass
        if self.library_path.exists():
            try:self.library=json.loads(self.library_path.read_text(encoding='utf-8'))
            except Exception: self.library=[]
        if not isinstance(self.library,list): self.library=[]
        self.game=tk.StringVar(value=str(initial or ''));self.status=tk.StringVar(value='选择游戏目录，或点击“隔离演示”体验安装与卸载。')
        root.title('A9 Mod 管理器 · 公开测试版 '+VERSION);root.geometry('1040x760');root.minsize(900,650);root.configure(bg='#f3f5f9')
        style=ttk.Style(root);style.theme_use('clam');style.configure('.',font=('Microsoft YaHei UI',10));style.configure('TFrame',background='#f3f5f9');style.configure('TLabel',background='#f3f5f9');style.configure('Treeview',rowheight=32);style.configure('Header.TLabel',font=('Microsoft YaHei UI',19,'bold'),background='#f3f5f9');style.configure('Hint.TLabel',foreground='#526173',background='#f3f5f9')
        top=ttk.Frame(root,padding=20);top.pack(fill='x')
        ttk.Label(top,text='A9 Mod 管理器',style='Header.TLabel').pack(anchor='w')
        ttk.Label(top,text='四组模块 0.2 公开测试版  ·  在线下载 / 组合安装 / 独立卸载  ·  新组合需游戏内验收',style='Hint.TLabel').pack(anchor='w',pady=(6,12))
        line=ttk.Frame(top);line.pack(fill='x');ttk.Label(line,text='游戏目录').pack(side='left');self.game_entry=ttk.Entry(line,textvariable=self.game);self.game_entry.pack(side='left',fill='x',expand=True,padx=10)
        self.buttons=[]
        def button(parent,label,fn):
            b=ttk.Button(parent,text=label,command=fn);b.pack(side='left',padx=4);self.buttons.append(b);return b
        button(line,'选择目录',self.choose);button(line,'检查安装',self.check)
        bar=ttk.Frame(root,padding=(20,0,20,12));bar.pack(fill='x');button(bar,'刷新在线目录',self.load_online);button(bar,'下载所勾选',self.download_groups);button(bar,'导入本地包',self.import_zip);button(bar,'隔离演示',self.open_demo);button(bar,'导出检查报告',self.export)
        center=ttk.Panedwindow(root,orient='horizontal');center.pack(fill='both',expand=True,padx=20)
        left=ttk.Frame(center);right=ttk.Frame(center,padding=(16,8));center.add(left,weight=3);center.add(right,weight=2)
        self.tree=ttk.Treeview(left,columns=('chosen','version','state'),show='tree headings',selectmode='browse');self.tree.heading('#0',text='Mod 库');self.tree.heading('chosen',text='保留');self.tree.heading('version',text='版本');self.tree.heading('state',text='状态');self.tree.column('#0',width=260,minwidth=140);self.tree.column('chosen',width=50,stretch=False);self.tree.column('version',width=135,stretch=False);self.tree.column('state',width=75,stretch=False)
        root.after(60,lambda:center.sashpos(0,int(root.winfo_width()*.55)))
        scroll=ttk.Scrollbar(left,orient='vertical',command=self.tree.yview);self.tree.configure(yscrollcommand=scroll.set);self.tree.pack(side='left',fill='both',expand=True);scroll.pack(side='right',fill='y');self.tree.bind('<<TreeviewSelect>>',self.select);self.tree.bind('<Button-1>',self.toggle_group,add='+')
        ttk.Label(right,text='详情与兼容性',font=('Microsoft YaHei UI',12,'bold')).pack(anchor='w');self.details=tk.Text(right,wrap='word',height=12,bg='#fff',relief='flat',font=('Microsoft YaHei UI',10),padx=12,pady=12);self.details.pack(fill='both',expand=True,pady=(10,0))
        actions=ttk.Frame(root,padding=(16,12));actions.pack(fill='x');button(actions,'预览四组选择',self.preview_groups);button(actions,'应用四组选择',self.apply_groups);button(actions,'卸载所选',self.uninstall);button(actions,'撤销最近变更',self.undo);button(actions,'恢复中断操作',self.recover)
        more=ttk.Menubutton(actions,text='恢复 / 空间');more.pack(side='left',padx=4);self.buttons.append(more)
        menu=tk.Menu(more,tearoff=False);menu.add_command(label='撤回到接管前整合版',command=self.withdraw_all);menu.add_command(label='清理已撤回的恢复副本',command=self.clear_snapshots);more.configure(menu=menu)
        self.progress=ttk.Progressbar(root,mode='indeterminate');self.progress.pack(fill='x',padx=20)
        ttk.Label(root,textvariable=self.status,wraplength=990,padding=(20,8)).pack(fill='x')
        self.log=tk.Text(root,height=6,wrap='word',font=('Microsoft YaHei UI',9),state='disabled',bg='#19232f',fg='#dce7f2',relief='flat',padx=12,pady=8);self.log.pack(fill='x',padx=20,pady=(0,14))
        self.set_details('先选择已登记的 r200 / r203 / r206 整合版目录。\n\n刷新在线目录，在“保留”列勾选想使用的四组，下载后预览、应用。公共核心会自动管理，也可导入本地模块包。\n\n首次接管默认勾选全部四组。未勾选的组会撤回登记及独占资源，已获车辆进度保留。\n\n普通纯净底包或未知修改版仍须先做兼容适配；本版不附带完整游戏底包。\n\n安装前需要关闭游戏和离线服务端。')
        root.protocol('WM_DELETE_WINDOW',self.close);root.after(80,self.poll);self.refresh()
    def close(self):
        if self.busy:messagebox.showinfo('正在操作','请等待当前操作完成。意外中断时，可重新打开后恢复。');return
        self.root.destroy()
    def manager(self):
        path=Path(self.game.get());is_demo=(path/'Asphalt9_emu.exe').is_file() and sha_file(path/'Asphalt9_emu.exe')==DEMO_SHA
        return Manager(path,demo=is_demo)
    def set_details(self,s): self.details.configure(state='normal');self.details.delete('1.0','end');self.details.insert('1.0',s);self.details.configure(state='disabled')
    def add_log(self,s): self.log.configure(state='normal');self.log.insert('end',s+'\n');self.log.see('end');self.log.configure(state='disabled')
    def work(self,fn,done=lambda r:None):
        if self.busy:return
        self.busy=True;self.progress.start(12)
        self.game_entry.configure(state='disabled')
        for b in self.buttons:b.configure(state='disabled')
        def run():
            try:self.events.put(('done',fn(),done))
            except Exception as e:self.events.put(('error',str(e),None))
        threading.Thread(target=run,daemon=True).start()
    def poll(self):
        try:
            while True:
                kind,value,done=self.events.get_nowait()
                if kind=='progress':self.status.set(value);self.add_log(value);continue
                self.busy=False;self.progress.stop()
                self.game_entry.configure(state='normal')
                for b in self.buttons:b.configure(state='normal')
                if kind=='error':self.status.set('操作未完成：'+value);self.add_log('检查结果：'+value);messagebox.showerror('操作未完成',value)
                else:
                    try:done(value)
                    except Exception as e:messagebox.showerror('显示结果失败',str(e))
                self.refresh()
        except queue.Empty:pass
        self.root.after(80,self.poll)
    def progress_note(self,s):self.events.put(('progress',s,None))
    def save_library(self):atomic_json(self.library_path,self.library)
    def remember(self,p):
        item={'reference':p.reference(),'summary':p.summary}
        self.library=[x for x in self.library if x.get('reference',{}).get('id')!=p.id]+[item];self.save_library()
    def refresh(self):
        selected=self.tree.selection();old=self.rows.get(selected[0],{}).get('reference') if selected else None
        self.tree.delete(*self.tree.get_children());self.rows={};installed=[]
        if self.game.get():
            try:installed=self.manager().load()['mods']
            except Exception:pass
        if self.desired_groups is None:
            ids={r['id'] for r in installed}
            self.desired_groups=ids&set(GROUPS)-{'a9.core'} if 'a9.core' in ids else set(GROUPS)-{'a9.core'}
        items=list(self.library)
        for ref in installed:
            if not any(x.get('reference')==ref for x in items):items.append({'reference':ref,'summary':{'title':ref['id'],'version':ref['version'],'description':'安装包未保存在当前库；卸载前会检查剩余模块。'}})
        for item in items:
            try:
                ref=item['reference'];s=item['summary'];active=ref in installed
                if ref['id']=='a9.core':continue
                chosen=('☑' if ref['id'] in self.desired_groups else '☐') if s.get('official') else '—'
                state='已安装' if active else ('待下载' if not Path(ref['archive']).is_file() else ('待接管' if s.get('official') and not any(r['id']=='a9.core' for r in installed) else '未安装'))
                iid=self.tree.insert('', 'end',text=s['title'],values=(chosen,s['version'],state));self.rows[iid]=item
                if old==ref:self.tree.selection_set(iid)
            except (KeyError,TypeError):continue
    def chosen(self):
        sel=self.tree.selection()
        if not sel:raise ModError('请先在左侧选择一个 Mod')
        return self.rows[sel[0]]
    def select(self,_=None):
        try:
            s=self.chosen()['summary'];ending='公共核心自动补齐。请勾选希望保留的各组后预览、应用；卸载会重新合成剩余组合。' if s.get('official') else '此包使用普通导入协议。整合包只能整体管理，不与四组模块叠加。'
            self.set_details(s['title']+'\n版本：'+s['version']+'\n\n'+s.get('description','')+'\n\n依赖：'+(', '.join(s.get('requires',[])) or '无')+'\n\n'+ending)
        except Exception:pass
    def choose(self):
        p=filedialog.askdirectory(title='选择包含 Asphalt9_emu.exe 的目录')
        if p:self.game.set(p);self.desired_groups=None;self.refresh();self.check()
    def check(self):
        try:m=self.manager()
        except Exception as e:messagebox.showerror('无法检查',str(e));return
        def run():return m.inspect()
        def done(r):
            self.last_report=r;self.status.set(('隔离演示' if self.manager().demo else '已确认离线4.7.0d主程序；预览还会核对整合版本')+'；已装 %d 个模块；基础副本 %s'%(sum(x['id']!='a9.core' for x in r['installed']),gib(r['base_bytes'])))
            note=''
            if not r['managed']:note='当前尚未由本管理器接管。应用四组选择时会先核对已登记的整合版本，保留一次恢复基础，再按勾选组合重建。\n\n'
            result='尚未接管既有内容' if not r['managed'] else '已管理资源完整'
            if r['differences']:result='发现外部修改，请先处理'
            if r['missing_base_files']:result='缺少底包文件，请查看详情'
            self.set_details(note+json.dumps(r,ensure_ascii=False,indent=2));self.add_log('检查完成：'+result+('；需要恢复中断操作' if r['recovery_required'] else ''))
        self.work(run,done)
    def import_zip(self):
        paths=filedialog.askopenfilenames(title='选择标准 Mod 或旧版完整分享ZIP',filetypes=[('Mod ZIP','*.zip'),('所有文件','*.*')])
        if paths:self.work(lambda:[Package(p) for p in paths],lambda ps:self.import_done(ps))
    def import_done(self,packages):
        for p in packages:self.remember(p);self.add_log('已导入：'+p.title)
        self.status.set('已导入 %d 个包。原ZIP保留在原位置，请勿移动或删除。'%len(packages))
    def desired(self,remove=False):
        item=self.chosen();ref=item['reference'];m=self.manager();installed=m.load()['mods']
        if remove and not any(r['id']==ref['id'] for r in installed):raise ModError('此Mod尚未安装')
        refs=[r for r in installed if r['id']!=ref['id']]
        if not remove:
            refs.append(ref)
            todo=list(Package(ref['archive']).requires);known={x['reference']['id']:x['reference'] for x in self.library if isinstance(x,dict) and 'reference' in x}
            seen={r['id'] for r in refs}
            while todo:
                ident=todo.pop()
                if ident in seen:continue
                if ident not in known:raise ModError('本地库缺少依赖：'+ident)
                dependency=known[ident];refs.append(dependency);seen.add(ident);todo.extend(Package(dependency['archive']).requires)
        return m,m.packages(refs)
    def plan_text(self,p):
        warning=''
        if any(x.legacy for x in p['packages']) or any(r['id'].startswith('legacy.') for r in p['state']['mods']):warning='\n\n旧整合包只做整体资源恢复，车辆存档兼容性尚未逐包实机验收。'
        if p.get('official'):
            warning+='\n\n目标游戏目录：'+p.get('target_directory','')+'\n恢复基础：'+p['official_meta']['baseline']+'\n启用车辆：'+(', '.join(map(str,p['official_meta']['active_cids'])) or '无新增车辆')+'\n'+'\n'.join(p.get('warnings',[]))
        return '所选组合：\n'+('\n'.join('• '+x.title+' '+x.version for x in p['packages'] if x.id!='a9.core') or '• 无新增组；保留公共核心')+'\n\n将重新生成 / 恢复：\n'+'\n'.join(p['affected'])+'\n\n新增基础备份：'+gib(p['new_base_bytes'])+'\n预计所需空闲空间（保守）：'+gib(p['estimated_temporary_bytes'])+'\n当前可用：'+gib(p['free_bytes'])+'\n\n此预览未修改游戏。存档不参与资源回滚。'+warning
    def preview(self):
        try:m,ps=self.desired()
        except Exception as e:messagebox.showerror('无法预览',str(e));return
        self.work(lambda:m.plan(ps),lambda p:(self.set_details(self.plan_text(p)),self.status.set('预览完成；'+('空间足够' if p['space_ok'] else '空间不足'))))
    def change(self,remove=False,undo=False):
        try:
            if undo:
                m=self.manager();ps=m.packages(m.load()['previous_mods'])
            else:m,ps=self.desired(remove)
        except Exception as e:messagebox.showerror('无法操作',str(e));return
        def preview_done(p):
            self.set_details(self.plan_text(p))
            if not p['space_ok']:messagebox.showerror('空间不足',self.plan_text(p));return
            if messagebox.askyesno('确认卸载' if remove else '确认变更',self.plan_text(p)+'\n\n请先关闭游戏和离线服务端。现在执行？'):
                self.work(lambda:m.apply(ps,self.progress_note),lambda r:(setattr(self,'last_report',r),self.status.set('变更完成，所选组合校验通过。请自行启动游戏验收。')))
        self.work(lambda:m.plan(ps),preview_done)
    def install(self):
        try:official=self.chosen()['summary'].get('official')
        except Exception:official=False
        if official:self.apply_groups()
        else:self.change()
    def uninstall(self):
        try:item=self.chosen()
        except Exception as e:messagebox.showerror('无法卸载',str(e));return
        if item['summary'].get('official'):
            self.desired_groups.discard(item['reference']['id']);self.refresh();self.apply_groups()
        else:self.change(remove=True)
    def undo(self):self.desired_groups=None;self.change(undo=True)
    def recover(self):
        try:m=self.manager()
        except Exception as e:messagebox.showerror('无法恢复',str(e));return
        self.work(lambda:m.recover(self.progress_note),lambda r:(setattr(self,'last_report',r),setattr(self,'desired_groups',None),self.status.set('中断恢复完成')))
    def withdraw_all(self):
        try:m=self.manager()
        except Exception as e:messagebox.showerror('无法撤回',str(e));return
        def done(p):
            self.set_details(self.plan_text(p))
            if messagebox.askyesno('撤回管理器接管','将恢复接管前的公共文件。接管前的整合版可能本来就含车辆和功能；这不会变成纯净原版，也不恢复个人存档。\n\n'+self.plan_text(p)):
                self.work(lambda:m.apply([],self.progress_note),lambda r:(setattr(self,'desired_groups',None),self.status.set('已恢复接管前公共文件。可在“恢复 / 空间”中清理副本。')))
        self.work(lambda:m.plan([]),done)
    def clear_snapshots(self):
        try:m=self.manager()
        except Exception as e:messagebox.showerror('无法清理',str(e));return
        if messagebox.askyesno('清理恢复副本','仅在完全撤回接管后清理本管理器保存的公共文件副本。清理后将重新接管，旧恢复历史不再保留；个人存档与游戏文件不删除。继续？'):
            self.work(lambda:m.clear_recovery_cache(self.progress_note),lambda r:(setattr(self,'desired_groups',None),self.status.set('已清理恢复副本 '+gib(r['cleared_bytes']))))
    def open_demo(self):
        def run():
            base=self.home/'IsolatedDemo'
            if not base.exists():return demo.create(base)
            game=base/'DemoGame';return game,[Package(p) for p in sorted((base/'Mods').glob('*.zip'))]
        def done(result):
            game,packages=result;self.game.set(str(game));self.import_done(packages);self.status.set('正在使用隔离演示目录。两个模块修改同一原生格式资源包的不同记录，真实游戏未修改。');self.refresh()
        self.work(run,done)
    def export(self):
        try:m=self.manager()
        except Exception as e:messagebox.showerror('无法导出',str(e));return
        path=filedialog.asksaveasfilename(title='导出不含存档的检查报告',defaultextension='.json',initialfile='A9-Mod-Manager-Check.json')
        if path:
            def run():r=m.inspect();atomic_json(Path(path),r);return r
            self.work(run,lambda r:self.status.set('已导出检查报告；不含存档、账号、个人设置或游戏日志。'))
    def toggle_group(self,event):
        if self.busy or self.tree.identify_column(event.x)!='#1':return
        iid=self.tree.identify_row(event.y);item=self.rows.get(iid)
        if not item or not item['summary'].get('official'):return
        ident=item['reference']['id']
        if ident in self.desired_groups:self.desired_groups.remove(ident)
        else:self.desired_groups.add(ident)
        self.tree.selection_set(iid);self.refresh();self.status.set('当前勾选 %d 组；尚未应用。'%len(self.desired_groups))
        return 'break'
    def group_request(self):
        m=self.manager();return m,m.packages(self.group_refs())
    def group_refs(self):
        known={x['reference']['id']:x['reference'] for x in self.library if x.get('summary',{}).get('official')}
        missing=({'a9.core'}|self.desired_groups)-set(known)
        if missing:raise ModError('缺少模块包：'+', '.join(sorted(missing)))
        return [known['a9.core']]+[known[k] for k in sorted(self.desired_groups)]
    def prepare_refs(self,refs):
        packages=[]
        for ref in refs:
            path=Path(ref['archive'])
            if not path.is_file():
                row=self.remote_rows.get(ref['id'])
                if not row or row['version']!=ref['version'] or row['manifest_sha256']!=ref['manifest_sha256']:raise ModError('本地包缺失，请重新导入或刷新在线目录：'+ref['id'])
                package=download(row,self.home/'Downloads',self.progress_note)
            else:package=Package(path)
            package.verify_reference(ref);packages.append(package)
        return packages
    def preview_groups(self):
        try:m=self.manager();refs=self.group_refs()
        except Exception as e:messagebox.showerror('无法预览四组',str(e));return
        missing=[r for r in refs if not Path(r['archive']).is_file()]
        if missing:
            self.set_details('所勾选的模块尚未全部下载：\n'+'\n'.join(r['id'] for r in missing)+'\n\n点击“下载所勾选”取得并核对文件后，可以检查详细的底包兼容性、资源改动和临时空间。\n\n此时尚未修改游戏。');return
        self.work(lambda:m.plan(self.prepare_refs(refs)),lambda p:(self.set_details(self.plan_text(p)),self.status.set('预览完成，尚未修改游戏。')))
    def apply_groups(self):
        try:m=self.manager();refs=self.group_refs()
        except Exception as e:messagebox.showerror('无法应用四组',str(e));return
        def preview_done(p):
            self.set_details(self.plan_text(p))
            if not p['space_ok']:messagebox.showerror('空间不足',self.plan_text(p));return
            if messagebox.askyesno('应用所勾选的四组模块',self.plan_text(p)+'\n\n确认按这组选择重建？请先关闭游戏和离线服务端。'):
                def done(r):
                    self.last_report=r;self.desired_groups=None;self.refresh();self.status.set('分组组合安装完成。请自行启动服务端和游戏验收。')
                self.work(lambda:m.apply(p['packages'],self.progress_note),done)
        self.work(lambda:m.plan(self.prepare_refs(refs)),preview_done)
    def download_groups(self):
        try:refs=self.group_refs()
        except Exception as e:messagebox.showerror('无法下载模块',str(e));return
        self.work(lambda:self.prepare_refs(refs),lambda ps:(self.import_done(ps),self.status.set('所勾选模块及公共核心已下载／核对；尚未安装到游戏。')))
    def load_online(self):
        existing=list(self.library)
        def run():
            catalog=fetch_catalog();items=[]
            for row in catalog['modules']:
                ref={'archive':str(cache_path(self.home/'Downloads',row)),'manifest_sha256':row['manifest_sha256'],'id':row['id'],'version':row['version']}
                # Preserve a verified offline/local copy instead of downloading it twice.
                for item in existing:
                    prior=item.get('reference',{});path=Path(prior.get('archive',''))
                    if all(prior.get(k)==row[k] for k in ('id','version','manifest_sha256')) and path.is_file() and path.stat().st_size==row['bytes'] and sha_file(path)==row['sha256']:
                        ref['archive']=str(path);break
                summary={'id':row['id'],'title':row['title'],'version':row['version'],'description':row.get('description',''),'requires':row['requires'],'conflicts':[],'official':True,'hidden':row['id']=='a9.core','vehicle_ids':row['vehicle_ids'],'payload_bytes':row['bytes']}
                items.append({'reference':ref,'summary':summary})
            return catalog,items
        def done(result):
            catalog,items=result
            self.remote_rows={r['id']:r for r in catalog['modules']};atomic_json(self.home/'online-catalog.json',catalog)
            ids={row['id'] for row in catalog['modules']}
            self.library=[x for x in self.library if x.get('reference',{}).get('id') not in ids]+items
            self.save_library();self.status.set('在线目录已更新。勾选模块后可按需下载，公共核心自动补齐。');self.refresh()
        self.work(run,done)
    def load_catalog(self,path):
        path=Path(path)
        def run():
            r=json.loads(path.read_bytes())
            if r.get('schema')!='A9MOD_LOCAL_CATALOG_V2':raise ModError('本地模块目录格式不符')
            packages=[]
            for row in r['modules']:
                from engine import safe_path
                p=safe_path(path.parent,row['path'])
                if p.stat().st_size!=row['bytes'] or sha_file(p)!=row['sha256']:raise ModError('内置模块包缺失或损坏：'+row['id'])
                package=Package(p)
                if package.id!=row['id'] or package.manifest_hash!=row['manifest_sha256']:raise ModError('模块目录与包身份不同')
                packages.append(package)
            return packages
        def done(ps):
            self.import_done(ps);self.status.set('四组模块已载入。先勾选要保留的组，再预览和应用；公共核心自动管理。');self.refresh()
        self.work(run,done)

def main():
    p=argparse.ArgumentParser();p.add_argument('--game',type=Path);p.add_argument('--demo',action='store_true');p.add_argument('--probe',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');p.add_argument('--smoke-ui',type=Path);p.add_argument('--catalog',type=Path);p.add_argument('--smoke-groups',type=Path);a=p.parse_args()
    if a.probe:
        r=public_probe(a.probe)
        if a.out:atomic_json(a.out,r)
        elif sys.stdout:print(json.dumps(r,ensure_ascii=False,indent=2))
        return
    if a.self_test:
        import selftest
        r=selftest.run()
        if a.out:atomic_json(a.out,r)
        elif sys.stdout:print(json.dumps(r,ensure_ascii=False,indent=2))
        raise SystemExit(0 if r['passed'] else 1)
    if os.name=='nt':
        import ctypes
        try:ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError,OSError):pass
    root=tk.Tk();home=data_home();app=App(root,home,a.game)
    catalog=a.catalog or app_home()/'catalog.json'
    if not (a.demo or a.smoke_ui):
        if catalog.is_file():root.after(100,lambda:app.load_catalog(catalog))
        else:root.after(100,app.load_online)
    if a.demo or a.smoke_ui:root.after(100,app.open_demo)
    if a.smoke_ui:
        def capture():
            if app.busy:root.after(100,capture);return
            try:
                from PIL import ImageGrab
                root.update();root.lift();root.attributes('-topmost',True);root.update()
                ImageGrab.grab(bbox=(root.winfo_rootx(),root.winfo_rooty(),root.winfo_rootx()+root.winfo_width(),root.winfo_rooty()+root.winfo_height())).save(a.smoke_ui)
                atomic_json(a.smoke_ui.with_suffix('.json'),{'window_created':True,'demo_library_rows':len(app.tree.get_children()),'game_directory_is_demo':app.manager().demo,'real_game_modified':False})
            finally:root.destroy()
        root.after(1400,capture)
    if a.smoke_groups:
        def capture_groups():
            if app.busy:root.after(100,capture_groups);return
            try:
                from PIL import ImageGrab
                root.update();root.lift();root.attributes('-topmost',True);root.update()
                ImageGrab.grab(bbox=(root.winfo_rootx(),root.winfo_rooty(),root.winfo_rootx()+root.winfo_width(),root.winfo_rooty()+root.winfo_height())).save(a.smoke_groups)
                atomic_json(a.smoke_groups.with_suffix('.json'),{'window_created':True,'visible_module_rows':len(app.tree.get_children()),'selected_groups':sorted(app.desired_groups),'core_hidden':not any(x['reference']['id']=='a9.core' for x in app.rows.values()),'game_files_modified':False})
            finally:root.destroy()
        root.after(1800,capture_groups)
    root.mainloop()
if __name__=='__main__':main()
