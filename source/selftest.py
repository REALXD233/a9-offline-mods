"""Regression tests against owned synthetic fixtures, never the real game."""
from pathlib import Path
import copy,io,json,os,struct,subprocess,sys,tempfile,time,unittest,zipfile
import demo
from engine import Manager,Package,ModError,DEMO_EXE,DEMO_SHA,digest,sha_file,atomic_json,relative,safe_path,patch_resource_pins
from resources import Pack,record_read

class Cases(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='A9ModManager-Test-');self.base=Path(self.tmp.name);self.game,self.ps=demo.create(self.base/'fixture');self.m=Manager(self.game,demo=True)
    def tearDown(self):
        for attempt in range(5):
            try:self.tmp.cleanup();return
            except OSError as e:
                if getattr(e,'winerror',None) not in (5,32,145) or attempt==4:raise
                time.sleep(.1*(attempt+1))
    def read(self,uid):
        p=Pack(self.game/'main.pack','main')
        try:return record_read(p.read(demo.LOGICAL),uid,demo.KIND)
        finally:p.close()
    def package(self,ops,contents,ident='test.extra',requires=()):return demo.write_package(self.base/(ident+'.zip'),ident,ident,ops,contents,requires)
    def filemod(self,name='demo/a.txt',before=b'base-a',after=b'changed-a',ident='test.file'):
        op={'kind':'file','target':name,'source':'payload/x.bin','bytes':len(after),'sha256':digest(after),'base_sha256':None if before is None else digest(before)}
        return self.package([op],{'payload/x.bin':after},ident)
    def test_shared_pack_composition_and_independent_uninstall(self):
        original=(self.game/'main.pack').read_bytes();self.m.apply(self.ps)
        self.assertEqual(self.read(demo.UID_A),b'MOD-A-ENABLED');self.assertEqual(self.read(demo.UID_B),b'MOD-B-ENABLED')
        self.m.apply([self.ps[1]])
        self.assertEqual(self.read(demo.UID_A),b'original-A');self.assertEqual(self.read(demo.UID_B),b'MOD-B-ENABLED')
        self.m.apply([]);self.assertEqual((self.game/'main.pack').read_bytes(),original)
        self.assertEqual(self.m.inspect()['differences'],[]);self.assertEqual(self.m.inspect()['installed'],[])
    def test_same_record_conflict_no_mutation(self):
        original=sha_file(self.game/'main.pack');p=copy.deepcopy(self.ps[0].ops[0]);p['source']='x.bin'
        conflict=self.package([p],{'x.bin':b'MOD-A-ENABLED'})
        with self.assertRaisesRegex(ModError,'冲突'):self.m.plan([self.ps[0],conflict])
        self.assertEqual(sha_file(self.game/'main.pack'),original);self.assertFalse(self.m.store.exists())
    def test_whole_bank_conflicts_with_record(self):
        p=Pack(self.game/'main.pack','main')
        try:b=p.read(demo.LOGICAL)
        finally:p.close()
        op={'kind':'resource','target':'main.pack','logical_path':demo.LOGICAL,'source':'x','bytes':len(b),'sha256':digest(b),'base_sha256':digest(b)}
        q=self.package([op],{'x':b})
        with self.assertRaisesRegex(ModError,'冲突'):self.m.plan([q,self.ps[0]])
    def test_dependency_missing_then_preserved(self):
        q=self.filemod();op=copy.deepcopy(self.ps[0].ops[0]);r=self.package([op],{'payload/record.bin':b'MOD-A-ENABLED'},'test.dependent',[q.id])
        with self.assertRaisesRegex(ModError,'依赖'):self.m.plan([r])
        self.m.apply([q,r])
        with self.assertRaisesRegex(ModError,'依赖'):self.m.plan([r])
        self.m.apply([q]);self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'changed-a')
    def test_new_file_removed_on_uninstall(self):
        q=self.filemod('demo/new.txt',None,b'new');self.m.apply([q]);self.assertTrue((self.game/'demo/new.txt').exists());self.m.apply([]);self.assertFalse((self.game/'demo/new.txt').exists())
    def test_failed_commit_rolls_back_every_file_and_state(self):
        p=self.filemod();original=sha_file(self.game/'main.pack')
        with self.assertRaisesRegex(RuntimeError,'simulated'):self.m.apply([p,self.ps[0]],fail_after=1)
        self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'base-a');self.assertEqual(sha_file(self.game/'main.pack'),original);self.assertEqual(self.m.load()['mods'],[])
        self.assertFalse((self.m.store/'transaction.json').exists())
    def test_external_changes_not_overwritten_on_uninstall(self):
        q=self.filemod();self.m.apply([q]);(self.game/'demo/a.txt').write_bytes(b'user-edit')
        with self.assertRaisesRegex(ModError,'变化'):self.m.apply([])
        self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'user-edit')
    def test_base_mismatch_no_mutation(self):
        q=self.filemod(before=b'wrong')
        with self.assertRaisesRegex(ModError,'基础内容'):self.m.apply([q])
        self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'base-a')
    def test_payload_corruption_rejected(self):
        q=self.filemod();info=q.ops[0]
        with zipfile.ZipFile(q.path) as z:m=z.read('manifest.json')
        with zipfile.ZipFile(q.path,'w') as z:z.writestr('manifest.json',m);z.writestr(info['source'],b'bad-value')
        q=Package(q.path)
        with self.assertRaisesRegex(ModError,'校验'):self.m.apply([q])
        self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'base-a')
    def test_archive_slip_links_duplicates_rejected(self):
        for i,name in enumerate(['../bad','C:/bad','/bad','x\\bad','nul.txt','foo./bad','x:stream','x//bad']):
            p=self.base/f'bad{i}.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr(name,b'x')
            with self.subTest(name=name),self.assertRaises(ModError):Package(p)
        p=self.base/'link.zip'
        with zipfile.ZipFile(p,'w') as z:
            x=zipfile.ZipInfo('link');x.create_system=3;x.external_attr=0o120777<<16;z.writestr(x,'outside')
        with self.assertRaises(ModError):Package(p)
        p=self.base/'case.zip'
        with zipfile.ZipFile(p,'w') as z:z.writestr('a',b'a');z.writestr('A',b'b')
        with self.assertRaises(ModError):Package(p)
    def test_demo_package_cannot_install_real_mode(self):
        with self.assertRaisesRegex(ModError,'4.7'):Manager(self.game)
    def test_private_target_and_technical_kit_rejected(self):
        p=self.filemod();m=json.loads(zipfile.ZipFile(p.path).read('manifest.json'));m['operations'][0]['target']='a9emu/data/profile.json'
        q=self.base/'private.zip'
        with zipfile.ZipFile(q,'w') as z:z.writestr('manifest.json',json.dumps(m));z.writestr('payload/x.bin',b'changed-a')
        with self.assertRaisesRegex(ModError,'不允许'):Package(q)
        q=self.base/'technical.zip'
        with zipfile.ZipFile(q,'w') as z:z.writestr('manifest.json',json.dumps({'schema':'C9_NITRO_PORTING_KIT_MANIFEST_V1'}))
        with self.assertRaisesRegex(ModError,'资料包'):Package(q)
    def test_legacy_bundle_whole_install_and_restore(self):
        q=self.base/'legacy.zip';m={'schema':'A9_SHARE_MOD180_V1','version':'fixture-1','required_executable':{'path':'Asphalt9_emu.exe','sha256':DEMO_SHA},'files':[{'path':'demo/a.txt','bytes':6,'sha256':digest(b'LEGACY')}]}
        with zipfile.ZipFile(q,'w') as z:z.writestr('Root/manifest.json',json.dumps(m));z.writestr('Root/files/demo/a.txt',b'LEGACY')
        p=Package(q)
        with self.assertRaisesRegex(ModError,'整合包'):self.m.plan([p,self.ps[0]])
        self.m.apply([p]);self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'LEGACY');self.m.apply([]);self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'base-a')
    def test_undo_restores_previous_combination(self):
        self.m.apply([self.ps[0]]);self.m.apply(self.ps);self.m.apply(self.m.packages(self.m.load()['previous_mods']))
        self.assertEqual(self.read(demo.UID_A),b'MOD-A-ENABLED');self.assertEqual(self.read(demo.UID_B),b'original-B')
    def test_readonly_plan_creates_no_manager_storage(self):
        before=sha_file(self.game/'main.pack');p=self.m.plan(self.ps);self.assertTrue(p['space_ok']);self.assertEqual(sha_file(self.game/'main.pack'),before);self.assertFalse(self.m.store.exists())
    def test_baseline_is_deduplicated_and_transactions_cleaned(self):
        self.m.apply([self.ps[0]]);base=self.m.inspect()['base_bytes'];self.m.apply(self.ps);self.m.apply([self.ps[1]])
        self.assertEqual(self.m.inspect()['base_bytes'],base);self.assertEqual(len(list((self.m.store/'objects').glob('*.bin'))),1)
        self.assertEqual(list((self.m.store/'transactions').iterdir()),[])
    def test_manifest_reference_detects_replacement(self):
        r=self.ps[0].reference();r['manifest_sha256']='0'*64
        with self.assertRaisesRegex(ModError,'变化'):self.m.packages([r])
    def test_tampered_recovery_target_refused(self):
        self.m.store.mkdir();atomic_json(self.m.store/'transaction.json',{'schema':'A9MOD_TRANSACTION_V1','token':'0'*32,'phase':'prepared','rows':[{'target':'../outside','before':None,'after':None}]})
        with self.assertRaises(ModError):self.m.recover()
    def test_loader_pin_update_only_changes_two_certified_slots(self):
        raw=bytearray(b'X'*400);raw[8:12]=b'\0'*4;a=digest(b'old-main');b=digest(b'old-gin');raw[64:96]=bytes.fromhex(a);raw[96:128]=bytes.fromhex(b)
        profile={'main_offset':64,'gin_offset':96,'checksum_offset':8,'main.pack':a,'gin.pack':b}
        changed=patch_resource_pins(bytes(raw),profile,digest(b'new-main'),b)
        self.assertEqual(changed[:64],raw[:64]);self.assertEqual(changed[96:],raw[96:]);self.assertNotEqual(changed[64:96],raw[64:96])
        profile['main_offset']=65
        with self.assertRaises(ModError):patch_resource_pins(bytes(raw),profile,digest(b'new-main'),b)
    @unittest.skipIf(getattr(sys,'frozen',False),'Subprocess source injection is source-only; remaining tests also run in EXE.')
    def test_power_loss_after_first_rename_recovers(self):
        p=self.filemod();self.child_crash([p,self.ps[0]],'commit');self.assertTrue((self.m.store/'transaction.json').exists());self.m.recover()
        self.assertEqual((self.game/'demo/a.txt').read_bytes(),b'base-a');self.assertEqual(self.read(demo.UID_A),b'original-A');self.assertEqual(self.m.load()['mods'],[])
    @unittest.skipIf(getattr(sys,'frozen',False),'Source-only subprocess crash harness.')
    def test_power_loss_after_state_publish_completes(self):
        self.child_crash(self.ps,'publish');self.m.recover();self.assertEqual(self.read(demo.UID_A),b'MOD-A-ENABLED');self.assertEqual(len(self.m.load()['mods']),2)
    def child_crash(self,packages,point):
        code="""
import os,sys,json
sys.path.insert(0,sys.argv[1])
import engine
m=engine.Manager(sys.argv[2],demo=True);ps=[engine.Package(p) for p in json.loads(sys.argv[3])]
if sys.argv[4]=='publish':
 old=engine.atomic_json
 def write(p,v):
  old(p,v)
  if p.name=='state.json':os._exit(92)
 engine.atomic_json=write
def progress(s):
 if sys.argv[4]=='commit' and s.startswith('提交：'):os._exit(91)
m.apply(ps,progress)
"""
        env=os.environ.copy();env['PYTHONIOENCODING']='utf-8'
        r=subprocess.run([sys.executable,'-c',code,str(Path(__file__).parent),str(self.game),json.dumps([str(p.path) for p in packages]),point],capture_output=True,env=env,timeout=30)
        self.assertIn(r.returncode,(91,92),r.stderr.decode('utf-8',errors='replace'))

def run():
    out=io.StringIO();result=unittest.TextTestRunner(stream=out,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    return {'schema':'A9MOD_MANAGER_SELFTEST_V1','passed':result.wasSuccessful(),'tests':result.testsRun,'skipped':len(result.skipped),'failures':len(result.failures),'errors':len(result.errors),'owned_isolated_fixtures_only':True,'real_game_files_modified':False,'details':out.getvalue()}
if __name__=='__main__':
    r=run();print(json.dumps(r,ensure_ascii=False,indent=2));raise SystemExit(0 if r['passed'] else 1)
