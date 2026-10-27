"""Exercise actual Tk commands and worker callbacks on an owned demo only."""
from pathlib import Path
import json,tempfile,time,tkinter as tk
import app
from engine import atomic_json
from resources import Pack,record_read
import demo

def run():
    errors=[];app.messagebox.askyesno=lambda *a,**k:True;app.messagebox.showerror=lambda *a,**k:errors.append(str(a))
    with tempfile.TemporaryDirectory(prefix='A9ModManager-UI-') as folder:
        home=Path(folder);root=tk.Tk();root.withdraw();ui=app.App(root,home)
        def pump():
            until=time.monotonic()+20
            while ui.busy:
                root.update();time.sleep(.01)
                if time.monotonic()>until:raise TimeoutError('UI worker did not finish')
            root.update()
            if errors:raise AssertionError(errors)
        def select(ident):
            found=[iid for iid,item in ui.rows.items() if item['reference']['id']==ident]
            assert len(found)==1;ui.tree.selection_set(found[0]);root.update()
        def read(uid):
            p=Pack(Path(ui.game.get())/'main.pack','main')
            try:return record_read(p.read(demo.LOGICAL),uid,demo.KIND)
            finally:p.close()
        try:
            ui.open_demo();pump();assert len(ui.tree.get_children())==2
            select('demo.module-a');ui.install();pump();assert read(demo.UID_A)==b'MOD-A-ENABLED'
            select('demo.module-b');ui.install();pump();assert len(ui.manager().load()['mods'])==2
            select('demo.module-a');ui.uninstall();pump();assert read(demo.UID_A)==b'original-A' and read(demo.UID_B)==b'MOD-B-ENABLED'
            assert [x['id'] for x in ui.manager().load()['mods']]==['demo.module-b']
            ui.undo();pump();assert len(ui.manager().load()['mods'])==2 and read(demo.UID_A)==b'MOD-A-ENABLED'
            ui.check();pump();assert not ui.last_report['differences']
            dest=home/'export.json';app.filedialog.asksaveasfilename=lambda **k:str(dest);ui.export();pump();assert json.loads(dest.read_bytes())['installed']
            return {'passed':True,'real_Tk_commands':True,'background_worker_and_confirmation_callbacks':True,'install_A_then_B':True,'uninstall_A_preserves_B':True,'undo_restores_A_and_B':True,'check_and_export':True,'owned_demo_only':True,'real_game_modified':False}
        finally:root.destroy()

if __name__=='__main__':
    import sys
    r=run();atomic_json(Path(sys.argv[1]),r);print(json.dumps(r))
