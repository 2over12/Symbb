import angr
import claripy
import simuvex


addrUse=0x004006c4

proj=angr.Project('a.out',load_options={'auto_load_libs': False})
cfg=proj.analyses.CFGAccurate(keep_state=True)
ddg=proj.analyses.DDG(cfg)
def addrFunc(n):
    func=cfg.kb.functions.function(name=n)
    return func.addr

state = proj.factory.entry_state()
arg1 = claripy.BVS('argv', 8)

initial_state = proj.factory.entry_state(args=["a.out", arg1], add_options={"BYPASS_UNSUPPORTED_SYSCALL"})
print hex(addrFunc("plt.free"))
pg = proj.factory.path_group(initial_state, immutable=False)
pg.step()

res=pg.explore(find=addrUse)
print pg.found[0].state.se.any_str(arg1)
