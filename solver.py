import angr,logging
import inspect
from find import find

proj=angr.Project('a.out',load_options={'auto_load_libs':False})
cfg=proj.analyses.CFGAccurate(keep_state=True)
ddg=proj.analyses.DDG(cfg)


argv1 = angr.claripy.BVS("argv1", 8)
initial_state = proj.factory.entry_state(args=["./a.out", argv1])
initial_state.add_constraints(argv1 >= '0')
initial_state.add_constraints(argv1 <= '9')

path_group = proj.factory.path_group(initial_state)

print find(path_group,cfg)
