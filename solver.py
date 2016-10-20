import angr,logging
import inspect

end=0x00400671

proj=angr.Project('a.out',load_options={'auto_load_libs':False})

cfg=proj.analyses.CFGAccurate(keep_state=True)
def funcAddr(name):
	for addr,func in cfg.kb.functions.iteritems():
		if func.name == name:
			return addr
addrFree=funcAddr("plt.free")
saved=0
print hex(addrFree)

argv1 = angr.claripy.BVS("argv1", 8)
initial_state = proj.factory.entry_state(args=["./a.out", argv1]) 
initial_state.add_constraints(argv1 >= '0')
initial_state.add_constraints(argv1 <= '9')

path_group = proj.factory.path_group(initial_state)

cfg=proj.analyses.DDG(cfg)

while len(path_group.active)>0:
	path_group.step()
	#print len(path_group.active)
	for path in path_group.active:
		if str(path.targets[-1]) == "<BV64 "+str(hex(addrFree)).rstrip("L")+">":
			add=path.addr_trace[-1]
			ex=proj.surveyors.Explorer(start=path,find=end)
			ex.run()
			if ex.found:
				print path.targets[-2]
				print ex.found[0].state.se.any_str(argv1)
		#for targ in path.targets:
		#	print targ

