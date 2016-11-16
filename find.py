#for a given path group and explore it for frees and return a list of addresses of frees
def find(path_group,cfg):
    addrFree=funcAddr("plt.malloc",cfg)
    #addrs=[]
    #while len(path_group.active)>0:
    #    path_group.step()
    #    for path in path_group.active:
    #      if str(path.targets[-1]) == "<BV64 "+str(hex(addrFree)).rstrip("L")+">":
    #        add=path.addr_trace[-1]
    #        print hex(add)
    #        addrs.append(add)
    #return addrs
    path_group.explore(find=addrFree)
def funcAddr(name,cfg):
    for addr,func in cfg.kb.functions.iteritems():
        if func.name == name:
            return addr
