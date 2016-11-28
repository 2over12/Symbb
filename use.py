import angr
import networkx as nx
import matplotlib.pyplot as plt
def use(path_group, ddg,cfg):
    nx.draw(ddg.graph)
    #for n in ddg.graph.nodes():
    #if n.ins_addr==path_group.found[0].addr_trace
    print hex(path_group.found[0].addr_trace[-1])
    #print hex(path_group.found[0].ins_addr)
    plt.show()
