import angr
import networkx as nx
import matplotlib.pyplot as plt
def use(path_group, ddg,cfg):
    nx.draw(ddg.graph)
    an=ddg.graph.nodes()
    print hex(an[0].ins_addr)
    plt.show()
