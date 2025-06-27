from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController, OVSSwitch
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call


from mininet.topo import Topo

class FatTreeK4Custom(Topo):
    def __init__(self):
        Topo.__init__(self)

        k = 4  # Fat-tree parameter (k=4)

        core_switches = []
        agg_switches = []
        access_switches = []
        hosts = []

        # Create Core Switches (4 switches)
        for i in range(1, 5):
            core = self.addSwitch(f'c{i}')
            core_switches.append(core)

        # Create Aggregation and Access Switches (8 each)
        for pod in range(k):
            pod_agg = []
            pod_access = []

            # Aggregation switches for this pod
            for i in range(int(k/2)):
                agg = self.addSwitch(f'a{pod * 2 + i + 1}')
                pod_agg.append(agg)
                agg_switches.append(agg)

            # Access switches for this pod
            for i in range(int(k/2)):
                access = self.addSwitch(f'ac{pod * 2 + i + 1}')
                pod_access.append(access)
                access_switches.append(access)

            # Connect Aggregation to Core with High Bandwidth Links
            for agg in pod_agg:
                for core in core_switches:
                    self.addLink(agg, core, bw=1000)  # 1 Gbps

            # Connect Access to Aggregation with Medium Bandwidth Links
            for access in pod_access:
                for agg in pod_agg:
                    self.addLink(access, agg, bw=500)  # 500 Mbps

            # Connect Hosts to Access with Low Bandwidth Links
            for access in pod_access:
                for h in range(2):  # Two hosts per access switch
                    host = self.addHost(f'h{len(hosts) + 1}')
                    hosts.append(host)
                    self.addLink(access, host, bw=100)  # 100 Mbps

topos = {'fat_tree_k4_custom': (lambda: FatTreeK4Custom())}

