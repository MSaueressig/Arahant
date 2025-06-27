from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import tcp, udp


import json
import os
import heapq

class EnergyAwareController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnergyAwareController, self).__init__(*args, **kwargs)
        
        # Modes: 'baseline', 'naive', 'criticality_aware'
        # Set your mode here or via command line args (extend later)
        self.mode = 'criticality_aware'

        self.mac_to_port = {}
        self.topology_api_app = self
        
        # Store switches and links
        self.switches = []
        self.links = []  # (src_dpid, dst_dpid, src_port, dst_port)
        
        # Track link states: True = active, False = sleeping
        self.link_states = {}
        
        #Track switch states
        self.switch_states = {}  # dpid -> True (awake) or False (asleep)
        
        # For flow classification example (simplified)
        # Key: flow_id (e.g. src_ip,dst_ip), Value: 'critical' or 'non_critical'
        self.flow_class = {}

        # Load critical flows from JSON
        self.critical_flows = []
        self.load_critical_flows()
        
    def load_critical_flows(self):
        filename = 'critical_flows.json'
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                data = json.load(f)
                self.critical_flows = data.get('critical_flows', [])
            self.logger.info(f"Loaded {len(self.critical_flows)} critical flows from {filename}")
        else:
            self.logger.warning(f"Critical flows file {filename} not found!")
            
    def is_flow_critical(self, src_ip, dst_ip, src_port=None, dst_port=None, protocol=None):
        for entry in self.critical_flows:
            # IP Match
            ip_match = False
            if 'src_ip' in entry and 'dst_ip' in entry:
                if entry['src_ip'] == src_ip and entry['dst_ip'] == dst_ip:
                    ip_match = True
            elif 'src_ip_prefix' in entry and 'dst_ip_prefix' in entry:
                if src_ip.startswith(entry['src_ip_prefix']) and dst_ip.startswith(entry['dst_ip_prefix']):
                    ip_match = True

            # Protocol Match (optional)
            protocol_match = ('protocol' not in entry) or (entry['protocol'] == protocol)

            # Port Match (optional)
            src_port_match = ('src_port' not in entry) or (entry['src_port'] == src_port)
            dst_port_match = ('dst_port' not in entry) or (entry['dst_port'] == dst_port)
    
            # Final decision
            if ip_match and protocol_match and src_port_match and dst_port_match:
                return True

        return False

    def get_shortest_path_any_state(self, src_dpid, dst_dpid):
        """
        Dijkstra over all links, ignoring whether links are asleep.
        This is used to find the optimal critical path (cached for future use).
        """
        visited = set()
        distances = {node: float('inf') for node in self.adjacency}
        previous = {node: None for node in self.adjacency}
        distances[src_dpid] = 0
    
        heap = [(0, src_dpid)]
    
        while heap:
            (cost, current) = heapq.heappop(heap)
            if current in visited:
                continue
            visited.add(current)
    
            for neighbor in self.adjacency[current]:
                link_cost = self.get_link_cost(current, neighbor)
                new_cost = cost + link_cost
    
                if new_cost < distances[neighbor]:
                    distances[neighbor] = new_cost
                    previous[neighbor] = current
                    heapq.heappush(heap, (new_cost, neighbor))
    
        # Reconstruct path
        path = []
        node = dst_dpid
        while node is not None:
            path.insert(0, node)
            node = previous[node]
    
        if path[0] != src_dpid:
            return None  # No path found

        return path


    def wake_path_links(self, path):
        """
        Wake up all links *and* switches along a path.
        """
        for i in range(len(path)):
            sw = path[i]
            if not self.switch_states.get(sw, True):
                self.wake_switch(sw)

        for i in range(len(path) - 1):
            s1 = path[i]
            s2 = path[i+1]

            self.link_states[(s1, s2)] = True
            self.link_states[(s2, s1)] = True

            port1 = self.adjacency[s1][s2]
            port2 = self.adjacency[s2][s1]

            self.send_port_mod(s1, port1, up=True)
            self.send_port_mod(s2, port2, up=True)

    def wake_switch(self, dpid):
        self.switch_states[dpid] = True
        self.logger.info(f"Switch {dpid} awakened.")
        # If you had disabled flow mods, re-enable them here
        # Or, wake interfaces via ovs-vsctl (if using external script)

    
    def send_port_mod(self, dpid, port_no, up=True):
        """
        Send PortMod to switch to bring port up or down.
        """
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        config = 0 if up else ofproto.OFPPC_PORT_DOWN
        mask = ofproto.OFPPC_PORT_DOWN
    
        req = parser.OFPPortMod(
            datapath=datapath,
            port_no=port_no,
            hw_addr='00:00:00:00:00:00',  # Not needed by Mininet
            config=config,
            mask=mask,
            advertise=0
        )
        datapath.send_msg(req)
        
     
    def on_topology_ready(self):
        for flow in self.critical_flows:
            src_dpid = self.hostsip[flow['src_ip']]['dpid']
            dst_dpid = self.hostsip[flow['dst_ip']]['dpid']
    
            path = self.get_shortest_path_any_state(src_dpid, dst_dpid)
            if path:
                key = (flow['src_ip'], flow['dst_ip'], flow['src_port'], flow['dst_port'], flow['protocol'])
                self.critical_path_cache[key] = path


    def precompute_critical_paths(self):
        """
        After topology discovery and critical flows loaded,
        precompute shortest paths for all critical flows.
        """
        for flow in self.critical_flows:
            src_ip = flow['src_ip']
            dst_ip = flow['dst_ip']
    
            # Get source and destination switch datapath IDs (dpid)
            if src_ip not in self.hostsip or dst_ip not in self.hostsip:
                self.logger.warning(f"Host info missing for flow {src_ip} -> {dst_ip}, skipping.")
                continue

            src_dpid = self.hostsip[src_ip]['dpid']
            dst_dpid = self.hostsip[dst_ip]['dpid']
    
            # Compute shortest path ignoring sleeping links
            path = self.get_shortest_path_any_state(src_dpid, dst_dpid)
    
            if path:
                key = (src_ip, dst_ip,
                       flow.get('src_port', None),
                       flow.get('dst_port', None),
                       flow.get('protocol', None))
                self.critical_path_cache[key] = path
                self.logger.info(f"Precomputed path for critical flow {key}: {path}")
            else:
                self.logger.warning(f"No path found for critical flow {src_ip} -> {dst_ip}")
                
    def try_initialize(self):
        if self.topology_ready and self.critical_flows and self.hostsip:
            self.precompute_critical_paths()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow entry on switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry to send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dpid = ev.switch.dp.id
        self.switch_states[dpid] = True
        self.datapaths[dpid] = ev.switch.dp

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        """Discover topology on switch join"""
        self.switches = get_switch(self.topology_api_app, None)
        links = get_link(self.topology_api_app, None)
        
        self.links = []
        self.link_states = {}
        
        for link in links:
            src = link.src
            dst = link.dst
            self.links.append((src.dpid, dst.dpid, src.port_no, dst.port_no))
            self.link_states[(src.dpid, src.port_no)] = True  # active by default
        
        self.logger.info(f"Topology updated: switches={len(self.switches)}, links={len(self.links)}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets and classify/install flows"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']
    
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
    
        if eth.ethertype == 0x88cc:
            return  # Ignore LLDP
    
        src, dst = eth.src, eth.dst
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
    
        # --- Extract L3/L4 info ---
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
    
        src_ip, dst_ip = None, None
        src_port, dst_port, protocol = None, None, None
    
        if ipv4_pkt:
            src_ip, dst_ip = ipv4_pkt.src, ipv4_pkt.dst
            if tcp_pkt:
                src_port, dst_port = tcp_pkt.src_port, tcp_pkt.dst_port
                protocol = 'TCP'
            elif udp_pkt:
                src_port, dst_port = udp_pkt.src_port, udp_pkt.dst_port
                protocol = 'UDP'

        # --- Classify flow ---
        flow_id = (src_ip, dst_ip, src_port, dst_port, protocol)
        is_critical = self.is_flow_critical(src_ip, dst_ip, src_port, dst_port, protocol)
        self.flow_class[flow_id] = 'critical' if is_critical else 'non_critical'
    
        # --- Critical flow logic ---
        if is_critical and flow_id in self.critical_path_cache:
            path = self.critical_path_cache[flow_id]
            if not self.is_path_awake(path):
                self.wake_path_links(path)
            self.install_flow_along_path(flow_id, path)  # new helper for path installation
            return  # early exit: flow was handled fully

        # --- Build OpenFlow Match ---
        match_fields = {'in_port': in_port, 'eth_src': src, 'eth_dst': dst}
        if ipv4_pkt:
            match_fields.update({'ipv4_src': src_ip, 'ipv4_dst': dst_ip})
        match = parser.OFPMatch(**match_fields)
    
        # --- Build Output Action ---
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
    
        # --- Install Flow Based on Mode ---
        if self.mode == 'baseline':
            self.add_flow(datapath, 1, match, actions)
    
        elif self.mode == 'naive':
            self.add_flow(datapath, 1, match, actions)
            # TODO: Simplistic sleeping logic here if desired
    
        elif self.mode == 'criticality_aware':
            priority = 10 if is_critical else 1
            self.add_flow(datapath, priority, match, actions)
            # TODO: Add custom sleeping logic for non-critical flows

        # --- Send Packet Out ---
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    
"""
Inside your flow-handling logic:
if key not in self.critical_path_cache:
    path = self.get_shortest_path_any_state(src_dpid, dst_dpid)
    if path:
        self.critical_path_cache[key] = path
        self.wake_path_links(path)  # <-- Step 2
        self.install_flow_along_path(flow, path)
"""  


