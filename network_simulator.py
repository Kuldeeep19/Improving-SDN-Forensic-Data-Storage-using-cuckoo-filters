"""
SDN Soft-Router Network Simulator
==================================
Implements a software-defined network with multiple "soft routers"
(virtual switches), each maintaining its own Bloom Filter and
Cuckoo Filter — exactly as described in:

  - Bhondele, Rawat, Renukuntla (2015) "Network Management
    Framework for Network Forensic Analysis" — payload attribution
    via per-router Bloom Filters
  - Sharma, Rawat (2023) "Optimizing Forensic Data Availability
    and Retention of SDN Forensic Logs by Using Bloom Filter" —
    Mininet-style topology (1 controller + 6 switches + 4 hosts)

TRACEBACK mechanism (Shesha Shila's original idea):
  When a victim is attacked, she extracts a packet "excerpt" and
  queries every router's filter. The routers that reply YES form
  the reconstructed attack path from attacker to victim.
"""

from collections import deque
from bloom_filter import BloomFilter
from cuckoo_filter import CuckooFilter


class SoftSwitch:
    """
    One virtual/software router in the SDN.
    Each switch maintains its OWN Bloom Filter and Cuckoo Filter
    — this matches Shesha Shila's "per-router payload attribution"
    design where every device stores a compressed record of what
    passed through it.
    """

    def __init__(self, switch_id, capacity=2000, fpr=0.01):
        self.id = switch_id
        self.bloom = BloomFilter(capacity=capacity, false_positive_rate=fpr,
                                 verbose=False)
        self.cuckoo = CuckooFilter(capacity=capacity, false_positive_rate=fpr,
                                   verbose=False)
        self.packets_forwarded = 0

    def forward(self, packet, is_attack=False, parent_sw_id=None):
        """
        Record a packet passing through this switch.

        parent_sw_id: the switch that handed us this packet
            (None if packet entered the network directly from a host).
            Stored in the Cuckoo entry — enables parent-pointer traceback.
        """
        self.bloom.insert(packet)
        self.cuckoo.insert(packet, is_attack=is_attack, parent_sw_id=parent_sw_id)
        self.packets_forwarded += 1

    def query_bloom(self, packet):
        """Did this packet pass through me? (Bloom Filter answer.)"""
        return self.bloom.lookup(packet)

    def query_cuckoo(self, packet):
        """Did this packet pass through me? (Cuckoo Filter answer.)"""
        return self.cuckoo.lookup(packet)


class SDNNetwork:
    r"""
    A simulated SDN topology.
    Default: 1 controller + 6 switches + 4 hosts (matches Sharma 2023).

    Topology:
                H0 (attacker)              H2
                 |                          |
                [S0] - [S1] - [S2] - [S3] - [S4] - [S5]
                 |             \_________________/      |
                 H1              (cross-link)          H3 (victim)

    Attack path H0 -> H3 goes through: S0, S1, S2, S3, S4, S5.
    Cross-link shortens some alternate paths.
    """

    def __init__(self, num_switches=6, num_hosts=4,
                 switch_capacity=2000, fpr=0.01, verbose=False):
        self.num_switches = num_switches
        self.num_hosts = num_hosts
        self.verbose = verbose

        # Create switches
        self.switches = {
            i: SoftSwitch(i, capacity=switch_capacity, fpr=fpr)
            for i in range(num_switches)
        }

        # Switch adjacency graph (undirected)
        self.switch_graph = self._build_switch_graph()

        # Map each host to the switch it attaches to
        self.host_switch = self._attach_hosts()

        if self.verbose:
            print(f"SDN Network: {num_switches} switches, {num_hosts} hosts")
            print(f"Host-switch map: {self.host_switch}")

    def _build_switch_graph(self):
        """Linear chain with one cross-link for path diversity."""
        adj = {i: set() for i in range(self.num_switches)}
        # Linear backbone: S0 - S1 - S2 - ... - S(n-1)
        for i in range(self.num_switches - 1):
            adj[i].add(i + 1)
            adj[i + 1].add(i)
        # Cross-link for path diversity (if >=5 switches)
        if self.num_switches >= 5:
            adj[1].add(self.num_switches - 2)
            adj[self.num_switches - 2].add(1)
        return adj

    def _attach_hosts(self):
        """Attach each host to a switch. Spread hosts across the network."""
        # H0 at S0, H(last) at S(last). Others in between.
        mapping = {}
        if self.num_hosts == 1:
            mapping[0] = 0
        else:
            step = max(1, (self.num_switches - 1) // (self.num_hosts - 1))
            for h in range(self.num_hosts):
                sw = min(h * step, self.num_switches - 1)
                mapping[h] = sw
        return mapping

    def shortest_path(self, host_src, host_dst):
        """BFS shortest path through switches from src host to dst host."""
        src_sw = self.host_switch[host_src]
        dst_sw = self.host_switch[host_dst]
        if src_sw == dst_sw:
            return [src_sw]

        parent = {src_sw: None}
        q = deque([src_sw])
        while q:
            curr = q.popleft()
            if curr == dst_sw:
                break
            for nbr in self.switch_graph[curr]:
                if nbr not in parent:
                    parent[nbr] = curr
                    q.append(nbr)

        if dst_sw not in parent:
            return []

        # Reconstruct path
        path = []
        node = dst_sw
        while node is not None:
            path.append(node)
            node = parent[node]
        return list(reversed(path))

    def transmit(self, packet, host_src, host_dst, is_attack=False):
        """
        Send a packet from host_src to host_dst through the switches.
        Every switch on the path records the packet in its filters
        AND stores the upstream switch ID (parent) for parent-pointer traceback.
        Returns the switch-path the packet actually took.
        """
        path = self.shortest_path(host_src, host_dst)
        prev_sw = None  # ingress: first switch has no upstream switch
        for sw_id in path:
            self.switches[sw_id].forward(packet, is_attack=is_attack,
                                         parent_sw_id=prev_sw)
            prev_sw = sw_id
        return path

    def traceback_parent(self, packet, victim_host, max_hops=None):
        """
        Parent-pointer traceback (Shesha Shila's 'store-from-which-node-it-came').

        Start at the victim's ingress switch, ask 'who sent you this packet?'.
        Walk backward through the parent pointers until we hit None (ingress)
        or a switch that doesn't recognize the packet (chain broken).

        Returns the reconstructed path from source to victim (ordered).
        Returns [] if the packet can't be located at the victim's switch at all.
        """
        if max_hops is None:
            max_hops = self.num_switches  # safety cap

        current_sw = self.host_switch[victim_host]
        reversed_path = []
        visited = set()

        for _ in range(max_hops):
            if current_sw in visited:
                break  # cycle guard — shouldn't happen in our topology
            visited.add(current_sw)

            found, parent = self.switches[current_sw].cuckoo.get_parent(packet)
            if not found:
                # Chain broken — current switch has no record of this packet
                if not reversed_path:
                    return []
                break

            reversed_path.append(current_sw)
            if parent is None:
                # Ingress reached — this switch is where the packet entered
                break
            current_sw = parent

        return list(reversed(reversed_path))

    def traceback_bloom(self, packet):
        """
        Query every switch's Bloom Filter.
        Return the list of switch IDs that report the packet is present.
        This is Shesha Shila's traceback: the YES-switches form the path.
        """
        return [sw_id for sw_id, sw in self.switches.items()
                if sw.query_bloom(packet)]

    def traceback_cuckoo(self, packet):
        """Same as traceback_bloom, but using Cuckoo Filters."""
        return [sw_id for sw_id, sw in self.switches.items()
                if sw.query_cuckoo(packet)]

    def get_wipe_counts(self):
        """Total Bloom wipes across all switches."""
        return sum(sw.bloom.wipe_count for sw in self.switches.values())

    def get_delete_counts(self):
        """Total Cuckoo selective deletes across all switches."""
        return sum(sw.cuckoo.delete_count for sw in self.switches.values())

    def get_total_memory_kb(self):
        """Aggregate memory across all switches, for both filter types."""
        bloom_kb = sum(sw.bloom.get_memory_kb() for sw in self.switches.values())
        cuckoo_kb = sum(sw.cuckoo.get_memory_kb() for sw in self.switches.values())
        return bloom_kb, cuckoo_kb


class SDNController:
    """
    SDN Controller — orchestrates forensic traceback across soft routers.

    In real OpenFlow SDN, the controller has global visibility of switches.
    When a victim's IDS detects an attack, the packet excerpt is forwarded
    to the controller, and the controller coordinates the query across
    every switch — matching the "1 controller + 6 switches" architecture
    from Sharma & Rawat (2023).

    This class is a thin coordination layer:
      - investigate_attack(): runs all three traceback strategies
      - query_count: how many switch-queries the controller issued
        (SPIE = O(num_switches); Parent-Pointer = O(path_length))
    """

    def __init__(self, network):
        self.network = network
        self.investigations = 0
        self.spie_queries = 0
        self.pp_queries = 0

    def investigate_attack(self, packet, victim_host):
        """
        Victim's IDS asks the controller to trace `packet`.
        The controller queries the switches on her behalf.
        Returns a dict with all three traceback results.
        """
        self.investigations += 1
        N = self.network.num_switches

        bloom_trace = self.network.traceback_bloom(packet)
        self.spie_queries += N

        cuckoo_trace = self.network.traceback_cuckoo(packet)
        self.spie_queries += N

        pp_trace = self.network.traceback_parent(packet, victim_host)
        # Parent-pointer issued one query per hop it walked
        self.pp_queries += max(1, len(pp_trace))

        return {
            'bloom_spie': bloom_trace,
            'cuckoo_spie': cuckoo_trace,
            'cuckoo_parent_pointer': pp_trace,
        }


# Smoke test
if __name__ == "__main__":
    print("=" * 60)
    print("Smoke test: 1 controller + 6 switches + 4 hosts")
    print("=" * 60)
    net = SDNNetwork(num_switches=6, num_hosts=4,
                     switch_capacity=100, verbose=True)

    print(f"\nSwitch graph: {dict(net.switch_graph)}")
    print(f"Shortest path H0 -> H3: "
          f"{net.shortest_path(0, 3)}")
    print(f"Shortest path H1 -> H2: "
          f"{net.shortest_path(1, 2)}")

    print("\nTransmitting 3 attack packets H0 -> H3 ...")
    for i in range(3):
        path = net.transmit(f"attack_pkt_{i}", 0, 3, is_attack=True)
        print(f"  attack_pkt_{i} took path: {path}")

    print("\nTraceback of attack_pkt_0 (Cuckoo):")
    trace = net.traceback_cuckoo("attack_pkt_0")
    print(f"  Switches that saw it: {trace}")
    print(f"  Reconstructed path matches true path: "
          f"{sorted(trace) == sorted(net.shortest_path(0, 3))}")
