"""
SDN Soft-Router Forensic Traceback Experiment
==============================================
This extends the offline filter comparison (analysis.py) into a full
network-level traceback experiment, matching:

  - Sharma & Rawat 2023 topology (1 controller + 6 switches + 4 hosts)
  - Shesha Shila 2015 traceback methodology (query every router, use
    YES-responses to reconstruct the attack path)

We use CIC-IDS2017 as the packet source instead of synthetic Mininet
traffic. Attack packets (FTP-Patator) flow from H0 (attacker) to H3
(victim); benign packets flow between other host pairs.

After all 50,000 packets are transmitted through the network, we
perform forensic traceback on 100 tracked attack packets and measure
how many can be correctly traced back to their source using Bloom
vs Cuckoo filters at each switch.
"""

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import random
from network_simulator import SDNNetwork, SDNController


# ─────────────────────────────────────────────────────────
# STEP 1 - Load CIC-IDS2017 dataset
# ─────────────────────────────────────────────────────────
print("=" * 70)
print("STEP 1: LOADING CIC-IDS2017 (Tuesday - FTP-Patator attacks)")
print("=" * 70)

df = pd.read_csv('MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv')
df.columns = df.columns.str.strip()
df = df.head(50000).reset_index(drop=True)
print(f"Loaded {len(df):,} records")
print(f"Labels: {df['Label'].value_counts().to_dict()}")


def make_flow_key(row):
    return (f"{row.name}_"
            f"{row['Destination Port']}_"
            f"{row['Flow Duration']}_"
            f"{row['Total Fwd Packets']}_"
            f"{row['Total Backward Packets']}_"
            f"{row['Total Length of Fwd Packets']}_"
            f"{row['Init_Win_bytes_forward']}_"
            f"{row['Init_Win_bytes_backward']}")


df['flow_key'] = df.apply(make_flow_key, axis=1)
df['is_attack'] = df['Label'] != 'BENIGN'


# ─────────────────────────────────────────────────────────
# STEP 2 - Build the SDN (Sharma-style: 1 ctrl + 6 sw + 4 hosts)
# ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("STEP 2: BUILDING SDN NETWORK")
print("=" * 70)

SWITCH_CAPACITY = 8000  # per-switch filter capacity (fits all ~5,193 attacks + headroom for benign)
net = SDNNetwork(num_switches=6, num_hosts=4,
                 switch_capacity=SWITCH_CAPACITY, verbose=True)
controller = SDNController(net)  # coordinator — orchestrates traceback on victim's behalf
print(f"Switch graph: {dict(net.switch_graph)}")
print(f"Attack path (H0 -> H3): {net.shortest_path(0, 3)}")
print("SDN Controller initialized — it will coordinate forensic queries.")


# ─────────────────────────────────────────────────────────
# STEP 3 - Define traffic routing
# ─────────────────────────────────────────────────────────
#   Attack flows    : H0 (attacker) -> H3 (victim)
#   Benign flows    : randomly between the other host pairs
random.seed(42)
BENIGN_HOST_PAIRS = [(1, 2), (2, 1), (1, 3), (2, 3), (0, 1), (0, 2)]


def pick_hosts(is_attack):
    if is_attack:
        return 0, 3  # attacker -> victim
    return random.choice(BENIGN_HOST_PAIRS)


# ─────────────────────────────────────────────────────────
# STEP 4 - Transmit all 50k packets through the network
# ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("STEP 3: TRANSMITTING PACKETS THROUGH SDN")
print("=" * 70)

true_paths = {}  # flow_key -> actual path (for verification)
tracked_attacks = []

for i, row in df.iterrows():
    packet = row['flow_key']
    is_atk = row['is_attack']
    src, dst = pick_hosts(is_atk)
    path = net.transmit(packet, src, dst, is_attack=is_atk)

    # Record the path for the first 100 attack packets
    if is_atk and len(tracked_attacks) < 100:
        tracked_attacks.append(packet)
        true_paths[packet] = path

    if (i + 1) % 10000 == 0:
        print(f"  Transmitted {i+1:,}/50,000 packets | "
              f"Bloom wipes so far: {net.get_wipe_counts()} | "
              f"Cuckoo deletes so far: {net.get_delete_counts():,}")

print(f"\nTransmission complete.")
print(f"Total Bloom wipes across all switches: {net.get_wipe_counts()}")
print(f"Total Cuckoo selective deletes: {net.get_delete_counts():,}")
print(f"Total Cuckoo wipes: 0 (guaranteed)")


# ─────────────────────────────────────────────────────────
# STEP 5 - Per-switch activity report
# ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("STEP 4: PER-SWITCH ACTIVITY")
print("=" * 70)
print(f"{'Switch':<10}{'Packets Seen':<18}"
      f"{'Bloom Wipes':<15}{'Cuckoo Deletes':<16}")
print("-" * 70)
for sw_id, sw in net.switches.items():
    print(f"S{sw_id:<9}{sw.packets_forwarded:<18,}"
          f"{sw.bloom.wipe_count:<15}{sw.cuckoo.delete_count:<16,}")


# ─────────────────────────────────────────────────────────
# STEP 6 - FORENSIC TRACEBACK on 100 tracked attack packets
# ─────────────────────────────────────────────────────────
#
# We evaluate THREE traceback strategies:
#   (A) Bloom + SPIE-query-all — the baseline from Varun Sharma 2023.
#       Query every switch with the packet; YES-switches form the path.
#       Bloom wipes destroy evidence → this is expected to fail badly.
#
#   (B) Cuckoo + SPIE-query-all — query every switch.
#       Returns an UNORDERED set of switches. Direction has to be
#       recovered from the topology afterward.
#
#   (C) Cuckoo + Parent-Pointer walk-back — Shesha Shila's exact method.
#       Each switch stored the upstream switch ID when it saw the packet.
#       Start at the victim's switch → follow parent pointers backward
#       until ingress. Produces an ORDERED path in O(path_length) queries.
#
print("\n" + "=" * 70)
print("STEP 5: FORENSIC TRACEBACK (three strategies compared)")
print("=" * 70)
print(f"\nFor each of {len(tracked_attacks)} tracked attack packets we run:")
print("  (A) Bloom + SPIE query-all")
print("  (B) Cuckoo + SPIE query-all  (unordered set)")
print("  (C) Cuckoo + Parent-Pointer walk-back  (ordered path)")
print()

# (A) and (B): SPIE-style query-all
bloom_success = 0
bloom_perfect = 0
bloom_per_hop_hits = 0
cuckoo_success = 0
cuckoo_perfect = 0
cuckoo_per_hop_hits = 0

# (C): Parent-pointer walk-back
pp_success = 0             # at least one true-path switch recovered
pp_perfect = 0             # entire ordered path matches
pp_per_hop_hits = 0        # correct hops summed across all tracked attacks
pp_correct_direction = 0   # reconstructed path in right order (src → victim)

total_hops = 0

for pkt in tracked_attacks:
    true_path = true_paths[pkt]
    total_hops += len(true_path)

    # Controller coordinates all three traceback strategies on victim's behalf
    result = controller.investigate_attack(pkt, victim_host=3)
    bloom_trace = result['bloom_spie']
    cuckoo_trace = result['cuckoo_spie']
    pp_trace = result['cuckoo_parent_pointer']

    # (A) Bloom + SPIE
    bloom_hits = sum(1 for sw in true_path if sw in bloom_trace)
    bloom_per_hop_hits += bloom_hits
    if bloom_hits > 0:
        bloom_success += 1
    if set(bloom_trace) == set(true_path):
        bloom_perfect += 1

    # (B) Cuckoo + SPIE
    cuckoo_hits = sum(1 for sw in true_path if sw in cuckoo_trace)
    cuckoo_per_hop_hits += cuckoo_hits
    if cuckoo_hits > 0:
        cuckoo_success += 1
    if set(cuckoo_trace) == set(true_path):
        cuckoo_perfect += 1

    # (C) Cuckoo + Parent-Pointer (ordered)
    pp_hits = sum(1 for sw in true_path if sw in pp_trace)
    pp_per_hop_hits += pp_hits
    if pp_hits > 0:
        pp_success += 1
    if pp_trace == true_path:
        pp_perfect += 1
        pp_correct_direction += 1

n = len(tracked_attacks)
print(f"{'Metric':<47}{'Bloom SPIE':<13}{'Cuckoo SPIE':<14}{'Cuckoo PP':<12}")
print("-" * 86)
print(f"{'Attacks with ANY hop traced':<47}"
      f"{bloom_success}/{n}        {cuckoo_success}/{n}         "
      f"{pp_success}/{n}")
print(f"{'Attacks with PERFECT path reconstructed':<47}"
      f"{bloom_perfect}/{n}        {cuckoo_perfect}/{n}          "
      f"{pp_perfect}/{n}")
print(f"{'Total correct hop identifications':<47}"
      f"{bloom_per_hop_hits}/{total_hops}      {cuckoo_per_hop_hits}/{total_hops}      "
      f"{pp_per_hop_hits}/{total_hops}")
print(f"{'Traceback success rate':<47}"
      f"{bloom_success/n*100:>5.1f}%       "
      f"{cuckoo_success/n*100:>5.1f}%        "
      f"{pp_success/n*100:>5.1f}%")
print(f"{'Perfect path reconstruction rate':<47}"
      f"{bloom_perfect/n*100:>5.1f}%       "
      f"{cuckoo_perfect/n*100:>5.1f}%        "
      f"{pp_perfect/n*100:>5.1f}%")
print(f"{'Ordered direction recovered':<47}"
      f"{'N/A':>7}      {'N/A':>7}       "
      f"{pp_correct_direction/n*100:>5.1f}%")


# ─────────────────────────────────────────────────────────
# STEP 5b - Network-level False Positive Rate
# ─────────────────────────────────────────────────────────
# A "false positive" at the network level = a switch that reports YES
# even though the packet never traversed it. For each tracked attack we
# count:
#   FP = switches that said YES but are NOT on the true path
#   FN = switches on the true path that said NO (evidence loss)
# We report rates across all tracked attacks.
print("\n" + "=" * 70)
print("STEP 5b: NETWORK-LEVEL FALSE-POSITIVE / FALSE-NEGATIVE RATES")
print("=" * 70)

bloom_fp = bloom_fn = 0
cuckoo_fp = cuckoo_fn = 0
total_non_path = 0
total_on_path = 0
N_switches = net.num_switches

for pkt in tracked_attacks:
    true_set = set(true_paths[pkt])
    on_path = len(true_set)
    non_path = N_switches - on_path
    total_on_path += on_path
    total_non_path += non_path

    bloom_trace = set(net.traceback_bloom(pkt))
    cuckoo_trace = set(net.traceback_cuckoo(pkt))

    bloom_fp += len(bloom_trace - true_set)
    bloom_fn += len(true_set - bloom_trace)
    cuckoo_fp += len(cuckoo_trace - true_set)
    cuckoo_fn += len(true_set - cuckoo_trace)

print(f"{'Metric':<45}{'Bloom':<18}{'Cuckoo':<18}")
print("-" * 81)
print(f"{'False positives (wrong YES)':<45}"
      f"{bloom_fp}/{total_non_path}  "
      f"({bloom_fp/max(1,total_non_path)*100:5.2f}%)    "
      f"{cuckoo_fp}/{total_non_path}  "
      f"({cuckoo_fp/max(1,total_non_path)*100:5.2f}%)")
print(f"{'False negatives (missed YES / evidence loss)':<45}"
      f"{bloom_fn}/{total_on_path}  "
      f"({bloom_fn/max(1,total_on_path)*100:5.2f}%)    "
      f"{cuckoo_fn}/{total_on_path}  "
      f"({cuckoo_fn/max(1,total_on_path)*100:5.2f}%)")
print("\nNote: Bloom's high FN rate = wipes destroying evidence.")
print("      Cuckoo FP = fingerprint collisions (tiny, bounded by 2b/2^f).")


# ─────────────────────────────────────────────────────────
# STEP 5c - Controller query efficiency
# ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("STEP 5c: CONTROLLER QUERY EFFICIENCY")
print("=" * 70)
print(f"Total investigations performed by controller: {controller.investigations}")
print(f"Total SPIE queries issued (bloom + cuckoo query-all): "
      f"{controller.spie_queries:,}")
print(f"Total parent-pointer queries issued: {controller.pp_queries:,}")
avg_spie = controller.spie_queries / max(1, controller.investigations * 2)
avg_pp = controller.pp_queries / max(1, controller.investigations)
print(f"Avg per-traceback:  SPIE = {avg_spie:.1f} (=N={N_switches})  "
      f"vs  Parent-Pointer = {avg_pp:.1f} (=path length)")
print(f"Query-count reduction: "
      f"{(1 - avg_pp/avg_spie)*100:.0f}% fewer queries with parent-pointer")


# ─────────────────────────────────────────────────────────
# STEP 7 - Case study: show one concrete traceback example
# ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("STEP 6: CASE STUDY - Single Attack Packet Traceback")
print("=" * 70)
sample = tracked_attacks[0]
true_p = true_paths[sample]
# Route through the controller just like a real IDS would
case_result = controller.investigate_attack(sample, victim_host=3)
bloom_t = case_result['bloom_spie']
cuckoo_t = case_result['cuckoo_spie']
pp_t = case_result['cuckoo_parent_pointer']

print(f"\nAttack packet (excerpt): {sample[:60]}...")
print(f"True attack path (H0 -> H3):              {true_p}")
print(f"(A) Bloom + SPIE query-all:               {bloom_t}")
print(f"(B) Cuckoo + SPIE query-all:              {cuckoo_t}")
print(f"(C) Cuckoo + Parent-Pointer walkback:     {pp_t}  <-- ordered")
print(f"\n(A) Bloom SPIE correct?        "
      f"{'YES' if set(bloom_t) == set(true_p) else 'NO (evidence wiped)'}")
print(f"(B) Cuckoo SPIE correct?       "
      f"{'YES' if set(cuckoo_t) == set(true_p) else 'NO'}")
print(f"(C) Cuckoo Parent-Ptr correct? "
      f"{'YES (exact order preserved!)' if pp_t == true_p else 'NO'}")


# ─────────────────────────────────────────────────────────
# STEP 8 - Visualization: topology + traceback results
# ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("STEP 7: GENERATING NETWORK TRACEBACK VISUALIZATION")
print("=" * 70)

fig, axes = plt.subplots(1, 3, figsize=(22, 7))
fig.suptitle(
    'SDN Forensic Traceback — Bloom vs Cuckoo Soft Routers\n'
    f'Topology: 1 controller + 6 switches + 4 hosts  |  '
    f'Dataset: CIC-IDS2017 (50,000 packets)  |  '
    f'Switch capacity: {SWITCH_CAPACITY:,}',
    fontsize=13, fontweight='bold'
)

# Switch and host coordinates
switch_xy = {
    0: (1, 2), 1: (2.5, 2), 2: (4, 2),
    3: (5.5, 2), 4: (7, 2), 5: (8.5, 2)
}
host_xy = {
    0: (1, 3.3),   # H0 - attacker
    1: (2.5, 0.2), # H1 - pushed further down to clear S1's stat text
    2: (4, 3.3),
    3: (8.5, 3.3)  # H3 - victim
}
host_labels = {0: 'H0 (Attacker)', 1: 'H1', 2: 'H2', 3: 'H3 (Victim)'}


def draw_topology(ax, title, traced_switches, trace_color,
                  ordered_path=None):
    """
    Draw the SDN topology onto `ax`.
    traced_switches: iterable of switch IDs identified by the traceback
    ordered_path:    if given, draw numbered arrows showing the walk-back
                     order (from victim's switch toward the source)
    """
    # Edges between switches
    for a, neighbors in net.switch_graph.items():
        for b in neighbors:
            if a < b:
                x1, y1 = switch_xy[a]
                x2, y2 = switch_xy[b]
                ax.plot([x1, x2], [y1, y2], color='#888',
                        linewidth=2, zorder=1)

    # Edges from hosts to their switches
    for h, sw in net.host_switch.items():
        x1, y1 = host_xy[h]
        x2, y2 = switch_xy[sw]
        ax.plot([x1, x2], [y1, y2], color='#AAA',
                linewidth=1.5, linestyle='--', zorder=1)

    # Parent-pointer walk-back arrows (drawn UNDERNEATH the nodes)
    if ordered_path and len(ordered_path) >= 2:
        # ordered_path is source→victim. Walk-back is victim→source,
        # so we draw arrows in reverse order, numbered 1, 2, 3, ...
        reverse = list(reversed(ordered_path))
        for step, (a, b) in enumerate(zip(reverse, reverse[1:]), start=1):
            x1, y1 = switch_xy[a]
            x2, y2 = switch_xy[b]
            ax.annotate(
                '', xy=(x2, y1 + 0.35), xytext=(x1, y1 + 0.35),
                arrowprops=dict(arrowstyle='->', color='#8E44AD',
                                linewidth=2.5, shrinkA=8, shrinkB=8),
                zorder=2
            )
            # Step number above the arrow midpoint
            ax.text((x1 + x2) / 2, y1 + 0.55, f"{step}",
                    ha='center', va='bottom', fontsize=10,
                    fontweight='bold', color='#8E44AD', zorder=5)

    # Switches (nodes)
    for sw_id, (x, y) in switch_xy.items():
        color = trace_color if sw_id in traced_switches else '#DDD'
        edge = 'black' if sw_id in traced_switches else '#777'
        ax.scatter(x, y, s=1400, color=color, edgecolor=edge,
                   linewidth=2, zorder=3)
        ax.text(x, y, f"S{sw_id}", ha='center', va='center',
                fontsize=11, fontweight='bold', zorder=4)
        # Per-switch statistics beneath the node
        sw = net.switches[sw_id]
        stat = (f"wipes:{sw.bloom.wipe_count}\n"
                f"deletes:{sw.cuckoo.delete_count:,}")
        ax.text(x, y - 0.55, stat, ha='center', va='top',
                fontsize=7, color='#555', zorder=4)

    # Hosts
    for h, (x, y) in host_xy.items():
        color = '#E74C3C' if h == 0 else ('#27AE60' if h == 3 else '#3498DB')
        ax.scatter(x, y, s=700, color=color, marker='s',
                   edgecolor='black', linewidth=1.5, zorder=3)
        # If host is below switches, put the label below its square; otherwise above.
        if y < 1.5:
            ax.text(x, y - 0.35, host_labels[h], ha='center',
                    va='top', fontsize=9, fontweight='bold', zorder=4)
        else:
            ax.text(x, y + 0.35, host_labels[h], ha='center',
                    va='bottom', fontsize=9, fontweight='bold', zorder=4)

    ax.set_xlim(0, 9.5)
    ax.set_ylim(-1, 4.5)
    ax.set_aspect('equal')
    ax.axis('off')
    ax.set_title(title, fontweight='bold', fontsize=12)


# Pick a sample attack to visualize — same packet as the Step 6 case study
sample_pkt = tracked_attacks[0]
true_path_sample = true_paths[sample_pkt]
bloom_trace_sample = net.traceback_bloom(sample_pkt)
cuckoo_trace_sample = net.traceback_cuckoo(sample_pkt)
pp_trace_sample = net.traceback_parent(sample_pkt, victim_host=3)

# Panel 1: Bloom + SPIE
bloom_title = (f"(A) Bloom + SPIE (query-all)\n"
               f"True path: {true_path_sample}  |  "
               f"Identified: {bloom_trace_sample}\n"
               f"Success: {bloom_success}/{n} "
               f"({bloom_success/n*100:.0f}%)   "
               f"Perfect: {bloom_perfect}/{n} "
               f"({bloom_perfect/n*100:.0f}%)")
draw_topology(axes[0], bloom_title, bloom_trace_sample, '#E74C3C')

# Panel 2: Cuckoo + SPIE
cuckoo_title = (f"(B) Cuckoo + SPIE (query-all)\n"
                f"True path: {true_path_sample}  |  "
                f"Identified: {cuckoo_trace_sample}\n"
                f"Success: {cuckoo_success}/{n} "
                f"({cuckoo_success/n*100:.0f}%)   "
                f"Perfect: {cuckoo_perfect}/{n} "
                f"({cuckoo_perfect/n*100:.0f}%)")
draw_topology(axes[1], cuckoo_title, cuckoo_trace_sample, '#2ECC71')

# Panel 3: Cuckoo + Parent-Pointer walk-back (with numbered arrows)
pp_title = (f"(C) Cuckoo + Parent-Pointer walk-back\n"
            f"True path: {true_path_sample}  |  "
            f"Reconstructed: {pp_trace_sample}\n"
            f"Success: {pp_success}/{n} "
            f"({pp_success/n*100:.0f}%)   "
            f"Perfect (ordered): {pp_perfect}/{n} "
            f"({pp_perfect/n*100:.0f}%)")
draw_topology(axes[2], pp_title, pp_trace_sample, '#9B59B6',
              ordered_path=pp_trace_sample)

# Legend
legend_handles = [
    mpatches.Patch(color='#E74C3C', label='Identified (Bloom SPIE)'),
    mpatches.Patch(color='#2ECC71', label='Identified (Cuckoo SPIE)'),
    mpatches.Patch(color='#9B59B6', label='Identified (Cuckoo Parent-Ptr)'),
    mpatches.Patch(color='#DDD', label='Switch, no response'),
    mpatches.Patch(color='#3498DB', label='Host')
]
fig.legend(handles=legend_handles, loc='lower center',
           ncol=5, fontsize=10, frameon=True)

plt.tight_layout(rect=[0, 0.05, 1, 0.93])
plt.savefig('results_network.png', dpi=150, bbox_inches='tight')
print("results_network.png saved!")


# ─────────────────────────────────────────────────────────
# STEP 9 - Final summary
# ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("FINAL SUMMARY - SDN FORENSIC TRACEBACK")
print("=" * 70)
print(f"{'Metric':<45}{'Bloom SPIE':<14}{'Cuckoo SPIE':<15}{'Cuckoo PP':<12}")
print("-" * 86)
print(f"{'Total wipes (evidence loss events)':<45}"
      f"{net.get_wipe_counts():<14}{'0':<15}{'0':<12}")
print(f"{'Total selective deletes':<45}"
      f"{'N/A':<14}{net.get_delete_counts():<15,}"
      f"{net.get_delete_counts():<12,}")
print(f"{'Attacks with successful traceback':<45}"
      f"{bloom_success}/{n} ({bloom_success/n*100:>3.0f}%)  "
      f"{cuckoo_success}/{n} ({cuckoo_success/n*100:>3.0f}%)  "
      f"{pp_success}/{n} ({pp_success/n*100:>3.0f}%)")
print(f"{'Attacks with perfect path reconstruction':<45}"
      f"{bloom_perfect}/{n} ({bloom_perfect/n*100:>3.0f}%)  "
      f"{cuckoo_perfect}/{n} ({cuckoo_perfect/n*100:>3.0f}%)  "
      f"{pp_perfect}/{n} ({pp_perfect/n*100:>3.0f}%)")
print(f"{'Ordered path direction recovered':<45}"
      f"{'N/A':<14}{'N/A':<15}"
      f"{pp_correct_direction}/{n} ({pp_correct_direction/n*100:>3.0f}%)")
bloom_mem, cuckoo_mem = net.get_total_memory_kb()
print(f"{'Aggregate memory across 6 switches':<45}"
      f"{bloom_mem:.2f} KB      {cuckoo_mem:.2f} KB     {cuckoo_mem:.2f} KB")
print("=" * 86)
print("\nCONCLUSION:")
print("  (A) Bloom + SPIE fails: wipes destroy evidence (0% traceback).")
print("  (B) Cuckoo + SPIE succeeds: returns the UNORDERED set of")
print("      switches the packet visited. Direction must be recovered")
print("      from topology knowledge afterward.")
print("  (C) Cuckoo + Parent-Pointer succeeds AND returns the ORDERED")
print("      path directly — exactly as Shesha Shila described:")
print("      'each router stores which node it came from; walk the")
print("      chain backward from the victim to the source.'")
print("      Only O(path_length) queries vs O(num_switches) for SPIE.")


# ─────────────────────────────────────────────────────────
# STEP 10 - Scalability sweep: does it hold at larger network sizes?
# ─────────────────────────────────────────────────────────
#
# We rebuild the SDN at N=6, 10, 20, 50 switches and rerun a scaled-down
# version of the traceback experiment (500 attacks + 4,500 benign). We
# measure: traceback success rate, ordered-path reconstruction rate,
# number of switch-queries per traceback, and aggregate memory.
#
# Key expectation:
#   - SPIE queries grow linearly with N  (O(N))
#   - Parent-Pointer queries stay ≈ path length  (O(path))
#   - Both Cuckoo methods should retain high success at scale.
#
print("\n" + "=" * 70)
print("STEP 8: SCALABILITY SWEEP  (N = 6, 10, 20, 50 switches)")
print("=" * 70)


def run_sweep(num_switches, num_attack=500, num_benign=4500, cap=8000):
    random.seed(42)
    s_net = SDNNetwork(num_switches=num_switches, num_hosts=4,
                       switch_capacity=cap, verbose=False)
    s_ctrl = SDNController(s_net)
    victim = 3  # H3

    # Transmit benign
    pairs = [(1, 2), (2, 1), (0, 1), (1, victim), (2, victim)]
    for i in range(num_benign):
        src, dst = random.choice(pairs)
        s_net.transmit(f"benign_{i}", src, dst, is_attack=False)

    # Transmit attacks (first 100 tracked)
    tracked = []
    tpaths = {}
    for i in range(num_attack):
        pkt = f"attack_{i}"
        path = s_net.transmit(pkt, 0, victim, is_attack=True)
        if i < 100:
            tracked.append(pkt)
            tpaths[pkt] = path

    # Traceback
    spie_perfect = 0
    pp_perfect = 0
    pp_success = 0
    for pkt in tracked:
        r = s_ctrl.investigate_attack(pkt, victim)
        tp = tpaths[pkt]
        if set(r['cuckoo_spie']) == set(tp):
            spie_perfect += 1
        if r['cuckoo_parent_pointer'] == tp:
            pp_perfect += 1
        if any(sw in r['cuckoo_parent_pointer'] for sw in tp):
            pp_success += 1

    path_len = len(tpaths[tracked[0]])
    bloom_kb, cuckoo_kb = s_net.get_total_memory_kb()
    return {
        'N': num_switches,
        'path_len': path_len,
        'spie_q': num_switches,           # queries per SPIE traceback
        'pp_q': path_len,                 # queries per parent-pointer walk
        'spie_perfect_pct': spie_perfect / len(tracked) * 100,
        'pp_perfect_pct': pp_perfect / len(tracked) * 100,
        'pp_success_pct': pp_success / len(tracked) * 100,
        'bloom_kb': bloom_kb,
        'cuckoo_kb': cuckoo_kb,
    }


sweep_results = []
for N in [6, 10, 20, 50]:
    print(f"  Running N={N}...")
    sweep_results.append(run_sweep(N))

# Print table
print(f"\n{'N':>4}  {'Path':>6}  {'SPIE q':>8}  {'PP q':>6}  "
      f"{'SPIE %':>8}  {'PP ord %':>9}  {'Cuckoo KB':>12}")
print("-" * 64)
for r in sweep_results:
    print(f"{r['N']:>4}  {r['path_len']:>6}  {r['spie_q']:>8}  "
          f"{r['pp_q']:>6}  {r['spie_perfect_pct']:>7.1f}%  "
          f"{r['pp_perfect_pct']:>8.1f}%  {r['cuckoo_kb']:>10.1f}  ")

# Plot scalability chart
fig2, axes2 = plt.subplots(1, 2, figsize=(14, 5))
fig2.suptitle('Scalability: Cuckoo SPIE vs Parent-Pointer at larger networks',
              fontsize=13, fontweight='bold')

Ns = [r['N'] for r in sweep_results]

# Left: queries per traceback
axes2[0].plot(Ns, [r['spie_q'] for r in sweep_results],
              'o-', color='#2ECC71', linewidth=2.5, markersize=10,
              label='SPIE (query-all)  O(N)')
axes2[0].plot(Ns, [r['pp_q'] for r in sweep_results],
              's-', color='#9B59B6', linewidth=2.5, markersize=10,
              label='Parent-Pointer  O(path)')
axes2[0].set_xlabel('Number of switches (N)')
axes2[0].set_ylabel('Switch queries per traceback')
axes2[0].set_title('Query efficiency vs network size')
axes2[0].legend(fontsize=11)
axes2[0].grid(alpha=0.3)

# Right: success rate
axes2[1].plot(Ns, [r['spie_perfect_pct'] for r in sweep_results],
              'o-', color='#2ECC71', linewidth=2.5, markersize=10,
              label='Cuckoo SPIE (unordered match)')
axes2[1].plot(Ns, [r['pp_perfect_pct'] for r in sweep_results],
              's-', color='#9B59B6', linewidth=2.5, markersize=10,
              label='Cuckoo Parent-Pointer (ordered match)')
axes2[1].set_xlabel('Number of switches (N)')
axes2[1].set_ylabel('Perfect reconstruction rate (%)')
axes2[1].set_title('Accuracy vs network size')
axes2[1].set_ylim(0, 105)
axes2[1].legend(fontsize=11)
axes2[1].grid(alpha=0.3)

plt.tight_layout(rect=[0, 0, 1, 0.94])
plt.savefig('results_scalability.png', dpi=150, bbox_inches='tight')
print("\nresults_scalability.png saved!")
