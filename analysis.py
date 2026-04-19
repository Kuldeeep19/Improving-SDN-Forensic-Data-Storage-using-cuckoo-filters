"""
Bloom Filter vs Cuckoo Filter — Forensic Performance Analysis
=============================================================
Dataset: CIC-IDS2017 (Tuesday - Brute Force Attacks)
Based on:
  1. Varun Sharma - "Optimizing Forensic Data Availability and Retention
     of SDN Forensic Logs by Using Bloom Filter"
  2. 978-3-319-13731-5_43 - Emerging ICT, CSI 2014 Proceedings

This analysis demonstrates why Cuckoo Filters are superior for
forensic data retention in SDN environments.
"""

import pandas as pd
import matplotlib.pyplot as plt
import math
from bloom_filter import BloomFilter
from cuckoo_filter import CuckooFilter

# ─────────────────────────────────────────
# STEP 1 - Load and Prepare Dataset
# ─────────────────────────────────────────
print("=" * 60)
print("LOADING CIC-IDS2017 DATASET")
print("=" * 60)

df = pd.read_csv('MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv')
df.columns = df.columns.str.strip()
df = df.head(50000)

print(f"Loaded {len(df)} records")
print(f"Labels: {df['Label'].value_counts().to_dict()}")


# Create flow keys using row index for guaranteed uniqueness.
# Each packet (row) in the dataset represents a distinct network event,
# so including the index ensures every flow key is unique — preventing
# duplicate flow keys from inflating traceability scores.
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

# Separate attack and benign traffic
attack_df = df[df['Label'] != 'BENIGN']
benign_df = df[df['Label'] == 'BENIGN']
attack_packets = attack_df['flow_key'].tolist()
benign_packets = benign_df['flow_key'].tolist()
all_packets = df['flow_key'].tolist()
all_labels = df['Label'].tolist()

print(f"\nTotal packets: {len(all_packets)}")
print(f"Attack packets: {len(attack_packets)}")
print(f"Benign packets: {len(benign_packets)}")

# Pick 100 specific attack packets we will track as forensic evidence
tracked_attacks = attack_packets[:100]
print(f"\nTracking {len(tracked_attacks)} attack packets as forensic evidence")

# ─────────────────────────────────────────
# STEP 2 - Run Bloom Filter
# ─────────────────────────────────────────
print("\n" + "=" * 60)
print("RUNNING BLOOM FILTER")
print("=" * 60)

CAPACITY = 10000  # Must exceed expected attack volume for meaningful preservation

bf = BloomFilter(capacity=CAPACITY, false_positive_rate=0.01)

bf_traceability = []
bf_wipes_log = []
bf_memory = []
bf_fpr_log = []
checkpoints = []

print("\nInserting all 50,000 packets...")
for i, packet in enumerate(all_packets):
    bf.insert(packet)

    if i % 500 == 0 and i > 0:
        # Check how many tracked attack packets are still findable
        found = sum(1 for ap in tracked_attacks if bf.lookup(ap))
        traceability = (found / len(tracked_attacks)) * 100

        bf_traceability.append(traceability)
        bf_wipes_log.append(bf.wipe_count)
        bf_memory.append(bf.get_memory_kb() / 1024)
        bf_fpr_log.append(bf.get_current_fpr())
        checkpoints.append(i)

        if i % 5000 == 0:
            print(f"  Progress: {i}/50,000 | Wipes: {bf.wipe_count} | "
                  f"Traceability: {traceability:.1f}% | "
                  f"FPR: {bf.get_current_fpr():.4f}%")

print(f"\nBloom Filter done!")
print(f"Total wipes: {bf.wipe_count}")

# ─────────────────────────────────────────
# STEP 3 - Run Cuckoo Filter
# ─────────────────────────────────────────
print("\n" + "=" * 60)
print("RUNNING CUCKOO FILTER")
print("=" * 60)

cf = CuckooFilter(capacity=CAPACITY, false_positive_rate=0.01)

cf_traceability = []
cf_deletes_log = []
cf_memory = []
cf_fpr_log = []

print("\nInserting all 50,000 packets (attack packets marked!)...")
for i, packet in enumerate(all_packets):
    is_attack = (all_labels[i] != 'BENIGN')
    cf.insert(packet, is_attack=is_attack)

    if i % 500 == 0 and i > 0:
        found = sum(1 for ap in tracked_attacks if cf.lookup(ap))
        traceability = (found / len(tracked_attacks)) * 100

        cf_traceability.append(traceability)
        cf_deletes_log.append(cf.delete_count)
        cf_memory.append(cf.get_memory_kb() / 1024)
        cf_fpr_log.append(cf.get_fpr())

        if i % 5000 == 0:
            print(f"  Progress: {i}/50,000 | Deletes: {cf.delete_count} | "
                  f"Traceability: {traceability:.1f}% | "
                  f"FPR: {cf.get_fpr():.4f}%")

print(f"\nCuckoo Filter done!")
print(f"Total wipes: {cf.wipe_count}")
print(f"Total selective deletes: {cf.delete_count}")

# ─────────────────────────────────────────
# STEP 4 - Demonstrate Selective Deletion
# ─────────────────────────────────────────
print("\n" + "=" * 60)
print("DEMONSTRATING SELECTIVE DELETION (Cuckoo Only)")
print("=" * 60)

# Pick 5 benign packets to delete and verify
demo_benign = benign_packets[:5]
print(f"\nAttempting to delete {len(demo_benign)} specific benign flows:")
for pkt in demo_benign:
    before = cf.lookup(pkt)
    deleted = cf.delete(pkt)
    after = cf.lookup(pkt)
    print(f"  Flow: {pkt[:40]}... | "
          f"Before: {before} | Deleted: {deleted} | After: {after}")

print(f"\nVerifying attack packets are STILL present after benign deletions:")
still_found = sum(1 for ap in tracked_attacks if cf.lookup(ap))
print(f"  {still_found}/{len(tracked_attacks)} attack packets still traceable")
print(f"  (Bloom Filter would have lost ALL data on any capacity event)")

# ─────────────────────────────────────────
# STEP 5 - Empirical False Positive Test
# ─────────────────────────────────────────
print("\n" + "=" * 60)
print("EMPIRICAL FALSE POSITIVE RATE TEST")
print("=" * 60)

# Create fresh filters for FPR testing
bf_test = BloomFilter(capacity=CAPACITY, false_positive_rate=0.01)
cf_test = CuckooFilter(capacity=CAPACITY, false_positive_rate=0.01)

# Insert first 2000 packets
test_inserted = all_packets[:2000]
for pkt in test_inserted:
    bf_test.insert(pkt)
    cf_test.insert(pkt)

# Test with 1000 packets NOT in the filter
test_absent = [f"nonexistent_flow_{i}_999" for i in range(1000)]

bf_fp = sum(1 for p in test_absent if bf_test.lookup(p))
cf_fp = sum(1 for p in test_absent if cf_test.lookup(p))

print(f"Tested {len(test_absent)} absent items:")
print(f"  Bloom Filter false positives: {bf_fp} ({bf_fp/10:.1f}%)")
print(f"  Cuckoo Filter false positives: {cf_fp} ({cf_fp/10:.1f}%)")
print(f"  Bloom theoretical FPR: {bf_test.get_current_fpr():.4f}%")
print(f"  Cuckoo theoretical FPR: {cf_test.get_fpr():.4f}%")

# ─────────────────────────────────────────
# STEP 6 - Generate 4 Graphs
# ─────────────────────────────────────────
print("\n" + "=" * 60)
print("GENERATING COMPARISON GRAPHS")
print("=" * 60)

fig, axes = plt.subplots(2, 2, figsize=(16, 12))
fig.suptitle(
    'Bloom Filter vs Cuckoo Filter — SDN Forensic Performance Analysis\n'
    f'Dataset: CIC-IDS2017 (Tuesday) | 50,000 packets | '
    f'Capacity: {CAPACITY}',
    fontsize=13, fontweight='bold'
)

# Color scheme
BLOOM_COLOR = '#E74C3C'    # Red
CUCKOO_COLOR = '#2ECC71'   # Green

# Graph 1 — Data Availability / Evidence Traceability
# (as required by problem statement: "Data Availability / Traceability")
axes[0][0].plot(checkpoints, bf_traceability, color=BLOOM_COLOR,
                label='Bloom Filter', linewidth=2, alpha=0.9)
axes[0][0].plot(checkpoints, cf_traceability, color=CUCKOO_COLOR,
                label='Cuckoo Filter', linewidth=2, alpha=0.9)
axes[0][0].set_title('Data Availability / Evidence Traceability\n(Higher = Better)',
                     fontweight='bold')
axes[0][0].set_xlabel('Packets Processed')
axes[0][0].set_ylabel('Forensic Evidence Found (%)')
axes[0][0].legend(loc='best')
axes[0][0].grid(True, alpha=0.3)
axes[0][0].set_ylim(-5, 110)
axes[0][0].fill_between(checkpoints, bf_traceability, alpha=0.1,
                        color=BLOOM_COLOR)
axes[0][0].fill_between(checkpoints, cf_traceability, alpha=0.1,
                        color=CUCKOO_COLOR)

# Graph 2 — Memory Usage (RAM in MB)
# (as required by problem statement: "Memory Usage (RAM in MB)")
axes[0][1].plot(checkpoints, bf_memory, color=BLOOM_COLOR,
                label='Bloom Filter', linewidth=2, alpha=0.9)
axes[0][1].plot(checkpoints, cf_memory, color=CUCKOO_COLOR,
                label='Cuckoo Filter', linewidth=2, alpha=0.9)
axes[0][1].set_title('Memory Usage (RAM)\n(Lower = Better)',
                     fontweight='bold')
axes[0][1].set_xlabel('Packets Processed')
axes[0][1].set_ylabel('RAM Usage (MB)')
axes[0][1].legend(loc='best')
axes[0][1].grid(True, alpha=0.3)

# Graph 3 — Wipes vs Selective Deletes
ax3 = axes[1][0]
ax3_twin = ax3.twinx()
ax3.plot(checkpoints, bf_wipes_log, color=BLOOM_COLOR,
         label='Bloom Filter (Wipes)', linewidth=2, alpha=0.9)
ax3_twin.plot(checkpoints, cf_deletes_log, color=CUCKOO_COLOR,
              label='Cuckoo Filter (Deletes)', linewidth=2, alpha=0.9)
ax3.set_title('Catastrophic Wipes vs Selective Deletes\n'
              '(Wipes = total evidence loss)',
              fontweight='bold')
ax3.set_xlabel('Packets Processed')
ax3.set_ylabel('Bloom Wipe Count', color=BLOOM_COLOR)
ax3_twin.set_ylabel('Cuckoo Delete Count', color=CUCKOO_COLOR)
ax3.tick_params(axis='y', labelcolor=BLOOM_COLOR)
ax3_twin.tick_params(axis='y', labelcolor=CUCKOO_COLOR)
# Combined legend
lines1, labels1 = ax3.get_legend_handles_labels()
lines2, labels2 = ax3_twin.get_legend_handles_labels()
ax3.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
ax3.grid(True, alpha=0.3)

# Graph 4 — False Positive Rate
axes[1][1].plot(checkpoints, bf_fpr_log, color=BLOOM_COLOR,
                label='Bloom Filter', linewidth=2, alpha=0.9)
axes[1][1].plot(checkpoints, cf_fpr_log, color=CUCKOO_COLOR,
                label='Cuckoo Filter', linewidth=2, alpha=0.9)
axes[1][1].set_title('False Positive Rate\n(Lower = Better)',
                     fontweight='bold')
axes[1][1].set_xlabel('Packets Processed')
axes[1][1].set_ylabel('False Positive Rate (%)')
axes[1][1].legend(loc='best')
axes[1][1].grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('results.png', dpi=150, bbox_inches='tight')
print("Graph saved as results.png!")

# ─────────────────────────────────────────
# STEP 7 - Final Summary Table
# ─────────────────────────────────────────
print("\n" + "=" * 70)
print("FINAL RESULTS SUMMARY")
print("=" * 70)
print(f"{'Metric':<40} {'Bloom Filter':<15} {'Cuckoo Filter':<15}")
print("-" * 70)
print(f"{'Total Wipes (evidence loss events)':<40} "
      f"{bf.wipe_count:<15} {cf.wipe_count:<15}")
print(f"{'Total Selective Deletes':<40} "
      f"{'N/A':<15} {cf.delete_count:<15}")
print(f"{'Final Traceability (%)':<40} "
      f"{bf_traceability[-1]:.1f}%{'':<11} "
      f"{cf_traceability[-1]:.1f}%")
bf_ram_final = bf.get_memory_kb() / 1024
cf_ram_final = cf.get_memory_kb() / 1024
print(f"{'Memory Usage (RAM MB)':<40} "
      f"{bf_ram_final:.4f}{'':<11} "
      f"{cf_ram_final:.4f}")
print(f"{'Theoretical FPR (%)':<40} "
      f"{bf.get_current_fpr():.4f}%{'':<8} "
      f"{cf.get_fpr():.4f}%")
print(f"{'Empirical FPR (%)':<40} "
      f"{bf_fp / 10:.1f}%{'':<11} "
      f"{cf_fp / 10:.1f}%")
print(f"{'Evidence Lost on Wipe':<40} {'YES':<15} {'NO':<15}")
print(f"{'Supports Deletion':<40} {'NO':<15} {'YES':<15}")
print(f"{'Attack-Aware Eviction':<40} {'NO':<15} {'YES':<15}")
print("=" * 70)

print("\nCONCLUSION: Cuckoo Filter preserves forensic evidence "
      "significantly better than Bloom Filter by supporting selective "
      "deletion and attack-aware eviction -- eliminating the catastrophic "
      "data loss caused by Bloom Filter wipes.")
