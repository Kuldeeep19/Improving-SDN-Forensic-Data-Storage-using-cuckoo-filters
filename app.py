from flask import Flask, jsonify, send_from_directory, request
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend — no popup window
import matplotlib.pyplot as plt
import time
import threading
import os

from bloom_filter import BloomFilter
from cuckoo_filter import CuckooFilter

app = Flask(__name__)

# ─────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────
sim_state = {
    'running': False,
    'packets_processed': 0,
    'total_packets': 0,
    'bloom_wipes': 0,
    'bloom_count': 0,
    'bloom_traceability': 0,
    'bloom_fpr': 0,
    'bloom_memory': 0,
    'cuckoo_deletes': 0,
    'cuckoo_count': 0,
    'cuckoo_traceability': 0,
    'cuckoo_fpr': 0,
    'cuckoo_memory': 0,
    'events': [],
    'done': False,
    'graph_ready': False,
    'capacity': 5000,
    'attack_packets_total': 0,
    'final': {}
}

sim_thread = None

# ─────────────────────────────────────────
# GRAPH GENERATOR
# ─────────────────────────────────────────
def generate_graph(checkpoints, bf_trace, cf_trace,
                   bf_mem, cf_mem, bf_wipes_log,
                   cf_deletes_log, bf_fpr_log, cf_fpr_log,
                   capacity, total_packets):

    BLOOM_COLOR  = '#E74C3C'
    CUCKOO_COLOR = '#2ECC71'

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle(
        f'Bloom Filter vs Cuckoo Filter — SDN Forensic Performance Analysis\n'
        f'Dataset: CIC-IDS2017 (Tuesday) | {total_packets:,} packets | '
        f'Capacity: {capacity:,}',
        fontsize=13, fontweight='bold'
    )

    # Graph 1 — Traceability
    axes[0][0].plot(checkpoints, bf_trace, color=BLOOM_COLOR,
                    label='Bloom Filter', linewidth=2, alpha=0.9)
    axes[0][0].plot(checkpoints, cf_trace, color=CUCKOO_COLOR,
                    label='Cuckoo Filter', linewidth=2, alpha=0.9)
    axes[0][0].set_title('Data Availability / Evidence Traceability\n(Higher = Better)',
                         fontweight='bold')
    axes[0][0].set_xlabel('Packets Processed')
    axes[0][0].set_ylabel('Forensic Evidence Found (%)')
    axes[0][0].legend(loc='best')
    axes[0][0].grid(True, alpha=0.3)
    axes[0][0].set_ylim(-5, 110)
    axes[0][0].fill_between(checkpoints, bf_trace, alpha=0.1, color=BLOOM_COLOR)
    axes[0][0].fill_between(checkpoints, cf_trace, alpha=0.1, color=CUCKOO_COLOR)

    # Graph 2 — Memory
    axes[0][1].plot(checkpoints, bf_mem, color=BLOOM_COLOR,
                    label='Bloom Filter', linewidth=2, alpha=0.9)
    axes[0][1].plot(checkpoints, cf_mem, color=CUCKOO_COLOR,
                    label='Cuckoo Filter', linewidth=2, alpha=0.9)
    axes[0][1].set_title('Memory Usage (RAM)\n(Lower = Better)', fontweight='bold')
    axes[0][1].set_xlabel('Packets Processed')
    axes[0][1].set_ylabel('RAM Usage (MB)')
    axes[0][1].legend(loc='best')
    axes[0][1].grid(True, alpha=0.3)

    # Graph 3 — Wipes vs Deletes (dual axis)
    ax3     = axes[1][0]
    ax3twin = ax3.twinx()
    ax3.plot(checkpoints, bf_wipes_log, color=BLOOM_COLOR,
             label='Bloom Filter (Wipes)', linewidth=2, alpha=0.9)
    ax3twin.plot(checkpoints, cf_deletes_log, color=CUCKOO_COLOR,
                 label='Cuckoo Filter (Deletes)', linewidth=2, alpha=0.9)
    ax3.set_title('Catastrophic Wipes vs Selective Deletes\n'
                  '(Wipes = total evidence loss)', fontweight='bold')
    ax3.set_xlabel('Packets Processed')
    ax3.set_ylabel('Bloom Wipe Count',   color=BLOOM_COLOR)
    ax3twin.set_ylabel('Cuckoo Delete Count', color=CUCKOO_COLOR)
    ax3.tick_params(axis='y', labelcolor=BLOOM_COLOR)
    ax3twin.tick_params(axis='y', labelcolor=CUCKOO_COLOR)
    lines1, labels1 = ax3.get_legend_handles_labels()
    lines2, labels2 = ax3twin.get_legend_handles_labels()
    ax3.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
    ax3.grid(True, alpha=0.3)

    # Graph 4 — FPR
    axes[1][1].plot(checkpoints, bf_fpr_log, color=BLOOM_COLOR,
                    label='Bloom Filter', linewidth=2, alpha=0.9)
    axes[1][1].plot(checkpoints, cf_fpr_log, color=CUCKOO_COLOR,
                    label='Cuckoo Filter', linewidth=2, alpha=0.9)
    axes[1][1].set_title('False Positive Rate\n(Lower = Better)', fontweight='bold')
    axes[1][1].set_xlabel('Packets Processed')
    axes[1][1].set_ylabel('False Positive Rate (%)')
    axes[1][1].legend(loc='best')
    axes[1][1].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('results.png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    print("✅ results.png generated!")

# ─────────────────────────────────────────
# SIMULATION
# ─────────────────────────────────────────
def run_simulation(capacity, num_packets):
    global sim_state

    sim_state['running']     = True
    sim_state['done']        = False
    sim_state['graph_ready'] = False
    sim_state['events']      = []
    sim_state['packets_processed'] = 0
    sim_state['bloom_wipes'] = 0
    sim_state['cuckoo_deletes'] = 0
    sim_state['capacity']    = capacity

    def add_event(etype, msg):
        sim_state['events'].append({
            'type': etype,
            'msg':  msg,
            'time': time.strftime('%H:%M:%S')
        })
        if len(sim_state['events']) > 200:
            sim_state['events'] = sim_state['events'][-200:]

    # ── Load dataset ──
    add_event('info', 'Loading CIC-IDS2017 dataset...')
    try:
        df = pd.read_csv(
            'MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv'
        )
        df.columns = df.columns.str.strip()
        df = df.head(num_packets)
    except Exception as e:
        add_event('error', f'Dataset error: {str(e)}')
        sim_state['running'] = False
        sim_state['done']    = True
        return

    def make_flow_key(row):
        return (
            f"{row.name}_"
            f"{row['Destination Port']}_"
            f"{row['Flow Duration']}_"
            f"{row['Total Fwd Packets']}_"
            f"{row['Total Backward Packets']}_"
            f"{row['Total Length of Fwd Packets']}_"
            f"{row['Init_Win_bytes_forward']}_"
            f"{row['Init_Win_bytes_backward']}"
        )

    df['flow_key']  = df.apply(make_flow_key, axis=1)
    all_packets     = df['flow_key'].tolist()
    all_labels      = df['Label'].tolist()
    attack_df       = df[df['Label'] != 'BENIGN']
    attack_pkts     = attack_df['flow_key'].tolist()
    tracked         = attack_pkts[:100]

    sim_state['total_packets']        = len(all_packets)
    sim_state['attack_packets_total'] = len(attack_pkts)

    add_event('info',
        f"Loaded {len(all_packets):,} packets — "
        f"{len(attack_pkts):,} attacks"
    )
    add_event('attack',
        f"Tracking {len(tracked)} attack packets as forensic evidence"
    )

    # ── Init filters ──
    bf = BloomFilter(capacity=capacity, false_positive_rate=0.01)
    cf = CuckooFilter(capacity=capacity, false_positive_rate=0.01)

    add_event('info', f"Bloom Filter: {bf.size} bits | {bf.hash_count} hash functions")
    add_event('info', f"Cuckoo Filter: {cf.num_buckets} buckets | {cf.fingerprint_bits}-bit fingerprints")

    # ── Data for graphs ──
    checkpoints    = []
    bf_trace_log   = []
    cf_trace_log   = []
    bf_mem_log     = []
    cf_mem_log     = []
    bf_wipes_log   = []
    cf_deletes_log = []
    bf_fpr_log     = []
    cf_fpr_log     = []

    INTERVAL = max(1, num_packets // 100)  # 100 checkpoints

    # ── Main loop ──
    for i, packet in enumerate(all_packets):
        if not sim_state['running']:
            break
        time.sleep(0.0001)  # tiny delay — makes it more realistic

        is_attack = (all_labels[i] != 'BENIGN')

        # Bloom insert
        prev_wipes = bf.wipe_count
        bf.insert(packet)
        if bf.wipe_count > prev_wipes:
            add_event('wipe',
                f"💥 BLOOM FILTER WIPED! "
                f"(Wipe #{bf.wipe_count}) — All evidence LOST!"
            )

        # Cuckoo insert
        prev_del = cf.delete_count
        cf.insert(packet, is_attack=is_attack)
        if cf.delete_count > prev_del:
            deleted = cf.delete_count - prev_del
            add_event('delete',
                f"↩ Sliding Window: Deleted {deleted} oldest "
                f"BENIGN entries (attacks preserved!)"
            )

        if is_attack and i % 500 == 0:
            add_event('attack',
                f"⚡ Attack packet inserted — is_attack=True (protected)"
            )

        # Checkpoint
        if i % INTERVAL == 0 or i == len(all_packets) - 1:
            bf_found = sum(1 for ap in tracked if bf.lookup(ap))
            cf_found = sum(1 for ap in tracked if cf.lookup(ap))
            b_trace  = round((bf_found / len(tracked)) * 100) if tracked else 0
            c_trace  = round((cf_found / len(tracked)) * 100) if tracked else 0
            b_mem    = round(bf.get_memory_kb() / 1024, 4)
            c_mem    = round(cf.get_memory_kb() / 1024, 4)

            # Live state update
            sim_state.update({
                'packets_processed':   i + 1,
                'bloom_wipes':         bf.wipe_count,
                'bloom_count':         bf.item_count,
                'bloom_traceability':  b_trace,
                'bloom_fpr':           round(bf.get_current_fpr(), 4),
                'bloom_memory':        b_mem,
                'cuckoo_deletes':      cf.delete_count,
                'cuckoo_count':        cf.item_count,
                'cuckoo_traceability': c_trace,
                'cuckoo_fpr':          round(cf.get_fpr(), 4),
                'cuckoo_memory':       c_mem,
            })

            # Graph data
            checkpoints.append(i + 1)
            bf_trace_log.append(b_trace)
            cf_trace_log.append(c_trace)
            bf_mem_log.append(b_mem)
            cf_mem_log.append(c_mem)
            bf_wipes_log.append(bf.wipe_count)
            cf_deletes_log.append(cf.delete_count)
            bf_fpr_log.append(round(bf.get_current_fpr(), 4))
            cf_fpr_log.append(round(cf.get_fpr(), 4))

    # ── Final summary ──
    add_event('done',
        f"✅ Simulation complete! "
        f"Bloom wipes: {bf.wipe_count} | "
        f"Cuckoo wipes: 0 | "
        f"Cuckoo deletes: {cf.delete_count:,} | "
        f"Final traceability — Bloom: {bf_trace_log[-1] if bf_trace_log else 0}% "
        f"Cuckoo: {cf_trace_log[-1] if cf_trace_log else 0}%"
    )

    sim_state['final'] = {
        'bloom_wipes':      bf.wipe_count,
        'cuckoo_wipes':     0,
        'cuckoo_deletes':   cf.delete_count,
        'bloom_trace':      bf_trace_log[-1] if bf_trace_log else 0,
        'cuckoo_trace':     cf_trace_log[-1] if cf_trace_log else 0,
        'bloom_memory':     bf_mem_log[-1]   if bf_mem_log   else 0,
        'cuckoo_memory':    cf_mem_log[-1]   if cf_mem_log   else 0,
        'bloom_fpr':        bf_fpr_log[-1]   if bf_fpr_log   else 0,
        'cuckoo_fpr':       cf_fpr_log[-1]   if cf_fpr_log   else 0,
    }

    # ── Generate graph ──
    add_event('info', 'Generating results.png...')
    try:
        generate_graph(
            checkpoints, bf_trace_log, cf_trace_log,
            bf_mem_log,  cf_mem_log,
            bf_wipes_log, cf_deletes_log,
            bf_fpr_log,   cf_fpr_log,
            capacity,     num_packets
        )
        sim_state['graph_ready'] = True
        add_event('done', '📊 results.png generated! Graph is now visible on dashboard.')
    except Exception as e:
        add_event('error', f'Graph error: {str(e)}')

    sim_state['running'] = False
    sim_state['done']    = True


# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'dashboard2.html')

@app.route('/start', methods=['POST'])
def start():
    global sim_thread
    if sim_state['running']:
        return jsonify({'error': 'Already running'}), 400
    data      = request.get_json() or {}
    capacity  = int(data.get('capacity',    5000))
    n_packets = int(data.get('num_packets', 50000))
    sim_thread = threading.Thread(
        target=run_simulation,
        args=(capacity, n_packets),
        daemon=True
    )
    sim_thread.start()
    return jsonify({'status': 'started'})

@app.route('/stop', methods=['POST'])
def stop():
    sim_state['running'] = False
    return jsonify({'status': 'stopped'})

@app.route('/state')
def state():
    return jsonify(sim_state)

@app.route('/results.png')
def results_png():
    if os.path.exists('results.png'):
        return send_from_directory('.', 'results.png')
    return '', 404

@app.route('/reset', methods=['POST'])
def reset():
    sim_state.update({
        'running': False, 'packets_processed': 0,
        'total_packets': 0, 'bloom_wipes': 0,
        'bloom_count': 0, 'bloom_traceability': 0,
        'bloom_fpr': 0, 'bloom_memory': 0,
        'cuckoo_deletes': 0, 'cuckoo_count': 0,
        'cuckoo_traceability': 0, 'cuckoo_fpr': 0,
        'cuckoo_memory': 0, 'events': [],
        'done': False, 'graph_ready': False,
        'attack_packets_total': 0, 'final': {}
    })
    return jsonify({'status': 'reset'})

if __name__ == '__main__':
    print("=" * 55)
    print("  SDN Forensic Dashboard — Flask Server")
    print("  Open http://localhost:5000 in your browser")
    print("=" * 55)
    app.run(debug=False, port=5000)