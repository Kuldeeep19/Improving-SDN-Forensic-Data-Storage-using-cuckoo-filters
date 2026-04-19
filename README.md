
# SDN Forensic Data Storage — Bloom Filter vs Cuckoo Filter

PG project exploring whether **Cuckoo Filters** can replace Bloom Filters in SDN
forensic logging — fixing the catastrophic-wipe evidence-loss problem and
enabling multi-strategy attack traceback.

## What's inside

| File | Purpose |
|------|---------|
| `bloom_filter.py`      | Bloom Filter with catastrophic wipe on overflow |
| `cuckoo_filter.py`     | Cuckoo Filter with attack-aware sliding-window deletion + parent-pointer storage |
| `analysis.py`          | Offline experiment — single Bloom vs single Cuckoo on 50,000 CIC-IDS2017 packets (produces `results.png`) |
| `network_simulator.py` | SDN topology (1 controller + 6 switches + 4 hosts), SoftSwitch, SDNController |
| `network_analysis.py`  | Network experiment — 3-way traceback, FPR/FNR, scalability sweep (produces `results_network.png`, `results_scalability.png`) |
| `app.py`               | Flask dashboard (optional — live visualization) |
| `report.tex`           | LaTeX project report |

## Setup

```bash
pip install -r requirements.txt
```

The CIC-IDS2017 Tuesday CSV must exist at
`MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv`.

## How to run (eval demo order)

**1. Bloom Filter — shows the wipe problem**
```bash
python bloom_filter.py
```
Inserts 12 items into a capacity-10 filter. Observe the catastrophic wipe — all
evidence lost.

**2. Cuckoo Filter — shows selective deletion**
```bash
python cuckoo_filter.py
```
Same workload, capacity 10. No wipe. Attack-marked items survive; oldest benign
items are selectively deleted.

**3. Network simulator smoke test — shows SDN traceback**
```bash
python network_simulator.py
```
6 soft routers, 4 hosts, cross-link topology. Attacker H0 → Victim H3.
Traceback reconstructs the attack path.

**4. Full experiment — main result**
```bash
python network_analysis.py
```
Runs the full pipeline on 50,000 CIC-IDS2017 packets:
- Per-switch Bloom + Cuckoo filters
- Three traceback strategies (Bloom+SPIE, Cuckoo+SPIE, Cuckoo+Parent-Pointer)
- Network-level FPR / FNR
- Controller query-efficiency report
- Scalability sweep (6 → 50 switches)

Produces `results_network.png` and `results_scalability.png`.

**5. (Optional) Flask dashboard**
```bash
python app.py
```
Open <http://localhost:5000> for live visualization.

## Key results

- Bloom+SPIE traceability → **0%** (evidence wiped)
- Cuckoo+SPIE traceability → **~100%** (attacks preserved)
- Cuckoo+Parent-Pointer → **~97%**, with **ordered** path + **~42% fewer queries** than SPIE
- Scales cleanly from 6 to 50 switches with 99–100% accuracy

## References

- Bhondele, Rawat, Renukuntla (2015) — Network Management Framework for Network
  Forensic Analysis
- Sharma, Rawat (2023) — Optimizing Forensic Data Availability and Retention of
  SDN Forensic Logs using Bloom Filter
- Fan et al. (2014) — Cuckoo Filter: Practically Better Than Bloom
- Snoeren et al. (2001) — Hash-Based IP Traceback (SPIE)
=======
# Improving-SDN-Forensic-Data-Storage-using-cuckoo-filters
PG project exploring whether **Cuckoo Filters** can replace Bloom Filters in SDN forensic logging — fixing the catastrophic-wipe evidence-loss problem and enabling multi-strategy attack traceback.
