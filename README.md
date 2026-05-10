# Improving SDN Forensic Data Storage using Cuckoo Filters

PG Project — IIIT Hyderabad, April 2026

**Authors:** Kuldeep Kumar Lakhe, Atharva Keskar, Dheeraj Makhija
**Guide:** Prof. Shatrunjay Rawat

---

## Problem

Bloom Filters are used to compress SDN forensic logs (1024 GB → 52 MB), but they
**cannot delete individual entries**. When a Bloom Filter fills up, it must be
completely wiped — destroying all stored forensic evidence. This is a disaster for
network forensic investigations.

## Solution

We replace Bloom Filters with **Cuckoo Filters** and introduce three key innovations:

1. **Attack-Aware Sliding Window** — selectively deletes only oldest benign entries,
   never attack evidence (achieves 96% traceability vs Bloom's 2%).
2. **Forensic Filter Manager (Snapshot + Reset)** — instead of deleting anything,
   archives full filters to disk as immutable snapshots. Achieves **100% traceability**
   with zero deletions — fully forensically sound.
3. **Parent-Pointer Traceback** — each switch stores which upstream switch forwarded
   the packet. The SDN controller walks backward to reconstruct the **ordered** attack
   path in O(path length) queries, not O(N switches).

## Project Files

| File | Purpose |
|------|---------|
| `bloom_filter.py` | Bloom Filter with catastrophic wipe on overflow |
| `cuckoo_filter.py` | Cuckoo Filter with attack-aware sliding window + parent-pointer |
| `forensic_filter_manager.py` | Snapshot + Reset model — immutable forensic archival |
| `network_simulator.py` | SDN topology (linear + tree), SoftSwitch, SDNController |
| `analysis.py` | Offline experiment: Bloom vs Cuckoo (produces `results.png`) |
| `network_analysis.py` | Network experiment: 3 traceback strategies + scalability (produces `results_network.png`, `results_scalability.png`) |
| `enhanced_analysis.py` | Enhanced analysis: 3-way comparison, tree topology, multi-attack, fingerprint sweep (produces `results_enhanced.png`) |
| `report.tex` | LaTeX project report (compile on Overleaf) |

## Setup

```bash
pip install -r requirements.txt
```

The CIC-IDS2017 Tuesday CSV must exist at:
`MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv`

## How to Run

### 1. Bloom Filter — shows the wipe problem
```bash
python bloom_filter.py
```

### 2. Cuckoo Filter — shows selective deletion
```bash
python cuckoo_filter.py
```

### 3. Forensic Filter Manager — shows immutable archival
```bash
python forensic_filter_manager.py
```

### 4. Network simulator — shows SDN traceback
```bash
python network_simulator.py
```

### 5. Offline experiment — Bloom vs Cuckoo
```bash
python analysis.py
```

### 6. Network experiment — full SDN traceback + scalability
```bash
python network_analysis.py
```

### 7. Enhanced analysis — all guide feedback addressed
```bash
python enhanced_analysis.py
```

## Key Results

| Metric | Bloom | Cuckoo (Delete) | Snapshot+Reset |
|--------|:-----:|:----------------:|:--------------:|
| Traceability (of 100) | 2 | 96 | **100** |
| Evidence wipes | 4 | 0 | **0** |
| Deletions | N/A | 41,000 | **0** |
| Forensically sound? | NO | NO | **YES** |

### Network Traceback (6-switch linear topology)

| Strategy | Success | Perfect Path |
|----------|:-------:|:------------:|
| Bloom + SPIE | 0/100 | 0/100 |
| Cuckoo + SPIE | 100/100 | 79/100 |
| Cuckoo + Parent-Pointer | 97/100 | **79/100 (ordered)** |

### Tree Topology with Multiple Attacks (7-switch tree)

| Strategy | Success |
|----------|:-------:|
| Bloom + SPIE | 1/100 |
| Cuckoo + Parent-Pointer | **100/100** |

### Fingerprint Size Cost-Benefit

All fingerprint sizes achieve 100% traceability with Snapshot+Reset.
Sweet spot: 12-bit (4× lower FPR at only +20% memory).

## Dataset

CIC-IDS2017 (Canadian Institute for Cybersecurity, UNB)
- Tuesday working hours: 50,000 records
- Contains FTP-Patator brute-force attacks
- 44,807 benign + 5,193 attack flows

## References

- Bhondele, Rawat, Renukuntla (2015) — Network Management Framework for Network Forensic Analysis
- Sharma, Rawat (2023) — Optimizing Forensic Data Availability and Retention of SDN Forensic Logs using Bloom Filter
- Fan et al. (2014) — Cuckoo Filter: Practically Better Than Bloom
- Snoeren et al. (2001) — Hash-Based IP Traceback (SPIE)
- Sharafaldin et al. (2018) — CIC-IDS2017 Dataset
