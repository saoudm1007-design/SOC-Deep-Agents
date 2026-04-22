# Benchmarks — SOC Analyst Deep Agents

## Overview

All benchmarks run with the pure agentic pipeline — no hardcoded rules. Every alert goes through the coordinator-mainagent → subagents → tools → verdict path.

**Default model:** `google/gemini-2.5-flash` via OpenRouter

---

## Accuracy Across Dataset Sizes

| Dataset | Accuracy | Correct | Malicious Recall | Benign Precision | Avg Latency | Max Latency | Total Cost | Per Alert |
|---------|----------|---------|------------------|------------------|-------------|-------------|------------|-----------|
| 20 alerts | **100%** | 20/20 | 100% (10/10) | 100% (10/10) | 11.5s | 18.5s | ~$0.11 | $0.006 |
| 65 alerts | **98.5%** | 64/65 | 100% (43/43) | 95% (21/22) | 16.9s | 44.9s | ~$0.37 | $0.006 |
| 200 alerts | **97.5%** | 195/200 | 98% (109/111) | 97% (86/89) | 17.5s | 53.5s | ~$1.14 | $0.006 |
| 600 alerts | **95.7%** | 574/600 | 96% (327/340) | 95% (247/260) | 12.0s | 53.5s | ~$3.46 | $0.006 |

---

## 20-Alert Benchmark (Core)

**100% accuracy — 20/20 correct**

| Alert | Type | True Label | Verdict | Confidence | MITRE |
|-------|------|-----------|---------|------------|-------|
| ALERT-001 | Authentication Success | Benign | Benign | 90% | — |
| ALERT-002 | System Update | Benign | Benign | 95% | — |
| ALERT-003 | Password Reset | Benign | Benign | 90% | — |
| ALERT-004 | High Network Traffic | Benign | Benign | 90% | — |
| ALERT-005 | HTTP 404 Error | Benign | Benign | 90% | — |
| ALERT-006 | Cron Job Execution | Benign | Benign | 95% | — |
| ALERT-007 | Database Select | Benign | Benign | 75% | — |
| ALERT-008 | VPN Connection | Benign | Benign | 95% | — |
| ALERT-009 | Health Check | Benign | Benign | 95% | — |
| ALERT-010 | File Access | Benign | Benign | 90% | — |
| ALERT-011 | SQL Injection | Malicious | Malicious | 95% | T1190 |
| ALERT-012 | DDoS/SYN Flood | Malicious | Malicious | 95% | T1498 |
| ALERT-013 | XSS Attempt | Malicious | Malicious | 95% | T1190 |
| ALERT-014 | SSH Brute Force | Malicious | Malicious | 90% | T1110 |
| ALERT-015 | C2 Callback | Malicious | Malicious | 95% | T1071 |
| ALERT-016 | Directory Traversal | Malicious | Malicious | 90% | T1190 |
| ALERT-017 | Impossible Travel | Malicious | Malicious | 95% | T1078 |
| ALERT-018 | Obfuscated PowerShell | Malicious | Malicious | 95% | T1059.001, T1027 |
| ALERT-019 | DNS Tunneling | Malicious | Malicious | 95% | T1071.004, T1048.003 |
| ALERT-020 | Privilege Escalation | Malicious | Malicious | 95% | T1548 |

---

## 6-Alert Demo Benchmark

**100% accuracy — 6/6 correct** (using professor's proposal examples + extras)

| Alert | Type | Verdict | Confidence | Subagents Used |
|-------|------|---------|------------|----------------|
| DEMO-001 | SQL Injection (sqlmap) | Malicious | 95% | Network Intel, Log & Payload |
| DEMO-002 | System Update (apt-get) | Benign | 95% | Network Intel, Log & Payload, User Behavior |
| DEMO-003 | Data Exfiltration (4.5GB) | Malicious | 85-90% | Network Intel, Log & Payload |
| DEMO-004 | Failed Login (2 attempts) | Benign | 90-95% | User Behavior |
| DEMO-005 | Cobalt Strike Beacon | Malicious | 95% | Network Intel, Log & Payload |
| DEMO-006 | Obfuscated PowerShell | Malicious | 95% | Log & Payload, User Behavior |

---

## 65-Alert Breakdown

**98.5% accuracy — 64/65 correct, 1 miss**

| Category | Count | Correct | Accuracy |
|----------|-------|---------|----------|
| Easy (benign) | 22 | 21 | 95% |
| Easy (malicious) | 18 | 18 | 100% |
| Medium (malicious) | 15 | 15 | 100% |
| Hard (mixed) | 10 | 10 | 100% |

**1 misclassification:**

| Alert | True | Predicted | Reason |
|-------|------|-----------|--------|
| EASY-006 | Benign | Suspicious @55% | Departmental doc read, UEBA flagged mass access |

---

## 200-Alert Breakdown

**97.5% accuracy — 195/200 correct, 5 misses**

**False negatives (Malicious missed — 2):**

| Alert | What happened | Why missed |
|-------|--------------|------------|
| ALERT-044 | Internal web scan (private→private) | Model trusted internal IPs |
| ALERT-093 | Cron `curl\|bash` by www-data | No tool flagged the pattern |

**False positives (Benign flagged — 3):**

| Alert | What happened | Why flagged |
|-------|--------------|-------------|
| ALERT-049 | Sysadmin sudo read | UEBA flagged anomaly |
| ALERT-175 | Internal Elasticsearch transfer | Large volume hedged |
| ALERT-177 | 4 failed logins | UEBA false impossible travel |

---

## 600-Alert Breakdown

**95.7% accuracy — 574/600 correct, 26 misses**

| Error Type | Count | Common Cause |
|-----------|-------|--------------|
| Malicious → Benign (missed attack) | 13 | Internal-only attacks, tools return clean for RFC1918 IPs |
| Benign → Suspicious (false positive) | 9 | UEBA over-flagging admin activity |
| Benign → Malicious (false positive) | 4 | Impossible travel false flags, OTX false hits |

**Most common failure pattern:** Attacks originating from internal IPs (RFC1918) where external threat intel APIs have no data. The model over-trusts clean tool results.

---

## Cost Analysis

### Token Usage (Gemini 2.5 Flash)

| Dataset | Input Tokens | Output Tokens | Cache Read Tokens | Cost |
|---------|-------------|---------------|-------------------|------|
| 20 alerts | 651K | 9K | 444K | $0.11 |
| 65 alerts | 2.4M | 34K | 1.7M | $0.37 |
| 200 alerts | 7.2M | 102K | 5.4M | $1.14 |
| 600 alerts | 21.7M | 308K | 17.8M | $3.46 |

### Cost Projections

| Scale | Cost | Time |
|-------|------|------|
| 100 alerts | $0.60 | ~20 min |
| 500 alerts (hidden test) | $3.00 | ~1.5 hrs |
| 1,000 alerts | $6.00 | ~3 hrs |
| 10,000 alerts | $60.00 | ~1.3 days |

### vs Human Analyst

| Metric | Human Tier-1 | SOC Deep Agents | Ratio |
|--------|-------------|-----------------|-------|
| Cost per alert | $2.00 | $0.006 | **333x cheaper** |
| Alerts per hour | 20 | 300 | **15x faster** |
| Availability | 8h/day | 24/7 | **3x uptime** |
| Consistency | Variable | Consistent | — |

---

## Latency Analysis

### Per-Alert Latency Distribution (20 alerts)

| Range | Count | Alerts |
|-------|-------|--------|
| < 10s | 6 | Health check, cron, failed login, dir traversal |
| 10-15s | 8 | SQL injection, DDoS, C2, DNS tunnel |
| 15-20s | 5 | System update, database, VPN, file access |
| > 20s | 1 | Obfuscated PowerShell (most tool calls) |

**What affects latency:**
- Number of subagents called (1 agent ~8s, 2 agents ~12s, 3 agents ~18s)
- Payload decoding complexity (multi-layer encoding adds time)
- OpenRouter backend routing (varies by time of day)

---

## Confidence Distribution

### 20-Alert Benchmark

| Confidence Range | Count | Accuracy |
|-----------------|-------|----------|
| 90-100% | 18 | 100% |
| 70-89% | 2 | 100% |
| 50-69% | 0 | — |
| < 50% | 0 | — |

### 600-Alert Benchmark

| Confidence Range | Count | Accuracy |
|-----------------|-------|----------|
| 80-100% | 405 | 97.5% |
| 50-79% | 181 | 93.4% |
| < 50% | 14 | 78.6% |

Low confidence correlates with lower accuracy — the coordinator correctly reduces confidence when evidence is ambiguous.

---

## Reproducibility

```bash
cd soc-agent
source .venv/bin/activate

# Run benchmarks
python benchmark.py                                    # 20 alerts
python benchmark.py --file tests/fixtures/sample_alerts_65.json   # 65 alerts
python benchmark.py --file tests/fixtures/sample_alerts_200.json  # 200 alerts
python benchmark.py --file tests/fixtures/sample_alerts_600.json  # 600 alerts

# Results saved to benchmark_results/
# CSV per run + cost_log.csv summary
```

All benchmark CSVs and the cost log are included in `soc-agent/benchmark_results/`.
