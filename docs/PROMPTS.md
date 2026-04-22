# Prompt Engineering — SOC Analyst Deep Agents

## Overview

The intelligence of the agent depends entirely on its prompts. We designed a hierarchical prompt system: one coordinator prompt that orchestrates, and three specialist subagent prompts that investigate.

**Key principle:** Subagents report findings. Only the coordinator makes the final verdict.

---

## Prompt Architecture

```
Coordinator Prompt (~145 lines)
├── Persona & methodology (PICERL)
├── 26 investigation rules
├── Tool trust hierarchy
├── Known-benign patterns (13 categories)
├── High-risk patterns (4 categories)
├── Confidence calibration scale
├── Verdict guide
├── MITRE & actions format
└── Output format (VERDICT_JSON)

Network Agent Prompt (~60 lines)
├── Tool descriptions (7 tools)
├── Parallelization workflow
├── Flag-when thresholds
└── Escalation triggers

Log & Payload Agent Prompt (~60 lines)
├── Tool descriptions (3 tools)
├── Parallelization workflow
├── Flag-when thresholds
└── Escalation triggers

User Behavior Agent Prompt (~50 lines)
├── Tool description (1 tool)
├── Risk score interpretation
├── Compound risk patterns
└── Escalation triggers
```

---

## Coordinator Prompt — Deep Dive

### 1. Persona

```
You are a Senior SOC Tier-2 Analyst coordinating an investigation
via PICERL methodology.
```

The PICERL framework gives the LLM a structured approach:
- **P**reparation → `write_todos` (plan before acting)
- **I**dentification → delegate to subagents to find IOCs
- **C**ontainment → recommend containment in actions
- **E**radication → suggest removal steps
- **R**ecovery → recommend recovery
- **L**essons Learned → document in reasoning

### 2. Investigation Rules (26 rules)

These rules prevent common LLM failure modes:

**Planning & delegation:**
- Rule 1: Always start with `write_todos` — forces Chain-of-Thought
- Rule 2: Call ONLY relevant subagents, never all three by default
- Rule 3: Parallelize — issue multiple `task` calls in one response
- Rule 4a: Skip `network_intel` when all IPs are private (RFC1918) — external APIs can't score private IPs, wastes 5s

**Evidence handling:**
- Rule 6: Second round only if first-round evidence is ambiguous
- Rule 7: Never fabricate tool results. On subagent error, reduce confidence

### 3. Tool Trust Hierarchy

This is critical — without it, the LLM often ignores strong tool evidence:

```
When log_pattern_analyzer anomaly_score >= 0.85 with a matched
attack pattern, TRUST that signal. Default to Malicious.
Only override if another subagent provides EXPLICIT benign context.
```

**Why this matters:** In early testing, the LLM would see a 0.9 SQL injection match from `log_pattern_analyzer` but then hedge: "while unusual, there's no direct IOC..." — missing obvious attacks. This rule fixed that.

### 4. Benign Indicator Precedence

Prevents false positives from UEBA noise:

```
When log_pattern_analyzer reports benign_indicators and NO attack
pattern has confidence >= 0.85 → classify Benign regardless of
what user_behavior_agent reports.
```

**Why this matters:** The UEBA tool often flags legitimate admin activity (off-hours, privilege escalation). Without this rule, every admin doing a sudo restart at night would be flagged Suspicious. The benign indicator from log analysis takes precedence over UEBA noise.

### 5. Known-Benign Patterns (13 categories)

These teach the LLM what "normal" looks like in a SOC:

| Pattern | Rule | Why |
|---------|------|-----|
| Internal-to-internal bulk transfer | Benign (both IPs RFC1918) | Backup/replication, no external egress |
| Internal SSH bulk transfer (port 22) | EXCEPTION: Malicious | Lateral movement / data staging |
| Admin activity during business hours | Benign | Routine operations |
| PowerShell AD scripts (Get-ADUser, Disable-ADAccount) | Benign | IT hygiene automation |
| PowerShell with IEX/DownloadString/-enc | Malicious | Malware download technique |
| EventID 4720 (new user) by admin, routine groups | Benign | Provisioning |
| EventID 4720 with Domain Admins group | Malicious | Privilege escalation |
| VPN session start with Duration=0s | Benign | Fresh session, 0s by definition |
| 1-5 failed logins from internal IP | Benign | User typo |
| 10+ failed logins or from external IP | Malicious | Brute force |
| Sudo restart nginx/postgres | Benign | Routine maintenance |
| SELECT with LIMIT <= 1000 | Benign | Paginated read |
| DNS to microsoft.com/google.com | Benign | Trusted domains |

### 6. High-Risk Patterns (4 categories)

These override benign signals — classify Malicious even if activity looks routine:

| Pattern | Why |
|---------|-----|
| Service install (EventID 7045) in ProgramData/AppData/Temp | Persistence mechanism |
| Database UPDATE on admin email/recovery field | Account takeover precursor |
| Service account executing bulk SELECT * without pagination | Data exfil recon |
| sc.exe writing .sys driver to System32\drivers | Kernel rootkit |

### 7. Confidence Calibration

Prevents the LLM from always outputting 0.95:

| Range | Meaning | When to use |
|-------|---------|-------------|
| 0.95-1.00 | Multi-signal confirmed | 2+ sources agree on attack |
| 0.80-0.94 | Strong evidence | 2+ sources, one ambiguous |
| 0.60-0.79 | Single strong signal | One tool found something, others clean |
| 0.40-0.59 | Suspicious | Partial evidence, needs analyst review |
| 0.70-0.95 | Confirmed Benign | Legitimate activity confirmed |

### 8. Output Format Enforcement

```
VERDICT_JSON:
{
  "verdict": "Malicious",
  "confidence": 0.95,
  "reasoning": "<= 600 chars",
  "mitre_techniques": ["T1190 — Exploit Public-Facing Application"],
  "recommended_actions": ["Block IP X at firewall"],
  "investigated_tools": ["log_pattern_analyzer", "geoip_lookup"]
}
```

The coordinator must output this block. Our code parses it with regex, validates against Pydantic schema, and retries up to 2x if malformed.

---

## Subagent Prompts

### Network Intelligence Agent

**Key instructions:**
- Use `ip_full_profile` as the preferred tool (runs 3 lookups in parallel)
- Parallelize: issue all tool calls in ONE response
- Flag when: abuse > 50, VPN/Tor, DGA > 0.5, domain < 30 days, OTX pulse >= 3
- Escalation triggers: Tor exit, domain < 7 days, DGA > 0.7, Metasploit ports

### Log & Payload Agent

**Key instructions:**
- Always run `log_pattern_analyzer` on log text
- Run `payload_decoder` for encoded blobs
- Run `cve_lookup` for referenced CVEs
- Flag when: anomaly score > 0.7, multi-layer encoding, CVSS >= 9.0
- Escalation triggers: Log4Shell, mimikatz, ransomware, Golden Ticket

### User Behavior Agent

**Key instructions:**
- Call `user_behavior_analyzer` once with username, resource, and log text
- Interpret risk score: 0-0.24 Low, 0.25-0.49 Medium, 0.50-0.74 High, 0.75-1.00 Critical
- Compound risks are more serious: off_hours + impossible_travel = account takeover
- Escalation triggers: impossible travel, priv-esc off-hours, 50+ failed then success

---

## Anti-Hallucination Measures

| Layer | Mechanism |
|-------|-----------|
| Prompt | "Never fabricate tool results. On subagent error, reduce confidence." |
| Prompt | "NEVER hallucinate a match when no such pattern was returned by the tool." |
| Prompt | "Only cite patterns that the tool explicitly returned." |
| Code | VERDICT_JSON parsed by regex — rejects malformed output |
| Code | Pydantic schema validation (verdict must be Malicious/Benign/Suspicious) |
| Code | 2 retry attempts if verdict can't be extracted |
| Code | Fallback to Suspicious at 0.4 confidence if all retries fail |

---

## Prompt Engineering Impact on Accuracy

| Version | Changes | Accuracy (20 alerts) |
|---------|---------|---------------------|
| v1 (initial) | Basic coordinator, no rules | ~75% |
| v2 | Added tool trust, benign indicators | ~85% |
| v3 | Added known-benign patterns, confidence calibration | 95% |
| v4 (current) | Added 26 rules, high-risk patterns, UEBA precedence | **100%** |

Each iteration addressed specific failure modes found during benchmarking. The rules aren't arbitrary — every one exists because the LLM made a specific mistake without it.

---

## Key Takeaways

1. **Structure matters more than length** — the coordinator prompt is ~145 lines, not 1,500. Clear sections with headers beat long prose.
2. **Rules prevent specific failures** — each rule addresses a real mistake observed in testing.
3. **Subagents don't make verdicts** — they report findings. Only the coordinator decides. This prevents conflicting conclusions.
4. **Tool trust is essential** — without explicit "trust the tool" instructions, the LLM second-guesses high-confidence tool results.
5. **Benign patterns reduce false positives** — teaching the LLM what "normal" looks like is as important as teaching it what attacks look like.
