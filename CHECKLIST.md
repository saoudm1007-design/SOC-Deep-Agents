# SOC Analyst Agent (Deep Agents) — Build Checklist

Track progress here. Check off each item as we complete it together.

---

## Milestone 1 — Project Foundation

- [x] Create `soc-agent/` folder structure
- [x] Create `requirements.txt`
- [x] Create `.env` with OpenRouter key + `.env.example`
- [x] Create `.gitignore`
- [x] Implement `config.py` (pydantic-settings, OpenRouter + Anthropic + Ollama)
- [x] Implement `models.py` (AlertInput, VerdictOutput, ToolResult)
- [x] Verify: `from config import settings` works

---

## Milestone 2 — All 10 Tools + Unit Tests ✅

- [x] Implement `tools/ip_reputation.py` (AbuseIPDB + VirusTotal + diskcache)
- [x] Implement `tools/geoip.py` (ip-api.com, no key needed)
- [x] Implement `tools/dns_lookup.py` (dnspython + DGA heuristic + tunnel score)
- [x] Implement `tools/whois_lookup.py` (domain age, new domain flags)
- [x] Implement `tools/threat_intel.py` (AlienVault OTX, free API)
- [x] Implement `tools/network_traffic.py` (volume + timing exfil detection)
- [x] Implement `tools/log_pattern.py` (40+ MITRE ATT&CK regex patterns)
- [x] Implement `tools/payload_decoder.py` (base64/URL/hex/gzip + IOC extraction)
- [x] Implement `tools/cve_lookup.py` (NVD API + 6 pre-cached critical CVEs)
- [x] Implement `tools/user_behavior.py` (stateless risk scorer, 10 signals)
- [x] Write `tests/test_tools.py` (52 tests)
- [x] Verify: **52/52 tests pass** ✅

---

## Milestone 3 — Prompt Engineering ✅

- [x] Write coordinator system prompt (PICERL persona + confidence calibration + output schema)
- [x] Write network subagent prompt (6 tools + escalation triggers + response format)
- [x] Write log & payload subagent prompt (3 tools + escalation triggers + response format)
- [x] Write user behavior subagent prompt (UEBA + compound risks + response format)
- [x] VerdictOutput schema validated (verdict/confidence/reasoning/mitre/actions/tools)
- [x] Verify: **39/39 prompt tests pass** ✅

---

## Milestone 4 — Subagents & Coordinator Agent ✅

- [x] Implement `tool_registry.py` (10 @tool wrappers, NETWORK/LOG/USER tool lists)
- [x] Implement `subagents.py` (3 SubAgent TypedDicts: network, log, user)
- [x] Implement `agent.py` (create_deep_agent + coordinator — pure agentic, no hardcoded rules)
- [x] Implement `run_agent()` + `run_agent_stream()` entry points
- [x] Write `tests/test_agent.py` (agent build, registry, subagents)
- [x] Verify: **15/15 offline tests pass, 3 LLM tests skipped** ✅

---

## Milestone 5 — Chainlit Dashboard ✅

- [x] Implement `dashboard.py` Chainlit app
- [x] Stream agent reasoning trace (thought/tool_call/tool_result steps)
- [x] Stream subagent delegation steps (collapsible per subagent)
- [x] Build verdict card (🔴🟡🟢 badge + █░ confidence bar + reasoning + MITRE + actions)
- [x] Add model selector (OpenRouter dropdown + custom model text field)
- [x] Add JSON + CSV + plain text + file upload input support
- [x] Add batch mode with summary table
- [x] Write `tests/test_dashboard.py` (27 tests: parsing + rendering)
- [x] Verify: **27/27 tests pass** ✅

---

## Milestone 6 — Testing & Optimization 🔄

- [x] Write `benchmark.py` (accuracy + latency + CSV cost log)
- [x] Fix checkpointer=True → MemorySaver()
- [x] Fix event key `agent` → `model` (deepagents 0.5.2 API)
- [x] Fix response_format → VERDICT_JSON text extraction
- [x] Switch model: gemini-3.1-flash-lite → gemini-2.5-flash (2.5× faster)
- [x] Fix Benign confidence calibration in coordinator prompt
- [x] Run all 20 alerts: **100% accuracy (20/20), avg 11.5s** ✅
- [x] Cost tracking CSV saved to `benchmark_results/` ✅

---

## Milestone 7 — Edge Cases & Hardening ✅

- [x] Handle private/RFC1918 IPs (skip external API calls)
- [x] Handle IPv6 addresses
- [x] Handle missing alert fields (all Optional in AlertInput)
- [x] Handle malformed JSON input gracefully
- [x] Add tool fallback responses when APIs are down
- [x] Verify: no crashes on any malformed alert (`tests/test_edge_cases.py`, **34/34 pass**) ✅

---

## Milestone 8 — Demo Preparation ✅

- [x] Prepare demo scenario 1: SQL Injection (`demo/scenarios/01_sql_injection.json`)
- [x] Prepare demo scenario 2: Obfuscated PowerShell (`demo/scenarios/02_obfuscated_powershell.json`)
- [x] Prepare demo scenario 3: Benign System Update (`demo/scenarios/03_benign_system_update.json`)
- [x] Prepare demo scenario 4: C2 Beacon (`demo/scenarios/04_c2_beacon.json`)
- [x] Create `demo/run_demo.py` terminal runner (colourised, summary table)
- [x] Verify: all 4 demo scenarios pass end-to-end — **4/4 (100%), avg 26.2s** ✅

---

## Milestone 9 — Paper ✅

- [x] Write Abstract (`paper/paper.md`)
- [x] Write Methodology section (ASCII agent architecture diagram + tool table + schema)
- [x] Write Results section (accuracy table + failure analysis)
- [x] Write Conclusion (limitations: stateless UEBA, API dep, benchmark size; future: memory subagent, Claude cache, SOAR, maintenance windows)
- [x] Create architecture diagram (ASCII, renders in markdown + PDF export)
- [x] Reproducibility appendix with `make` targets

---

## Milestone 10 — Final Submission 🔄

- [x] Complete `README.md` (setup, architecture, API key config, layout, benchmark summary)
- [x] Complete `Makefile` (install, test, test-tools, test-agent, test-edge, demo, benchmark, run, clean)
- [x] Full test suite green — **183 passed, 3 skipped** ✅
- [ ] Final paper PDF exported (from `paper/paper.md`)
- [ ] Clean code, meaningful commits
- [ ] Submit codebase
- [ ] Live demo presentation

---

## Bonus Goals ✅

- [x] Claude prompt caching — anthropic-beta `prompt-caching-2024-07-31` header attached in `agent._build_llm()` when OpenRouter model starts with `anthropic/`
- [x] MITRE coverage: T1110, T1078, T1059, T1190, T1105, T1041 (all 6 present in `log_pattern.py`, verified by `tests/test_bonus.py`)
- [x] Cost tracker CSV — per-investigation token columns (input/output/cache_read/cache_creation) in `benchmark_YYYYMMDD.csv`; summary totals in `cost_log.csv`
- [x] "Suspicious" third verdict fully handled — schema, prompt, coordinator output parsing, `benchmark._CORRECT_MAP`, and dashboard all support it
- [x] Verify: **15/15 bonus tests pass**, full suite **183 passed, 3 skipped** ✅
