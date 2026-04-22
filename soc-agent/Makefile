.PHONY: help install test test-tools test-agent test-edge demo benchmark run clean

VENV ?= .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

help:
	@echo "SOC Analyst Deep Agents — make targets"
	@echo ""
	@echo "  make install     Create .venv and install requirements.txt"
	@echo "  make test        Run full test suite (tools + prompts + agent + dashboard + edge cases)"
	@echo "  make test-tools  Run tool unit tests only"
	@echo "  make test-agent  Run agent integration tests only"
	@echo "  make test-edge   Run Milestone 7 edge-case tests only"
	@echo "  make demo        Run 4 canonical demo scenarios end-to-end"
	@echo "  make benchmark   Run 20-alert benchmark → benchmark_results/*.csv"
	@echo "  make run         Launch Chainlit dashboard (http://localhost:8008)"
	@echo "  make clean       Remove caches and build artefacts"

install:
	python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo ""
	@echo "✓ Install complete. Next: cp .env.example .env and add your OpenRouter key."

test:
	$(PY) -m pytest tests/ -v

test-tools:
	$(PY) -m pytest tests/test_tools.py -v

test-agent:
	$(PY) -m pytest tests/test_agent.py -v

test-edge:
	$(PY) -m pytest tests/test_edge_cases.py -v

demo:
	$(PY) demo/run_demo.py

benchmark:
	$(PY) benchmark.py

run:
	$(VENV)/bin/chainlit run dashboard.py --port 8008

clean:
	rm -rf .cache .pytest_cache __pycache__ */__pycache__ */*/__pycache__
	rm -rf .chainlit .files
	@echo "✓ Cleaned caches."
