# Installation Guide — SOC Analyst Deep Agents

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Git

---

## Step 1: Clone the Repository

```bash
git clone <repository-url>
cd soc-agent
```

---

## Step 2: Create Virtual Environment & Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/Mac
# .venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

---

## Step 3: Configure API Keys

### 3.1 Create the .env file

```bash
cp .env.example .env
```

### 3.2 Add your OpenRouter API Key

1. Go to https://openrouter.ai and create a free account
2. Go to https://openrouter.ai/keys and create a new API key
3. Open the `.env` file and paste your key:

```
MODEL_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=google/gemini-2.5-flash
```

### 3.3 Optional API Keys (improve accuracy but not required)

These keys enhance tool results. Without them, the tools degrade gracefully:

```
ABUSEIPDB_API_KEY=           # https://www.abuseipdb.com/account/api (free)
VIRUSTOTAL_API_KEY=          # https://www.virustotal.com/gui/my-apikey (free)
NVD_API_KEY=                 # https://nvd.nist.gov/developers/request-an-api-key (free)
```

---

## Step 4 (Optional): Install Ollama for Local LLM

If you want to run models locally without an API key:

### 4.1 Install Ollama

```bash
# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Mac
brew install ollama

# Windows
# Download from https://ollama.com/download
```

### 4.2 Pull a Model

```bash
ollama pull llama3.1          # 8B parameters, ~4.7GB
# Other options:
# ollama pull llama3.2        # Smaller, faster
# ollama pull mistral         # Good for reasoning
# ollama pull qwen2.5         # Multilingual
# ollama pull deepseek-r1     # Strong reasoning
# ollama pull gemma2          # Google's open model
```

### 4.3 Start Ollama

```bash
ollama serve
```

Ollama runs on `http://localhost:11434` by default. The dashboard will automatically connect to it when you select a local model.

### 4.4 Configure .env for Ollama (optional)

If you want Ollama as the default provider instead of OpenRouter:

```
MODEL_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

---

## Step 5: Verify Installation

```bash
# Run the test suite (no API key needed for most tests)
make test

# Expected output: 183 passed, 3 skipped
```

---

## Step 6: Launch the Dashboard

```bash
make run
# or
chainlit run dashboard.py --port 8008
```

Open http://localhost:8008 in your browser.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Make sure the virtual environment is activated: `source .venv/bin/activate` |
| `OPENROUTER_API_KEY not set` | Check your `.env` file has the key, no spaces around `=` |
| `Connection refused (Ollama)` | Run `ollama serve` in a separate terminal |
| `Model not found (Ollama)` | Pull the model first: `ollama pull llama3.1` |
| `Rate limit exceeded` | OpenRouter free tier has rate limits. Wait a minute and retry |
| `504 Gateway Timeout` | OpenRouter backend is slow. Try again or switch models |

---

## Project Structure

```
soc-agent/
├── .env.example         # Copy this to .env and add your API keys
├── .env                 # Your API keys (never commit this)
├── agent.py             # Coordinator-mainagent
├── dashboard.py         # Chainlit web UI
├── benchmark.py         # Accuracy + latency + cost tracker
├── Makefile             # make install/test/run/demo/benchmark
├── requirements.txt     # Python dependencies
└── ...
```
