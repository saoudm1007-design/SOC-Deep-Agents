"""
Parallel model comparison — runs the 20-alert benchmark across N models
simultaneously via subprocess, then aggregates results into a comparison table.

Usage:
    .venv/bin/python compare_models.py
"""
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

MODELS = [
    # Family champions (7)
    "google/gemini-2.5-flash-lite",
    "openai/gpt-oss-120b",
    "x-ai/grok-4.1-fast",
    "minimax/minimax-m2.5",
    "anthropic/claude-haiku-4.5",
    "qwen/qwen3-30b-a3b-instruct-2507",
    "cohere/command-r-08-2024",
    # Cross-family additions (5)
    "openai/gpt-5-nano",
    "meta-llama/llama-3.3-70b-instruct",
    "amazon/nova-lite-v1",
    "deepseek/deepseek-chat",
    "mistralai/mistral-small-3.2-24b-instruct",
    # Wildcards (4)
    "z-ai/glm-4.7-flash",
    "bytedance-seed/seed-1.6-flash",
    "anthropic/claude-3.5-haiku",
    "google/gemini-2.0-flash-lite-001",
    # Newest MiniMax
    "minimax/minimax-m2.7",
]

# OpenRouter per-1M-token pricing (fetched 2026-04-13)
PRICING = {
    "google/gemini-2.5-flash-lite":             {"in": 0.10,  "out": 0.40},
    "openai/gpt-oss-120b":                      {"in": 0.039, "out": 0.19},
    "x-ai/grok-4.1-fast":                       {"in": 0.20,  "out": 0.50},
    "minimax/minimax-m2.5":                     {"in": 0.118, "out": 0.99},
    "anthropic/claude-haiku-4.5":               {"in": 1.00,  "out": 5.00},
    "qwen/qwen3-30b-a3b-instruct-2507":         {"in": 0.09,  "out": 0.30},
    "cohere/command-r-08-2024":                 {"in": 0.15,  "out": 0.60},
    "openai/gpt-5-nano":                        {"in": 0.05,  "out": 0.40},
    "meta-llama/llama-3.3-70b-instruct":        {"in": 0.10,  "out": 0.32},
    "amazon/nova-lite-v1":                      {"in": 0.06,  "out": 0.24},
    "deepseek/deepseek-chat":                   {"in": 0.14,  "out": 0.28},
    "mistralai/mistral-small-3.2-24b-instruct": {"in": 0.075, "out": 0.20},
    "z-ai/glm-4.7-flash":                       {"in": 0.06,  "out": 0.40},
    "bytedance-seed/seed-1.6-flash":            {"in": 0.075, "out": 0.30},
    "anthropic/claude-3.5-haiku":               {"in": 0.80,  "out": 4.00},
    "google/gemini-2.0-flash-lite-001":         {"in": 0.075, "out": 0.30},
    "minimax/minimax-m2.7":                     {"in": 0.30,  "out": 1.20},
}

OUT_DIR = Path("benchmark_results/compare")
OUT_DIR.mkdir(parents=True, exist_ok=True)

WORKER_SCRIPT = r'''
import json, time, os, sys
from pathlib import Path
sys.path.insert(0, ".")
from models import AlertInput
from agent import run_agent, LAST_RUN_USAGE

alerts = json.load(open("tests/fixtures/sample_alerts.json"))
model = os.environ["OPENROUTER_MODEL"]
out_path = sys.argv[1]

results = []
t_run_start = time.time()
for i, a in enumerate(alerts, 1):
    try:
        alert = AlertInput.from_dict(a)
        t0 = time.perf_counter()
        v = run_agent(alert)
        elapsed = time.perf_counter() - t0
        usage = dict(LAST_RUN_USAGE)
        true_label = a["true_label"]
        # Suspicious counts as correct for Malicious alerts
        correct = (v.verdict == true_label) or (v.verdict == "Suspicious" and true_label == "Malicious")
        results.append({
            "id": a["id"], "true": true_label, "pred": v.verdict,
            "confidence": round(v.confidence, 3),
            "elapsed_s": round(elapsed, 2),
            "correct": correct,
            "input_tokens": usage.get("input", 0),
            "output_tokens": usage.get("output", 0),
            "cache_read": usage.get("cache_read", 0),
        })
        print(f"[{model}] [{i}/{len(alerts)}] {a['id']}: {v.verdict} ({elapsed:.1f}s)", flush=True)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        results.append({"id": a["id"], "true": a.get("true_label"), "error": err})
        print(f"[{model}] [{i}/{len(alerts)}] {a['id']}: ERROR {err}", flush=True)

total_time = time.time() - t_run_start
json.dump({
    "model": model,
    "total_wall_time_s": round(total_time, 2),
    "results": results,
}, open(out_path, "w"), indent=2)
'''


def _safe(model: str) -> str:
    return model.replace("/", "_")


def run_model(model: str) -> dict:
    safe = _safe(model)
    log_path  = OUT_DIR / f"{safe}.log"
    json_path = OUT_DIR / f"{safe}.json"

    env = os.environ.copy()
    env["OPENROUTER_MODEL"] = model

    with open(log_path, "w") as logf:
        proc = subprocess.Popen(
            [".venv/bin/python", "-c", WORKER_SCRIPT, str(json_path)],
            env=env,
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
        rc = proc.wait()

    if json_path.exists():
        return json.loads(json_path.read_text())
    return {
        "model": model,
        "total_wall_time_s": None,
        "results": [],
        "fatal_error": f"Worker exited rc={rc}; see {log_path}",
    }


def _summarize(run: dict) -> dict:
    model = run["model"]
    results = run["results"]
    completed = [r for r in results if "error" not in r]
    errors    = [r for r in results if "error" in r]
    correct   = sum(1 for r in completed if r.get("correct"))
    total     = len(results)

    # Exclude near-zero elapsed from latency avg
    llm_latencies = [r["elapsed_s"] for r in completed if r["elapsed_s"] > 0.5]
    avg_lat = sum(llm_latencies) / len(llm_latencies) if llm_latencies else 0.0

    total_in  = sum(r.get("input_tokens", 0)  for r in completed)
    total_out = sum(r.get("output_tokens", 0) for r in completed)

    price = PRICING.get(model, {"in": 0, "out": 0})
    cost  = (total_in / 1_000_000) * price["in"] + (total_out / 1_000_000) * price["out"]

    return {
        "model":       model,
        "completed":   len(completed),
        "errors":      len(errors),
        "total":       total,
        "correct":     correct,
        "accuracy":    correct / total if total else 0,
        "avg_lat_s":   avg_lat,
        "wall_time_s": run.get("total_wall_time_s") or 0,
        "tokens_in":   total_in,
        "tokens_out":  total_out,
        "cost_usd":    cost,
    }


def print_table(summaries: list[dict]):
    summaries = sorted(summaries, key=lambda s: (-s["accuracy"], s["avg_lat_s"] or 9e9))
    print("\n" + "=" * 108)
    print(f"{'Model':<42} {'Acc':>10} {'AvgLat':>9} {'Wall':>8} {'Tok in/out':>16} {'Cost':>9}  Err")
    print("-" * 108)
    for s in summaries:
        acc_str = f"{s['correct']:>2}/{s['total']:<2} {s['accuracy']*100:>4.0f}%"
        lat_str = f"{s['avg_lat_s']:.1f}s" if s["avg_lat_s"] else "-"
        wall    = f"{s['wall_time_s']:.0f}s"
        toks    = f"{s['tokens_in']//1000}k/{s['tokens_out']//1000}k"
        cost    = f"${s['cost_usd']:.4f}"
        err     = str(s["errors"]) if s["errors"] else ""
        print(f"{s['model']:<42} {acc_str:>10} {lat_str:>9} {wall:>8} {toks:>16} {cost:>9}  {err}")
    print("=" * 108)


def main():
    print(f"Launching {len(MODELS)} models in parallel...")
    print(f"Logs: {OUT_DIR}/<model>.log")
    print()

    start = time.time()
    runs = []
    with ThreadPoolExecutor(max_workers=len(MODELS)) as pool:
        futures = {pool.submit(run_model, m): m for m in MODELS}
        for f in as_completed(futures):
            model = futures[f]
            try:
                run = f.result()
                runs.append(run)
                errors = sum(1 for r in run.get("results", []) if "error" in r)
                print(f"  ✓ {model:<42}  "
                      f"{len(run.get('results', []))} alerts  "
                      f"{run.get('total_wall_time_s', '?')}s  "
                      f"{errors} errors")
            except Exception as e:
                print(f"  ✗ {model}: FATAL {e}")
                runs.append({"model": model, "total_wall_time_s": None, "results": []})

    total_wall = time.time() - start
    print(f"\nTotal wall-clock time: {total_wall:.0f}s")

    summaries = [_summarize(r) for r in runs]
    print_table(summaries)

    # Save aggregated JSON
    agg_path = OUT_DIR / "comparison_summary.json"
    agg_path.write_text(json.dumps(summaries, indent=2))
    print(f"\nAggregated summary → {agg_path}")


if __name__ == "__main__":
    main()
