"""
SOC Agent Benchmark — runs all alerts in sample_alerts.json through the agent
and measures accuracy, latency, and verdict distribution.

Usage:
    cd soc-agent
    source .venv/bin/activate
    python benchmark.py                              # runs all 20 alerts
    python benchmark.py --file tests/fixtures/sample_alerts.json
    python benchmark.py --limit 5                   # first 5 only (quick smoke test)
    python benchmark.py --ids ALERT-011 ALERT-018   # specific alerts
"""
import json
import time
import csv
import argparse
import sys
import os
from datetime import datetime
from pathlib import Path

from models import AlertInput, VerdictOutput
from agent import run_agent, LAST_RUN_USAGE

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_ALERTS = Path(__file__).parent / "tests" / "fixtures" / "sample_alerts.json"
RESULTS_DIR    = Path(__file__).parent / "benchmark_results"

# True labels for scoring (verdict that matches the true_label wins)
# "Suspicious" counts as correct for Malicious alerts (conservative catch)
_CORRECT_MAP = {
    "Malicious": {"Malicious", "Suspicious"},
    "Benign":    {"Benign"},
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_alerts(path: Path, limit: int | None, ids: list[str] | None) -> list[dict]:
    with open(path) as f:
        alerts = json.load(f)
    if ids:
        alerts = [a for a in alerts if a.get("id") in ids]
    if limit:
        alerts = alerts[:limit]
    return alerts


def _verdict_correct(predicted: str, true_label: str) -> bool:
    return predicted in _CORRECT_MAP.get(true_label, {predicted})


def _color(text: str, code: str) -> str:
    """ANSI color codes for terminal output."""
    codes = {"green": "32", "red": "31", "yellow": "33", "cyan": "36", "bold": "1"}
    return f"\033[{codes.get(code, '0')}m{text}\033[0m"


def _bar(value: float, width: int = 20) -> str:
    filled = round(value * width)
    return "█" * filled + "░" * (width - filled)


# ── Single alert run ──────────────────────────────────────────────────────────

def run_single(alert_dict: dict, idx: int, total: int) -> dict:
    alert_id   = alert_dict.get("id", f"ALERT-{idx:03d}")
    true_label = alert_dict.get("true_label", "Unknown")

    print(f"\n[{idx}/{total}] {_color(alert_id, 'cyan')} — {alert_dict.get('event_type', '')} "
          f"(true: {_color(true_label, 'bold')})")
    print(f"  Log: {str(alert_dict.get('raw_log', ''))[:100]}...")

    alert = AlertInput.from_dict(alert_dict)

    t0 = time.perf_counter()
    verdict: VerdictOutput = run_agent(alert)
    elapsed = round(time.perf_counter() - t0, 2)
    usage = dict(LAST_RUN_USAGE)  # snapshot before next run clears it

    correct = _verdict_correct(verdict.verdict, true_label)
    color   = "green" if correct else "red"
    mark    = "✅" if correct else "❌"

    print(f"  {mark} Predicted: {_color(verdict.verdict, color)} "
          f"({verdict.confidence:.0%} conf) in {elapsed}s")
    print(f"     Reasoning: {verdict.reasoning[:120]}...")
    if verdict.mitre_techniques:
        print(f"     MITRE: {', '.join(verdict.mitre_techniques[:3])}")

    return {
        "alert_id":          alert_id,
        "event_type":        alert_dict.get("event_type", ""),
        "true_label":        true_label,
        "predicted_verdict": verdict.verdict,
        "confidence":        round(verdict.confidence, 3),
        "correct":           correct,
        "latency_s":         elapsed,
        "reasoning":         verdict.reasoning[:300],
        "mitre_techniques":  "; ".join(verdict.mitre_techniques),
        "recommended_actions": "; ".join(verdict.recommended_actions[:3]),
        "investigated_tools":  "; ".join(verdict.investigated_tools),
        "input_tokens":       usage.get("input", 0),
        "output_tokens":      usage.get("output", 0),
        "cache_read_tokens":  usage.get("cache_read", 0),
        "cache_creation_tokens": usage.get("cache_creation", 0),
        "timestamp":         datetime.utcnow().isoformat(),
    }


# ── Benchmark runner ──────────────────────────────────────────────────────────

def run_benchmark(alerts: list[dict]) -> list[dict]:
    results = []
    total   = len(alerts)

    print(_color(f"\n{'='*60}", "bold"))
    print(_color(f"  SOC Agent Benchmark — {total} alerts", "bold"))
    print(_color(f"{'='*60}", "bold"))

    for i, alert_dict in enumerate(alerts, 1):
        try:
            row = run_single(alert_dict, i, total)
        except Exception as e:
            alert_id = alert_dict.get("id", f"ALERT-{i:03d}")
            print(f"  ❌ ERROR on {alert_id}: {e}")
            row = {
                "alert_id": alert_id,
                "event_type": alert_dict.get("event_type", ""),
                "true_label": alert_dict.get("true_label", "Unknown"),
                "predicted_verdict": "ERROR",
                "confidence": 0.0,
                "correct": False,
                "latency_s": 0.0,
                "reasoning": str(e)[:300],
                "mitre_techniques": "",
                "recommended_actions": "",
                "investigated_tools": "",
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_tokens": 0,
                "cache_creation_tokens": 0,
                "timestamp": datetime.utcnow().isoformat(),
            }
        results.append(row)

    return results


# ── Summary report ────────────────────────────────────────────────────────────

def print_summary(results: list[dict]):
    total     = len(results)
    correct   = sum(1 for r in results if r["correct"])
    accuracy  = correct / total if total else 0

    latencies = [r["latency_s"] for r in results if r["latency_s"] > 0]
    avg_lat   = sum(latencies) / len(latencies) if latencies else 0
    max_lat   = max(latencies) if latencies else 0

    # Per-class breakdown
    classes   = ["Malicious", "Benign", "Suspicious"]
    class_stats = {}
    for cls in classes:
        subset  = [r for r in results if r["true_label"] == cls]
        if subset:
            hits = sum(1 for r in subset if r["correct"])
            class_stats[cls] = (hits, len(subset))

    # Confidence distribution
    high_conf  = sum(1 for r in results if r["confidence"] >= 0.8)
    low_conf   = sum(1 for r in results if r["confidence"] < 0.5)

    print(_color(f"\n{'='*60}", "bold"))
    print(_color("  BENCHMARK RESULTS", "bold"))
    print(_color(f"{'='*60}", "bold"))

    acc_color = "green" if accuracy >= 0.9 else ("yellow" if accuracy >= 0.7 else "red")
    print(f"\n  Accuracy:      {_color(f'{accuracy:.1%}  {_bar(accuracy)}', acc_color)}  ({correct}/{total})")

    lat_color = "green" if avg_lat < 15 else ("yellow" if avg_lat < 30 else "red")
    print(f"  Avg latency:   {_color(f'{avg_lat:.1f}s', lat_color)}  (max: {max_lat:.1f}s)")
    print(f"  LLM calls:     {total}/{total}")
    print(f"  High conf (≥80%): {high_conf}/{total}")
    print(f"  Low conf (<50%):  {low_conf}/{total}")

    print(f"\n  Per-class breakdown:")
    for cls, (hits, n) in class_stats.items():
        ratio = hits / n
        color = "green" if ratio >= 0.9 else ("yellow" if ratio >= 0.7 else "red")
        print(f"    {cls:<12} {_color(f'{ratio:.0%}', color)} ({hits}/{n})")

    print(f"\n  Verdict distribution:")
    for v in ["Malicious", "Suspicious", "Benign", "ERROR"]:
        count = sum(1 for r in results if r["predicted_verdict"] == v)
        if count:
            print(f"    {v:<12} {count}")

    # Goal checks
    print(f"\n  {'='*40}")
    goal_acc = accuracy >= 0.9
    goal_lat = avg_lat < 15
    print(f"  {'✅' if goal_acc else '❌'} Accuracy >= 90%:  {accuracy:.1%}")
    print(f"  {'✅' if goal_lat else '❌'} Avg latency < 15s: {avg_lat:.1f}s")

    # Missed alerts
    missed = [r for r in results if not r["correct"]]
    if missed:
        print(f"\n  Incorrect predictions ({len(missed)}):")
        for r in missed:
            print(f"    ❌ {r['alert_id']:12} true={r['true_label']:10} "
                  f"pred={r['predicted_verdict']:12} conf={r['confidence']:.0%}")
            print(f"       {r['reasoning'][:100]}...")

    print(_color(f"\n{'='*60}\n", "bold"))


# ── CSV export ────────────────────────────────────────────────────────────────

def save_results(results: list[dict], output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    csv_path = output_dir / f"benchmark_{ts}.csv"

    fieldnames = [
        "alert_id", "event_type", "true_label", "predicted_verdict",
        "confidence", "correct", "latency_s", "reasoning",
        "mitre_techniques", "recommended_actions", "investigated_tools",
        "input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens",
        "timestamp",
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # Cost tracking summary row
    summary_path = output_dir / "cost_log.csv"
    summary_exists = summary_path.exists()
    total     = len(results)
    correct   = sum(1 for r in results if r["correct"])
    avg_lat   = sum(r["latency_s"] for r in results) / total if total else 0
    llm_calls = total
    total_in  = sum(r.get("input_tokens", 0) for r in results)
    total_out = sum(r.get("output_tokens", 0) for r in results)
    total_cache_read = sum(r.get("cache_read_tokens", 0) for r in results)
    avg_in_per_llm   = total_in / llm_calls if llm_calls else 0

    with open(summary_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "run_timestamp", "total_alerts", "correct", "accuracy",
            "avg_latency_s", "llm_calls",
            "total_input_tokens", "total_output_tokens", "total_cache_read_tokens",
            "avg_input_per_llm_call", "results_file",
        ])
        if not summary_exists:
            writer.writeheader()
        writer.writerow({
            "run_timestamp":   ts,
            "total_alerts":    total,
            "correct":         correct,
            "accuracy":        f"{correct/total:.3f}" if total else "0",
            "avg_latency_s":   f"{avg_lat:.2f}",
            "llm_calls":       llm_calls,
            "total_input_tokens":      total_in,
            "total_output_tokens":     total_out,
            "total_cache_read_tokens": total_cache_read,
            "avg_input_per_llm_call":  f"{avg_in_per_llm:.0f}",
            "results_file":    str(csv_path.name),
        })

    print(f"  Results saved → {csv_path}")
    print(f"  Cost log      → {summary_path}")
    return csv_path


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Agent Benchmark")
    parser.add_argument("--file",  default=str(DEFAULT_ALERTS), help="Path to alerts JSON")
    parser.add_argument("--limit", type=int, default=None,      help="Limit number of alerts")
    parser.add_argument("--ids",   nargs="+", default=None,     help="Specific alert IDs to run")
    parser.add_argument("--no-save", action="store_true",       help="Skip saving CSV results")
    args = parser.parse_args()

    alerts = _load_alerts(Path(args.file), args.limit, args.ids)
    if not alerts:
        print("No alerts found. Check --file and --ids arguments.")
        sys.exit(1)

    results = run_benchmark(alerts)
    print_summary(results)

    if not args.no_save:
        save_results(results, RESULTS_DIR)


if __name__ == "__main__":
    main()
