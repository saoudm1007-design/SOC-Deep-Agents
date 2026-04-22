"""
SOC Analyst Deep Agents — Demo Runner

Runs the 4 canonical demo scenarios end-to-end and prints
colourised verdicts for live presentation.

Usage:
    cd soc-agent
    .venv/bin/python demo/run_demo.py              # run all 4 scenarios
    .venv/bin/python demo/run_demo.py 01 03        # run specific scenarios
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import AlertInput, VerdictOutput
from agent import run_agent


SCENARIOS_DIR = Path(__file__).parent / "scenarios"


# ── ANSI colours ──────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    END    = "\033[0m"


_VERDICT_COLOR = {
    "Malicious":  C.RED,
    "Suspicious": C.YELLOW,
    "Benign":     C.GREEN,
}
_VERDICT_ICON = {"Malicious": "🔴", "Suspicious": "🟡", "Benign": "🟢"}


def _confidence_bar(conf: float, width: int = 20) -> str:
    filled = round(conf * width)
    return "█" * filled + "░" * (width - filled)


def _load_scenarios(filters: list[str]) -> list[tuple[Path, dict]]:
    files = sorted(SCENARIOS_DIR.glob("*.json"))
    if filters:
        files = [f for f in files if any(fil in f.stem for fil in filters)]
    return [(f, json.loads(f.read_text())) for f in files]


def _print_header(scenario: dict, idx: int, total: int) -> None:
    print()
    print(C.CYAN + "━" * 78 + C.END)
    print(f"{C.BOLD}{C.CYAN}[Scenario {idx}/{total}] {scenario['alert_id']}{C.END}")
    print(C.CYAN + "━" * 78 + C.END)
    print(f"{C.BOLD}Description:{C.END} {scenario['scenario_description']}")
    print(f"{C.BOLD}Event Type :{C.END} {scenario['event_type']}  "
          f"({C.DIM}severity: {scenario['severity']}{C.END})")
    print(f"{C.BOLD}Source IP  :{C.END} {scenario.get('source_ip', 'N/A')}  →  "
          f"{scenario.get('destination_ip', 'N/A')}")
    print(f"{C.BOLD}Expected   :{C.END} "
          f"{_VERDICT_COLOR[scenario['expected_verdict']]}{scenario['expected_verdict']}{C.END}")
    print(f"{C.BOLD}Payload    :{C.END} {C.GRAY}{scenario['payload'][:140]}"
          f"{'...' if len(scenario['payload']) > 140 else ''}{C.END}")
    print()


def _print_verdict(v: VerdictOutput, expected: str, elapsed: float) -> bool:
    color  = _VERDICT_COLOR.get(v.verdict, C.END)
    icon   = _VERDICT_ICON.get(v.verdict, "⚪")
    match  = v.verdict == expected
    badge  = f"{C.GREEN}✓ MATCH{C.END}" if match else f"{C.RED}✗ MISMATCH{C.END}"

    print(f"  {icon} Verdict    : {color}{C.BOLD}{v.verdict}{C.END}  [{badge}]")
    print(f"  {C.BOLD}Confidence {C.END}: {color}{_confidence_bar(v.confidence)}{C.END}  "
          f"{v.confidence * 100:.0f}%")
    print(f"  {C.BOLD}Elapsed    {C.END}: {elapsed:.2f}s")
    print(f"  {C.BOLD}Reasoning  {C.END}: {v.reasoning}")

    if v.mitre_techniques:
        print(f"  {C.BOLD}MITRE      {C.END}:")
        for t in v.mitre_techniques:
            print(f"    • {C.BLUE}{t}{C.END}")

    if v.recommended_actions:
        print(f"  {C.BOLD}Actions    {C.END}:")
        for i, a in enumerate(v.recommended_actions, 1):
            print(f"    {i}. {a}")

    if v.investigated_tools:
        print(f"  {C.BOLD}Tools used {C.END}: {C.DIM}"
              f"{', '.join(v.investigated_tools)}{C.END}")
    return match


def _run_one(scenario: dict) -> tuple[VerdictOutput, float, bool]:
    alert = AlertInput.from_dict(scenario)
    start = time.monotonic()
    verdict = run_agent(alert)
    elapsed = time.monotonic() - start
    matched = _print_verdict(verdict, scenario["expected_verdict"], elapsed)
    return verdict, elapsed, matched


def main():
    filters = sys.argv[1:]
    scenarios = _load_scenarios(filters)

    if not scenarios:
        print(f"{C.RED}No scenarios found{C.END} in {SCENARIOS_DIR}"
              + (f" matching {filters}" if filters else ""))
        sys.exit(1)

    print(f"\n{C.BOLD}🛡️  SOC Analyst Deep Agents — Demo Run{C.END}")
    print(f"{C.DIM}Running {len(scenarios)} scenario(s) from {SCENARIOS_DIR}{C.END}")

    results: list[tuple[str, str, str, float, bool]] = []
    for idx, (path, scenario) in enumerate(scenarios, 1):
        _print_header(scenario, idx, len(scenarios))
        try:
            verdict, elapsed, matched = _run_one(scenario)
            results.append((
                scenario["alert_id"], verdict.verdict,
                scenario["expected_verdict"], elapsed, matched,
            ))
        except Exception as e:
            print(f"  {C.RED}✗ ERROR{C.END}: {type(e).__name__}: {e}")
            results.append((scenario["alert_id"], "ERROR",
                            scenario["expected_verdict"], 0.0, False))

    # Summary table
    print()
    print(C.CYAN + "━" * 78 + C.END)
    print(f"{C.BOLD}{C.CYAN}Demo Summary{C.END}")
    print(C.CYAN + "━" * 78 + C.END)
    print(f"{'Alert ID':<22} {'Expected':<12} {'Got':<12} {'Time':>8}   Result")
    print(C.GRAY + "-" * 78 + C.END)
    matches = 0
    total_time = 0.0
    for aid, got, expected, elapsed, matched in results:
        total_time += elapsed
        if matched:
            matches += 1
            result_str = f"{C.GREEN}✓ PASS{C.END}"
        else:
            result_str = f"{C.RED}✗ FAIL{C.END}"
        got_color = _VERDICT_COLOR.get(got, C.END)
        print(f"{aid:<22} {expected:<12} {got_color}{got:<12}{C.END} "
              f"{elapsed:>7.2f}s   {result_str}")

    acc = 100 * matches / len(results) if results else 0
    print(C.GRAY + "-" * 78 + C.END)
    print(f"{C.BOLD}Accuracy{C.END}: {matches}/{len(results)} ({acc:.0f}%)   "
          f"{C.BOLD}Total time{C.END}: {total_time:.2f}s   "
          f"{C.BOLD}Avg{C.END}: {total_time / len(results):.2f}s")
    print()

    sys.exit(0 if matches == len(results) else 1)


if __name__ == "__main__":
    main()
