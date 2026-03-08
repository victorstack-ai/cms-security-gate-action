#!/usr/bin/env python3
"""Fail pipeline when findings meet or exceed configured severity."""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Dict, Iterable, List


RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def classify(result: Dict, rules_by_id: Dict[str, Dict]) -> str:
    props = result.get("properties", {})
    sev = props.get("security-severity")
    if isinstance(sev, str):
        sev = sev.lower()
        if sev in RANK:
            return sev
        try:
            value = float(sev)
            if value >= 9.0:
                return "critical"
            if value >= 7.0:
                return "high"
            if value >= 4.0:
                return "medium"
            return "low"
        except ValueError:
            pass

    rule_id = result.get("ruleId", "")
    rule = rules_by_id.get(rule_id, {})
    rule_sev = rule.get("properties", {}).get("security-severity")
    if isinstance(rule_sev, str) and rule_sev.lower() in RANK:
        return rule_sev.lower()

    level = result.get("level", "warning").lower()
    if level == "error":
        return "high"
    if level == "warning":
        return "medium"
    return "low"


def load_results(paths: Iterable[pathlib.Path]) -> List[str]:
    severities: List[str] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            sarif = json.load(handle)
        for run in sarif.get("runs", []):
            rules = {
                rule.get("id", ""): rule
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
                if rule.get("id")
            }
            for result in run.get("results", []):
                severities.append(classify(result, rules))
    return severities


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce fail-on-severity policy from SARIF.")
    parser.add_argument("--input", nargs="+", required=True, help="SARIF files to evaluate")
    parser.add_argument("--fail-on-severity", default="high", choices=["low", "medium", "high", "critical"])
    args = parser.parse_args()

    threshold = args.fail_on_severity.lower()
    severities = load_results([pathlib.Path(p).resolve() for p in args.input])
    counts = {name: 0 for name in RANK}
    for severity in severities:
        counts[severity] += 1

    print(
        "Severity totals: "
        + ", ".join(f"{name}={counts[name]}" for name in ("critical", "high", "medium", "low"))
    )

    blocked = [name for name, rank in RANK.items() if rank >= RANK[threshold] and counts[name] > 0]
    if blocked:
        print(f"Policy failed: threshold={threshold}; blocking severities={', '.join(blocked)}")
        return 1
    print(f"Policy passed: threshold={threshold}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
