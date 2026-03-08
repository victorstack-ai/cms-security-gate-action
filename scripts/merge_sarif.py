#!/usr/bin/env python3
"""Merge SARIF logs and deduplicate findings."""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Dict, Iterable, List, Tuple


def read_sarif(path: pathlib.Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dedupe_key(result: Dict) -> Tuple[str, str, int]:
    rule_id = result.get("ruleId", "")
    locations = result.get("locations", [])
    uri = ""
    line = 1
    if locations:
        physical = locations[0].get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})
        uri = artifact.get("uri", "")
        line = int(region.get("startLine", 1))
    return (rule_id, uri, line)


def merge_runs(sarif_documents: Iterable[Dict]) -> Dict:
    merged_results: List[Dict] = []
    merged_rules: Dict[str, Dict] = {}
    seen = set()

    for document in sarif_documents:
        for run in document.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id")
                if rule_id and rule_id not in merged_rules:
                    merged_rules[rule_id] = rule
            for result in run.get("results", []):
                key = dedupe_key(result)
                if key in seen:
                    continue
                seen.add(key)
                merged_results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CMS Security Gate",
                        "version": "1.0.0",
                        "rules": list(merged_rules.values()),
                    }
                },
                "results": merged_results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge and deduplicate SARIF files.")
    parser.add_argument("--input", nargs="+", required=True, help="Input SARIF files")
    parser.add_argument("--output", required=True, help="Merged SARIF output")
    args = parser.parse_args()

    sarif_docs = [read_sarif(pathlib.Path(path).resolve()) for path in args.input]
    merged = merge_runs(sarif_docs)
    output = pathlib.Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(merged, handle, indent=2)
        handle.write("\n")
    print(f"Merged {len(sarif_docs)} files into {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
