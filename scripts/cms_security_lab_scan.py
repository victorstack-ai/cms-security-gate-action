#!/usr/bin/env python3
"""CMS-focused static scanner that emits SARIF."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


DEFAULT_EXCLUDES = {
    ".git",
    ".github",
    "vendor",
    "node_modules",
    ".idea",
    ".vscode",
}


SEVERITY_TO_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    description: str
    severity: str
    pattern: str
    include: Optional[str] = None


def read_json(path: pathlib.Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_rules(preset_path: pathlib.Path) -> Dict:
    preset = read_json(preset_path)
    rules = [
        Rule(
            rule_id=item["id"],
            name=item["name"],
            description=item["description"],
            severity=item["severity"].lower(),
            pattern=item["pattern"],
            include=item.get("include"),
        )
        for item in preset.get("rules", [])
    ]
    return {
        "name": preset.get("name", "CMS preset"),
        "extensions": set(preset.get("extensions", [".php"])),
        "rules": rules,
    }


def list_files(root: pathlib.Path, extensions: set[str]) -> Iterable[pathlib.Path]:
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDES]
        base_path = pathlib.Path(base)
        for filename in files:
            path = base_path / filename
            if path.suffix.lower() in extensions:
                yield path


def line_number_from_offset(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1


def make_result(rule: Rule, file_path: pathlib.Path, content: str, match: re.Match, root: pathlib.Path) -> Dict:
    line = line_number_from_offset(content, match.start())
    level = SEVERITY_TO_LEVEL.get(rule.severity, "warning")
    relative = file_path.relative_to(root).as_posix()
    return {
        "ruleId": rule.rule_id,
        "level": level,
        "message": {"text": f"{rule.name}: {rule.description}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": relative},
                    "region": {"startLine": line},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": f"{rule.rule_id}:{relative}:{line}",
        },
        "properties": {
            "security-severity": rule.severity,
            "tags": ["external/cwe", "security", "cms"],
        },
    }


def scan(root: pathlib.Path, preset_path: pathlib.Path) -> Dict:
    preset = load_rules(preset_path)
    results: List[Dict] = []
    for path in list_files(root, preset["extensions"]):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rule in preset["rules"]:
            if rule.include and rule.include not in path.as_posix():
                continue
            for match in re.finditer(rule.pattern, content, flags=re.MULTILINE):
                results.append(make_result(rule, path, content, match, root))

    rules = [
        {
            "id": rule.rule_id,
            "name": rule.name,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(rule.severity, "warning")},
            "properties": {"security-severity": rule.severity, "tags": ["security", "cms"]},
        }
        for rule in preset["rules"]
    ]

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CMS Security Lab Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/victorstack-ai/cms-security-gate-action",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CMS Security Lab scan and emit SARIF.")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--preset", required=True, help="Preset file path")
    parser.add_argument("--output", required=True, help="Output SARIF file")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    preset = pathlib.Path(args.preset).resolve()
    output = pathlib.Path(args.output).resolve()
    sarif = scan(root, preset)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(sarif, handle, indent=2)
        handle.write("\n")
    print(f"Wrote SARIF with {len(sarif['runs'][0].get('results', []))} findings to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
