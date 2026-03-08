from __future__ import annotations

import json
import tempfile
from pathlib import Path

from scripts.enforce_policy import load_results
from scripts.merge_sarif import merge_runs


def _sarif_with_result(rule_id: str, uri: str, line: int, severity: str):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "test",
                        "rules": [{"id": rule_id, "properties": {"security-severity": severity}}],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "warning",
                        "properties": {"security-severity": severity},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_merge_deduplicates_same_rule_location():
    a = _sarif_with_result("WP001", "foo.php", 10, "high")
    b = _sarif_with_result("WP001", "foo.php", 10, "high")
    merged = merge_runs([a, b])
    assert len(merged["runs"][0]["results"]) == 1


def test_policy_loader_reads_severities():
    sarif = _sarif_with_result("DR001", "bar.module", 2, "critical")
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "sample.sarif"
        path.write_text(json.dumps(sarif), encoding="utf-8")
        severities = load_results([path])
    assert severities == ["critical"]
