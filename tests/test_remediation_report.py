from scripts.generate_remediation_report import build_report, to_markdown


def test_report_gate_fails_for_high_at_high_threshold():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "test",
                        "rules": [{"id": "WP001", "properties": {"security-severity": "high"}}],
                    }
                },
                "results": [
                    {
                        "ruleId": "WP001",
                        "level": "warning",
                        "message": {"text": "Raw SQL query"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "plugin.php"},
                                    "region": {"startLine": 8},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    report = build_report(sarif=sarif, threshold="high", model="gpt-4.1-mini")
    assert report["gate"]["status"] == "fail"
    assert report["counts"]["high"] == 1
    assert report["ai_used"] is False


def test_markdown_contains_maintainer_actions_section():
    report = {
        "gate": {"status": "pass", "fail_on_severity": "critical"},
        "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "total": 1},
        "top_findings": [
            {
                "severity": "medium",
                "rule_id": "DR001",
                "path": "mod.module",
                "line": 22,
                "suggested_fix": "Require access checks",
            }
        ],
        "ai_guidance": None,
        "maintainer_note": "AI guidance unavailable (set OPENAI_API_KEY to enable).",
    }
    markdown = to_markdown(report)
    assert "## Maintainer Actions" in markdown
    assert "DR001" in markdown
    assert "AI guidance unavailable" in markdown
