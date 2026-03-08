#!/usr/bin/env python3
"""Generate maintainer-focused remediation report from SARIF findings."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

try:
    from scripts.enforce_policy import RANK, classify
except ModuleNotFoundError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from enforce_policy import RANK, classify


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    path: str
    line: int


def _normalize_severity(value: str) -> str:
    lowered = value.lower()
    if lowered in RANK:
        return lowered
    return "medium"


def _extract_findings(sarif: Dict) -> List[Finding]:
    findings: List[Finding] = []
    for run in sarif.get("runs", []):
        rules = {
            rule.get("id", ""): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            if rule.get("id")
        }
        for result in run.get("results", []):
            locations = result.get("locations", [])
            path = ""
            line = 1
            if locations:
                physical = locations[0].get("physicalLocation", {})
                path = physical.get("artifactLocation", {}).get("uri", "")
                line = int(physical.get("region", {}).get("startLine", 1))
            message = result.get("message", {}).get("text", "Potential security issue")
            severity = _normalize_severity(classify(result, rules))
            findings.append(
                Finding(
                    rule_id=result.get("ruleId", "UNKNOWN"),
                    severity=severity,
                    message=message,
                    path=path,
                    line=line,
                )
            )
    return findings


def _gate_status(findings: Iterable[Finding], threshold: str) -> str:
    threshold_rank = RANK[threshold]
    for finding in findings:
        if RANK[finding.severity] >= threshold_rank:
            return "fail"
    return "pass"


def _default_fix_hint(finding: Finding) -> str:
    msg = finding.message.lower()
    rule = finding.rule_id.lower()
    if "wpdb" in msg or "query" in msg or "sql" in msg:
        return "Use prepared statements (`$wpdb->prepare`, Drupal placeholders) and never concatenate user input into SQL."
    if "superglobal" in msg or "$_get" in msg or "$_post" in msg:
        return "Validate and sanitize input early, then escape on output (`esc_html`, `Html::escape`, render-safe APIs)."
    if "ajax" in msg or "nopriv" in msg:
        return "Require nonce/capability checks for endpoints and avoid exposing privileged actions to unauthenticated handlers."
    if "access" in msg or "route" in msg:
        return "Require explicit permission/capability checks in route/controller access handlers."
    if rule.startswith("wp"):
        return "Apply WordPress coding standards for input validation, output escaping, and capability checks."
    if rule.startswith("dr"):
        return "Apply Drupal secure coding patterns (access callbacks, placeholders, and escaped render output)."
    return "Review call chain and add strict input validation, output encoding, and authorization checks."


def _summarize_findings(findings: List[Finding], limit: int = 20) -> str:
    lines = []
    for finding in findings[:limit]:
        lines.append(
            f"- [{finding.severity}] {finding.rule_id} at {finding.path}:{finding.line} :: {finding.message}"
        )
    return "\n".join(lines)


def _call_openai_guidance(findings: List[Finding], threshold: str, model: str) -> Optional[str]:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None

    findings_text = _summarize_findings(findings, limit=25)
    prompt = (
        "You are a senior application security engineer specializing in WordPress and Drupal.\n"
        "Return concise markdown with two sections: 'Priority Fix Plan' and 'Regression Tests to Add'.\n"
        "Each bullet must be actionable for maintainers. No code fences.\n"
        f"Fail threshold: {threshold}\n"
        f"Findings:\n{findings_text}"
    )

    body = {
        "model": model,
        "input": prompt,
        "max_output_tokens": 900,
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None

    output = payload.get("output", [])
    text_parts: List[str] = []
    for item in output:
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                text_parts.append(content.get("text", "").strip())
    text = "\n\n".join(part for part in text_parts if part)
    return text or None


def build_report(sarif: Dict, threshold: str, model: str) -> Dict:
    findings = sorted(_extract_findings(sarif), key=lambda item: RANK[item.severity], reverse=True)
    counts = Counter([finding.severity for finding in findings])
    status = _gate_status(findings, threshold)

    top_findings = [
        {
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "message": finding.message,
            "path": finding.path,
            "line": finding.line,
            "suggested_fix": _default_fix_hint(finding),
        }
        for finding in findings[:30]
    ]

    ai_guidance = _call_openai_guidance(findings=findings, threshold=threshold, model=model)
    return {
        "gate": {
            "status": status,
            "fail_on_severity": threshold,
        },
        "counts": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "total": len(findings),
        },
        "top_findings": top_findings,
        "ai_guidance": ai_guidance,
        "ai_used": bool(ai_guidance),
        "maintainer_note": (
            "AI guidance unavailable (set OPENAI_API_KEY to enable)." if not ai_guidance else "AI guidance included."
        ),
    }


def to_markdown(report: Dict) -> str:
    gate = report["gate"]
    counts = report["counts"]
    lines = [
        "# Security Gate Remediation Report",
        "",
        f"- Gate status: **{gate['status'].upper()}**",
        f"- Fail threshold: **{gate['fail_on_severity']}**",
        f"- Findings: critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, low={counts['low']}, total={counts['total']}",
        "",
        "## Maintainer Actions",
    ]
    for item in report["top_findings"][:15]:
        lines.append(
            f"- `{item['severity']}` `{item['rule_id']}` at `{item['path']}:{item['line']}`: {item['suggested_fix']}"
        )
    lines.extend(["", "## AI Guidance", report.get("ai_guidance") or report["maintainer_note"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate remediation report from SARIF.")
    parser.add_argument("--sarif", required=True, help="Merged SARIF input file")
    parser.add_argument("--json-out", required=True, help="Machine-readable report output path")
    parser.add_argument("--markdown-out", required=True, help="Markdown report output path")
    parser.add_argument("--fail-on-severity", default="high", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--model", default="gpt-4.1-mini", help="OpenAI model name for optional guidance")
    args = parser.parse_args()

    sarif_path = pathlib.Path(args.sarif).resolve()
    with sarif_path.open("r", encoding="utf-8") as handle:
        sarif = json.load(handle)

    report = build_report(sarif=sarif, threshold=args.fail_on_severity, model=args.model)

    json_out = pathlib.Path(args.json_out).resolve()
    markdown_out = pathlib.Path(args.markdown_out).resolve()
    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_out.write_text(to_markdown(report), encoding="utf-8")

    print(
        f"Generated remediation report: status={report['gate']['status']} total={report['counts']['total']} ai_used={report['ai_used']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
