# CMS Security Gate Action

Reusable GitHub Actions security gate for WordPress and Drupal repositories. It combines:

- CodeQL analysis for broad code scanning
- CMS Security Lab scanning with WordPress/Drupal presets
- SARIF merge + upload
- Policy enforcement (`fail-on-severity`) to block risky merges
- AI-assisted remediation reporting for maintainers

## Why this exists

CMS teams often run security checks, but policies are inconsistent across repos. This project gives maintainers one reusable gate that ships with CMS-aware presets and standard SARIF output so findings are visible in GitHub code scanning.
It also produces a remediation report in JSON + Markdown so maintainers get direct fix guidance instead of raw scanner output.

## What it scans

- `presets/wordpress.json`: risky `$wpdb` query interpolation, unescaped superglobal output, nopriv AJAX endpoints
- `presets/drupal.json`: concatenated `db_query`, open access routes, unescaped superglobal render patterns

You can extend the preset files with your own rules and severities.

## Use in a repository

Copy this workflow to the caller repo (or consume it from this repo once published):

```yaml
name: Security Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security:
    uses: victorstack-ai/cms-security-gate-action/.github/workflows/cms-security-gate.yml@main
    with:
      cms: auto
      fail-on-severity: high
    secrets:
      openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

Inputs:

- `cms`: `wordpress`, `drupal`, or `auto` (default)
- `fail-on-severity`: `low`, `medium`, `high`, `critical` (default `high`)
- `python-version`: scanner runtime (default `3.12`)
- `openai-api-key` (optional secret): enables AI guidance in remediation report. If omitted, deterministic maintainer guidance is still generated.

Outputs:

- `merged-results.sarif`: uploaded to GitHub code scanning
- `security-remediation-report.json`: machine-readable remediation report
- `security-remediation-report.md`: maintainer-friendly remediation notes and prioritized actions

## Local validation

Run scanner locally:

```bash
python scripts/cms_security_lab_scan.py --root . --preset presets/wordpress.json --output out.sarif
python scripts/enforce_policy.py --input out.sarif --fail-on-severity high
python scripts/generate_remediation_report.py \
  --sarif out.sarif \
  --json-out remediation.json \
  --markdown-out remediation.md \
  --fail-on-severity high
```

Enable AI guidance locally:

```bash
export OPENAI_API_KEY="your_key"
python scripts/generate_remediation_report.py \
  --sarif out.sarif \
  --json-out remediation.json \
  --markdown-out remediation.md
```

Run tests:

```bash
python -m pytest -q
```

## Repo structure

- `.github/workflows/cms-security-gate.yml` reusable workflow
- `scripts/cms_security_lab_scan.py` CMS scanner that emits SARIF
- `scripts/merge_sarif.py` merges/deduplicates SARIF logs
- `scripts/enforce_policy.py` policy gate by severity threshold
- `scripts/generate_remediation_report.py` maintainer report generator with optional AI guidance
- `presets/*.json` CMS-specific rule packs
- `tests/test_security_gate.py` basic validation
