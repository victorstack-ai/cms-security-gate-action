# CMS Security Gate Action

Reusable GitHub Actions security gate for WordPress and Drupal repositories. It combines:

- CodeQL analysis for broad code scanning
- CMS Security Lab scanning with WordPress/Drupal presets
- SARIF merge + upload
- Policy enforcement (`fail-on-severity`) to block risky merges

## Why this exists

CMS teams often run security checks, but policies are inconsistent across repos. This project gives maintainers one reusable gate that ships with CMS-aware presets and standard SARIF output so findings are visible in GitHub code scanning.

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
```

Inputs:

- `cms`: `wordpress`, `drupal`, or `auto` (default)
- `fail-on-severity`: `low`, `medium`, `high`, `critical` (default `high`)
- `python-version`: scanner runtime (default `3.12`)

## Local validation

Run scanner locally:

```bash
python scripts/cms_security_lab_scan.py --root . --preset presets/wordpress.json --output out.sarif
python scripts/enforce_policy.py --input out.sarif --fail-on-severity high
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
- `presets/*.json` CMS-specific rule packs
- `tests/test_security_gate.py` basic validation
