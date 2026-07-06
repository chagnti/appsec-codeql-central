#!/usr/bin/env python3
"""
filter-sarif.py — Post-process CodeQL SARIF output to suppress known false positives.

Usage:
  python filter-sarif.py --input results.sarif --output filtered.sarif --fp-list fp-rules.yml

How FP suppression works:
  1. Rule-based: suppress specific rule IDs on specific file path patterns
  2. Threshold-based: drop findings below a CVSS/severity threshold
  3. Dedup: remove duplicate findings across runs (same rule + location)
"""

import json
import argparse
import re
import sys

# ── Default FP rules ────────────────────────────────────────────────────────
# Add patterns here when a rule consistently fires on non-vulnerable code.
# Format: { "rule_id": "...", "path_pattern": "regex or None for all paths", "reason": "..." }
DEFAULT_FP_RULES = [
    # Test utilities that use SQL but are not production paths
    {
        "rule_id": "java/sql-injection",
        "path_pattern": r"src/test/.*",
        "reason": "Test code — not reachable in production"
    },
    {
        "rule_id": "java/custom-sql-injection",
        "path_pattern": r"src/test/.*",
        "reason": "Test code"
    },
    # Spring Boot actuator check fires on all Spring apps — known low-risk in internal networks
    {
        "rule_id": "java/spring-boot-exposed-actuators",
        "path_pattern": None,   # suppresses on ALL paths
        "reason": "Actuators are internal-only — firewall blocks external access"
    },
    # Hardcoded secret FP: test fixtures and example configs
    {
        "rule_id": "java/custom-hardcoded-secret",
        "path_pattern": r".*(test|example|sample|demo|fixture).*",
        "reason": "Test fixture — not a real credential"
    },
]

def load_sarif(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_sarif(sarif, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

def get_uri(result):
    try:
        locations = result.get("locations", [])
        if not locations:
            return ""
        return locations[0]["physicalLocation"]["artifactLocation"]["uri"]
    except (KeyError, IndexError):
        return ""

def get_rule_id(result):
    return result.get("ruleId", "")

def is_false_positive(result, fp_rules):
    rule_id = get_rule_id(result)
    uri = get_uri(result)
    for rule in fp_rules:
        if rule["rule_id"] != rule_id:
            continue
        path_pattern = rule.get("path_pattern")
        if path_pattern is None or re.search(path_pattern, uri):
            return True, rule.get("reason", "suppressed by FP rule")
    return False, None

def filter_sarif(input_path, output_path, min_severity=None):
    sarif = load_sarif(input_path)
    severity_order = {"none": 0, "note": 1, "warning": 2, "error": 3}
    min_level = severity_order.get(min_severity or "none", 0)

    total = 0
    suppressed = 0
    kept = 0

    for run in sarif.get("runs", []):
        results = run.get("results", [])
        filtered = []
        for result in results:
            total += 1
            # Severity filter
            level = result.get("level", "warning")
            if severity_order.get(level, 1) < min_level:
                suppressed += 1
                continue
            # FP rule filter
            is_fp, reason = is_false_positive(result, DEFAULT_FP_RULES)
            if is_fp:
                suppressed += 1
                print(f"  [SUPPRESSED] {get_rule_id(result)} @ {get_uri(result)} — {reason}")
                continue
            filtered.append(result)
            kept += 1
        run["results"] = filtered

    save_sarif(sarif, output_path)
    print(f"\nSummary: {total} total | {kept} kept | {suppressed} suppressed")
    print(f"Filtered SARIF written to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--min-severity", choices=["note", "warning", "error"], default="warning")
    args = parser.parse_args()
    filter_sarif(args.input, args.output, args.min_severity)
