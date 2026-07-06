#!/usr/bin/env python3
"""
validate-suppressions.py

Scans all Java source files for CodeQL inline suppression comments.
For each comment found, checks it exists in the approved registry.
If ANY unapproved suppression is found — exits with code 1 (fails the CI job).

This script runs BEFORE CodeQL analysis in the reusable workflow.
Failing here blocks the scan entirely, forcing dev to go through
the AppSec approval process before the comment has any effect.

Usage:
  python3 validate-suppressions.py
    --source-root src/
    --registry approved-suppressions.yml
    --repo chagnti/dvja
"""

import os
import re
import sys
import json
import argparse
import yaml
from datetime import date

# Pattern matching CodeQL inline suppression comments
# Matches: // codeql[rule-id] and // codeql[rule-id] -- SUP-001: reason
SUPPRESS_PATTERN = re.compile(
    r'//\s*codeql\[([^\]]+)\]',
    re.IGNORECASE
)

def load_registry(registry_path):
    with open(registry_path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("suppressions") or []

def scan_source_files(source_root, extensions=(".java", ".kt", ".cs", ".py", ".js", ".ts")):
    """Walk source tree and find all inline suppression comments."""
    findings = []
    for dirpath, _, filenames in os.walk(source_root):
        # Skip build output and test dirs — same as paths-ignore in codeql-config.yml
        if any(skip in dirpath for skip in ["target", "node_modules", ".git", "build"]):
            continue
        for filename in filenames:
            if not filename.endswith(extensions):
                continue
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, source_root)
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, start=1):
                    matches = SUPPRESS_PATTERN.findall(line)
                    for rule_id in matches:
                        findings.append({
                            "file": rel_path.replace("\\", "/"),
                            "line": lineno,
                            "rule": rule_id.strip(),
                            "raw_line": line.strip()
                        })
    return findings

def check_expiry(entry):
    """Return True if suppression has expired."""
    expires = entry.get("expires")
    if not expires:
        return False
    expiry_date = date.fromisoformat(str(expires))
    return date.today() > expiry_date

def validate(source_root, registry_path, repo):
    registry = load_registry(registry_path)
    suppressions_in_code = scan_source_files(source_root)

    if not suppressions_in_code:
        print("No inline suppression comments found.")
        return True

    print(f"Found {len(suppressions_in_code)} inline suppression comment(s) — validating against registry...\n")

    unapproved = []
    expired = []
    approved = []

    for found in suppressions_in_code:
        matched = None
        for entry in registry:
            if (entry.get("rule") == found["rule"] and
                entry.get("repo") == repo and
                entry.get("file") == found["file"]):
                matched = entry
                break

        if matched is None:
            unapproved.append(found)
        elif check_expiry(matched):
            expired.append({"found": found, "entry": matched})
        else:
            approved.append({"found": found, "entry": matched})

    # Report approved
    for item in approved:
        f = item["found"]
        e = item["entry"]
        print(f"  [APPROVED]  {f['file']}:{f['line']} — {f['rule']}")
        print(f"              SUP-ID: {e.get('id')} | Approved by: {e.get('approved_by')} on {e.get('approved_date')}")
        if e.get("risk_accepted"):
            print(f"              ** RISK ACCEPTED — not a FP **")
        print()

    # Report expired — must be re-reviewed
    for item in expired:
        f = item["found"]
        e = item["entry"]
        print(f"  [EXPIRED]   {f['file']}:{f['line']} — {f['rule']}")
        print(f"              Suppression {e.get('id')} expired on {e.get('expires')} — AppSec must re-approve")
        print()

    # Report unapproved — these fail the build
    for f in unapproved:
        print(f"  [BLOCKED]   {f['file']}:{f['line']} — {f['rule']}")
        print(f"              Comment: {f['raw_line']}")
        print(f"              This suppression has NO approved entry in the registry.")
        print(f"              Open a suppression request at:")
        print(f"              https://github.com/chagnti/appsec-codeql-central/issues/new?template=suppression-request.yml")
        print()

    # Exit codes
    # Detect orphaned registry entries — approved but comment no longer in code
    # This happens when code is refactored/deleted after suppression was approved
    # Orphans indicate the registry is stale and needs cleanup
    orphaned = []
    for entry in registry:
        if entry.get("repo") != repo:
            continue
        found_match = any(
            f["rule"] == entry.get("rule") and f["file"] == entry.get("file")
            for f in suppressions_in_code
        )
        if not found_match:
            orphaned.append(entry)

    if orphaned:
        print("  [ORPHANED REGISTRY ENTRIES — AppSec action needed]")
        for e in orphaned:
            print(f"  {e.get('id')} — {e.get('rule')} @ {e.get('file')}")
            print(f"  Comment no longer exists in code — file may have been renamed or deleted.")
            print(f"  Remove this entry from approved-suppressions.yml")
            print()

    if unapproved or expired:
        print("=" * 60)
        print(f"SCAN BLOCKED: {len(unapproved)} unapproved + {len(expired)} expired suppression(s).")
        print("All inline codeql[] comments must be approved by AppSec")
        print("before they can be used. See above for next steps.")
        print("=" * 60)
        return False

    print(f"All {len(approved)} suppression(s) are approved and current.")
    if orphaned:
        print(f"WARNING: {len(orphaned)} orphaned registry entries need cleanup.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--repo", required=True)
    args = parser.parse_args()

    ok = validate(args.source_root, args.registry, args.repo)
    sys.exit(0 if ok else 1)
