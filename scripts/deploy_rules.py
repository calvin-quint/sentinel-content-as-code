#!/usr/bin/env python3
"""Deploy YAML analytics rules to a Microsoft Sentinel workspace.

Validates every rule, converts it to the Sentinel alertRules REST API
body, and PUTs it via `az rest` (relies on an already-authenticated
Azure CLI session, e.g. from the azure/login GitHub Action with OIDC).

Usage:
  deploy_rules.py [rules_dir] [--dry-run]

Required environment variables (unless --dry-run):
  AZURE_SUBSCRIPTION_ID
  AZURE_RESOURCE_GROUP
  AZURE_WORKSPACE_NAME
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from rule_transform import (
    alert_rule_url,
    find_rule_files,
    load_rule,
    load_schema,
    to_arm_body,
    validate_rule,
)


def deploy_rule(rule: dict, url: str, yaml_path: Path) -> None:
    body = to_arm_body(rule, yaml_path)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(body, f)
        payload_path = f.name

    try:
        result = subprocess.run(
            [
                "az", "rest",
                "--method", "put",
                "--url", url,
                "--body", f"@{payload_path}",
                "--headers", "Content-Type=application/json",
            ],
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(payload_path)

    if result.returncode != 0:
        raise RuntimeError(f"az rest failed:\n{result.stdout}\n{result.stderr}")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry_run = "--dry-run" in sys.argv

    rules_dir = Path(args[0]) if args else Path("rules/analytics")
    if not rules_dir.is_dir():
        print(f"error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    schema = load_schema()
    files = find_rule_files(rules_dir)
    if not files:
        print(f"warning: no YAML rule files found under {rules_dir}")
        return 0

    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    resource_group = os.environ.get("AZURE_RESOURCE_GROUP")
    workspace_name = os.environ.get("AZURE_WORKSPACE_NAME")

    if not dry_run and not all([subscription_id, resource_group, workspace_name]):
        print(
            "error: AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP and "
            "AZURE_WORKSPACE_NAME must be set (or pass --dry-run)",
            file=sys.stderr,
        )
        return 1

    had_errors = False
    for path in files:
        rule = load_rule(path)
        errors = validate_rule(rule, schema, str(path))
        if errors:
            had_errors = True
            print(f"skipping {path}, validation failed:")
            for error in errors:
                print(f"  - {error}")
            continue

        if dry_run:
            print(f"[dry-run] would deploy {path} (id={rule['id']}, name={rule['name']!r})")
            continue

        url = alert_rule_url(subscription_id, resource_group, workspace_name, rule["id"])
        print(f"deploying {path} (id={rule['id']}, name={rule['name']!r}) ...", end=" ")
        try:
            deploy_rule(rule, url, path)
            print("done")
        except RuntimeError as exc:
            had_errors = True
            print("FAILED")
            print(str(exc))

    return 1 if had_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
