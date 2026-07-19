#!/usr/bin/env python3
"""Deploy Markdown analytics-rule pages to a Microsoft Sentinel workspace.

Validates every deployable rule (pages with an `analytics_rule`
frontmatter block), converts it to the Sentinel alertRules REST API
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
    derive_arm_rule,
    find_rule_files,
    is_deployable,
    load_rule,
    load_schema,
    to_arm_body,
    validate_rule,
)


def deploy_rule(arm_rule: dict, url: str) -> None:
    body = to_arm_body(dict(arm_rule))
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
        print(f"warning: no rule pages found under {rules_dir}")
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
        try:
            rule = load_rule(path)
        except Exception as exc:  # noqa: BLE001
            had_errors = True
            print(f"skipping {path}: failed to parse frontmatter: {exc}")
            continue

        if not is_deployable(rule):
            continue  # hunting/narrative-only page, nothing to deploy

        try:
            arm_rule = derive_arm_rule(rule, path)
        except ValueError as exc:
            had_errors = True
            print(f"skipping {path}: {exc}")
            continue

        errors = validate_rule(arm_rule, schema, str(path))
        if errors:
            had_errors = True
            print(f"skipping {path}, validation failed:")
            for error in errors:
                print(f"  - {error}")
            continue

        if dry_run:
            print(f"[dry-run] would deploy {path} (id={arm_rule['id']}, name={arm_rule['name']!r})")
            continue

        url = alert_rule_url(subscription_id, resource_group, workspace_name, arm_rule["id"])
        print(f"deploying {path} (id={arm_rule['id']}, name={arm_rule['name']!r}) ...", end=" ")
        try:
            deploy_rule(arm_rule, url)
            print("done")
        except RuntimeError as exc:
            had_errors = True
            print("FAILED")
            print(str(exc))

    return 1 if had_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
