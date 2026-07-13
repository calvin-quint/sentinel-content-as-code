#!/usr/bin/env python3
"""Validate all YAML analytics rules under a directory against the
analytics-rule JSON schema, and check for duplicate rule ids.

Usage: validate_rules.py [rules_dir]
"""
from __future__ import annotations

import sys
from pathlib import Path

from rule_transform import find_rule_files, load_rule, load_schema, validate_rule


def main() -> int:
    rules_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rules/analytics")
    if not rules_dir.is_dir():
        print(f"error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    schema = load_schema()
    files = find_rule_files(rules_dir)
    if not files:
        print(f"warning: no YAML rule files found under {rules_dir}")
        return 0

    all_errors: list[str] = []
    seen_ids: dict[str, Path] = {}

    for path in files:
        rel = path.relative_to(rules_dir.parent.parent) if rules_dir.is_absolute() is False else path
        try:
            rule = load_rule(path)
        except Exception as exc:  # noqa: BLE001
            all_errors.append(f"{path}: failed to parse YAML: {exc}")
            continue

        all_errors.extend(validate_rule(rule, schema, str(path)))

        rule_id = rule.get("id")
        if rule_id:
            if rule_id in seen_ids:
                all_errors.append(
                    f"{path}: duplicate rule id '{rule_id}' also used by {seen_ids[rule_id]}"
                )
            else:
                seen_ids[rule_id] = path

    if all_errors:
        print(f"Found {len(all_errors)} validation error(s):\n")
        for error in all_errors:
            print(f"  - {error}")
        return 1

    print(f"OK: {len(files)} rule(s) validated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
