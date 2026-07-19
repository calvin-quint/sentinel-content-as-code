#!/usr/bin/env python3
"""Validate all Markdown analytics-rule pages under a directory against
the analytics-rule JSON schema, and check for duplicate rule ids.

Pages with no `analytics_rule` frontmatter block (hunting/lookup pages,
narrative-only pages) are skipped — they aren't deployable and have
nothing to validate against this schema.

Usage: validate_rules.py [rules_dir]
"""
from __future__ import annotations

import sys
from pathlib import Path

from rule_transform import derive_arm_rule, find_rule_files, is_deployable, load_rule, load_schema, validate_rule


def main() -> int:
    rules_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rules/analytics")
    if not rules_dir.is_dir():
        print(f"error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    schema = load_schema()
    files = find_rule_files(rules_dir)
    if not files:
        print(f"warning: no rule pages found under {rules_dir}")
        return 0

    all_errors: list[str] = []
    seen_ids: dict[str, Path] = {}
    deployable_count = 0
    skipped_count = 0

    for path in files:
        try:
            rule = load_rule(path)
        except Exception as exc:  # noqa: BLE001
            all_errors.append(f"{path}: failed to parse frontmatter: {exc}")
            continue

        if not is_deployable(rule):
            skipped_count += 1
            continue

        deployable_count += 1
        try:
            arm_rule = derive_arm_rule(rule, path)
        except ValueError as exc:
            all_errors.append(str(exc))
            continue

        all_errors.extend(validate_rule(arm_rule, schema, str(path)))

        rule_id = arm_rule.get("id")
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

    print(
        f"OK: {deployable_count} deployable rule(s) validated successfully "
        f"({skipped_count} non-deployable page(s) skipped)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
