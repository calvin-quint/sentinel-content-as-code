#!/usr/bin/env python3
"""Validates watchlist CSVs before merge. Fails if any errors found."""
import csv
import sys
from pathlib import Path

WATCHLIST_DIR = Path("watchlists")
REQUIRED_COLUMNS = {
    "TrustedIPs":         {"SearchKey", "Description", "Category", "AddedBy", "AddedDate"},
    "ServiceAccounts":    {"SearchKey", "DisplayName", "AccountType", "Owner", "AddedBy", "AddedDate"},
    "PrivilegedAccounts": {"SearchKey", "DisplayName", "Role", "AddedBy", "AddedDate"},
    "PlaybookOverride":   {"SearchKey", "EntityType", "Reason", "ExpiresAt", "AddedBy", "AddedDate"},
    "SanctionedTools":    {"SearchKey", "ToolName", "Version", "Publisher", "AddedBy", "AddedDate"},
}

errors = []
csv_files = sorted(WATCHLIST_DIR.glob("*.csv"))

if not csv_files:
    print("No CSV files found in watchlists/")
    sys.exit(1)

for filepath in csv_files:
    name = filepath.stem
    expected = REQUIRED_COLUMNS.get(name)

    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = set(reader.fieldnames or [])

        if not headers:
            errors.append(f"{name}: file is empty or has no headers")
            continue

        if "SearchKey" not in headers:
            errors.append(f"{name}: missing required column 'SearchKey'")
            continue

        if expected and not expected.issubset(headers):
            missing = expected - headers
            errors.append(f"{name}: missing columns {sorted(missing)}")

        seen = set()
        for i, row in enumerate(reader, start=2):
            key = row["SearchKey"].strip()
            if not key:
                errors.append(f"{name} row {i}: empty SearchKey")
            elif key in seen:
                errors.append(f"{name} row {i}: duplicate SearchKey '{key}'")
            else:
                seen.add(key)

    status = "✓" if not any(name in e for e in errors) else "✗"
    print(f"{status} {name}: {len(seen)} entries")

if errors:
    print("\nValidation errors:")
    for e in errors:
        print(f"  ✗ {e}")
    sys.exit(1)

print("\nAll watchlists valid")
