"""Shared helpers for loading and transforming Markdown analytics-rule
pages into the Microsoft Sentinel (Microsoft.SecurityInsights/alertRules)
REST API request body.

Each rule lives as a single .md file: YAML frontmatter (narrative
metadata plus an `analytics_rule` block matching the ARM schema) and a
body with standard sections, including a fenced ```kusto query block
under "## Query" labeled **Sentinel**. Only files whose frontmatter sets
`analytics_rule` are deployable — hunting/lookup pages and narrative-only
pages (analytics_rule: null) are skipped.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

API_VERSION = "2023-11-01"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "analytics-rule.schema.json"

SEVERITY_MAP = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",  # ARM has no Critical enum value; critical narrative severity maps to High
}

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.DOTALL)
SECTION_RE = re.compile(r"\n## ")
SENTINEL_QUERY_RE = re.compile(
    r"\*\*[^*\n]*Sentinel[^*\n]*\*\*\s*\n```kusto\n(.*?)\n```", re.DOTALL | re.IGNORECASE
)


def load_schema() -> dict:
    with SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_rule_files(root: Path) -> list[Path]:
    files = []
    for p in sorted(root.rglob("*.md")):
        if "versions" in p.parts:
            continue
        if p.name in ("README.md", "TEMPLATE.md"):
            continue
        files.append(p)
    return files


def split_frontmatter(text: str) -> tuple[dict, str]:
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("no YAML frontmatter found (expected leading --- ... ---)")
    fm = yaml.safe_load(m.group(1)) or {}
    return fm, m.group(2)


def split_sections(body: str) -> dict[str, str]:
    """Split a markdown body on '## Heading' lines, dropping the H1 title."""
    parts = SECTION_RE.split(body)
    sections = {}
    for part in parts[1:]:
        first_newline = part.find("\n")
        heading = part[:first_newline].strip()
        content = part[first_newline + 1:].rstrip("\n")
        sections[heading] = content
    return sections


def load_rule(path: Path) -> dict:
    """Return the raw frontmatter dict for a rule .md file. Does not
    resolve the query or build the ARM body — see derive_arm_rule for that."""
    text = path.read_text(encoding="utf-8")
    fm, _body = split_frontmatter(text)
    if not isinstance(fm, dict):
        raise ValueError(f"{path}: frontmatter must be a mapping")
    return fm


def is_deployable(rule: dict) -> bool:
    return bool(rule.get("analytics_rule"))


def resolve_query(rule: dict, path: Path) -> str:
    """Extract the Sentinel-labeled ```kusto block from the Query section."""
    text = path.read_text(encoding="utf-8")
    _fm, body = split_frontmatter(text)
    sections = split_sections(body)
    query_section = sections.get("Query")
    if not query_section:
        raise ValueError(f"{path}: no '## Query' section found")
    m = SENTINEL_QUERY_RE.search(query_section)
    if not m:
        raise ValueError(
            f"{path}: no **Sentinel** ```kusto block found in Query section "
            "(a Defender XDR-only page has nothing to deploy)"
        )
    query_text = m.group(1).strip()
    if not query_text:
        raise ValueError(f"{path}: resolved Sentinel query is empty")
    return query_text


def resolve_description(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    _fm, body = split_frontmatter(text)
    sections = split_sections(body)
    summary = sections.get("Summary", "").strip()
    if not summary:
        raise ValueError(f"{path}: no '## Summary' section found")
    return summary


def derive_arm_rule(rule: dict, path: Path) -> dict:
    """Merge frontmatter's narrative fields + analytics_rule block +
    the resolved Sentinel query into one ARM-schema-shaped dict, ready
    for schema validation and deployment."""
    analytics_rule = rule.get("analytics_rule")
    if not analytics_rule:
        raise ValueError(f"{path}: analytics_rule is not set — not deployable")

    severity_key = str(rule.get("severity", "")).lower()
    if severity_key not in SEVERITY_MAP:
        raise ValueError(
            f"{path}: top-level severity '{rule.get('severity')}' has no ARM mapping "
            f"(expected one of {sorted(SEVERITY_MAP)})"
        )

    arm = dict(analytics_rule)
    arm["name"] = rule.get("title", "")
    arm["description"] = resolve_description(path)
    arm["severity"] = SEVERITY_MAP[severity_key]
    arm["query"] = resolve_query(rule, path)
    return arm


def validate_rule(arm_rule: dict, schema: dict, source: str) -> list[str]:
    validator = Draft202012Validator(schema)
    errors = []
    for error in validator.iter_errors(arm_rule):
        location = "/".join(str(p) for p in error.absolute_path) or "<root>"
        errors.append(f"{source}: {location}: {error.message}")
    return errors


def to_arm_body(arm_rule: dict) -> dict[str, Any]:
    kind = arm_rule.pop("kind", "Scheduled")
    # status is ARM lifecycle metadata only, not sent to the API
    arm_rule.pop("status", None)
    return {"kind": kind, "properties": arm_rule}


def alert_rule_url(subscription_id: str, resource_group: str, workspace_name: str, rule_id: str) -> str:
    return (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
        f"?api-version={API_VERSION}"
    )
