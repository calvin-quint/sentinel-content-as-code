"""Shared helpers for loading and transforming YAML analytics rules
into the Microsoft Sentinel (Microsoft.SecurityInsights/alertRules)
REST API request body.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

API_VERSION = "2023-11-01"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "analytics-rule.schema.json"

# Fields that exist in the YAML for documentation purposes only and must
# not be forwarded to the Sentinel API.
METADATA_ONLY_FIELDS = {"status", "requiredDataConnectors"}


def load_schema() -> dict:
    with SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_rule_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.yaml")) + sorted(p for p in root.rglob("*.yml"))


def load_rule(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML content must be a mapping")
    return data


def validate_rule(rule: dict, schema: dict, source: str) -> list[str]:
    validator = Draft202012Validator(schema)
    errors = []
    for error in validator.iter_errors(rule):
        location = "/".join(str(p) for p in error.absolute_path) or "<root>"
        errors.append(f"{source}: {location}: {error.message}")
    return errors


def resolve_query(rule: dict, yaml_path: Path) -> str:
    """Return the KQL query text, loading it from queryFile if used."""
    if "query" in rule:
        return rule["query"]
    query_file = rule.get("queryFile")
    if not query_file:
        raise ValueError(f"{yaml_path}: rule has neither 'query' nor 'queryFile'")
    resolved = (yaml_path.parent / query_file).resolve()
    if not resolved.is_file():
        raise ValueError(f"{yaml_path}: queryFile not found: {resolved}")
    return resolved.read_text(encoding="utf-8")


def to_arm_properties(rule: dict, query_text: str) -> dict[str, Any]:
    """Convert a validated rule dict into Sentinel alertRules API properties."""
    properties: dict[str, Any] = {
        "displayName": rule["name"],
        "description": rule["description"],
        "severity": rule["severity"],
        "enabled": rule.get("enabled", True),
        "query": query_text,
        "queryFrequency": rule["queryFrequency"],
        "queryPeriod": rule["queryPeriod"],
        "triggerOperator": rule["triggerOperator"],
        "triggerThreshold": rule["triggerThreshold"],
        "suppressionEnabled": rule.get("suppressionEnabled", False),
        "suppressionDuration": rule.get("suppressionDuration", "PT5H"),
    }

    for optional_field in (
        "tactics",
        "relevantTechniques",
        "entityMappings",
        "incidentConfiguration",
        "eventGroupingSettings",
        "customDetails",
        "alertDetailsOverride",
    ):
        if optional_field in rule:
            # API field name differs from YAML field name for techniques.
            api_field = "techniques" if optional_field == "relevantTechniques" else optional_field
            properties[api_field] = rule[optional_field]

    return properties


def to_arm_body(rule: dict, yaml_path: Path) -> dict[str, Any]:
    query_text = resolve_query(rule, yaml_path)
    return {
        "kind": rule.get("kind", "Scheduled"),
        "properties": to_arm_properties(rule, query_text),
    }


def alert_rule_url(subscription_id: str, resource_group: str, workspace_name: str, rule_id: str) -> str:
    return (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
        f"?api-version={API_VERSION}"
    )
