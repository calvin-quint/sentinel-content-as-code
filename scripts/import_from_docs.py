#!/usr/bin/env python3
"""One-off/repeatable importer: turns hand-written .kql detections from
calvin-quint/docs (01-detection-engineering/kql/**) into paired
<rule>.kql + <rule>.yaml files under rules/analytics/, parsing the
standard header-comment convention used there:

  // Author: ...
  // GitHub: ...
  // <Title>
  // MITRE ATT&CK: <Tactic> — <desc> (Txxxx); <Tactic> — ... (Txxxx)
  // Detects: <free text, may wrap multiple lines>
  // Severity: <Sev> | Frequency: <ISO8601> | Period: <ISO8601>   [optional]
  // Entity mapping: <Type> → <identifier> → <ColumnName>          [optional, may repeat]

Files whose header signals they are a lookup/enrichment template
rather than a standalone alert (filename contains "lookup", or the
Detects text says as much) are copied as plain .kql hunting queries
instead of wrapped in an analytics-rule YAML.

Usage:
  import_from_docs.py <source_kql_dir> <dest_rules_dir> <dest_hunting_dir>
"""
from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

import yaml

KEYWORDS = {
    "MITRE ATT&CK:": "mitre",
    "Detects:": "detects",
    "Entity mapping:": "entity",
    "Severity:": "severity_line",
    "Custom details:": "custom",
    "Suppression:": "suppression_line",
    "Replaces:": "replaces",
    "Threshold confirmed:": "threshold",
}

TACTIC_MAP = {
    "reconnaissance": "Reconnaissance",
    "resource development": "ResourceDevelopment",
    "initial access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege escalation": "PrivilegeEscalation",
    "defense evasion": "DefenseEvasion",
    "credential access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral movement": "LateralMovement",
    "collection": "Collection",
    "command and control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

VALID_ENTITY_TYPES = {
    "Account", "Host", "IP", "Malware", "File", "Process", "CloudApplication",
    "DNS", "AzureResource", "FileHash", "RegistryKey", "RegistryValue",
    "SecurityGroup", "URL", "Mailbox", "MailCluster", "MailMessage",
    "SubmissionMail",
}

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
SEV_FREQ_RE = re.compile(
    r"(?P<sev>\w+)\s*\|\s*Frequency:\s*(?P<freq>\S+)\s*\|\s*Period:\s*(?P<period>\S+)"
)
LOOKUP_HINTS = ("lookup", "not a standalone alert", "rather than a standalone alert")


def slugify(stem: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", stem).strip("-").lower()
    return re.sub(r"-{2,}", "-", slug)


def parse_header(lines: list[str]) -> dict:
    title_parts: list[str] = []
    sections: dict[str, list[str]] = {}
    current: str | None = None

    for raw in lines:
        if not raw.startswith("//"):
            break
        content = raw[2:].strip()
        if not content:
            continue
        if content.startswith("Author:") or content.startswith("GitHub:"):
            current = None
            continue

        matched_keyword = None
        for kw, section in KEYWORDS.items():
            if content.startswith(kw):
                matched_keyword = (kw, section)
                break

        if matched_keyword:
            kw, section = matched_keyword
            current = section
            remainder = content[len(kw):].strip()
            sections.setdefault(section, [])
            if remainder:
                sections[section].append(remainder)
            continue

        if current is None:
            title_parts.append(content)
        else:
            sections.setdefault(current, []).append(content)

    return {
        "title": " ".join(title_parts).strip(),
        "mitre": " ".join(sections.get("mitre", [])).strip(),
        "detects": " ".join(sections.get("detects", [])).strip(),
        "entity_lines": sections.get("entity", []),
        "severity_line": " ".join(sections.get("severity_line", [])).strip(),
    }


def extract_tactics_and_techniques(mitre_text: str) -> tuple[list[str], list[str]]:
    lowered = mitre_text.lower()
    found = []
    for phrase, enum_val in TACTIC_MAP.items():
        idx = lowered.find(phrase)
        if idx != -1:
            found.append((idx, enum_val))
    found.sort(key=lambda t: t[0])
    tactics = list(dict.fromkeys(v for _, v in found))
    techniques = list(dict.fromkeys(TECHNIQUE_RE.findall(mitre_text)))
    return tactics, techniques


def extract_entity_mappings(entity_lines: list[str]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    order: list[str] = []
    for line in entity_lines:
        parts = [p.strip() for p in line.split("→")]
        if len(parts) != 3:
            continue
        entity_type, identifier, column = parts
        if entity_type not in VALID_ENTITY_TYPES:
            print(f"  ! skipping unrecognized entity type in mapping: {line!r}")
            continue
        if entity_type not in grouped:
            grouped[entity_type] = []
            order.append(entity_type)
        if len(grouped[entity_type]) < 3:
            grouped[entity_type].append({"identifier": identifier, "columnName": column})
    return [{"entityType": t, "fieldMappings": grouped[t]} for t in order]


def existing_id(dest_yaml: Path) -> str | None:
    if not dest_yaml.is_file():
        return None
    try:
        with dest_yaml.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("id") if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        return None


def is_lookup_only(stem: str, detects_text: str) -> bool:
    haystack = f"{stem} {detects_text}".lower()
    return any(hint in haystack for hint in LOOKUP_HINTS)


def import_file(src: Path, category: str, dest_rules_dir: Path, dest_hunting_dir: Path) -> None:
    raw = src.read_text(encoding="utf-8")
    lines = raw.splitlines()
    header = parse_header(lines)
    slug = slugify(src.stem)

    if is_lookup_only(src.stem, header["detects"]):
        out_dir = dest_hunting_dir / category
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{slug}.kql").write_text(raw, encoding="utf-8")
        print(f"[hunting] {src.relative_to(src.parents[2])} -> {out_dir.name}/{slug}.kql")
        return

    out_dir = dest_rules_dir / category
    out_dir.mkdir(parents=True, exist_ok=True)
    kql_name = f"{slug}.kql"
    yaml_path = out_dir / f"{slug}.yaml"

    (out_dir / kql_name).write_text(raw, encoding="utf-8")

    tactics, techniques = extract_tactics_and_techniques(header["mitre"])
    entity_mappings = extract_entity_mappings(header["entity_lines"])

    sev_match = SEV_FREQ_RE.search(header["severity_line"]) if header["severity_line"] else None
    if sev_match:
        severity = sev_match.group("sev").capitalize()
        frequency = sev_match.group("freq")
        period = sev_match.group("period")
        defaulted = False
    else:
        severity, frequency, period = "Medium", "PT1H", "PT1H"
        defaulted = True

    rule_id = existing_id(yaml_path) or str(uuid.uuid4())

    rule: dict = {
        "id": rule_id,
        "name": header["title"] or src.stem,
        "description": header["detects"] or header["title"] or src.stem,
        "severity": severity,
        "status": "Available",
        "enabled": True,
        "queryFile": kql_name,
        "queryFrequency": frequency,
        "queryPeriod": period,
        "triggerOperator": "gt",
        "triggerThreshold": 0,
        "suppressionEnabled": False,
        "suppressionDuration": "PT5H",
    }
    if tactics:
        rule["tactics"] = tactics
    if techniques:
        rule["relevantTechniques"] = techniques
    if entity_mappings:
        rule["entityMappings"] = entity_mappings

    header_comment = (
        "# yaml-language-server: $schema=../../../schemas/analytics-rule.schema.json\n"
        f"# Imported from calvin-quint/docs: 01-detection-engineering/kql/{category}/{src.name}\n"
    )
    if defaulted:
        header_comment += (
            "# NOTE: source had no explicit Severity/Frequency/Period header — "
            "defaulted to Medium/PT1H/PT1H, review before relying on it.\n"
        )

    with yaml_path.open("w", encoding="utf-8") as f:
        f.write(header_comment)
        yaml.safe_dump(rule, f, sort_keys=False, width=100, allow_unicode=True)

    print(f"[rule]     {src.relative_to(src.parents[2])} -> {category}/{slug}.yaml (+ .kql)")


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 1

    source_dir = Path(sys.argv[1])
    dest_rules_dir = Path(sys.argv[2])
    dest_hunting_dir = Path(sys.argv[3])

    for category_dir in sorted(p for p in source_dir.iterdir() if p.is_dir()):
        category = category_dir.name
        for kql_file in sorted(category_dir.glob("*.kql")):
            import_file(kql_file, category, dest_rules_dir, dest_hunting_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
