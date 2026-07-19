#!/usr/bin/env python3
"""Deploy a Logic App playbook definition to Azure.

Usage: deploy-playbook.py <path/to/definition.json>

Required env vars:
  AZURE_SUBSCRIPTION_ID
  RESOURCE_GROUP
  WORKSPACE_NAME

Optional env vars (default shown):
  AZURE_LOCATION         eastus
  PLAYBOOK_NAME_PREFIX   SOAR

Trigger URL secrets (set the ones you have; unset ones leave the placeholder):
  C1_TRIGGER_URL, C2_TRIGGER_URL, C4_TRIGGER_URL, C5_TRIGGER_URL,
  C6_TRIGGER_URL, C10_TRIGGER_URL
"""

import json
import os
import subprocess
import sys


PLACEHOLDERS = {
    "__SUBSCRIPTION_ID__": "AZURE_SUBSCRIPTION_ID",
    "__RESOURCE_GROUP__": "RESOURCE_GROUP",
    "__WORKSPACE_NAME__": "WORKSPACE_NAME",
    "__TENANT_DOMAIN__": "TENANT_DOMAIN",
    "__AUTOMATION_SENDER_UPN__": "AUTOMATION_SENDER_UPN",
    "__SERVICEDESK_EMAIL__": "SERVICEDESK_EMAIL",
    "__SYNC_APP_NAME__": "SYNC_APP_NAME",
    "__C1_TRIGGER_URL__": "C1_TRIGGER_URL",
    "__C2_TRIGGER_URL__": "C2_TRIGGER_URL",
    "__C3_TRIGGER_URL__": "C3_TRIGGER_URL",
    "__C4_TRIGGER_URL__": "C4_TRIGGER_URL",
    "__C5_TRIGGER_URL__": "C5_TRIGGER_URL",
    "__C6_TRIGGER_URL__": "C6_TRIGGER_URL",
    "__C7_TRIGGER_URL__": "C7_TRIGGER_URL",
    "__C10_TRIGGER_URL__": "C10_TRIGGER_URL",
}

REQUIRED_ENV = ("AZURE_SUBSCRIPTION_ID", "RESOURCE_GROUP", "WORKSPACE_NAME")


def main(definition_path: str) -> None:
    for var in REQUIRED_ENV:
        if not os.environ.get(var):
            sys.exit(f"ERROR: required environment variable {var} is not set")

    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    resource_group = os.environ["RESOURCE_GROUP"]
    location = os.environ.get("AZURE_LOCATION", "eastus")
    prefix = os.environ.get("PLAYBOOK_NAME_PREFIX", "SOAR")

    # Derive Logic App name from directory: playbooks/children/C1-Enrich-IP/definition.json -> SOAR-C1-Enrich-IP
    parts = definition_path.rstrip("/").split("/")
    dir_name = parts[-2]
    logic_app_name = f"{prefix}-{dir_name}" if prefix else dir_name

    with open(definition_path) as f:
        content = f.read()

    for placeholder, env_var in PLACEHOLDERS.items():
        value = os.environ.get(env_var, "")
        if not value and placeholder in content:
            print(f"WARNING: {placeholder} found in {definition_path} but {env_var} is not set", file=sys.stderr)
        content = content.replace(placeholder, value)

    try:
        playbook_def = json.loads(content)
    except json.JSONDecodeError as e:
        sys.exit(f"ERROR: invalid JSON in {definition_path} after substitution: {e}")

    if "definition" not in playbook_def:
        sys.exit(f"ERROR: {definition_path} missing top-level 'definition' key")

    arm_body = {
        "location": location,
        "properties": {
            "definition": playbook_def["definition"],
            "parameters": playbook_def.get("parameters", {}),
        },
    }

    resource_url = (
        f"https://management.azure.com"
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Logic/workflows/{logic_app_name}"
        f"?api-version=2019-05-01"
    )

    print(f"Deploying {logic_app_name} to {resource_group}...")

    result = subprocess.run(
        [
            "az", "rest",
            "--method", "PUT",
            "--url", resource_url,
            "--body", json.dumps(arm_body),
            "--headers", "Content-Type=application/json",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(f"ERROR: failed to deploy {logic_app_name} (exit {result.returncode})")

    try:
        response = json.loads(result.stdout)
        provisioning_state = (
            response.get("properties", {}).get("provisioningState", "unknown")
        )
        print(f"OK: {logic_app_name} — provisioningState={provisioning_state}")
    except json.JSONDecodeError:
        print(f"OK: {logic_app_name} deployed (response not JSON)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <path/to/definition.json>")
    main(sys.argv[1])
