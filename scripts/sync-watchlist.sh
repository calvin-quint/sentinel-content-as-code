#!/usr/bin/env bash
set -euo pipefail

# Usage: ./sync-watchlist.sh <WatchlistAlias>
# Env required: AZURE_SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME

ALIAS="${1:?Watchlist alias required}"
FILE="watchlists/${ALIAS}.csv"

if [[ ! -f "$FILE" ]]; then
  echo "Error: $FILE not found"
  exit 1
fi

declare -A DISPLAY_NAMES=(
  ["TrustedIPs"]="Trusted IPs"
  ["ServiceAccounts"]="Service Accounts"
  ["PrivilegedAccounts"]="Privileged Accounts"
  ["PlaybookOverride"]="Playbook Override"
  ["SanctionedTools"]="Sanctioned Tools"
)

DISPLAY="${DISPLAY_NAMES[$ALIAS]:-$ALIAS}"

# JSON-encode the CSV content to safely embed in the request body
RAW_CONTENT=$(python3 -c "
import json, sys
with open('$FILE', encoding='utf-8-sig') as f:
    print(json.dumps(f.read()))
")

URL="https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/watchlists/${ALIAS}?api-version=2023-02-01"

az rest \
  --method PUT \
  --url "$URL" \
  --body "{
    \"properties\": {
      \"displayName\": \"${DISPLAY}\",
      \"provider\": \"${ORG_NAME:-GitHub}\",
      \"itemsSearchKey\": \"SearchKey\",
      \"rawContent\": ${RAW_CONTENT},
      \"contentType\": \"text/csv\"
    }
  }"

echo "✓ ${ALIAS} synced to Sentinel"
