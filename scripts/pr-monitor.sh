#!/usr/bin/env bash
# PR status monitor for spaceapp#260
# Checks CI status and review state; logs changes to local files only.

set -euo pipefail

REPO="oll4com/spaceapp"
PR="260"
STATE_FILE="/workspace/.bounty-monitor/pr-${PR}-status.json"
LOG_FILE="/workspace/.bounty-monitor/pr-${PR}-status.log"
TOKEN_FILE="/workspace/.gh-pat"

export GH_TOKEN="${GH_TOKEN:-$(cat "$TOKEN_FILE")}"

mkdir -p "$(dirname "$STATE_FILE")"

# Fetch current PR state, checks, and reviews.
pr_json=$(gh pr view "$PR" -R "$REPO" --json state,mergeStateStatus,mergeable,reviewDecision,statusCheckRollup,reviews,createdAt,updatedAt 2>/dev/null || echo "{}")

timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Normalize checks for comparison.
checks=$(echo "$pr_json" | jq -c '[.statusCheckRollup // [] | .[] | {name: (.context // .name // "unknown"), status: (.state // .status // "UNKNOWN")}] | sort_by(.name)')

# Normalize reviews for comparison.
reviews=$(echo "$pr_json" | jq -c '[.reviews // [] | .[] | {author: .author.login, state: .state}] | sort_by(.author + .state)')

current=$(jq -n \
  --arg timestamp "$timestamp" \
  --argjson pr "$pr_json" \
  --argjson checks "$checks" \
  --argjson reviews "$reviews" \
  '{
    timestamp: $timestamp,
    state: ($pr.state // "UNKNOWN"),
    mergeStateStatus: ($pr.mergeStateStatus // "UNKNOWN"),
    mergeable: ($pr.mergeable // "UNKNOWN"),
    reviewDecision: ($pr.reviewDecision // "UNKNOWN"),
    checks: $checks,
    reviews: $reviews,
    prUpdatedAt: ($pr.updatedAt // null)
  }')

# Compare with previous state (if any) using only the fields that matter.
if [ -f "$STATE_FILE" ]; then
  prev_checks=$(jq -c '.checks // []' "$STATE_FILE")
  prev_reviews=$(jq -c '.reviews // []' "$STATE_FILE")
  prev_decision=$(jq -r '.reviewDecision // "UNKNOWN"' "$STATE_FILE")
  prev_state=$(jq -r '.state // "UNKNOWN"' "$STATE_FILE")

  current_checks=$(echo "$current" | jq -c '.checks')
  current_reviews=$(echo "$current" | jq -c '.reviews')
  current_decision=$(echo "$current" | jq -r '.reviewDecision')
  current_state=$(echo "$current" | jq -r '.state')

  changed=false
  [ "$prev_state" != "$current_state" ] && changed=true
  [ "$prev_decision" != "$current_decision" ] && changed=true
  [ "$prev_checks" != "$current_checks" ] && changed=true
  [ "$prev_reviews" != "$current_reviews" ] && changed=true

  if [ "$changed" = true ]; then
    echo "[${timestamp}] PR #${PR} state changed" >> "$LOG_FILE"
    {
      echo "State:        ${current_state}"
      echo "Mergeable:    ${current_state} / mergeState: $(echo "$current" | jq -r '.mergeStateStatus')"
      echo "Review:       ${current_decision}"
      echo "Checks:"
      echo "$current" | jq -r '.checks[] | "  - \(.name): \(.status)"'
      echo "Reviews:"
      echo "$current" | jq -r '.reviews[] | "  - \(.author): \(.state)"'
      echo "---"
    } >> "$LOG_FILE"
  fi
else
  {
    echo "[${timestamp}] Initial PR #${PR} status recorded"
    echo "State:        $(echo "$current" | jq -r '.state')"
    echo "Review:       $(echo "$current" | jq -r '.reviewDecision')"
    echo "Checks:"
    echo "$current" | jq -r '.checks[] | "  - \(.name): \(.status)"'
    echo "---"
  } >> "$LOG_FILE"
fi

echo "$current" > "$STATE_FILE"

# Print concise summary for Schedule logs.
echo "PR #${PR} state: $(echo "$current" | jq -r '.state') | review: $(echo "$current" | jq -r '.reviewDecision') | checks:"
echo "$current" | jq -r '.checks[] | "  \(.name): \(.status)"'
