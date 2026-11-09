#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/checkpoint.sh"

parse_common_args "$@"
init_workspace

F="$WS/exploit/findings-raw.md"
V="$WS/report/validation.md"
mkdir -p "$WS/report"
echo "# validation ($(date -u +%FT%TZ)) target=$TARGET" > "$V"

[[ -s "$F" ]] || { echo "no findings-raw.md — nothing to validate" | tee -a "$V"; exit 0; }

log "adversarial re-check of candidates in findings-raw.md"

grep -oE "\*\*[^*]+\*\*" "$F" 2>/dev/null | sed 's/\*\*//g' | sort -u > "$WS/report/candidates.txt" || true
N=$(wc -l < "$WS/report/candidates.txt" 2>/dev/null || echo 0)
echo "candidates: $N" | tee -a "$V"

PROOF_MARKERS="root:x:|UPL_|Dump completed|hostname output|uid=[0-9]"
while IFS= read -r cand; do
  [[ -z "$cand" ]] && continue
  line=$(grep -F "$cand" "$F" | head -1 || true)
  if echo "$line" | grep -qE "$PROOF_MARKERS"; then
    echo "CONFIRMED-PROOF: $cand" >> "$V"
  elif echo "$cand" | grep -qiE "candidate|possible|real\?"; then
    echo "UNPROVEN (needs standalone repro): $cand" >> "$V"
  elif echo "$cand" | grep -qiE "negative|soft404|absent"; then
    echo "INFO/negative: $cand" >> "$V"
  else
    echo "RE-CHECK NEEDED: $cand" >> "$V"
  fi
done < "$WS/report/candidates.txt"

{
echo ""
echo "## standing rules"
echo "- status-code diff alone is NOT proof"
echo "- unproven → severity Low"
echo "- one standalone repro per finding before report"
} >> "$V"

log "validation → $V"
mark_phase_done report
