# shellcheck shell=bash
# Known vulnerabilities in what is installed on this Mac. The daily job's `vulns` module writes the
# results; `audit` and `mac-secure vulns` only read them.
#
# Results are one tab-separated line per match:
#   location  severity  id  kev|-  malware|-  fix-state  fixed-in  type  package  version  path
# `location` is the scanned directory, or `homebrew` for formulae.
# shellcheck disable=SC2034  # The variables are used by the files that source this one.

MS_VULN_DIR="$MS_STATE_DIR/vulns"
MS_VULN_RESULTS="$MS_VULN_DIR/latest.tsv"
MS_VULN_STAMP="$MS_VULN_DIR/scanned-at"
MS_VULN_COVERAGE="$MS_VULN_DIR/coverage.txt"
MS_VULN_IGNORE="$MS_CONFIG_DIR/vulns-ignore.txt"
MS_VULN_STALE_DAYS=3

# Where tools, runtimes, editor extensions and apps get installed. The scan reads what is installed
# in each, not what a lockfile there declares, so a cloned repository's dependencies do not count.
ms_vuln_targets() {
  local prefix extra path
  cat <<EOF
$HOME/.nvm/versions/node
$HOME/.volta/tools
$HOME/Library/Application Support/fnm
$HOME/.npm/_npx
$HOME/.bun/install/global
$HOME/.local
$HOME/go/bin
$HOME/.cargo/bin
$HOME/Library/Caches/ms-playwright-go
$HOME/.vscode/extensions
$HOME/.cursor/extensions
$HOME/.claude/plugins
${MS_SYSTEM_LIBRARY:-/Library}/Frameworks/Python.framework
${MS_APPLICATIONS_DIR:-/Applications}
EOF
  if command -v brew >/dev/null 2>&1; then
    prefix=$(brew --prefix 2>/dev/null)
    [ -z "$prefix" ] || echo "$prefix/lib"
  fi
  extra=$(ms_config_get VULN_SCAN_PATHS)
  printf '%s\n' "$extra" | tr ':' '\n' | while IFS= read -r path; do
    case "$path" in
      '') ;;
      "~"/*) echo "$HOME/${path#\~/}" ;;
      *) echo "$path" ;;
    esac
  done
}

# The results without the matches listed in vulns-ignore.txt, as `<id>` or `<id>|<path part>|<why>`.
ms_vulns_effective() {
  local ignore=/dev/null
  [ -f "$MS_VULN_RESULTS" ] || return 1
  [ ! -f "$MS_VULN_IGNORE" ] || ignore=$MS_VULN_IGNORE
  awk -F'\t' '
    FILENAME == ARGV[1] {
      if ($0 ~ /^[[:space:]]*(#|$)/) next
      n++
      ids[n] = $0; sub(/\|.*/, "", ids[n]); gsub(/[[:space:]]/, "", ids[n])
      parts[n] = ""
      if (index($0, "|")) { parts[n] = substr($0, index($0, "|") + 1); sub(/\|.*/, "", parts[n]); gsub(/^[[:space:]]+|[[:space:]]+$/, "", parts[n]) }
      next
    }
    {
      for (i = 1; i <= n; i++) if ($3 == ids[i] && (parts[i] == "" || index($11, parts[i]))) next
      print
    }
  ' "$ignore" "$MS_VULN_RESULTS"
}

# One line per critical, known-exploited or malware match, for telling a new one from one already seen.
ms_vuln_urgent_keys() {
  ms_vulns_effective 2>/dev/null |
    awk -F'\t' '$2 == "Critical" || $4 == "kev" || $5 == "malware" { print $1 "|" $3 "|" $9 "|" $10 }' | sort -u
}

ms_vuln_scan_age_days() {
  local stamp
  stamp=$(cat "$MS_VULN_STAMP" 2>/dev/null)
  case "$stamp" in
    ''|*[!0-9]*) return 1 ;;
  esac
  echo $((($(date +%s) - stamp) / 86400))
}

# Prints the matches at or above High, or all of them with "all", whose location, path or package
# contains the filter. Malware matches are always included. Most severe first.
# Usage: ms_vulns_list <all|high> [filter]
ms_vulns_list() {
  ms_vulns_effective | awk -F'\t' -v OFS='\t' -v scope="$1" -v filter="${2:-}" '
    filter != "" && !index($1, filter) && !index($11, filter) && !index($9, filter) { next }
    scope != "all" && $2 != "Critical" && $2 != "High" && $5 != "malware" { next }
    { rank = ($5 == "malware") ? 0 : ($2 == "Critical") ? 1 : ($2 == "High") ? 2 : ($2 == "Medium") ? 3 : ($2 == "Low") ? 4 : 5
      print rank, $0 }
  ' | sort -t "$(printf '\t')" -k1,1n -k2,2 -k10,10 -k11,11 | cut -f2-
}
