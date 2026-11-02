# shellcheck shell=bash
# Shared by the CLI and the per-user jobs. The root job never sources this file: it may only run
# root-owned code, and this file can live in a user-writable checkout.
# shellcheck disable=SC2034  # The variables are used by the files that source this one.

MS_VERSION=0.1.0
MS_LABEL=io.github.piekstra.mac-secure
MS_CONFIG_DIR="$HOME/.config/mac-secure"
MS_STATE_DIR="$HOME/Library/Application Support/mac-secure"
MS_LOG_DIR="$HOME/Library/Logs/mac-secure"
MS_AGENT_DIR="$HOME/Library/LaunchAgents"
MS_ROOT_LIBEXEC=${MS_ROOT_LIBEXEC:-/usr/local/libexec/mac-secure}
MS_ROOT_CONF="$MS_ROOT_LIBEXEC/root.conf"
MS_ROOT_LOG=${MS_ROOT_LOG:-/var/log/mac-secure/macos.log}
MS_ROOT_RESULTS=${MS_ROOT_RESULTS:-/var/log/mac-secure/last-run.tsv}
MS_ROOT_PLIST=${MS_ROOT_PLIST:-/Library/LaunchDaemons/$MS_LABEL.macos.plist}
# What sudo runs. These ignore the environment overrides above, and PATH can lead with directories
# the user can write to, where a planted sudo would receive the typed password.
MS_SUDO=/usr/bin/sudo
MS_INSTALLED_ROOT_JOB=/usr/local/libexec/mac-secure/macos-update
MS_FIREWALL=${MS_FIREWALL:-/usr/libexec/ApplicationFirewall/socketfilterfw}
MS_OSASCRIPT=${MS_OSASCRIPT:-/usr/bin/osascript}

# Reads one KEY=value line. The file is never sourced, so a value cannot run code.
ms_config_get() {
  local key=$1 default=${2:-} value=""
  if [ -f "$MS_CONFIG_DIR/config" ]; then
    value=$(sed -n "s/^$key=//p" "$MS_CONFIG_DIR/config" | tail -1)
  fi
  printf '%s' "${value:-$default}"
}

# A value that is not a whole number falls back to the default, so a typo cannot break a job.
ms_config_int() {
  local value
  value=$(ms_config_get "$1" "$2")
  case "$value" in
    ''|*[!0-9]*) printf '%s' "$2" ;;
    *) printf '%s' "$value" ;;
  esac
}

# launchd gives a job only the system directories.
ms_tool_path() {
  local extra
  extra=$(ms_config_get EXTRA_PATH)
  printf '%s' "${MS_JOB_PATH:-${extra:+$extra:}/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:$HOME/.cargo/bin:$HOME/.bun/bin:$HOME/.local/bin:$HOME/google-cloud-sdk/bin:/usr/bin:/bin:/usr/sbin:/sbin}"
}

ms_free_gib() {
  { df -k /System/Volumes/Data 2>/dev/null || df -k /; } | awk 'NR==2{printf "%d",$4/1048576}'
}

# Bounded, because a notification call waiting on a permission dialog would otherwise hold a job
# and its lock until someone answers. terminal-notifier does exactly that, so it is not used.
ms_notify() {
  local pid waited=0 limit=${MS_NOTIFY_WAIT:-15}
  "$MS_OSASCRIPT" -e 'on run argv' -e 'display notification (item 2 of argv) with title (item 1 of argv)' -e 'end run' "$1" "$2" >/dev/null 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$limit" ]; do
    sleep 1
    waited=$((waited + 1))
  done
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 0
}

# Prints this user's processes running from an app in /Applications, optionally limited to a
# subdirectory of Contents. A literal prefix, so another copy of the app or a file open in an editor
# does not match, and a name like "Foo (Beta).app" is not read as a pattern.
# Usage: ms_app_pids <Foo.app> [MacOS/]
ms_app_pids() {
  local prefix="/Applications/$1/Contents/${2:-}" pid command
  # shellcheck disable=SC2034  # command is matched below; it is not an executed command.
  ps -U "$(id -u)" -ww -o pid=,command= | while read -r pid command; do
    case "$command" in
      "$prefix"*) echo "$pid" ;;
    esac
  done
}

ms_json_string() {
  printf '"'
  printf '%s' "$1" | tr '\t\n' '  ' | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
  printf '"'
}

ms_die() {
  printf 'mac-secure: %s\n' "$*" >&2
  exit 2
}
