# shellcheck shell=bash
# Read-only state. Nothing here writes, asks for a password, or can raise a dialog.

ms_filevault_state() {
  local out
  out=$(fdesetup status 2>/dev/null)
  case "$out" in
    *"FileVault is On"*) echo on ;;
    *"FileVault is Off"*) echo off ;;
    *) echo unknown ;;
  esac
}

ms_firewall_state() {
  local out
  out=$("$MS_FIREWALL" --getglobalstate 2>/dev/null)
  case "$out" in
    *enabled*) echo on ;;
    *disabled*) echo off ;;
    *) echo unknown ;;
  esac
}

ms_gatekeeper_state() {
  local out
  out=$(spctl --status 2>/dev/null)
  case "$out" in
    *"assessments enabled"*) echo on ;;
    *"assessments disabled"*) echo off ;;
    *) echo unknown ;;
  esac
}

ms_sip_state() {
  local out
  out=$(csrutil status 2>/dev/null)
  case "$out" in
    *"status: enabled"*) echo on ;;
    *"status: disabled"*) echo off ;;
    *) echo unknown ;;
  esac
}

# Prints on, off, or unset. Unset means the Mac uses Apple's default for the key.
ms_pref_state() {
  case "$(defaults read "$1" "$2" 2>/dev/null)" in
    1) echo on ;;
    0) echo off ;;
    *) echo unset ;;
  esac
}

ms_macos_auto_install_state() {
  ms_pref_state /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates
}

ms_app_store_auto_state() {
  ms_pref_state /Library/Preferences/com.apple.commerce AutoUpdate
}

ms_agent_loaded() {
  launchctl print "gui/$(id -u)/$1" >/dev/null 2>&1 && echo yes || echo no
}

ms_daemon_loaded() {
  launchctl print "system/$1" >/dev/null 2>&1 && echo yes || echo no
}

# Filters the vendor list the way the root installer does, so it can be compared with the installed copy.
ms_vendor_lines() {
  grep -E '^[a-z0-9][a-z0-9@.+-]*\|[A-Z0-9]{10}$' "$MS_CONFIG_DIR/vendor-installers.txt" 2>/dev/null
}

ms_root_files="macos-update install-root.sh feed-password.exp"

ms_path_is_root_only() {
  [ ! -L "$1" ] && [ "$(stat -f %u "$1")" = 0 ] && [ $((0$(stat -f %Lp "$1") & 022)) -eq 0 ]
}

ms_installed_root_hour() {
  plutil -extract StartCalendarInterval.Hour raw -o - "$MS_ROOT_PLIST" 2>/dev/null
}

# Prints what `refresh` would change in the root job, and nothing when it matches this checkout.
ms_root_job_changes() {
  local name wanted installed hour
  for name in $ms_root_files; do
    cmp -s "$ROOT/root/$name" "$MS_ROOT_LIBEXEC/$name" && continue
    if [ -f "$MS_ROOT_LIBEXEC/$name" ]; then
      diff -u "$MS_ROOT_LIBEXEC/$name" "$ROOT/root/$name"
    else
      echo "New file: $name"
    fi
  done
  wanted=$(ms_vendor_lines)
  installed=$(cat "$MS_ROOT_LIBEXEC/vendor-installers.txt" 2>/dev/null)
  if [ "$wanted" != "$installed" ]; then
    printf 'Vendor installers installed:\n%s\nVendor installers wanted:\n%s\n' "${installed:-(none)}" "${wanted:-(none)}"
  fi
  hour=$(ms_installed_root_hour)
  if [ -n "$hour" ] && [ "$hour" != "$(ms_config_int MACOS_HOUR 3)" ]; then
    echo "Root job hour: installed $hour, wanted $(ms_config_int MACOS_HOUR 3)"
  fi
}

# Prints not-installed, current, or outdated: the installed root job against this checkout and settings.
ms_root_job_state() {
  [ -f "$MS_ROOT_LIBEXEC/macos-update" ] || { echo not-installed; return; }
  if [ -n "$(ms_root_job_changes)" ]; then
    echo outdated
  else
    echo current
  fi
}

ms_last_root_run() {
  grep ' finished;' "$MS_ROOT_LOG" 2>/dev/null | tail -1
}

# The last line wins: the root job records a restart before it starts, and a failure after it.
ms_last_run_field() {
  local results="$MS_STATE_DIR/last-run.tsv"
  [ "$(ms_module_field "$1" 2)" != root ] || results=$MS_ROOT_RESULTS
  awk -F'\t' -v id="$1" -v field="$2" '$2==id{value=$field} END{print value}' "$results" 2>/dev/null
}

ms_yes_no() {
  "$@" && echo yes || echo no
}

ms_status_json() {
  local id first=1
  printf '{"version":%s,"macos":%s,"free_gib":%s,' \
    "$(ms_json_string "$MS_VERSION")" "$(ms_json_string "$(sw_vers -productVersion 2>/dev/null)")" "$(ms_free_gib)"
  printf '"security":{"filevault":"%s","firewall":"%s","gatekeeper":"%s","sip":"%s","macos_auto_install":"%s","app_store_auto_update":"%s"},' \
    "$(ms_filevault_state)" "$(ms_firewall_state)" "$(ms_gatekeeper_state)" "$(ms_sip_state)" \
    "$(ms_macos_auto_install_state)" "$(ms_app_store_auto_state)"
  printf '"jobs":{"daily_loaded":"%s","enforcer_loaded":"%s","root_loaded":"%s","root_job":"%s","last_root_run":%s},' \
    "$(ms_agent_loaded "$MS_LABEL.daily")" "$(ms_agent_loaded "$MS_LABEL.enforcer")" \
    "$(ms_daemon_loaded "$MS_LABEL.macos")" "$(ms_root_job_state)" "$(ms_json_string "$(ms_last_root_run)")"
  printf '"modules":['
  for id in $(ms_module_ids); do
    [ "$first" -eq 1 ] || printf ','
    first=0
    printf '{"id":"%s","scope":"%s","enabled":"%s","available":"%s","last_run":%s,"last_result":%s,"last_detail":%s}' \
      "$id" "$(ms_module_field "$id" 2)" "$(ms_yes_no ms_module_enabled "$id")" "$(ms_yes_no ms_module_available "$id")" \
      "$(ms_json_string "$(ms_last_run_field "$id" 1)")" "$(ms_json_string "$(ms_last_run_field "$id" 3)")" \
      "$(ms_json_string "$(ms_last_run_field "$id" 5)")"
  done
  printf ']}\n'
}

ms_status_text() {
  local id last_root
  printf 'mac-secure %s on macOS %s, %s GiB free\n\n' "$MS_VERSION" "$(sw_vers -productVersion 2>/dev/null)" "$(ms_free_gib)"
  printf '%-22s %s\n' \
    "FileVault" "$(ms_filevault_state)" \
    "Firewall" "$(ms_firewall_state)" \
    "Gatekeeper" "$(ms_gatekeeper_state)" \
    "System Integrity" "$(ms_sip_state)" \
    "macOS auto-install" "$(ms_macos_auto_install_state)" \
    "App Store auto-update" "$(ms_app_store_auto_state)" \
    "Daily job loaded" "$(ms_agent_loaded "$MS_LABEL.daily")" \
    "Enforcer job loaded" "$(ms_agent_loaded "$MS_LABEL.enforcer")" \
    "Root job loaded" "$(ms_daemon_loaded "$MS_LABEL.macos")" \
    "Root job" "$(ms_root_job_state)"
  last_root=$(ms_last_root_run)
  [ -z "$last_root" ] || printf '%-22s %s\n' "Last root run" "$last_root"
  printf '\n%-18s %-5s %-8s %-9s %-17s %s\n' MODULE SCOPE ENABLED RESULT WHEN DETAIL
  for id in $(ms_module_ids); do
    printf '%-18s %-5s %-8s %-9s %-17s %s\n' "$id" "$(ms_module_field "$id" 2)" "$(ms_yes_no ms_module_enabled "$id")" \
      "$(ms_last_run_field "$id" 3)" "$(ms_last_run_field "$id" 1)" "$(ms_last_run_field "$id" 5)"
  done
}
