# shellcheck shell=bash
# Puts the per-user jobs in place. Root steps are in root/install-root.sh.

MS_APP_DIR="$MS_STATE_DIR/app"
MS_POLICY_MARKER="$MS_STATE_DIR/browser-policy-set"

ms_chromium_browsers() {
  cat <<'EOF'
com.google.Chrome|Google Chrome.app
com.microsoft.Edge|Microsoft Edge.app
com.brave.Browser|Brave Browser.app
EOF
}

ms_xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# Jobs run from a copy, so switching branches or moving the checkout does not change what runs at
# night. The old copy is moved aside whole, so a job in progress keeps reading the files it started with.
ms_install_app_copy() {
  local new="$MS_APP_DIR.new" old="$MS_APP_DIR.old"
  rm -rf "$new" "$old"
  mkdir -p "$new/lib" "$new/jobs" "$new/config"
  cp "$ROOT/lib/common.sh" "$ROOT/lib/modules.sh" "$new/lib/"
  cp "$ROOT/jobs/daily" "$ROOT/jobs/enforcer" "$new/jobs/"
  cp "$ROOT/config/restart-apps.default" "$new/config/"
  chmod 755 "$new/jobs/daily" "$new/jobs/enforcer"
  if [ -d "$MS_APP_DIR" ]; then
    mv "$MS_APP_DIR" "$old"
  fi
  mv "$new" "$MS_APP_DIR"
  rm -rf "$old"
}

# Usage: ms_write_agent <label suffix> <job name> <launchd schedule XML>
ms_write_agent() {
  local label="$MS_LABEL.$1" job=$2 schedule=$3 plist domain
  plist="$MS_AGENT_DIR/$label.plist"
  domain="gui/$(id -u)"
  mkdir -p "$MS_AGENT_DIR" "$MS_LOG_DIR"
  cat >"$plist.new" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$(ms_xml_escape "$MS_APP_DIR/jobs/$job")</string>
  </array>
$schedule
  <key>StandardOutPath</key><string>$(ms_xml_escape "$MS_LOG_DIR/$job.launchd.log")</string>
  <key>StandardErrorPath</key><string>$(ms_xml_escape "$MS_LOG_DIR/$job.launchd.log")</string>
</dict>
</plist>
EOF
  plutil -lint "$plist.new" >/dev/null || ms_die "could not write a valid $plist"
  launchctl bootout "$domain/$label" 2>/dev/null
  mv -f "$plist.new" "$plist"
  launchctl bootstrap "$domain" "$plist" || ms_die "launchctl could not load $label"
}

ms_remove_agent() {
  local label="$MS_LABEL.$1"
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null
  rm -f "$MS_AGENT_DIR/$label.plist"
}

ms_any_daily_module_enabled() {
  local id
  for id in $(ms_module_ids); do
    [ "$(ms_module_field "$id" 2)" = user ] || continue
    [ "$id" != browsers ] || continue
    ms_user_enabled "$id" && return 0
  done
  return 1
}

# launchd runs a calendar job on wake when the Mac slept through its time.
ms_sync_user_jobs() {
  local hour minute interval
  ms_install_app_copy
  hour=$(ms_config_int DAILY_HOUR 4)
  minute=$(ms_config_int DAILY_MINUTE 15)
  interval=$(ms_config_int ENFORCER_INTERVAL 900)
  if ms_any_daily_module_enabled; then
    ms_write_agent daily daily "  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>$hour</integer><key>Minute</key><integer>$minute</integer></dict>"
  else
    ms_remove_agent daily
  fi
  if ms_user_enabled browsers; then
    ms_write_agent enforcer enforcer "  <key>StartInterval</key><integer>$interval</integer>
  <key>RunAtLoad</key><true/>"
    ms_set_browser_policy
  else
    ms_remove_agent enforcer
    ms_clear_browser_policy
  fi
}

# Chromium browsers restart themselves on this policy, which covers any window the enforcer's next
# check has not reached. A browser installed later gets it at the next refresh. The marker lists the
# browsers this tool set it for, so a value the user or their organization set is left in place.
ms_set_browser_policy() {
  local domain app period
  period=$(($(ms_config_int GRACE_SECONDS 1800) * 1000))
  mkdir -p "$MS_STATE_DIR"
  while IFS='|' read -r domain app; do
    [ -d "${MS_APPLICATIONS_DIR:-/Applications}/$app" ] || continue
    if ! grep -qxF "$domain" "$MS_POLICY_MARKER" 2>/dev/null; then
      defaults read "$domain" RelaunchNotification >/dev/null 2>&1 && continue
      echo "$domain" >>"$MS_POLICY_MARKER"
    fi
    defaults write "$domain" RelaunchNotification -int 2
    defaults write "$domain" RelaunchNotificationPeriod -int "$period"
  done <<EOF
$(ms_chromium_browsers)
EOF
}

ms_clear_browser_policy() {
  [ -f "$MS_POLICY_MARKER" ] || return 0
  local domain
  while IFS= read -r domain; do
    defaults delete "$domain" RelaunchNotification 2>/dev/null
    defaults delete "$domain" RelaunchNotificationPeriod 2>/dev/null
  done <"$MS_POLICY_MARKER"
  rm -f "$MS_POLICY_MARKER"
}

ms_enabled_add() {
  mkdir -p "$MS_CONFIG_DIR"
  grep -qxF "$1" "$MS_CONFIG_DIR/enabled" 2>/dev/null || echo "$1" >>"$MS_CONFIG_DIR/enabled"
}

ms_enabled_remove() {
  [ -f "$MS_CONFIG_DIR/enabled" ] || return 0
  grep -vxF "$1" "$MS_CONFIG_DIR/enabled" >"$MS_CONFIG_DIR/enabled.new"
  mv -f "$MS_CONFIG_DIR/enabled.new" "$MS_CONFIG_DIR/enabled"
}
