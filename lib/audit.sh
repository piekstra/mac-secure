# shellcheck shell=bash
# Read-only findings about this Mac. A check reports what it sees and how to act on it; nothing here
# changes anything. Without root, the listener check sees only the current user's processes.

MS_APPLICATIONS_DIR=${MS_APPLICATIONS_DIR:-/Applications}
MS_SYSTEM_LIBRARY=${MS_SYSTEM_LIBRARY:-/Library}
MS_OLD_HELPER_YEARS=3

# Usage: finding <high|medium|low|info> <id> <what was found> <how to act on it>
finding() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$MS_AUDIT_OUT"
}

audit_core() {
  [ "$(ms_filevault_state)" != off ] || finding high filevault-off "FileVault is off." "System Settings, Privacy & Security, FileVault."
  [ "$(ms_gatekeeper_state)" != off ] || finding high gatekeeper-off "Gatekeeper is off." "sudo spctl --global-enable"
  [ "$(ms_sip_state)" != off ] || finding high sip-off "System Integrity Protection is off." "In Recovery, run: csrutil enable"
  [ "$(ms_firewall_state)" != off ] || finding medium firewall-off "The firewall is off." "mac-secure enable firewall"
  [ "$(ms_macos_auto_install_state)" != off ] || finding medium macos-auto-install-off "macOS updates do not install automatically." "mac-secure enable macos"
  [ "$(ms_app_store_auto_state)" != off ] || finding low app-store-auto-off "App Store apps do not update automatically." "mac-secure enable app-store"
  if [ -n "$(defaults read "$MS_SYSTEM_LIBRARY/Preferences/com.apple.loginwindow" autoLoginUser 2>/dev/null)" ]; then
    finding high auto-login-on "This Mac logs in by itself at startup, without a password." "System Settings, Users & Groups, Automatically log in as: Off."
  fi
  if [ "$(defaults read "$MS_SYSTEM_LIBRARY/Preferences/com.apple.loginwindow" GuestEnabled 2>/dev/null)" = 1 ]; then
    finding low guest-account-on "The guest account is on." "System Settings, Users & Groups, Guest User."
  fi
  local pending
  pending=$(defaults read "$MS_SYSTEM_LIBRARY/Preferences/com.apple.SoftwareUpdate" LastRecommendedUpdatesAvailable 2>/dev/null)
  case "$pending" in
    ''|0|*[!0-9]*) ;;
    *) finding medium macos-updates-pending "macOS updates waiting: $pending, as of the last check by macOS." "softwareupdate --list" ;;
  esac
  [ "$(ms_root_job_state)" != outdated ] || finding medium root-job-outdated "The installed root job differs from this checkout." "Run mac-secure refresh, which shows the changes. Review them before approving."
  if [ -f "$MS_ROOT_LIBEXEC/macos-update" ]; then
    local path
    for path in /usr/local /usr/local/libexec "$MS_ROOT_LIBEXEC"; do
      [ -e "$path" ] || continue
      ms_path_is_root_only "$path" || finding high root-job-path-unsafe "$path is not writable by root alone, so another user could replace the root job." "sudo chown root:wheel $path; sudo chmod go-w $path"
    done
  fi
}

audit_management() {
  local out
  out=$(profiles status -type enrollment 2>/dev/null)
  case "$out" in
    *"MDM enrollment: Yes"*) finding medium mdm-enrolled "This Mac is enrolled in device management, which can change its settings remotely." "If it is not your organization's Mac, ask the previous owner to release it." ;;
  esac
}

audit_accounts() {
  local me name uid
  me=$(id -un)
  while read -r name uid; do
    case "$uid" in ''|*[!0-9]*) continue ;; esac
    [ "$uid" -ge 501 ] || continue
    [ "$name" != "$me" ] || continue
    [ "$name" != secupdate ] || ! ms_root_enabled macos-unattended || continue
    if dseditgroup -o checkmember -m "$name" admin 2>/dev/null | grep -q '^yes'; then
      finding medium other-admin-account "Another admin account exists: $name." "If nobody uses it, remove it in System Settings, Users & Groups."
    else
      finding info other-account "Another account exists: $name." "If nobody uses it, remove it in System Settings, Users & Groups."
    fi
  done <<EOF
$(dscl . list /Users UniqueID 2>/dev/null)
EOF
}

audit_sharing() {
  if nc -z -G 1 127.0.0.1 22 >/dev/null 2>&1; then
    finding low remote-login-on "Remote Login (SSH) is accepting connections." "If unused: System Settings, General, Sharing, Remote Login."
  fi
  if nc -z -G 1 127.0.0.1 5900 >/dev/null 2>&1; then
    finding low screen-sharing-on "Screen Sharing is accepting connections." "If unused: System Settings, General, Sharing, Screen Sharing."
  fi
}

launch_item_program() {
  local plist=$1 program script
  program=$(ms_plist_value "$plist" Program) ||
    program=$(ms_plist_value "$plist" ProgramArguments.0) || return 1
  case "$program" in
    /bin/sh|/bin/bash|/bin/zsh)
      script=$(ms_plist_value "$plist" ProgramArguments.1) && program=$script
      ;;
  esac
  printf '%s' "$program"
}

audit_launch_items() {
  local dir plist program
  for dir in "$HOME/Library/LaunchAgents" "$MS_SYSTEM_LIBRARY/LaunchAgents" "$MS_SYSTEM_LIBRARY/LaunchDaemons"; do
    for plist in "$dir"/*.plist; do
      [ -f "$plist" ] || continue
      program=$(launch_item_program "$plist") || continue
      case "$program" in /*) ;; *) continue ;; esac
      [ ! -e "$program" ] || continue
      finding low dead-launch-item "$plist runs $program, which does not exist." "launchctl bootout, then delete the plist. Items under /Library need sudo."
    done
  done
}

audit_system_extensions() {
  local team bundle
  while IFS=$'\t' read -r _ _ team bundle _; do
    case "$bundle" in *.*) ;; *) continue ;; esac
    finding medium system-extension "System extension $bundle from team $team is active. Network and security extensions can see traffic or files." "If you do not use it: System Settings, General, Login Items & Extensions."
  done <<EOF
$(systemextensionsctl list 2>/dev/null | grep -F 'activated enabled')
EOF
}

audit_root_helpers() {
  local helper year this_year severity
  this_year=$(date +%Y)
  for helper in "$MS_SYSTEM_LIBRARY/PrivilegedHelperTools"/*; do
    [ -f "$helper" ] || continue
    year=$(stat -f %Sm -t %Y "$helper" 2>/dev/null) || continue
    severity=info
    [ $((this_year - year)) -le "$MS_OLD_HELPER_YEARS" ] || severity=medium
    finding "$severity" root-helper "$(basename "$helper"), dated $year, runs as root when called." "If its app is gone or unused, remove the helper and its LaunchDaemon."
  done
}

audit_kexts() {
  local kext
  for kext in "$MS_SYSTEM_LIBRARY/Extensions"/*.kext; do
    [ -d "$kext" ] || continue
    finding info kernel-extension "Third-party kernel extension installed: $(basename "$kext")." "If unused, remove it with its vendor's uninstaller."
  done
}

audit_apps() {
  local app executable arch
  arch=$(uname -m)
  for app in "$MS_APPLICATIONS_DIR"/*.app; do
    if [ -L "$app" ] && [ ! -e "$app" ]; then
      finding low dangling-app-link "$app points at nothing." "Delete the link."
      continue
    fi
    [ "$arch" = arm64 ] || continue
    [ -f "$app/Contents/Info.plist" ] || continue
    executable=$(ms_plist_value "$app/Contents/Info.plist" CFBundleExecutable) || continue
    [ -f "$app/Contents/MacOS/$executable" ] || continue
    case "$(file -b "$app/Contents/MacOS/$executable")" in
      *x86_64*)
        case "$(file -b "$app/Contents/MacOS/$executable")" in
          *arm64*) ;;
          *) finding low intel-only-app "$(basename "$app") is Intel-only, so it runs under Rosetta and its vendor has not shipped a native build." "Update it, or remove it if unused." ;;
        esac
        ;;
    esac
  done
}

audit_listeners() {
  local listeners command address
  listeners=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1, $9}' | sort -u)
  while read -r command address; do
    case "$address" in
      ''|127.*|\[::1\]*|localhost*) continue ;;
    esac
    finding info network-listener "$command accepts connections from other machines on $address." "If unexpected, stop the program or block it in the firewall."
  done <<EOF
$listeners
EOF
}

audit_stale_browsers() {
  local list="$MS_CONFIG_DIR/restart-apps.txt" name app binary updated_at pid dow month day clock year rest started
  [ -f "$list" ] || list="$ROOT/config/restart-apps.default"
  while IFS='|' read -r name app binary _; do
    case "$name" in ''|\#*) continue ;; esac
    [ -f "$app/Contents/Info.plist" ] || continue
    updated_at=$(stat -f %m "$app/Contents/Info.plist")
    while read -r pid dow month day clock year rest; do
      case "$rest" in
        "$app/Contents/MacOS/$binary"|"$app/Contents/MacOS/$binary "*) ;;
        *) continue ;;
      esac
      started=$(LC_ALL=C date -j -f '%a %b %e %T %Y' "$dow $month $day $clock $year" +%s 2>/dev/null) || continue
      if [ "$started" -lt "$updated_at" ]; then
        finding medium stale-browser "$name (pid $pid) is running code older than its installed update." "Restart it, or: mac-secure enable browsers"
      fi
    done <<EOF
$(LC_ALL=C ps -U "$(id -u)" -ww -o pid=,lstart=,command=)
EOF
  done <"$list"
}

audit_homebrew() {
  command -v brew >/dev/null 2>&1 || return 0
  local formulae casks
  formulae=$(HOMEBREW_NO_AUTO_UPDATE=1 brew outdated --formula --quiet 2>/dev/null | wc -l | tr -d ' ')
  casks=$(HOMEBREW_NO_AUTO_UPDATE=1 brew outdated --cask --greedy-auto-updates --quiet 2>/dev/null | wc -l | tr -d ' ')
  if [ "$formulae" -gt 0 ] || [ "$casks" -gt 0 ]; then
    finding medium homebrew-outdated "Homebrew outdated: $formulae formulae and $casks casks, as of its last update." "mac-secure enable brew-formulae brew-casks"
  fi
}

ms_audit_collect() {
  MS_AUDIT_OUT=$1
  audit_core
  audit_management
  audit_accounts
  audit_sharing
  audit_launch_items
  audit_system_extensions
  audit_root_helpers
  audit_kexts
  audit_apps
  audit_listeners
  audit_stale_browsers
  audit_homebrew
}

# Most severe first.
ms_audit_sorted() {
  awk -F'\t' '{r=($1=="high"?0:$1=="medium"?1:$1=="low"?2:3); print r"\t"$0}' "$1" | sort -s -n -k1,1 | cut -f2-
}

ms_audit_json() {
  local severity id what fix first=1
  printf '['
  while IFS=$'\t' read -r severity id what fix; do
    [ -n "$id" ] || continue
    [ "$first" -eq 1 ] || printf ','
    first=0
    printf '{"severity":"%s","id":"%s","finding":%s,"action":%s}' "$severity" "$id" "$(ms_json_string "$what")" "$(ms_json_string "$fix")"
  done <<EOF
$(ms_audit_sorted "$1")
EOF
  printf ']\n'
}

ms_audit_text() {
  local severity id what fix total
  total=$(wc -l <"$1" | tr -d ' ')
  if [ "$total" -eq 0 ]; then
    echo "No findings."
    return
  fi
  printf '%s findings: %s high, %s medium, %s low, %s info\n\n' "$total" \
    "$(grep -c '^high' "$1")" "$(grep -c '^medium' "$1")" "$(grep -c '^low' "$1")" "$(grep -c '^info' "$1")"
  while IFS=$'\t' read -r severity id what fix; do
    [ -n "$id" ] || continue
    printf '%-7s %-24s %s\n%32s%s\n' "$severity" "$id" "$what" "" "$fix"
  done <<EOF
$(ms_audit_sorted "$1")
EOF
}
