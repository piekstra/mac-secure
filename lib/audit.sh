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

# Looking inside these can raise a macOS privacy prompt for whatever app runs audit, or reach a
# network or removable volume, so a Playwright copy or cache there is reported as unknown, not read.
playwright_path_is_protected() {
  case "$1" in
    "$HOME/Desktop" | "$HOME/Desktop/"* | "$HOME/Documents" | "$HOME/Documents/"* | "$HOME/Downloads" | "$HOME/Downloads/"* | \
      "$HOME/Pictures" | "$HOME/Pictures/"* | "$HOME/Music" | "$HOME/Music/"* | "$HOME/Movies" | "$HOME/Movies/"* | \
      "$HOME/Library/Mobile Documents/"* | "$HOME/Library/CloudStorage/"* | /Volumes/* | /Network/* | /net/*) return 0 ;;
  esac
  return 1
}

# Where a missing copy can be taken as deleted: places that are always mounted and never guarded.
playwright_path_can_vanish() {
  case "$1" in
    "$HOME/"* | /private/tmp/* | /tmp/* | /private/var/folders/* | /var/folders/* | /opt/* | /usr/local/* | /Library/* | /Applications/*) return 0 ;;
  esac
  return 1
}

# Prints "<build folder>|<copy path>|<browser version>" for each build an installed copy of Playwright
# needs, and "unreadable|<copy path>|" for a copy whose list could not be read. Each file in .links
# holds the path of one copy, whose browsers.json names each build and its browser version.
playwright_build_users() {
  local link path i name revision version found
  for link in "$1/.links"/*; do
    [ -f "$link" ] || continue
    path=$(cat "$link")
    if playwright_path_is_protected "$path"; then
      echo "unreadable|$path|"
      continue
    fi
    if [ ! -d "$path" ]; then
      playwright_path_can_vanish "$path" || echo "unreadable|$path|"
      continue
    fi
    i=0 found=0
    while [ "$i" -lt 100 ] && name=$(ms_plist_value "$path/browsers.json" "browsers.$i.name"); do
      found=1
      case "$name" in
        chromium | chromium-headless-shell | firefox)
          revision=$(ms_plist_value "$path/browsers.json" "browsers.$i.revision") &&
            version=$(ms_plist_value "$path/browsers.json" "browsers.$i.browserVersion" || true) &&
            echo "$(echo "$name" | tr '-' '_')-$revision|$path|$version"
          ;;
      esac
      i=$((i + 1))
    done
    [ "$found" -eq 1 ] || echo "unreadable|$path|"
  done
}

# Prints "<kind>|<build folder>|<version>" for each build in the cache, and "unknown|<build folder>|"
# for one whose version could not be read. A headless shell sharing its revision with a full Chromium
# build is the same browser, so only the full build is listed.
playwright_cache_builds() {
  local cache=$1 users=$2 dir build kind plist version
  for dir in "$cache"/chromium-[0-9]* "$cache"/chromium_headless_shell-[0-9]* "$cache"/firefox-[0-9]*; do
    [ -d "$dir" ] || continue
    build=$(basename "$dir")
    kind=${build%-*}
    case "$kind" in chromium_headless_shell) [ ! -d "$cache/chromium-${build##*-}" ] || continue ;; esac
    version=""
    for plist in "$dir"/chrome-mac*/*.app/Contents/Info.plist "$dir"/firefox/*.app/Contents/Info.plist; do
      [ -f "$plist" ] || continue
      version=$(ms_plist_value "$plist" CFBundleShortVersionString) && break
    done
    # A headless shell has no app bundle; the copies that use a build record its version.
    [ -n "$version" ] || version=$(printf '%s\n' "$users" | awk -F'|' -v b="$build" '$1 == b && $3 != "" { print $3; exit }')
    case "${version%%.*}" in
      '' | *[!0-9]*) echo "unknown|$build|" ;;
      *) echo "$kind|$build|$version" ;;
    esac
  done
}

# No package scanner identifies Playwright's own browser builds. One older than the installed
# browser, or than the newest build Playwright has in the same cache, lacks the security fixes
# released since. Playwright deletes a build once no installed copy needs it, so the finding names
# those copies. Both the default cache and PLAYWRIGHT_BROWSERS_PATH are checked, since the daily job
# and the person's shell may install into different ones.
audit_playwright_browsers() {
  local cache=$HOME/Library/Caches/ms-playwright
  audit_playwright_cache "$cache"
  case "${PLAYWRIGHT_BROWSERS_PATH:-0}" in
    0 | "$cache" | "$cache/") ;;
    *)
      if playwright_path_is_protected "${PLAYWRIGHT_BROWSERS_PATH%/}"; then
        finding low playwright-cache-not-checked "Playwright's browser builds in ${PLAYWRIGHT_BROWSERS_PATH%/} were not checked: looking there can raise a privacy prompt, or it is a removable or network volume." "Run npx playwright install from a terminal with access to it, which deletes builds no copy needs."
      else
        audit_playwright_cache "${PLAYWRIGHT_BROWSERS_PATH%/}"
      fi
      ;;
  esac
}

# Usage: version_older <a> <b>   true when dotted version a is older than b.
version_older() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    n = split(a, x, "."); m = split(b, y, ".")
    for (i = 1; i <= (n > m ? n : m); i++) {
      if (x[i] + 0 < y[i] + 0) exit 0
      if (x[i] + 0 > y[i] + 0) exit 1
    }
    exit 1
  }'
}

# Prints the newest version among the builds of one kind. Usage: newest_build_version <builds> <kind pattern>
newest_build_version() {
  printf '%s\n' "$1" | awk -F'|' -v k="$2" '
    function older(a, b,    x, y, n, m, i) {
      n = split(a, x, "."); m = split(b, y, ".")
      for (i = 1; i <= (n > m ? n : m); i++) { if (x[i] + 0 < y[i] + 0) return 1; if (x[i] + 0 > y[i] + 0) return 0 }
      return 0
    }
    $1 ~ k { if (best == "" || older(best, $3)) best = $3 }
    END { print best }'
}

audit_playwright_cache() {
  local cache=$1 builds users unreadable unknown kind build version newest label browser reference installed used_by action severity
  [ -d "$cache" ] || return 0
  users=$(playwright_build_users "$cache")
  builds=$(playwright_cache_builds "$cache" "$users")
  [ -n "$builds" ] || return 0
  unreadable=$(printf '%s\n' "$users" | awk -F'|' -v home="$HOME" '
    $1 == "unreadable" { p = index($2, home "/") == 1 ? "~" substr($2, length(home) + 1) : $2; out = out (out == "" ? "" : ", ") p }
    END { print out }')
  unknown=$(printf '%s\n' "$builds" | awk -F'|' '$1 == "unknown" { out = out (out == "" ? "" : ", ") $2 } END { print out }')
  [ -z "$unknown" ] || finding low playwright-browser-unreadable "The version of these Playwright browser builds in $cache could not be read, so they were not compared with the installed browsers: $unknown." "If no Playwright copy uses them, delete them. Otherwise run npx playwright install, which deletes builds no copy needs."
  while IFS='|' read -r kind build version; do
    case "$kind" in chromium | chromium_headless_shell | firefox) ;; *) continue ;; esac
    if [ "$kind" = firefox ]; then
      label=Firefox browser=Firefox
      newest=$(newest_build_version "$builds" '^firefox$')
    else
      label=Chromium browser="Google Chrome"
      [ "$kind" = chromium ] || label="Chromium headless shell"
      newest=$(newest_build_version "$builds" '^chromium')
    fi
    # The reference is whichever is newer, the installed browser or the newest cached build, compared
    # by full version: Chrome ships security fixes in updates within a major version.
    reference="the newest build Playwright has here,"
    installed=$(ms_plist_value "$MS_APPLICATIONS_DIR/$browser.app/Contents/Info.plist" CFBundleShortVersionString) || installed=""
    case "${installed%%.*}" in
      '' | *[!0-9]*) ;;
      *) if ! version_older "$installed" "$newest"; then newest=$installed reference=$browser; fi ;;
    esac
    version_older "$version" "$newest" || continue
    severity=medium
    [ "${version%%.*}" -lt "${newest%%.*}" ] || severity=low
    used_by=$(printf '%s\n' "$users" | awk -F'|' -v b="$build" -v home="$HOME" '
      $1 == b { p = index($2, home "/") == 1 ? "~" substr($2, length(home) + 1) : $2; out = out (out == "" ? "" : ", ") p }
      END { print out }')
    if [ -n "$used_by" ] && [ "$version" = "$(newest_build_version "$builds" "^$kind\$")" ]; then
      # The newest build Playwright has is older than the installed browser: no update fixes it yet.
      action="No newer Playwright build is here yet; one comes with a later Playwright release. Copies that use it: $used_by."
      [ "$kind" = firefox ] || action="$action To run them on the installed Google Chrome, which updates itself, set channel: 'chrome' in their Playwright config."
    elif [ -n "$used_by" ]; then
      action="Update or remove the Playwright copies that use it: $used_by. Playwright deletes a build once no copy needs it."
    elif [ -n "$unreadable" ]; then
      action="Which copies use it is unknown, since these copies could not be read: $unreadable. After updating them, npx playwright install deletes builds no copy needs."
    else
      action="No installed copy of Playwright uses it: rm -r '$cache/$build'"
    fi
    finding "$severity" stale-playwright-browser "Playwright's $label $version ($build) is older than $reference $newest, so it lacks the security fixes released since." "$action"
  done <<EOF
$builds
EOF
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

# One finding per scanned location with critical or high matches, and one per malware match.
# With the module off, earlier results are not reported: nothing refreshes them, so they would read
# as current.
audit_vulns() {
  local age what action
  if ! ms_user_enabled vulns; then
    finding low vuln-scan-off "Installed tools, packages and apps are not checked for known vulnerabilities." "brew install grype syft; mac-secure enable vulns"
    return 0
  fi
  if ! ms_module_available vulns; then
    finding medium vuln-scan-missing "The vulns module is on, but $(ms_module_missing_tool vulns) is not installed, so nothing is scanned." "brew install grype syft"
    return 0
  fi
  if [ ! -f "$MS_VULN_RESULTS" ]; then
    finding medium vuln-scan-missing "The vulns module is on, but no scan has finished." "mac-secure run vulns, then: mac-secure logs daily"
    return 0
  fi
  cat "$MS_VULN_LOCATION_GAPS" "$MS_VULN_GAPS" 2>/dev/null | while IFS=$'\t' read -r what action; do
    [ -z "$what" ] || finding low vuln-coverage-gap "$what" "$action"
  done
  if ! age=$(ms_vuln_scan_age_days); then
    finding medium vuln-scan-stale "No vulnerability scan has finished every location, so some may not have been checked." "mac-secure logs daily, or: mac-secure run vulns"
  elif [ "$age" -gt "$MS_VULN_STALE_DAYS" ]; then
    finding medium vuln-scan-stale "The last complete vulnerability scan is $age days old, so newer advisories are not reflected." "mac-secure logs daily, or: mac-secure run vulns"
  fi
  ms_vulns_effective | awk -F'\t' -v home="$HOME" '
    function show(p) { return index(p, home "/") == 1 ? "~" substr(p, length(home) + 1) : p }
    function label(t) { return t == "homebrew" ? "Homebrew formulae" : show(t) }
    function count_of(n, one, many) { return n " " (n == 1 ? one : many) }
    # What to update or remove: the first directory or file under the location, or the first two
    # when the first only groups others, such as bin, share or Versions. A formula for Homebrew.
    function unit(t, path, name,    rel, n, parts) {
      if (t == "homebrew") return name
      rel = substr(path, length(t) + 2)
      n = split(rel, parts, "/")
      if (n >= 2 && parts[1] ~ /^(bin|lib|libexec|share|Versions|node_modules|pipx|venvs|tools)$/) return parts[1] "/" parts[2]
      return parts[1]
    }
    $5 == "malware" {
      if (!(($3, $11) in seen)) {
        seen[$3, $11] = 1
        printf "high\tmalware-package\t%s %s at %s matches malware advisory %s.\tCheck that the advisory applies to this copy. If it does, remove it and change the credentials your account can read.\n", $9, $10, show($11), $3
      }
      next
    }
    $2 != "Critical" && $2 != "High" { if (!($1 in quiet)) { quiet[$1] = 1; nquiet++ } if (!(($3, $9, $10) in lowseen)) { lowseen[$3, $9, $10] = 1; lower++ } next }
    {
      t = $1; pkg = $9 " " $10; part = unit(t, $11, $9)
      if (!(t in vulns)) order[++nt] = t
      # A vulnerability counts once per package version, however many copies of it are installed.
      if (!((t, $3, pkg) in seen_vuln)) { seen_vuln[t, $3, pkg] = 1; vulns[t]++ }
      if (!((t, pkg) in seen_pkg)) { seen_pkg[t, pkg] = 1; npkg[t]++ }
      if (!((t, part) in per)) units[t, ++nunits[t]] = part
      if (!((t, part, $3, pkg) in seen_unit)) { seen_unit[t, part, $3, pkg] = 1; per[t, part]++ }
      if ($4 == "kev" && !((t, $3) in kevseen)) { kevseen[t, $3] = 1; if (++nkev[t] <= 2) kevids[t] = kevids[t] (nkev[t] > 1 ? ", " : "") $3 }
      if ($2 == "Critical" && $6 == "fixed") fixable[t]++
    }
    END {
      for (i = 1; i <= nt; i++) {
        t = order[i]; top = ""
        for (k = 1; k <= 3; k++) {
          best = ""; most = 0
          for (j = 1; j <= nunits[t]; j++) { u = units[t, j]; if (per[t, u] > most && !((t, u) in used)) { best = u; most = per[t, u] } }
          if (best == "") break
          used[t, best] = 1
          top = top (top == "" ? "" : ", ") best " (" most ")"
        }
        what = sprintf("%s: %s in %s", label(t), count_of(vulns[t], "critical or high vulnerability", "critical or high vulnerabilities"),
          count_of(npkg[t], "package", "packages"))
        if (nkev[t] > 0) what = what sprintf(", %d known to be exploited (%s%s)", nkev[t], kevids[t], nkev[t] > 2 ? ", ..." : "")
        printf "%s\tvulnerable-software\t%s. Most affected: %s.\tmac-secure vulns %s lists each one and the version that fixes it. Update what you use and remove what you do not.\n",
          (nkev[t] > 0 || fixable[t] > 0) ? "high" : "medium", what, top, (t == "homebrew" ? "homebrew" : show(t))
      }
      if (lower > 0) printf "info\tlower-vulnerabilities\t%s in %s.\tmac-secure vulns --all\n",
        count_of(lower, "medium, low or unscored vulnerability", "medium, low or unscored vulnerabilities"), count_of(nquiet, "location", "locations")
    }
  ' >>"$MS_AUDIT_OUT"
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
  audit_playwright_browsers
  audit_homebrew
  audit_vulns
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
