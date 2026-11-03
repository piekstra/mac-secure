# shellcheck shell=bash
# Tests of BSD tool usage. They run on a Mac only, with the same stubs for anything that changes the system.

fake_app() {
  APP="$TMP/Fake Browser.app"
  mkdir -p "$APP/Contents/MacOS"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>2.0</string></dict></plist>\n' >"$APP/Contents/Info.plist"
  mkdir -p "$HOME/.config/mac-secure"
  echo "Fake Browser|$APP|fake|--restore-last-session" >"$HOME/.config/mac-secure/restart-apps.txt"
  LAST_FAKE_PID=""
}

# Starts a process whose command line reads as the app's executable.
start_fake() {
  ( exec -a "$APP/Contents/MacOS/fake $*" sleep 120 ) >/dev/null 2>&1 &
  LAST_FAKE_PID=$!
  disown "$LAST_FAKE_PID" 2>/dev/null
  sleep 1
}

mark_app_updated() {
  touch -t "$(date -v+1H +%Y%m%d%H%M.%S)" "$APP/Contents/Info.plist"
}

run_enforcer() {
  "$REPO/jobs/enforcer" </dev/null
}

assert_alive() {
  kill -0 "$1" 2>/dev/null || fail "pid $1 was stopped"
  kill "$1" 2>/dev/null
}

assert_stopped() {
  local waited=0
  while kill -0 "$1" 2>/dev/null && [ "$waited" -lt 5 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$1" 2>/dev/null; then
    kill "$1" 2>/dev/null
    fail "pid $1 is still running"
  fi
}

test_enforcer_leaves_a_current_process_alone() {
  fake_app
  start_fake
  GRACE_SECONDS=0 run_enforcer
  assert_alive "$LAST_FAKE_PID"
  assert_not_called 'open'
}

test_enforcer_warns_first_and_keeps_the_app_running_during_grace() {
  fake_app
  start_fake
  mark_app_updated
  GRACE_SECONDS=1800 run_enforcer
  assert_alive "$LAST_FAKE_PID"
  assert_called 'osascript'
  assert_not_called 'open'
  assert_contains "$(cat "$HOME/Library/Logs/mac-secure/enforcer.log")" "restart due in 1800s"
}

test_enforcer_restarts_after_grace_with_the_configured_arguments() {
  fake_app
  start_fake
  mark_app_updated
  GRACE_SECONDS=1800 run_enforcer
  local marker="$HOME/Library/Application Support/mac-secure/stale/Fake Browser.$LAST_FAKE_PID"
  [ -f "$marker" ] || fail "no marker"
  echo $(($(date +%s) - 2000)) >"$marker"
  GRACE_SECONDS=1800 run_enforcer
  assert_stopped "$LAST_FAKE_PID"
  assert_called "open -a $APP --args --restore-last-session"
  [ ! -e "$marker" ] || fail "marker left behind"
}

test_enforcer_leaves_young_automation_alone() {
  fake_app
  start_fake --user-data-dir=/tmp/profile
  mark_app_updated
  GRACE_SECONDS=0 AUTOMATION_MIN_AGE_SECONDS=86400 run_enforcer
  assert_alive "$LAST_FAKE_PID"
  assert_not_called 'open'
}

test_enforcer_stops_old_automation_without_reopening_it() {
  fake_app
  start_fake --user-data-dir=/tmp/profile
  mark_app_updated
  GRACE_SECONDS=1800 AUTOMATION_MIN_AGE_SECONDS=0 run_enforcer
  assert_stopped "$LAST_FAKE_PID"
  assert_not_called 'open'
  assert_not_called 'osascript'
}

test_cask_field_uses_arm64_fields_on_apple_silicon() {
  # shellcheck source=root/macos-update
  . "$REPO/root/macos-update"
  PATH="$STUBS:$PATH"
  assert_eq "https://downloads.example.com/2.0.0/arm64/example.pkg" "$(cask_field "$FIXTURES/cask-pkg.json" url)"
  assert_eq aaaa "$(cask_field "$FIXTURES/cask-pkg.json" sha256)"
}

test_cask_field_uses_the_codename_variation_on_intel() {
  # shellcheck source=root/macos-update
  . "$REPO/root/macos-update"
  PATH="$STUBS:$PATH"
  stub uname 'echo x86_64'
  stub sw_vers 'echo 15.7'
  assert_eq "https://downloads.example.com/2.0.0/x86/example.pkg" "$(cask_field "$FIXTURES/cask-pkg.json" url)"
  assert_eq bbbb "$(cask_field "$FIXTURES/cask-pkg.json" sha256)"
  assert_eq 2.0.0 "$(cask_field "$FIXTURES/cask-pkg.json" version)"
}

test_agents_pass_plutil_lint() {
  mac_secure enable bun browsers --yes >/dev/null
  plutil -lint "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.daily.plist" >/dev/null || fail "daily agent"
  plutil -lint "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.enforcer.plist" >/dev/null || fail "enforcer agent"
}

test_feed_password_answers_only_the_named_prompt() {
  local fake="$TMP/fake" password="$TMP/password" answers="$TMP/answers"
  cat >"$fake" <<STANDIN
#!/bin/bash
printf 'Enter password for someadmin :'; read -rs first; echo
printf 'Enter password for secupdate :'; read -rs second; echo
printf '%s|%s\n' "\$first" "\$second" >'$answers'
exit 7
STANDIN
  chmod +x "$fake"
  printf 'service-secret' >"$password"
  # The outer expect plays the person at the terminal, who answers only the prompt for their own password.
  /usr/bin/expect -c "
    set timeout 15
    log_user 0
    spawn /usr/bin/expect -f $REPO/root/feed-password.exp $password {Enter password for secupdate ?:} $fake
    expect {Enter password for someadmin :}
    send {typed-by-person}
    send \"\r\"
    expect eof
    catch wait result
    exit [lindex \$result 3]
  "
  assert_eq 7 $? "exit status passed through"
  assert_eq "typed-by-person|service-secret" "$(cat "$answers")"
}

test_feed_password_prompt_can_ignore_case() {
  local fake="$TMP/fake" password="$TMP/password" answers="$TMP/answers"
  cat >"$fake" <<STANDIN
#!/bin/bash
printf 'New Password: '; read -rs first; echo
printf '%s\n' "\$first" >'$answers'
STANDIN
  chmod +x "$fake"
  printf 'service-secret' >"$password"
  /usr/bin/expect -c "
    set timeout 15
    log_user 0
    spawn /usr/bin/expect -f $REPO/root/feed-password.exp $password {(?i)password} $fake
    expect eof
  "
  assert_eq service-secret "$(cat "$answers")"
}

test_path_is_root_only() {
  . "$REPO/lib/status.sh"
  ms_path_is_root_only /usr || fail "/usr should pass"
  if ms_path_is_root_only "$TMP"; then
    fail "a directory the user owns should not pass"
  fi
  ln -s /usr "$TMP/link"
  if ms_path_is_root_only "$TMP/link"; then
    fail "a symlink should not pass"
  fi
  # shellcheck source=root/install-root.sh
  . "$REPO/root/install-root.sh"
  set +e
  path_is_root_only /usr || fail "installer: /usr should pass"
  if path_is_root_only "$TMP"; then
    fail "installer: a directory the user owns should not pass"
  fi
}

test_status_reports_a_changed_hour_as_outdated() {
  install_root_copy
  cat >"$MS_ROOT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>StartCalendarInterval</key><dict><key>Hour</key><integer>3</integer></dict></dict></plist>
PLIST
  assert_contains "$(mac_secure status --json)" '"root_job":"current"'
  mkdir -p "$HOME/.config/mac-secure"
  echo MACOS_HOUR=5 >"$HOME/.config/mac-secure/config"
  assert_contains "$(mac_secure status --json)" '"root_job":"outdated"'
}

audit_setup() {
  export MS_SYSTEM_LIBRARY="$TMP/Library"
  mkdir -p "$MS_SYSTEM_LIBRARY/PrivilegedHelperTools" "$MS_SYSTEM_LIBRARY/Extensions" \
    "$MS_SYSTEM_LIBRARY/LaunchDaemons" "$HOME/Library/LaunchAgents"
}

audit_findings() {
  mac_secure audit --json
}

test_audit_reports_core_settings_high_first() {
  audit_setup
  stub fdesetup 'echo "FileVault is Off."'
  stub socketfilterfw 'echo "Firewall is disabled. (State = 0)"'
  stub spctl 'echo "assessments enabled"'
  local out
  out=$(audit_findings)
  assert_json "$out"
  assert_contains "$out" '"id":"filevault-off"'
  assert_contains "$out" '"id":"firewall-off"'
  assert_eq high "$(printf '%s' "$out" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["severity"])')"
}

test_audit_unknown_state_is_not_reported_as_off() {
  audit_setup
  local out
  out=$(audit_findings)
  assert_not_contains "$out" 'filevault-off'
  assert_not_contains "$out" 'firewall-off'
}

test_audit_finds_dead_launch_items() {
  audit_setup
  cat >"$HOME/Library/LaunchAgents/com.example.dead.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.example.dead</string>
<key>ProgramArguments</key><array><string>/nonexistent/agent</string></array></dict></plist>
PLIST
  cat >"$HOME/Library/LaunchAgents/com.example.deadscript.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.example.deadscript</string>
<key>ProgramArguments</key><array><string>/bin/bash</string><string>/nonexistent/script</string></array></dict></plist>
PLIST
  cat >"$HOME/Library/LaunchAgents/com.example.alive.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.example.alive</string>
<key>Program</key><string>/bin/ls</string></dict></plist>
PLIST
  local out
  out=$(audit_findings)
  assert_contains "$out" '/nonexistent/agent'
  assert_contains "$out" '/nonexistent/script'
  assert_not_contains "$out" 'com.example.alive'
}

test_audit_finds_system_extensions_from_the_listing() {
  audit_setup
  stub systemextensionsctl "cat '$FIXTURES/systemextensionsctl-list.txt'"
  local out
  out=$(audit_findings)
  assert_contains "$out" 'com.example.networkextension (1.0.0/100) from team ABCDE12345'
  assert_not_contains "$out" 'bundleID'
}

test_audit_finds_apps_by_architecture_and_dangling_links() {
  audit_setup
  local app
  for app in Old New; do
    mkdir -p "$MS_APPLICATIONS_DIR/$app.app/Contents/MacOS"
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleExecutable</key><string>%s</string></dict></plist>\n' "$app" >"$MS_APPLICATIONS_DIR/$app.app/Contents/Info.plist"
    touch "$MS_APPLICATIONS_DIR/$app.app/Contents/MacOS/$app"
  done
  ln -s /nonexistent/Gone.app "$MS_APPLICATIONS_DIR/Gone.app"
  stub file 'case "$2" in *Old) echo "Mach-O 64-bit executable x86_64" ;; *) echo "Mach-O universal binary with 2 architectures: [x86_64] [arm64]" ;; esac'
  local out
  out=$(audit_findings)
  assert_contains "$out" 'Old.app is Intel-only'
  assert_not_contains "$out" 'New.app is Intel-only'
  assert_contains "$out" 'Gone.app points at nothing'
}

test_audit_skips_loopback_listeners() {
  audit_setup
  stub lsof "cat '$FIXTURES/lsof-listen.txt'"
  local out
  out=$(audit_findings)
  assert_contains "$out" 'exampled accepts connections'
  assert_not_contains "$out" 'localhost accepts'
  assert_not_contains "$out" 'localsix accepts'
}

# Usage: fake_bundle <path to .app> <version>
fake_bundle() {
  mkdir -p "$1/Contents"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>%s</string></dict></plist>\n' "$2" >"$1/Contents/Info.plist"
}

playwright_cache_setup() {
  CACHE=${1:-$HOME/Library/Caches/ms-playwright}
  fake_bundle "$CACHE/chromium-1200/chrome-mac-arm64/Google Chrome for Testing.app" 143.0.7499.4
  fake_bundle "$CACHE/chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app" 156.0.8078.4
  fake_bundle "$CACHE/firefox-1509/firefox/Nightly.app" 146.0.1
  fake_bundle "$CACHE/firefox-1555/firefox/Nightly.app" 152.0
  mkdir -p "$CACHE/.links" "$HOME/old copy/playwright-core"
  cp "$FIXTURES/playwright-browsers.json" "$HOME/old copy/playwright-core/browsers.json"
  echo "$HOME/old copy/playwright-core" >"$CACHE/.links/aaa"
  echo "$TMP/deleted/playwright-core" >"$CACHE/.links/bbb"
}

test_audit_finds_playwright_builds_older_than_the_installed_browser() {
  audit_setup
  playwright_cache_setup
  fake_bundle "$MS_APPLICATIONS_DIR/Google Chrome.app" 156.0.8078.80
  local out
  out=$(audit_findings)
  assert_contains "$out" "Playwright's Chromium 143.0.7499.4 (chromium-1200) is older than Google Chrome 156"
  assert_contains "$out" "Update or remove the Playwright copies that use it: ~/old copy/playwright-core."
  assert_not_contains "$out" "(chromium-1248)"
  assert_contains "$out" "Playwright's Firefox 146.0.1 (firefox-1509) is older than the newest build Playwright has here, 152"
  assert_not_contains "$out" "(firefox-1555)"
}

test_audit_names_the_newer_reference_when_the_installed_browser_is_behind() {
  audit_setup
  playwright_cache_setup
  fake_bundle "$MS_APPLICATIONS_DIR/Google Chrome.app" 150.0.1
  fake_bundle "$MS_APPLICATIONS_DIR/Firefox.app" 160.0
  local out
  out=$(audit_findings)
  assert_contains "$out" "Playwright's Chromium 143.0.7499.4 (chromium-1200) is older than the newest build Playwright has here, 156"
  assert_not_contains "$out" "older than Google Chrome"
  assert_contains "$out" "Playwright's Firefox 152.0 (firefox-1555) is older than Firefox 160"
}

test_audit_reads_the_playwright_cache_the_environment_names() {
  audit_setup
  playwright_cache_setup "$TMP/pw browsers"
  export PLAYWRIGHT_BROWSERS_PATH="$TMP/pw browsers"
  assert_contains "$(audit_findings)" "(chromium-1200) is older than"
  export PLAYWRIGHT_BROWSERS_PATH=0
  assert_not_contains "$(audit_findings)" "stale-playwright-browser"
}

test_audit_does_not_call_a_build_unused_when_a_browser_list_is_unreadable() {
  audit_setup
  playwright_cache_setup
  echo '{"browsers": [' >"$HOME/old copy/playwright-core/browsers.json"
  local out
  out=$(audit_findings)
  assert_contains "$out" "Which copies use it is unknown, since these copies could not be read: ~/old copy/playwright-core."
  assert_not_contains "$out" "No installed copy of Playwright uses it"
}

test_audit_does_not_read_a_playwright_copy_in_a_protected_folder() {
  audit_setup
  playwright_cache_setup
  mkdir -p "$HOME/Documents/project/playwright-core"
  cp "$FIXTURES/playwright-browsers.json" "$HOME/Documents/project/playwright-core/browsers.json"
  echo "$HOME/Documents/project/playwright-core" >"$CACHE/.links/aaa"
  local out
  out=$(audit_findings)
  assert_contains "$out" "Which copies use it is unknown, since these copies could not be read: ~/Documents/project/playwright-core."
}

test_audit_does_not_check_a_playwright_cache_in_a_protected_folder() {
  audit_setup
  export PLAYWRIGHT_BROWSERS_PATH="$HOME/Documents/pw-browsers"
  playwright_cache_setup "$HOME/Documents/pw-browsers"
  local out
  out=$(audit_findings)
  assert_contains "$out" "Playwright's browser builds in $HOME/Documents/pw-browsers were not checked"
  assert_not_contains "$out" "stale-playwright-browser"
}

test_audit_does_not_call_a_build_unused_when_its_copy_is_on_a_missing_volume() {
  audit_setup
  playwright_cache_setup
  echo "/srv/build/playwright-core" >"$CACHE/.links/aaa"
  local out
  out=$(audit_findings)
  assert_contains "$out" "Which copies use it is unknown, since these copies could not be read: /srv/build/playwright-core."
  assert_not_contains "$out" "No installed copy of Playwright uses it"
}

test_audit_checks_a_headless_shell_build_by_its_recorded_version() {
  audit_setup
  playwright_cache_setup
  mkdir -p "$CACHE/chromium_headless_shell-1190/chrome-headless-shell-mac-arm64" "$CACHE/chromium_headless_shell-1200"
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); d["browsers"][1].update(revision="1190", browserVersion="142.0.7444.0"); json.dump(d, open(sys.argv[2], "w"), indent=2)' \
    "$FIXTURES/playwright-browsers.json" "$HOME/old copy/playwright-core/browsers.json"
  fake_bundle "$MS_APPLICATIONS_DIR/Google Chrome.app" 156.0.8078.80
  local out
  out=$(audit_findings)
  assert_contains "$out" "Playwright's Chromium headless shell 142.0.7444.0 (chromium_headless_shell-1190) is older than Google Chrome 156"
  assert_not_contains "$out" "(chromium_headless_shell-1200)"
}

test_audit_checks_the_default_cache_and_the_one_the_environment_names() {
  audit_setup
  playwright_cache_setup
  playwright_cache_setup "$TMP/other cache"
  export PLAYWRIGHT_BROWSERS_PATH="$TMP/other cache"
  local out
  out=$(audit_findings)
  assert_eq 2 "$(printf '%s' "$out" | grep -o '(chromium-1200) is older' | wc -l | tr -d ' ')" "chromium-1200 findings"
}

test_audit_reports_a_playwright_build_it_cannot_read() {
  audit_setup
  playwright_cache_setup
  mkdir -p "$CACHE/chromium-1100/chrome-mac-arm64"
  assert_contains "$(audit_findings)" "could not be read, so they were not compared with the installed browsers: chromium-1100."
}

test_audit_names_no_copy_for_an_unused_playwright_build() {
  audit_setup
  playwright_cache_setup
  rm "$CACHE/.links/aaa"
  local out
  out=$(audit_findings)
  assert_contains "$out" "Playwright's Chromium 143.0.7499.4 (chromium-1200) is older than the newest build Playwright has here, 156"
  assert_contains "$out" "No installed copy of Playwright uses it: rm -r '$CACHE/chromium-1200'"
}

test_audit_changes_nothing() {
  audit_setup
  audit_findings >/dev/null
  assert_not_called 'sudo'
  assert_not_called 'defaults write'
  assert_not_called 'launchctl bootstrap'
  [ ! -e "$HOME/.config" ] || fail "audit created config"
}
