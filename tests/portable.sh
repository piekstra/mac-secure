# shellcheck shell=bash
# Tests that run anywhere, including on the Linux CI runner.

# --- configuration and registry

test_config_value_is_never_executed() {
  . "$REPO/lib/common.sh"
  mkdir -p "$MS_CONFIG_DIR"
  # shellcheck disable=SC2016
  printf 'EVIL=$(touch %s/pwned)\n' "$TMP" >"$MS_CONFIG_DIR/config"
  local value
  value=$(ms_config_get EVIL)
  assert_contains "$value" 'touch'
  [ ! -e "$TMP/pwned" ] || fail "config value ran"
}

test_config_int_rejects_non_numbers() {
  . "$REPO/lib/common.sh"
  mkdir -p "$MS_CONFIG_DIR"
  printf 'GOOD=42\nBAD=12x\n' >"$MS_CONFIG_DIR/config"
  assert_eq 42 "$(ms_config_int GOOD 1)"
  assert_eq 1 "$(ms_config_int BAD 1)"
  assert_eq 7 "$(ms_config_int MISSING 7)"
}

test_every_user_module_has_an_implementation() {
  . "$REPO/lib/common.sh"
  . "$REPO/lib/modules.sh"
  local id fn
  for id in $(ms_module_ids); do
    [ "$(ms_module_field "$id" 2)" = user ] || continue
    [ "$id" != browsers ] || continue
    fn="ch_$(echo "$id" | tr '-' '_')"
    grep -q "^$fn()" "$REPO/jobs/daily" || fail "$id has no $fn in jobs/daily"
  done
}

test_every_root_module_is_known_to_the_installer() {
  . "$REPO/lib/common.sh"
  . "$REPO/lib/modules.sh"
  local id modules
  modules=$(grep '^ROOT_MODULES=' "$REPO/root/install-root.sh")
  for id in $(ms_module_ids); do
    [ "$(ms_module_field "$id" 2)" = root ] || continue
    assert_contains "$modules" "$id" "ROOT_MODULES"
  done
}

test_every_module_has_six_fields_and_a_stated_disruption() {
  . "$REPO/lib/common.sh"
  . "$REPO/lib/modules.sh"
  local bad
  bad=$(ms_modules | awk -F'|' 'NF!=6 || $6==""')
  assert_eq "" "$bad" "malformed registry lines"
}

test_disruptive_opt_in_modules_are_not_recommended() {
  . "$REPO/lib/common.sh"
  . "$REPO/lib/modules.sh"
  local id
  for id in macos-unattended macos-major adopt-apps vendor-installers cargo-local colima; do
    assert_eq no "$(ms_module_field "$id" 4)" "$id recommended"
  done
}

test_readme_documents_every_module() {
  . "$REPO/lib/common.sh"
  . "$REPO/lib/modules.sh"
  local id
  for id in $(ms_module_ids); do
    grep -qF "\`$id\`" "$REPO/README.md" || fail "README.md does not list $id"
  done
}

# --- read-only commands

install_root_copy() {
  mkdir -p "$MS_ROOT_LIBEXEC"
  cp "$REPO/root/macos-update" "$REPO/root/install-root.sh" "$REPO/root/feed-password.exp" "$MS_ROOT_LIBEXEC/"
}

test_modules_json_is_valid() {
  local out
  out=$(mac_secure modules --json)
  assert_json "$out"
  assert_contains "$out" '"id":"macos-unattended"'
}

test_status_json_is_valid_and_reports_state() {
  stub fdesetup 'echo "FileVault is On."'
  stub socketfilterfw 'echo "Firewall is disabled. (State = 0)"'
  stub spctl 'echo "assessments enabled"'
  stub csrutil 'echo "System Integrity Protection status: enabled."'
  stub sw_vers 'echo 26.1'
  stub launchctl 'exit 1'
  local out
  out=$(mac_secure status --json)
  assert_json "$out"
  assert_contains "$out" '"filevault":"on"'
  assert_contains "$out" '"firewall":"off"'
  assert_contains "$out" '"root_job":"not-installed"'
}

test_status_changes_nothing() {
  mac_secure status --json >/dev/null
  mac_secure status >/dev/null
  assert_not_called "sudo"
  assert_not_called "launchctl bootstrap"
  assert_not_called "defaults write"
  [ ! -e "$HOME/.config" ] || fail "status created config"
}

test_status_reports_outdated_root_job() {
  install_root_copy
  assert_contains "$(mac_secure status --json)" '"root_job":"current"'
  echo tampered >>"$MS_ROOT_LIBEXEC/feed-password.exp"
  assert_contains "$(mac_secure status --json)" '"root_job":"outdated"'
}

test_status_reports_a_removed_vendor_list_as_outdated() {
  install_root_copy
  echo 'zoom|BJ4HAAB9B3' >"$MS_ROOT_LIBEXEC/vendor-installers.txt"
  assert_contains "$(mac_secure status --json)" '"root_job":"outdated"'
  mkdir -p "$HOME/.config/mac-secure"
  cp "$MS_ROOT_LIBEXEC/vendor-installers.txt" "$HOME/.config/mac-secure/vendor-installers.txt"
  assert_contains "$(mac_secure status --json)" '"root_job":"current"'
}

test_plist_read_error_on_stdout_is_not_taken_for_a_value() {
  install_root_copy
  stub plutil 'echo "file: Could not extract value, error: No value at that key path"; exit 1'
  assert_contains "$(mac_secure status --json)" '"root_job":"current"'
}

test_status_shows_root_module_results() {
  printf '2026-01-01 03:00\tmacos\tok\t0\tinstalling\n2026-01-01 03:05\tmacos\tfailed\t0\tsee log\n' >"$MS_ROOT_RESULTS"
  local out
  out=$(mac_secure status --json)
  assert_contains "$out" '"id":"macos","scope":"root","enabled":"no","available":"yes","last_run":"2026-01-01 03:05","last_result":"failed"'
}

test_json_string_escapes_quotes_and_controls() {
  . "$REPO/lib/common.sh"
  local out
  out=$(ms_json_string "$(printf 'a"b\\c\td')")
  assert_json "$out"
}

test_unknown_command_exits_2() {
  mac_secure bogus >/dev/null 2>&1
  assert_eq 2 $?
}

# --- enable and disable

test_enable_refuses_unknown_module_and_writes_nothing() {
  mac_secure enable brew-formulae bogus --yes >/dev/null 2>&1
  assert_eq 2 $?
  [ ! -e "$HOME/.config/mac-secure/enabled" ] || fail "wrote enabled"
  assert_not_called "launchctl"
}

test_enable_without_yes_or_terminal_changes_nothing() {
  mac_secure enable --recommended >/dev/null 2>&1
  assert_eq 2 $?
  [ ! -e "$HOME/.config/mac-secure/enabled" ] || fail "wrote enabled"
  assert_not_called "launchctl"
}

test_enable_user_module_installs_a_valid_agent_when_home_needs_escaping() {
  export HOME="$TMP/a&b c"
  mkdir -p "$HOME"
  mac_secure enable brew-formulae --yes >/dev/null
  assert_eq 0 $?
  local plist="$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.daily.plist" program
  [ -f "$plist" ] || fail "no agent written"
  program=$(python3 -I -c 'import plistlib,sys; print(plistlib.load(open(sys.argv[1],"rb"))["ProgramArguments"][1])' "$plist")
  assert_eq "$HOME/Library/Application Support/mac-secure/app/jobs/daily" "$program"
  [ -x "$program" ] || fail "job copy is not executable"
  assert_called "launchctl bootstrap gui/"
  [ ! -e "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.enforcer.plist" ] || fail "enforcer installed"
}

test_enabling_another_module_leaves_someone_elses_browser_policy_alone() {
  mac_secure enable bun --yes >/dev/null
  mac_secure disable bun --yes >/dev/null
  mac_secure uninstall --purge --yes >/dev/null
  assert_not_called "defaults delete"
  assert_not_called "defaults write"
}

test_browser_policy_someone_else_set_is_neither_overwritten_nor_deleted() {
  mkdir -p "$MS_APPLICATIONS_DIR/Google Chrome.app"
  stub defaults 'exit 0'
  mac_secure enable browsers --yes >/dev/null
  assert_not_called "defaults write com.google.Chrome"
  mac_secure disable browsers --yes >/dev/null
  assert_not_called "defaults delete com.google.Chrome"
}

test_enable_browsers_sets_policy_only_for_installed_browsers_and_disable_clears_it() {
  mkdir -p "$MS_APPLICATIONS_DIR/Google Chrome.app"
  mac_secure enable browsers --yes >/dev/null
  assert_not_called "defaults write com.microsoft.Edge"
  assert_called "defaults write com.google.Chrome RelaunchNotification -int 2"
  assert_called "defaults write com.google.Chrome RelaunchNotificationPeriod -int 1800000"
  [ -f "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.enforcer.plist" ] || fail "no enforcer"
  mac_secure disable browsers --yes >/dev/null
  assert_called "defaults delete com.google.Chrome RelaunchNotification"
  [ ! -e "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.enforcer.plist" ] || fail "enforcer kept"
}

test_disabling_the_last_daily_module_removes_the_agent() {
  mac_secure enable bun --yes >/dev/null
  [ -f "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.daily.plist" ] || fail "no agent"
  mac_secure disable bun --yes >/dev/null
  [ ! -e "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.daily.plist" ] || fail "agent kept"
}

test_root_module_without_terminal_prints_command_and_exits_3() {
  local out rc
  out=$(mac_secure enable firewall --yes 2>&1)
  rc=$?
  assert_eq 3 "$rc"
  assert_contains "$out" "sudo /bin/bash"
  assert_contains "$out" "install-root.sh"
  assert_contains "$out" "enable firewall"
  assert_not_called "sudo "
}

test_disable_reaches_root_even_when_the_module_is_not_in_root_conf() {
  install_root_copy
  : >"$MS_ROOT_LIBEXEC/root.conf"
  local out rc
  out=$(mac_secure disable macos-unattended --yes 2>&1)
  rc=$?
  assert_eq 3 "$rc"
  assert_contains "$out" "disable macos-unattended"
}

test_disable_of_a_root_module_with_no_root_job_needs_no_root() {
  mac_secure disable firewall --yes >/dev/null 2>&1
  assert_eq 0 $?
}

test_vendor_list_is_always_named_so_removing_it_takes_effect() {
  local out
  out=$(mac_secure enable firewall --yes 2>&1)
  assert_contains "$out" "--vendors"
}

test_recommended_enables_user_modules_before_stopping_at_root() {
  local out rc
  out=$(mac_secure enable --recommended --yes 2>&1)
  rc=$?
  assert_eq 3 "$rc"
  grep -qx brew-formulae "$HOME/.config/mac-secure/enabled" || fail "user module not enabled"
  grep -qx macos "$HOME/.config/mac-secure/enabled" && fail "root module in the user list"
  assert_not_contains "$out" "macos-unattended"
  assert_contains "$out" "enable macos app-store firewall"
}

test_unattended_pulls_in_macos() {
  local out
  out=$(mac_secure enable macos-unattended --yes 2>&1)
  assert_contains "$out" "enable macos macos-unattended"
}

test_refresh_replaces_installed_jobs() {
  mac_secure enable bun --yes >/dev/null
  local job="$HOME/Library/Application Support/mac-secure/app/jobs/daily"
  echo tampered >"$job"
  mac_secure refresh >/dev/null
  cmp -s "$REPO/jobs/daily" "$job" || fail "job was not replaced"
}

test_refresh_shows_root_changes_and_exits_3_without_a_terminal() {
  install_root_copy
  mkdir -p "$HOME/.config/mac-secure"
  echo 'tampered line' >>"$MS_ROOT_LIBEXEC/macos-update"
  local out rc
  out=$(mac_secure refresh 2>&1)
  rc=$?
  assert_eq 3 "$rc"
  assert_contains "$out" "The root job would change"
  assert_contains "$out" "tampered line"
  assert_contains "$out" "refresh"
  assert_not_called "sudo "
}

test_refresh_with_a_current_root_job_needs_no_root() {
  install_root_copy
  local out
  out=$(mac_secure refresh 2>&1)
  assert_eq 0 $?
  assert_contains "$out" "the root job is current"
}

test_sudo_is_never_called_through_path() {
  local bad
  bad=$(grep -nE '(^|[^/_A-Za-z$"])sudo ' "$REPO/bin/mac-secure" | grep -vE '^[0-9]+:\s*#' | grep -vF 'Root modules run sudo')
  assert_eq "" "$bad" "bare sudo calls"
}

test_run_exits_1_when_a_module_failed() {
  stub bun 'exit 1'
  mac_secure run bun >/dev/null 2>&1
  assert_eq 1 $?
  stub bun 'exit 0'
  mac_secure run bun >/dev/null 2>&1
  assert_eq 0 $?
}

test_uninstall_keeps_settings_unless_purged() {
  mac_secure enable bun browsers --yes >/dev/null
  mac_secure uninstall --yes >/dev/null
  [ ! -e "$HOME/Library/LaunchAgents/io.github.piekstra.mac-secure.daily.plist" ] || fail "agent kept"
  [ -f "$HOME/.config/mac-secure/enabled" ] || fail "settings removed without --purge"
  mac_secure uninstall --purge --yes >/dev/null
  [ ! -e "$HOME/.config/mac-secure" ] || fail "settings kept with --purge"
}

# --- daily job

run_daily() {
  "$REPO/jobs/daily" "$@" </dev/null
}

result_of() {
  awk -F'\t' -v id="$1" '$2==id{print $3}' "$HOME/Library/Application Support/mac-secure/last-run.tsv"
}

detail_of() {
  awk -F'\t' -v id="$1" '$2==id{print $5}' "$HOME/Library/Application Support/mac-secure/last-run.tsv"
}

test_daily_records_ok_failed_and_skipped() {
  stub bun 'case "$1" in --version) echo 1.2.3 ;; esac; exit 0'
  stub uv 'exit 1'
  rm "$STUBS/colima"
  run_daily bun uv colima
  assert_eq ok "$(result_of bun)"
  assert_eq failed "$(result_of uv)"
  assert_eq skipped "$(result_of colima)"
  assert_called 'osascript'
  assert_contains "$(cat "$CALLS")" 'Failed: uv'
}

test_daily_no_notification_when_nothing_fails() {
  run_daily rust
  assert_eq ok "$(result_of rust)"
  assert_not_called 'osascript'
}

test_daily_defers_on_low_disk() {
  export FREE_GIB=5
  run_daily brew-formulae
  assert_eq deferred "$(result_of disk)"
  assert_eq deferred "$(result_of brew-formulae)"
  assert_not_called 'brew upgrade'
  assert_called 'brew cleanup'
}

test_daily_timeout_kills_a_hung_tool_and_later_modules_still_run() {
  stub bun 'sleep 60'
  export MS_MODULE_LIMIT=2
  local started elapsed
  started=$(date +%s)
  run_daily bun rust
  elapsed=$(($(date +%s) - started))
  [ "$elapsed" -lt 20 ] || fail "took ${elapsed}s"
  assert_eq failed "$(result_of bun)"
  assert_contains "$(detail_of bun)" "timed out"
  assert_eq ok "$(result_of rust)"
  if pgrep -f "$STUBS/bun" >/dev/null 2>&1; then
    fail "the hung tool is still running"
  fi
}

test_daily_second_instance_exits_while_first_runs() {
  local lock="$HOME/Library/Application Support/mac-secure/run.lock"
  mkdir -p "$lock"
  echo $$ >"$lock/pid"
  run_daily rust 2>/dev/null
  assert_eq 0 $?
  assert_not_called 'rustup'
}

test_daily_recovers_a_stale_lock() {
  local lock="$HOME/Library/Application Support/mac-secure/run.lock"
  mkdir -p "$lock"
  echo 99999999 >"$lock/pid"
  run_daily rust
  assert_called 'rustup update'
  [ ! -e "$lock" ] || fail "lock left behind"
}

test_npm_upgrades_scoped_packages_by_name() {
  stub npm "case \"\$1\" in outdated) cat '$FIXTURES/npm-outdated.txt' ;; esac; exit 0"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_called 'npm install -g @example/tool@latest'
  assert_called 'npm install -g plain@latest'
}

test_npm_failed_check_is_deferred_not_ok() {
  stub npm 'exit 1'
  run_daily npm
  assert_eq deferred "$(result_of npm)"
  assert_contains "$(detail_of npm)" "could not check"
}

test_npm_nothing_outdated_is_ok() {
  stub npm 'exit 0'
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_not_called 'npm install'
}

test_pinned_formula_does_not_fail_the_module() {
  stub brew 'case "$*" in
    "outdated --formula --quiet") printf "pinned-one\n" ;;
    "list --pinned") printf "pinned-one\n" ;;
  esac'
  run_daily brew-formulae
  assert_eq ok "$(result_of brew-formulae)"
  assert_contains "$(detail_of brew-formulae)" "0 outdated before, 0 after; pinned: 1"
}

test_unpinned_outdated_formula_still_fails_the_module() {
  stub brew 'case "$*" in
    "outdated --formula --quiet") printf "stuck-one\n" ;;
  esac'
  run_daily brew-formulae
  assert_eq failed "$(result_of brew-formulae)"
}

test_app_pids_match_only_the_literal_app_path() {
  . "$REPO/lib/common.sh"
  ( exec -a "/Applications/Foo (Beta).app/Contents/MacOS/foo --flag" sleep 30 ) >/dev/null 2>&1 &
  local wanted=$!
  ( exec -a "$HOME/Applications/Foo (Beta).app/Contents/MacOS/foo" sleep 30 ) >/dev/null 2>&1 &
  local other_copy=$!
  ( exec -a "vim /Applications/Foo (Beta).app/Contents/Info.plist" sleep 30 ) >/dev/null 2>&1 &
  local editor=$!
  ( exec -a "/Applications/FooXBeta).app/Contents/MacOS/foo" sleep 30 ) >/dev/null 2>&1 &
  local lookalike=$!
  sleep 1
  local found
  found=$(ms_app_pids "Foo (Beta).app" MacOS/)
  kill "$wanted" "$other_copy" "$editor" "$lookalike" 2>/dev/null
  assert_eq "$wanted" "$found" "matched pids"
}

test_rust_retries_a_failed_self_update() {
  local marker="$TMP/rustup-tried"
  stub rustup "case \"\$1\" in
    self) [ -f '$marker' ] && exit 0; touch '$marker'; exit 1 ;;
    --version) echo rustup 1 ;;
  esac; exit 0"
  export MS_RETRY_SECONDS=0
  run_daily rust
  assert_eq ok "$(result_of rust)"
}

test_playwright_installs_nothing_for_someone_not_using_it() {
  stub python3 'exit 1'
  run_daily playwright
  assert_eq ok "$(result_of playwright)"
  assert_eq "not in use" "$(detail_of playwright)"
  assert_not_called 'npx'
}

# Builds a one-commit repository whose path has a space, and a cargo stub that reports it as a
# local install and audits as the file named by $AUDIT_FIXTURE.
cargo_local_setup() {
  REPO_DIR="$TMP/my tool"
  mkdir -p "$REPO_DIR"
  (
    cd "$REPO_DIR" || exit 1
    git init -q -b main .
    git config user.email test@example.com
    git config user.name test
    printf '[package]\nname = "tool"\n' >Cargo.toml
    touch Cargo.lock
    git add .
    git commit -qm init
  )
  mkdir -p "$HOME/.cargo/bin"
  echo old >"$HOME/.cargo/bin/tool"
  stub cargo "case \"\$1 \${2:-}\" in
    'install --list') printf 'tool v0.1.0 (%s):\n    tool\n' '$REPO_DIR' ;;
    'audit --json') cat \"\$AUDIT_FIXTURE\" ;;
    install*)
      while [ \$# -gt 0 ]; do [ \"\$1\" = --root ] && root=\$2; shift; done
      mkdir -p \"\$root/bin\"; echo built >\"\$root/bin/tool\" ;;
  esac"
}

test_cargo_local_rebuilds_once_per_advisory_set() {
  cargo_local_setup
  export AUDIT_FIXTURE="$FIXTURES/cargo-audit-advisories.json"
  run_daily cargo-local
  assert_eq ok "$(result_of cargo-local)"
  assert_eq built "$(cat "$HOME/.cargo/bin/tool")"
  assert_contains "$(detail_of cargo-local)" "rebuilt: my tool"
  : >"$CALLS"
  run_daily cargo-local
  assert_not_called 'cargo install --path'
  assert_contains "$(detail_of cargo-local)" "already handled: 1"
}

test_cargo_local_clean_audit_builds_nothing() {
  cargo_local_setup
  export AUDIT_FIXTURE="$FIXTURES/cargo-audit-clean.json"
  run_daily cargo-local
  assert_eq ok "$(result_of cargo-local)"
  assert_not_called 'cargo install --path'
  assert_eq old "$(cat "$HOME/.cargo/bin/tool")"
}

test_cargo_local_failed_audit_is_not_read_as_clean() {
  cargo_local_setup
  export AUDIT_FIXTURE="$FIXTURES/cargo-audit-error.txt"
  run_daily cargo-local
  assert_eq deferred "$(result_of cargo-local)"
  assert_contains "$(detail_of cargo-local)" "audit unavailable: my tool"
}

test_cargo_local_runs_the_configured_signer() {
  cargo_local_setup
  export AUDIT_FIXTURE="$FIXTURES/cargo-audit-advisories.json"
  stub my-signer
  mkdir -p "$HOME/.config/mac-secure"
  echo "CARGO_LOCAL_SIGN_COMMAND=my-signer" >"$HOME/.config/mac-secure/config"
  run_daily cargo-local
  assert_called 'my-signer '
}

test_notification_is_bounded() {
  . "$REPO/lib/common.sh"
  stub osascript 'sleep 60'
  export MS_NOTIFY_WAIT=1
  local started elapsed
  started=$(date +%s)
  ms_notify title body
  elapsed=$(($(date +%s) - started))
  [ "$elapsed" -lt 5 ] || fail "waited ${elapsed}s"
}

# --- root job

load_root_job() {
  # shellcheck source=root/macos-update
  . "$REPO/root/macos-update"
  PATH="$STUBS:$PATH"
  CONF="$TMP/root.conf"
  : >"$CONF"
  STATE="$TMP/state"
  mkdir -p "$STATE/vendor"
  VENDOR_LIST="$TMP/vendors.txt"
  LOG_DIR="$TMP/root-logs"
  mkdir -p "$LOG_DIR"
  RESULTS="$LOG_DIR/last-run.tsv"
  SERVICE_PASSWORD_FILE="$STATE/service-password"
  FIREWALL="$STUBS/socketfilterfw"
  LOG="$LOG_DIR/macos.log"
  WARNING_SECONDS=0
  NETWORK_ATTEMPTS=2
  NETWORK_RETRY_SECONDS=0
  notify() { echo "notify $*" >>"$CALLS"; }
  console_uid() { echo 501; }
}

softwareupdate_lists() {
  stub softwareupdate "case \"\$1\" in --list) cat '$FIXTURES/$1' ;; esac; exit 0"
}

test_plan_labels_each_update() {
  load_root_job
  local plan
  plan=$(plan_apple_updates "$(cat "$FIXTURES/softwareupdate-updates.txt")" 26 1)
  assert_contains "$plan" "restart|27.2|macOS 27.2-26B123"
  assert_contains "$plan" "restart|26.7.2|macOS Tahoe 26.7.2-25G332"
  assert_contains "$plan" "install|27.2|Safari27.2TahoeAuto-27.2"
}

test_plan_skips_a_major_upgrade_unless_allowed() {
  load_root_job
  local plan
  plan=$(plan_apple_updates "$(cat "$FIXTURES/softwareupdate-updates.txt")" 26 0)
  assert_contains "$plan" "skip|27.2|macOS 27.2-26B123"
  assert_contains "$plan" "restart|26.7.2|macOS Tahoe 26.7.2-25G332"
}

test_restart_picks_lowest_version_not_lowest_label() {
  load_root_job
  local plan
  plan=$(plan_apple_updates "$(cat "$FIXTURES/softwareupdate-updates.txt")" 26 1)
  assert_eq "macOS Tahoe 26.7.2-25G332" "$(printf '%s\n' "$plan" | next_restart_label)"
}

test_no_space_message_counts_as_failure_despite_exit_0() {
  load_root_job
  stub softwareupdate "cat '$FIXTURES/softwareupdate-no-space.txt'; exit 0"
  softwareupdate_checked --download label >/dev/null
  assert_eq 1 $?
  assert_called 'notify macOS update failed'
}

test_empty_listing_is_a_failed_check_not_no_updates() {
  load_root_job
  echo macos >"$CONF"
  softwareupdate_lists softwareupdate-offline.txt
  run_apple_updates >/dev/null
  assert_eq 1 $?
  assert_called 'notify macOS update check failed'
}

test_no_updates_is_quiet() {
  load_root_job
  echo macos >"$CONF"
  softwareupdate_lists softwareupdate-none.txt
  run_apple_updates >/dev/null
  assert_eq 0 $?
  assert_not_called 'notify'
  assert_not_called 'softwareupdate --install'
}

test_without_unattended_a_restart_update_is_only_downloaded() {
  load_root_job
  echo macos >"$CONF"
  softwareupdate_lists softwareupdate-updates.txt
  stub sw_vers 'echo 26.5.1'
  run_apple_updates >/dev/null
  assert_called 'softwareupdate --download macOS Tahoe 26.7.2-25G332'
  assert_called 'softwareupdate --install Safari27.2TahoeAuto-27.2'
  assert_not_called '--restart'
  assert_called 'notify macOS update ready'
}

test_failed_download_does_not_announce_ready() {
  load_root_job
  echo macos >"$CONF"
  stub softwareupdate "case \"\$1\" in --download) exit 1 ;; esac"
  install_restart_update "macOS Tahoe 26.7.2-25G332" >/dev/null
  assert_not_called 'notify macOS update ready'
  assert_called 'notify macOS update failed'
}

test_unattended_restart_passes_the_password_on_stdin_only() {
  load_root_job
  printf 'macos\nmacos-unattended\n' >"$CONF"
  printf 'dummy-password' >"$SERVICE_PASSWORD_FILE"
  stub softwareupdate "cat >'$TMP/stdin'"
  install_restart_update "macOS Tahoe 26.7.2-25G332" >/dev/null
  assert_called 'softwareupdate --install macOS Tahoe 26.7.2-25G332 --restart --user secupdate --stdinpass'
  assert_eq dummy-password "$(cat "$TMP/stdin")"
  assert_not_called 'dummy-password'
  assert_called 'notify Mac restarting soon'
}

test_no_restart_flag_only_downloads_even_when_unattended() {
  load_root_job
  printf 'macos\nmacos-unattended\n' >"$CONF"
  printf 'dummy-password' >"$SERVICE_PASSWORD_FILE"
  ALLOW_RESTART=0
  install_restart_update "macOS Tahoe 26.7.2-25G332" >/dev/null
  assert_called 'softwareupdate --download'
  assert_not_called '--restart'
}

test_firewall_on_is_not_sent_again() {
  load_root_job
  echo firewall >"$CONF"
  stub socketfilterfw 'case "$1" in --getglobalstate) echo "Firewall is enabled. (State = 1)" ;; esac'
  apply_settings
  assert_not_called '--setglobalstate'
}

test_firewall_off_is_turned_on() {
  load_root_job
  echo firewall >"$CONF"
  stub socketfilterfw 'case "$1" in --getglobalstate) echo "Firewall is disabled. (State = 0)" ;; esac'
  apply_settings
  assert_called 'socketfilterfw --setglobalstate on'
}

test_settings_follow_the_enabled_modules() {
  load_root_job
  : >"$CONF"
  apply_settings
  assert_not_called 'defaults write'
  assert_not_called 'socketfilterfw'
}

test_no_network_skips_and_notifies() {
  load_root_job
  stub curl 'exit 6'
  wait_for_network >/dev/null
  assert_eq 1 $?
  assert_called 'notify macOS update skipped'
}

test_vendor_line_validation() {
  load_root_job
  valid_vendor_line 'zoom|BJ4HAAB9B3' || fail "valid line rejected"
  valid_vendor_line 'dotnet-sdk@8|UBF8T346G9' || fail "valid line rejected"
  local bad
  for bad in '../evil|BJ4HAAB9B3' 'zoom|short' 'zoom|bj4hab9b3a' 'zoom' '$(evil)|BJ4HAAB9B3' 'zoom|BJ4HAAB9B3|x'; do
    if valid_vendor_line "$bad"; then
      fail "accepted [$bad]"
    fi
  done
}

# Stubs one vendor update. Variables read by the stubs: VENDOR_VERSION, VENDOR_URL, VENDOR_SHA (the
# published value), VENDOR_DOWNLOAD_SHA, VENDOR_PAYLOAD (first bytes of the download), SIGNATURE
# (fixture name), SIGNATURE_RC, GATEKEEPER, ASSESS_RC.
vendor_stubs() {
  stub curl "while [ \$# -gt 0 ]; do [ \"\$1\" = -o ] && out=\$2; shift; done
    case \"\$out\" in
      *cask.json) echo '{}' >\"\$out\" ;;
      *) printf '%s' \"\${VENDOR_PAYLOAD:-xar!rest}\" >\"\$out\" ;;
    esac"
  stub plutil 'case "$2" in
    version) echo "${VENDOR_VERSION:-2.0.0}" ;;
    url) echo "${VENDOR_URL:-https://downloads.example.com/example.pkg}" ;;
    sha256) echo "${VENDOR_SHA:-aaaa}" ;;
  esac'
  stub shasum 'echo "${VENDOR_DOWNLOAD_SHA:-aaaa}  file"'
  stub pkgutil "cat '$FIXTURES/'\"\${SIGNATURE:-pkgutil-signed.txt}\"; exit \"\${SIGNATURE_RC:-0}\""
  stub spctl 'case "$1" in
    --status) echo "assessments ${GATEKEEPER:-enabled}" ;;
    --assess) exit "${ASSESS_RC:-0}" ;;
  esac'
}

test_vendor_installs_when_every_check_passes() {
  load_root_job
  vendor_stubs
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_eq 0 $?
  assert_called 'installer -pkg'
  assert_eq 2.0.0 "$(cat "$STATE/vendor/example")"
  assert_not_called 'notify'
}

test_vendor_skips_a_version_already_installed() {
  load_root_job
  vendor_stubs
  echo 2.0.0 >"$STATE/vendor/example"
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_not_called 'installer -pkg'
  assert_not_called 'installer.pkg'
}

assert_vendor_refused() {
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_eq 1 $?
  assert_not_called 'installer -pkg'
  assert_called "notify Vendor installer not installed example: $1"
  [ "$(cat "$STATE/vendor/example" 2>/dev/null)" != 2.0.0 ] || fail "recorded as installed"
}

test_vendor_rejects_a_sha_mismatch() {
  load_root_job
  vendor_stubs
  export VENDOR_DOWNLOAD_SHA=ffff
  assert_vendor_refused 'sha256 mismatch'
}

test_vendor_rejects_the_wrong_team() {
  load_root_job
  vendor_stubs
  update_vendor_pkg example ZZZZZ99999 >/dev/null
  assert_eq 1 $?
  assert_not_called 'installer -pkg'
  assert_called 'not signed by the pinned team'
}

test_vendor_rejects_a_self_signed_certificate_naming_the_team() {
  load_root_job
  vendor_stubs
  export SIGNATURE=pkgutil-self-signed.txt SIGNATURE_RC=1
  assert_vendor_refused 'not signed by the pinned team'
}

test_vendor_rejects_untrusted_status_even_with_exit_0() {
  load_root_job
  vendor_stubs
  export SIGNATURE=pkgutil-self-signed.txt SIGNATURE_RC=0
  assert_vendor_refused 'not signed by the pinned team'
}

test_vendor_team_must_be_on_the_leaf_certificate() {
  load_root_job
  vendor_stubs
  export SIGNATURE=pkgutil-team-not-on-leaf.txt
  assert_vendor_refused 'not signed by the pinned team'
}

test_vendor_rejects_a_gatekeeper_failure() {
  load_root_job
  vendor_stubs
  export ASSESS_RC=3
  assert_vendor_refused 'rejected by Gatekeeper'
}

test_vendor_refuses_when_gatekeeper_is_off() {
  load_root_job
  vendor_stubs
  export GATEKEEPER=disabled
  assert_vendor_refused 'Gatekeeper is off'
}

test_vendor_rejects_a_plain_http_url() {
  load_root_job
  vendor_stubs
  export VENDOR_URL=http://downloads.example.com/example.pkg
  assert_vendor_refused 'refusing a download that is not https'
}

test_vendor_refuses_a_downgrade() {
  load_root_job
  vendor_stubs
  echo 10.0.0 >"$STATE/vendor/example"
  export VENDOR_VERSION=9.9.9
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_eq 1 $?
  assert_not_called 'installer -pkg'
  assert_called 'older than the installed 10.0.0'
  assert_eq 10.0.0 "$(cat "$STATE/vendor/example")"
}

test_vendor_accepts_a_newer_version_comparing_numerically() {
  load_root_job
  vendor_stubs
  echo 9.9.9 >"$STATE/vendor/example"
  export VENDOR_VERSION=10.0.0
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_called 'installer -pkg'
  assert_eq 10.0.0 "$(cat "$STATE/vendor/example")"
}

test_cask_field_ignores_a_plist_error_printed_to_stdout() {
  load_root_job
  stub uname 'echo x86_64'
  stub sw_vers 'echo 15.7'
  stub plutil 'case "$2" in
    variations.*) echo "file: Could not extract value"; exit 1 ;;
    *) echo 2.0.0 ;;
  esac'
  assert_eq 2.0.0 "$(cask_field "$TMP/any.json" version)"
}

test_incomplete_cask_metadata_is_refused() {
  load_root_job
  vendor_stubs
  stub plutil 'echo "file: Could not extract value"; exit 1'
  assert_vendor_refused "Homebrew's metadata is incomplete"
}

test_vendor_with_no_version_reinstalls_only_when_the_download_changes() {
  load_root_job
  vendor_stubs
  export VENDOR_VERSION=latest VENDOR_SHA=no_check VENDOR_DOWNLOAD_SHA=aaaa
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_called 'installer -pkg'
  assert_eq latest:aaaa "$(cat "$STATE/vendor/example")"
  : >"$CALLS"
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_not_called 'installer -pkg'
  export VENDOR_DOWNLOAD_SHA=bbbb
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_called 'installer -pkg'
  assert_eq latest:bbbb "$(cat "$STATE/vendor/example")"
}

test_vendor_non_pkg_download_is_reported_once_per_version() {
  load_root_job
  vendor_stubs
  export VENDOR_PAYLOAD='PK-zip-file'
  assert_vendor_refused 'the download is not a pkg'
  assert_eq unsupported:2.0.0 "$(cat "$STATE/vendor/example")"
  : >"$CALLS"
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_eq 0 $?
  assert_not_called 'notify'
  assert_not_called 'installer.pkg'
}

test_vendor_installer_failure_notifies_and_is_not_recorded() {
  load_root_job
  vendor_stubs
  stub installer 'exit 1'
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_eq 1 $?
  assert_called 'the installer failed'
  [ ! -e "$STATE/vendor/example" ] || fail "recorded as installed"
}

test_vendor_downloads_refuse_redirects_off_https() {
  load_root_job
  vendor_stubs
  update_vendor_pkg example ABCDE12345 >/dev/null
  assert_called '--proto-redir =https'
}

test_every_curl_call_in_root_code_ignores_curlrc() {
  local bad
  bad=$(grep -nE '(^|[^a-z_-])curl ' "$REPO/root/macos-update" "$REPO/root/install-root.sh" | grep -vE ':\s*#' | grep -v 'curl -q ')
  assert_eq "" "$bad" "curl calls without -q"
}

test_root_scripts_start_from_an_empty_environment() {
  local file
  for file in macos-update install-root.sh; do
    grep -q 'exec /usr/bin/env -i MS_CLEAN_ENV=1 HOME=/var/root' "$REPO/root/$file" || fail "$file keeps the environment"
  done
}

test_root_job_records_results_for_status() {
  load_root_job
  printf 'macos\nfirewall\napp-store\nvendor-installers\n' >"$CONF"
  vendor_stubs
  echo 'example|ABCDE12345' >"$VENDOR_LIST"
  softwareupdate_lists softwareupdate-none.txt
  stub socketfilterfw 'echo "Firewall is enabled. (State = 1)"'
  stub sw_vers 'echo 26.1'
  main --no-restart
  local results
  results=$(cut -f2,3 "$RESULTS")
  assert_contains "$results" "firewall	ok"
  assert_contains "$results" "app-store	ok"
  assert_contains "$results" "vendor-installers	ok"
  assert_contains "$results" "macos	ok"
}

test_root_job_records_a_failed_vendor_and_a_failed_update() {
  load_root_job
  printf 'macos\nvendor-installers\n' >"$CONF"
  vendor_stubs
  export VENDOR_DOWNLOAD_SHA=ffff
  echo 'example|ABCDE12345' >"$VENDOR_LIST"
  softwareupdate_lists softwareupdate-offline.txt
  stub sw_vers 'echo 26.1'
  main --no-restart
  local results
  results=$(cut -f2,3,5 "$RESULTS")
  assert_contains "$results" "vendor-installers	failed	failed: example"
  assert_contains "$results" "macos	failed"
}

test_root_job_records_deferred_without_network() {
  load_root_job
  printf 'macos\nvendor-installers\n' >"$CONF"
  stub curl 'exit 6'
  stub sw_vers 'echo 26.1'
  main --no-restart
  local results
  results=$(cut -f2,3 "$RESULTS")
  assert_contains "$results" "vendor-installers	deferred"
  assert_contains "$results" "macos	deferred"
}

test_restart_records_its_result_before_softwareupdate_can_restart() {
  load_root_job
  printf 'macos\nmacos-unattended\n' >"$CONF"
  printf 'dummy-password' >"$SERVICE_PASSWORD_FILE"
  stub softwareupdate "cp '$RESULTS' '$TMP/at-restart'"
  install_restart_update "macOS Tahoe 26.7.2-25G332" >/dev/null
  assert_contains "$(cat "$TMP/at-restart")" "installing macOS Tahoe 26.7.2-25G332 with a restart"
}

test_root_job_calls_only_system_binaries() {
  local bad
  bad=$(grep -nE '/opt/homebrew|/usr/local/bin|\$HOME|\bbrew\b' "$REPO/root/macos-update" "$REPO/root/install-root.sh" | grep -vE '^[^:]+:[0-9]+:\s*#' | grep -v 'formulae.brew.sh')
  assert_eq "" "$bad" "user-writable paths in root code"
}

test_root_job_never_sources_a_file() {
  local bad
  bad=$(grep -nE '^\s*(\.|source)\s' "$REPO/root/macos-update" "$REPO/root/install-root.sh")
  assert_eq "" "$bad" "root code sourcing files"
}

# --- root installer

load_root_installer() {
  # shellcheck source=root/install-root.sh
  . "$REPO/root/install-root.sh"
  set +e
  PATH="$STUBS:$PATH"
  CONF="$TMP/root.conf"
  STATE="$TMP/state"
  mkdir -p "$STATE"
  WAKE_MARKER="$STATE/scheduled-wake"
  ACCOUNT_MARKER="$STATE/created-service-account"
  PASSWORD_FILE="$STATE/service-password"
  ADMIN_USER=someadmin
}

# Reports the given repeating wake schedule.
pmset_shows() {
  stub pmset "case \"\$*\" in \"-g sched\") printf 'Repeating power events:\n  %s\nScheduled power events:\n [0]  wake at 1/1/2030 by x\n' '$1' ;; esac"
}

test_wake_schedule_leaves_an_existing_repeat_alone() {
  load_root_installer
  pmset_shows 'wake at 7:00AM every day'
  schedule_wake >/dev/null
  assert_not_called 'pmset repeat'
  [ ! -e "$WAKE_MARKER" ] || fail "claimed a schedule it did not set"
}

test_wake_schedule_set_when_none_exists() {
  load_root_installer
  HOUR=3
  schedule_wake >/dev/null
  assert_called 'pmset repeat wakeorpoweron MTWRFSU 02:55:00'
  [ -f "$WAKE_MARKER" ] || fail "no marker"
}

test_wake_schedule_replaces_its_own_and_wraps_at_midnight() {
  load_root_installer
  pmset_shows 'wakepoweron at 2:55AM every day'
  repeat_schedule >"$WAKE_MARKER"
  HOUR=0
  schedule_wake >/dev/null
  assert_called 'pmset repeat wakeorpoweron MTWRFSU 23:55:00'
}

test_wake_schedule_set_by_someone_after_this_tool_is_left_alone() {
  load_root_installer
  pmset_shows 'wakepoweron at 2:55AM every day'
  repeat_schedule >"$WAKE_MARKER"
  pmset_shows 'wake at 7:00AM every day'
  schedule_wake >/dev/null
  assert_not_called 'pmset repeat'
}

test_uninstall_cancels_only_its_own_wake() {
  load_root_installer
  pmset_shows 'wakepoweron at 2:55AM every day'
  repeat_schedule >"$WAKE_MARKER"
  cancel_wake >/dev/null
  assert_called 'pmset repeat cancel'
  [ ! -e "$WAKE_MARKER" ] || fail "marker left behind"

  : >"$CALLS"
  repeat_schedule >"$WAKE_MARKER"
  pmset_shows 'wake at 7:00AM every day'
  cancel_wake >/dev/null
  assert_not_called 'pmset repeat cancel'
}

test_uninstall_with_no_marker_leaves_a_wake_alone() {
  load_root_installer
  pmset_shows 'wake at 7:00AM every day'
  cancel_wake >/dev/null
  assert_not_called 'pmset repeat'
}

test_root_conf_add_and_remove() {
  load_root_installer
  : >"$CONF"
  conf_add firewall
  conf_add firewall
  conf_add macos
  assert_eq "firewall
macos" "$(cat "$CONF")"
  conf_remove firewall
  assert_eq macos "$(cat "$CONF")"
  conf_remove macos
  assert_eq "" "$(cat "$CONF")"
}

test_remove_account_leaves_an_account_it_did_not_create() {
  load_root_installer
  stub id 'exit 0'
  remove_account >/dev/null
  assert_not_called 'sysadminctl -deleteUser'
}

test_remove_account_deletes_its_own_and_checks_the_result() {
  load_root_installer
  touch "$ACCOUNT_MARKER" "$PASSWORD_FILE"
  stub id 'exit 1'
  remove_account >/dev/null
  assert_called 'sysadminctl -deleteUser secupdate'
  [ ! -e "$ACCOUNT_MARKER" ] || fail "marker left behind"
  [ ! -e "$PASSWORD_FILE" ] || fail "password left behind"
}

test_remove_account_keeps_the_marker_when_deletion_fails() {
  load_root_installer
  touch "$ACCOUNT_MARKER" "$PASSWORD_FILE"
  stub id 'exit 0'
  remove_account >/dev/null 2>&1
  assert_eq 1 $?
  [ -e "$ACCOUNT_MARKER" ] || fail "lost track of an account that still exists"
}

# Stands in for sysadminctl and tracks whether the account exists.
account_stubs() {
  stub id "[ -f '$TMP/account-exists' ]"
  stub sysadminctl "case \"\$1\" in
    -addUser) touch '$TMP/account-exists' ;;
    -deleteUser) rm -f '$TMP/account-exists' ;;
    -secureTokenStatus) echo \"Secure token is \${TOKEN_STATE:-ENABLED} for user\" ;;
  esac"
  stub openssl 'printf generated-password'
  feed_password() {
    shift
    "$@"
  }
}

test_service_account_is_created_with_its_password_off_the_command_line() {
  load_root_installer
  account_stubs
  create_service_account >/dev/null
  assert_eq 0 $?
  assert_eq generated-password "$(cat "$PASSWORD_FILE")"
  assert_called 'sysadminctl -addUser secupdate -fullName Security Updates -admin -password -'
  assert_called 'sysadminctl -adminUser someadmin -adminPassword - -secureTokenOn secupdate -password -'
  assert_not_called 'generated-password'
  [ -e "$ACCOUNT_MARKER" ] || fail "no marker"
}

test_failed_secure_token_removes_the_account_it_created() {
  load_root_installer
  account_stubs
  export TOKEN_STATE=DISABLED
  create_service_account >/dev/null 2>&1
  assert_eq 1 $?
  assert_called 'sysadminctl -deleteUser secupdate'
  [ ! -e "$TMP/account-exists" ] || fail "an unused admin account remains"
  [ ! -e "$PASSWORD_FILE" ] || fail "password left behind"
  [ ! -e "$ACCOUNT_MARKER" ] || fail "marker left behind"
}

test_failed_secure_token_keeps_an_account_it_did_not_create() {
  load_root_installer
  account_stubs
  touch "$TMP/account-exists"
  printf existing >"$PASSWORD_FILE"
  export TOKEN_STATE=DISABLED
  create_service_account >/dev/null 2>&1
  assert_eq 1 $?
  assert_not_called 'sysadminctl -deleteUser'
  assert_eq existing "$(cat "$PASSWORD_FILE")"
}

test_account_that_was_not_created_leaves_no_password_behind() {
  load_root_installer
  account_stubs
  stub sysadminctl 'exit 0'
  create_service_account >/dev/null 2>&1
  assert_eq 1 $?
  [ ! -e "$PASSWORD_FILE" ] || fail "password left behind"
}
