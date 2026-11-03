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

# Installed jobs run from a copy, so a library a job sources but the copy leaves out breaks only installed Macs.
test_installed_job_copy_has_every_library_the_jobs_source() {
  ROOT=$REPO
  . "$REPO/lib/common.sh"
  . "$REPO/lib/modules.sh"
  . "$REPO/lib/install.sh"
  ms_install_app_copy
  local file
  for file in $(sed -n 's|^\. "\$ROOT/\(lib/[a-z]*\.sh\)"$|\1|p' "$REPO/jobs/daily" "$REPO/jobs/enforcer"); do
    [ -f "$MS_APP_DIR/$file" ] || fail "the job copy has no $file"
  done
  "$MS_APP_DIR/jobs/daily" rust </dev/null
  assert_eq ok "$(result_of rust)"
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

test_plist_values_are_read_only_through_the_two_wrappers() {
  local reads wrappers
  reads=$(cd "$REPO" && grep -rn 'plutil -extract' bin jobs lib root | cut -d: -f1 | sort | tr '\n' ' ')
  assert_eq "lib/status.sh root/macos-update " "$reads" "files reading plists directly"
  wrappers=$(sed -n 's/.*value=\$(\(plutil -extract.*\)$/\1/p' "$REPO/lib/status.sh" "$REPO/root/macos-update" | sort -u | wc -l | tr -d ' ')
  assert_eq 1 "$wrappers" "the two wrappers should read the same way"
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

# An nvm in <folder> (default ~/.nvm) whose default alias resolves to v20.0.0, whose npm reports
# itself, ccusage and newer-node-only outdated. Flags: NVM_DEFAULT replaces the resolved version;
# NVM_NPM_FAILS fails install-latest-npm; NVM_NPM_BREAKS makes it leave an npm that does not run;
# NVM_OUTDATED_FAILS fails the outdated check.
# Usage: nvm_setup [folder]
nvm_setup() {
  local dir=${1:-$HOME/.nvm}
  local root="$dir/versions/node/v20.0.0"
  mkdir -p "$root/bin" "$root/lib/node_modules/npm" "$dir/alias"
  echo 20 >"$dir/alias/default"
  cat >"$dir/nvm.sh" <<'EOF'
nvm() {
  printf 'nvm %s\n' "$*" >>"$CALLS"
  case "$1" in
    version) echo "${NVM_DEFAULT:-v20.0.0}" ;;
    install-latest-npm)
      [ -z "${NVM_NPM_FAILS:-}" ] || return 1
      [ -z "${NVM_NPM_BREAKS:-}" ] || touch "$NVM_DIR/versions/node/v20.0.0/lib/node_modules/npm/broken" ;;
  esac
}
EOF
  # npm_runs calls node with npm-cli.js; this node runs npm unless the npm folder is marked broken.
  mkdir -p "$root/lib/node_modules/npm/bin"
  touch "$root/lib/node_modules/npm/bin/npm-cli.js"
  cat >"$root/bin/node" <<'EOF'
#!/bin/bash
[ -f "$1" ] && [ ! -f "$(dirname "$0")/../lib/node_modules/npm/broken" ] && echo 10.0.0
EOF
  chmod +x "$root/bin/node"
  cat >"$root/bin/npm" <<'EOF'
#!/bin/bash
printf 'nvm-npm %s engine_strict=%s\n' "$*" "${npm_config_engine_strict:-}" >>"$CALLS"
[ ! -f "$(dirname "$0")/../lib/node_modules/npm/broken" ] || exit 1
case "$1" in
  --version) [ ! -f "$(dirname "$0")/../lib/node_modules/npm/broken" ] && echo 10.0.0 ;;
  outdated)
    [ -z "${NVM_OUTDATED_FAILS:-}" ] || exit 1
    echo "/n/lib/node_modules/npm:npm@11.0.0:npm@10.0.0:npm@11.0.0:global"
    echo "/n/lib/node_modules/ccusage:ccusage@2.0.0:ccusage@1.0.0:ccusage@2.0.0:global"
    echo "/n/lib/node_modules/newnode:newnode@9.0.0:newnode@8.0.0:newnode@9.0.0:global"
    exit 1 ;;
  install)
    case "$3" in newnode@latest) echo "npm ERR! code EBADENGINE"; exit 1 ;; esac ;;
esac
EOF
  chmod +x "$root/bin/npm"
}

test_npm_updates_nvm_default_node_and_leaves_npm_to_nvm() {
  nvm_setup
  stub npm 'exit 0'
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_called 'nvm-npm install -g ccusage@latest'
  assert_not_called 'nvm-npm install -g npm@latest'
  assert_called 'nvm use --silent v20.0.0'
  assert_called 'nvm install-latest-npm'
  assert_contains "$(detail_of npm)" "updated 1; nvm default v20.0.0; held back for that Node: newnode; failed: none"
  assert_called 'nvm-npm install -g ccusage@latest engine_strict=true'
}

test_npm_puts_back_an_npm_that_does_not_run_after_nvm_updates_it() {
  nvm_setup
  stub npm 'exit 0'
  export NVM_NPM_BREAKS=1
  run_daily npm
  assert_eq failed "$(result_of npm)"
  assert_contains "$(detail_of npm)" "failed: npm(v20.0.0)"
  local modules="$HOME/.nvm/versions/node/v20.0.0/lib/node_modules"
  [ ! -e "$modules/npm/broken" ] || fail "the npm that does not run was left in place"
  [ ! -e "$modules/.npm.mac-secure-previous" ] || fail "the kept copy was left behind"
  [ ! -e "$modules/.npm.mac-secure-replaced" ] || fail "the replaced npm was left behind"
}

test_npm_puts_back_the_copy_a_stopped_run_left() {
  nvm_setup
  stub npm 'exit 0'
  local modules="$HOME/.nvm/versions/node/v20.0.0/lib/node_modules"
  cp -Rp "$modules/npm" "$modules/.npm.mac-secure-previous"
  touch "$modules/.npm.mac-secure-previous/good" "$modules/npm/broken"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  [ -e "$modules/npm/good" ] || fail "the kept copy was not put back"
  [ ! -e "$modules/npm/broken" ] || fail "the npm that does not run is still in place"
}

test_npm_reads_a_home_relative_nvm_dir_and_scans_it() {
  nvm_setup "$HOME/.config/nvm"
  stub npm 'exit 0'
  mkdir -p "$HOME/.config/mac-secure"
  echo 'NVM_DIR=~/.config/nvm' >"$HOME/.config/mac-secure/config"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_called 'nvm-npm install -g ccusage@latest'
  ( . "$REPO/lib/common.sh"; . "$REPO/lib/vulns.sh"; ms_vuln_targets ) | grep -qx "$HOME/.config/nvm/versions/node" ||
    fail "the vulns scan does not cover the configured nvm folder"
}

test_npm_configured_nvm_dir_that_is_missing_defers() {
  stub npm 'exit 0'
  mkdir -p "$HOME/.config/mac-secure"
  echo 'NVM_DIR=~/nowhere' >"$HOME/.config/mac-secure/config"
  run_daily npm
  assert_eq deferred "$(result_of npm)"
  assert_contains "$(detail_of npm)" "NVM_DIR $HOME/nowhere has no versions/node"
}

test_npm_engine_warning_on_another_failure_is_a_failure() {
  stub npm 'case "$1" in
    outdated) echo "/x/lib/node_modules/tool:tool@2.0.0:tool@1.0.0:tool@2.0.0:global"; exit 1 ;;
    install) echo "npm warn EBADENGINE Unsupported engine"; echo "npm error code ECONNRESET"; exit 1 ;;
  esac'
  run_daily npm
  assert_eq failed "$(result_of npm)"
  assert_contains "$(detail_of npm)" "failed: tool"
}

test_npm_puts_back_npm_that_a_stopped_run_left_missing() {
  nvm_setup
  stub npm 'exit 0'
  local root="$HOME/.nvm/versions/node/v20.0.0"
  mv "$root/lib/node_modules/npm" "$root/lib/node_modules/.npm.mac-secure-previous"
  mv "$root/bin/npm" "$root/lib/node_modules/.npm.mac-secure-previous/npm-launcher"
  ln -s ../lib/node_modules/npm/npm-launcher "$root/bin/npm"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  [ -x "$root/bin/npm" ] || fail "npm was not put back"
  assert_called 'nvm-npm install -g ccusage@latest'
}

test_npm_offline_nvm_check_defers_without_touching_npm() {
  nvm_setup
  stub npm 'exit 0'
  export NVM_OUTDATED_FAILS=1 NVM_NPM_FAILS=1
  run_daily npm
  assert_eq deferred "$(result_of npm)"
  assert_not_called 'nvm install-latest-npm'
}

test_npm_nvm_without_a_default_alias_is_named_and_clean() {
  nvm_setup
  stub npm 'exit 0'
  rm "$HOME/.nvm/alias/default"
  export NVM_DEFAULT=N/A
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_contains "$(detail_of npm)" "nvm has no default Node"
}

test_npm_nvm_default_that_does_not_resolve_is_deferred() {
  nvm_setup
  stub npm 'exit 0'
  export NVM_DEFAULT=N/A
  run_daily npm
  assert_eq deferred "$(result_of npm)"
  assert_contains "$(detail_of npm)" "could not check: nvm default 20 does not resolve"
}

test_npm_finds_homebrew_nvm_and_a_configured_folder() {
  nvm_setup "$HOME/nvm-data"
  mkdir -p "$TMP/homebrew/opt/nvm" "$HOME/.config/mac-secure"
  mv "$HOME/nvm-data/nvm.sh" "$TMP/homebrew/opt/nvm/nvm.sh"
  stub brew "case \"\$1\" in --prefix) echo '$TMP/homebrew' ;; esac"
  rm "$STUBS/npm"
  echo "NVM_DIR=$HOME/nvm-data" >"$HOME/.config/mac-secure/config"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_called 'nvm-npm install -g ccusage@latest'
}

test_npm_runs_for_nvm_without_npm_on_path() {
  nvm_setup
  rm "$STUBS/npm"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_called 'nvm-npm install -g ccusage@latest'
}

test_npm_failed_nvm_npm_update_fails_the_module() {
  nvm_setup
  export NVM_NPM_FAILS=1
  run_daily npm
  assert_eq failed "$(result_of npm)"
  assert_contains "$(detail_of npm)" "failed: npm(v20.0.0)"
}

test_npm_failed_nvm_check_is_deferred_and_named() {
  nvm_setup
  stub npm 'exit 0'
  export NVM_OUTDATED_FAILS=1
  run_daily npm
  assert_eq deferred "$(result_of npm)"
  assert_contains "$(detail_of npm)" "could not check: nvm v20.0.0"
}

test_npm_covers_nvm_default_once_when_it_is_first_on_path() {
  nvm_setup
  rm "$STUBS/npm"
  # As EXTRA_PATH would put it, ahead of the standard directories.
  export MS_JOB_PATH="$HOME/.nvm/versions/node/v20.0.0/bin:$MS_JOB_PATH"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_not_called 'nvm-npm install -g npm@latest'
  assert_eq 1 "$(grep -c 'nvm-npm install -g ccusage@latest' "$CALLS")" "ccusage installs"
}

test_sandbox_hides_the_real_nvm() {
  [ -z "${NVM_DIR:-}" ] || fail "NVM_DIR is set in the sandbox: $NVM_DIR"
}

test_npm_is_not_in_use_without_npm_or_nvm() {
  rm "$STUBS/npm"
  run_daily npm
  assert_eq ok "$(result_of npm)"
  assert_eq "not in use" "$(detail_of npm)"
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

# --- vulnerability scanning

# One scanned location, ~/.nvm/versions/node, whose matches are the grype fixture, and Homebrew
# formulae from the brew vulns fixture. No other default location exists in the sandbox.
vulns_setup() {
  mkdir -p "$HOME/.nvm/versions/node"
  rmdir "$MS_APPLICATIONS_DIR"
  export MS_SYSTEM_LIBRARY="$TMP/Library"
  # shellcheck disable=SC2016
  stub syft 'for a in "$@"; do case "$a" in syft-json=*) echo "{}" >"${a#syft-json=}" ;; esac; done'
  stub grype "case \"\$1\" in sbom:*) cat \"\${GRYPE_FIXTURE:-$FIXTURES/grype-matches.txt}\" ;; esac"
  stub brew "case \"\$1\" in --prefix) echo '$TMP/homebrew' ;; vulns) [ \"\$2\" = --help ] && exit 0; cat '$FIXTURES/brew-vulns.json'; exit 1 ;; esac"
  VULN_DIR="$HOME/Library/Application Support/mac-secure/vulns"
}

# Writes results directly, in the layout lib/vulns.sh documents, with a scan stamp of the given age.
# Usage: vulns_results <days old> <line>...   Each line has its fields separated by "|".
vulns_results() {
  local days=$1 line
  shift
  mkdir -p "$HOME/Library/Application Support/mac-secure/vulns"
  for line in "$@"; do
    printf '%s\n' "$line" | tr '|' '\t'
  done >"$HOME/Library/Application Support/mac-secure/vulns/latest.tsv"
  echo $(($(date +%s) - days * 86400)) >"$HOME/Library/Application Support/mac-secure/vulns/scanned-at"
}

# With the module on and its tools present, unless a test changes either first.
audit_vulns_only() {
  PATH="$STUBS:$PATH"
  [ -n "${VULNS_OFF:-}" ] || { mkdir -p "$HOME/.config/mac-secure"; grep -qx vulns "$HOME/.config/mac-secure/enabled" 2>/dev/null || echo vulns >>"$HOME/.config/mac-secure/enabled"; }
  . "$REPO/lib/common.sh"
  . "$REPO/lib/modules.sh"
  . "$REPO/lib/vulns.sh"
  . "$REPO/lib/audit.sh"
  MS_AUDIT_OUT="$TMP/findings"
  : >"$MS_AUDIT_OUT"
  audit_vulns
  cat "$MS_AUDIT_OUT"
}

test_vulns_records_installed_packages_and_drops_other_manifests() {
  vulns_setup
  run_daily vulns
  assert_eq ok "$(result_of vulns)"
  local results
  results=$(cat "$VULN_DIR/latest.tsv")
  assert_contains "$results" "$(printf '%s\tCritical\tCVE-2099-0001\tkev' "$HOME/.nvm/versions/node")"
  assert_contains "$results" "$HOME/.nvm/versions/node/v18.0.0/bin/node"
  assert_contains "$results" "@example/cli"
  assert_contains "$results" "evil-dep"
  assert_not_contains "$results" "example-extension"
  assert_not_contains "$results" "bundled-docs"
  assert_contains "$results" "$(printf 'homebrew\tCritical\tCVE-2099-0101\t-\t-\tnot-fixed\t\tbrew\texampled\t1.0.0\t%s/homebrew/opt/exampled' "$TMP")"
  assert_contains "$results" "$(printf 'homebrew\tHigh\tCVE-2099-0100\t-\t-\tfixed\t1.0.1')"
  assert_contains "$results" "$(printf 'homebrew\tUnknown\tCVE-2099-0102')"
  assert_contains "$(detail_of vulns)" "6 critical or high, 1 known exploited, 1 malware"
  assert_contains "$results" "$(printf 'High\tGHSA-aaaa-bbbb-0001\t-\t-\tfixed')"
  assert_called "syft scan dir:$HOME/.nvm/versions/node -c "
  assert_contains "$(grep '^grype sbom:' "$CALLS")" " -c "
  assert_contains "$(detail_of vulns)" "3 formulae checked, 1 skipped"
  assert_called 'grype db update'
  [ -s "$VULN_DIR/scanned-at" ] || fail "a complete scan was not stamped"
}

test_vulns_failed_location_keeps_its_previous_results_and_defers() {
  vulns_setup
  run_daily vulns
  rm "$VULN_DIR/scanned-at"
  stub grype 'case "$1" in sbom:*) exit 1 ;; esac'
  run_daily vulns
  assert_eq deferred "$(result_of vulns)"
  assert_contains "$(detail_of vulns)" "failed: $HOME/.nvm/versions/node"
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "v18.0.0/bin/node"
  [ ! -f "$VULN_DIR/scanned-at" ] || fail "a partial scan was stamped as complete"
}

test_vulns_unreadable_homebrew_report_is_not_read_as_clean() {
  vulns_setup
  run_daily vulns
  stub brew "case \"\$1\" in --prefix) echo '$TMP/homebrew' ;; vulns) [ \"\$2\" = --help ] && exit 0; echo 'Error: no network' >&2; exit 1 ;; esac"
  run_daily vulns
  assert_eq deferred "$(result_of vulns)"
  assert_contains "$(detail_of vulns)" "failed: homebrew"
  assert_contains "$(cat "$HOME/Library/Logs/mac-secure/"*.log)" "Error: no network"
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "CVE-2099-0101"
}

test_vulns_without_either_tool_is_skipped_and_names_it() {
  vulns_setup
  rm "$STUBS/syft"
  run_daily vulns
  assert_eq skipped "$(result_of vulns)"
  assert_eq "syft not installed" "$(detail_of vulns)"
  stub syft
  rm "$STUBS/grype"
  run_daily vulns
  assert_eq "grype not installed" "$(detail_of vulns)"
  assert_eq no "$(mac_secure modules --json | python3 -I -c 'import json,sys; print([m["available"] for m in json.load(sys.stdin) if m["id"]=="vulns"][0])')"
}

test_audit_names_the_missing_tool_when_vulns_is_on() {
  mkdir -p "$HOME/.config/mac-secure"
  echo vulns >"$HOME/.config/mac-secure/enabled"
  PATH="$STUBS:/usr/bin:/bin"
  rm "$STUBS/grype"
  assert_contains "$(audit_vulns_only)" "but grype is not installed, so nothing is scanned."
}

test_vulns_homebrew_without_brew_vulns_is_a_reported_gap_not_a_failure() {
  vulns_setup
  stub brew "case \"\$1\" in --prefix) echo '$TMP/homebrew' ;; vulns) echo 'Error: Unknown command: vulns' >&2; exit 1 ;; esac"
  run_daily vulns
  assert_eq ok "$(result_of vulns)"
  assert_contains "$(detail_of vulns)" "this Homebrew has no brew vulns"
  [ -s "$VULN_DIR/scanned-at" ] || fail "the scan was not stamped as complete"
  assert_not_contains "$(cat "$VULN_DIR/latest.tsv")" "homebrew"
}

test_vulns_malformed_rows_are_never_read() {
  local NVM="$HOME/.nvm/versions/node"
  vulns_results 0 \
    "$NVM|Critical|CVE-2099-0001|kev|-|fixed|18.99.0|binary|node|18.0.0|$NVM/v18.0.0/bin/node" \
    "$NVM|Critical|CVE-2099-0009|kev|-|fixed|binary|node|18.0.0|$NVM/v18.0.0/bin/node"
  assert_not_contains "$(mac_secure vulns --all --json)" "CVE-2099-0009"
  assert_not_contains "$(audit_vulns_only)" "CVE-2099-0009"
}

test_vulns_command_changes_nothing() {
  mac_secure vulns >/dev/null 2>&1
  mac_secure notices >/dev/null 2>&1
  vulns_results 0 "$HOME/x|High|CVE-2099-0004|-|-|fixed|2.0.0|npm|b|1.0.0|$HOME/x/node_modules/b/package.json"
  local before
  before=$(find "$HOME" | sort)
  mac_secure vulns >/dev/null
  mac_secure vulns --json >/dev/null
  mac_secure vulns --all b >/dev/null
  mac_secure notices >/dev/null
  mac_secure notices --json >/dev/null
  assert_eq "$before" "$(find "$HOME" | sort)" "files under HOME"
  assert_not_called "sudo"
  assert_not_called "grype"
  assert_not_called "syft"
  assert_not_called "brew"
  assert_not_called "osascript"
}

test_vulns_notifies_only_about_new_urgent_matches() {
  vulns_setup
  run_daily vulns
  assert_called 'osascript'
  assert_contains "$(cat "$CALLS")" 'new critical, known-exploited or malware'
  : >"$CALLS"
  run_daily vulns
  assert_not_called 'osascript'
}

test_vulns_notifies_when_a_later_scan_finds_a_new_urgent_match() {
  vulns_setup
  run_daily vulns
  : >"$CALLS"
  { cat "$FIXTURES/grype-matches.txt"
    printf 'Critical\tCVE-2099-0050\t-\tA new one\tfixed\t2.0.0\tnpm\tnew-thing\t1.0.0\t/v18.0.0/lib/node_modules/new-thing/package.json\n'
  } >"$TMP/more.txt"
  export GRYPE_FIXTURE="$TMP/more.txt"
  run_daily vulns
  assert_contains "$(cat "$CALLS")" '1 new critical, known-exploited or malware'
}

test_vulns_reads_a_description_cut_inside_a_character() {
  vulns_setup
  export LC_ALL=en_US.UTF-8
  printf 'High\tCVE-2099-0070\t-\tAIOHTTP leaks \342\200\tfixed\t3.9.4\tpython\taiohttp\t3.9.3\t/v18.0.0/lib/python/aiohttp-3.9.3.dist-info/METADATA\n' >"$TMP/cut.txt"
  export GRYPE_FIXTURE="$TMP/cut.txt"
  run_daily vulns
  assert_eq ok "$(result_of vulns)"
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "CVE-2099-0070"
}

test_vulns_reads_a_location_inside_node_modules() {
  vulns_setup
  rm -r "$HOME/.nvm"
  mkdir -p "$HOME/lib/node_modules" "$HOME/.config/mac-secure"
  echo "VULN_SCAN_PATHS=~/lib/node_modules" >"$HOME/.config/mac-secure/config"
  printf 'High\tCVE-2099-0060\t-\tA bug\tfixed\t1.0.1\tnpm\tminimist\t1.0.0\t/minimist/package.json\n' >"$TMP/nm.txt"
  export GRYPE_FIXTURE="$TMP/nm.txt"
  run_daily vulns
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "$HOME/lib/node_modules/minimist/package.json"
}

test_vulns_lists_a_location_once_however_it_is_written() {
  PATH="$STUBS:$PATH"
  . "$REPO/lib/common.sh"
  . "$REPO/lib/vulns.sh"
  mkdir -p "$MS_CONFIG_DIR"
  echo 'VULN_SCAN_PATHS=~/.nvm/versions/node/:~/src//' >"$MS_CONFIG_DIR/config"
  local targets
  targets=$(ms_vuln_targets)
  assert_eq 1 "$(printf '%s\n' "$targets" | grep -cx "$HOME/.nvm/versions/node")" "nvm listings"
  assert_eq 1 "$(printf '%s\n' "$targets" | grep -cx "$HOME/src")" "src listings"
}

test_vulns_timeout_leaves_no_work_directory() {
  vulns_setup
  stub syft 'sleep 30'
  export MS_MODULE_LIMIT=2 TMPDIR="$TMP/tmp"
  mkdir -p "$TMPDIR"
  run_daily vulns
  assert_eq failed "$(result_of vulns)"
  assert_eq "" "$(find "$TMPDIR" -name 'mac-secure-vulns.*')" "work directories left"
}

test_notices_prints_nothing_when_nothing_needs_attention() {
  assert_eq "" "$(mac_secure notices)"
  assert_eq "[]" "$(mac_secure notices --json)"
}

test_notices_report_malware_new_known_exploited_failures_and_a_stale_scan() {
  local NVM="$HOME/.nvm/versions/node" old new now
  vulns_results 9 \
    "$NVM|Critical|CVE-2099-0001|kev|-|fixed|18.99.0|binary|node|18.0.0|$NVM/v18.0.0/bin/node" \
    "$NVM|High|CVE-2099-0005|kev|-|fixed|1.0.1|npm|old-one|1.0.0|$NVM/v18.0.0/lib/node_modules/old-one/package.json" \
    "$NVM|Critical|GHSA-mmmm-0000-0003|-|malware|not-fixed||npm|evil-dep|1.0.1|$NVM/v18.0.0/lib/node_modules/evil-dep/package.json"
  now=$(date +%s)
  printf '%s|CVE-2099-0001|node|18.0.0|kev|-\t%s\n%s|CVE-2099-0005|old-one|1.0.0|kev|-\t%s\n' "$NVM" "$now" "$NVM" $((now - 30 * 86400)) \
    >"$HOME/Library/Application Support/mac-secure/vulns/first-seen.tsv"
  printf '2026-11-03 04:15\tbrew-casks\tfailed\t10\tx\n2026-11-03 04:15\trust\tok\t5\t\n2026-11-03 04:15\tuv\tfailed\t5\t\n' \
    >"$HOME/Library/Application Support/mac-secure/last-run.tsv"
  mkdir -p "$HOME/.config/mac-secure"
  printf 'vulns\nbrew-casks\n' >"$HOME/.config/mac-secure/enabled"
  local out
  out=$(mac_secure notices)
  assert_contains "$out" "mac-secure: 1 package matches a malware advisory. Next: mac-secure vulns --json lists them"
  assert_not_contains "$out" "evil-dep"
  assert_contains "$out" "mac-secure: 1 known-exploited vulnerability first found in the last 7 days, in ~/.nvm/versions/node. Next:"
  assert_contains "$out" "mac-secure: The last update run failed for: brew-casks. Next: mac-secure logs"
  assert_not_contains "$out" "uv"
  assert_contains "$out" "mac-secure: The last complete vulnerability scan is 9 days old."
  assert_eq 4 "$(printf '%s\n' "$out" | grep -c '^mac-secure: ')" "lines with the prefix"
  assert_eq 4 "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "lines"
  out=$(mac_secure notices --json)
  assert_json "$out"
  assert_contains "$out" '{"id":"malware-package","severity":"high","notice":"1 package matches a malware advisory."'
  assert_contains "$out" '"id":"known-exploited-new"'
  assert_contains "$out" '"id":"update-run-failed"'
  assert_contains "$out" '"id":"vuln-scan-stale"'
}

test_notices_call_a_match_new_when_it_becomes_known_exploited() {
  local NVM="$HOME/.nvm/versions/node"
  mkdir -p "$HOME/.config/mac-secure"
  echo vulns >"$HOME/.config/mac-secure/enabled"
  vulns_results 0 "$NVM|Critical|CVE-2099-0001|kev|-|fixed|18.99.0|binary|node|18.0.0|$NVM/v18.0.0/bin/node"
  printf '%s|CVE-2099-0001|node|18.0.0|-|-\t1000\n' "$NVM" >"$HOME/Library/Application Support/mac-secure/vulns/first-seen.tsv"
  (
    . "$REPO/lib/common.sh"; . "$REPO/lib/modules.sh"; . "$REPO/lib/vulns.sh"
    ms_vuln_record_first_seen ""
  )
  assert_contains "$(mac_secure notices)" "1 known-exploited vulnerability first found in the last 7 days"
}

test_vulns_upgrade_dates_matches_the_previous_results_had_as_not_new() {
  vulns_setup
  run_daily vulns
  rm "$VULN_DIR/first-seen.tsv"
  run_daily vulns
  assert_contains "$(cat "$VULN_DIR/first-seen.tsv")" "$(printf 'CVE-2099-0001|node|18.0.0|kev|-\t0')"
  mkdir -p "$HOME/.config/mac-secure"
  grep -qx vulns "$HOME/.config/mac-secure/enabled" 2>/dev/null || echo vulns >>"$HOME/.config/mac-secure/enabled"
  assert_not_contains "$(mac_secure notices)" "known-exploited"
}

test_notices_leave_out_results_once_vulns_is_off() {
  local NVM="$HOME/.nvm/versions/node"
  vulns_results 0 "$NVM|Critical|GHSA-mmmm-0000-0003|-|malware|not-fixed||npm|evil-dep|1.0.1|$NVM/x/node_modules/evil-dep/package.json"
  assert_eq "" "$(mac_secure notices)"
}

test_vulns_first_seen_keeps_the_first_date_and_drops_gone_matches() {
  vulns_setup
  run_daily vulns
  local file="$VULN_DIR/first-seen.tsv"
  assert_contains "$(cat "$file")" "CVE-2099-0001|node|18.0.0"
  sed 's/	[0-9]*$/	1000/' "$file" >"$file.x" && mv "$file.x" "$file"
  printf 'gone|CVE-1|x|1\t1000\n' >>"$file"
  run_daily vulns
  assert_contains "$(cat "$file")" "$(printf 'CVE-2099-0001|node|18.0.0|kev|-\t1000')"
  assert_not_contains "$(cat "$file")" "gone|CVE-1"
}

test_session_start_hook_is_silent_without_mac_secure_and_relays_notices() {
  local hook="$REPO/hooks/session-start" out
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "SessionStart" in d["hooks"]' "$REPO/hooks/hooks.json" || fail "hooks.json lacks hooks.SessionStart"
  out=$(PATH="/usr/bin:/bin" HOME="$TMP/nohome" "$hook")
  assert_eq 0 $? "hook exit status"
  assert_eq "" "$out"
  mkdir -p "$TMP/bin"
  printf '#!/bin/bash\n[ "$1" = notices ] && echo "mac-secure: something"\nexit 3\n' >"$TMP/bin/mac-secure"
  chmod +x "$TMP/bin/mac-secure"
  out=$(PATH="$TMP/bin:/usr/bin:/bin" "$hook")
  assert_eq 0 $? "hook exit status when mac-secure fails"
  assert_eq "mac-secure: something" "$out"
  mkdir -p "$HOME/.config/mac-secure"
  echo SESSION_NOTICES=no >"$HOME/.config/mac-secure/config"
  assert_eq "" "$(PATH="$TMP/bin:/usr/bin:/bin" "$hook")" "output with SESSION_NOTICES=no"
}

test_vulns_scan_paths_setting_adds_locations() {
  PATH="$STUBS:$PATH"
  . "$REPO/lib/common.sh"
  . "$REPO/lib/vulns.sh"
  mkdir -p "$MS_CONFIG_DIR"
  echo 'VULN_SCAN_PATHS=~/projects:/opt/tools' >"$MS_CONFIG_DIR/config"
  local targets
  targets=$(ms_vuln_targets)
  assert_contains "$targets" "$HOME/projects"
  assert_contains "$targets" "/opt/tools"
  assert_contains "$targets" "$HOME/.npm/_npx"
}

test_audit_vulns_groups_by_location_and_raises_known_exploited() {
  local out
  local NVM="$HOME/.nvm/versions/node"
  vulns_results 0 \
    "$NVM|Critical|CVE-2099-0001|kev|-|fixed|18.99.0|binary|node|18.0.0|$NVM/v18.0.0/bin/node" \
    "$NVM|High|GHSA-aaaa-bbbb-0001|-|-|fixed|7.9.9|npm|tar|6.0.0|$NVM/v18.0.0/lib/node_modules/npm/node_modules/tar/package.json" \
    "$NVM|High|GHSA-aaaa-bbbb-0003|-|-|fixed|7.9.9|npm|tar|6.0.0|$NVM/v18.0.0/lib/node_modules/npm/node_modules/tar/package.json" \
    "$NVM|Medium|CVE-2099-0002|-|-|not-fixed||npm|minimist|1.0.0|$NVM/v18.0.0/lib/node_modules/minimist/package.json" \
    "$NVM|Critical|GHSA-mmmm-0000-0003|-|malware|not-fixed||npm|evil-dep|1.0.1|$NVM/v18.0.0/lib/node_modules/x/node_modules/evil-dep/package.json" \
    "/Applications|High|CVE-2099-0200|-|-|not-fixed||go-module|stdlib|go1.17.0|/Applications/Old.app/Contents/MacOS/old"
  out=$(audit_vulns_only)
  assert_contains "$out" "$(printf 'high\tvulnerable-software\t~/.nvm/versions/node: 3 critical or high vulnerabilities in 2 packages, 1 known to be exploited (CVE-2099-0001). Most affected: v18.0.0 (3).')"
  assert_contains "$out" "mac-secure vulns ~/.nvm/versions/node lists each one"
  assert_contains "$out" "$(printf 'high\tmalware-package\tevil-dep 1.0.1 at ~/.nvm/versions/node/v18.0.0/lib/node_modules/x/node_modules/evil-dep/package.json matches malware advisory GHSA-mmmm-0000-0003.')"
  assert_contains "$out" "$(printf 'medium\tvulnerable-software\t/Applications: 1 critical or high vulnerability in 1 package. Most affected: Old.app (1).')"
  assert_contains "$out" "$(printf 'info\tlower-vulnerabilities\t1 medium, low or unscored vulnerability in 1 location.')"
  assert_not_contains "$out" "vuln-scan"
}

test_audit_vulns_reports_a_scan_that_is_off_missing_or_stale() {
  local NVM="$HOME/.nvm/versions/node"
  assert_contains "$(VULNS_OFF=1 audit_vulns_only)" "$(printf 'low\tvuln-scan-off')"
  assert_contains "$(audit_vulns_only)" "$(printf 'medium\tvuln-scan-missing\tThe vulns module is on, but no scan has finished.')"
  vulns_results 9 "$NVM|Low|CVE-2099-0003|-|-|fixed|1.0.1|npm|a|1.0.0|$NVM/v18.0.0/lib/node_modules/a/package.json"
  assert_contains "$(audit_vulns_only)" "$(printf 'medium\tvuln-scan-stale\tThe last complete vulnerability scan is 9 days old')"
  rm "$HOME/Library/Application Support/mac-secure/vulns/scanned-at"
  assert_contains "$(audit_vulns_only)" "No vulnerability scan has finished every location"
}

test_vulns_ignore_file_hides_reviewed_matches() {
  local NVM="$HOME/.nvm/versions/node"
  vulns_results 0 \
    "$NVM|Critical|GHSA-mmmm-0000-0003|-|malware|not-fixed||npm|evil-dep|1.0.1|$NVM/v18.0.0/lib/node_modules/evil-dep/package.json" \
    "$NVM|Critical|GHSA-mmmm-0000-0003|-|malware|not-fixed||npm|evil-dep|1.0.1|$HOME/other/node_modules/evil-dep/package.json" \
    "$NVM|High|CVE-2099-0004|-|-|fixed|2.0.0|npm|b|1.0.0|$NVM/v18.0.0/lib/node_modules/b/package.json"
  mkdir -p "$HOME/.config/mac-secure"
  printf '# reviewed\nGHSA-mmmm-0000-0003 | ~/.nvm/versions | same name as our internal package\nCVE-2099-0004\n' >"$HOME/.config/mac-secure/vulns-ignore.txt"
  local out
  out=$(mac_secure vulns)
  # The listing shows the home folder as a tilde.
  local home_mark='~'
  assert_contains "$out" "$home_mark/other/node_modules/evil-dep"
  assert_not_contains "$out" "$home_mark/.nvm/versions/node/v18.0.0/lib/node_modules/evil-dep"
  assert_not_contains "$out" "CVE-2099-0004"
}

test_audit_reports_nothing_from_old_results_once_vulns_is_off() {
  local NVM="$HOME/.nvm/versions/node" out
  vulns_results 0 "$NVM|Critical|CVE-2099-0001|kev|-|fixed|18.99.0|binary|node|18.0.0|$NVM/v18.0.0/bin/node"
  out=$(VULNS_OFF=1 audit_vulns_only)
  assert_contains "$out" "$(printf 'low\tvuln-scan-off')"
  assert_not_contains "$out" "vulnerable-software"
  assert_contains "$(mac_secure vulns)" "The vulns module is off, so these results are not being updated."
}

test_audit_reports_coverage_gaps() {
  vulns_setup
  run_daily vulns
  local out
  out=$(audit_vulns_only)
  assert_contains "$out" "$(printf 'low\tvuln-coverage-gap\tbrew vulns could not check other-tap-formula (untrusted_tap).')"
  assert_contains "$out" "1 Homebrew formulae have no source URL brew vulns supports"
}

test_vulns_names_formulae_checked_at_the_wrong_version() {
  vulns_setup
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); d["outdated_without_sbom"]=["oldfx"]; json.dump(d, open(sys.argv[2],"w"))' \
    "$FIXTURES/brew-vulns.json" "$TMP/brew-stale.json"
  stub brew "case \"\$1\" in --prefix) echo '$TMP/homebrew' ;; vulns) [ \"\$2\" = --help ] && exit 0; cat '$TMP/brew-stale.json'; exit 1 ;; esac"
  run_daily vulns
  assert_contains "$(cat "$VULN_DIR/gaps.tsv")" "$(printf 'brew vulns checked the current formula, not the installed version, of oldfx')"
  assert_contains "$(cat "$VULN_DIR/gaps.tsv")" "$(printf '\tbrew upgrade oldfx')"
}

test_vulns_other_brew_errors_keep_homebrew_results() {
  vulns_setup
  run_daily vulns
  stub brew "case \"\$1\" in --prefix) echo '$TMP/homebrew' ;; vulns) echo 'Error: Failed to install Homebrew Portable Ruby' >&2; exit 1 ;; esac"
  run_daily vulns
  assert_eq deferred "$(result_of vulns)"
  assert_contains "$(detail_of vulns)" "failed: homebrew"
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "CVE-2099-0101"
}

test_vulns_homebrew_can_be_left_out() {
  vulns_setup
  mkdir -p "$HOME/.config/mac-secure"
  echo VULN_HOMEBREW=no >"$HOME/.config/mac-secure/config"
  run_daily vulns
  assert_eq ok "$(result_of vulns)"
  assert_not_called 'brew vulns'
  assert_not_contains "$(cat "$VULN_DIR/latest.tsv")" "homebrew"
}

test_vulns_failed_database_update_is_not_a_complete_scan() {
  vulns_setup
  stub grype "case \"\$1 \$2\" in 'db update') exit 1 ;; esac; case \"\$1\" in sbom:*) cat '$FIXTURES/grype-matches.txt' ;; esac"
  run_daily vulns
  assert_eq deferred "$(result_of vulns)"
  assert_contains "$(detail_of vulns)" "failed: database-update"
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "CVE-2099-0001"
  [ ! -f "$VULN_DIR/scanned-at" ] || fail "a scan with an old database was stamped complete"
}

test_vulns_missing_configured_location_keeps_its_results() {
  vulns_setup
  mkdir -p "$HOME/.config/mac-secure" "$TMP/volume/tools"
  echo "VULN_SCAN_PATHS=$TMP/volume/tools" >"$HOME/.config/mac-secure/config"
  run_daily vulns
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "$TMP/volume/tools/v18.0.0/bin/node"
  rm -r "$TMP/volume"
  rm "$VULN_DIR/scanned-at"
  run_daily vulns
  assert_eq ok "$(result_of vulns)"
  [ -s "$VULN_DIR/scanned-at" ] || fail "a missing configured location held back the stamp"
  assert_contains "$(cat "$VULN_DIR/latest.tsv")" "$TMP/volume/tools/v18.0.0/bin/node"
  assert_contains "$(audit_vulns_only)" "$(printf 'low\tvuln-coverage-gap\t%s, from VULN_SCAN_PATHS, was not there to scan' "$TMP/volume/tools")"
}

test_vulns_output_drops_control_characters() {
  local NVM="$HOME/.nvm/versions/node" out
  mkdir -p "$HOME/.config/mac-secure"
  echo vulns >"$HOME/.config/mac-secure/enabled"
  vulns_results 0 "$NVM|High|CVE-2099-0004|-|-|fixed|2.0.0|npm|$(printf 'b\033[2Jad')|1.0.0|$NVM/x/node_modules/b/package.json"
  out=$(mac_secure vulns)
  assert_contains "$out" "b[2Jad 1.0.0"
  assert_not_contains "$out" "$(printf '\033')"
  assert_not_contains "$(audit_vulns_only)" "$(printf '\033')"
}

test_vulns_takes_one_filter() {
  vulns_results 0 "$HOME/x|High|CVE-2099-0004|-|-|fixed|2.0.0|npm|b|1.0.0|$HOME/x/node_modules/b/package.json"
  mac_secure vulns nvm express >/dev/null 2>&1
  assert_eq 2 $? "exit status with two filters"
}

test_vulns_command_refuses_without_results_and_prints_valid_json() {
  local NVM="$HOME/.nvm/versions/node"
  mac_secure vulns >/dev/null 2>&1
  assert_eq 2 $? "exit status without results"
  vulns_results 0 \
    "$NVM|Critical|CVE-2099-0001|kev|-|fixed|18.99.0|binary|node|18.0.0|$NVM/v18.0.0/bin/node" \
    "/Applications|High|CVE-2099-0200|-|-|not-fixed||go-module|stdlib|go1.17.0|/Applications/Old \"quoted\".app/old" \
    "/Applications|Low|CVE-2099-0201|-|-|fixed|1.1|npm|c|1.0|/Applications/Old.app/node_modules/c/package.json"
  local out
  out=$(mac_secure vulns --json)
  assert_json "$out"
  assert_contains "$out" '"known_exploited":true'
  assert_contains "$out" '"severity":"critical"'
  assert_contains "$out" '"fixed_in":null'
  assert_contains "$out" '"module_enabled":false'
  assert_contains "$out" "$(printf '"last_complete_scan":"%s' "$(date -u '+%Y-%m-%dT')")"
  assert_contains "$out" 'Old \"quoted\".app'
  assert_not_contains "$out" 'CVE-2099-0201'
  assert_contains "$(mac_secure vulns --all --json)" 'CVE-2099-0201'
  out=$(mac_secure vulns /Applications)
  assert_contains "$out" 'CVE-2099-0200'
  assert_not_contains "$out" 'CVE-2099-0001'
  vulns_results 0 \
    "homebrew|High|CVE-2099-0100|-|-|fixed|1.0.1|brew|exampled|1.0.0|/opt/homebrew/opt/exampled" \
    "/opt/homebrew/lib|High|CVE-2099-0300|-|-|fixed|2.0|python|tornado|1.0|/opt/homebrew/lib/python3.9/site-packages/tornado-1.0.dist-info/METADATA"
  out=$(mac_secure vulns homebrew)
  assert_contains "$out" 'CVE-2099-0100'
  assert_not_contains "$out" 'CVE-2099-0300'
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
  # status reads this as the user, and the job's umask would leave a new file root-only.
  assert_eq "-rw-r--r--" "$(ls -l "$RESULTS" | cut -c1-10)" "results mode"
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
