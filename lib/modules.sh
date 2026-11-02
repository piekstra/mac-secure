# shellcheck shell=bash
# The module registry. Fields: id|scope|tool|recommended|summary|disruption
# Order is run order. A tool of "-" means no external tool is needed.

ms_modules() {
  cat <<'EOF'
brew-formulae|user|brew|yes|Upgrade every Homebrew formula|Running services keep old code until they restart.
adopt-apps|user|brew|no|Move the apps listed in adopt-apps.txt under Homebrew, so they update while closed|Replaces each app and closes it if running.
brew-casks|user|brew|yes|Upgrade every cask, including apps that claim to update themselves|Closes an app being upgraded, then reopens it.
npm|user|npm|yes|Upgrade global npm packages to latest|A new major version can change how a CLI behaves.
rust|user|rustup|yes|Update Rust toolchains and rustup|None.
cargo|user|cargo|yes|Reinstall crates installed from crates.io|Compiles from source; can take many minutes.
cargo-local|user|cargo-audit|no|Rebuild local-source Rust CLIs whose lockfile has a RustSec advisory|Replaces the installed binary with a build of the default branch.
gcloud|user|gcloud|yes|Update Google Cloud SDK components|None.
bun|user|bun|yes|Upgrade Bun|None.
uv|user|uv|yes|Upgrade Pythons managed by uv|None.
playwright|user|-|yes|Keep the Playwright copies you already use, and their browsers, current|Removes cached npx copies that no running process uses.
claude-code|user|claude|yes|Update Claude Code|None.
colima|user|colima|no|Patch Ubuntu and Docker in running Colima VMs|Restarts Docker and VMs. Waits while a CI job is running.
browsers|user|-|yes|Restart browsers that still run old code after an update|Closes the browser 30 minutes after a warning. Stops stale automation profiles without a restart.
macos|root|-|yes|Keep macOS auto-update settings on, install updates that need no restart, download the rest|Safari closes when it updates. macOS's own automatic install can restart the Mac overnight.
macos-unattended|root|-|no|Install restart-required macOS updates by itself at the scheduled hour|Creates a hidden admin account with a stored random password. Restarts the Mac after a 5-minute warning.
macos-major|root|-|no|Include new major macOS versions|A major upgrade can break software that has not caught up.
app-store|root|-|yes|Keep App Store auto-updates on|Apps can close when they update.
firewall|root|-|yes|Keep the macOS firewall on|An unsigned program that listens beyond this Mac raises an allow dialog.
vendor-installers|root|-|no|Keep the pkg-based apps in vendor-installers.txt current|An app can close when its installer runs.
EOF
}

# Read once: `status` looks up every field of every module.
MS_MODULE_TABLE=$(ms_modules)

ms_module_ids() {
  local id _
  while IFS='|' read -r id _; do
    echo "$id"
  done <<EOF
$MS_MODULE_TABLE
EOF
}

ms_module_field() {
  local f1 f2 f3 f4 f5 f6
  while IFS='|' read -r f1 f2 f3 f4 f5 f6; do
    [ "$f1" = "$1" ] || continue
    case "$2" in
      1) echo "$f1" ;;
      2) echo "$f2" ;;
      3) echo "$f3" ;;
      4) echo "$f4" ;;
      5) echo "$f5" ;;
      6) echo "$f6" ;;
    esac
    return
  done <<EOF
$MS_MODULE_TABLE
EOF
}

ms_module_exists() { ms_module_ids | grep -qxF "$1"; }

ms_module_available() {
  local tool
  tool=$(ms_module_field "$1" 3)
  [ "$tool" = "-" ] || command -v "$tool" >/dev/null 2>&1
}

ms_recommended_ids() {
  printf '%s\n' "$MS_MODULE_TABLE" | awk -F'|' '$4=="yes"{print $1}'
}

ms_user_enabled() {
  grep -qxF "$1" "$MS_CONFIG_DIR/enabled" 2>/dev/null
}

ms_root_enabled() {
  grep -qxF "$1" "$MS_ROOT_CONF" 2>/dev/null
}

ms_module_enabled() {
  if [ "$(ms_module_field "$1" 2)" = root ]; then
    ms_root_enabled "$1"
  else
    ms_user_enabled "$1"
  fi
}
