#!/bin/bash
# Installs and changes the root job. `mac-secure` runs this with sudo.
# Usage: install-root.sh [--hour <0-23>] [--vendors <file>] refresh | enable <module>... | disable <module>... | uninstall
#
# --vendors names the wanted list: a file that does not exist means no vendor installers.

set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

HERE=$(cd "$(dirname "$0")" && pwd)
LIBEXEC=/usr/local/libexec/mac-secure
STATE=/var/db/mac-secure
LOG=/var/log/mac-secure/macos.log
CONF=$LIBEXEC/root.conf
LABEL=io.github.piekstra.mac-secure.macos
PLIST=/Library/LaunchDaemons/$LABEL.plist
SERVICE_USER=secupdate
PASSWORD_FILE=$STATE/service-password
ACCOUNT_MARKER=$STATE/created-service-account
WAKE_MARKER=$STATE/scheduled-wake
ADMIN_USER=${SUDO_USER:-}
ROOT_MODULES="macos macos-unattended macos-major app-store firewall vendor-installers"
VENDOR_LINE='^[a-z0-9][a-z0-9@.+-]*\|[A-Z0-9]{10}$'
HOUR=3
VENDORS=""

# launchd runs the job by path, so whoever can rename a parent directory can replace the job.
path_is_root_only() {
  [ ! -L "$1" ] && [ "$(stat -f %u "$1")" = 0 ] && [ $((0$(stat -f %Lp "$1") & 022)) -eq 0 ]
}

check_install_path() {
  local path
  for path in /usr /usr/local /usr/local/libexec; do
    [ -e "$path" ] || continue
    path_is_root_only "$path" || {
      echo "$path must be owned by root and writable only by root. Refusing to install a root job under it." >&2
      exit 1
    }
  done
}

install_files() {
  local name
  check_install_path
  install -d -o root -g wheel -m 755 "$LIBEXEC"
  install -o root -g wheel -m 755 "$HERE/macos-update" "$LIBEXEC/macos-update"
  # Kept so `mac-secure refresh` can show what would change in these as well.
  for name in install-root.sh feed-password.exp; do
    install -o root -g wheel -m 644 "$HERE/$name" "$LIBEXEC/$name"
  done
  install -d -o root -g wheel -m 700 "$STATE"
  [ -f "$CONF" ] || install -o root -g wheel -m 644 /dev/null "$CONF"
  if [ -n "$VENDORS" ] && [ -f "$VENDORS" ]; then
    grep -E "$VENDOR_LINE" "$VENDORS" >"$LIBEXEC/vendor-installers.txt.new" || true
    chown root:wheel "$LIBEXEC/vendor-installers.txt.new"
    chmod 644 "$LIBEXEC/vendor-installers.txt.new"
    mv -f "$LIBEXEC/vendor-installers.txt.new" "$LIBEXEC/vendor-installers.txt"
  elif [ -n "$VENDORS" ]; then
    rm -f "$LIBEXEC/vendor-installers.txt"
  fi
}

install_daemon() {
  cat >"$PLIST.new" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$LIBEXEC/macos-update</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>0</integer></dict>
</dict>
</plist>
PLIST
  chown root:wheel "$PLIST.new"
  chmod 644 "$PLIST.new"
  plutil -lint "$PLIST.new" >/dev/null
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  mv -f "$PLIST.new" "$PLIST"
  launchctl bootstrap system "$PLIST"
}

repeat_schedule() {
  pmset -g sched | awk '/^Repeating power events/{on=1; next} /^[^ ]/{on=0} on'
}

# True when a repeating wake exists that this tool did not set. The marker holds the schedule as it
# read right after this tool set it, so one changed later counts as someone else's.
foreign_wake_exists() {
  local current
  current=$(repeat_schedule)
  [ -n "$current" ] && { [ ! -f "$WAKE_MARKER" ] || [ "$current" != "$(cat "$WAKE_MARKER")" ]; }
}

# Wakes the Mac 5 minutes before the job. A Mac holds only one repeating wake, so one this tool did
# not set is left alone; the job then runs at the next wake after its hour.
schedule_wake() {
  local at
  at=$(printf '%02d:55:00' $(((HOUR + 23) % 24)))
  if foreign_wake_exists; then
    echo "Leaving your existing repeating wake schedule alone. The job runs at the next wake after $HOUR:00."
    return 0
  fi
  pmset repeat wakeorpoweron MTWRFSU "$at"
  repeat_schedule >"$WAKE_MARKER"
}

cancel_wake() {
  [ -f "$WAKE_MARKER" ] || return 0
  if foreign_wake_exists; then
    echo "Leaving your repeating wake schedule alone: this tool did not set it."
  else
    pmset repeat cancel
  fi
  rm -f "$WAKE_MARKER"
}

conf_add() {
  grep -qxF "$1" "$CONF" 2>/dev/null || echo "$1" >>"$CONF"
}

conf_remove() {
  grep -vxF "$1" "$CONF" >"$CONF.new" || true
  chown "$(id -u):$(id -g)" "$CONF.new"
  chmod 644 "$CONF.new"
  mv -f "$CONF.new" "$CONF"
}

feed_password() {
  /usr/bin/expect -f "$HERE/feed-password.exp" "$PASSWORD_FILE" "$@"
}

# sysadminctl exits 0 when it fails, so each result is read back.
create_service_account() {
  local created=0
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    [ -s "$PASSWORD_FILE" ] || {
      echo "Account '$SERVICE_USER' exists but $PASSWORD_FILE does not. Remove the account or restore the file." >&2
      return 1
    }
  else
    (umask 077 && openssl rand -base64 33 | tr -d '\n' >"$PASSWORD_FILE")
    # Run as root, this command prompts for nothing but the new account's password.
    feed_password '(?i)password' sysadminctl -addUser "$SERVICE_USER" -fullName "Security Updates" -admin -password -
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
      echo "Could not create '$SERVICE_USER'." >&2
      rm -f "$PASSWORD_FILE"
      return 1
    fi
    dscl . -create "/Users/$SERVICE_USER" IsHidden 1
    touch "$ACCOUNT_MARKER"
    created=1
  fi
  echo "Enter your login password when asked, to let '$SERVICE_USER' authorize updates."
  feed_password "Enter password for $SERVICE_USER ?:" sysadminctl -adminUser "$ADMIN_USER" -adminPassword - -secureTokenOn "$SERVICE_USER" -password -
  if ! sysadminctl -secureTokenStatus "$SERVICE_USER" 2>&1 | grep -q ENABLED; then
    echo "'$SERVICE_USER' did not get a secure token, so it cannot authorize updates." >&2
    # An admin account nothing uses must not outlive a mistyped password.
    [ "$created" -eq 0 ] || remove_account
    return 1
  fi
}

setup_account() {
  [ -n "$ADMIN_USER" ] || { echo "macos-unattended must be enabled through sudo from your own account." >&2; return 1; }
  cat <<TEXT

macos-unattended

On Apple Silicon, softwareupdate needs a volume owner's password to install an OS update.
This creates a hidden admin account, '$SERVICE_USER', with a random password in a root-only file.
Your own password is not stored. The Mac then installs macOS updates and restarts at $HOUR:00, after
a 5-minute warning, whether or not you are at it.

Anyone who gains root on this Mac can read that password, but root can already do what it allows.
The account may appear on the FileVault unlock screen.

TEXT
  printf "Type 'create' to create the account: "
  read -r answer </dev/tty
  [ "$answer" = create ] || { echo "Account not created. macos-unattended stays off."; return 1; }
  create_service_account
}

remove_account() {
  if [ -f "$ACCOUNT_MARKER" ]; then
    sysadminctl -deleteUser "$SERVICE_USER"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
      echo "Could not delete account '$SERVICE_USER'. Delete it in System Settings, Users & Groups." >&2
      return 1
    fi
    rm -f "$ACCOUNT_MARKER"
  elif id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "Leaving account '$SERVICE_USER': this tool did not create it."
  fi
  rm -f "$PASSWORD_FILE"
}

run_job_now() {
  echo
  echo "Applying settings and installing updates that need no restart."
  echo "A restart-required macOS update is only downloaded now."
  "$LIBEXEC/macos-update" --no-restart
  tail -25 "$LOG"
}

is_root_module() {
  case " $ROOT_MODULES " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

main() {
  [ "$(id -u)" = 0 ] || { echo "run this with sudo" >&2; exit 1; }
  while [ $# -gt 0 ]; do
    case "$1" in
      --hour) HOUR=$2; shift 2 ;;
      --vendors) VENDORS=$2; shift 2 ;;
      *) break ;;
    esac
  done
  case "$HOUR" in
    [0-9]|1[0-9]|2[0-3]) ;;
    *) echo "--hour must be 0 to 23" >&2; exit 2 ;;
  esac
  local action=${1:-} module
  [ $# -eq 0 ] || shift

  case "$action" in
    refresh)
      install_files
      install_daemon
      schedule_wake
      run_job_now
      ;;
    enable)
      for module in "$@"; do
        is_root_module "$module" || { echo "not a root module: $module" >&2; exit 2; }
      done
      install_files
      for module in "$@"; do
        if [ "$module" = macos-unattended ]; then
          setup_account || continue
        fi
        conf_add "$module"
        echo "enabled $module"
      done
      install_daemon
      schedule_wake
      run_job_now
      ;;
    disable)
      for module in "$@"; do
        is_root_module "$module" || { echo "not a root module: $module" >&2; exit 2; }
        if [ -f "$CONF" ]; then
          conf_remove "$module"
        fi
        [ "$module" != macos-unattended ] || remove_account
        echo "disabled $module"
      done
      ;;
    uninstall)
      launchctl bootout "system/$LABEL" 2>/dev/null || true
      rm -f "$PLIST"
      remove_account
      cancel_wake
      rm -rf "$LIBEXEC" "$STATE" /var/log/mac-secure
      echo "Removed the root job. The firewall, App Store and Software Update settings stay as they are."
      ;;
    *)
      echo "usage: install-root.sh [--hour <0-23>] [--vendors <file>] refresh | enable <module>... | disable <module>... | uninstall" >&2
      exit 2
      ;;
  esac
}

# sudo keeps the calling user's HOME, and tools read settings from it.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  [ -n "${MS_CLEAN_ENV:-}" ] || exec /usr/bin/env -i MS_CLEAN_ENV=1 HOME=/var/root SUDO_USER="${SUDO_USER:-}" TERM="${TERM:-dumb}" /bin/bash "$0" "$@"
  main "$@"
fi
