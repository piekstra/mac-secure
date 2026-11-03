#!/bin/bash
# Plain shell tests. Every tool that changes a system is replaced with a stub on PATH, so a run
# cannot reach the real softwareupdate, brew, launchctl or sudo.
# Usage: tests/run.sh [name filter]

set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
FIXTURES="$REPO/tests/fixtures"
FILTER=${1:-}
PASSED=0
FAILED=0
FAILED_NAMES=""

STUBBED_TOOLS="brew npm npx rustup rustc cargo cargo-audit gcloud bun uv claude colima limactl launchctl defaults sudo
softwareupdate installer pmset curl pkgutil spctl shasum open osascript sysadminctl dscl dseditgroup fdesetup csrutil
sw_vers socketfilterfw nc profiles systemextensionsctl lsof pkill file xattr"

# Usage: stub <tool> [script body]. Every stub records its arguments in $CALLS.
stub() {
  {
    echo '#!/bin/bash'
    printf 'printf "%%s\\n" "%s $*" >>"$CALLS"\n' "$1"
    printf '%s\n' "${2:-exit 0}"
  } >"$STUBS/$1"
  chmod +x "$STUBS/$1"
}

sandbox() {
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/mac-secure-test.XXXXXX")
  export HOME="$TMP/home"
  mkdir -p "$HOME"
  # Tools that find their data from the environment rather than HOME would reach the real system.
  unset NVM_DIR
  STUBS="$TMP/stubs"
  mkdir -p "$STUBS"
  export CALLS="$TMP/calls"
  : >"$CALLS"
  export MS_JOB_PATH="$STUBS:/usr/bin:/bin:/usr/sbin:/sbin"
  export MS_OSASCRIPT="$STUBS/osascript" MS_OPEN="$STUBS/open" MS_FIREWALL="$STUBS/socketfilterfw"
  export MS_ROOT_LIBEXEC="$TMP/libexec" MS_ROOT_LOG="$TMP/macos.log" MS_ROOT_RESULTS="$TMP/root-results.tsv"
  export MS_ROOT_PLIST="$TMP/macos.plist" MS_APPLICATIONS_DIR="$TMP/Applications"
  mkdir -p "$MS_APPLICATIONS_DIR"
  local tool
  for tool in $STUBBED_TOOLS; do
    stub "$tool"
  done
  stub uname 'case "$1" in -m) echo arm64 ;; *) echo Darwin ;; esac'
  stub defaults 'case "$1" in read) exit 1 ;; esac'
  command -v plutil >/dev/null 2>&1 || stub plutil
  stub df 'printf "Filesystem 1024-blocks Used Available\n/dev/disk 1 1 %s\n" "$((${FREE_GIB:-100} * 1048576))"'
}

fail() {
  printf '    %s\n' "$*"
  exit 1
}

assert_eq() {
  [ "$1" = "$2" ] || fail "${3:-values differ}: expected [$1], got [$2]"
}

assert_contains() {
  case "$1" in
    *"$2"*) ;;
    *) fail "${3:-text} does not contain [$2]: [$1]" ;;
  esac
}

assert_not_contains() {
  case "$1" in
    *"$2"*) fail "${3:-text} contains [$2]: [$1]" ;;
  esac
}

assert_called() {
  grep -qF -- "$1" "$CALLS" || fail "not called: [$1]. Calls: $(cat "$CALLS")"
}

assert_not_called() {
  if grep -qF -- "$1" "$CALLS"; then
    fail "should not be called: [$1]. Calls: $(cat "$CALLS")"
  fi
}

assert_json() {
  printf '%s' "$1" | python3 -I -m json.tool >/dev/null || fail "invalid JSON: $1"
}

mac_secure() {
  "$REPO/bin/mac-secure" "$@" </dev/null
}

# shellcheck source=tests/portable.sh
. "$REPO/tests/portable.sh"
if [ "$(uname -s)" = Darwin ]; then
  # shellcheck source=tests/macos.sh
  . "$REPO/tests/macos.sh"
fi

for name in $(declare -F | awk '{print $3}' | grep '^test_'); do
  case "$name" in
    *"$FILTER"*) ;;
    *) continue ;;
  esac
  started=$SECONDS
  if (sandbox; "$name"); then
    PASSED=$((PASSED + 1))
    result=ok
  else
    FAILED=$((FAILED + 1))
    FAILED_NAMES="$FAILED_NAMES $name"
    result=FAIL
  fi
  printf '%-5s %s (%ss)\n' "$result" "$name" "$((SECONDS - started))"
done

echo
echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ] || { echo "failed:$FAILED_NAMES"; exit 1; }
