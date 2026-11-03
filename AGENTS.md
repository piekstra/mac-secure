# Working in this repository

`mac-secure` is Bash that runs unattended, some of it as root, on other people's Macs. `README.md` describes the behaviour; `skills/mac-secure/SKILL.md` describes how an agent uses the tool.

Run `make verify` before you call a change done. It is what CI runs.

## Rules for the code

- Everything runs under the macOS `/bin/bash`, version 3.2. No associative arrays, `mapfile`, `${var,,}`, or `|&`.
- `root/` runs as root. It calls system binaries only, reads only root-owned files, sources nothing, and starts from an empty environment. `tests/portable.sh` checks this. Adding a user-writable path to `root/` hands root to any process running as the user.
- Call `sudo` as `$MS_SUDO`. `PATH` can lead with directories the user can write to. Every `curl` in `root/` starts with `-q`.
- A password never goes on a command line, where `ps` shows it to every process. See `root/feed-password.exp`.
- Read a plist value through `ms_plist_value`, or `plist_value` in `root/macos-update`. `plutil` can print its error to stdout, where it reads as the value. There are two because root code sources nothing, so keep them identical. `tests/portable.sh` fails on any other `plutil -extract`.
- `status`, `audit`, `modules`, `vulns`, `notices`, and `logs` never write, never call `sudo`, and never run anything that can raise a dialog. An agent may call them freely.
- A job has no one to answer a prompt. Anything that can wait on a dialog is bounded or avoided: no AppleScript app control, no `terminal-notifier`, no `/usr/bin/python3` or `lipo` outside code that already needs Xcode's tools, since those shims raise an install dialog on a Mac without them.
- Check the output of a tool that reports failure in text. `softwareupdate` can exit 0 while printing "Not enough free disk space", and prints nothing at all when the network is down.
- A module function returns 0 for ok, 75 for retry next run, and anything else for failed. A check that could not run is 75, never read as a clean result.
- Defaults are neutral documented facts. Personal lists, machine names, and tuning belong in `~/.config/mac-secure/`, not here.
- A new module goes in `lib/modules.sh`, with its real disruption stated, and in the README table. Tests fail otherwise. Nothing that restarts the Mac or creates an account is recommended by default.

## Tests

`tests/run.sh [filter]` runs `tests/portable.sh` everywhere and `tests/macos.sh` on a Mac. `sandbox` in `run.sh` gives every test a temporary `HOME` and stubs every tool that changes a system; add a new such tool to `STUBBED_TOOLS` before calling it. A tool found through an environment variable or a sourced script rather than `PATH` or `HOME`, such as nvm through `NVM_DIR`, reaches the real system unless `sandbox` clears that variable. Data with a real tool's output format goes in `tests/fixtures/`, with dummy values.
