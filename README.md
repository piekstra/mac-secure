# mac-secure

Keeps a Mac updated without waiting for anyone to click a button, and reports what is wrong with its security settings.

It closes and restarts apps to do that, and can restart the Mac if you opt in. Read what each module can disrupt before you enable it. mac-secure is an independent project, not affiliated with Apple or any vendor it updates.

## Start

```sh
git clone https://github.com/piekstra/mac-secure
cd mac-secure
make install               # links mac-secure into ~/.local/bin, which must be on PATH; PREFIX=<dir> changes it
mac-secure status          # read-only
mac-secure audit           # read-only
mac-secure modules         # what each module does and can disrupt
mac-secure enable --recommended
```

`--recommended` shows the modules and asks first. It creates no account, and mac-secure itself restarts nothing but the listed apps. It does turn on Apple's automatic macOS install, which can restart the Mac overnight on Apple's schedule.

## Commands

| Command | Effect |
| --- | --- |
| `status [--json]` | Security settings, jobs, each module's last result. Read-only. |
| `audit [--json]` | Findings about this Mac, most severe first. Read-only. |
| `modules [--json]` | Every module, what it does and what it can disrupt. Read-only. |
| `logs [daily\|enforcer\|root] [-n <lines>]` | The newest log. Read-only. |
| `enable <module>... \| --recommended [--yes]` | Turns modules on and installs their jobs. |
| `disable <module>... [--yes]` | Turns modules off. Settings the module applied stay as they are. |
| `run [module...]` | Runs the enabled modules, or the named ones, now. |
| `refresh [--yes]` | Shows what would change in the root job, then installs this checkout's jobs. |
| `uninstall [--purge] [--yes]` | Removes every job. `--purge` also removes your settings and logs. |

Exit status: 0 done, 1 a module failed, 2 usage error or refused request, 3 a root step needs a person at a terminal. Without a terminal, a root step prints the exact `sudo` command and changes nothing as root.

## Modules

| Module | Runs as | Recommended | What it does | What it can disrupt |
| --- | --- | --- | --- | --- |
| `brew-formulae` | you | yes | Upgrades every Homebrew formula | Running services keep old code until they restart |
| `brew-casks` | you | yes | Upgrades every cask, including apps that claim to update themselves | Closes an app being upgraded, then reopens it |
| `adopt-apps` | you | no | Moves the apps in `adopt-apps.txt` under Homebrew, so they update while closed | Replaces each app, closing it if running |
| `npm` | you | yes | Upgrades global npm packages to latest, in the Node on the job's PATH (Homebrew's, or one added with `EXTRA_PATH`) and in nvm's default Node, where nvm picks the npm that runs on it | A new major version can change how a CLI behaves |
| `rust` | you | yes | Updates Rust toolchains and rustup | None |
| `cargo` | you | yes | Reinstalls crates installed from crates.io | Compiles from source, which can take many minutes |
| `cargo-local` | you | no | Rebuilds local-source Rust CLIs whose lockfile has a RustSec advisory | Replaces the installed binary with a build of the default branch |
| `gcloud` | you | yes | Updates Google Cloud SDK components | None |
| `bun` | you | yes | Upgrades Bun | None |
| `uv` | you | yes | Upgrades Pythons managed by uv | None |
| `playwright` | you | yes | Keeps the Playwright copies you already use, and their browsers, current | Removes cached npx copies that no running process uses |
| `claude-code` | you | yes | Updates Claude Code | None |
| `colima` | you | no | Patches Ubuntu and Docker in running Colima VMs | Restarts Docker and VMs; waits while a CI job is running |
| `browsers` | you | yes | Restarts browsers that run old code after an update | Closes the browser 30 minutes after a warning; stops stale automation profiles without a restart |
| `macos` | root | yes | Keeps macOS auto-update settings on, installs updates that need no restart, downloads the rest | Safari closes when it updates; macOS's own automatic install can restart the Mac overnight |
| `macos-unattended` | root | no | Installs restart-required macOS updates by itself at the scheduled hour | Creates a hidden admin account with a stored random password; restarts the Mac after a 5-minute warning |
| `macos-major` | root | no | Includes new major macOS versions | A major upgrade can break software that has not caught up |
| `app-store` | root | yes | Keeps App Store auto-updates on | Apps can close when they update |
| `firewall` | root | yes | Keeps the macOS firewall on | An unsigned program that listens beyond this Mac raises an allow dialog |
| `vendor-installers` | root | no | Keeps the pkg-based apps in `vendor-installers.txt` current | An app can close when its installer runs |

A module whose tool is not installed is skipped until the tool appears, so enabling one you do not use costs nothing.

## What runs

| Job | Runs as | When | Label |
| --- | --- | --- | --- |
| `jobs/daily` | you | 04:15, or on wake if the Mac slept through it | `io.github.piekstra.mac-secure.daily` |
| `jobs/enforcer` | you | Every 15 minutes | `io.github.piekstra.mac-secure.enforcer` |
| `root/macos-update` | root | 03:00; the Mac wakes at 02:55 | `io.github.piekstra.mac-secure.macos` |

Each module in the daily job ends as `ok`, `deferred` (retried next run, for a low disk or a busy CI runner), `failed`, or `skipped`. A failure raises a notification. A module that hangs is killed at its time limit, and the modules after it still run. A second run started while one is going exits at once.

The Mac can hold only one repeating wake schedule. If it has one that mac-secure did not set, including one you set after mac-secure's, mac-secure leaves it alone, and the root job runs at the next wake after its hour.

The enforcer finds app processes older than the app's installed update, warns, and restarts them after the grace period. A browser instance with its own profile is automation, so it is stopped only after a day, and is not reopened. Only your own processes are touched.

## Settings

Everything personal lives in `~/.config/mac-secure/`:

| File | Purpose | Example |
| --- | --- | --- |
| `enabled` | The per-user modules that are on; written by `enable` and `disable` | |
| `config` | Times, grace period, disk thresholds, extra paths | `config/config.example` |
| `adopt-apps.txt` | Apps for `adopt-apps` | `config/adopt-apps.example` |
| `vendor-installers.txt` | Casks and pinned signing teams for `vendor-installers` | `config/vendor-installers.example` |
| `restart-apps.txt` | Apps the enforcer restarts, replacing the default browser list | `config/restart-apps.default` |

`config` is read as `KEY=value` text and is never sourced, so a shell does not interpret a value. Two keys, `CARGO_LOCAL_SIGN_COMMAND` and `PLAYWRIGHT_PYTHON`, name a program the daily job runs as you. After changing a schedule or a root-side list, run `mac-secure refresh`.

## Trust model

- The installed root job is a root-owned copy in `/usr/local/libexec/mac-secure`, and it reads only root-owned settings. Once it is installed, a process running as you cannot change what it runs. The installer refuses a path whose parents anyone but root can write to.
- `enable` and `refresh` install from your checkout through `sudo`, so the checkout is trusted at that moment, and a process running as you could have edited it. `refresh` shows the difference first. Keep the checkout somewhere only you can write, and read that difference before you approve it.
- The root job calls system binaries only, starts from an empty environment, and never runs `brew`, `npm`, or anything else under `/opt/homebrew` or a home directory. `mac-secure` calls `sudo` by its full path.
- A vendor installer runs only if its download is https, it is a pkg, its sha256 matches Homebrew's published value when one is published, Apple issued its certificate chain, its leaf certificate names the Apple Team ID you pinned, Gatekeeper is on and accepts it, and its version is not older than the one mac-secure last installed.
- Homebrew's public cask API tells the root job which version and download to fetch. If that API were compromised, it could offer any package the pinned team signed, but nothing else. Pin only vendors you trust with root, and a vendor that changes signing team stops updating until you review and re-pin. A cask without a sha256 relies on the signature checks alone, and one with no version is downloaded on every run to compare it.
- Third-party taps are not an input to the root job.
- `mac-secure` never reads or stores your password. `sudo` and `sysadminctl` prompt for it in the terminal.
- mac-secure does not update itself. To take a new version, review it, `git pull`, then `mac-secure refresh`.

## Unattended macOS restarts

On Apple Silicon, `softwareupdate` needs a volume owner's password to install an OS update. Without `macos-unattended`, the root job downloads each restart-required update, notifies you, and opens Software Update.

`macos-unattended` creates a hidden admin account, `secupdate`, with a random password in a root-only file, and grants it a secure token. It asks you to type `create` first. Your own password is not stored. `root/feed-password.exp` answers `sysadminctl`'s prompt from the file, so the password is never on a command line. Anyone with root can read the stored password, though root can already do what it allows. If the secure token fails, for example on a mistyped password, the account is removed. `disable macos-unattended` deletes the account if mac-secure created it.

## Use with an AI agent

The repository ships a Claude Code plugin with a skill that teaches an agent how to use this tool safely:

```
/plugin marketplace add piekstra/mac-secure
/plugin install mac-secure@mac-secure
```

Other agents can read `skills/mac-secure/SKILL.md`, and `AGENTS.md` for changes to this repository.

## Develop

`make verify` runs what CI runs: `shellcheck`, `actionlint`, and `tests/run.sh`. The tests are plain shell, with stubs on `PATH` for every tool that changes a system. Scripts must run under the macOS `/bin/bash`, which is version 3.2.

Pull requests run on Linux only. The macOS job runs on `main` and on manual runs. When hosted macOS arm64 runners have no capacity, GitHub cancels the job with no steps run and the annotation "The job was not acquired by Runner". A manual run can pick another runner: `gh workflow run ci --ref <branch> -f macos-runner=macos-15-intel`.

## Coverage gaps

- Automated tests stub `softwareupdate`, `launchctl`, `sudo`, and `sysadminctl`. Nothing automated runs the root job as root, creates the service account, or restarts a Mac.
- Not verified: `feed-password.exp` against the real `sysadminctl` as root. It is tested against a stand-in. `-addUser` shows its prompt only to root, so its wording is unknown, and that step answers any password prompt. A failure there ends in the secure-token check, which removes the account.
- Not verified: whether a restart started by `softwareupdate --restart` unlocks FileVault. If it does not, the Mac waits at the unlock screen.
- On Intel, the test suite, `status`, and `audit` pass on a `macos-15-intel` CI runner. No vendor package has been installed on an Intel Mac.
- Not verified: `RelaunchNotification` policy on Edge and Brave. It is the same Chromium policy as Chrome.
- Without root, `audit` sees only the current user's listening processes.
- `kMDItemLastUsedDate` is unreliable after an app is reinstalled, so `audit` makes no claim about when an app was last used.

## License

MIT
