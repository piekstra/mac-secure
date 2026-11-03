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
| `vulns [filter] [--all] [--json]` | Each known vulnerability from the last scan: critical, high and malware, or every severity with `--all`. The filter matches a location, path or package. Read-only. |
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
| `npm` | you | yes | Upgrades global npm packages to latest, in the Node on the job's PATH (Homebrew's, or one added with `EXTRA_PATH`) and in nvm's default Node, where nvm picks the npm that runs on it | A new major version can change how a CLI behaves. On nvm's default Node, a release that declares it needs a newer Node is held back, and an npm that does not run after nvm's update is put back |
| `rust` | you | yes | Updates Rust toolchains and rustup | None |
| `cargo` | you | yes | Reinstalls crates installed from crates.io | Compiles from source, which can take many minutes |
| `cargo-local` | you | no | Rebuilds local-source Rust CLIs whose lockfile has a RustSec advisory | Replaces the installed binary with a build of the default branch |
| `gcloud` | you | yes | Updates Google Cloud SDK components | None |
| `bun` | you | yes | Upgrades Bun | None |
| `uv` | you | yes | Upgrades Pythons managed by uv | None |
| `playwright` | you | yes | Keeps the Playwright copies you already use, and their browsers, current | Removes cached npx copies that no running process uses |
| `claude-code` | you | yes | Updates Claude Code | None |
| `colima` | you | no | Patches Ubuntu and Docker in running Colima VMs | Restarts Docker and VMs; waits while a CI job is running |
| `vulns` | you | yes | Scans installed tools, packages, editor extensions and apps for known vulnerabilities and malware, and notifies you of new ones | None. Its database takes about 3 GB of disk, and each daily update downloads about 200 MB |
| `browsers` | you | yes | Restarts browsers that run old code after an update | Closes the browser 30 minutes after a warning; stops stale automation profiles without a restart |
| `macos` | root | yes | Keeps macOS auto-update settings on, installs updates that need no restart, downloads the rest | Safari closes when it updates; macOS's own automatic install can restart the Mac overnight |
| `macos-unattended` | root | no | Installs restart-required macOS updates by itself at the scheduled hour | Creates a hidden admin account with a stored random password; restarts the Mac after a 5-minute warning |
| `macos-major` | root | no | Includes new major macOS versions | A major upgrade can break software that has not caught up |
| `app-store` | root | yes | Keeps App Store auto-updates on | Apps can close when they update |
| `firewall` | root | yes | Keeps the macOS firewall on | An unsigned program that listens beyond this Mac raises an allow dialog |
| `vendor-installers` | root | no | Keeps the pkg-based apps in `vendor-installers.txt` current | An app can close when its installer runs |

`audit` also reports a Playwright browser build older than the browser installed on the Mac, or than the newest build Playwright has there, with the copies of Playwright that keep it. Versions are compared in full, since Chrome ships security fixes in updates within a major version: an older major version is medium, an older update of the same one low. When even the newest Playwright build is behind the installed Chrome, the action points to Playwright's [`channel: 'chrome'`](https://playwright.dev/docs/browsers#google-chrome--microsoft-edge), which runs the installed Chrome. It checks `~/Library/Caches/ms-playwright` and, when set in the environment of whoever runs `audit`, the folder `PLAYWRIGHT_BROWSERS_PATH` names. A copy or cache under Desktop, Documents, Downloads, Pictures, Music, Movies, iCloud Drive, `~/Library/CloudStorage`, `/Volumes` or a network mount is not read, since that can raise a privacy prompt or reach a volume that is not there, so the finding says which copies use such a build is unknown, or that the cache was not checked. A build whose version cannot be read is reported as `playwright-browser-unreadable`. Playwright [deletes a build](https://playwright.dev/docs/browsers#stale-browser-removal) once no installed copy needs it.

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
| `vulns-ignore.txt` | Matches you reviewed and want left out of `audit` and `vulns` | `config/vulns-ignore.example` |

`config` is read as `KEY=value` text and is never sourced, so a shell does not interpret a value. Two keys, `CARGO_LOCAL_SIGN_COMMAND` and `PLAYWRIGHT_PYTHON`, name a program the daily job runs as you. After changing a schedule or a root-side list, run `mac-secure refresh`.

## Vulnerability scanning

The `vulns` module needs [grype](https://github.com/anchore/grype) and [syft](https://github.com/anchore/syft): `brew install grype syft`. syft lists what is installed, and grype matches it against Anchore's database, which includes GitHub's advisories (malware advisories among them), the NVD, and CISA's list of vulnerabilities known to be exploited. When Homebrew has `brew vulns`, it checks the installed formulae as well; `audit` says when it does not.

grype matches what is installed against the database it downloads from Anchore, on the Mac. `brew vulns` instead sends each formula's source repository URL and version tag to [OSV.dev](https://google.github.io/osv.dev/api/) (`api.osv.dev`), which can name a private repository or host for a formula from a private tap. `VULN_HOMEBREW=no` in `config` leaves formulae out.

It runs in the daily job after the update modules, so its results describe what the updates left behind. It scans these locations when they exist: Node versions from nvm, Volta and fnm; the npx cache; Bun's global packages; `~/.local`; `~/go/bin`; `~/.cargo/bin`; Playwright's Go drivers; VS Code and Cursor extensions; `~/.claude/plugins`; python.org's Python framework; `/Applications`; and Homebrew's `lib`. `VULN_SCAN_PATHS` in `config` adds more.

The scan reads what is installed: package manifests under `node_modules`, Python package metadata, the build information in Go and Rust binaries, app bundles, and known binaries such as `node` and `python`. It does not read lockfiles, so a cloned repository's dependencies count only once they are installed. npm installs a package at `node_modules/<name>/package.json`, and any other `package.json` (an editor extension's or a project's own) is left out, because malware advisories often reuse those names.

How you learn about results:

- A notification when a scan finds a critical, known-exploited or malware match that the previous scan did not have.
- `audit` lists one finding per location with critical or high matches (`vulnerable-software`), one per malware match (`malware-package`), and one counting the lower-severity matches that `mac-secure vulns --all` lists (`lower-vulnerabilities`). It also reports what the scan could not check (`vuln-coverage-gap`), a scan that has not finished in 3 days or a failed database update (`vuln-scan-stale`), a missing tool or result (`vuln-scan-missing`), and a module that is off (`vuln-scan-off`). With the module off, earlier results are not reported, since nothing updates them.
- `mac-secure vulns` lists each match with the version that fixes it, and `--json` gives the same to a script or an agent.

A location that cannot be scanned keeps its previous results, and the module reports `deferred`, so a failed scan never reads as a clean one. A `VULN_SCAN_PATHS` location that is missing, such as an unplugged drive, keeps its previous results too, and `audit` reports it as a `vuln-coverage-gap`. A failed database update leaves the scan unstamped, so `audit` reports it after 3 days.

`mac-secure disable vulns` keeps the results and grype's database. `uninstall --purge` removes the results; `grype db delete` removes the database.

A match is a lead, not a verdict. To leave out one you reviewed, add a line to `vulns-ignore.txt`: the advisory id alone, or the id, a part of the path, and why, separated by `|`.

Not covered: Playwright's browser builds, which no scanner here identifies; container images; project checkouts, unless added with `VULN_SCAN_PATHS`; Homebrew casks, which `brew vulns` does not check; and formulae `brew vulns` skips for lack of a supported source URL, which the module's result counts.

## Trust model

- The installed root job is a root-owned copy in `/usr/local/libexec/mac-secure`, and it reads only root-owned settings. Once it is installed, a process running as you cannot change what it runs. The installer refuses a path whose parents anyone but root can write to.
- `enable` and `refresh` install from your checkout through `sudo`, so the checkout is trusted at that moment, and a process running as you could have edited it. `refresh` shows the difference first. Keep the checkout somewhere only you can write, and read that difference before you approve it.
- The root job calls system binaries only, starts from an empty environment, and never runs `brew`, `npm`, or anything else under `/opt/homebrew` or a home directory. `mac-secure` calls `sudo` by its full path.
- A vendor installer runs only if its download is https, it is a pkg, its sha256 matches Homebrew's published value when one is published, Apple issued its certificate chain, its leaf certificate names the Apple Team ID you pinned, Gatekeeper is on and accepts it, and its version is not older than the one mac-secure last installed.
- Homebrew's public cask API tells the root job which version and download to fetch. If that API were compromised, it could offer any package the pinned team signed, but nothing else. Pin only vendors you trust with root, and a vendor that changes signing team stops updating until you review and re-pin. A cask without a sha256 relies on the signature checks alone, and one with no version is downloaded on every run to compare it.
- Third-party taps are not an input to the root job.
- The `vulns` module's `brew vulns` step sends each formula's source repository URL and version tag to OSV.dev. grype sends nothing about what is installed: it downloads Anchore's database and matches on the Mac. `VULN_HOMEBREW=no` turns the Homebrew step off.
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
- With `PLAYWRIGHT_BROWSERS_PATH=0`, each copy of Playwright keeps its browsers in its own `node_modules`, which `audit` does not check.
- `vulns` matches an app by the packages and binaries inside it. A vulnerability in an app's own code is reported only when the database names that app, so an app with no match is not proven clean.
- `kMDItemLastUsedDate` is unreliable after an app is reinstalled, so `audit` makes no claim about when an app was last used.

## License

MIT
