# Security

Report a vulnerability through [GitHub private vulnerability reporting](https://github.com/piekstra/mac-secure/security/advisories/new), not a public issue.

In scope: anything that lets a process running as the user gain root through mac-secure, runs an installer that should have been rejected, exposes the service account password, or makes `status` or `audit` report a safe state that is not true.

The trust model is in the [README](README.md#trust-model).

mac-secure has no release process or backported fixes. The fix goes on `main`, and you take it with `git pull` and `mac-secure refresh`.
