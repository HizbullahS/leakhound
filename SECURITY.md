# Security

LeakHound is an early-stage local heuristic scanner. It does not validate credentials, enforce server-side repository policy, or guarantee that a commit is safe. Local hooks can be bypassed and must not be your only control.

Do not post real secrets in public issues or pull requests. For a security issue, use GitHub's private vulnerability reporting option if it is available for this repository. If it is unavailable, open an issue requesting a private reporting channel without disclosing exploit details or credentials.

If a real credential has been exposed, revoke or rotate it with its provider. Removing it from a file or rewriting Git history does not invalidate it.
