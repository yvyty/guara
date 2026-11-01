# Security Policy

## Supported versions

Guará is pre-1.0. Security fixes land on the latest 0.1.x release and `main`.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |
| < 0.1   | no        |

## Reporting a vulnerability

Do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting:

https://github.com/yvyty/guara/security/advisories/new

Include the affected version or commit, platform, reproduction steps, and
impact. A minimal synthetic sample is enough. Do not attach live malware,
ransomware, or real executable payloads.

We will acknowledge reports as soon as practical and coordinate disclosure
after a fix is available. There is no bug bounty.

## Scope

In scope:

- Memory-safety or panic bugs reachable from untrusted files, paths, or IPC
  input.
- Path traversal or unintended file modification in quarantine.
- IPC authentication or protocol confusion.
- Installer or release artifact integrity.
- Command injection through CLI arguments or config.

Out of scope:

- Heuristic false positives or false negatives. Guará is a signal, not antivirus.
- Behavior that requires `--quarantine` and a destination the user chose.
- Local denial of service from scanning a very large tree.
- Issues in third-party dependencies that are already fixed upstream.

## Security model

Guará has no telemetry and performs no network reputation lookups. Quarantine is
report-only unless `--quarantine` and `--quarantine-dir` are both supplied, and
files are moved, never deleted in place. See `README.md` and
`docs/architecture/overview.md`.
