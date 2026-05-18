# Security Policy

## Supported Versions

Blue Jay is in early development. Security fixes are applied to the latest
code on the default branch.

## Responsible Use

Blue Jay is a defensive security and authorised testing tool. Only run scans
against systems you own, administer, or have explicit permission to assess.
Public targets must be added intentionally to `allowed_targets.txt`.

Do not use this project for unauthorised scanning, exploitation, credential
theft, evasion, persistence, or destructive activity.

## Reporting Security Issues

If you find a vulnerability in Blue Jay itself, please open a private security
advisory on GitHub if available, or contact the maintainer through the
repository issue tracker with minimal public detail.

Please include:

- Affected version or commit
- Clear reproduction steps
- Impact and affected files or commands
- Suggested fix, if known

Do not include private scan logs, credentials, tokens, or third-party target
details in public issues.

## Data Handling

Blue Jay stores local runtime data under `chats/`, `data/`, `logs/`,
`reports/`, and `scans/`. These folders are ignored by Git except for
placeholder files. Review generated output before sharing reports or bug
reproductions.
