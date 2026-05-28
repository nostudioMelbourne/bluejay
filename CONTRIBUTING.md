# Contributing

Thanks for helping improve Blue Jay.

Blue Jay is open to focused contributions that make the tool safer, clearer,
more reliable, or easier to use in authorised defensive environments.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the app locally:

```bash
python app.py
python -m bluejay
```

## Verification

Before submitting changes, run:

```bash
python -m compileall app.py bluejay tests
python -m unittest discover
```

Some workflows also need local tools such as Ollama, Nmap, dig, and optionally
Nuclei. Use `/status` in the CLI to check availability.

## Good First Contributions

Good places to start include:

- Documentation fixes and clearer examples
- Tests for target validation, parsing, and report generation
- Safer error handling and clearer CLI messages
- Report wording improvements that stay tied to saved evidence
- Small workflow improvements for local lab or authorised-use scenarios

## Security Boundaries

Keep contributions defensive and authorised-use focused. Do not add features
that enable unauthorised access, stealth, credential theft, persistence,
malware, or destructive actions.

Avoid submitting real credentials, private logs, customer data, or third-party
target details in issues, tests, fixtures, screenshots, or reports.

Generated runtime data belongs in ignored folders and should not be committed:
`chats/`, `data/`, `logs/`, `reports/`, and `scans/`.

## Issues

When opening an issue, include:

- What you expected to happen
- What actually happened
- The command or workflow involved
- Your OS and Python version when relevant
- Sanitised sample input or output when it helps reproduce the issue

For security vulnerabilities in Blue Jay itself, follow
[SECURITY.md](SECURITY.md) instead of posting sensitive details publicly.

## Pull Requests

Pull requests should include:

- Short summary of the change
- Verification commands run
- Any new external tool requirements
- Screenshots or report excerpts when terminal output or generated Markdown changes

Keep pull requests focused. If a change mixes a feature, refactor, and large
documentation rewrite, split it into smaller PRs where possible.
