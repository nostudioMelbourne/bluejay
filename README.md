# Bluejay

Bluejay is an open-source, local-first defensive cybersecurity platform for understanding and improving the security posture of authorised systems.

It combines network reconnaissance, web and TLS checks, vulnerability scanning, log analysis, evidence tracking, findings management, baselines, remediation and retesting in one persistent workflow. It is not just an AI wrapper around Nmap. Local AI supports the analysis layer while the application controls tools, safety boundaries, evidence and state.

Bluejay uses locally running models through Ollama to help interpret technical evidence and explain findings without sending sensitive security data to a third-party AI service.

## What Bluejay does

- Discovers networks and services with controlled Nmap workflows
- Checks DNS, HTTP, TLS, security headers and cookies
- Runs bounded same-origin website audits and optional Nuclei scans
- Analyses Nmap output, DNS results, authentication logs, web logs and firewall logs
- Stores assets, scans, evidence and findings locally
- Deduplicates repeated findings and keeps first-seen, last-seen and occurrence history
- Compares current findings with saved baselines
- Supports triage, remediation, retesting and evidence-based reporting
- Uses local Ollama models to explain evidence and findings

## Quickstart

Bluejay requires Python 3.10 or later. Nmap and Ollama are needed for the main scan and analysis workflows.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m bluejay
```

Run `/status` first to see which local tools and models are available. See [Getting started](docs/getting-started.md) for Nmap, Ollama, model and allowlist setup.

## Example workflow

```text
/status
/scan localhost quick
/findings
/triage localhost
/baseline localhost
/report remediation localhost
```

After applying a fix, use `/retest <finding-id>` and `/diff localhost` to collect new evidence and compare it with the saved baseline.

## Local-first by design

Bluejay keeps runtime data under the local project directory and uses local Ollama models for chat, evidence analysis and finding explanations. The model does not receive direct shell access. Python wrappers validate inputs, run bounded tools, save raw evidence and create structured records before the analysis layer explains the result.

Local-first does not mean no network activity. Scan, DNS and web commands contact the authorised targets or resolvers needed to perform their checks.

## Documentation

- [Getting started](docs/getting-started.md)
- [Command reference](docs/commands.md)
- [Scanning and checks](docs/scanning.md)
- [Findings, baselines and reports](docs/findings.md)
- [Local AI and model configuration](docs/local-ai.md)
- [Architecture and local storage](docs/architecture.md)
- [Roadmap](ROADMAP.md)

## Contributing

Bug reports, documentation improvements, tests and focused pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and verification steps.

## Responsible use

Only use Bluejay against systems you own, administer or have explicit permission to assess. Public targets must be added intentionally to `allowed_targets.txt` before active scan and web workflows will run.

Do not use Bluejay for unauthorised scanning, exploitation, credential theft, evasion, persistence or destructive activity. A clean result is not proof that a system is secure, and model-generated advice must be reviewed by a human.

Read [SECURITY.md](SECURITY.md) for the complete responsible-use, data-handling and vulnerability-reporting guidance.

## Licence

Bluejay is released under the [MIT Licence](LICENSE).
