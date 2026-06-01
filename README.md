# Blue Jay

Blue Jay is a local LLM-powered cyber security assistant for analysing network scans and system logs in authorised environments.

It uses Python, Ollama, a custom Modelfile, and Nmap to turn raw technical output into clear defensive security reports. Blue Jay is designed for home labs, learning, IT support practice, and authorised security testing.

## Repository Status

- Public GitHub project: issues and pull requests are welcome
- License: MIT
- Python: 3.10+
- CI: `python -m compileall app.py bluejay tests` and `python -m unittest discover`
- Runtime data: ignored under `chats/`, `data/`, `logs/`, `reports/`, and `scans/`

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and [SECURITY.md](SECURITY.md) for responsible-use and vulnerability-reporting guidance.

## Quickstart

```bash
pip install -r requirements.txt
python -m bluejay
```

Once running, try `/status` as a safe first command. Only scan targets you are authorised to test.

## Overview

Blue Jay helps users understand:

- Open ports
- Exposed services
- Nmap scan results
- Structured Nmap XML findings
- Basic vulnerability scan results
- DNS records and exposed infrastructure clues
- Web security headers and TLS certificate checks
- Evidence tracking and remediation status
- SSH/authentication logs
- Web server logs
- Firewall logs
- Basic network exposure
- Defensive hardening steps

The project focuses on local-first analysis. Scan and log data is processed on the user's machine through a local Ollama model rather than being sent to a cloud API.

## Project Structure

- `app.py` - thin CLI entrypoint for `python app.py`
- `bluejay/cli.py` - startup loop and chat handling
- `bluejay/commands.py` - slash-command router
- `bluejay/cmd_system.py` - help, status, config, saved chat, and file/report listing commands
- `bluejay/cmd_findings.py` - asset, finding, triage, remediation, retest, and report commands
- `bluejay/cmd_workflows.py` - scan, DNS, web, site, Nuclei, profile, and analysis commands
- `bluejay/config.py` - model profile configuration
- `bluejay/ui.py` - terminal rendering, prompt history, and completions
- `bluejay/storage.py` - SQLite assets, scans, evidence, and findings
- `bluejay/targets.py` - target normalization and allowlist checks
- `bluejay/nmap.py` - Nmap and DNS collection workflows
- `bluejay/http_checks.py` - HTTP/TLS/header/cookie checks
- `bluejay/site_audit.py` - bounded same-origin crawling and form/link checks
- `bluejay/nuclei.py` - optional Nuclei execution and JSONL parsing
- `bluejay/web.py` - public exports for web-related workflows
- `bluejay/analysis.py` - local model file analysis and report saving
- `bluejay/reports.py` - evidence-based findings reports

The package can also be launched with:

```bash
python -m bluejay
```

## Features

- Slash-command terminal interface
- Local LLM analysis through Ollama
- Custom Blue Jay Modelfile
- Controlled Nmap scanning
- Nmap XML parsing into structured findings
- Bounded Nmap vulnerability-script scanning
- DNS lookup and DNS report generation
- HTTP/TLS/security-header checks
- Local website audit workflow with bounded same-origin crawling
- Local findings database
- SQLite-backed assets, scans, evidence, and findings
- Finding deduplication with `first_seen`, `last_seen`, and `times_seen`
- Findings list/detail/resolve workflow
- Finding baselines and current-vs-baseline diffs
- Asset inventory and scan history
- Repeatable scan profiles
- Optional bounded Nuclei integration
- Interactive triage, remediation, explanation, and retest commands
- Evidence-based Markdown report generation
- Improved terminal UI with tables, panels, command history, and tab completion
- Optional Rich-powered Markdown/table rendering
- Allowlist support for approved public targets
- Private LAN scanning support
- Markdown report generation
- Recent report viewing
- Support for scan and log file analysis
- Configurable Ollama model profiles for chat, analysis, and finding explanations
- Beginner-friendly security explanations
- Tool status checks
- Safer input validation, file limits, and command timeouts
- Plain-text chat with the local model
- Saved local chat transcripts with bounded context

## Current Commands

Blue Jay supports normal chat and slash commands inside the terminal.

Type a normal message to chat with the local model:

```txt
What should I check after finding port 22 open?
```

Use slash commands when you want Blue Jay to run a controlled tool or manage reports.

### `/help`

Shows the help menu.

### `/files`

Lists files inside the `scans/` and `logs/` folders.

### `/allowed`

Shows targets listed in `allowed_targets.txt`.

### `/status`

Shows active model profiles, local tool availability, finding counts, and workspace paths.

### `/model`

Shows the configured Ollama model profiles.

### `/config [show|model|reset] ...`

Shows or changes local Blue Jay configuration.

Examples:

```txt
/config show
/config model chat bluejay
/config model analysis bluejay-analyst
/config model explain bluejay-explainer
/config reset
```

### `/newchat`

Starts a fresh saved chat transcript. Older transcripts remain in `chats/`.

### `/resume [number|file]`

Lists saved chat transcripts and resumes one.

With `prompt_toolkit` installed, Blue Jay opens an interactive selector. Without it, use the numbered list:

```txt
/resume
/resume 1
```

### `/chatlog`

Shows the current chat transcript path and context settings.

### `/dig <domain>`

Runs DNS lookups for common record types, saves the output in `logs/`, analyses it with the local model, and creates a Markdown report.

Example:

```txt
/dig example.com
```

### `/web <host-or-url>`

Runs basic HTTP, TLS, and security-header checks, records findings, saves raw output in `logs/`, analyses it with the local model, and creates a Markdown report.

Examples:

```txt
/web localhost
/web https://example.com/
```

### `/site <host-or-url>`

Runs a bounded local website audit. It crawls a small same-origin page set, reuses the HTTP/TLS/header/cookie checks, records structured findings, saves raw JSON evidence in `logs/`, and generates a Markdown analysis report.

It currently checks for issues such as broken crawled pages, exposed directory listings, password forms over HTTP, password forms using GET, HTTP form actions, mixed-content resources, and unsafe external new-tab links.

Examples:

```txt
/site http://localhost:3000/
/site http://127.0.0.1:8080/
```

### `/nuclei <host-or-url> [severity-list]`

Runs bounded Nuclei templates against an allowed web target, saves JSONL output in `logs/`, records findings, and creates a Markdown analysis report.

Nuclei is optional and must be installed separately.

Example:

```txt
/nuclei localhost info,low,medium
```

### `/profile <quiet|quick|standard|deep|web|report> <target|all>`

Runs repeatable workflows.

Profiles:

- `quiet`: low-noise Nmap scan only, top 25 TCP ports, no service detection or scripts.
- `quick`: DNS plus quick Nmap service scan.
- `standard`: DNS, standard Nmap service scan, and web checks.
- `deep`: DNS, standard scan, bounded Nmap vuln scripts, and web checks.
- `web`: DNS plus web checks.
- `report`: evidence-based report generation.

Examples:

```txt
/profile quiet localhost
/profile standard localhost
/profile deep scanme.nmap.org
/profile report all
```

### `/scan <target> [quiet|quick|standard|deep] [options]`

Runs a controlled Nmap scan, saves normal and XML output, records structured findings, analyses the result with the local model, and creates a Markdown report.

Scan modes:

- `quiet`: top 25 TCP ports, slower timing, scan delay, no service detection, no scripts. Lower signal but less noisy.
- `quick`: top 25 TCP ports with service detection.
- `standard`: top 100 TCP ports with service detection. This is the default.
- `deep`: top 50 ports with service detection and bounded Nmap vulnerability scripts.

Options:

- `ports <list>`: scan explicit ports such as `22,80,443` or `1-1024`.
- `top <count>`: scan the top N ports, from `1` to `5000`.
- `udp`: use UDP scan mode.
- `tcp`: use TCP scan mode. This is the default.
- `service`: enable service/version detection.
- `no-service`: disable service/version detection.
- `reason`: include Nmap reason output.
- `timing <value>`: use `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, or `0` to `4`.

Examples:

```txt
/scan localhost
/scan localhost quiet
/scan 192.168.1.1 quick
/scan localhost ports 22,80,443 reason
/scan 192.168.1.1 top 1000 no-service timing polite
/scan 192.168.1.1 quick udp top 50
/scan 192.168.1.1
/scan scanme.nmap.org
```

### `/vuln <target>`

Runs a bounded Nmap vulnerability-script scan, saves the result, analyses it defensively, and creates a Markdown report.

This command uses the same target safety rules as `/scan`:

- `localhost`
- private LAN IPs
- public targets explicitly listed in `allowed_targets.txt`

Examples:

```txt
/vuln localhost
/vuln scanme.nmap.org
```

Use `/vuln` only against systems you own or have explicit permission to test. The generated report is intended to help verify exposure, patch services, harden configuration, and decide what to investigate next.

### `/analyse <file> <mode>`

Analyses an existing scan or log file.

Examples:

```txt
/analyse scans/example-nmap.txt nmap
/analyse logs/example-auth.log auth-log
/analyse logs/example-nginx-access.log web-log
/analyse logs/example-firewall.log firewall-log
```

Supported modes:

```txt
nmap
vulnerability
dns
auth-log
web-log
firewall-log
general
```

### `/reports`

Shows recent Markdown reports.

### `/assets`

Lists known assets discovered or checked by Blue Jay.

### `/asset <target>`

Shows asset details, open finding count, and recent scans.

### `/history [target]`

Shows recent scan history across all assets or one target.

### `/findings [open|resolved|all] [target]`

Lists stored structured findings from scans and web checks.

Examples:

```txt
/findings
/findings all
/findings open localhost
```

### `/finding <id>`

Shows the evidence, source, recommendation, CVEs, and metadata for a single finding.

### `/resolve <id>`

Marks a finding as resolved.

### `/reopen <id>`

Marks a resolved finding as open again.

### `/report [mode] [target|all]`

Creates a Markdown report from open structured findings.

Examples:

```txt
/report all
/report localhost
/report executive all
/report remediation localhost
/report retest localhost
/report learning all
```

Report modes:

- `technical`: default evidence report.
- `executive`: shorter priority-focused report.
- `remediation`: checklist for fixing findings.
- `retest`: retest plan.
- `learning`: beginner-friendly learning notes.

### `/baseline [target|all]`

Lists saved baselines, or saves the current open findings as a baseline for a target or all targets.

Examples:

```txt
/baseline
/baseline localhost
/baseline all
```

### `/diff <target|all>`

Compares current open findings to the saved baseline for that scope.

It highlights new findings, findings that are fixed or no longer open, changed findings, and unchanged findings.

Examples:

```txt
/diff localhost
/diff all
```

### `/triage [target]`

Shows severity counts and the next highest-priority findings.

### `/next [target]`

Shows the next highest-priority open finding.

### `/remediate <id>`

Shows a practical remediation workflow for one finding.

### `/explain <id>`

Asks the local model to explain one stored finding.

### `/retest <id>`

Reruns the closest safe check for a finding.

### `/view <number>`

Views a report from the recent reports list.

### `/clear`

Clears the terminal.

### `/about`

Shows project information.

### `/exit`

Closes Blue Jay.

## Project Structure

```txt
bluejay/
  Modelfile
  Modelfile.analysis
  Modelfile.explain
  app.py
  allowed_targets.txt
  scans/
  logs/
  reports/
  chats/
  data/
```

### `Modelfile`

Defines the main local Blue Jay chat model using Ollama and `gpt-oss`.

### `Modelfile.analysis`

Defines the evidence-first analysis/report model using `qwen2.5-coder`.

### `Modelfile.explain`

Defines the finding explanation model using `llama3.1`.

### `app.py`

Runs the Blue Jay terminal interface, slash commands, controlled Nmap scanning, file analysis, and report generation.

### `allowed_targets.txt`

Stores approved public targets that Blue Jay is allowed to scan.

Private LAN targets and localhost are allowed by default.

Example:

```txt
# Blue Jay authorised scan targets
# Add one target per line.

scanme.nmap.org
localhost
127.0.0.1
```

### `scans/`

Stores Nmap scan output files.

Blue Jay writes both normal text output and XML output so it can produce human-readable reports and machine-readable findings.

### `logs/`

Stores log files for analysis.

Blue Jay also stores DNS lookup output from `/dig` and web-check output from `/web` here.

### `reports/`

Stores generated Markdown security reports.

### `chats/`

Stores saved local chat transcripts as JSONL files.

### `data/`

Stores generated local application data.

Important files:

- `bluejay.db`: SQLite database for assets, scans, findings, and evidence.
- `findings.jsonl`: compatibility mirror of generated findings.
- `config.json`: local model profile settings, created when `/config` changes are saved.

## Installation

### 1. Create a Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For an editable install with the `bluejay` console command:

```bash
python -m pip install -e .
bluejay
```

### 2. Install Ollama

Download and install Ollama from the official Ollama website.

After installing, check that it works:

```bash
ollama --version
```

### 3. Pull the local role models

Blue Jay uses separate Ollama models for chat, technical analysis, and finding explanations.

```bash
ollama pull gpt-oss:latest
ollama pull qwen2.5-coder:latest
ollama pull llama3.1:latest
```

### 4. Create the Blue Jay role models

From inside the project folder:

```bash
ollama create bluejay -f Modelfile
ollama create bluejay-analyst -f Modelfile.analysis
ollama create bluejay-explainer -f Modelfile.explain
```

Test them:

```bash
ollama run bluejay
ollama run bluejay-analyst
ollama run bluejay-explainer
```

### 5. Install Nmap

On macOS with Homebrew:

```bash
brew install nmap
```

On Debian, Kali, or Ubuntu:

```bash
sudo apt update
sudo apt install nmap
```

Check that it works:

```bash
nmap --version
```

### 6. Optional: Install Nuclei

Nuclei is only needed for `/nuclei` scans. Install it separately if you want
template-based web checks.

### 7. Terminal UI dependencies

Blue Jay works with the Python standard library, but installing the optional TUI dependencies enables better panels, tables, status spinners, Markdown rendering, and a Codex-style slash-command picker.

```bash
python3 -m pip install -r requirements.txt
```

With `prompt_toolkit` installed, type `/` at the prompt to open a command menu, then use the arrow keys and Enter or Tab to select a command.

### 8. Run Blue Jay

```bash
python3 app.py
python3 -m bluejay
```

You should see:

```txt
Blue Jay
Local AI Security Workbench
Type normally to chat. Use /help for commands.
```

## Example Usage

### Scan localhost

```txt
/scan localhost
```

Blue Jay will:

1. Run a controlled Nmap scan
2. Save normal and XML scan output in `scans/`
3. Parse XML into structured findings in `data/findings.jsonl`
4. Send the scan output to the local Blue Jay model
5. Generate a Markdown report
6. Save the report in `reports/`

### Chat with Blue Jay

```txt
How do I safely triage an exposed web server?
```

Blue Jay will send the message to the local Ollama model and save the conversation under `chats/`.

Use `/newchat` to start a fresh transcript.

### Scan a local router

```txt
/scan 192.168.1.1
```

### Scan an allowlisted public target

Add the target to `allowed_targets.txt` first:

```txt
scanme.nmap.org
```

Then run:

```txt
/scan scanme.nmap.org
```

### Run a vulnerability-oriented scan

```txt
/vuln localhost
```

Blue Jay will run a bounded Nmap vulnerability script scan against an authorised target, then ask the local model to explain findings as a defensive report.

### Run a web check

```txt
/web localhost
```

Blue Jay will check HTTP/HTTPS reachability, response headers, TLS certificate health where applicable, record structured findings, and generate a report.

### Run a repeatable profile

```txt
/profile standard localhost
```

Blue Jay will run the configured profile steps and store assets, scan history, findings, and evidence.

### Dig DNS records

```txt
/dig example.com
```

Blue Jay will collect common DNS record types, save the lookup output in `logs/`, and generate a DNS report.

### Work with findings

```txt
/findings
/finding GP-20260511222600000000-localhost
/resolve GP-20260511222600000000
/report all
```

Findings are deterministic evidence records generated from tool output. Reports generated by `/report` use the stored findings, while reports generated by `/analyse`, `/scan`, `/vuln`, `/dig`, and `/web` use the local model for explanation.

### Triage and retest

```txt
/triage
/next
/remediate GP-20260511222600000000
/retest GP-20260511222600000000
```

Use these commands to work through open findings, plan fixes, and retest before marking a finding resolved.

### Analyse an existing Nmap file

```txt
/analyse scans/example-nmap.txt nmap
```

### Analyse an SSH auth log

```txt
/analyse logs/example-auth.log auth-log
```

### View generated reports

```txt
/reports
/view 1
```

## Example Report Output

Blue Jay generates reports using this structure:

```md
# Blue Jay Security Report

## 1. Summary

## 2. Key Findings

## 3. Technical Details

## 4. Risk Level

## 5. What This Means

## 6. Safe Defensive Next Steps

## 7. Hardening Checklist
```

## Safety Design

Blue Jay is designed for defensive security and authorised testing only.

The tool uses a controlled design:

```txt
User command -> Python tool wrapper -> evidence file -> structured findings -> local LLM analysis -> Markdown report
```

The local model does not get direct shell access. The Python application controls what tools can run.

Additional safety controls:

- Tool inputs are passed as argument lists rather than through a shell.
- Public scan targets must be present in `allowed_targets.txt`.
- `/scan` and `/vuln` reject targets with schemes, paths, ports, whitespace, or shell syntax.
- `/web` only accepts allowed hosts or simple HTTP/HTTPS URLs without credentials, queries, or fragments.
- `/nuclei` uses the same web target controls and runs with rate limits, timeouts, and severity filtering.
- `/analyse` only reads files inside the Blue Jay project folder.
- Analysis input is capped to avoid accidentally sending very large files to the model.
- Nmap, dig, web checks, and Ollama calls have timeouts.
- Vulnerability reports focus on defensive verification, patching, configuration review, and hardening.
- Structured findings preserve source evidence separately from model-generated explanation.
- Repeated findings are deduplicated and tracked with `times_seen`, `first_seen`, and `last_seen`.
- Resolved findings reopen automatically if the same evidence appears again.
- Chat transcripts are saved locally in `chats/`.
- Chat prompts include only recent bounded context instead of unlimited history.

Blue Jay currently allows scanning of:

- `localhost`
- `127.0.0.1`
- Private LAN IPs such as `192.168.x.x`, `10.x.x.x`, and `172.16.x.x` to `172.31.x.x`
- Public targets explicitly listed in `allowed_targets.txt`

This allowlist system helps prevent accidental scanning of unauthorised public systems.

## Ethical Use

Blue Jay should only be used on:

- Your own devices
- Your own home network
- Your own lab environments
- Systems where you have explicit permission
- Legal practice targets such as `scanme.nmap.org`

Do not use Blue Jay to scan, test, or probe systems you do not own or have permission to assess.

## Why Local LLMs?

Blue Jay uses a local model through Ollama so that scan and log data can stay on the user's machine.

Benefits:

- No cloud API required
- No external upload of local logs or scans
- Works offline once the model is installed
- Useful for private home lab analysis
- Good for learning how AI-assisted security tooling works

## Tech Stack

- Python
- Ollama
- Custom Modelfile
- Local LLM
- Nmap
- Nuclei optional
- XML parsing
- SQLite
- JSONL findings storage
- HTTP/TLS checks
- Markdown
- Terminal interface
- Optional Rich TUI rendering
- Optional prompt_toolkit slash-command picker
- Readline command history and tab completion

## Roadmap

Planned improvements:

- Coloured output and panels
- `/export` command for reports
- PDF report export
- More log parsers
- SSH hardening checklist command
- Web server hardening checklist command
- Local notes/RAG support
- Better severity scoring
- Report templates
- Config file support
- Optional JSON metadata for reports
- Safer per-profile scan presets
- Optional CVE enrichment cache
- SARIF/HTML export
- Authenticated web checks
- Plugin architecture for external tools

Possible future commands:

```txt
/export 1
/harden ssh
/harden web
/check-ssh logs/example-auth.log
/check-web logs/example-nginx-access.log
```

## Project Goals

Blue Jay is a defensive, local-first security assistant. It is built to help users:

- Understand scan, log, DNS, and web-check output
- Preserve evidence in structured findings
- Track exposure and remediation work over time
- Learn safe security workflows on systems they own or are authorised to assess
- Collaborate on practical tooling that keeps security data local

Blue Jay is not intended to automate unauthorised testing or offensive activity. Contributions should keep the project focused on defensive analysis, evidence quality, explainability, and clear safety boundaries.

## Contributing

This repository is public and open to collaboration. Bug reports, documentation improvements, tests, and focused feature pull requests are welcome.

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and [SECURITY.md](SECURITY.md) for responsible-use guidance.

## Disclaimer

Blue Jay is an educational and defensive security tool.

It does not guarantee that a system is secure. A clean scan or simple report should not be treated as a full security audit.

Always get permission before scanning systems and always review model-generated advice before making security decisions.

## License

Blue Jay is released under the MIT License. See [LICENSE](LICENSE).
