# Command reference

Bluejay accepts normal text for local chat and slash commands for controlled tools and stored workflows. Type `/help` in the application to see the command list for the checked-out version.

## System and chat

| Command | Purpose |
| --- | --- |
| `/help` | Show all commands. |
| `/status` | Show model profiles, tool availability, finding counts and workspace paths. |
| `/allowed` | List targets from `allowed_targets.txt`. |
| `/model` | Show the configured Ollama model for each role. |
| `/config show` | Show model configuration and the config file path. |
| `/config model <chat\|analysis\|explain\|all> <model>` | Change one or all local model profiles. |
| `/config reset` | Restore the default Bluejay model profile names. |
| `/newchat` | Start a new saved chat transcript. |
| `/resume [number\|file]` | List saved chats or resume one. |
| `/chatlog` | Show the current transcript and context limits. |
| `/files` | List files under `scans/` and `logs/`. |
| `/reports` | List recent Markdown reports. |
| `/view <number>` | Open a report from the recent report list. |
| `/clear` | Clear and redraw the terminal. |
| `/about` | Show a short project and safety overview. |
| `/exit` | Close Bluejay. |

Normal text is sent to the configured local chat model and saved to the current transcript:

```text
What should I verify after finding an exposed SSH service?
```

With `prompt_toolkit` available, `/resume` opens an interactive transcript selector. You can also use the numbered list directly, for example `/resume 1`.

## Collection and analysis

| Command | Purpose |
| --- | --- |
| `/scan <target> [quiet\|quick\|standard\|deep] [options]` | Run a controlled Nmap scan, save text and XML evidence, record findings and generate local analysis. |
| `/vuln <target>` | Run bounded Nmap vulnerability scripts against an authorised target. |
| `/dig <domain> [advanced\|all]` | Collect DNS records and generate a local analysis report. |
| `/web <host-or-url>` | Check HTTP, TLS, response headers and cookies. |
| `/site <host-or-url>` | Crawl a bounded same-origin page set and run website checks. |
| `/nuclei <host-or-url> [severity-list]` | Run optional Nuclei templates with rate, retry and timeout limits. |
| `/profile <quiet\|quick\|standard\|deep\|web\|report> <target\|all>` | Run a repeatable multi-step workflow. |
| `/repo <directory>` | Run bounded, read-only checks on a directory inside the Bluejay project. |
| `/analyse <file> <mode>` | Analyse a saved local file with the analysis model. |

Supported `/analyse` modes are `nmap`, `vulnerability`, `dns`, `web-check`, `auth-log`, `web-log`, `firewall-log` and `general`. The file must be inside the project directory and no larger than 200,000 bytes.

Examples:

```text
/scan localhost quick
/dig example.com advanced
/web https://localhost/
/site http://127.0.0.1:8080/
/nuclei localhost info,low,medium
/repo .
/analyse logs/example-auth.log auth-log
```

See [Scanning and checks](scanning.md) for scan modes, options, limits and target rules.

## Assets, findings and reports

| Command | Purpose |
| --- | --- |
| `/assets` | List known assets. |
| `/asset <target>` | Show one asset, its open finding count and recent scans. |
| `/history [target]` | Show recent scan history for all targets or one target. |
| `/findings [open\|resolved\|all] [target]` | List stored findings. Open findings are shown by default. |
| `/finding <id>` | Show one finding, its evidence, recommendation, source and metadata. ID prefixes are accepted when unambiguous. |
| `/triage [target]` | Show severity counts and the next five priorities. |
| `/next [target]` | Show the highest-priority open finding. |
| `/remediate <id>` | Show a practical remediation workflow for one finding. |
| `/explain <id>` | Ask the configured local explanation model to explain a finding. |
| `/retest <id>` | Rerun the closest supported safe check for a finding. |
| `/baseline [target\|all]` | List baselines, or save current open findings as a baseline. |
| `/diff <target\|all>` | Compare current open findings with a saved baseline. |
| `/resolve <id>` | Mark a finding as resolved. |
| `/reopen <id>` | Mark a finding as open. |
| `/report [mode] [target\|all]` | Generate a Markdown report from current open findings. |

Report modes are `technical`, `executive`, `remediation`, `retest` and `learning`. `technical` is the default.

Examples:

```text
/findings open localhost
/finding GP-20260511222600000000-localhost
/explain GP-20260511222600000000-localhost
/resolve GP-20260511222600000000-localhost
/report remediation localhost
/baseline localhost
/diff localhost
```

See [Findings, baselines and reports](findings.md) for the complete workflow.
