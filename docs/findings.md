# Findings, baselines and reports

Bluejay keeps the result of a check available after the command finishes. This persistent state connects discovery, evidence review, remediation and retesting into one workflow.

## What is stored

The SQLite database at `data/bluejay.db` contains:

- assets, including first-seen and last-seen times
- scan history, status, tool, profile, command and evidence paths
- structured findings with severity, confidence, status and recommendations
- evidence entries associated with findings

`data/findings.jsonl` is maintained as a compatibility mirror. Raw Nmap output lives under `scans/`, other collected evidence under `logs/`, generated Markdown under `reports/`, and baselines under `data/baselines/`.

Generated runtime data is ignored by Git apart from placeholder files. Review it before sharing because it may still contain sensitive hostnames, addresses, paths, logs or service details.

## Deterministic findings and model analysis

Structured findings are created by parsers and rule-based checks for Nmap XML, HTTP and TLS results, site audit evidence and Nuclei JSONL. They retain a source path so the observation can be checked against saved evidence.

The Ollama analysis layer writes explanations and reports from saved evidence. Its prose is separate from the underlying finding records and should be reviewed by a human. `/report` builds directly from stored findings without asking the model, while commands such as `/scan`, `/web`, `/dig` and `/analyse` also request a local model interpretation of their evidence.

## Deduplication and history

Bluejay calculates a stable fingerprint from a finding's target, type, title, CVEs and selected metadata. When the same fingerprint appears again, Bluejay:

- keeps the original finding ID and `first_seen` time
- updates `last_seen`, evidence, recommendation and source
- increments `times_seen`
- reopens the finding if it had been resolved
- appends another evidence record

This provides history without filling the finding list with identical rows.

## Review and triage

```text
/assets
/asset localhost
/history localhost
/findings open localhost
/finding <finding-id>
/triage localhost
/next localhost
```

`/triage` groups open findings by severity and shows the next five priorities. `/next` opens the highest-priority finding. Severity is a starting point, not a replacement for understanding exposure, business context and the quality of the evidence.

## Remediation and retesting

```text
/remediate <finding-id>
/explain <finding-id>
/retest <finding-id>
/resolve <finding-id>
```

`/remediate` gives a practical fix and validation sequence from the stored recommendation. `/explain` asks the local explanation model to describe the observation, risk, validation and remediation in plain language.

`/retest` chooses the closest supported workflow:

- web and TLS findings rerun `/web`
- Nuclei findings rerun the bounded Nuclei workflow
- Nmap script findings rerun the vulnerability profile
- other findings rerun a standard Nmap scan

Review the new evidence before resolving the original finding. Resolving or reopening a finding changes its status and keeps its stored observations and occurrence history. If the same finding is observed again later, deduplication reopens it automatically.

## Baselines and change detection

Save current open findings for a target or for all targets:

```text
/baseline localhost
/baseline all
```

Run new checks after a change, then compare the current open set with the saved snapshot:

```text
/diff localhost
```

The diff identifies:

- new findings
- fixed or no-longer-open findings
- findings whose tracked details changed
- unchanged findings that remain open

The comparison is saved as Markdown evidence under `reports/`. Running `/baseline` with no argument lists existing snapshots.

## Evidence-based reports

`/report` creates Markdown from current open structured findings:

```text
/report all
/report localhost
/report executive all
/report remediation localhost
/report retest localhost
/report learning all
```

Available modes:

- `technical`: full evidence, source and recommendation details
- `executive`: a shorter priority summary
- `remediation`: an action checklist
- `retest`: a finding-by-finding retest plan
- `learning`: findings with beginner-friendly framing

Use `/reports` to list recent generated files and `/view <number>` to read one in the terminal.

## Suggested workflow

```text
/profile standard localhost
/findings open localhost
/triage localhost
/baseline localhost
/remediate <finding-id>
```

After the system owner applies the change:

```text
/retest <finding-id>
/diff localhost
/resolve <finding-id>
/report technical localhost
```

Mark a finding resolved only when the new evidence supports that conclusion. A clean Bluejay result is not a complete security audit and does not guarantee that a system is secure.
