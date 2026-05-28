# Blue Jay System Architecture

Blue Jay is a local-first defensive security assistant. It provides a terminal interface for controlled security checks, stores evidence locally, and uses local Ollama models to explain scan results and generate reports.

## Architecture Overview

```mermaid
flowchart TB
    User[User / Security Learner] --> CLI[Terminal CLI<br/>bluejay.cli]
    CLI --> Router[Command Router<br/>bluejay.commands]
    CLI --> Chat[Local Chat Loop<br/>bluejay.chat]

    Router --> SystemCmds[System Commands<br/>help, status, config, files]
    Router --> WorkflowCmds[Workflow Commands<br/>scan, vuln, dig, web, site, nuclei]
    Router --> FindingCmds[Finding Commands<br/>findings, triage, remediate, report]

    WorkflowCmds --> TargetSafety[Target Validation<br/>bluejay.targets]
    TargetSafety --> Allowlist[allowed_targets.txt<br/>localhost + private LAN + approved public targets]

    WorkflowCmds --> Nmap[Nmap Workflows<br/>bluejay.nmap]
    WorkflowCmds --> DNS[DNS Collection<br/>dig / resolver checks]
    WorkflowCmds --> HTTP[HTTP / TLS Checks<br/>bluejay.http_checks]
    WorkflowCmds --> SiteAudit[Site Audit<br/>bluejay.site_audit]
    WorkflowCmds --> Nuclei[Optional Nuclei<br/>bluejay.nuclei]

    Nmap --> RawScans[Raw Scan Files<br/>scans/]
    DNS --> Logs[Evidence Logs<br/>logs/]
    HTTP --> Logs
    SiteAudit --> Logs
    Nuclei --> Logs

    Nmap --> Storage[SQLite Storage<br/>bluejay.storage<br/>data/bluejay.db]
    HTTP --> Storage
    SiteAudit --> Storage
    Nuclei --> Storage

    Storage --> Findings[Assets, Scans,<br/>Evidence, Findings]
    FindingCmds --> Findings

    Chat --> Ollama[Local Ollama Models]
    WorkflowCmds --> Analysis[Local Analysis<br/>bluejay.analysis]
    FindingCmds --> Reports[Report Builder<br/>bluejay.reports]

    Analysis --> Ollama
    Reports --> Ollama
    Findings --> Reports
    RawScans --> Analysis
    Logs --> Analysis

    Analysis --> MarkdownReports[Markdown Reports<br/>reports/]
    Reports --> MarkdownReports
    Chat --> ChatLogs[Saved Chat Transcripts<br/>chats/]
```

## Main Components

| Component | Responsibility |
| --- | --- |
| `app.py` | Thin entrypoint for launching the application. |
| `bluejay.cli` | Starts the terminal UI, chat loop, and slash-command handling. |
| `bluejay.commands` | Routes slash commands to the correct command module. |
| `bluejay.cmd_system` | Handles help, status, config, files, reports, and chat commands. |
| `bluejay.cmd_workflows` | Handles scan, DNS, web, site audit, Nuclei, profile, and analysis workflows. |
| `bluejay.cmd_findings` | Handles assets, findings, triage, remediation, retest, baselines, diffs, and reports. |
| `bluejay.targets` | Normalizes targets and enforces safe target rules. |
| `bluejay.nmap` | Runs controlled Nmap scans and parses XML output into structured findings. |
| `bluejay.http_checks` | Performs HTTP, TLS, security-header, and cookie checks. |
| `bluejay.site_audit` | Runs bounded same-origin crawling and website checks. |
| `bluejay.nuclei` | Runs optional bounded Nuclei scans and parses JSONL output. |
| `bluejay.storage` | Stores assets, scans, evidence, and findings in SQLite. |
| `bluejay.analysis` | Sends scan/log evidence to local Ollama models for defensive analysis. |
| `bluejay.reports` | Builds evidence-based Markdown reports from stored findings. |
| `bluejay.config` | Manages local model profile configuration. |
| `bluejay.ui` | Provides terminal rendering, prompts, history, and completions. |

## Data Flow

```mermaid
sequenceDiagram
    actor User
    participant CLI as Blue Jay CLI
    participant Safety as Target Safety
    participant Tool as Security Tool
    participant Files as scans/ and logs/
    participant DB as SQLite Database
    participant LLM as Local Ollama Model
    participant Reports as reports/

    User->>CLI: Run slash command
    CLI->>Safety: Validate target and options
    Safety-->>CLI: Approved target
    CLI->>Tool: Run controlled scan or check
    Tool-->>Files: Save raw evidence
    Tool-->>DB: Store assets, scans, evidence, findings
    CLI->>LLM: Analyze saved evidence locally
    LLM-->>CLI: Defensive explanation and recommendations
    CLI->>Reports: Save Markdown report
    CLI-->>User: Show summary and next steps
```

## Command Workflow

```mermaid
flowchart LR
    Start[User enters command] --> Parse[Parse command and arguments]
    Parse --> CommandType{Command type}

    CommandType -->|System| System[Show status, config, files, help, reports]
    CommandType -->|Scan / Web / DNS| Validate[Validate target and safety rules]
    CommandType -->|Findings| Query[Query stored findings and assets]
    CommandType -->|Chat| LocalChat[Send prompt to local model]

    Validate --> Approved{Allowed?}
    Approved -->|No| Reject[Reject command with safety message]
    Approved -->|Yes| Execute[Run bounded tool workflow]

    Execute --> SaveEvidence[Save raw evidence]
    SaveEvidence --> ParseEvidence[Parse structured results]
    ParseEvidence --> Store[Store assets, scans, evidence, findings]
    Store --> Analyze[Analyze with local model]
    Analyze --> Report[Generate Markdown report]

    Query --> Triage[Show triage, remediation, retest, diff, or report]
    LocalChat --> ChatTranscript[Save local chat transcript]
```

## Local Storage Model

```mermaid
erDiagram
    ASSET ||--o{ SCAN : has
    ASSET ||--o{ FINDING : has
    SCAN ||--o{ EVIDENCE : produces
    FINDING ||--o{ EVIDENCE : supported_by
    BASELINE ||--o{ FINDING : compares_against

    ASSET {
        string target
        string address
        string type
        datetime first_seen
        datetime last_seen
    }

    SCAN {
        string scan_id
        string target
        string mode
        string tool
        datetime created_at
    }

    FINDING {
        string finding_id
        string target
        string title
        string severity
        string status
        datetime first_seen
        datetime last_seen
        int times_seen
    }

    EVIDENCE {
        string evidence_id
        string finding_id
        string source
        string file_path
        datetime created_at
    }

    BASELINE {
        string scope
        datetime created_at
        string finding_snapshot
    }
```

## Model Profiles

```mermaid
flowchart TB
    Config[data/config.json] --> Profiles[Model Profiles]
    Profiles --> ChatModel[Chat Model<br/>general guidance]
    Profiles --> AnalysisModel[Analysis Model<br/>scan and log reports]
    Profiles --> ExplainModel[Explain Model<br/>finding explanations]

    ChatModel --> Ollama[Ollama Runtime]
    AnalysisModel --> Ollama
    ExplainModel --> Ollama

    Ollama --> LocalOnly[Local Processing<br/>no cloud API required]
```

## Safety Boundaries

Blue Jay is designed for defensive and authorized use. Target validation is applied before active workflows run.

```mermaid
flowchart TD
    Target[Requested Target] --> Normalize[Normalize host, URL, or IP]
    Normalize --> Localhost{Localhost?}
    Normalize --> PrivateLAN{Private LAN IP?}
    Normalize --> PublicTarget{Public target?}

    Localhost -->|Yes| Allow[Allow]
    PrivateLAN -->|Yes| Allow
    PublicTarget --> CheckAllowlist[Check allowed_targets.txt]
    CheckAllowlist -->|Listed| Allow
    CheckAllowlist -->|Not listed| Block[Block]

    Allow --> Run[Run bounded scan/check]
    Block --> Message[Show responsible-use message]
```

## Deployment Model

Blue Jay runs as a local Python application. It depends on local tools for scanning and local model execution.

```mermaid
flowchart LR
    Python[Python 3.10+] --> BlueJay[Blue Jay CLI]
    BlueJay --> Ollama[Ollama]
    BlueJay --> Nmap[Nmap]
    BlueJay --> OptionalNuclei[Optional Nuclei]
    BlueJay --> SQLite[SQLite]
    BlueJay --> LocalFolders[Local workspace folders<br/>scans, logs, reports, chats, data]
```

## Summary

Blue Jay is structured as a modular local security workbench:

- The CLI provides a beginner-friendly interactive interface.
- Command modules separate system, workflow, and finding-management behavior.
- Tool integrations collect raw evidence from Nmap, DNS, HTTP/TLS checks, website audits, and optional Nuclei scans.
- SQLite stores assets, scans, evidence, findings, baselines, and scan history.
- Local Ollama models generate explanations and reports without sending scan data to a cloud service.
- Markdown reports and saved chat transcripts provide repeatable learning and remediation records.
