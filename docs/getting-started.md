# Getting started

This guide sets up Bluejay for local use. Only run its active checks against systems you own, administer or have explicit permission to assess.

## Requirements

- Python 3.10 or later
- Nmap for `/scan` and `/vuln`
- Ollama for chat, evidence analysis and finding explanations
- `dig` for complete DNS collection
- Nuclei only if you plan to use `/nuclei`

The Python dependencies in `requirements.txt` provide the richer terminal interface, Markdown rendering, command history and slash-command picker. Bluejay has simpler fallbacks when those packages are unavailable.

## Install the Python package

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

You can also install the project in editable mode to add the `bluejay` console command:

```bash
python -m pip install -e .
bluejay
```

Without an editable install, use either entry point:

```bash
python -m bluejay
python app.py
```

## Install local tools

Install [Ollama](https://ollama.com/) using its platform instructions, then confirm it is available:

```bash
ollama --version
```

On macOS, install Nmap with Homebrew:

```bash
brew install nmap
```

On Debian, Kali or Ubuntu:

```bash
sudo apt update
sudo apt install nmap
```

Confirm Nmap is available:

```bash
nmap --version
```

Install Nuclei separately if you want template-based checks through `/nuclei`. It is not required for the rest of Bluejay.

## Install the Ollama models

Bluejay defines separate roles for general chat, evidence analysis and finding explanations.

```bash
ollama pull gpt-oss:latest
ollama pull qwen2.5-coder:latest
ollama pull llama3.1:latest

ollama create bluejay -f Modelfile
ollama create bluejay-analyst -f Modelfile.analysis
ollama create bluejay-explainer -f Modelfile.explain
```

The role models can be changed later. See [Local AI](local-ai.md).

## Start Bluejay

```bash
python -m bluejay
```

Use `/status` to check the configured models, local tools, findings count and workspace paths:

```text
/status
```

In an interactive terminal with `prompt_toolkit`, type `/` to open the command menu and use the arrow keys, Enter or Tab to select a command. The fallback interface provides Tab completion.

## Authorise targets

Localhost, loopback addresses and private or link-local IP addresses are accepted by default. Public targets must be listed in `allowed_targets.txt`, one per line:

```text
# Blue Jay authorised scan targets
# Add one target per line.

scanme.nmap.org
```

Adding a target to the file does not establish legal permission. Only add targets that you are authorised to assess. Use `/allowed` to review the current list.

## First workflow

Start with a low-scope local scan:

```text
/scan localhost quick
/findings
/triage localhost
/report technical localhost
```

Bluejay saves Nmap text and XML evidence under `scans/`, records the asset, scan and findings in `data/bluejay.db`, writes a JSONL compatibility mirror under `data/`, and saves the local model's Markdown analysis under `reports/`.

For a wider workflow:

```text
/profile standard localhost
/baseline localhost
```

The standard profile collects DNS information, runs a standard Nmap service scan and performs web checks. Read [Scanning and checks](scanning.md) before using broader or noisier modes.

## Check the installation

For development verification:

```bash
python -m compileall app.py bluejay tests
python -m unittest discover
```

If a command reports a missing tool, install that tool or choose a workflow that does not require it. `/status` is the quickest way to review the environment.
