# Contributing

Thanks for helping improve Blue Jay.

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

## Security Boundaries

Keep contributions defensive and authorised-use focused. Do not add features
that enable unauthorised access, stealth, credential theft, persistence,
malware, or destructive actions.

Generated runtime data belongs in ignored folders and should not be committed:
`chats/`, `data/`, `logs/`, `reports/`, and `scans/`.

## Pull Requests

Pull requests should include:

- Short summary of the change
- Verification commands run
- Any new external tool requirements
- Screenshots or report excerpts when terminal output or generated Markdown changes
