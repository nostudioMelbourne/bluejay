# Blue Jay Improvement Plan

This roadmap tracks the next upgrades for turning Blue Jay into a stronger local security workbench.

## Phase 1 - Model Profiles

- Add persistent config in `data/config.json`.
- Support separate model profiles for chat, analysis/report generation, and finding explanations.
- Add `/config show`, `/config model <profile> <model>`, and `/config reset`.
- Update `/model` and `/status` to show active profiles.

## Phase 2 - Local Site Audit

- Add `/site <host-or-url>` as a first-class local website workflow.
- Reuse the existing HTTP, TLS, header, cookie, and finding logic.
- Crawl a small same-origin page set with tight limits.
- Detect high-signal local web issues such as broken internal links, password forms over HTTP, insecure form actions, mixed-content references, and unsafe external `_blank` links.
- Save raw JSON evidence under `logs/` and record structured findings.

## Phase 3 - Baselines And Diffs

- [x] Add `/baseline <target|all>` to save current open findings.
- [x] Add `/diff <target|all>` to compare current findings with the saved baseline.
- [x] Highlight new, fixed, changed, and still-open findings.

## Phase 4 - Repository Checks

- Add project-aware checks for common local web app files.
- Inspect dependency manifests such as `package.json`, `requirements.txt`, lockfiles, Dockerfiles, and environment templates.
- Optionally integrate tools such as `npm audit`, `pip-audit`, `trivy`, and `semgrep` when installed.

## Phase 5 - Report Quality

- Improve report formats for developer remediation, retest evidence, executive summaries, and before/after comparisons.
- Add clearer "safe to ignore" notes and confidence rationale.
- Keep every model-generated report tied to saved local evidence.
