# Scanning and checks

Bluejay wraps collection tools in validated, bounded workflows. Use these commands only on systems you own, administer or have explicit permission to assess.

## Target rules

Active Nmap, web, site and Nuclei workflows accept:

- `localhost` and loopback addresses
- private and link-local IP addresses
- public hostnames or IP addresses explicitly listed in `allowed_targets.txt`

Nmap targets must be plain hostnames or IP addresses. Schemes, paths, ports, whitespace and shell syntax are rejected. Web targets may be a host or a simple `http` or `https` URL without credentials, fragments or an initial query string. Redirects are checked again and blocked if their destination is not allowed.

Tool arguments are passed as argument lists rather than through a shell. Timeouts are applied to Nmap, DNS, web, Nuclei and model operations.

## Nmap scan modes

Use:

```text
/scan <target> [quiet|quick|standard|deep] [options]
```

| Mode | Default behaviour |
| --- | --- |
| `quiet` | Top 25 TCP ports, `-T2`, 200 ms scan delay, no service detection or scripts. This is lower noise, not invisible. |
| `quick` | Top 25 TCP ports, `-T3`, service detection and a 60-second host timeout. |
| `standard` | Top 100 TCP ports, `-T3`, service detection and a 120-second host timeout. This is the default. |
| `deep` | Top 50 TCP ports, `-T3`, service detection and bounded Nmap `vuln` scripts. |

`/vuln <target>` uses the same bounded vulnerability-script profile as a deep scan.

Each successful Nmap run saves normal output and XML under `scans/`. The XML parser records open services and relevant script results as structured findings. The text result is also passed to the local analysis model for a Markdown report.

## Nmap options

Options can follow the target and optional mode:

| Option | Behaviour |
| --- | --- |
| `ports <list>` | Scan explicit ports such as `22,80,443` or `1-1024`. |
| `top <count>` | Scan the top 1 to 5,000 ports. |
| `udp` | Use UDP scanning. |
| `tcp` | Use TCP scanning. This is the default. |
| `service` or `-sV` | Enable service and version detection. |
| `no-service` | Disable service and version detection. |
| `version-intensity <0-9>` | Set Nmap version-probe intensity and enable service detection. |
| `version-light` | Set version intensity to 2. |
| `version-all` | Set version intensity to 9. |
| `reason` | Include Nmap reason output. |
| `timing <value>` or `-T0` to `-T4` | Use `paranoid`, `sneaky`, `polite`, `normal`, `aggressive` or the matching number. |
| `decoy <list>` or `-D <list>` | Use an explicit validated decoy list with `ME` exactly once. |

The decoy list supports up to five decoy hosts plus `ME`. Each decoy must itself be local, private or explicitly allowlisted. Decoys are intended for authorised monitoring exercises, not anonymity. TCP connect and version-detection traffic may still identify the scanning host.

Examples:

```text
/scan localhost
/scan localhost quiet
/scan 192.168.1.1 quick udp top 50
/scan localhost ports 22,80,443 reason
/scan localhost -sV -T0 version-intensity 7
/scan 192.168.1.1 top 1000 no-service timing polite
/scan 192.168.56.10 decoy 192.168.56.20,192.168.56.21,ME
```

Deep and vulnerability scans can be noisy. Confirm permission and scope before running them.

## Repeatable profiles

Profiles combine existing workflows:

| Profile | Steps |
| --- | --- |
| `quiet` | Quiet Nmap scan. |
| `quick` | DNS collection, then a quick Nmap scan. |
| `standard` | DNS collection, standard Nmap scan and web checks. |
| `deep` | DNS collection, standard Nmap scan, bounded vulnerability scripts and web checks. |
| `web` | DNS collection and web checks. |
| `report` | Generate a technical report from stored open findings. |

```text
/profile quiet localhost
/profile standard localhost
/profile deep scanme.nmap.org
/profile report all
```

The `report` profile accepts `all`. Active profiles expect a plain hostname or IP address, and their active steps still enforce the target allowlist.

## DNS checks

`/dig <domain>` collects A, AAAA, MX, NS, TXT and CAA records. `/dig <domain> advanced` or `all` also collects:

- SOA, DNSKEY and DS records
- selected SIP and submission SRV records
- DMARC and SPF hints
- common DKIM TXT and CNAME selector hints
- PTR records for up to four returned IP addresses

DKIM selectors vary by provider, so the selector checks are hints rather than a complete inventory. If `dig` is unavailable, Bluejay falls back to the local resolver for addresses and records that the advanced data could not be collected.

DNS output is saved under `logs/` and sent to the local analysis model.

## HTTP, TLS and header checks

`/web <host-or-url>` tries HTTPS and HTTP when given a bare host, or checks the supplied URL. It records connectivity, response status, selected disclosure headers, missing security headers, cookie attributes and TLS certificate issues where applicable.

```text
/web localhost
/web https://example.com/
```

Raw JSON evidence is saved under `logs/`. Findings and scan history are stored locally before the evidence is analysed by the configured Ollama model.

## Bounded website audit

`/site <host-or-url>` performs the web and TLS checks and crawls a same-origin page set. Current limits are:

- 8 fetched pages
- 40 queued links
- 500,000 response bytes per page

The audit checks for broken crawled pages, exposed directory listings, password forms on HTTP, password forms using GET, password forms submitting over HTTP, mixed-content resources and external new-tab links without opener protection.

The crawler does not submit forms. Cross-origin pages are not queued, and redirects remain subject to the target allowlist.

## Optional Nuclei integration

`/nuclei <host-or-url> [severity-list]` runs Nuclei only when the executable is installed. It uses JSONL output, a rate limit of 10, a 5-second request timeout, one retry and a 240-second process timeout.

```text
/nuclei localhost
/nuclei localhost info,low,medium
```

Allowed severities are `info`, `low`, `medium`, `high` and `critical`. Parsed template results are recorded as findings, but should still be validated before remediation decisions are made.

## Local repository checks

`/repo <directory>` inspects a directory inside the Bluejay project without running a third-party scanner. It inventories common dependency and build manifests, flags non-template `.env` files, and checks Dockerfiles for `latest` base-image tags and root-user defaults.

Traversal is read-only, ignores common generated directories, does not follow directory symlinks and stops after 5,000 files. These checks are heuristic and do not replace dependency, secret or container scanners.

```text
/repo .
```

## Existing file analysis

`/analyse <file> <mode>` sends an existing local file to the configured analysis model. Files must stay inside the project and are limited to 200,000 bytes.

```text
/analyse scans/example-nmap.txt nmap
/analyse logs/example-auth.log auth-log
/analyse logs/example-nginx-access.log web-log
/analyse logs/example-firewall.log firewall-log
```

The available modes are listed in the [command reference](commands.md).
