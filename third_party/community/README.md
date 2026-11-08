# Community tools — original third-party code

These are **verbatim copies of upstream-authored CLI tools**, not software written by Don Lopez. The imports are pinned to [CarterPerez-dev/Cybersecurity-Projects at `6c8ac8547cf52edaa06935e637a1fe11ac45b865`](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865). The upstream source attributes ©AngelaMos (2026). Each tool remains under its original **AGPL-3.0-or-later** license. See [the import manifest](imports.json) and [original author credits](../../THIRD_PARTY.md).

| Copied tool | Upstream source | What it does | Status |
| --- | --- | --- | --- |
| [HTTP security-header scanner](http-headers-scanner/) | [Foundations project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/foundations/http-headers-scanner) | Fetches one URL and grades six response security headers. | Verbatim source; no collection scan or recorded result |
| [Hash identifier](hash-identifier/) | [Foundations project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/foundations/hash-identifier) | Suggests hash algorithm formats by prefix, length and character set. | Verbatim source; no accuracy study or recorded result |
| [Linux CIS hardening auditor](linux-cis-hardening-auditor/) | [Beginner project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/beginner/linux-cis-hardening-auditor) | Evaluates Linux hardening controls and formats compliance reports. | Verbatim source; [synthetic section-5 test-root result](../../projects/15-linux-cis-synthetic-hardening/); no live host audited |
| [DLP scanner](dlp-scanner/) | [Intermediate project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/intermediate/dlp-scanner) | Checks files, database samples and packet captures for sensitive-data patterns. | Verbatim source; no real-data scan or results |
| [DNS lookup CLI](dns-lookup/) | [Beginner project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/beginner/dns-lookup) | Queries DNS record types, reverse lookup and WHOIS. | Verbatim source; no network queries or results |
| [Docker Security Auditor](docker-security-audit/) | [Intermediate project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/intermediate/docker-security-audit) | Checks container, Dockerfile and Compose configurations against security controls. | Verbatim source; no daemon connection or scan result |
| [SBOM Vulnerability Matcher](sbom-generator-vulnerability-matcher/) | [Intermediate project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/intermediate/sbom-generator-vulnerability-matcher) | Generates SBOMs and matches dependencies to OSV/NVD records. | Verbatim source; no package scan or vulnerability findings |

## Use locally

All copies retain the upstream code, README and license, plus relevant package metadata or config. They omit upstream tests, large learning modules and lockfiles; the original READMEs may link to those omitted companion assets. For details, follow the pinned upstream source links above.

For the original two Python CLI tools, use Python 3.13+ in a dedicated environment with `rich>=15` and (for headers) `httpx>=0.28.1`:

```bash
python third_party/community/hash-identifier/hash_identifier.py --help
python third_party/community/http-headers-scanner/http_headers_scanner.py --help
```

For a read-only Linux CIS control listing (Bash on Debian/Ubuntu):

```bash
bash third_party/community/linux-cis-hardening-auditor/src/cisaudit.sh --list-controls
```

For the recorded synthetic section-5 before/after check (no real host accessed):

```bash
python3 projects/15-linux-cis-synthetic-hardening/verify_lab.py
```

For the DLP and DNS CLIs, use isolated virtual environments with the Python versions required by their upstream `pyproject.toml` (DLP ≥3.12; DNS ≥3.13). Installation can download large dependencies; review each upstream `pyproject.toml` and install only if you need to run that tool. From the repository root:

```bash
python -m pip install -e third_party/community/dlp-scanner
python -m pip install -e third_party/community/dns-lookup
dlp-scan --help
dnslookup --help
```


For the copied Go CLIs, use the Go version specified by each upstream `go.mod` (Docker audit: 1.25.9; SBOM matcher: 1.25.0). These commands may download Go dependencies; they are **examples only and were not executed during import**:

```bash
cd third_party/community/docker-security-audit
go run ./cmd/docksec --help
```

```bash
cd third_party/community/sbom-generator-vulnerability-matcher
go run ./cmd/bomber --help
```

Docker auditing may require permission to connect to a local Docker daemon. SBOM vulnerability matching uses external databases (OSV/NVD); do not run it in an unauthorized or sensitive repository without reviewing what it sends. The copied code is not independently security-audited and no successful build is claimed.

Only scan systems, hosts and data you own or are authorized to examine. DLP output can include sensitive matches: do not commit real logs, personal data, credentials, or scan reports to this public repo. The CIS auditor describes a benchmark subset, not a certification of compliance. DNS/WHOIS may make external queries. Hash identification is heuristic; HTTP-header grades are not vulnerability confirmation. **Only the Linux CIS import has a documented synthetic test-root execution**; the other six remain source-only, and no live-host results are claimed.

Run the bounded source-integrity check, which **does not execute the imported scanners**:

```bash
python scripts/check_community_imports.py
```

Existing [ssh-audit and detect-secrets integrations](../README.md) retain their earlier frozen [manifest](../imports.json) and results; importing these new tools does not rewrite that evidence.
