# Community tools — original third-party code

These are **verbatim copies of upstream-authored CLI tools**, not software written by Don Lopez. The imports are pinned to [CarterPerez-dev/Cybersecurity-Projects at `6c8ac8547cf52edaa06935e637a1fe11ac45b865`](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865). The Python source attributes ©AngelaMos (2026). Each tool remains under its original **AGPL-3.0-or-later** license. See [the import manifest](imports.json) and [original author credits](../../THIRD_PARTY.md).

| Copied tool | Upstream source | What it does | Status |
| --- | --- | --- | --- |
| [HTTP security-header scanner](http-headers-scanner/) | [Foundations project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/foundations/http-headers-scanner) | Fetches one URL and grades six response security headers. | Verbatim source; no collection scan or recorded result |
| [Hash identifier](hash-identifier/) | [Foundations project](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/foundations/hash-identifier) | Suggests hash algorithm formats by prefix, length and character set. | Verbatim source; no accuracy study or recorded result |

## Use locally

These copies include the upstream scripts, readmes, dependency metadata and licenses. They omit the large upstream learning modules, tests and lockfiles. The original READMEs may link to omitted companion material; use the pinned upstream links above for that material.

For Python 3.13+ in a dedicated environment, install the upstream runtime dependencies `rich>=15` (both tools) and `httpx>=0.28.1` (header scanner), then invoke:

```bash
python third_party/community/hash-identifier/hash_identifier.py --help
python third_party/community/http-headers-scanner/http_headers_scanner.py --help
```

Use the header scanner **only with websites you own or are authorized to assess**. Hash guesses are heuristic, not proof of a generating algorithm. Neither copy is represented as a vulnerability confirmation or original portfolio project.

Run the bounded source-integrity check, which **does not execute either tool**:

```bash
python scripts/check_community_imports.py
```

Existing [ssh-audit and detect-secrets integrations](../README.md) retain their earlier frozen [manifest](../imports.json) and results; importing these new tools does not rewrite that evidence.
