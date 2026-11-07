# Imported open-source tools

![Open-source integration](assets/badges/open-source-integration.svg)

**Work type:** upstream-authored tool source, paired with collection-developed integration examples. [Portfolio projects](README.md#portfolio-projects) have a separate index.

These tools are copied release snapshots credited to their original authors. Their source is unmodified; each retains its own license. The collection's contribution is the pinned import, local examples, recorded outputs and integration checks.

| Tool | Original project and authors | Imported release | License | Collection example |
| --- | --- | --- | --- | --- |
| ssh-audit | [Joe Testa and contributors](https://github.com/jtesta/ssh-audit), including original author Andris Raugulis | [v3.9.0 / dbf8b69](https://github.com/jtesta/ssh-audit/tree/dbf8b696331925ce7d4dbf72cb93faf3968397aa) | [MIT](third_party/ssh-audit/LICENSE) | [Offline SSH algorithm review](projects/11-ssh-algorithm-review/) |
| detect-secrets | [Yelp and contributors](https://github.com/Yelp/detect-secrets) | [v1.5.0 / 01886c8](https://github.com/Yelp/detect-secrets/tree/01886c8a910c64595c47f186ca1ffc0b77fa5458) | [Apache-2.0](third_party/detect-secrets/LICENSE), with embedded notices preserved | [Secret-detection controls](projects/12-secret-detection/) |

[imports.json](third_party/imports.json) records every imported path and SHA-256. Runtime source, package metadata and notices are included; upstream test suites, build automation and test keys are excluded. Upstream READMEs are retained unchanged as source documents; use the collection examples above for commands that match this layout.

The first-party catalog checker skips upstream documentation and source. A separate [import checker](scripts/check_upstream_imports.py) checks their exact bytes and Python syntax, along with the retained examples. Current CI checks this evidence without launching SSH services or verifying credentials against network services.

Updates are manual: choose an upstream revision, review its changes, preserve its notices, refresh the import hashes and repeat only the affected example. These release snapshots do not receive automatic upstream fixes. The original tool authors are not represented as endorsing this collection.
