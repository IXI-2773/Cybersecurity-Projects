# Third-party source

![Third-party source](../assets/badges/third-party-source.svg)

This directory contains unmodified release snapshots of software written by upstream authors. Author credits, licenses, revision pins and file hashes are preserved.

The collection-developed fixtures, runners and recorded results are described under [Open-source tool integrations](../README.md#open-source-tool-integrations). Portfolio investigations and software are listed separately under [Portfolio projects](../README.md#portfolio-projects).


Additional [community CLI source copies](community/) include HTTP security-header scanning, hash identification, Linux CIS hardening audits, DLP scanning, DNS lookup, Docker security audits and SBOM/vulnerability matching from CarterPerez-dev/AngelaMos (AGPL-3.0-or-later). Their [separate pinned manifest](community/imports.json) leaves the previously recorded import evidence untouched. They are runnable source only; no collection-authored security findings or results are claimed.

Additional [independently maintained GitHub tools](external/) include dnstwist, assetfinder and httprobe; their [separate manifest](external/imports.json) pins 37 upstream files. All three are source-only imports with no collection execution results.

[Original authors and licenses](../THIRD_PARTY.md) · [Import manifest](imports.json)
