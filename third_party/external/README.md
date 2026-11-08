# Independent upstream source snapshots

These files are copied from the credited **original GitHub repositories** at pinned commits. Their authors wrote the software; the collection owner did not. Each snapshot includes its upstream license and has an exact-file [import manifest](imports.json). None was run, built, network-scanned, or validated for real-world findings as part of this import.

| Imported source | Original authors / repository | Source revision | License | Included scope |
| --- | --- | --- | --- | --- |
| [dnstwist](dnstwist/) | [elceef/dnstwist](https://github.com/elceef/dnstwist) — domain lookalike detection | [3413953](https://github.com/elceef/dnstwist/tree/341395377f40761fe4152f43fd18eea757b6069a) | [Apache-2.0](dnstwist/LICENSE) | CLI Python code, dictionaries, dependency metadata and text docs; no optional webapp or binary media |
| [assetfinder](assetfinder/) | [tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) — public subdomain discovery | [4e95d87](https://github.com/tomnomnom/assetfinder/tree/4e95d8701aae8cff1c27af2626eb22ba110ad583) | [MIT](assetfinder/LICENSE) | Original Go source, docs and build helper |
| [httprobe](httprobe/) | [tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) — HTTP/HTTPS reachability probing | [0745f64](https://github.com/tomnomnom/httprobe/tree/0745f649beb01c3cf712e0c52f9760d8a92cfdc2) | [MIT](httprobe/LICENSE) | Original Go source, docs, Dockerfile and module metadata |

This is a third-party source archive, **not three original portfolio projects or proof of practical tool use**. Code and referenced services may have changed since the pinned revision. Any later hands-on study needs explicit authorized targets, retained evidence and separate reporting. Never run the probes against systems without permission.

Integrity check (does not execute third-party code): `python scripts/check_external_imports.py` from the repository root.
