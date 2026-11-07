# SSH algorithm review with ssh-audit

![Open-source integration](../../assets/badges/open-source-integration.svg)

**Contribution type:** integration example. Original tool authorship is identified below; collection work covers the fixtures, runner and recorded results.

**Upstream tool:** [ssh-audit](https://github.com/jtesta/ssh-audit), Joe Testa and contributors. **License:** [MIT](../../third_party/ssh-audit/LICENSE). The imported runtime is unmodified v3.9.0; [provenance](../../THIRD_PARTY.md).

## Collection contribution

This example supplies a two-algorithm input, runs the upstream CLI's offline database lookup and retains the exact output and source-bound receipt. It demonstrates interpreting the tool's classifications; it is not a live SSH server assessment or a claim of original tool authorship.

| Input algorithm | Observed upstream classification |
| --- | --- |
| `diffie-hellman-group1-sha1` | `fail`: the recorded output flags its small modulus and SHA-1 |
| `mlkem768x25519-sha256` | `info`: comparison algorithm, with no warning/failure line in this lookup |

The [actual output](artifacts/lookup.txt) includes the upstream explanations. The CLI returned **3**, which means a finding was present for this release, rather than a connection failure. This lookup evaluates named entries in the bundled database; it does not establish a server's offered algorithms, patch status or overall security.

## Run

From the repository root, choose a new output directory:

```sh
python scripts/imported_tool_demo.py ssh --output-dir ssh-algorithm-case
```

Or call the copied upstream tool directly:

```sh
python third_party/ssh-audit/ssh-audit.py --lookup mlkem768x25519-sha256,diffie-hellman-group1-sha1 --no-colors
```

No network connection or external dependency is needed for this example. The full upstream runtime also supports authorized host audits; consult its [source README](https://github.com/jtesta/ssh-audit/blob/dbf8b696331925ce7d4dbf72cb93faf3968397aa/README.md) for those separate operations. An attempted temporary-server experiment could not complete in the development environment because its chroot/user-mapping permissions were unavailable; no live-server success is claimed here.

[Inputs](fixtures/algorithms.json) · [Execution receipt](artifacts/receipt.json) · [All projects](../../README.md#all-projects)
