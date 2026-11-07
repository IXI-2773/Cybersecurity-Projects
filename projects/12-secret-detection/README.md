# Secret detection with detect-secrets

![Open-source integration](../../assets/badges/open-source-integration.svg)

**Contribution type:** integration example. Original tool authorship is identified below; collection work covers the fixtures, runner and recorded results.

**Upstream tool:** [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets). **License:** [Apache-2.0](../../third_party/detect-secrets/LICENSE), with original embedded notices preserved. Runtime source is unmodified v1.5.0; [provenance](../../THIRD_PARTY.md).

## Collection contribution and observed result

The integration runs the upstream CLI over three controlled files, checks the findings, removes the demonstration marker in a temporary copy and rescans. Source and input/output hashes are retained with the actual execution.

| Control | Before | After marker removal |
| --- | ---: | ---: |
| Private-key **header only**, with no key material | 1 `Private Key` candidate | 0 |
| Benign notes | 0 | 0 |
| Explicitly allowlisted demonstration header | 0 | 0 |

The [before JSON](artifacts/before.json) and [after JSON](artifacts/after.json) are actual CLI outputs. Both CLI invocations return **0**: `scan` creates a baseline even when findings exist. Inspect the findings rather than treating exit zero as an absence-of-secrets verdict.

All inputs are public, harmless examples. The experiment uses `--no-verify` and one worker; it does not verify credentials against network services or scan personal files. Removing this header is a controlled detection test, not evidence of rotating or remediating a real leaked credential. An allowlist exception hides a candidate and needs its own justification in real use.

## Run

Create a virtual environment and use its Python interpreter for the installation and run:

```sh
python -m venv .venv-tools
# Activate .venv-tools using your shell's normal activation command.
python -m pip install -r projects/12-secret-detection/requirements.txt
python scripts/imported_tool_demo.py secrets --output-dir secret-detection-case
```

Choose a new output directory. The two runtime dependencies are pinned in [requirements.txt](requirements.txt). The copied source is loaded from `third_party/detect-secrets`, without installing a separate detect-secrets release. Optional upstream word-list/gibberish features are not used by this example.

[Inputs](fixtures/) · [Execution receipt](artifacts/receipt.json) · [Upstream runtime](../../third_party/detect-secrets/detect_secrets/) · [All projects](../../README.md#all-projects)
