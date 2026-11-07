# Reproduce LAB-DFIR-001

This standard-library Python lab builds a deterministic ZIP evidence package, verifies it against an acquisition hash, examines a temporary working copy, inventories the artifacts, and creates a bounded timeline and findings.

```bash
python projects/07-forensic-evidence/build_evidence.py \
  projects/07-forensic-evidence/evidence-source \
  /tmp/evidence-package.zip \
  --manifest /tmp/manifest.json

python projects/07-forensic-evidence/examine_evidence.py \
  /tmp/evidence-package.zip \
  409bd208bf9a794f61e72176cc19c713cb81abb29e7b0006612075fed2c64cba

python projects/07-forensic-evidence/test_forensic_lab.py
```

The deterministic package built from the committed source files should have SHA-256 `409bd208bf9a794f61e72176cc19c713cb81abb29e7b0006612075fed2c64cba`.

## Safety and limits

All evidence is lab-created. URLs use reserved example domains, no network request occurs, and no executable is included. The findings show artifact correlation only; they do not establish execution, maliciousness, identity, or a real incident.
