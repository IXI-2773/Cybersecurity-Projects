# Linux access audit with SQL

This case creates three dummy regular files in a fresh temporary directory, joins
their observed Linux modes to declared policies in SQLite, applies scoped chmod
changes and checks actual access as UID/GID 65534 with no supplementary groups.
No host accounts or services are changed; the dummy script is never executed.

The complete execution requires Linux and permission to drop a child process's
UID/GID. Root alone does not guarantee those capabilities inside a restricted
container. A failed probe does not produce a successful execution report.

```sh
sudo python projects/09-linux-access-audit/audit_lab.py --output /tmp/access-report.json
sudo python -m unittest discover -s projects/09-linux-access-audit -p 'test_*.py' -v
```

Run just the SQL policy tests without privilege:

```sh
cd projects/09-linux-access-audit
python -m unittest test_audit_lab.PolicyTests -v
```

## Recorded result

[Open the visual case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/linux-sql-access-audit.html).

The [retained execution](https://github.com/IXI-2773/Cybersecurity_Portfolio/actions/runs/40333115846)
passed all eight tests, including actual kernel access checks, on Ubuntu 24.04.5,
Python 3.11.17 and SQLite 3.45.1. Execution time: 2026-10-26 13:43:45 UTC.

| File | Before → after | UID/GID 65534 probe |
| --- | --- | --- |
| Dummy service secret | 0644 → 0600 | Read allowed → denied |
| Dummy maintenance script | 0777 → 0755 | Write-open allowed → denied |
| Public notice | 0644 → 0644 | Read allowed → allowed |

SQL findings changed from two to zero under the same policies. All file-content
hashes remained unchanged. The write test opens without truncating or writing;
the dummy script is never executed. Files are root-owned and directories permit
traversal, so the probe tests file access rather than a blocked parent directory.

The committed [JSON](artifacts/executed_report.json) and
[stdout](artifacts/execution.txt) are unchanged bytes downloaded from artifact
`linux-access-audit-execution` (ID `12656040352`). The downloaded ZIP's SHA-256 was
`439c57a8eed9f6d0af2baa5ef0ebab098563c73b0c430c3b38c3a8d573caa69e`.
GitHub may expire the original artifact after 30 days; these committed copies
remain inspectable. The linked historical portfolio workflow ran the experiment. This collection's catalog check does not rerun privileged access probes; use the documented local commands for a fresh experiment.

Source branch commit: `325eab04e40a70435772e21883712f12fcb8ce6f`.
The pull-request runner checked out GitHub's test-merge commit
`5d1a34086adc419921e5d8696dfe1289b80daa89`, recorded as `GITHUB_SHA`.
The report also retains SHA-256 hashes of `audit_lab.py` and `audit.sql`; public
validation checks those exact source bytes and recomputes SQL findings from the
retained inventory. Changing executable source requires new executed evidence.

To validate this retained report and repeat the experiment without rewriting it:

```sh
sudo python projects/09-linux-access-audit/audit_lab.py --check
```

## Decisions and limits

Policies cover group/other read on the dummy secret and group/other write on the
script and public notice. Secret exposure is a confidentiality risk; a writable
trusted script is an integrity risk if executed later. This exercise observes
open permission, not exploitation or service behavior. On real systems, confirm
service ownership and required group access before applying these target modes.

Scope is standard Unix mode bits on three deliberately configured files. ACLs,
capabilities, network services, application authorization and all ways a file can
be replaced are outside this lab. No employment or production incident is claimed.
