# Splunk Threat Investigation Playbook

Work through authentication, endpoint execution and persistence questions with source-aware searches.

Splunk SPL · Event correlation · Investigation playbook

Authentic reference visuals accompany the website case, with credit and scope captions.

## Three useful investigation paths

This playbook expands the multi-source Splunk case with specific questions an analyst can work through. The searches below are illustrative starting points for exported or ingested lab data. Indexes, field names, audit configuration and source coverage must match the actual environment.

## Repeated authentication failures followed by success

Start with the affected accounts, source addresses and time range. Inspect the event sequence; a count alone does not establish that failures preceded the success. Consider ordinary mistakes, administrative activity and shared addresses, then seek session or endpoint context.

```spl
index=lab EventCode IN (4624, 4625)
| eval outcome=if(EventCode=4624, "success", "failure")
| table _time host TargetUserName IpAddress EventCode outcome
| sort 0 _time
```

This table preserves events for review; it is not a deployed correlation alert. The separate public authentication case contains a tested inclusive-window detector.

[Inspect the tested authentication rule ↗](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/authentication-detection.html)

## Unexpected PowerShell or other process execution

Review parent process, user, command line and host context in available Sysmon process-creation events. Correlate relevant PowerShell logging and network events when collected. An encoded command or unusual parent relationship is a lead; legitimate automation remains a competing explanation.

```spl
index=lab source="*Sysmon*" EventCode=1
| table _time host User ParentImage Image CommandLine
| sort 0 _time
```

## Suspicious persistence or scheduled activity

Where available, inspect task-creation or change records, the initiating account and the executable or script. Compare the timing with nearby process execution and approved administration. Explain missing telemetry rather than filling gaps with a presumed attack chain.

## Turn searches into an investigation

Validate the sourcesConfirm time interpretation, host identity, field extraction and which event channels were actually collected.

Build a timelineKeep the original source references attached to observations across identity, endpoint and network data.

Challenge the interpretationUse benign comparison activity and document what would disprove the current hypothesis.

Explain the dispositionState whether the case needs more collection, escalation or closure, and why.

## Scope

Investigation playbook and example searches, not newly executed Splunk results. No ingested dataset, fired alert, dashboard capture or incident outcome is invented. The broader completed résumé lab and the smaller reproducible exercises retain their own evidence scope.

[Splunk Security Content and analytic stories ↗](https://research.splunk.com/)



## Academic foundation

Completed coursework: IST 5250 Incident Handling & Cyber Investigation and IST 4910 Enterprise Systems Administration (Fall 2024).

[Explore the academic background](https://ixi-2773.github.io/Cybersecurity_Portfolio/education.html).
