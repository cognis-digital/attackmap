# Deep demo -- mapping an incident timeline to ATT&CK

This scenario shows ATTACKMAP turning a free-text incident timeline into a
structured ATT&CK technique map, a tactic coverage heatmap, a gap analysis,
and a Navigator layer -- in the spirit of the public **MITRE ATT&CK** matrix
and the ATT&CK Navigator.

## Input

`incident_findings.txt` is a (synthetic) authorized blue-team timeline for a
ransomware intrusion. Each line is the kind of one-sentence finding an analyst
writes during triage: phishing delivery, PowerShell + `certutil` staging,
HTTPS beaconing, scheduled-task/service persistence, `mimikatz`/LSASS and
DCSync credential theft, BloodHound discovery, PsExec lateral movement,
7-Zip staging, cloud exfil, `vssadmin delete` recovery inhibition, Defender
tamper, and the final ransomware encryption. One line is deliberately benign
(a CDN TLS handshake) and should map to nothing.

## Run it

```sh
# Map every finding to technique IDs (exit code 1 == techniques found)
python -m attackmap map demos/02-deep/incident_findings.txt

# Tactic-by-tactic coverage heatmap (kill-chain order)
python -m attackmap heatmap demos/02-deep/incident_findings.txt

# Gap analysis: which bundled techniques were NOT observed
python -m attackmap gap demos/02-deep/incident_findings.txt

# Export an ATT&CK Navigator layer you can load at
# https://mitre-attack.github.io/attack-navigator/
python -m attackmap navigator demos/02-deep/incident_findings.txt \
    --name "Ransomware IR" --out layer.json

# JSON for piping into a SIEM / notebook
python -m attackmap map demos/02-deep/incident_findings.txt --format json
```

## What to expect

The timeline lights up the full kill chain -- Initial Access (T1566.001),
Execution (T1059.001, T1053.005), Persistence (T1543.003), Defense Evasion
(T1562.001), Credential Access (T1003.001, T1003.003), Discovery (T1482),
Lateral Movement (T1021.002), Collection (T1560), Command and Control
(T1071.001, T1105), Exfiltration (T1567.002), and Impact (T1486, T1490) --
each with evidence strings and a confidence level. The benign CDN line maps
to nothing. The Navigator layer scores each observed technique 33/66/100 by
confidence so it renders as a heatmap in the public ATT&CK Navigator.
