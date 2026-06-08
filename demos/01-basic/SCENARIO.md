# Demo 01 - Basic: mapping triage findings to ATT&CK

This scenario uses a small set of findings produced by a **defensive** triage of
an authorized incident-response engagement (EDR alerts + a web-app pentest
report). ATTACKMAP resolves each finding to MITRE ATT&CK (sub-)techniques,
builds a per-tactic coverage heatmap, and exports an ATT&CK Navigator layer.

No exploitation is performed; this is analysis/detection mapping only.

## Input

`findings.json` - a list of findings. Each finding may include `name`,
`description`, `severity`, and an optional explicit `technique_id` override.

## Run it

```bash
# Map findings to techniques (table)
python -m attackmap map --input demos/01-basic/findings.json

# Weighted per-tactic coverage heatmap
python -m attackmap heatmap --input demos/01-basic/findings.json

# ATT&CK Navigator layer (paste into navigator at mitre-attack.github.io)
python -m attackmap navigator --input demos/01-basic/findings.json --format json

# Pipe instead of file
cat demos/01-basic/findings.json | python -m attackmap map --format json
```

## Expected behavior

- `map` resolves PowerShell, LSASS dumping, RDP lateral movement, an HTTPS C2
  beacon, SQL injection on a public-facing app, and ransomware impact.
- One low-signal finding ("Informational: outdated TLS") stays **unmapped** and
  is listed separately.
- Exit code is **1** because actionable techniques were mapped (useful in CI to
  flag that detections are present).

## Severity weighting

Heatmap scores sum severity weights per technique:
`info=1, low=2, medium=4, high=7, critical=10`.
