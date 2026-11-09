# red-validate

Adversarial re-check of every candidate in `exploit/findings-raw.md`:
proof-marker grep (root:x:, UPL_, Dump completed), unproven demotion,
re-check queue. Writes `report/validation.md`.

```bash
./phases/07-validate.sh --target host --ws ~/redteam-runs/<target>/<ts>
```

Rules: status-code diff alone is not proof; unproven → Low; one standalone repro per finding.
Authorized targets only.
