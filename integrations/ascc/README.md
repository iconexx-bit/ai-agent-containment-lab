# Lab → ASCC: the containment judgement as SARIF (`clab/v1`)

[ASCC](https://github.com/iconexx-bit/ascc) correlates cloud scanner findings into attack chains.
This directory turns the lab's own judgement into a SARIF 2.1.0 log that ASCC can ingest next to
Prowler, Trivy and Checkov. Nothing here imports ASCC code; the contract is the file format.

```console
$ just probe                                            # writes artifacts/<run>/verdict.json (VERDICT_JSON)
$ just emit-sarif arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f67890
artifacts/<run>/clab.sarif.json <sha12>
```

`just emit-sarif ARN [TTC]` calls `integrations/ascc/emit.sh <verdict.json> <ttc.json> <arn>`; the
TTC summary defaults to the committed run-3 evidence `docs/evidence/d6-run3-ttc.json`.

## Contract (`schemas/clab.v1.json`, a profile of SARIF 2.1.0)

- One run. `tool.driver.name` = `containment-lab`; `run.properties.schema` = `clab/v1` (how ASCC
  recognises the file).
- `run.properties.binding` = `{"method": "operator_declared", "resource_arn": <ARN>}`. The ARN must be
  an EC2 instance ARN (`emit.sh` exits 2 otherwise). **It is declared by the operator, not observed:**
  no scanner saw that the range runs on that instance. The reference range is a local Docker range on
  one VM, so binding it to an AWS instance is a statement about where the agent would run.
- Six results, one per control, always in this order, each located at the declared ARN:

| ruleId | control | source | level on fail |
|---|---|---|---|
| `CLAB-EGRESS-001` | egress blocked by IP and by name | `verdict.sh` | error |
| `CLAB-TRIPWIRE-001` | tripwire domain sinkholed | `verdict.sh` | error |
| `CLAB-SIGMA-001` | detection rule files present (files on disk; loading is proven only by alerts) | `verdict.sh` | warning |
| `CLAB-CANARY-001` | canary accounts present | `verdict.sh` | warning |
| `CLAB-SIMCA-001` | simulation CA present (PEM header) | `verdict.sh` | note |
| `CLAB-TTC-001` | contained within the TTC threshold in every measured cycle | `measure-ttc` summary | error |

- `kind`: `pass` = verified, `fail` = violated, `open` = not verified (operator skip, `VERDICT_SKIP`).
  SARIF requires `level` `none` for anything but `fail`.
- Nothing is judged in `emit.sh`. Probe controls take `verdict.sh`'s result from `VERDICT_JSON`
  (schema `verdict/v1`; `verdict.sh` stays the only place a probe PASS/FAIL is decided). The TTC
  control is `pass` only if every requested cycle completed and passed its threshold.
- Provenance: `run.properties.probe` = the probe's `ts` and sha256, `run.properties.ttc.sha256` = the
  TTC summary's sha256. No clock, no network: the same inputs give the same bytes (`test-clab-sarif` E7).
- TTD is not exported: it is data, never a condition (`verdict.sh`, D6b).

Tested by `tests/test-clab-sarif.sh` (part of `just test`).
