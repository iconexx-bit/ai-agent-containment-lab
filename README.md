# AI Agent Containment Lab

Reproducible range for testing whether an autonomous agent stays contained.
Containment is asserted by machine-checkable evidence, not by prompt text.

**A prompt is not a security control.**

<!-- GIF: demo/containment.gif -->

| Control | Verified by |
|---|---|
| Egress blocked | curl from inside the range, by IP and by name |
| Tripwire sinkholed | resolution inside the range, not on the host |
| Sigma rules loaded | Wazuh API, exact count (disk presence is not loading) |
| Canary accounts | getent per user |
| Simulation attestation | CA fingerprint — scope confusion becomes checkable |

```bash
./bootstrap.sh && just ready     # -> READY TO RECORD
```

Containment time: see `artifacts/<run>/containment.json`. Target < 60 s.
