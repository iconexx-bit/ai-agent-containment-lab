# ai-agent-containment-lab

## Status
2026-09-15: TOOLING FREEZE (armed 2026-08-14, scoped to v0.1.0-rc) lifted at v0.1.0 — range, killswitch and probe harness shipped.
New tooling ideas go to ## Backlog as one-liners, not code. Exception: CI-blocking failures only.

## Backlog
- restore-canaries recipe — быстрый reset canary-состояния, непроверено, after rc
- ~~range-dns healthcheck: nslookup of an A record while dnsmasq answered only AAAA~~ — done 2026-10-14
  (`9fbbdc9`): NULL sinkhole answers A and AAAA; the healthcheck resolves the in-scope `health.sim.invalid`.
- ~~Detection pack~~ — done: v1 = 8 rules (`rules/containment.xml`: 100200-100206 + 100220) with the
  dnsmasq decoder, verified offline by `scripts/logtest.sh` (`e84bcfd`). `range-idp` has no decoder yet
  (canary rules 100230-100239 reserved). The sigma negative mutates the expectation, never the live
  manager (`scripts/negatives.sh`, D5 P3); `SIGMA_EXPECTED` has no default (D5 P5b).
- Wazuh active-response (`range-contain-trigger`, `<location>local</location>`)
  was designed but never written to disk. Containment currently runs via
  systemd + sudoers, not Wazuh.
- `docs/postmortem-replication.md` removed as an empty draft. Reinstate only
  with a named incident and the replication steps that reproduce it.
