# ai-agent-containment-lab

## Status
2026-09-15: TOOLING FREEZE (armed 2026-08-14, scoped to v0.1.0-rc) lifted at v0.1.0 — range, killswitch and probe harness shipped.
New tooling ideas go to ## Backlog as one-liners, not code. Exception: CI-blocking failures only.
2026-10-24: D6 closed: three TTC/TTD measurements (n=5 each; run 3 after `stop_grace_period: 1s`, TTC median 1598 ms against about 10.6 s before) and the time to egress-closed with committed evidence in `docs/evidence/`; delivery to the phone proven for 100202, 100203, 100204 and 100220.
2026-10-27: A3 integration lab -> ASCC (operator decision 2026-10-27, an explicit exception to the backlog-only line above):
the judgement leaves the lab only as SARIF `clab/v1` (`schemas/clab.v1.json`, `integrations/ascc/emit.sh`, `verdict.sh` `VERDICT_JSON`,
`tests/test-clab-sarif.sh`). `verdict.sh` stays the only place a probe PASS/FAIL is decided; the emitter maps, never judges.
The ARN binding is `operator_declared`: never write that a scanner or the lab observed it. No ASCC code is imported here.
2026-10-28: public CI (`.github/workflows/test.yml`) runs `scripts/test-all.sh`, the same script as `just test` and pre-push
(`tests/test-ci.sh` keeps them one). A README claim stays backed by a test that now runs in public on every push.

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
- ~~compose stop takes about 10 s because `range-idp` and `agent-runner` do not exit on SIGTERM (docker's 10 s grace, then SIGKILL)~~ — done 2026-10-24 (`c9eb2e6`): `stop_grace_period: 1s` on `range-dns`, `range-idp`, `agent-runner`; re-measured, TTC median 1598 ms (run 3).
