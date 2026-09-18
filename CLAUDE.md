# ai-agent-containment-lab

## Status
TOOLING FREEZE until v0.1.0-rc (2026-08-21).
New tooling ideas go to ## Backlog as one-liners, not code.
Exception: CI-blocking failures only.

## Backlog
- restore-canaries recipe — быстрый reset canary-состояния, непроверено, after rc
- range-dns healthcheck checks A record via bare nslookup, but dnsmasq only answers AAAA (::) — false unhealthy, fix healthcheck test string, after rc

## BACKLOG
- Detection pack: journald decoder for tags `dnsmasq` / `range-idp`, then Sigma
  rules 100200-100299 (7 rules, matching SIGMA_EXPECTED). Verified by
  `scripts/negatives.sh sigma` — break/unbreak must flip the check.
  Do it alongside the Wazuh triage blog post; the rules are its illustration.
- Wazuh active-response (`range-contain-trigger`, `<location>local</location>`)
  was designed but never written to disk. Range containment currently runs via
  systemd + sudoers, not Wazuh.

## BACKLOG
- Detection pack: journald decoder for tags `dnsmasq` / `range-idp`, then Sigma
  rules 100200-100299 (7 rules, matching SIGMA_EXPECTED). Verified by
  `scripts/negatives.sh sigma` — break/unbreak must flip the check.
  Do it alongside the Wazuh triage blog post; the rules are its illustration.
- Wazuh active-response (`range-contain-trigger`, `<location>local</location>`)
  was designed but never written to disk. Containment currently runs via
  systemd + sudoers, not Wazuh.
- `docs/postmortem-replication.md` removed as an empty draft. Reinstate only
  with a named incident and the replication steps that reproduce it.
