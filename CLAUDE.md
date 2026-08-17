# ai-agent-containment-lab

## Status
TOOLING FREEZE until v0.1.0-rc (2026-08-21).
New tooling ideas go to ## Backlog as one-liners, not code.
Exception: CI-blocking failures only.

## Backlog
- restore-canaries recipe — быстрый reset canary-состояния, непроверено, after rc
- range-dns healthcheck checks A record via bare nslookup, but dnsmasq only answers AAAA (::) — false unhealthy, fix healthcheck test string, after rc
