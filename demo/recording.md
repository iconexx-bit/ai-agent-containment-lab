# 40-second shot list

| s | Frame | Command |
|---|---|---|
| 0–5 | Title + 10.66.0.0/16 | — |
| 5–12 | Range up, probe green | `just range-up` |
| 12–20 | **Break live**, probe red | `just break-canaries && just probe` |
| 20–26 | Fixed, green again | `just range-up` |
| 26–33 | Agent reaches out, tripwire logs | `docker exec agent-runner curl -s --max-time 3 https://canary.tripwire-range.invalid` |
| 33–40 | Killswitch + containment_ms overlay | `./scripts/containment-timer.sh` |

Seconds 12–20 carry the whole video. A green check convinces nobody;
a check that visibly goes red does.

Terminal: >=16pt. `git config core.pager cat`. range.env never on screen.
containment_ms=11588 (11.6s) verdict=PASS run=20260815T142841Z
