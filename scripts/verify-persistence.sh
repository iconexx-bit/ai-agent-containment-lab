#!/usr/bin/env bash
# verify-persistence.sh — does the killswitch survive `systemctl restart docker`?  (runbook O14 C, O17)
#
# This is the ONLY place in the lab that restarts the Docker daemon (tests/test-persistence-gate.sh).
# A restart stops every container on the host (live-restore is off): Wazuh, Qdrant, LiteLLM, Langfuse...
# The SIEM and the push channel are blind until they are back, so the act is rare and deliberate:
#   - an interactive terminal and a typed confirmation (no flag, no --yes)
#   - hc-ping.timer must already be stopped (runbook rule 38), the range down, the killswitch disarmed
#     with no marker: it will not clobber a live state
#   - sudoers.d/range-lab has no NOPASSWD for the restart: sudo asks for the password
# Two restarts:
#   phase A (O17)  marker ABSENT, jump armed by hand: does Docker itself keep the DOCKER-USER rules?
#                  With no marker range-killswitch.service does nothing, so the answer is Docker's alone.
#                  Reported as data (docker-preserves-jump=yes|no), never as pass/fail.
#   phase B (O24)  marker present, killswitch REMOVED (no jump, no chain): the iptables state after a host
#                  reboot. Only range-killswitch.service can bring the jump back within PERSIST_WAIT_ARM
#                  checks. This is the assertion. (Arming before the restart made it vacuous: Docker keeps
#                  DOCKER-USER, O17, so the jump survived whatever the unit did — runbook rule 71.)
# Every DOCKER-USER snapshot must be an iptables listing; anything else (sudo refused) is exit 3, not evidence.
# The wait tunables are iteration counts of 1 s: PERSIST_WAIT_DOCKER (90), PERSIST_WAIT_ARM (30),
# PERSIST_SETTLE (5, seconds before phase A looks at the chain).
#   exit 0 PASS   1 persistence FAIL   2 refused before anything was changed   3 environment error mid-run
# On every exit after the first change: marker removed, killswitch off (a failed cleanup is exit 3).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARKER="${RANGE_KILL_MARKER:-/var/lib/range-lab/killswitch.armed}"
WAIT_DOCKER="${PERSIST_WAIT_DOCKER:-90}"
WAIT_ARM="${PERSIST_WAIT_ARM:-30}"
SETTLE="${PERSIST_SETTLE:-5}"
KS="$ROOT/scripts/killswitch.sh"

refuse() { echo "REFUSED: $*" >&2; exit 2; }
# numbers from the environment are validated before any arithmetic (runbook rule 69)
[[ $WAIT_DOCKER =~ ^[1-9][0-9]*$ ]] || refuse "PERSIST_WAIT_DOCKER must be a positive integer"
[[ $WAIT_ARM =~ ^[1-9][0-9]*$ ]]    || refuse "PERSIST_WAIT_ARM must be a positive integer"
[[ $SETTLE =~ ^(0|[1-9][0-9]*)$ ]]  || refuse "PERSIST_SETTLE must be a non-negative integer"

# ---- guards: all of them before the first change ----------------------------------------------------
[[ -t 0 && -t 1 ]] || refuse "needs an interactive terminal (stdin and stdout must be a tty)"
state=$(systemctl is-active hc-ping.timer 2>/dev/null || true)
case $state in
  inactive|failed) ;;
  *) refuse "hc-ping.timer is '${state:-unknown}', not stopped — open the rule-38 window first:
  sudo systemctl stop hc-ping.timer && sudo systemd-run --on-active=20m --unit=hc-ping-resume-\$(date +%s) /bin/systemctl start hc-ping.timer" ;;
esac
running=$(docker ps -q --filter label=com.docker.compose.project=agent-range 2>&1) || refuse "cannot list containers: $running"
[[ -z $running ]] || refuse "range containers are running — just range-down first"
[[ ! -e $MARKER ]] || refuse "marker $MARKER exists — just killswitch-off first"
st=$("$KS" status 2>&1) || refuse "killswitch status failed: $st"
[[ ${st%%$'\n'*} == disarmed ]] || refuse "killswitch is armed — just killswitch-off first"

cat <<'BANNER'
This restarts the Docker daemon TWICE (phase A, phase B).
Every container on this host stops: Wazuh manager, Qdrant, LiteLLM, Langfuse, the range.
They come back by restart policy; until then the SIEM, the push channel and ops-doctor are blind.
Type RESTART-DOCKER to continue:
BANNER
read -r tok || refuse "no confirmation read"
[[ $tok == RESTART-DOCKER ]] || refuse "confirmation did not match — nothing was changed"

OUT="$ROOT/artifacts/verify-persistence-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT" || refuse "cannot create $OUT"
ver=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || ver=unknown

# ---- from here on every exit cleans up ---------------------------------------------------------------
final=0
cleanup() {
  local bad=0 s
  sudo rm -f "$MARKER" 2>/dev/null
  [[ ! -e $MARKER ]] || { echo "CLEANUP FAILED: marker $MARKER is still there" >&2; bad=1; }
  "$KS" off >/dev/null 2>&1
  s=$("$KS" status 2>&1); s=${s%%$'\n'*}
  [[ $s == disarmed ]] || { echo "CLEANUP FAILED: killswitch is still armed ($s)" >&2; bad=1; }
  ((bad)) && exit 3
  exit "$final"
}
trap cleanup EXIT
trap 'final=130; exit 130' INT TERM HUP

die() { echo "ERROR: $*" >&2; final=3; exit 3; }
snap() { # file — DOCKER-USER listing; an error text is not evidence (runbook rule 21)
  local first=""
  sudo -n iptables -S DOCKER-USER >"$1" 2>&1 || die "cannot read DOCKER-USER (see $1)"
  IFS= read -r first <"$1" || true
  [[ $first == "-N DOCKER-USER" ]] || die "DOCKER-USER snapshot is not an iptables listing (see $1)"
}
restart_docker() { # the single call site in the lab
  sudo systemctl restart docker
}
wait_docker() { # bounded: WAIT_DOCKER checks, 1 s apart
  local i
  for i in $(seq 1 "$WAIT_DOCKER"); do
    docker info >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

echo "docker $ver"

# ---- phase A: Docker alone (O17) ---------------------------------------------------------------------
echo "== phase A (O17): marker absent — does Docker itself keep the DOCKER-USER jump?"
"$KS" arm >"$OUT/a.arm.txt" 2>&1 || die "phase A: killswitch arm failed (see $OUT/a.arm.txt)"
snap "$OUT/a.before.txt"
restart_docker || die "phase A: the restart command failed"
wait_docker || die "phase A: docker did not come back within ${WAIT_DOCKER}s"
sleep "$SETTLE"
snap "$OUT/a.after.txt"
if "$KS" verify >/dev/null 2>&1; then preserves=yes; else preserves=no; fi
echo "docker-preserves-jump=$preserves"
"$KS" off >/dev/null 2>&1 || die "phase A: killswitch off failed"

# ---- phase B: the assertion (O24) --------------------------------------------------------------------
echo "== phase B (O24): marker present, killswitch removed (the state after a reboot) — the unit must re-arm it"
sudo mkdir -p "$(dirname "$MARKER")" && sudo touch "$MARKER" || die "phase B: cannot create the marker"
st=$("$KS" status 2>&1); st=${st%%$'\n'*}
[[ $st == disarmed ]] || die "phase B: the killswitch is '$st' before the restart — not the lost state"
snap "$OUT/b.before.txt"
restart_docker || die "phase B: the restart command failed"
wait_docker || die "phase B: docker did not come back within ${WAIT_DOCKER}s"
armed_at=0
for i in $(seq 1 "$WAIT_ARM"); do
  if "$KS" verify >/dev/null 2>&1; then armed_at=$i; break; fi
  sleep 1
done
snap "$OUT/b.after.txt"

# ---- verdict -----------------------------------------------------------------------------------------
if ((armed_at > 0)); then
  msg="PERSISTENCE PASS (docker $ver; docker-preserves-jump=$preserves; unit re-armed the removed killswitch after ~$((armed_at - 1))s)"
  final=0
else
  msg="PERSISTENCE FAIL (docker $ver; docker-preserves-jump=$preserves; the unit did NOT re-arm the removed killswitch within ${WAIT_ARM}s)"
  final=1
fi
{ echo "docker $ver"; echo "docker-preserves-jump=$preserves"; echo "$msg"; } >"$OUT/result.txt"
echo "$msg"
echo "evidence: $OUT"
exit "$final"
