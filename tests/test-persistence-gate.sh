#!/usr/bin/env bash
# test-persistence-gate.sh — O14 C (runbook 10.6): restarting the Docker daemon is one deliberate,
# guarded act in ONE place; the Friday gate and every recipe leave the daemon alone.
#   D1 no tracked code except scripts/verify-persistence.sh restarts or stops the Docker daemon
#   D2 verify-persistence.sh restarts it from exactly one call site (function restart_docker)
#   D3 justfile: no break-docker; recipe verify-persistence runs the script; ready.sh never calls it
#   D4 sudoers.d/range-lab grants no NOPASSWD restart of docker (the sudo password is part of the gate)
#   D5 README: `just ready` is no longer described as restarting the daemon; verify-persistence is named
#   V0..V10 behaviour of scripts/verify-persistence.sh in a fake world (fake sudo/systemctl/docker/sleep,
#      stub killswitch.sh; a real pseudo-terminal via script(1)) — see the table in each case
# Each scanner is proven on fixtures first (rule 54). Hermetic: no Docker, no sudo, no network.
#   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in justfile scripts/ready.sh sudoers.d/range-lab README.md; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
for b in script timeout awk; do command -v "$b" >/dev/null 2>&1 || { echo "$b missing" >&2; exit 2; }; done
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

# ---- scanner: daemon restart/stop in code (text after '#' ignored) -----------------------------------
P1='systemctl[[:space:]]+(restart|stop|kill|try-restart|reload-or-restart)[[:space:]]+docker([.]service|[.]socket)?([^[:alnum:]_-]|$)'
P2='service[[:space:]]+docker[[:space:]]+(restart|stop)'
P3='(pkill|killall)[[:space:]].*dockerd'
daemon_hits() { # files... -> "file:line: text" per hit
  P1="$P1" P2="$P2" P3="$P3" awk '{ code=$0; sub(/#.*/, "", code) }
    code ~ ENVIRON["P1"] || code ~ ENVIRON["P2"] || code ~ ENVIRON["P3"] { printf "%s:%d: %s\n", FILENAME, FNR, $0 }' "$@"
}
cat >"$T/bad" <<'FX'
sudo systemctl restart docker
  bash -c 'sudo systemctl restart docker && sleep 8'
sudo systemctl stop docker.socket
sudo service docker restart
sudo pkill -9 dockerd
systemctl try-restart docker
FX
cat >"$T/ok" <<'FX'
# sudo systemctl restart docker
sudo systemctl status docker
sudo systemctl start range-killswitch
sudo systemctl restart docker-compose-helper
sudo systemctl restart dockerd-proxy
echo fine  # systemctl restart docker
docker compose restart range-dns
FX
nb=$(daemon_hits "$T/bad" | wc -l); nk=$(daemon_hits "$T/ok" | wc -l)
((nb == 6 && nk == 0)) || { echo "GUARD UNPROVEN: daemon_hits bad=$nb/6 ok=$nk/0" >&2; daemon_hits "$T/bad" "$T/ok" >&2; exit 2; }

# ---- D1 ---------------------------------------------------------------------------------------------
mapfile -t files < <(cd "$ROOT" && git ls-files -- '*.sh' justfile Makefile ':!tests/' ':!scripts/verify-persistence.sh')
((${#files[@]} > 0)) || { echo "nothing scanned (git ls-files)" >&2; exit 2; }
hits=$(cd "$ROOT" && daemon_hits "${files[@]}")
[[ -z $hits ]] || no "D1 daemon restart/stop outside scripts/verify-persistence.sh: $(paste -sd'|' <<<"$hits")"

# ---- D2 ---------------------------------------------------------------------------------------------
VP="$ROOT/scripts/verify-persistence.sh"
if [[ ! -f $VP ]]; then
  no "D2 scripts/verify-persistence.sh does not exist"
else
  n=$(daemon_hits "$VP" | wc -l)
  inf=$(awk '/^restart_docker\(\)/,/^}/' "$VP" | sed 's/#.*//' | grep -cE "$P1")
  ((n == 1 && inf == 1)) || no "D2 want exactly 1 restart call site inside restart_docker(): total=$n inside=$inf"
fi

# ---- D3 ---------------------------------------------------------------------------------------------
grep -qE '^break-docker:' "$ROOT/justfile" && no "D3 justfile still has a break-docker recipe"
body=$(awk '/^verify-persistence:/{f=1; next} f && /^[^[:space:]]/{exit} f' "$ROOT/justfile")
grep -qF './scripts/verify-persistence.sh' <<<"$body" || no "D3 justfile has no verify-persistence recipe running ./scripts/verify-persistence.sh"
sed 's/#.*//' "$ROOT/scripts/ready.sh" | grep -q 'verify-persistence' && no "D3 ready.sh calls verify-persistence: the Friday gate must never restart the daemon"

# ---- D4 ---------------------------------------------------------------------------------------------
sd() { sed 's/#.*//' "$1" | grep -cE 'systemctl[[:space:]]+restart[[:space:]]+docker'; }
printf 'Cmnd_Alias X = /usr/bin/systemctl restart docker, \\\n' >"$T/sd.bad"; printf '# /usr/bin/systemctl restart docker\nA = b\n' >"$T/sd.ok"
[[ $(sd "$T/sd.bad") == 1 && $(sd "$T/sd.ok") == 0 ]] || { echo "GUARD UNPROVEN: sudoers scan" >&2; exit 2; }
c=$(sd "$ROOT/sudoers.d/range-lab")
[[ $c == 0 ]] || no "D4 sudoers.d/range-lab still grants 'systemctl restart docker' ($c line)"

# ---- D5 ---------------------------------------------------------------------------------------------
grep -qF 'verify-persistence' "$ROOT/README.md" || no "D5 README does not mention verify-persistence"
grep -nF 'killswitch, Docker restart' "$ROOT/README.md" >/dev/null && no "D5 README still describes just ready as including a Docker restart"
grep -nF 'and restarts the Docker daemon' "$ROOT/README.md" >/dev/null && no "D5 README still says just ready restarts the Docker daemon"

# ---- V: behaviour of scripts/verify-persistence.sh ----------------------------------------------------
if [[ ! -f $VP ]]; then
  no "V0 scripts/verify-persistence.sh does not exist: behaviour not tested"
else
  # world: $d/{scripts,bin,w}; w/ holds the state: log restarts jump marker docker-down range-running timer rearm
  world() { # name -> prints dir
    local d="$T/$1"
    mkdir -p "$d/scripts" "$d/bin" "$d/w" || exit 2
    cp "$VP" "$d/scripts/verify-persistence.sh" || exit 2
    echo inactive >"$d/w/timer"
    cat >"$d/scripts/killswitch.sh" <<'KS'
#!/usr/bin/env bash
# stub: the iptables jump is the file $FAKE_W/jump; the systemd unit's async re-arm is the counter file rearm
W="$FAKE_W"
case "${1:-}" in
  arm)    touch "$W/jump"; echo "KILLSWITCH ARMED" ;;
  verify) if [[ -f $W/rearm ]]; then d=$(<"$W/rearm"); if ((d > 0)); then echo $((d - 1)) >"$W/rearm"; else rm -f "$W/rearm"; touch "$W/jump"; fi; fi
          if [[ -e $W/jump ]]; then echo "KILLSWITCH ARMED"; else echo "KILLSWITCH NOT ARMED" >&2; exit 1; fi ;;
  off)    rm -f "$W/jump" "$W/rearm"; echo "KILLSWITCH DISARMED" ;;
  status) if [[ -e $W/jump ]]; then echo armed; else echo disarmed; fi ;;
  *) exit 2 ;;
esac
KS
    cat >"$d/bin/sudo" <<'SUDO'
#!/usr/bin/env bash
W="$FAKE_W"; a=("$@"); [[ ${a[0]:-} == -n ]] && a=("${a[@]:1}")
echo "sudo ${a[*]}" >>"$W/log"
case "${a[0]:-}" in
  systemctl)
    [[ "${a[1]:-} ${a[2]:-}" == "restart docker" ]] || exit 0
    echo RESTART >>"$W/restarts"
    [[ -n ${FAKE_DOCKER_NEVER:-} ]] && touch "$W/docker-down"
    [[ -n ${FAKE_DOCKER_DROPS:-} ]] && rm -f "$W/jump"
    if [[ -e $FAKE_MARKER && -n ${FAKE_UNIT_REARMS:-} ]]; then echo "${FAKE_REARM_DELAY:-0}" >"$W/rearm"; else rm -f "$W/rearm"; fi ;;
  iptables)
    if [[ ${a[1]:-} == -S && ${a[2]:-} == DOCKER-USER ]]; then
      echo "-N DOCKER-USER"; [[ -e $W/jump ]] && echo "-A DOCKER-USER -j RANGE-KILL"; echo "-A DOCKER-USER -j RETURN"
    fi ;;
  *) exec "${a[@]}" ;;
esac
SUDO
    cat >"$d/bin/systemctl" <<'SC'
#!/usr/bin/env bash
if [[ ${1:-} == is-active ]]; then s=$(<"$FAKE_W/timer"); echo "$s"; [[ $s == active ]]; exit; fi
exit 0
SC
    cat >"$d/bin/docker" <<'DK'
#!/usr/bin/env bash
case "${1:-}" in
  version) echo 29.6.1 ;;
  info)    [[ -e $FAKE_W/docker-down ]] && exit 1; exit 0 ;;
  ps)      [[ -e $FAKE_W/range-running ]] && echo abc123; exit 0 ;;
esac
exit 0
DK
    printf '#!/bin/sh\nexit 0\n' >"$d/bin/sleep"
    chmod +x "$d"/bin/* "$d"/scripts/*.sh
    [[ $(PATH="$d/bin:$PATH" command -v sudo) == "$d/bin/sudo" ]] || { echo "fake sudo not first on PATH" >&2; exit 2; }
    echo "$d"
  }
  # run NAME MODE TOKEN PRE [ENV=val...]   MODE: tty | notty; PRE: shell snippet (w = world state dir) or ""
  # -> sets d out rc nrest.  `timer=X` sets the fake hc-ping.timer state.
  run() {
    d=$(world "$1") || exit 2; local mode=$2 token=$3 pre=$4; shift 4
    local w="$d/w"; : >"$w/log"; : >"$w/restarts"
    [[ -n $pre ]] && eval "$pre"
    local envs=(FAKE_W="$w" FAKE_MARKER="$w/marker" RANGE_KILL_MARKER="$w/marker"
                PERSIST_WAIT_DOCKER=3 PERSIST_WAIT_ARM=5 PERSIST_SETTLE=0 "$@") e
    for e in "${envs[@]}"; do case $e in timer=*) echo "${e#timer=}" >"$w/timer" ;; esac; done
    if [[ $mode == tty ]]; then
      out=$(cd "$d" && env -i PATH="$d/bin:/usr/bin:/bin" TERM=dumb "${envs[@]}" \
            timeout 30 script -qec "bash scripts/verify-persistence.sh" /dev/null < <(printf '%s\n' "$token") 2>&1 | tr -d '\r'; exit "${PIPESTATUS[0]}"); rc=$?
    else
      out=$(cd "$d" && env -i PATH="$d/bin:/usr/bin:/bin" TERM=dumb "${envs[@]}" \
            timeout 30 bash scripts/verify-persistence.sh < <(printf '%s\n' "$token") 2>&1); rc=$?
    fi
    nrest=$(wc -l <"$w/restarts")
  }
  show() { echo "--- $1 (rc=$rc, restarts=$nrest):"; echo "$out"; cat "$d/w/log"; }
  clean() { [[ ! -e $d/w/jump && ! -e $d/w/marker ]]; }
  TOK=RESTART-DOCKER

  # harness self-proof: a full PASS run must work before any negative is trusted
  run v6 tty "$TOK" "" FAKE_UNIT_REARMS=1
  if ! { ((rc == 0)) && grep -q 'PERSISTENCE PASS' <<<"$out"; }; then
    no "V6 baseline: right token, Docker preserves the jump -> rc 0 and PERSISTENCE PASS"; show v6
  fi
  ((nrest == 2)) || { no "V6 exactly 2 daemon restarts (phase A, phase B), got $nrest"; show v6; }
  grep -q 'docker-preserves-jump=yes' <<<"$out" || { no "V6 phase A must report docker-preserves-jump=yes"; show v6; }
  grep -q 'docker 29.6.1' <<<"$out" || { no "V6 output must carry the daemon version"; show v6; }
  clean || { no "V6 end state: killswitch disarmed and marker removed"; show v6; }
  ls "$d"/artifacts/verify-persistence-*/result.txt >/dev/null 2>&1 || { no "V6 evidence file artifacts/verify-persistence-*/result.txt missing"; show v6; }

  # refusals: nothing may restart, nothing may be armed or marked
  run v1 notty "$TOK" "" FAKE_UNIT_REARMS=1
  { ((rc == 2 && nrest == 0)) && grep -qi 'terminal' <<<"$out"; } || { no "V1 no tty, right token piped in: rc 2, no restart, says why (a scripted confirmation is refused)"; show v1; }
  run v2 tty "$TOK" "" timer=active
  { ((rc == 2 && nrest == 0)) && grep -q 'hc-ping.timer' <<<"$out"; } || { no "V2 hc-ping.timer active: rc 2, no restart (rule 38)"; show v2; }
  run v2b tty "$TOK" "" timer=
  { ((rc == 2 && nrest == 0)); } || { no "V2b timer state unknown/empty must refuse (fail closed)"; show v2b; }
  run v3 tty "$TOK" 'touch "$w/range-running"'
  { ((rc == 2 && nrest == 0)) && grep -qi 'range' <<<"$out"; } || { no "V3 range containers running: rc 2, no restart"; show v3; }
  run v4 tty "$TOK" 'touch "$w/jump"'
  { ((rc == 2 && nrest == 0)) && [[ -e $d/w/jump ]]; } || { no "V4 killswitch already armed: rc 2, no restart, the live jump is NOT cleaned up"; show v4; }
  run v4b tty "$TOK" 'touch "$w/marker"'
  { ((rc == 2 && nrest == 0)) && [[ -e $d/w/marker ]]; } || { no "V4b marker already present: rc 2, no restart, the marker is NOT removed"; show v4b; }
  run v5 tty "yes" ""
  { ((rc == 2 && nrest == 0)) && clean; } || { no "V5 wrong confirmation: rc 2, no restart, nothing armed"; show v5; }
  run v5b tty "" ""
  { ((rc == 2 && nrest == 0)) && clean; } || { no "V5b empty confirmation: rc 2, no restart"; show v5b; }

  # outcomes
  run v7 tty "$TOK" "" FAKE_DOCKER_DROPS=1 FAKE_UNIT_REARMS=1 FAKE_REARM_DELAY=3
  { ((rc == 0 && nrest == 2)) && grep -q 'PERSISTENCE PASS' <<<"$out"; } || { no "V7 Docker drops the jump, unit re-arms after 3 polls: rc 0, PASS, 2 restarts"; show v7; }
  grep -q 'docker-preserves-jump=no' <<<"$out" || { no "V7 phase A (marker absent) must report docker-preserves-jump=no — not confounded by the unit"; show v7; }
  clean || { no "V7 end state clean"; show v7; }
  run v7b tty "$TOK" "" FAKE_DOCKER_DROPS=1 FAKE_UNIT_REARMS=1 FAKE_REARM_DELAY=0
  { ((rc == 0 && nrest == 2)) && grep -q 'docker-preserves-jump=no' <<<"$out"; } || { no "V7b phase A must stay unconfounded even when the unit would re-arm instantly (no marker in phase A)"; show v7b; }
  run v8 tty "$TOK" "" FAKE_DOCKER_DROPS=1
  { ((rc == 1 && nrest == 2)) && grep -q 'PERSISTENCE FAIL' <<<"$out"; } || { no "V8 jump dropped and never re-armed: rc 1, PERSISTENCE FAIL"; show v8; }
  clean || { no "V8 end state clean even on FAIL (trap)"; show v8; }
  run v8b tty "$TOK" "" FAKE_DOCKER_DROPS=1 FAKE_UNIT_REARMS=1 FAKE_REARM_DELAY=9
  { ((rc == 1)) && grep -q 'PERSISTENCE FAIL' <<<"$out"; } || { no "V8b re-arm slower than the bounded wait: rc 1 (the wait is finite)"; show v8b; }
  run v10 tty "$TOK" "" 'PERSIST_WAIT_ARM=x[$(touch pwned)]'
  { ((rc == 2 && nrest == 0)) && [[ ! -e $d/pwned ]]; } || { no "V10 non-numeric PERSIST_WAIT_ARM: rc 2 before anything runs, payload not executed (rule 69)"; show v10; }
  run v9 tty "$TOK" "" FAKE_DOCKER_NEVER=1
  { ((rc == 3 && nrest == 1)); } || { no "V9 daemon never returns: rc 3 after the first restart, no second restart"; show v9; }
  clean || { no "V9 end state clean after an environment error (trap)"; show v9; }
fi

if ((fail)); then exit 1; fi
echo "persistence-gate: PASS (no daemon restart outside verify-persistence 1/1, break-docker gone, sudoers tightened, README; behaviour V1-V10; guards 2/2)"
