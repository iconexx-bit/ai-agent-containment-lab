#!/usr/bin/env bash
# bootstrap.sh — run ONCE on ai-sec-ubuntu. Idempotent.
#   ./bootstrap.sh            install
#   ./bootstrap.sh --check    verify install without changing anything
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK=0; [[ "${1:-}" == "--check" ]] && CHECK=1
rc=0
ok()   { printf '  %-34s ok\n' "$1"; }
warn() { printf '  %-34s WARN: %s\n' "$1" "$2"; }
bad()  { printf '  %-34s FAIL: %s\n' "$1" "$2"; rc=1; }
do_or_check() { [[ $CHECK -eq 1 ]] && return 1 || return 0; }

echo "== range-lab bootstrap =="

# 1. executables --------------------------------------------------------------
if do_or_check; then chmod +x "$ROOT"/scripts/*.sh "$ROOT/bootstrap.sh"; fi
ok "scripts executable"

# 2. config -------------------------------------------------------------------
if [[ ! -f "$ROOT/range.env" ]]; then
  if do_or_check; then
    cp "$ROOT/range.env.example" "$ROOT/range.env"; chmod 600 "$ROOT/range.env"
    warn "range.env" "created from example — SET WAZUH_PASS BEFORE PROBING"
  else
    bad "range.env" "missing"
  fi
else
  ok "range.env"
  grep -q 'CHANGE_ME' "$ROOT/range.env" && warn "range.env" "still contains CHANGE_ME"
fi

# 3. dependencies -------------------------------------------------------------
missing=""
for b in docker jq dig iptables just python3; do
  command -v "$b" >/dev/null 2>&1 || missing="$missing $b"
done
if [[ -n "$missing" ]]; then
  bad "dependencies" "missing:$missing"
  echo "      sudo apt-get install -y jq dnsutils iptables xmlstarlet libxml2-utils"
  echo "      curl -fsSL https://just.systems/install.sh | bash -s -- --to ~/.local/bin"
else
  ok "dependencies"
fi

# 4. sudoers ------------------------------------------------------------------
if [[ -f /etc/sudoers.d/range-lab ]]; then
  ok "sudoers.d/range-lab"
else
  if do_or_check; then
    if sudo visudo -c -f "$ROOT/sudoers.d/range-lab" >/dev/null 2>&1; then
      sudo install -m 0440 -o root -g root "$ROOT/sudoers.d/range-lab" /etc/sudoers.d/range-lab
      sudo groupadd -f rangelab
      sudo usermod -aG rangelab "$USER"
      warn "sudoers.d/range-lab" "installed — LOG OUT AND BACK IN for group to apply"
    else
      bad "sudoers.d/range-lab" "visudo syntax check failed — NOT installed"
    fi
  else
    bad "sudoers.d/range-lab" "not installed"
  fi
fi

# 5. killswitch persistence ---------------------------------------------------
if [[ -x /usr/local/bin/range-killswitch-arm.sh ]] \
   && systemctl is-enabled range-killswitch.service >/dev/null 2>&1; then
  ok "killswitch persistence"
else
  if do_or_check; then
    sudo install -m 0755 "$ROOT/scripts/range-killswitch-arm.sh" /usr/local/bin/
    sudo install -m 0644 "$ROOT/systemd/range-killswitch.service" /etc/systemd/system/
    sudo mkdir -p /var/lib/range-lab
    sudo systemctl daemon-reload
    sudo systemctl enable range-killswitch.service >/dev/null 2>&1
    ok "killswitch persistence (installed + enabled)"
  else
    bad "killswitch persistence" "unit not installed/enabled"
  fi
fi

# 6. probe image cache --------------------------------------------------------
IMG=$(grep -E '^PROBE_IMAGE=' "$ROOT/range.env" 2>/dev/null | cut -d= -f2)
IMG="${IMG:-curlimages/curl:8.11.0}"
if docker image inspect "$IMG" >/dev/null 2>&1; then
  ok "probe image cached"
else
  if do_or_check && docker pull -q "$IMG" >/dev/null 2>&1; then
    ok "probe image pulled"
  else
    bad "probe image" "$IMG not cached — egress check will be a false negative"
  fi
fi

# 7. syntax -------------------------------------------------------------------
synfail=0
for f in "$ROOT"/scripts/*.sh; do bash -n "$f" 2>/dev/null || { echo "      syntax: $f"; synfail=1; }; done
[[ $synfail -eq 0 ]] && ok "shell syntax" || bad "shell syntax" "see above"

echo
if [[ $rc -eq 0 ]]; then
  echo "BOOTSTRAP OK -> next: just preflight"
else
  echo "BOOTSTRAP INCOMPLETE — fix the FAIL lines above"
fi
exit $rc
