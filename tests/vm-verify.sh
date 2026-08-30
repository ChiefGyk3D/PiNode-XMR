#!/bin/bash
#
# vm-verify.sh - End-to-end verification of the PiNode-XMR security hardening
# on a real node or a disposable VM.
#
#   sudo ./tests/vm-verify.sh
#
# WARNING: destructive to node configuration. It overwrites the mining address,
# ports, peer limits, chain selection and custom start command with test values,
# and applies the least-privilege permission model. Intended for a throwaway VM
# or a node you are happy to reconfigure afterwards.
#
# Covers the parts that cannot be exercised off-appliance: Apache with mod_php
# (in particular www-data's effective group membership, which the permission
# model depends on), real systemd units, and the actual node start-up path.
#
# Exit status 0 = every check passed.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_ROOT=/var/www/html
VARS=/home/pinodexmr/variables
EXEC=/home/pinodexmr/execScripts
BASE="${BASE:-http://127.0.0.1}"

# The console requires authentication by default. Supply credentials with
# PINODE_USER / PINODE_PASS, or let the script read the generated pair that
# enable-web-auth.sh leaves in /root/pinode-web-credentials.
CREDS_FILE=/root/pinode-web-credentials
PINODE_USER="${PINODE_USER:-}"
PINODE_PASS="${PINODE_PASS:-}"
if [ -z "$PINODE_PASS" ] && [ -r "$CREDS_FILE" ]; then
  PINODE_USER="${PINODE_USER:-$(awk '/^username:/{print $2}' "$CREDS_FILE")}"
  PINODE_PASS="$(awk '/^password:/{print $2}' "$CREDS_FILE")"
fi
AUTH=()
[ -n "$PINODE_PASS" ] && AUTH=(-u "${PINODE_USER:-pinodexmr}:$PINODE_PASS")
CURL=(curl -fsS "${AUTH[@]+"${AUTH[@]}"}")

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
sec()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }

sec "Environment"
. /etc/os-release 2>/dev/null
echo "  OS:      ${PRETTY_NAME:-unknown} ($(uname -m))"
echo "  Apache:  $(apache2 -v 2>/dev/null | head -1 | sed 's/.*: //')"
echo "  PHP:     $(php -v 2>/dev/null | head -1 | cut -d' ' -f1-2)"
echo "  systemd: $([ -d /run/systemd/system ] && echo yes || echo no)"
for u in pinodexmr www-data; do
  id "$u" >/dev/null 2>&1 || { echo "Missing user '$u' - is this a PiNode install?" >&2; exit 1; }
done

sec "Deploy hardened endpoints"
cp "$REPO"/HTML/*.php "$WEB_ROOT"/ && ok "endpoints copied to $WEB_ROOT" || bad "copy failed"
php -l "$WEB_ROOT/pinode_security.php" >/dev/null 2>&1 && ok "pinode_security.php parses on this PHP" || bad "pinode_security.php failed to parse"

sec "Endpoint suite (current permissions)"
"$REPO/tests/security-test.sh" "$BASE" > /tmp/vm_pre.log 2>&1
tail -2 /tmp/vm_pre.log | head -1
grep -q "ALL CHECKS PASSED" /tmp/vm_pre.log && ok "suite passes before hardening" || bad "suite failed before hardening (see /tmp/vm_pre.log)"

sec "Apply least-privilege permissions"
bash "$REPO/home/pinodexmr/harden-permissions.sh" > /tmp/vm_harden.log 2>&1 \
  && ok "harden-permissions.sh completed" || bad "harden-permissions.sh failed (see /tmp/vm_harden.log)"
systemctl restart apache2 2>/dev/null || service apache2 restart 2>/dev/null || apache2ctl -k restart 2>/dev/null
sleep 2
RC=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]+"${AUTH[@]}"}" -H 'X-PiNode-CSRF: 1' \
  -X POST "$BASE/runScript.php" --data-urlencode 'function=x' 2>/dev/null)
# 400 is the expected answer for an unknown selector; 401 means our credentials
# were refused, and 000 means nothing is listening.
case "$RC" in
  400|200) ok "console still serving after apache restart (HTTP $RC)" ;;
  401)     bad "console refused our credentials after restart - check $CREDS_FILE" ;;
  000)     bad "console unreachable after apache restart" ;;
  *)       bad "console answered HTTP $RC after apache restart" ;;
esac

sec "Web account's effective identity under Apache"
cat > "$WEB_ROOT/_vmcheck.php" <<'PHP'
<?php
$u = posix_getpwuid(posix_geteuid());
$g = array_map(function ($x) { $r = posix_getgrgid($x); return $r['name']; }, posix_getgroups());
echo json_encode(['user' => $u['name'], 'groups' => $g,
  'can_write_custom' => is_writable('/home/pinodexmr/execScripts/moneroCustomNode.sh'),
  'can_write_private' => is_writable('/home/pinodexmr/execScripts/moneroPrivate.sh'),
  'can_write_vars' => is_writable('/home/pinodexmr/variables')]);
PHP
chmod 644 "$WEB_ROOT/_vmcheck.php" 2>/dev/null
J=$("${CURL[@]}" "$BASE/_vmcheck.php" 2>/dev/null); rm -f "$WEB_ROOT/_vmcheck.php"
echo "  $J"
echo "$J" | grep -q '"groups":\[[^]]*pinodeweb' && ok "web account is in the pinodeweb group" \
  || bad "web account did NOT pick up pinodeweb - apache restart may not have taken effect"
echo "$J" | grep -q '"can_write_custom":true'  && ok "can write moneroCustomNode.sh (feature intact)" || bad "cannot write moneroCustomNode.sh - custom node feature broken"
echo "$J" | grep -q '"can_write_private":false' && ok "cannot write moneroPrivate.sh (escalation blocked)" || bad "CAN write moneroPrivate.sh - still vulnerable"
echo "$J" | grep -q '"can_write_vars":true'    && ok "can write variables/ (settings intact)" || bad "cannot write variables/ - settings broken"

sec "Endpoint suite (hardened permissions)"
"$REPO/tests/security-test.sh" "$BASE" > /tmp/vm_post.log 2>&1
tail -2 /tmp/vm_post.log | head -1
grep -q "ALL CHECKS PASSED" /tmp/vm_post.log && ok "suite passes after hardening" || bad "suite failed after hardening (see /tmp/vm_post.log)"

sec "Node account can consume what the console wrote"
for f in mining-address monero-port p2poolChain; do
  [ -f "$VARS/$f.sh" ] || { skip "$f.sh not present"; continue; }
  if su pinodexmr -s /bin/bash -c ". '$VARS/$f.sh'" 2>/dev/null; then ok "pinodexmr can source $f.sh"
  else bad "pinodexmr CANNOT source $f.sh - node will fail to start"; fi
done

sec "systemd units"
if [ -d /run/systemd/system ]; then
  for unit in moneroCustomNode monerod-prune; do
    if systemctl cat "$unit.service" >/dev/null 2>&1; then
      systemd-analyze verify "$unit.service" >/dev/null 2>&1 \
        && ok "$unit.service verifies" || bad "$unit.service failed verification"
    else skip "$unit.service not installed"; fi
  done
  echo
  echo "  Manual step - start each node type from the web UI and confirm it comes up:"
  echo "    systemctl status moneroPrivate p2pool moneroCustomNode"
else
  skip "systemd not running - cannot verify units here"
fi

sec "Authentication boundary"
if [ -n "$PINODE_PASS" ]; then
  for u in nodeControl.html mining-address.php runScript.php; do
    c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$u")
    { [ "$c" = "401" ] || [ "$c" = "403" ]; } && ok "$u refused without credentials (HTTP $c)" \
      || bad "$u served unauthenticated (HTTP $c)"
  done
  c=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/nodeControl.html")
  [ "$c" = "200" ] && ok "console reachable with credentials" || bad "console refused credentials (HTTP $c)"
  H=/etc/apache2/.htpasswd
  [ -f "$H" ] && { M=$(stat -c '%a' "$H"); [ "$M" = "640" ] && ok "htpasswd is 0640" || bad "htpasswd is $M, expected 640"; }
else
  skip "authentication not enabled - run home/pinodexmr/enable-web-auth.sh"
fi

sec "Apache config permissions"
V=/etc/apache2/sites-enabled/000-default.conf
if [ -f "$V" ]; then
  M=$(stat -c '%U:%G %a' "$V"); echo "  $V -> $M"
  [ "$M" = "root:root 644" ] && ok "vhost is root-owned 644" || bad "vhost is $M, expected root:root 644"
  su www-data -s /bin/bash -c "test -w '$V'" 2>/dev/null && bad "vhost is writable by www-data" || ok "vhost not writable by www-data"
else skip "vhost not found"; fi

printf '\n\033[1m---------------------------------------\033[0m\n'
printf 'passed: \033[32m%s\033[0m  failed: \033[31m%s\033[0m  skipped: \033[33m%s\033[0m\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -eq 0 ]; then echo "VM VERIFICATION PASSED"; exit 0; else echo "FAILURES PRESENT"; exit 1; fi
