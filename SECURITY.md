# PiNode-XMR Security Audit

This document records a security review of the PiNode-XMR web console and its
install/update tooling, and the hardening applied in this fork. It is intended
to help the upstream project identify and remediate the issues.

> Scope of this review: the PHP endpoints under `HTML/`, the Apache
> configuration, the `sudoers` policy, and the shell scripts that consume
> web-set values. It is a source review only — no live instance was tested.

## Threat model

The web console is served by Apache on the node and, by design, exposes
node-control actions to a browser. HTTP Basic Auth on the console is
**optional and disabled by default** (`htmlPasswordRequired=FALSE`). The
console is therefore frequently reachable by anyone who can reach the node on
port 80 — the local network at minimum, and the public Internet if the node
is port-forwarded or bound to a routable interface.

The web server runs as `www-data`, which is granted a broad set of passwordless
`sudo systemctl` rights, and the node itself runs as `pinodexmr`, which has
`NOPASSWD: ALL`. Any code execution as either account is effectively root on
the device.

---

## Findings

### 1. Unauthenticated remote code execution via `save-custom.php` — Critical

`HTML/save-custom.php` wrote the raw `value` POST parameter into
`/home/pinodexmr/execScripts/moneroCustomNode.sh`, which is executed verbatim
by the `moneroCustomNode.service` systemd unit as the `pinodexmr` user:

```php
$fp = fopen('/home/pinodexmr/execScripts/moneroCustomNode.sh', 'w');
fwrite($fp, "#!/bin/bash\ncd /home/pinodexmr/monero/build/release/bin/\n$VALUE");
```

Anyone able to POST to this endpoint could write an arbitrary shell script and
have it run as `pinodexmr` (→ root via `NOPASSWD: ALL`) the next time the
custom node service started. No authentication, CSRF protection, or input
validation existed.

**Remediation (this fork):** `save-custom.php` now validates the value through
`pn_custom_monero_command()`, which requires the command to launch `monerod`,
forbids all shell metacharacters (`; & | \` $ ( ) < > \ ' " ! * ? [ ] # ~`),
restricts the character set to what monerod flags need, and rejects multi-line
input. This blocks command chaining/substitution while preserving the intended
"custom monerod flags" feature. The feature remains powerful and should be
gated behind authentication (see finding 4).

### 2. Command injection via shell-variable setter endpoints — Critical

Every value-setter endpoint (`mining-address.php`, `monero-rpc-port.php`,
`i2p-address.php`, `speed_up.php`, `in-peers.php`, `ethJsonRpc.php`, and the
rest) wrote unvalidated input into a `.sh` fragment as an **unquoted**
assignment:

```php
fwrite($fp, "#!/bin/bash\nMINING_ADDRESS=$VALUE");
```

Those fragments are later `source`d by the node start scripts (e.g.
`execScripts/p2pool.sh` does `. /home/pinodexmr/variables/mining-address.sh`
and then `--wallet $MINING_ADDRESS`). Because the value was neither validated
nor quoted, a payload containing a newline or shell metacharacters injected
arbitrary commands that ran as `pinodexmr` when the fragment was sourced — a
second unauthenticated path to root.

**Remediation (this fork):** all setter endpoints now validate input against
strict allow-lists (numeric ranges for ports/peers/threads/intensity/rates,
Base58 length checks for Monero addresses, URL/host validation for the ETH RPC
node and I2P address, an explicit whitelist for the P2Pool chain flag), and
write values via `pn_write_shell_var()`, which single-quotes and escapes the
value so it cannot break out of its assignment even if a validator is later
loosened. Shared logic lives in `HTML/pinode_security.php`.

### 3. Mining-address substitution (reward theft) — High

`mining-address.php` let an unauthenticated caller change the P2Pool payout
wallet (`MINING_ADDRESS`). An attacker on the network could silently redirect
all mining rewards to their own address. Even setting aside code execution,
this is a direct financial-loss vector.

**Remediation (this fork):** the address is now validated as a well-formed
Base58 Monero address of the correct length. This does not solve the
underlying authorization gap — the endpoint should require authentication
(finding 4) — but it removes the injection vector and rejects malformed input.

### 4. Console actions lack authentication and CSRF protection — High

`runScript.php` exposes node lifecycle control (start/stop/enable services,
`shutdown`, `reboot`, `monerod-kill`, swap enable/disable) via simple
`GET ?function=...` calls, and every setter endpoint accepts state-changing
POSTs. With Basic Auth off by default, these are fully unauthenticated; even
with Basic Auth on, there is no CSRF token, so a malicious web page viewed by
an authenticated operator could drive the console cross-site.

`runScript.php` itself uses a fixed `switch` allow-list, so it is not
injectable, and it was left functionally intact.

**Recommendation (not changed here to avoid breaking behavior):**
 - Enable HTTP Basic Auth by default (ship `htmlPasswordRequired=TRUE` and the
   password-protected Apache vhost), or bind the console to `127.0.0.1`/an
   overlay interface only.
 - Add a per-session CSRF token to all state-changing requests.
 - Prefer POST (not GET) for actions with side effects.

### 5. Overly broad `sudo` grants — High

`etc/sudoers` contains:

```
pinodexmr ALL=NOPASSWD: ALL
```

This gives the node's service account unrestricted passwordless root, which is
what turns any of the code-execution findings above into full device
compromise. The `www-data` grant is scoped to specific `systemctl` unit
commands (good), but is still broad enough to stop/disable node services
unauthenticated.

**Recommendation (not changed here — needs owner validation against the setup
flow):** replace `pinodexmr NOPASSWD: ALL` with a scoped command list covering
only the specific scripts/units the node genuinely needs, mirroring the
approach already used for `www-data`.

### 6. World-writable Apache configuration — Medium

The install/update/setup scripts set the root-owned Apache vhost
world-writable:

```
sudo chmod 777 /etc/apache2/sites-enabled/000-default.conf
```

Any local user (including a compromised `www-data`) could rewrite the vhost —
for example to add aliases exposing sensitive files or to disable the auth
block — and have it take effect on the next Apache reload.

**Remediation (this fork):** changed to `chmod 644` in `update-pinodexmr.sh`,
`home/pinodexmr/setup.sh`, and `ubuntu-install-continue.sh`. Apache reads the
config as root and does not need write access.

### 7. Reflected XSS in endpoint responses — Medium

The setter endpoints echoed the submitted value back into the HTTP response
unescaped (e.g. `echo "Mining address set to $VALUE";`). Combined with the
lack of validation, this allowed reflected XSS.

**Remediation (this fork):** all responses now pass values through
`htmlspecialchars()` via `pn_h()`. Input validation additionally rejects
values that could carry markup.

### 8. Broad world-writable recursive permissions — Medium (recommendation only)

The installers run `chmod 777 -R` on `/var/www/html/`, `/home/pinodexmr/*`, and
`~/.bitmonero`. `www-data` needs write access to a few directories (the
`variables/`, `execScripts/`, and status `.txt` files), but recursive `777`
across the home directory widens the blast radius of any web-tier compromise.

**Recommendation (not changed here — needs careful testing):** grant the
minimum needed via group ownership (e.g. add `www-data` to a shared group and
`chmod 775`/`g+w` only on the specific writable directories) rather than
world-writable recursion.

### 9. Log files exposed without authentication — Low

`etc/apache2/sites-enabled/000-default.conf` aliases several logs
(`bitmonero.log`, `p2pool.log`, `debug.log`, `explorer.log`, etc.) with
`Require all granted`, so they are readable even when console auth is enabled.
`debug.log` in particular can contain operational detail useful to an
attacker. Consider placing log access behind the same auth as the console, or
not exposing `debug.log` over HTTP.

---

## Summary of changes in this fork

| # | Finding | Severity | Status in fork |
|---|---------|----------|----------------|
| 1 | RCE via `save-custom.php` | Critical | Fixed (strict command validation) |
| 2 | Command injection in setter endpoints | Critical | Fixed (validation + safe writes) |
| 3 | Mining-address reward theft | High | Injection fixed; needs auth |
| 4 | No auth / CSRF on actions | High | Documented; recommend auth+CSRF |
| 5 | `pinodexmr NOPASSWD: ALL` sudo | High | Documented; recommend scoping |
| 6 | World-writable Apache vhost | Medium | Fixed (`chmod 644`) |
| 7 | Reflected XSS in responses | Medium | Fixed (output escaping) |
| 8 | Recursive `chmod 777` | Medium | Documented; recommend tightening |
| 9 | Logs exposed over HTTP | Low | Documented |

New shared helper: `HTML/pinode_security.php` (validation, safe shell-variable
writing, output escaping). All existing endpoint behavior and file formats are
preserved for valid input; invalid input is rejected with HTTP 400 and nothing
is written.

## Reporting

Security issues in upstream PiNode-XMR should be reported privately to the
maintainers rather than in public issues, to allow deployed nodes time to
update.
