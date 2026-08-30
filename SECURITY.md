# PiNode-XMR Security Audit

This document records a security review of the PiNode-XMR web console and its
install/update tooling, and the hardening applied in this fork. It is intended
to help the upstream project identify and remediate the issues.

> Scope of this review: the PHP endpoints under `HTML/`, the Apache
> configuration, the `sudoers` policy, and the shell scripts that consume
> web-set values.
>
> Findings were reproduced and re-tested on a working deployment: Ubuntu 24.04
> with Apache 2.4.58 serving the real endpoint files through `mod_php` 8.3,
> writing to their actual `/home/pinodexmr` and `/var/www/html` paths, with the
> real start-up scripts consuming the results as genuine `pinodexmr` and
> `www-data` accounts. What remains untested is the running node itself —
> systemd was not available in the test environment, and `monerod`/`p2pool` were
> replaced by stubs that record their argv. See **Verification** below.

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

**Assessment:** scoping this grant to a command allow-list is not achievable
without breaking the project's design. `pinodexmr` is the interactive admin
account: the setup menu legitimately calls `sudo` with `apt-get install`,
`sed -i`, `passwd`, `tee`, `mount`, `sfdisk` and `wipefs`. Every one of those
is root-equivalent on its own, so an allow-list containing them would provide
no real boundary — it would only look like one.

**Recommendation:** treat `pinodexmr` as an admin account and put the effort
into keeping the web tier away from it, which is what finding 8 does. If the
device is exposed beyond a trusted LAN, additionally drop `NOPASSWD` so the
setup menu prompts for a password — a usability trade-off for a headless
appliance, and the owner's call.

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

### 8. Broad world-writable recursive permissions — High

The installers run `chmod 777 -R` on `/var/www/html/`, `/home/pinodexmr/*`, and
`~/.bitmonero`.

This was initially rated Medium as a blast-radius concern. Testing showed it is
worse than that: because `chmod 777 -R /home/pinodexmr/*` covers `execScripts/`,
**every** node start-up script becomes world-writable, not just the one the
console manages. An unprivileged local account can append to
`execScripts/moneroPrivate.sh` and get execution as `pinodexmr` the next time
that service starts. That path does not go through the web endpoints at all, so
it bypasses the validation added for finding 1 entirely. It is a second route to
the same outcome, and it also exposed the blockchain data, atomic-swap wallet
material and the RPC credentials in `variables/RPCu.sh` / `RPCp.sh`.

The console only needs write access to `variables/`, the single file
`execScripts/moneroCustomNode.sh`, and `/var/www/html`.

**Remediation (this fork):** added `home/pinodexmr/harden-permissions.sh`, which
grants exactly that through a dedicated `pinodeweb` group shared by the node and
web accounts, with no world access anywhere. The remaining start-up scripts stay
`pinodexmr`-owned and unwritable by the web account; blockchain data, wallet
material and RPC credentials are removed from its reach. The Apache vhost is
reset to root-owned `644`. The script is idempotent; `apache2` must be restarted
afterwards so the web account picks up its new group.

### 9. Log files exposed without authentication — Low

`etc/apache2/sites-enabled/000-default.conf` aliases several logs
(`bitmonero.log`, `p2pool.log`, `debug.log`, `explorer.log`, etc.) with
`Require all granted`. These `Alias` blocks sit outside the
`<Directory '/var/www/html'>` block that carries the `Require valid-user`
directive, so enabling console authentication does not protect them — the logs
stay world-readable over HTTP either way (confirmed against
`000-default-passwordAuthEnabled.conf`).
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
| 5 | `pinodexmr NOPASSWD: ALL` sudo | High | Documented; scoping not viable, see finding |
| 6 | World-writable Apache vhost | Medium | Fixed (`chmod 644`) |
| 7 | Reflected XSS in responses | Medium | Fixed (output escaping) |
| 8 | Recursive `chmod 777` | High | Fixed (`harden-permissions.sh`) |
| 9 | Logs exposed over HTTP | Low | Documented |

New shared helper: `HTML/pinode_security.php` (validation, safe shell-variable
writing, output escaping). All existing endpoint behavior and file formats are
preserved for valid input; invalid input is rejected with HTTP 400 and nothing
is written.

## Verification

Findings were reproduced before fixing and re-tested afterwards against the
real deployment layout — the endpoints served over HTTP, writing to their
actual `/home/pinodexmr` and `/var/www/html` paths, with the node scripts
consuming the results as real `pinodexmr` and `www-data` accounts.

- **Findings 1 and 2** were exploited on the pre-fix code: a POST to
  `save-custom.php` produced an `execScripts` file that ran attacker commands
  when the service started, and a newline payload to `mining-address.php`
  produced a fragment that executed commands when `p2pool.sh` sourced it. The
  same payloads against the current code return HTTP 400 and leave the target
  files byte-identical.
- **Finding 8** was demonstrated by appending to `execScripts/moneroPrivate.sh`
  as an unprivileged local account under the installer's `777` state, and
  confirmed blocked after `harden-permissions.sh`.
- **Finding 6** was confirmed by writing to the vhost as an unprivileged
  account at `777`, then being refused at `644` while Apache could still read
  it.

This was carried out on the real stack: Ubuntu 24.04, Apache 2.4.58,
`mod_php` 8.3.6 under `apache2handler`. The `save-custom.php` payload was
confirmed to still execute against the pre-fix endpoints served by that Apache,
and to be refused with HTTP 400 by the current ones.

The permission model was verified by asking Apache's own PHP what it could
reach after `harden-permissions.sh` and an `apache2` restart: the web account
runs as `www-data` in the `pinodeweb` group, can write
`execScripts/moneroCustomNode.sh` and `variables/`, and cannot write
`execScripts/moneroPrivate.sh`. The node account can still source every
fragment the console wrote.

`tests/security-test.sh` automates the endpoint checks (59 assertions). Run
against the pre-fix code it reports 50 failures; against the current code, 0 —
both before and after the permission model is applied.

    ./tests/security-test.sh http://127.0.0.1

Two issues were found by this testing rather than by reading the code, and are
fixed in the branches above:

1. `tempnam()` creates files as `0600` owned by the web user, so the atomic
   rename left fragments the node could not read. Once permissions were
   tightened, `p2pool.sh` failed to start. `pn_write_file()` now preserves the
   mode of the file it replaces.
2. `execScripts/` only needs to expose `moneroCustomNode.sh` to the web
   account, not the whole directory, so the hardening script grants the single
   file and relies on the in-place write fallback.

### Not yet covered

The reconstruction above exercises the code paths, but the following have **not**
been validated on a real appliance and should be before these changes are relied
on in production:

- **Real systemd units** starting and restarting the node. systemd was not
  available in the test environment, so units were exercised by invoking their
  `ExecStart` command directly.
- **Real `monerod` and `p2pool` binaries** accepting the generated command
  lines. Argv construction was verified with recording stubs; the daemons
  themselves were never launched.
- **A full install/update run** of `ubuntu-install-continue.sh` and
  `update-pinodexmr.sh` with the permission changes in place.
- **`harden-permissions.sh` against an established install** carrying real
  blockchain data, wallets and an existing `.htpasswd`.
- **Other PHP versions.** Testing ran on 8.3 (Apache) and 8.4 (CLI). The syntax
  used is PHP 7.0+ compatible, but the installer pulls the distro `php`
  metapackage, so older releases may ship 7.4.
- **ARM hardware.** Testing was on x86-64. The changes are PHP and shell and
  carry no architecture-specific behaviour, but the project's target boards are
  ARM.

`tests/vm-verify.sh` covers this list end-to-end on a disposable VM or a node
that can be reconfigured. It is destructive to node settings by design.

## Reporting

Security issues in upstream PiNode-XMR should be reported privately to the
maintainers rather than in public issues, to allow deployed nodes time to
update.
