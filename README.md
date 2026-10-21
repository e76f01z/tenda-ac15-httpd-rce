# Tenda AC15: pre-auth root RCE via admin password overwrite in the fast-setup handler

While reverse engineering the Tenda AC15 firmware (V15.03.05.18_multi_TD01, TRX → SquashFS on the Broadcom ARM SDK, kernel 2.6.36.4brcmarm), I found a chain in the `httpd` binary that turns two unauthenticated POSTs into root command execution on default-state routers, plus a second, memory-corruption route for routers that are already configured. The vulnerable code is Tenda's `httpd` (the goform dispatch layer), which ships in basically every Tenda home router of that era, so this probably affects more of the AC-line fleet than just the AC15. Firmware V15.03.05.18 on the AC15 is the only build I verified, so that's what this write-up sticks to.

## TL;DR

Every request to `httpd` passes through `R7WebsSecurityHandler` (0x2F194), which decides authentication with a giant `strncmp` allowlist. Any URI matching one of those prefixes is let through **before any credential check** — and `/goform/fast_setting*` is on that list.

The `form_fast_setting_wifi_set` handler (0x6723C) takes the `loginPwd` POST parameter, writes it to flash config with `SetValue("sys.userpass", v16)`, and then calls `sub_2ED88(1)` — which reloads the live `g_Pass` global straight from `sys.userpass`. One unauthenticated POST therefore overwrites the admin password **immediately and persistently**. No memory corruption, no ROP, deterministic.

With the new password, `/login/Auth` hands out a session cookie, and `/goform/exeCommand` (0x7BA84) pastes the `cmdinput` parameter into `doSystemCmd("%s", s)` — `system()` as root — echoing `/tmp/cmdTmp.txt` back in the response body. That is a built-in web shell.

No credentials are needed at any point. The fast-setup forms are reachable on every router whose admin password is unset (factory default) or the default `admin`; configured routers fall back to the cookie-parser overflow described further down.

```
[no creds] GET /main.html                     -> R7WebsSecurityHandler allowlist walk
[no creds] POST /goform/fast_setting_wifi_set loginPwd=<random>
                                              -> SetValue("sys.userpass") + g_Pass reload
[attacker] POST /login/Auth admin/<password>  -> Set-Cookie: password=...
[root]     POST /goform/exeCommand cmdinput   -> doSystemCmd -> stdout in response
```

## Background: how httpd works

The firmware's web server is a single root daemon (`/bin/httpd`, ~1970 functions, non-PIE, load base 0x8000, ASLR-off 2.6.36 kernel — every address static). It serves the webroot, and the `/goform/<name>` URI space is dispatched through a registered function-pointer table (~115 `form*` handlers). Parameters are read with `httpGetEnv` (sub_2BABC) from the query string and POST body, URL-decoded.

`R7WebsSecurityHandler` runs in front of everything. Its guard is a long `&&` chain of `strncmp` prefix checks; if the URI matches none of them, the auth machinery runs (cookie check against `g_Pass` + IP + `cookie_suffix`). If it matches any, the function returns 0 immediately and the request proceeds unauthenticated. The effective pre-auth allowlist:

- `/goform/fast_setting*` (setup wizard: wifi, pppoe, internet)
- `/goform/telnet` — but only while `g_Pass` is empty or `YWRtaW4=` (base64 `admin`)
- `/goform/ate`, `/goform/InsertWhite`, `/goform/getWanConnectStatus`, `/goform/getProduct`, `/goform/getRebootStatus`
- static assets (`/public/`, `/lang/`, images, js, css), `/redirect.html`, `/yun_safe.html`, `/kns-query`, `/wdinfo.php`

`getProduct` is the free fingerprinting oracle: it returns product name and firmware version with no auth.

## Bug 1: unauthenticated admin password overwrite (CWE-284)

From `form_fast_setting_wifi_set` (0x6723C):

```c
v16 = httpGetEnv(req, "loginPwd", "");   // fully attacker-controlled
SetValue("sys.userpass", v16);           // persisted to flash
sub_2ED88(1);                            // and reloaded into the live global:
    // sub_2ED88: GetValue("sys.username", g_User);
    //            GetValue("sys.userpass", &g_Pass);
```

The handler then commits the config. From this point the login comparison `strcmp(src, &g_Pass)` in the `/login/Auth` path accepts the attacker's value, and because the value is in flash it survives reboots — the takeover is also persistence. The same handler doubles as the chain's transport: it is reachable pre-auth precisely because the setup wizard has to be.

Side effect worth knowing: the same request also writes the `ssid`/`wrlPassword`/`timeZone` parameters (all empty by default) into the wireless config, so on a *live* router this form visibly resets WiFi settings. On default-state devices it is harmless.

## Bug 2: command execution in the diagnosis form (CWE-78)

`formexeCommand` (0x7BA84), registered for `/goform/exeCommand`:

```c
src = httpGetEnv(req, "cmdinput", "");
strcpy(s, src);                          // s[512] — see the bonus section
sub_7B700(s1, s);                        // first word
...
doSystemCmd("%s > /tmp/cmdTmp.txt", s);  // default branch: raw system()
...
fgets(v4, 4096, stream) ...              // echo the file back into the response
```

Any command that is not one of the six special-cased words is passed to `system()` verbatim, and stdout comes back in the HTTP response — the handler is its own exfiltration channel. This form needs a session, which Bug 1 provides (or default creds, or Bug 3 below).

## Bonus: the memory-corruption surface on the same binary

The auth gate itself is exploitable when the router is already configured, which makes the "needs auth" limitation of Bug 2 mostly cosmetic:

- **`R7WebsSecurityHandler` cookie overflow (CVE-2018-5767, unpatched in this build)** — `sscanf(cookie, "%*[^=]=%[^;];*", v34)` into a 128-byte stack buffer, unbounded, on every protected request before any auth decision. Saved LR sits 0x1CC (460) bytes above `v34`; a ~461-byte cookie value gives PC control. Public ROP chains for this CVE apply as-is.
- **`form_fast_setting_wifi_set` `ssid` double `strcpy`** into `char[64]` buffers — LR at +0x7C (124 bytes) from the first buffer; same pre-auth form as Bug 1.
- **Same function, `timeZone` `sscanf`** — `sscanf(v15+1, "%[^:]:%s", nptr, v6)` into two 4-byte buffers, unbounded, 0x154 bytes to LR.
- **`formSetFirewallCfg`** — `if (strlen(src) > 3) strcpy(dest[4], firewallEn)`, 0x38 bytes to LR.
- **`formSetPPTPServer`** — `sscanf(startIp, "%[^.].%[^.].%[^.].%s", char[8], char[8], ...)` unbounded.
- **`formSetSpeedWan`** — `sprintf(s[32], "{\"errCode\":%d,\"speed_dir\":%s}", speed_dir)`.
- **`formSetClientState`** — `sprintf(s[512], "%d;%s;%s;%s", deviceId+limitSpeed+limitSpeedUp)` concatenation overflow.
- **`formSetPPTPUserList`** — `strcpy(&v17[64 * v35++], token)` with unbounded slot count and token length.
- **`formSetIptv`** — `doSystemCmd("nvram set adv.iptv.stballvlans=\"%s\"", list)` double-quote breakout; **`formSetSambaConf`** — `doSystemCmd("...string_info=%s", usbName)` injection. Both single POSTs once authenticated.

The PoC sticks to the Bug1→Bug2 chain because it needs no corruption; the cookie overflow (CVE-2018-5767 route) is the fallback for already-configured devices.

## Chaining

Allowlist passed, password overwritten, session granted, shell command executed as root with output returned. A working PoC is in [`tenda-ac15-poc.go`](tenda-ac15-poc.go):

```
go build tenda-ac15-poc.go
./tenda-ac15-poc -host 192.168.0.1 -cmd "cat /etc/passwd"
zmap -p 80 -q | ./tenda-ac15-poc -port 80 -workers 50      # stdin streaming mode
```

It generates a random 16-char admin password per target, fires the three requests, and classifies the answer: the command's stdout means full chain success; a `login.html` redirect means the takeover failed (configured device — see the bonus section); `{"errCode":...}` means authenticated but the command produced no output. Fingerprint candidates first with the free pre-auth oracle: `GET /goform/getProduct` should return the AC15 product JSON.

## Impact

- Bug 1 + Bug 2 chained: unauthenticated root RCE on any default-state AC15, deterministic, two POSTs, no corruption. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8.
- Bug 2 alone is an authenticated web shell; with the cookie-parser overflow it becomes pre-auth for configured devices too.
- The management interface listens on LAN port 80 by default (`lan.webport=80`); WAN exposure applies when remote web management is enabled. The fast-setup allowlist forms and `getProduct` answer on WAN as well when exposed.

## Mitigation / what the fix should look like

- Never let a wizard form write `sys.userpass` without an authenticated session; `sub_2ED88(1)` reloading the live password global from a pre-auth handler is the core defect.
- Remove `exeCommand` (or gate it behind a factory/mfg mode and pass commands as argv, never through a shell).
- Bound every `httpGetEnv` result at the copy site: the `strcpy`/`sprintf`/`sscanf` sinks listed in the bonus section all take attacker-length strings into fixed stack objects.
- Replace the `strncmp` prefix allowlist with exact matches; compile PIE and ship an ASLR-enabled kernel so the corruption bugs stop being deterministic.

## Notes

- Verified by static analysis of the extracted V15.03.05.18_multi_TD01 SquashFS (IDA database on `bin/httpd`; all addresses in this write-up are IDA vaddrs with image base 0x8000: `R7WebsSecurityHandler` 0x2F194, `form_fast_setting_wifi_set` 0x6723C, `sub_2ED88` 0x2ED88, `formexeCommand` 0x7BA84, `TendaTelnet` 0x4FB88).
- Bonus findings: `TendaTelnet` unconditionally spawns `telnetd` as root and is pre-auth while `g_Pass` is empty/default — free shell on unconfigured devices without any corruption.
- Affected surface recap: Tenda's `httpd` goform layer ships across the AC-line; only AC15 V15.03.05.18 was verified here.
