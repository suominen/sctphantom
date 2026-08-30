---
title: "SCTPhantom — SCTP ASCONF transport use-after-free"
description: "Linux kernel SCTP ASCONF DEL-IP use-after-free (CVE-2026-64564, SCTPhantom) — remote-triggerable transport UAF, local privilege escalation and container-to-host escape — distro patch status tracker"
layout: "single"
date: 2026-08-10
lastmod: 2026-08-30
cover:
  image: "sctphantom-tracker.png"
  alt: "SCTPhantom — Linux kernel SCTP ASCONF transport use-after-free tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-64564 |
| Alias | `SCTPhantom` (the name the [write-up][writeup] uses) |
| Component | Kernel: SCTP ASCONF DEL-IP processing — reuse of the ASCONF chunk's own cached transport (`sctp_process_asconf` / `sctp_process_asconf_param`, `net/sctp/sm_make_chunk.c`) |
| Type | Use-after-free of an `sctp_transport`. A single ASCONF carrying `[Address Parameter L][DEL-IP L][DEL-IP 0.0.0.0]` frees `asconf->transport` (via `sctp_assoc_rm_peer()`, RCU-deferred), then the wildcard DEL-IP reuses the dangling pointer in `sctp_assoc_set_primary()` / `sctp_assoc_del_nonprimary_peers()`, planting freed memory into `asoc->peer.primary_path` / `active_path` |
| Impact | Kernel heap UAF: a reproducible oops/panic (**DoS**), and per the discoverers a **local privilege escalation to root** and **container-to-host escape**. The chunk is processed in the receive/state-machine path, so it is reachable by any SCTP peer that completes an association with the ADD-IP (ASCONF) extension negotiated |
| Upstream fix | [`9b2854f86f0b`][fix] (*sctp: don't free the ASCONF's own transport in DEL-IP processing*); first in **v7.2-rc5** |
| Introduced | [`42e30bf3463c`][intro] in **v2.6.25** (2008) — the ASCONF DEL-IP handler has cached-and-reused the chunk's transport since SCTP ADD-IP support landed, so **essentially every SCTP-capable kernel is in-window** |
| Affected window | **2.6.25 through 7.1** without the backport (and 7.2 before `-rc5`). Fixed in **v7.2-rc5** and the **6.1 / 5.15 / 5.10 / 6.6 / 6.12 / 6.18 / 7.1** stable backports — every maintained upstream kernel line now carries the fix (per-branch *First fixed* below); distro kernels still need to adopt it independently |
| Discoverer | Corvus AI (Tencent Zhuque Lab / TencentOS Security Team) |
| Public disclosure | 2026-08-06 ([Tencent Matrix write-up][writeup]) |
| Public PoC | None public. The researchers report internal PoCs demonstrating local privilege escalation and container-to-host escape |
| KEV / EPSS / CVSS | Two scores exist. **Kernel CNA:** CVSS 3.1 **9.8 CRITICAL** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), scoring the bug from a *remote SCTP peer*. **Discoverers:** CVSS 4.0 **8.5 HIGH** (`AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/…`), scoring the *demonstrated local privilege-escalation* primitive. Not in KEV; EPSS **1.48%** (72nd percentile). See *Scoring* below |
| Reachability | An established SCTP association with the **ADD-IP / ASCONF** extension negotiated and a valid AUTH chunk. Both can be enabled **per socket** (`SCTP_ASCONF_SUPPORTED` / `SCTP_AUTH_SUPPORTED`) with no privilege, so a local attacker turns them on and supplies the AUTH chunk itself — neither `net.sctp.addip_enable` nor `net.sctp.addip_noauth_enable` gates the local path (per the discoverers; confirmed in the kernel setsockopt handlers, which apply no capability check). The sysctls bound only the *remote* surface. On most distributions the `sctp` module is **not loaded until an application uses SCTP** — see *Detection* and *Mitigation* |
{.summary}

> :information_source: **Two vantage points, one bug.** The kernel CNA
> scores SCTPhantom as **network-reachable** (`AV:N`): a remote peer that
> completes an SCTP association with ADD-IP negotiated sends the crafted
> ASCONF, and nothing on the target needs local access. The discoverers
> score it **locally** (`AV:L`) because what they *demonstrated* is a
> privilege-escalation and container-escape primitive built on the same
> use-after-free. Both are correct at different layers — the trigger is a
> received packet; the weaponised impact shown is local root. Treat any
> host that terminates untrusted SCTP associations as remotely reachable,
> and any multi-tenant host as exposed to local escalation.

## How the exploitation chain works

SCTP is multi-homed: one association can span several peer IP addresses,
each represented by an `sctp_transport`. The **ADD-IP** extension (RFC 5061)
lets a peer add and remove those addresses at runtime by sending **ASCONF**
chunks, processed in the receive path by `sctp_process_asconf()`.

`sctp_process_asconf()` caches the transport the chunk arrived on in
`asconf->transport` (set once in `sctp_rcv()`). When an ASCONF is instead
located through its **Address Parameter** by `__sctp_rcv_asconf_lookup()`,
that cached transport corresponds to the *Address Parameter*, which **need
not be the packet's source address**.

`sctp_process_asconf_param()` already refuses a DEL-IP aimed at the packet
*source* address (the ADD-IP D8 rule, `SCTP_ERROR_DEL_SRC_IP`) — but nothing
protected `asconf->transport` itself. A single ASCONF can carry, in order:

```
[Address Parameter L]  [DEL-IP L]  [DEL-IP 0.0.0.0]
```

where `L` differs from the source address:

1. **`[Address Parameter L]`** selects transport `L` as `asconf->transport`.
2. **`[DEL-IP L]`** passes the D8 source-address check (the source isn't
   `L`) and calls `sctp_assoc_rm_peer()` on transport `L` — the very
   transport `asconf->transport` still points at — **freeing it**
   (RCU-deferred).
3. **`[DEL-IP 0.0.0.0]`** (wildcard) then reuses the now-dangling
   `asconf->transport`: `sctp_assoc_set_primary()` dereferences the freed
   object (`->ipaddr`, `->state`) and plants the dangling pointer into
   `asoc->peer.primary_path` / `active_path`, while
   `sctp_assoc_del_nonprimary_peers()` removes every *real* transport,
   keeping only the pointer that is no longer on the list. The association
   is left with `transport_count == 0` and `primary_path` / `active_path`
   pointing at freed memory.

From there the freed `sctp_transport` is a classic reclaim-and-reuse
primitive: a following dereference of the dangling `primary_path` faults
(the oops/panic path), or, with heap grooming, the freed slot is reclaimed
by attacker-controlled data for a read/write primitive — which the
[write-up][writeup] escalates to root and out of a container.

The fix, [`9b2854f86f0b`][fix], rejects a DEL-IP that targets the transport
the ASCONF is being processed against, mirroring the existing
source-address guard, so the wildcard branch can never reuse a freed
transport.

> :warning: Because the introducing commit landed in **v2.6.25 (2008)**,
> this is **not** a recent-regression bug: there is no "too old to be
> affected" kernel. Any kernel with SCTP ADD-IP support, from 2.6.25 up to
> the fixed point releases below, is in-window. A kernel is safe only by
> carrying the [`9b2854f86f0b`][fix] fix — not by being old.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`42e30bf3463c`][intro] | Introduced | ASCONF DEL-IP support (**v2.6.25**, 2008) — `sctp_process_asconf()` caches the chunk's transport and the DEL-IP path can free it while the wildcard branch still holds the pointer. |
| [`9b2854f86f0b`][fix] | Fixed | *sctp: don't free the ASCONF's own transport in DEL-IP processing* — rejects a DEL-IP targeting `asconf->transport`, mirroring the source-address guard; first released in **v7.2-rc5**. |

The reachable lifetime runs from **v2.6.25** through **v7.1** (and 7.2
before `-rc5`). Unlike a backported-regression CVE, no in-support kernel
predates the flaw, so the *only* not-affected kernels are those that carry
the fix.

## Patch status

A row is **Fixed** only if its kernel carries the [`9b2854f86f0b`][fix]
backport; every SCTP-capable kernel without it is in-window and
**Vulnerable**. The first group is the upstream kernel; the rest are a
focused set of x86-64 distributions, with per-distribution detail in the
sections that follow. *First fixed* and *Fixed since* stay `—` until a row
is fixed.

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.2 | 7.2-rc5 | 2026-07-26 | :white_check_mark: Fixed — carries `9b2854f86f0b` |
| Linux kernel | 7.2.x | 7.2.2 | 7.2 | 2026-08-16 | :white_check_mark: Fixed |
| Linux kernel | 7.1.x | 7.1.12 | 7.1.6 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.18.x | 6.18.48 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.107 | 6.12.101 | 2026-08-03 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.155 | 6.6.148 | 2026-08-03 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.186 | 6.1.183 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.219 | 5.15.216 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.268 | 5.10.265 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Debian | sid (unstable) | 7.1.12-1 | 7.1.6-1 | 2026-08-04 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.8-2 | 7.1.6-1 | 2026-08-08 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.105-1 | 6.12.101-1 | 2026-08-06 | :white_check_mark: Fixed — DSA-6415-1 |
| Debian | 12 (bookworm) | 6.1.180-1 | — | — | :x: Vulnerable |
| Debian | 12 (6.12 opt-in) | 6.12.101-1~deb12u1 | 6.12.101-1~deb12u1 | 2026-08-15 | :white_check_mark: Fixed |
| Debian | 11 (bullseye, LTS) | 5.10.262-1 | — | — | :x: Vulnerable |
| Debian | 11 (6.1 opt-in) | 6.1.180-1~deb11u1 | — | — | :x: Vulnerable |
| Proxmox VE | 9 (default) | 7.0.14-14-pve | 7.0.14-10 | 2026-08-06 | :white_check_mark: Fixed — cherry-pick |
| Proxmox VE | 8 (default) | 6.8.12-43-pve | 6.8.12-41 | 2026-08-07 | :white_check_mark: Fixed — cherry-pick |
| NixOS | master | 6.18.48 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.48 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.47 | 6.18.42 | 2026-08-04 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.48 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.48 | 6.18.42 | 2026-08-08 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.47 | 6.18.42 | 2026-08-05 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.48 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.49.1.el10_2 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 9 | 5.14.0-687.42.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 8 | 4.18.0-553.158.1.el8_10 | — | — | :x: Vulnerable — no RHSA yet |
| Amazon Linux | 2023 (default) | 6.1.180-225.360 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.100-125.179 | — | — | :x: Vulnerable — no ALAS yet, below 6.12.101 fix |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.41-94.142 | — | — | :x: Vulnerable — no ALAS yet |
{.distros}

### Linux kernel

The fix reached Linus in **v7.2-rc5** (tagged 2026-07-26) and the kernel
CNA backported it across the maintained stable lines on **2026-08-03**:
**6.6.148** (`fedeb4468987`), **6.12.101** (`74e8f3e7114f`), **6.18.42**
(`85aca407c560`), and **7.1.6** (`d136b29bf91d`) — each the same fix by
subject, confirmed present on its `linux-*.y` branch, with `finger_banner`
current point releases at or above them.

The **6.1, 5.15, and 5.10** long-term lines picked up the backport later,
on **2026-08-19**: **6.1.183** (`2b324ba3494a`), **5.15.216**
(`a63afa1f9b12`), and **5.10.265** (`a9ce31be4cb1`) are each that branch's
first-fixed release — confirmed present on its `linux-*.y` branch, with
`finger_banner` current point releases at or above them. Every maintained
upstream kernel line now carries the fix.

**v7.2** itself was released on **2026-08-16**, promoting the former
`mainline` (rc) line to its own maintained stable branch. Since the fix
already landed by `v7.2-rc5`, the GA release carries it too, so the new
**7.2.x** row is fixed from its first release.

### Debian

Debian's status splits on which upstream branch each suite tracks.
**sid** and **forky** (testing, the future Debian 14) follow the 7.1
line: sid has been **fixed** since the `7.1.6-1` upload (upstream 7.1.6
is the branch's first-fixed release), and forky since that same version
migrated to testing on 2026-08-08. **trixie** (Debian 13) shipped the
fix as `6.12.101-1` — exactly the 6.12 branch's first-fixed release —
so it is **fixed** too. **bookworm** rides the 6.1 line and
**bullseye** the 5.10 line; both lines now carry an upstream fix
(6.1.183 / 5.10.265, 2026-08-19), but neither suite has shipped a
kernel with the backport, so both are **vulnerable**, as the Debian
security tracker records. They follow once Debian rebases onto the
fixed point releases or cherry-picks the fix.

Both older suites also offer an **opt-in newer kernel**. bookworm's
`linux-6.12` (bookworm-security) reached `6.12.101-1~deb12u1` on
2026-08-15 — exactly the 6.12 branch's first-fixed release — so it is
**fixed**, independently of the still-vulnerable bookworm default.
bullseye's `linux-6.1` (bullseye-security) rebuilds the 6.1 line but has
not reached its `6.1.183` first fix, so it stays **vulnerable**.

SCTP itself is not built into Debian's kernel image but shipped as the
`sctp` module, autoloaded on first use of an `AF_INET`/`IPPROTO_SCTP`
socket; it is not blacklisted by default, so a host running any SCTP
service loads the vulnerable code.

### Proxmox VE

Proxmox ships its own kernels, so Debian's status does not carry over. Both
maintained series backport the SCTP fix (a
`…-sctp-don-t-free-the-ASCONF-s-own-transport-in-DEL-IP.patch`): **PVE 9's
`proxmox-kernel-7.0`** first carries it in **`7.0.14-10`** (2026-08-06), and
**PVE 8's `proxmox-kernel-6.8`** in **`6.8.12-41`** (2026-08-07). The 6.8
series is the familiar Proxmox pattern: although the upstream 6.8 base is
old, the Ubuntu-derived kernel carries SCTP and receives the cherry-pick, so
a pre-fix Proxmox series cannot be assumed safe by base version alone.

Both releases also still publish pre-GA preview kernel series that Proxmox
abandoned before this disclosure and that never received the fix — PVE 9's
`proxmox-kernel-6.14` and `proxmox-kernel-6.17`, and PVE 8's
`proxmox-kernel-6.2` and `proxmox-kernel-6.5`. No fix is coming for any of
them: a host still booting one of these preview kernels stays vulnerable
until it switches to its release's current default kernel, which carries
the fix.

### NixOS

Every tracked ref's default `linuxPackages` is `linux_6_18`, at or above
the 6.18 branch's `6.18.42` first-fixed release, so every tracked ref is
**fixed**; they differ only in which point release each has reached. Kernel
updates land on nixpkgs `master` first, and each channel publishes them
once its Hydra jobset passes. A channel can therefore sit a few days behind
`master`, and an unstable channel is not necessarily ahead of a release
channel. The `-small` channels (`nixos-unstable-small`, `nixos-26.05-small`)
are gated on a reduced jobset and pick up kernel updates fastest. Every
upstream-maintained series now carries the fix, and nixpkgs currently pins
`linux_6_1` / `linux_5_15` / `linux_5_10` at or above their first-fixed
releases too, so a host overriding the default to one of them is fixed as
well, as long as it tracks a ref current enough to have picked up that
bump.

The `master` and `release-26.05` rows are the git branches the fix lands
on. They are not Hydra-gated, so they carry a kernel bump from the moment
the commit lands — typically a day or more before a channel republishes it,
which is what the *Fixed since* dates down the group show. They are
development branches, not deployment targets.

Flake inputs map onto these directly.
`github:NixOS/nixpkgs/nixos-unstable` tracks the `nixos-unstable` channel —
the GitHub channel branches are updated to exactly the published channel
pins — and a bare `github:NixOS/nixpkgs` with no ref follows `master`. A
bare `nixpkgs` registry input resolves by default to `nixpkgs-unstable`,
which is a separate channel aimed at Nix users on other operating systems
rather than at NixOS, so it is not gated on the NixOS tests and can hold a
different kernel from `nixos-unstable`.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks that carry SCTP, so all three
in-support lines — EL10 (6.12-based), EL9 (5.14-based), EL8 (4.18-based) —
are in-window. Red Hat published a CVE assessment (VEX/CSAF record,
initial release 2026-08-04) but has **not** shipped a fix — the record's
only remediation is a module-blacklist workaround, with no `vendor_fix`
entry or RHSA — so every stream is **vulnerable pending an advisory**.
Default module posture
is uniform across the family: on all three releases `sctp.ko` is not in
the base kernel packages but in **`kernel-modules-extra`**, and that
package installs `/etc/modprobe.d/sctp-blacklist.conf` (`blacklist sctp`,
plus `sctp_diag`) alongside it. So `sctp` never **autoloads** on a stock
EL host — without `kernel-modules-extra` the module is absent entirely,
and with it the blacklist suppresses autoload — though an explicit
`modprobe sctp` still loads it wherever the package is installed, so this
does not close the local vector. Rocky rebuilds RHEL's
kernels unchanged, so its fixes track Red Hat's; AlmaLinux is typically
the fastest rebuild and the leading indicator. Oracle Linux and
CloudLinux track the RHEL determination.

### Amazon Linux

No ALAS has been issued for this CVE, so every AL2023 kernel stream — the
default `kernel` (the 6.1 line) and the `kernel6.12` and `kernel6.18`
opt-ins — remains **vulnerable** pending an Amazon cherry-pick. All
three streams sit below their branches' first-fixed releases (`6.1.183`
/ `6.12.101` / `6.18.42`); each turns fixed when Amazon ships a
cherry-pick or the stream crosses its branch's first fix.

## Detection

**Is the running kernel in the affected window and missing the fix?**
Every SCTP-capable kernel is in-window; compare the running kernel against
the *Patch status* table's *First fixed* column for its series:

```bash
uname -r
```

**Is the `sctp` module available or loaded?**  The bug is only reachable
when SCTP is in use. On most distributions `sctp` autoloads on first use of
an SCTP socket:

```bash
lsmod | grep '^sctp'
```

**Is SCTP autoload blocked?**  A `blacklist`/`install … /bin/false` entry
(on Rocky/RHEL 8, 9, and 10 the `kernel-modules-extra` package that
provides `sctp.ko` ships one) means the datapath will not autoload —
though an explicit `modprobe sctp` still can:

```bash
modprobe -n -v sctp 2>&1; grep -rE '(^|[[:space:]])(install|blacklist)[[:space:]]+sctp' /etc/modprobe.d /usr/lib/modprobe.d 2>/dev/null
```

**Is a service actually terminating SCTP associations?**  Reaching the
ASCONF path needs an established association, so an SCTP listener is the
real exposure (telephony/SIGTRAN, some RADIUS/Diameter and load-balancer
stacks, `lksctp` test tools):

```bash
ss -a --sctp 2>/dev/null || ss -a | grep -i sctp
```

**Is ASCONF (ADD-IP) enabled?**  These sysctls set only the *system-wide
default* — they decide whether a listening service that relies on that
default will process ASCONF from remote peers. A local process enables
ADD-IP and AUTH on its own socket (`SCTP_ASCONF_SUPPORTED` /
`SCTP_AUTH_SUPPORTED`, no privilege) regardless of their value, so a `0`
here does not measure local exposure:

```bash
sysctl net.sctp.addip_enable net.sctp.addip_noauth_enable
```

## Public PoC

There is **no public exploit**. The [write-up][writeup] from Tencent Zhuque
Lab describes the primitive and reports internal proof-of-concept exploits
for local privilege escalation and container-to-host escape, but does not
release code. Absence of a public PoC is not safety — the mechanism is
fully described and the fix is public, so a working exploit is well within
reach; patch rather than rely on obscurity.

## Mitigation

The real fix is a patched kernel (the [`9b2854f86f0b`][fix] backport).
Until one is installed, the exposure is narrowed by keeping the SCTP
datapath unreachable — none of these is a fix.

### Disable the `sctp` module (if you don't use SCTP)

Most hosts never use SCTP. Where it is genuinely unused, block the module
so the vulnerable code cannot be autoloaded — this also blocks privileged
and container callers, unlike the sysctl below. Unload it if present but
idle:

```bash
sudo modprobe -r sctp
```

Then keep it from being (re)loaded, including on-demand autoload;
`install sctp /bin/false` is surer than a plain `blacklist sctp`, which
only suppresses alias-based autoloading:

```bash
echo 'install sctp /bin/false' | sudo tee /etc/modprobe.d/sctphantom.conf
```

Only do this where SCTP is genuinely unused — telephony/SIGTRAN gateways,
some Diameter/RADIUS and SS7 stacks, and `lksctp`-based tooling need it and
must fall back to the measures below.

### Bound the remote surface with the ADD-IP sysctls

These sysctls bound only the **remote** surface, and only for a service that
relies on the system default. Keeping `net.sctp.addip_noauth_enable` at **0**
(its default) makes a remote ASCONF carry a valid AUTH chunk, so a remote
peer must complete SCTP-AUTH key negotiation first. Apply it for the current
boot:

```bash
sudo sysctl -w net.sctp.addip_noauth_enable=0
```

Persist it across reboots:

```bash
echo 'net.sctp.addip_noauth_enable = 0' | sudo tee /etc/sysctl.d/99-sctphantom.conf
```

Where ADD-IP is not needed at all, `net.sctp.addip_enable=0` additionally
stops a default-configured listener from processing ASCONF from remote
peers.

**Neither sysctl touches the local vector.** The discoverers' demonstrated
privilege escalation and container escape enable ADD-IP and AUTH per socket
(`SCTP_ASCONF_SUPPORTED` / `SCTP_AUTH_SUPPORTED`, no `CAP_NET_ADMIN`, working
under the default container seccomp profile) and send a legitimately
authenticated ASCONF — so a `0` in either sysctl leaves that path fully
open. On a multi-tenant or container host, only blocking the `sctp` module
(above) or patching removes it.

### Restrict who can reach the SCTP listener

Where the service must stay up, limit exposure at the network edge:
firewall SCTP (`-p sctp`) to known peers, terminate associations only from
trusted networks, and avoid exposing SCTP listeners to untrusted clients.
This shrinks the remote attack surface but leaves a trusted-peer or local
path open.

## Risk notes

- **SCTP services are the remote surface:** any host terminating SCTP
  associations with ADD-IP negotiated — telephony/SIGTRAN, some Diameter,
  RADIUS, and SS7 stacks — can be driven into the UAF by a peer. Treat
  untrusted-peer SCTP as remotely exploitable.
- **Multi-tenant and container hosts:** the demonstrated impact is local
  privilege escalation and container-to-host escape, so shared hosts where
  an unprivileged user or a container can open SCTP sockets are directly in
  scope — even without a remote peer. The ADD-IP sysctls give no protection
  here: the demonstrated exploit enables ADD-IP and AUTH per socket without
  `CAP_NET_ADMIN` and authenticates its own ASCONF, so only blocking the
  `sctp` module or patching closes this path.
- **No "too old to be affected":** the flaw dates to 2.6.25, so old LTS
  kernels are *not* safe by age. Every maintained upstream line now
  carries the fix, but distro kernels adopt it independently — check the
  *First fixed* column for the distro in question, not the kernel's age.
- **`sctp` often not loaded:** on hosts that never use SCTP the module is
  absent, and blocking its autoload removes reachability entirely — the
  cheapest durable mitigation short of the patch.

## Verification log

Every verdict in the table above is backed by a checkable source. This log
records the provenance — the git reference, advisory, or repository index
that established each fact — so any row can be audited or reproduced. Most
readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `9b2854f86f0b` (*sctp: don't free the ASCONF's own transport
  in DEL-IP processing*), first released in **v7.2-rc5** (`git describe
  --contains` → `v7.2-rc5~27^2~4`, tag date 2026-07-26, via
  `~/src/linux/net` and `~/src/linux/stable`). It rejects a DEL-IP that
  targets `asconf->transport`.
- The bug was introduced by `42e30bf3463c` in **v2.6.25** (`describe
  --contains` → `v2.6.25-rc1~1162^2~979`), the ASCONF DEL-IP support — so
  every maintained line is in-window.
- **CVE-2026-64564** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`, `cve/published/2026/CVE-2026-64564.{json,dyad,cvss}`;
  record keys on `9b2854f86f0b56e9027d68e7a3fc909d1a9b566f`). The `.dyad`'s
  vulnerable:fixed pairs are `2.6.25 → 5.10.265 / 5.15.216 / 6.1.183 /
  6.6.148 / 6.12.101 / 6.18.42 / 7.1.6 / 7.2-rc5`.
- **Stable backports** (fix cherry-picks confirmed by subject grep against
  `~/src/linux/stable`, each a new SHA): 6.6.148 (`fedeb4468987`), 6.12.101
  (`74e8f3e7114f`), 6.18.42 (`85aca407c560`), 7.1.6 (`d136b29bf91d`) — all
  tagged **2026-08-03** (commit dates 11:15–11:26 +0200). The `Linux
  kernel` rows' *Current kernel* cells are read from kernel.org's
  `finger_banner`.
- **6.1.y / 5.15.y / 5.10.y backports** (fix cherry-picks confirmed by
  subject grep against `~/src/linux/stable`, each a new SHA, and by the
  `.dyad`): 6.1.183 (`2b324ba3494a`), 5.15.216 (`a63afa1f9b12`), 5.10.265
  (`a9ce31be4cb1`) — all tagged **2026-08-19** (commit dates 17:12–17:16
  +0200), each its branch's first-fixed release. No not-affected lines
  exist — the intro predates every maintained branch, and every branch now
  carries the fix.
- **v7.2** GA tag (`8d3ae59288f1`) dated **2026-08-16**, confirmed via
  `~/src/linux/stable` to already contain `9b2854f86f0b` (landed at
  `v7.2-rc5`), so the new `linux-7.2.y` branch is fixed from its first
  release; `finger_banner`'s current 7.2 point release is read for the
  row's *Current kernel*.

#### Scoring

- **Kernel CNA** (`vulns.git` `.cvss`/`.json`, `origin/master`): CVSS 3.1
  **9.8 CRITICAL** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). The
  CNA scenario scores `AV:N` because the ASCONF is processed from a
  received packet on an established association, and `PR:N` because the
  peer negotiates its own SCTP-AUTH keys (or the target runs
  `addip_noauth`).
- **Discoverers** ([write-up](https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564)): CVSS 4.0 **8.5 HIGH**
  (`CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`),
  scoring `AV:L` for the demonstrated local privilege-escalation /
  container-escape primitive. The divergence is vantage point, not
  disagreement on the flaw.
- **NVD / EPSS / KEV**: NVD record not yet analysed (`vulnStatus`
  `Received`, its listed CVSS 3.1 mirrors the CNA score rather than an
  independent NVD assessment); EPSS **1.48%** (72nd percentile, via
  api.first.org); not in KEV.

#### Distributions

- **Debian** (Debian security tracker, CVE-2026-64564):
  - sid resolved *fixed*; the tracker's fixed version for unstable is
    `7.1.6-1` (upstream 7.1.6, the 7.1 branch's first-fixed release),
    first seen 2026-08-04 per snapshot.debian.org.
  - forky resolved *fixed*; `7.1.6-1` migrated to testing 2026-08-08
    (via tracker.debian.org testing watch), the first fixed kernel in
    the suite.
  - trixie resolved *fixed*; first fixed `6.12.101-1`, shipped via
    **DSA-6415-1** (trixie-security, first seen 2026-08-06).
  - bookworm *vulnerable* — Debian has not adopted the 6.1.y line's
    `6.1.183` fix.
  - bookworm `linux-6.12` opt-in reached `6.12.101-1~deb12u1`
    (bookworm-security, first seen 2026-08-15) — the 6.12 branch's
    first-fixed release — so it is *fixed*; security-tracker does not
    assess `CVE-2026-64564` against the opt-in source packages by name,
    so status is a version compare against the branch's first-fixed
    release.
  - bullseye *vulnerable* — Debian has not adopted the 5.10.y line's
    `5.10.265` fix.
  - bullseye `linux-6.1` opt-in remains below the 6.1 branch's
    `6.1.183` first fix, so it is *vulnerable* — same version-compare
    method as bookworm's opt-in.
  - The rows' *Current kernel* values come from ftp-master madison and
    the tracker's `<suite>-security` `repositories` entries.
- **Proxmox VE** (`~/src/proxmox/pve-kernel`): patch
  `…-sctp-don-t-free-the-ASCONF-s-own-transport-in-DEL-IP.patch` present as
  `0059-…` in the `proxmox-kernel-7.0` tree (branch `master`) and `0034-…`
  in `proxmox-kernel-6.8` (branch `bookworm-6.8`). Per `debian/changelog`,
  the fix first ships in **`7.0.14-10`** (2026-08-06 20:53) for PVE 9 — its
  `7.0.14-11` (2026-08-07) is the *next* release, fixing the unrelated
  CVE-2026-68480 — and in **`6.8.12-41`** (2026-08-07 00:52) for PVE 8. The
  CVE identifiers were tagged in `38fa3e0` / `6daa7f0` (2026-08-07). The
  `pve-no-subscription` `Packages.gz` indexes publish both first-fixed
  builds (`proxmox-kernel-7.0.14-10-pve` in trixie,
  `proxmox-kernel-6.8.12-41-pve` in bookworm); the rows' *Current
  kernel* builds are read from the same indexes.
  - `proxmox-default-kernel`'s `Depends` confirms the live defaults:
    `7.0` on trixie (PVE 9), `6.8` on bookworm (PVE 8).
  - Pre-GA preview series still published but no longer updated, none
    carrying the fix: PVE 9's `proxmox-kernel-6.14` (branch
    `trixie-6.14`, last build `6.14.11-9`, 2026-05-15) and
    `proxmox-kernel-6.17` (branch `trixie-6.17`, last build `6.17.13-21`,
    2026-07-28 — no commits since); PVE 8's `proxmox-kernel-6.2` (branch
    `bookworm-6.2`, last build `6.2.16-20`) and `proxmox-kernel-6.5`
    (branch `bookworm-6.5`, last build `6.5.13-6`). All four predate this
    disclosure.
- **NixOS** (`~/src/nixos/nixpkgs`): `linux_default = packages.linux_6_18`;
  every tracked ref resolves `6.18` at or above the `6.18.42` first-fixed
  release, so all seven rows are fixed. Each row's *Current kernel* is
  the `6.18` version `kernels-org.json` resolves at that ref (branch
  tips for `master` / `release-26.05`, channel `git-revision` pins for
  the other five). At the same refs, `linux_6_1` / `linux_5_15` /
  `linux_5_10` also resolve at or above their branches' first-fixed
  releases.
  *Fixed since*: the branch rows use the commit date of the 6.18.42 bump
  (`b658e06342e8` on master, `33565191d37a` on release-26.05, both
  2026-08-03); the channel rows use `scripts/nixos-first-shipped`
  (nixos-unstable 2026-08-04, nixos-unstable-small 2026-08-03,
  nixpkgs-unstable 2026-08-08, nixos-26.05 2026-08-05, nixos-26.05-small
  2026-08-03).
- **Rocky / RHEL family**: Red Hat's CSAF/VEX record
  (`security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-64564.json`,
  initial release 2026-08-04) lists 274 affected products across
  EL6–EL10 and only a `workaround` remediation (module blacklist) — no
  `vendor_fix` entry, so no RHSA yet. EL8/EL9/EL10 all carry
  SCTP and are in-window. Default module posture (verified on live
  Rocky hosts, corroborated from BaseOS `filelists.xml.gz`): on all of
  Rocky 8 / 9 / 10 `sctp.ko` ships in `kernel-modules-extra`, and every
  build of that package also installs
  `/etc/modprobe.d/sctp-blacklist.conf` (`blacklist sctp`), suppressing
  autoload — earlier entries here misread this as EL10-only. The Rocky
  rows' *Current kernel* NVRs are read from BaseOS repodata
  (`primary.xml.gz`, highest `rel`). No AlmaLinux errata or OSV entry
  for this CVE yet, so AlmaLinux is not ahead of the bare VEX record.
- **Amazon Linux**: no ALAS for CVE-2026-64564 in the AL2023
  `updateinfo.xml.gz`. The per-stream *Current kernel* values (default
  `kernel`, `kernel6.12`, `kernel6.18`) are read from `primary.xml.gz`
  — all in-window and below their branches' first-fixed releases.
{{< /details >}}

## References

| Source | URL |
|---|---|
| Researcher write-up (Tencent Matrix) | <https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564> |
| Kernel fix (v7.2-rc5) | <https://git.kernel.org/stable/c/9b2854f86f0b56e9027d68e7a3fc909d1a9b566f> |
| Stable 6.6.148 | <https://git.kernel.org/stable/c/fedeb4468987bcaff85fe3061de5ae052d414740> |
| Stable 6.12.101 | <https://git.kernel.org/stable/c/74e8f3e7114f0e26d1b2c4c048044db9fcc27603> |
| Stable 6.18.42 | <https://git.kernel.org/stable/c/85aca407c560aba81b5ce9d3d6cf94c74077d19b> |
| Stable 7.1.6 | <https://git.kernel.org/stable/c/d136b29bf91dd8e3161281b87de597b7311d9462> |
| Stable 6.1.183 | <https://git.kernel.org/stable/c/2b324ba3494ae958cba16a453e3e71489b4de7fc> |
| Stable 5.15.216 | <https://git.kernel.org/stable/c/a63afa1f9b12d5293cbe0b77fd45dc0632533a13> |
| Stable 5.10.265 | <https://git.kernel.org/stable/c/a9ce31be4cb1a5dd82b3e0a1d0c3e7cbdcd31293> |
| CVE-2026-64564 | <https://www.cve.org/CVERecord?id=CVE-2026-64564> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-64564> |
| Red Hat security data | <https://access.redhat.com/security/cve/CVE-2026-64564> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
{.references}

[writeup]: https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564
[fix]: https://git.kernel.org/stable/c/9b2854f86f0b56e9027d68e7a3fc909d1a9b566f
[intro]: https://git.kernel.org/stable/c/42e30bf3463cd37d73839376662cb79b4d5c416c
