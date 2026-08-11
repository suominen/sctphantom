# SCTPhantom Tracking — Claude Code Context

This repository contains a living tracking document for **SCTPhantom**
(**CVE-2026-64564**), a **use-after-free** in the Linux kernel **SCTP**
stack.  `sctp_process_asconf()` caches the transport an ASCONF chunk is
processed against in `asconf->transport`.  An ASCONF carrying, in order,
`[Address Parameter L][DEL-IP L][DEL-IP 0.0.0.0]` — where `L` differs from
the packet source — makes the `DEL-IP L` pass the D8 source-address check
and free the still-cached transport via `sctp_assoc_rm_peer()`
(RCU-deferred); the wildcard `DEL-IP 0.0.0.0` then reuses the dangling
`asconf->transport` in `sctp_assoc_set_primary()` and
`sctp_assoc_del_nonprimary_peers()`, planting freed memory into
`asoc->peer.primary_path` / `active_path` (`net/sctp/sm_make_chunk.c`).
Impact: a reproducible kernel oops/panic (**DoS**) and, per the
discoverers, **local privilege escalation** and **container-to-host
escape**.

The canonical fix is [`9b2854f86f0b`][fix] (*sctp: don't free the ASCONF's
own transport in DEL-IP processing*), first released in **v7.2-rc5**.
**Crucially, this is an ANCIENT bug, not a regression**: the flaw was
introduced by `42e30bf3463c` (ASCONF DEL-IP support) in **v2.6.25** (2008),
so **every maintained SCTP-capable kernel is in-window**.  There is **no
"predates the introducing commit / not affected" case** — a kernel is safe
only by carrying the fix, never by being old.

**CVE-2026-64564** is assigned by the kernel CNA.  Discovered by **Corvus
AI** (Tencent Zhuque Lab / TencentOS Security Team), disclosed 2026-08-06 in
a [write-up][writeup].  **No public PoC** — the researchers report internal
PoCs for local privesc and container escape but released no code.

Reaching the bug needs the **`sctp` module in use** (autoloaded on first
SCTP socket on most distros; on Rocky/RHEL 8/9/10 alike `sctp.ko` ships in
`kernel-modules-extra`, which installs a `blacklist sctp` config, so it
never autoloads there), an association with the **ADD-IP / ASCONF**
extension negotiated, and a valid
**AUTH** chunk.  Both ADD-IP and AUTH can be enabled **per socket**
(`SCTP_ASCONF_SUPPORTED` / `SCTP_AUTH_SUPPORTED`, no privilege, no
`CAP_NET_ADMIN`), so a local attacker turns them on and authenticates its
own ASCONF; the `net.sctp.addip_enable` / `addip_noauth_enable` sysctls
bound only the **remote** surface, not the local privesc/container path.
These are reachability conditions, not verdict axes.

Two scores exist and both belong in the Summary: the **kernel CNA** scores
it CVSS 3.1 **9.8 CRITICAL** (`AV:N`, remote SCTP peer); the
**discoverers** score CVSS 4.0 **8.5 HIGH** (`AV:L`, demonstrated local
priv-esc).  The divergence is vantage point, not disagreement on the flaw.

SCTPhantom is a single, self-contained bug — there is **no** companion tracker
to cross-reference.

The rendered site is published at <https://kimmo.cloud/sctphantom/>.

[fix]: https://git.kernel.org/stable/c/9b2854f86f0b56e9027d68e7a3fc909d1a9b566f
[intro]: https://git.kernel.org/stable/c/42e30bf3463cd37d73839376662cb79b4d5c416c
[writeup]: https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564

## Your task

Keep `site/content/_index.md` (the canonical tracker) up to date as the
kernel fix is picked up by distro kernels.  After edits, rebuild with
`make build` and publish with `make dist`.

A scheduled background agent runs against this repo to refresh the tracker
on its own.  If you find the file has been edited since you last looked,
that's likely why — re-read before assuming stale state.

## Repo layout

```
.
├── site/                                     # Hugo project
│   ├── content/_index.md                     # the tracker — single source of truth
│   ├── hugo.toml                             # config (subpath baseURL — don't break)
│   ├── assets/css/extended/custom.css        # CSS overrides (PaperMod extension point)
│   ├── layouts/partials/post_meta.html       # overrides PaperMod: adds labels + lastmod
│   └── go.mod, go.sum                        # Hugo Modules — pulls PaperMod theme
├── scripts/                                  # auto-update agent: prompt + driver
│   ├── auto-update                           # wrapper invoked by the systemd timer
│   ├── auto-update-prompt.txt                # prompt fed to headless Claude
│   └── nixos-first-shipped                   # channel + commit -> first-published date
├── systemd/                                  # user-level timer + service units
│   ├── sctphantom-tracker-update.service        # runs scripts/auto-update
│   └── sctphantom-tracker-update.timer          # twice daily
├── flake.nix, .envrc                         # Nix dev shell: hugo + go + git
├── Makefile                                  # `make build`, `make dist`, `make banner`
├── LICENSE                                   # CC BY 4.0
├── README.md                                 # user-facing project README
├── WEBSITE.md                                # publication plan / decisions log
└── CLAUDE.md                                 # this file
```

## The tracker file (`site/content/_index.md`) — important constraints

- It has Hugo front-matter with these required fields: `title`,
  `description`, `layout: "single"`, `date` (published), `lastmod` (last
  updated).  Keep all five; the rendering depends on them.
- The H1 has been stripped — Hugo emits the title from front-matter via
  PaperMod's single-post layout.  Don't add an H1 back.
- The TOC is generated by PaperMod's auto-TOC (`ShowToc = true` +
  `UseHugoToc = true` in `hugo.toml`).  Don't add a manual TOC.
- The "Last updated" date lives in the `lastmod` front-matter field.
- **The tracker is for its human readers, not for you.**  Write every
  section for the operator deciding whether their system is exposed —
  the bug, who can reach it, per-distro status, what to do.  Keep out
  anything that only explains how the tracker is *built*: row-inclusion
  policy ("no row", "dead weight", "prose only"), verdict-axis or column
  mechanics ("recorded in prose, not columns", "sticky"), and tracking
  methodology.  Those live here in `CLAUDE.md`; stating them in the
  tracker too duplicates them and drifts.  State the reader-relevant
  *fact* ("7.0.y is EOL and unpatched — permanently vulnerable"), never
  the policy behind it.  In particular, when prose covers a row-less
  item (a dead series, an untracked release), end with the consequence
  and the way out for a host still on it ("no fix is coming — switch to
  the current default kernel"), never with the row decision ("so it
  gets no row here") — the reader can see the table for themselves.
- **One command per fenced code block, no inline comments.**  Each `bash`
  code fence holds a single command with nothing after it on the line, so
  the rendered copy button yields a clean, runnable command.  Put any
  clarifying note in the prose *before* the block — never as a trailing
  `# ...` comment or a second command in the same fence.

## Update workflow

1. Edit `site/content/_index.md` (or any file under `site/`).
2. Optional: `cd site && hugo server` for a local live preview at
   <http://localhost:1313/sctphantom/>.
3. `make build` — emits to `site/public/` (gitignored).
4. `make dist` — runs `make build`, then rsyncs `site/public/` to
   `haig:/sctphantom/` with `--delete`.

## What flips a verdict — the kernel backport, and only that

This bug lives entirely in the kernel, and the fix is a single commit.
Because the bug is **ancient** (intro v2.6.25), a row's verdict is one
question only:

- **Does the kernel carry the [`9b2854f86f0b`][fix] backport?**  Every
  SCTP-capable kernel is in-window, so an in-window kernel `≥ v7.2-rc5` or
  carrying a stable/distro backport is fixed; every other in-support kernel
  is `:x:`.  This is what *Status* and *Fixed since* key on.  There is **no
  "predates the bug / not affected" case** — do not rate any kernel row
  `:heavy_minus_sign:` on age grounds.  (The only conceivable not-affected
  row is a build that ships *no* SCTP at all — none of the tracked
  distributions does.)

The reachability gate decides *who can reach* an unpatched kernel, but is
**not a verdict axis** — record it in the per-distro `###` prose or the
Summary, never as a column:

- **`sctp` module in use.**  The bug is unreachable unless SCTP is loaded
  and an association is established.  On most distros `sctp` autoloads on
  first use of an SCTP socket; on Rocky/RHEL **8, 9, and 10 alike**
  `sctp.ko` ships in `kernel-modules-extra`, which always installs
  `/etc/modprobe.d/sctp-blacklist.conf` (`blacklist sctp`) alongside it
  (verified on live hosts and in BaseOS filelists), so `sctp` never
  autoloads on a stock EL host — without the package the module is absent,
  with it the blacklist suppresses autoload.  An explicit `modprobe sctp`
  still loads it wherever the package is installed.
- **ADD-IP / ASCONF + AUTH.**  The ASCONF path needs the ADD-IP extension
  negotiated and a valid AUTH chunk.  A socket enables both per-socket via
  `SCTP_ASCONF_SUPPORTED` / `SCTP_AUTH_SUPPORTED` with no privilege
  (confirmed in the kernel setsockopt handlers, which apply no capability
  check), so the `net.sctp.addip_enable` / `addip_noauth_enable` sysctls set
  only the system-wide default: they bound a remote peer's reach against a
  default-configured listener but do **not** gate the local privesc/container
  vector, where the attacker enables the features on its own socket and
  authenticates its own ASCONF.  Blocking the module removes the local reach;
  `net.sctp.addip_enable=0` is a remote-only mitigation, not a fix.

The combined *Patch status* table is the **single source** for every
row's kernel versions, dates, and status — upstream and distros alike.
Columns: `Distribution | Release | Current kernel | First fixed | Fixed
since | Status`.  The upstream kernel is the **first** "distribution" in
the table, labelled `Linux kernel`, one row per branch (`mainline`,
`7.1.x`, … `5.10.x`); its upstream-specific prose lives in the
`### Linux kernel` subsection.  Don't restate the table's columns in
prose or add a parallel per-release table.  The version cells hold
versions only (or `:grey_question:` when unverified) — the verdict lives
in *Status* as the emoji **plus a one-word verdict** and an optional
short note after an em dash (`:white_check_mark: Fixed — DSA-…`,
`:x: Vulnerable — no ALAS yet`); longer caveats go in the `###` prose.
Label NixOS channels in the **Release** column in friendly form
(`Unstable`, `26.05`).  Where a channel has variants, keep the friendly
base and add the variant in parentheses — `Unstable (small)`,
`Unstable (nixpkgs)`, `26.05 (small)`; this is the one place the
`<release> (<x>)` parenthetical carries something other than a kernel
series, so introduce the real channel name (`nixos-unstable-small`,
`nixpkgs-unstable`) in the `###` prose.  The nixpkgs `master` row is
labelled with the bare branch name, since it is a branch and not a
channel.  Label opt-in/alternate kernel rows by their
kernel *series*, uniformly `<release> (<series> opt-in)` — `11 (6.1
opt-in)`, `2023 (6.12 opt-in)` — and introduce the underlying package
name (`linux-6.1`, `kernel6.12`) in the `###` prose, never in the
Release cell.  Row and list ordering: releases **descending**
within a distribution; within a release the default kernel row first,
then live opt-in/alternate series rows **ascending**, then superseded
(`old`) series rows **descending** — like releases, old series are
something users are expected to move up from.  The same rule applies to
version lists in prose.  Rows sharing a Distribution value must stay
contiguous — the browser transform renders each run as one group heading
row.  Keep the `{.distros}` block attribute on the line **immediately
after** the table (no blank line between).

Amazon rows are **one per AL2023 kernel stream** — label the default
stream's row `2023 (default)` (it is the plain `kernel` package,
currently 6.1 — named in the `### Amazon Linux` prose, not the table)
and each opt-in stream by its series (`2023 (6.12 opt-in)` — the
`kernel6.12` package, named in the prose); keep every supported stream
(default + opt-in) as its own row, and add a row when Amazon ships a
new stream.  **AL2 has no rows**: it reached end of support on
2026-06-30 — before this tracker existed — so it is covered collectively
in the `### Amazon Linux` prose (its 4.14 / 5.10 / 5.15 streams all carry
SCTP and are in-window, but no ALAS is coming); don't poll AL2 repodata and
don't re-add AL2 rows.  AL2023 remains supported and is polled as usual.

Debian suites get one row for the **default** `linux` kernel and, where
one exists, a separate row per opt-in alternative kernel package (e.g.
bullseye's `linux-6.1` source package, the bookworm 6.1 kernel rebuilt
for bullseye — row `11 (6.1 opt-in)`).  Because the bug is ancient, every
Debian kernel — bullseye's 5.10 default, bookworm's 6.1 default, and every
opt-in — is in-window; a suite is fixed only once its kernel carries the
backport (trixie and sid do at seed; bookworm and bullseye do not).  An
opt-in row's verdict never flips the default row's.  The same
default-plus-variant row pattern applies
to Proxmox (`proxmox-kernel-*` series), with two wrinkles: a default
row is labelled plain `9 (default)` — its series is visible in *Current
kernel* and named in the prose — and there is a third Release label:
PVE opt-in kernels are previews of the next default (per the Proxmox
forum announcements), so series get superseded — a former default or
an opt-in overtaken by a newer one is labelled `old` (`9 (6.17 old)`).
Keep an `old` row (hosts still run it), but expect no more updates for
it: Proxmox discontinues updates for superseded series after a short
transition tail, and every such series is EOL on kernel.org, so an
in-window vulnerable `old` row will likely never flip.  However, a
release, stream, or kernel series that was already **dead before the
tracker existed** — its updates ended before the disclosure — gets
**no** row at all, anywhere in the table, if it died *without* the
fix (the AL2 and upstream-7.0.y treatment): its permanent `:x:`
verdict is one sentence in the relevant `###` prose.  (A series that
died already *fixed* keeps its row.)  Don't add upstream `Linux kernel`
rows for series that appear in the table only because PVE ships them (PVE's
Ubuntu-derived 7.0 and 6.8 kernels are distro rows, not upstream ones);
their upstream-line status is one sentence in the `### Proxmox VE` prose.
Because the bug is ancient, a PVE series is never "not affected" by base
version — its Ubuntu-derived kernel carries SCTP and is in-window until it
takes the cherry-pick.  Niche variants (e.g.
the EL `kernel-rt` real-time kernel) get **no** row — cover them as a
reader-facing note in the `### Rocky Linux / RHEL family` prose.

A per-distro `###` section is for **reader-facing** caveats that don't fit
the table (the reachability gate, which kernels predate the regression,
EL-family scope).  Keep tracking methodology out of it — that is agent
guidance and belongs in this file.

## Routine run scope — live Current kernel, sticky verdict columns

The **Current kernel** column is **live**: refresh it for **every** row
on every run — upstream point releases and distro package versions
alike — and record any movement.  A Current-kernel bump alone is a real
content change: commit it and bump `lastmod`.  The **verdict columns
are sticky**: *First fixed*, *Fixed since*, and *Status* change **only**
when a row actually flips — its kernel reaches a fixed upstream release
(see the `Linux kernel` rows), **or** the distro ships the
`9b2854f86f0b` backport / cherry-pick.  A Current-kernel bump that stays
inside the vulnerable window without the backport moves the *Current
kernel* cell and **nothing else**.

**A default-kernel-series switch is always recordable.** PVE moves its
default series during a release's lifetime (`proxmox-default-kernel`
changing which `proxmox-kernel-*` it depends on), and a distro can add
an opt-in series alongside it.  Record a switch in the prose and the
rows: the default row keeps its plain `(default)` label while its
*Current kernel* moves to the new series, the superseded series gets an
`old` row of its own (re-sort: old rows follow the live opt-ins,
descending), a new opt-in series gets a **new row**, and update the
verification log — **together**, since a log-only update leaves the
tracker self-inconsistent.
A switch can also flip a verdict on its own — a newer series may already
contain the fix, or may newly be in-window where the old one was not — so
re-derive the verdict rather than carrying the old one across.

Each run:

- Refresh the `Linux kernel` rows' *Current kernel* from the stable
  point releases (finger_banner; verify backports via
  `~/src/linux/stable`, recipe below).  The fix is backported to
  7.1.y / 6.18.y / 6.12.y / 6.6.y (7.1.6 / 6.18.42 / 6.12.101 / 6.6.148,
  all tagged 2026-08-03); mainline carries it from v7.2-rc5.  The 6.1.y,
  5.15.y, and 5.10.y lines are in-window but **unpatched** at seed —
  re-check them every run, as a later stable batch is where they most
  likely flip.  No line is "not affected" — the bug predates every
  maintained branch.  (PVE 9's Ubuntu-derived 7.0 kernel is a distro row,
  not an upstream one.)
- For a distro row, re-pull the distro's **kernel** version and update
  *Current kernel*.  If an in-window kernel reaches its branch's
  first-fixed release **or** a distro advisory ships the `9b2854f86f0b`
  backport ⇒ flip *Status* to `:white_check_mark: Fixed`, set *First
  fixed* to the first fixed package build, and set *Fixed since*.
- Watch AlmaLinux (leading indicator) and Rocky/RHEL for the EL rows,
  and Ubuntu for the Proxmox rows.

`zcat` / `gunzip` **are** in the headless allowlist — use them for the
`Packages.gz` / repodata pulls.  Pull only kernel versions and advisory
state — the tracker records no other per-distro facts.

**Never record NixOS channel git-revisions** (the
`channels.nixos.org/<channel>/git-revision` pins) in the tracker.  They
advance on nearly every run — recording them manufactures a diff on an
otherwise no-op run.

## Conventions for status entries

A *Status* cell is the emoji plus its one-word verdict, optionally
followed by an em dash and a short note (advisory ID, `LTS`, `no ALAS
yet`) — longer caveats go in the `###` prose.  **The note must say
something the row's other columns do not.**  Don't restate the verdict
(`Vulnerable — no fix yet` / `no backport yet` just repeats `Vulnerable`)
or the kernel series (`Vulnerable — 6.1 line` just repeats *Current
kernel*); a plain `:x: Vulnerable` is the norm.  Keep a note only when it
adds information — the awaited advisory (`no RHSA yet`, `no ALAS yet`), a
non-obvious near-miss (`6.12.100 below the 6.12.101 first fix`), or a
posture caveat *specific to that row* (the family-wide EL autoload
blacklist is prose, not a note):

- `:white_check_mark: Fixed` — a kernel that carries the `9b2854f86f0b`
  backport (confirmed in changelog / advisory / kernel pin, not merely
  announced): set *First fixed* and *Fixed since*.
- `:heavy_minus_sign: Not affected` — **essentially never applies to this
  bug.**  The flaw predates every maintained kernel, so no row is
  not-affected on age grounds.  Reserve the badge for a build that ships no
  SCTP at all (none of the tracked distributions does); *First fixed* /
  *Fixed since* stay `—`.
- `:x: Vulnerable` — an SCTP-capable kernel without the backport (the
  default state for every unpatched row).
- `:warning: Staged` / `:warning: Mitigated` — not fully resolved: the
  fix is staged but not yet in the user-facing channel (merged /
  cherry-picked but not in a released package), **or** a distro default
  *materially* reduces exposure.  Note the Rocky/RHEL `blacklist sctp`
  default (all of 8/9/10, via `kernel-modules-extra`) does **not**
  qualify: it only suppresses on-demand autoload, and an explicit
  `modprobe sctp` (the local attacker's path) still loads it — so the EL
  rows stay `:x:`, with the blacklist a prose caveat.  A mitigation is
  **not** a fix — it never earns `:white_check_mark:`.
- `:grey_question: Unverified` — not yet verified (kernel pin or
  advisory not yet inspected).

Note: SCTPhantom has **no** severity downgrade — an unpatched SCTP-capable
row is `:x:`, regardless of whether a given host autoloads or blacklists
`sctp`.  The reachability gate is prose about *reach*, not status.  A
`:warning:` is only a staged-but-unreleased fix or a materially-reducing
vendor default.

### "First fixed" and "Fixed since" columns

Both are **sticky**, set when a row flips to fixed, and stay `—` while
the row is vulnerable, unverified, or not affected.  *First fixed* is the
first release or package build carrying the fix — from the `.dyad` for the
`Linux kernel` rows, from the advisory / changelog for distro rows.
*Fixed since* is the **first-observation** date the fix first held: the
release tag date for `Linux kernel` rows, the advisory/ship date for
distro rows.  Only touch either if the verdict flips again or the
recorded first-fixed build turns out to have been wrong.

### Verification log

The section has a fixed shape: a short reader-facing intro paragraph
stays **visible**, and the log body is collapsed inside a
`{{< details summary="Full verification log" >}} … {{< /details >}}`
shortcode wrapper (rendered by
`site/layouts/shortcodes/details.html`).  Keep the intro and the
wrapper intact.  Inside the wrapper the
subsections are `####` headings (h4 — deliberately below the ToC's
`endLevel`, so the collapsed content has no ToC anchors pointing into
it).  Current subsections are `#### Upstream` and `#### Distributions`;
add a `#### Scoring` subsection if/when a CVSS/EPSS score is published.

Log entries are **one top-level bullet per source or topic**, opening
with a terse bold lead and the method attribution (e.g. `**Debian**
(via …):`), followed by **one fact per nested sub-bullet** — never run
multiple facts together into a paragraph-bullet; the nesting is what
keeps the log readable.  Sub-bullets follow the table's ordering
conventions (releases descending; within a release the default kernel
first, live opt-in series ascending, then old series descending).

When you re-verify entries, update the section rather than appending a
line per re-check.  Edit the relevant subsection in place — usually
the one sub-bullet whose fact changed.  Add a new `####` subsection
only when a genuinely new topic appears.  The log carries no dates of
its own — the front-matter `lastmod` is the document's only recency
marker, so do not write verification dates inline.  Method/source
attribution *without* a date is fine (e.g. `(via …/madison)`,
`(checked against ~/src/linux/stable)`).

The log records **facts**, not run outcomes.  Never write "no change",
"unchanged from prior run", "no verdict changes this run", or similar
prose anywhere in the tracker — an entry that is still accurate reports
that by staying untouched.  This applies just as much on a run that
*does* change something real: update only the lines whose facts changed
and leave every other line exactly as it was.

### Date handling — first-seen / last-changed, not "today"

Dates in the prose (`lastmod`, every "as of <date>" / "released
<date>" / "Fixed since" value) are **first-seen / last-changed**
dates, not "today" dates.  Only move a date when the fact it
qualifies actually changes.  If the entire run is a no-op (no status,
kernel version, advisory, or upstream-backport change), leave the file
alone and don't commit at all — don't bump `lastmod`, don't insert
"re-confirmed <today>" parentheticals.

## Build environment

- Hugo extended **≥ 0.146.0** (PaperMod's minimum).  Debian apt is too old.
- Go (any recent version) — needed for Hugo Modules to pull PaperMod.
- The Nix flake provides both: `nix develop` (or just `cd` in if direnv is
  set up).
- On this host `nix` is **not** available (Debian, no nixpkgs installed) —
  don't try `nix develop`.  Hugo ≥ 0.146 is at `/usr/local/bin/hugo`, so
  plain `make build` / `make dist` work directly.

## Auto-update worktree

The auto-update job works in a dedicated git worktree
at `~/src/auto-update/sctphantom`, checked out on a single long-lived branch
named `auto-update`.  The wrapper merges `origin/main` forward into that
branch on each run, then hands off to headless Claude, which commits any
tracker changes back onto `auto-update` only.  The agent must not create
per-run branches, switch branches, push, or open PRs — merges of
`auto-update` into `main` are done manually by the user.

One-time setup (from the primary checkout at `~/src/sctphantom`):

```
git worktree add -b auto-update ~/src/auto-update/sctphantom main
```

The wrapper runs `git fetch origin` and `git merge origin/main` under
`set -e`, so the repo needs a GitHub `origin` with `main` pushed or every
scheduled run aborts before doing anything.  A freshly `git init`'d tracker
must `git remote add origin https://github.com/suominen/sctphantom.git` and
`git push -u origin main` before the timer is worth enabling.

**The timer runs the wrapper from the primary checkout, not from the
worktree.**  `ExecStart` points at `<primary>/scripts/auto-update`, and the
wrapper reads its prompt from there too, so what executes is always code you
have reviewed and merged to `main`.  The agent can commit to `auto-update`,
so anything under `scripts/`, `.claude/`, `CLAUDE.md`, or `.mcp.json` on
that branch is untrusted: after merging `origin/main` forward the wrapper
refuses to run if any of them differs from `origin/main`, and it refuses
outright if it was invoked from inside the worktree at all.  A wrapper
change therefore takes effect on the next run after you merge it to `main`,
with no re-exec dance.

The service unit adds a kernel-level backstop — `ProtectSystem=strict` with
a short `ReadWritePaths` list (the worktree, the `.git` directories git has
to update, and `~/.claude/session-env`, which Claude Code writes on every
Bash call).  Without it the guards above are advisory: the agent may run
`curl`, and `curl -o` writes anywhere this user can, including over the
wrapper the timer runs.  Each repository's `.git/hooks` and `.git/config`
are handed back as `ReadOnlyPaths`, since nothing in a run needs to write
either and both are executable code.

A refusal is a stop-and-look rather than something to clear reflexively —
it means a file that should only ever arrive by merge was rewritten on the
branch.  Inspect it with `git -C ~/src/auto-update/<slug> diff origin/main
-- scripts .claude CLAUDE.md .mcp.json` before doing anything else.

To run a refresh immediately (same path the timer takes):

```
systemctl --user start sctphantom-tracker-update.service
```

It is a `oneshot`, so the command blocks until the run finishes; follow its
output with `journalctl --user -u sctphantom-tracker-update`.  Run the
trackers **one at a time**, never in parallel — they share the
`~/src/linux/*` reference clones.

The systemd units ship in `systemd/`.  They are not in a standard unit
search path, so wiring the timer means symlinking both units into
`~/.config/systemd/user/` and then enabling the timer.  Use `ln -sr` so the
links are relative:

```
ln -sr ~/src/sctphantom/systemd/sctphantom-tracker-update.service \
       ~/src/sctphantom/systemd/sctphantom-tracker-update.timer \
       ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now sctphantom-tracker-update.timer
```

The timer fires at `05,17:50` — staggered from the sibling trackers
(ovswrap `:05`, zapscape `:20`, CVE-2026-42533 `:35`) so the shared
kernel clones are not fetched simultaneously.  Verify the live set with
`systemctl --user list-timers | grep tracker` — this in-doc list has gone
stale before.

## Tearing down the auto-update

To stop the scheduled refresh, unwire it in this order — the sequence
matters, because `systemctl disable` needs the unit definition to still be
resolvable when it runs.

1. **Disable the timer first**, while the unit symlinks are still in place:

   ```
   systemctl --user disable --now sctphantom-tracker-update.timer
   ```

2. **Remove the unit-definition symlinks** from the search path:

   ```
   rm ~/.config/systemd/user/sctphantom-tracker-update.timer \
      ~/.config/systemd/user/sctphantom-tracker-update.service
   ```

3. **Reload** so the running user manager drops the units:

   ```
   systemctl --user daemon-reload
   ```

If the definition symlinks were removed *before* disabling, the stale
`enable` symlink is left behind, parking the timer in a `failed` state.
Recover by deleting it directly, then reloading and clearing the failure:

```
rm ~/.config/systemd/user/timers.target.wants/sctphantom-tracker-update.timer
systemctl --user daemon-reload
systemctl --user reset-failed sctphantom-tracker-update.timer
```

Finally, remove the worktree and its branch (run from `~/src/sctphantom`):

```
git worktree remove ~/src/auto-update/sctphantom
git branch -d auto-update
```

## Local reference clones

git.kernel.org's cgit HTML pages (any URL ending in /log/, /tree/,
/commit/, etc.) and lore.kernel.org (the mailing-list archive and its
search) are Anubis-gated; WebFetch hits the no-JS challenge and the
auto-update agent cannot read them.  The agent inspects kernel history via
long-living local clones under `~/src/linux/`:

| Clone path           | Upstream                                                           |
|----------------------|--------------------------------------------------------------------|
| `~/src/linux/stable` | `https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git` |
| `~/src/linux/net`    | `git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git`     |
| `~/src/linux/vulns`  | `https://git.kernel.org/pub/scm/linux/security/vulns.git`          |
| `~/src/proxmox/pve-kernel` | `https://git.proxmox.com/git/pve-kernel.git`                 |

`net` is the netdev "net" tree, where networking fixes (SCTP among them)
land and get tagged for stable before Linus — handy for confirming a
backport's provenance ahead of the stable release.  `vulns` is the kernel
CNA's CVE database.

The auto-update *wrapper* refreshes the clones with `git -C <clone> fetch`
before invoking the headless agent; the agent inspects via the
`origin/<branch>` remote-tracking refs (e.g. `origin/linux-6.12.y`).

**Is a stable branch fixed yet?**  Every SCTP-capable branch is in-window
(no intro check needed — the bug predates them all), so there is only one
question: does the branch carry the fix?  The backport is a cherry-pick
with a new SHA, so search by the upstream subject, not `git tag --contains`:

```
git -C ~/src/linux/stable log v<series>..origin/linux-<series>.y --grep="don't free the ASCONF's own transport" --format='%h %s'
```

Empty output ⇒ the series is in-window but still **unpatched** (Vulnerable)
— never "not affected".  Keep the range bounded to `v<series>..` — an
unbounded subject grep over the whole branch history can match an unrelated
commit and read as a false result.  **Check the subject of every hit**: a
later commit that cites the fix SHA in its body or a `Fixes:` tag also
matches a SHA grep, and its backports can land in **later** point releases
than the real fix's — reading such a follow-up as the fix records
first-fixed versions too late.  Prefer the `.dyad` when it covers the
branch.  Confirm the fix landed mainline in v7.2-rc5 with:

```
git -C ~/src/linux/stable describe --contains 9b2854f86f0b
```

The git smart-HTTP protocol is not Anubis-gated, so `git fetch` /
`git ls-remote` work from any UA.

## The CVE record (`vulns.git`)

**CVE-2026-64564** is already assigned.  The kernel CNA's `vulns.git` keys
each record on the *fixing commit SHA*; inspect via `origin/master`, not
`HEAD` (the wrapper only `git fetch`es):

```
git -C ~/src/linux/vulns show origin/master:cve/published/2026/CVE-2026-64564.dyad
```

The `.dyad` gives the authoritative per-branch `<introduced>:<fixed>`
versions used in the `Linux kernel` rows.  For this bug the **introduced**
side is `2.6.25` on every pair, confirming there is no not-affected series.
The `.json` carries the CNA description; the `.cvss` carries the CNA's
CVSS 3.1 9.8 (`AV:N`) vector.  The discoverers' CVSS 4.0 8.5 (`AV:L`) score
lives in the write-up.  Watch NVD for an analysed record / EPSS to add to
the Summary.  The repo/site slug stays `sctphantom` (see `WEBSITE.md`).

## SCTP reachability — the reach discriminators (prose, not columns)

For an unpatched kernel, whether the bug is reachable at all, and by whom,
turns on three host properties:

- **`sctp` module in use** — loaded and terminating associations.  On most
  distros it autoloads on first use of an SCTP socket; on Rocky/RHEL
  **8/9/10 alike** `sctp.ko` lives in `kernel-modules-extra`, which
  installs `blacklist sctp` alongside it, so it never autoloads there
  (verified on live hosts and in BaseOS filelists).  A host with no SCTP
  traffic is not exposed regardless of kernel version.
- **ADD-IP / ASCONF negotiated** — the DEL-IP path is only reached on an
  association that negotiated the ADD-IP extension.  `net.sctp.addip_enable`
  sets the system-wide default, but a socket can negotiate ADD-IP per-socket
  via `SCTP_ASCONF_SUPPORTED` regardless of it (no privilege).
- **AUTH requirement** — an ASCONF needs a valid AUTH chunk.
  `net.sctp.addip_noauth_enable=1` drops that requirement system-wide, but a
  local attacker does not need it: it enables AUTH per-socket
  (`SCTP_AUTH_SUPPORTED`) and sends a legitimately authenticated ASCONF.  So
  both sysctls bound only the remote surface against a default-configured
  listener; neither gates the demonstrated local privesc/container path.

These are per-host properties recorded in prose (Summary, the
reachability blockquote, Detection, Mitigation) — re-derive them only when
adding a distro or when a distro reworks its defaults.  They never change a
`Status` cell.

## Local nixpkgs clone for NixOS channel verification

*Seeding-and-adoption method — see "Routine run scope" above.  Do not
record the resolved channel revisions in the tracker.*

NixOS rows are verified from a local nixpkgs clone at `~/src/nixos/nixpkgs`,
not the (JS-rendered, lagging) security-tracker page.  Each channel has a
git-revision pointer at `https://channels.nixos.org/<channel>/git-revision`;
at that commit, `pkgs/os-specific/linux/kernel/kernels-org.json` carries
the version for every supported mainline.org kernel series.  The **default**
`linuxPackages` is set by `packageAliases.linux_default` in
`pkgs/top-level/linux-kernels.nix`.  Read that alias rather than assuming
the default is the newest or oldest LTS — it has moved before.  At seed the
default is `linux_6_18` (fixed at 6.18.42).  Every kernel series carries
SCTP and is in-window, so a default is fixed only once its series carries
the backport; a host pinned to `linux_6_1` / `linux_5_15` / `linux_5_10`
stays vulnerable.

Tracked refs: the two ungated git branches `master` and `release-26.05`,
plus the five channels `nixos-unstable`, `nixos-unstable-small`,
`nixpkgs-unstable`, `nixos-26.05`, `nixos-26.05-small`.  Rows are ordered
by **propagation**, not by release: the branch a fix lands on first, then
the branch it is backported to, then the channels that republish them,
keeping each `-small` variant next to its sibling rather than splitting
the pair by date.  *Fixed since* then comes out non-decreasing across the
branch-to-channel boundary, which is a free check that no channel
predates its branch.  (This mirrors the shared tracker template's
`DESIGN.md` row-order rule and its `CLAUDE-package-sources.md` NixOS
recipe; keep this section in step with those.)

The five channels are read from their `git-revision` pins:

```
rev=$(curl -fsSL https://channels.nixos.org/<channel>/git-revision)
git -C ~/src/nixos/nixpkgs show "${rev}:pkgs/os-specific/linux/kernel/kernels-org.json"
```

`channels.nixos.org/<channel>/git-revision` returns a 302 — always pass
`-L` to curl.  The wrapper refreshes the clone on every run.

**The branch rows have no `git-revision` pin** — read them from the
clone's remote-tracking refs instead:

```
git -C ~/src/nixos/nixpkgs show origin/master:pkgs/os-specific/linux/kernel/kernels-org.json
```

The branches are rows on purpose: ungated by Hydra, they carry the fix
from the moment the commit lands, so they show where it sits before any
channel publishes it — the NixOS analogue of the upstream `mainline` row,
and what a flake input pinned to a bare `github:NixOS/nixpkgs` or to
`release-26.05` actually follows.  Don't prune them as non-deployable
refs.  A branch row's *Current kernel* tracks the `kernels-org.json`
version, which moves only on a kernel bump, so the row does not churn
with ordinary commit traffic.

**A branch row's *Fixed since* is the commit date of the fixing commit**
— nothing publishes an ungated branch, so there is no release date to
use.  Find it by searching the branch for the bump that first reached the
fixed release:

```
git -C ~/src/nixos/nixpkgs log --format='%H %cI %s' -S'6.18.40' origin/master -- pkgs/os-specific/linux/kernel/kernels-org.json
```

**A channel row's *Fixed since* must be derived, never stamped from the
branch date.**  It is the date the channel first published a release
whose revision contains its branch's fixing commit.  Resolve it from the
`nix-releases` bucket with the installed helper:

```
~/src/sctphantom/scripts/nixos-first-shipped <channel> <commit>
```

**Invoke it by that absolute primary-checkout path, never as
`./scripts/…` from the auto-update worktree.**  `scripts/` is one of the
guarded paths: the agent can commit to the `auto-update` branch, so the
worktree copy is untrusted code, and the wrapper's guard only compares it
against `origin/main` once at start-up.  Running the primary checkout's
copy keeps what executes to what you have reviewed and merged — the same
reason `ExecStart` points at the primary checkout's wrapper.  The
worktree copy exists only so the file is under version control; don't run
it.  Pass the *master*
commit for `nixos-unstable`, `nixos-unstable-small`, and
`nixpkgs-unstable`, and the *release-26.05* commit for `nixos-26.05` and
`nixos-26.05-small` — a release channel ships its own branch's backport,
not master's commit.  These dates differ by days and are the whole point
of the group: the branches picked up 6.18.42 on/after 2026-08-03, and each
channel republished it once its jobset passed — resolve the exact per-row
dates with `nixos-first-shipped` rather than stamping the branch date.

The three unstable channels are genuinely distinct and can hold different
kernels: `nixos-unstable` is gated on a full NixOS jobset and can sit
days behind `master`, `nixos-unstable-small` on a reduced jobset and
leads, and `nixpkgs-unstable` is a separate channel — aimed at Nix users
on other operating systems, so not gated on the NixOS tests — that a
bare `nixpkgs` flake registry input resolves to by default (a user or
system registry entry can override it).  Don't assert a ranking between
the unstable channels beyond what the pins show: they routinely hold the
same version.  The GitHub channel *branches* are updated to
exactly the channel pins, so no separate check is needed for flake inputs
pinned to a channel branch.

## Proxmox kernel version source

*Seeding-and-adoption method — see "Routine run scope" above.  The
`Packages.gz` index is gzipped; `zcat` is in the headless allowlist.*

Proxmox ships its **own** Ubuntu-derived kernel (`proxmox-kernel-*`) with a
Debian userland, so the Debian madison feed does not cover it.  Pull the
kernel version from the `pve-no-subscription` `Packages` index.  VE 9 is
trixie-based, VE 8 bookworm-based:

```
url=http://download.proxmox.com/debian/pve/dists/<trixie|bookworm>/pve-no-subscription/binary-amd64/Packages.gz
curl -fsSL "$url" | zcat | grep -A3 '^Package: proxmox-default-kernel'
```

The default kernel *series* is whatever the highest-versioned
`proxmox-default-kernel` meta-package depends on — check it each time, it
moves.  Every PVE series carries SCTP and is in-window (the bug is ancient),
so there is no "predates the bug" shortcut: each series needs the
cherry-pick to be fixed.  At seed both maintained series carry it —
`proxmox-kernel-7.0` (PVE 9) and `proxmox-kernel-6.8` (PVE 8), CVE-tagged
2026-08-07.

**Two sources — only one is authoritative for the version.** The
*Current kernel* column is the `proxmox-kernel-<series>` build published
in `pve-no-subscription` (read it from the same Packages.gz — the
per-series package entries, not just the `proxmox-default-kernel` meta;
take the highest `rel`).  That is the build a host actually installs.
The pve-kernel **git changelog leads apt** — a build is committed there
before it reaches any apt channel (git → pvetest → pve-no-subscription →
enterprise) — so **never copy a changelog version into *Current
kernel***; reading the version from git on one run and apt on the next
is exactly what makes the column bounce forth-and-back.  Use the git
changelog only to confirm a cherry-pick.  If it shows the CVE cherry-pick
in a build `pve-no-subscription` has not yet published, the fix is
*staged*, not shipped: mark `:warning: Staged`, keep *Current kernel* at
the published version, and flip to `:white_check_mark: Fixed` only when
the fixed build appears in `pve-no-subscription`.

Whether an in-window Proxmox kernel carries the fix tracks its Ubuntu
series, not Debian's.  **A named cherry-pick is not the only fix
path.**  For a series Ubuntu still maintains, the fix can arrive
silently inside an `update sources to Ubuntu-<base>` rebase, with no
CVE-named changelog line — the ghostlock tracker misread PVE 8's
default 6.8 as vulnerable for a month by grepping the changelog for
the CVE alone.  On every run, for each live in-window series, take
the newest `update sources to Ubuntu-*` base version from the
changelog and compare it against Ubuntu's fixed version for that
series in the Ubuntu CVE tracker
(`https://ubuntu.com/security/cves/CVE-2026-64564.json` — the
`packages[].statuses[]` entries; `released` + version).  Base ≥
Ubuntu's fixed version ⇒ the PVE build carries the fix.  Kernel.org
EOL for the series is irrelevant here — Ubuntu keeps fixing series
long after upstream EOL.  Named cherry-picks remain the signal only
for series Ubuntu no longer fixes (superseded/`old` series, and
opt-ins whose Ubuntu HWE source is EOL).  To confirm a cherry-pick,
read the packaging changelog in Proxmox's kernel git, where Proxmox
lists every security cherry-pick by name/CVE.  The cgit HTML may be
gated, so read it from the shared local clone at
`~/src/proxmox/pve-kernel` via its `origin/...` refs — the wrapper
refreshes it each run:

```
git -C ~/src/proxmox/pve-kernel show origin/master:debian/changelog
```

Branches are named `<debian-suite>-<series>` — `bookworm-6.8`,
`trixie-6.17` — except the newest series on the current suite, which lives
on `master`.  **Don't assume a mapping.** PVE switches its default kernel
series during a release's lifetime and adds opt-in series alongside it, so
resolve the series first (`proxmox-default-kernel` for the default, the
`proxmox-kernel-*` metapackages for opt-in), then pick the branch that
matches:

```
git -C ~/src/proxmox/pve-kernel branch -r
```

Confirm the branch is the one you meant by checking that its changelog head
names that series, then read `debian/changelog` and `patches/` from it.  A
series that PVE has moved off is still a live branch here, so reading a
stale one reports "no cherry-pick" from a kernel nobody runs.  For an
`old` row's series, refresh *Current kernel* from the same Packages.gz
pull as the rest, but only re-read its changelog branch if that package
version actually moved.

Do not clone it per run: it is a shared reference like
`~/src/linux/stable`, and a clone made inside the worktree leaves untracked
debris that stalls every later run.

The enterprise repository (`enterprise.proxmox.com`) is HTTP-auth-gated
(401 without subscription credentials), so it cannot be polled headlessly.
Track `pve-no-subscription` only: packages flow pvetest →
pve-no-subscription → pve-enterprise, so no-subscription is strictly the
leading indicator and enterprise receives the same kernels later.

## Rocky / Amazon kernel version source (RPM repodata)

*Seeding-and-adoption method — see "Routine run scope" above.  These
indexes are gzipped; `zcat` is in the headless allowlist.*

**For the EL rows, Red Hat's security data is the authoritative leading
signal** — RHEL is upstream of Rocky and AlmaLinux, so neither can be fixed
before RHEL is.  Because the bug is ancient, all three EL lines (4.18 /
5.14 / 6.12.0) carry SCTP and are in-window — do **not** rate any EL row
"not affected".  At seed Red Hat has published **no** record for this CVE:
`https://access.redhat.com/security/cve/CVE-2026-64564` returns HTTP 404,
so every EL row is `:x:` Vulnerable, awaiting an RHSA.  Module posture,
worth a prose note but **not** a verdict change, is uniform across the
family (verified on live hosts and corroborated from BaseOS
`filelists.xml.gz`): on Rocky/RHEL **8, 9, and 10 alike** `sctp.ko` ships
in `kernel-modules-extra` — not the base kernel packages — and every build
of that package installs `/etc/modprobe.d/sctp-blacklist.conf`
(`blacklist sctp`, plus `sctp_diag`), so `sctp` never autoloads on a
stock EL host.  The blacklist is autoload-only — `modprobe sctp` still
loads it wherever the package is installed — so it does not close the
local vector.  Read the
CSAF/VEX record once it exists (the hydra securitydata
API and the access.redhat.com CVE page are JS-rendered / 404 headlessly):

```
curl -fsSL 'https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-64564.json'
```

In the VEX record, `product_status.known_affected` /
`known_not_affected` carry the per-product verdicts (with `flags` the
justification) and `remediations` the fix state; a shipped RHSA
appears as a `vendor_fix` remediation with the fixed kernel NVR.
When one appears, that NVR is the target; Rocky rebuilds it as an
RLSA, with AlmaLinux the fastest rebuild (cross-check OSV
`https://api.osv.dev/v1/vulns/CVE-2026-64564`).  The RPM repodata below then
confirms the Rocky ship and gives the current NVR.

Both ship `kernel` as an RPM; pull versions straight from repodata
(`repomd.xml` → the `*-primary.xml.gz` index).  The EL `os/` repos
accumulate every point release's kernel, so pick the numerically-highest
`rel` (`sort -V`).

- **Rocky** BaseOS: `https://dl.rockylinux.org/pub/rocky/<8|9|10>/BaseOS/x86_64/os`.
  Verdicts follow the Red Hat record: at seed all of Rocky 8 / 9 / 10 are
  affected, awaiting an RHSA.  An affected row flips only when the BaseOS
  kernel NVR reaches the RHEL fixed build.
- **Amazon Linux**: the machine-readable ALAS signal is the repodata
  **`updateinfo.xml.gz`** (maps CVE → ALAS → fixed kernel NVR); the per-CVE
  ALAS HTML pages are JS-rendered and return nothing headlessly, so reading
  them falsely sees "no advisory".  Resolve the mirror, fetch
  `<base>repodata/updateinfo.xml.gz` (plain filename) and grep the CVE for
  the ALAS id + fixed `kernel*` version; check **all** streams (AL2023
  `kernel` 6.1, opt-in `kernel6.12`, `kernel6.18`), and read current versions
  from `primary.xml.gz`.  All three AL2023 streams are in-window (as is
  AL2's 4.14, though AL2 is untracked).  Mirror:
  `…/al2023/core/mirrors/latest/x86_64/mirror.list`.  (AL2 is EOL and
  untracked — no AL2 repodata pulls.)

## Debian kernel version source

**The security tracker, not a madison base-version compare, is
authoritative for Debian status.** Two traps make a naive version check
wrong: the base suite lags the `-security` upload that ships the fix, and
Debian often backports the fix to a version *below* the upstream
first-fixed release.  Every Debian kernel carries SCTP and is in-window —
there is no "predates the bug" suite here.  At seed the tracker resolves
trixie (`6.12.101-1`) and sid (`7.1.7-1`) *fixed*, and bookworm
(`6.1.180-1`) and bullseye (`5.10.262-1`) *vulnerable* (their branches
carry no backport).

Read status and fixed version straight from the security tracker. WebFetch
the human-readable per-CVE page, or `curl` the JSON and read the
`CVE-2026-64564` block for each release's `status` (resolved/open) and the
version under `repositories` (a `<suite>-security` entry means the fix
shipped as a security update):

```
curl -fsSL 'https://security-tracker.debian.org/tracker/data/json'
```

Use the dak madison API only for the base-suite version and the
sid/testing lineage (unstable=sid, testing=forky, stable=trixie,
oldstable=bookworm, oldoldstable=bullseye):

```
curl -fsSL 'https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm,bullseye&text=on'
```

For a *Fixed since* date, use the `first_seen` of the fixed version in
snapshot.debian.org:

```
curl -fsSL 'https://snapshot.debian.org/mr/package/linux/<version>/srcfiles?fileinfo=1'
```

Debian autoloads the `sctp` module on first use of an SCTP socket and does
not blacklist it, so any Debian host running an SCTP service loads the
vulnerable code.

## Key sources to monitor

| Source | URL |
|---|---|
| Researcher write-up (Tencent Matrix) | <https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564> |
| Kernel fix (v7.2-rc5) | <https://git.kernel.org/stable/c/9b2854f86f0b56e9027d68e7a3fc909d1a9b566f> |
| Introducing commit (v2.6.25) | <https://git.kernel.org/stable/c/42e30bf3463cd37d73839376662cb79b4d5c416c> |
| CVE record | <https://www.cve.org/CVERecord?id=CVE-2026-64564> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-64564> |
| Debian package madison (dak-backed) | <https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm,bullseye&text=on> |
| Red Hat security data | <https://access.redhat.com/security/cve/CVE-2026-64564> |
| AlmaLinux errata | <https://errata.almalinux.org/> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| Proxmox advisories (thread) | <https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/> |

For machine-readable data, prefer API/feed endpoints over HTML pages —
several distro sites are JS-rendered SPAs that don't render via WebFetch.

## Platform-specific notes

- **Reachability, not architecture:** SCTPhantom is architecture-independent;
  what gates it is the `sctp` module in use + ADD-IP/ASCONF negotiated +
  AUTH, not the CPU.  Record host posture in prose, never as a column.
- **EL family (Rocky/RHEL/Alma/Oracle/CloudLinux):** all of EL8 (4.18),
  EL9 (5.14), and EL10 (6.12.0) carry SCTP and are in-window; at seed Red
  Hat has published no record (404), so all are `:x:` awaiting an RHSA.
  All of **EL8/9/10** ship `sctp.ko` in `kernel-modules-extra`, which
  installs a default `blacklist sctp` alongside it (autoload-only) — a
  prose note, not a verdict change.  AlmaLinux ships ahead of
  Rocky/RHEL and is the leading indicator for the fix.
- **Debian / Ubuntu / Proxmox VE:** every kernel here is in-window (the bug
  is ancient) — trixie/sid are fixed, bookworm/bullseye are not; PVE 9
  (7.0) and PVE 8 (6.8) both carry the 2026-08-07 cherry-pick.
- **NixOS:** seven refs are tracked, not one default — see *Local nixpkgs
  clone for NixOS channel verification*.  Resolve `linux_default` at each
  ref separately (it can differ between channels) and decide each verdict
  by whether that series carries the backport; the default `linux_6_18`
  (≥ 6.18.42) is fixed.
- **Mitigation vs fix:** blocking the `sctp` module or disabling ADD-IP
  (`net.sctp.addip_enable=0`) leaves the kernel hole, never
  `:white_check_mark:`.  The two are not equivalent, either:
  `net.sctp.addip_enable=0` bounds only the **remote** surface (a local
  attacker enables ADD-IP/AUTH per-socket and authenticates its own ASCONF),
  whereas blocking the module removes the local vector too.  The EL-family
  autoload blacklist (8/9/10, via
  `kernel-modules-extra`) is autoload-only (an explicit `modprobe sctp`
  defeats it), so it does not even earn `:warning:` — the EL rows stay
  `:x:` with a prose caveat.  A `:warning:`
  needs a default that *materially* cuts exposure, not merely autoload.

## Known harmless warnings during build

PaperMod's templates still call `.Language.LanguageDirection` and
`.Language.LanguageCode`, which Hugo deprecated in 0.158.0.  The build emits
`WARN deprecated:` lines for both.  Upstream theme issue — don't try to fix
it in this repo.

## License

The tracker content is licensed under **CC BY 4.0** (see `LICENSE` at the
repo root).  Copyright © 2026 Kimmo Suominen.  The site footer credits both
the author and the licence.
