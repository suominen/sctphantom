# SCTPhantom — Linux kernel SCTP ASCONF use-after-free tracking site

Source for the **SCTPhantom** patch-status tracker: a single-page site
recording which distributions have shipped a fix for the SCTP ASCONF
transport use-after-free in the Linux kernel.

## Where the facts live

Everything about the bug — CVE IDs, affected and fixed versions, upstream
fix commits, discovery and disclosure credit, and current per-distribution
patch status — belongs to the tracker page, not to this README:

- **Rendered:** <https://kimmo.cloud/sctphantom/>
- **Source:** [`site/content/_index.md`](site/content/_index.md)

Edit that file; everything else in this repo is build infrastructure.

None of it is restated here on purpose.  The tracker page is revised as
CVEs are assigned and distributions ship fixes — for the actively updated
trackers, twice daily by the auto-update agent — so any copy kept in this
README would silently rot.  Resist re-adding a summary.

Deployment plan and current setup state live in
[`WEBSITE.md`](WEBSITE.md).

## Local development

Requires Hugo extended (≥ 0.146.0) and Go (for Hugo Modules to fetch the
PaperMod theme).

### With Nix (recommended)

```sh
nix develop          # dev shell: hugo, go, git, resvg
cd site
hugo server          # local preview at http://localhost:1313/sctphantom/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the dev
shell auto-activates whenever you `cd` into the repo.

### Without Nix

Install Hugo extended ≥ 0.146.0 and Go ≥ 1.24 yourself, then:

```sh
cd site
hugo server          # http://localhost:1313/sctphantom/
```

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:/sctphantom/
make banner      # re-rasterise the social banner SVG → PNG (needs resvg + Roboto)
```

`make dist` runs `make build` first.  `make banner` is only needed after
editing `site/assets/sctphantom-tracker.svg`; the rendered PNG is committed.

## Repo layout

```
.
├── flake.nix              # Nix dev environment (hugo, go, git, resvg + RPM tools)
├── .envrc                 # direnv hook → `use flake`
├── .gitignore
├── Makefile               # `make build`, `make dist`, `make banner`
├── LICENSE                # CC BY 4.0
├── README.md              # this file
├── CLAUDE.md              # project instructions for Claude Code
├── WEBSITE.md             # publication plan / decisions log
├── scripts/               # auto-update agent: prompt + driver
├── systemd/               # user-level timer + service units
└── site/                  # Hugo project
    ├── hugo.toml
    ├── content/
    │   └── _index.md      # the tracker (single page)
    ├── assets/css/extended/custom.css   # PaperMod CSS overrides
    ├── assets/sctphantom-tracker.svg       # social-banner source (→ make banner)
    ├── static/sctphantom-tracker.png       # rendered OpenGraph banner (committed)
    ├── layouts/partials/  # PaperMod overrides (post_meta, extend_footer)
    ├── go.mod, go.sum     # Hugo Modules — pulls PaperMod theme
    └── …                  # standard Hugo skeleton
```

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
