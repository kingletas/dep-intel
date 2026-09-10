# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`docs/from-nothing.md`**, a guide from a clean machine to a first scan, a fix and a sweep, using an example lockfile.
- **A release workflow.** Pushing a `vX.Y.Z` tag checks that the tag matches `dep-intel --version`, runs `make check`, and publishes a GitHub release whose notes are that version's section of this file.

### Changed

- **`sweep` walks the current directory when `DEP_INTEL_ROOTS` is not set.** The old default was a list of folders from one particular machine, so on anyone else's machine it walked folders that were not there. To sweep a fixed set of folders from anywhere, set `DEP_INTEL_ROOTS`, for example `export DEP_INTEL_ROOTS=~/code:~/work`.
- **`make check` runs `ruff` as well as `shellcheck`**, and CI runs `make check` instead of its own list of the same steps. Pushes and pull requests run on Ubuntu only; the macOS run is still there, on demand.

### Fixed

- **The Markdown report's credit line was a wiki link to a note in a private notebook**, so it rendered as a broken link everywhere else. It names `dep-intel` in plain text now.

## [1.2.0] — 2026-09-07

### Added

- **RubyGems.** 4,707 advisories from OSV, a `Gemfile.lock` parser and a
  `rubygems` comparator. Ruby was the last common ecosystem with no feed, which
  meant a Ruby project could be scanned and reported clean without a single
  advisory having been consulted.
- **A `rubygems` version scheme**, because semver cannot stand in for it.
  Semver's expression stops after the third numeric segment and therefore
  *rejects* the four-segment versions RubyGems uses everywhere — `parser` ships
  3.3.12.0 and rack was fixed in 2.2.6.3 — so every bound in the feed would
  have been undecidable. The comparator implements `Gem::Version`'s canonical
  segments, and was checked against real `Gem::Version` over 6,496 pairs.

## [1.1.1] — 2026-09-02

### Fixed

- A uv project with `dynamic = ["version"]` reported itself as an unchecked
  coverage gap. `parse_uv_lock` already skipped the project being scanned, but
  the guard for a malformed entry ran first, and a dynamic version carries no
  `version` key for it to find. The source is decided first now, so the
  repository under scan is never counted as one of its own dependencies.

## [1.1.0] — 2026-09-01

Five ecosystems added, and the interesting part is that three of them are not
shaped like the first three at all. Composer, npm and PyPI share one answer to
*what identifies an advisory, what orders its versions, and where does its feed
come from* — a distribution, a registry proxy and a product with no bulk feed
each give three different answers, and the registry in `ecosystems.py` exists
because collapsing them was no longer possible.

### Added

- **Ubuntu**, matched against the release the host actually runs. `host` is a
  new command rather than part of `scan`, because the operating system is not
  a repository: nothing commits it and no CI gate can fire on it.
- **A dpkg comparator**, Debian policy 5.6.12, including the two rungs nothing
  else here has — a `~` that sorts below the end of a string, and an epoch.
  Checked against `dpkg --compare-versions` itself over 20,231 pairs drawn
  from a real installed set, and again in CI on every run.
- **Adobe Commerce / Magento**, built from NVD's CPE data. The one feed that
  is a query rather than a download, narrowed to name a product and nothing
  else, and labelled as such everywhere it appears.
- **crates.io, Go and GitHub Actions**, from their OSV buckets.
- **Terraform**, via the Go feed: a provider locked as
  `registry.terraform.io/hashicorp/aws` is matched as the Go module
  `github.com/hashicorp/terraform-provider-aws`.
- **`Cargo.lock`, `.terraform.lock.hcl` and `.github/workflows/*.yml`** as
  manifest formats.
- **A `related` table** for OSV's `related` and `upstream` fields, joined by
  the KEV catalogue alongside `alias`.
- **A coverage warning** naming any ecosystem whose packages were matched
  against a feed that has never been synced, and a **count of affected blocks
  dropped** for an unregistered ecosystem, printed by `sync`.
- **114 further assertions**, for 259 across 30 tests.

### Fixed

Four of these were found by writing the tests rather than by using the tool,
and every one of them fails silently:

- **A dpkg version parsed as semver gives the wrong answer rather than no
  answer.** semver's regex matches `6.8.0-1028.33` and reads the revision as
  a *prerelease*, sorting it below plain `6.8.0` — so an advisory bounded at
  `introduced: 6.8.0` would have cleared a vulnerable kernel. An unregistered
  ecosystem now resolves to no scheme at all, so it is `unresolved` rather
  than decided by whichever comparator was nearest.
- **An ecosystem suffix means two different things and was treated as one.**
  `Packagist:https://packages.drupal.org/8` names a mirror and collapses;
  `Ubuntu:24.04:LTS` names the *release* and must not, or a 22.04 advisory
  decides a 24.04 machine. Release scoping keys on the distribution rather
  than on registration, so an unregistered `Ubuntu:Pro:FIPS:16.04:LTS` is
  never truncated to bare `Ubuntu`.
- **The KEV catalogue reached none of the 11,853 Ubuntu advisories.** An
  Ubuntu record carries no aliases at all — it names its CVE under `related`
  — and the join went through `alias` alone, so every Ubuntu finding came
  back not-known-exploited by construction.
- **An Ubuntu advisory names the source package; `dpkg` lists binary
  packages.** 3,439 binaries come from 1,820 sources here, and the source
  *version* differs from the binary version for 39 of them, sometimes by an
  epoch. Matching binary names and versions would have missed most of the
  machine in silence.
- **`magento/product-enterprise-edition` had zero advisories in the store.**
  Commerce ships from `repo.magento.com`, so the Packagist feed's 366 Magento
  advisories are all for Open Source and Magento 1 names. A Commerce store
  scanned clean on the one package that decides whether the shop is
  exploitable; it now matches 198.
- **`.github` was invisible to discovery**, which skipped every dotted
  directory, so no workflow was ever read.
- **A bucket name containing a space or a colon was not URL-quoted**, so the
  `GitHub Actions` and `Ubuntu:*` feeds would have 404'd and ingested
  nothing — a clean scan for a reason unrelated to the code. CI now asserts
  the space-containing bucket ingests rows.
- **`scripts/install` was documented as the install command.** It is
  `make install`; the script is the implementation.

### Not added, and why

- **Rust as a lockfile ecosystem is present; Rust code here is not.** The
  `crates.io` feed is synced and `Cargo.lock` is parsed, but the Rust support
  has not yet been exercised against a real Rust project's lockfile.
- **Terraform providers have no ecosystem of their own.** They are Go
  modules and are matched as such. The name derivation is the registry's
  naming *convention*, not a lookup, so every derived name is reported: a
  provider whose repository is named differently would match nothing, and a
  name that matches nothing looks exactly like a name with nothing against
  it.
- **A moving action tag is not a version.** `actions/checkout@v5` is
  repointed as releases land, so it is reported as unpinned rather than
  resolved to `5.0.0` and decided against a range nobody pinned. A commit
  SHA is reported as unmatchable for the opposite reason: it is the
  strongest pin there is and cannot be ordered against a version range.
- **Alpine, Red Hat and the rpm family resolve to no comparator.** apk and
  rpm order versions differently from dpkg, and borrowing the nearest
  comparator is how a scanner returns a confident wrong answer.

## [1.0.0] — 2026-08-26

First release. Built against 59 real repositories and 13,229 locked packages,
which is where most of the entries below come from.

### Added

- **Offline advisory matching.** `sync` downloads the whole OSV feed for
  Composer, npm and PyPI plus the CISA KEV catalogue into a local SQLite
  store; everything else runs with no network at all. No package name,
  version, path or repository name is ever sent anywhere.
- **`scan`** over `composer.lock`, `package-lock.json` (v1, v2 and v3),
  `uv.lock`, `poetry.lock` and `requirements.txt`.
- **`sweep`** across every git repository under configured roots, and
  **`affected ID`** to answer *which of my repositories carry this CVE*.
- **Severity and confidence as independent axes**, with a CI policy that
  applies both — and a CISA KEV entry that fails regardless of either.
- **Output as terminal text, JSON, SARIF 2.1.0 and Markdown.**
- **145 assertions across 15 tests**, standard library only, plus an
  end-to-end suite that runs the installed pair.

### Fixed

Six defects found by the tool's own gates before the first release, listed
because each is a trap the next change could walk back into.

- **PEP 440 ordering put `1.0.dev1` above `1.0a1`.** A pure dev release sorts
  below every prerelease of the same version and an absent prerelease sorts
  above them; one flag cannot express both. Cross-checked against
  `packaging`, which this tool does not depend on.
- **A GIT range's bounds are commit SHAs.** PYSEC advisories publish one
  beside the real version range, and trying to order a 40-character hash
  against a version turned every decidable advisory into `unresolved` — 37 in
  one repository, 74 in another. Only `ECOSYSTEM` and `SEMVER` ranges decide.
- **No index on `affected(vuln_id)`.** Ingest rewrites an advisory's rows
  wholesale, so every record ran a full table scan. The first npm sync took
  **43 minutes; it now takes 28 seconds.**
- **npm hoisting counted one package twice.** `node_modules/lodash` and
  `node_modules/x/node_modules/lodash` are one package installed twice, and
  produced two identical findings for one advisory.
- **Nested repositories were counted by their parent as well as themselves**,
  reporting 20,923 packages across repositories that hold 13,229.
- **`2.6.0-cu124` is not valid PEP 440**, but PyTorch publishes it and PYSEC
  repeats it. Nine real findings were sitting in the unresolved bucket over
  one character.

### Known limits

- **Lockfiles only.** A constraint file with no lockfile is reported as a
  coverage gap rather than resolved to a guess.
- **`tomllib` is 3.11+.** On 3.9 and 3.10, `uv.lock` and `poetry.lock` need
  `tomli`; without it they are **skipped and reported as skipped**.
- **CVSS v4.0 base scores are not computed.** v4 is a 270-entry lookup table
  rather than a formula, and a wrong number in a security report is worse
  than an absent one — the advisory's qualitative band is used instead, and
  labelled as such.
- Composer, npm and PyPI only.

[1.0.0]: https://github.com/kingletas/dep-intel/releases/tag/v1.0.0
