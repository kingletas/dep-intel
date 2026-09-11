<h1 align="center">🛡️ dep-intel</h1>

<p align="center">
  Know which of your dependencies are vulnerable — <em>without telling anyone what you run.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-3776ab">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-none-brightgreen">
  <img alt="Ecosystems" src="https://img.shields.io/badge/ecosystems-9-blue">
  <img alt="Output" src="https://img.shields.io/badge/output-text%20%7C%20JSON%20%7C%20SARIF-8957e5">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
</p>

---

```bash
dep-intel sync            # download OSV + CISA KEV into a local SQLite store
dep-intel scan .          # match this repository's lockfiles against it
dep-intel sweep           # every repository under your configured roots
dep-intel host            # match the operating system's own packages
```

**Nine ecosystems:** Composer, npm, PyPI, RubyGems, crates.io, Go, GitHub Actions, Adobe Commerce / Magento, and Ubuntu.

## Why another dependency scanner

**Because the others ask a server about your dependencies, and this one does not.**

A scanner that queries an API per package tells that API exactly what software you run and at which versions. That is a useful thing for you to know and an extremely useful thing for somebody else to know. `dep-intel` downloads the **entire** advisory feed and matches locally, so no package name, version, path or repository name ever leaves the machine. Offline operation is not a mode — it is the only mode there is.

The cost is a one-time ~400 MB download. The benefit is that your dependency graph is not a request log somewhere.

> **One feed is a query rather than a download, and it is labelled as such.** Adobe Commerce ships from `repo.magento.com` rather than Packagist, so no bulk feed carries an advisory for it at all — `dep-intel` builds that one from NVD's CPE data instead. The query names a **product** and nothing else: no installed version, no package list, no repository name, no path. What NVD can learn is that somebody asked about Adobe Commerce, not what they are running.

> **A Mage-OS store is checked as the Magento release it is built on.** Mage-OS locks no `magento/*` package, so its edition, `mage-os/product-community-edition`, is matched against Magento Open Source's advisories at the version in its `extra.magento_version`. Each Mage-OS module is checked as the `magento/*` package it replaces, at the exact version its `replace` names. A finding is reported against the Mage-OS package and names the Magento package and version it was matched as. An edition with no `extra.magento_version` is listed as undecided, never as clean. `dep-intel affected <CVE>` finds these packages the same way.

## Install

No dependencies, no packaging, nothing to build:

```bash
git clone https://github.com/kingletas/dep-intel && cd dep-intel && make install
```

`make install` copies `bin/dep-intel` and `bin/dep-intel.d/` into `~/bin` by default; pass a prefix (`make install PREFIX=/usr/local/bin`) for anywhere else. `make help` lists the rest. Python **3.9 or newer** and `bash`, and **no third-party imports** — a scanner that needs a particular environment is a scanner that gets skipped on the machine where it matters.

> On Python 3.9 and 3.10, `uv.lock`, `poetry.lock` and `Cargo.lock` need `tomli` (`tomllib` is 3.11+). Without it those files are **skipped and reported as skipped**, never silently ignored — `doctor` says so, and so does every scan.

## Use it

```bash
dep-intel sync -n
```

`-n` prints what it would download and how big it is before fetching anything. Then:

```bash
dep-intel sync
```

| Feed | Advisories | Download |
|---|--:|--:|
| `osv:npm` | ~227,000 | 212 MB |
| `osv:Ubuntu:<release>` | ~11,900 | 136 MB |
| `osv:PyPI` | ~24,600 | 32 MB |
| `osv:Go` | ~8,900 | 11 MB |
| `osv:Packagist` | ~6,900 | 10 MB |
| `osv:crates.io` | ~2,700 | 3 MB |
| `osv:RubyGems` | ~4,700 | 4 MB |
| CISA KEV | ~1,700 | 2 MB |
| `osv:GitHub Actions` | ~55 | 97 KB |
| `nvd:Magento` | ~220 | query, not a download |

A full sync takes about **2m30s** on a warm connection. `--ecosystem npm` syncs just one.

**`--ecosystem ubuntu` means the release this machine runs**, resolved from `/etc/os-release`. The whole-Ubuntu feed is 670 MB against 136 MB for one release, and advisories for a release nothing here runs cannot produce a finding — only a longer sync and a larger store. If the release cannot be read, `dep-intel` refuses rather than guessing: matching a 24.04 machine against 22.04 advisories is wrong in both directions at once, clearing real findings and inventing others.

```bash
dep-intel scan .
```

Reads `composer.lock`, `package-lock.json`, `uv.lock`, `poetry.lock`, `requirements.txt`, `Gemfile.lock`, `Cargo.lock`, `.terraform.lock.hcl` and `.github/workflows/*.yml`, matches every locked version, and prints findings with the fixed version and an evidence line. `--format json|sarif|markdown`, `--output FILE`, `--no-dev` to skip dev dependencies.

## The rule the whole tool rests on

> **Undecided is never clean.**

When a version comparator cannot parse a bound, the package goes into `unresolved` and is reported as such. It never falls through to *not affected*.

A scanner that turns *I could not check* into *you are fine* is worse than no scanner, because it manufactures confidence. Every output format carries the unresolved count, the Markdown report gives it its own section, and SARIF puts it in `invocations[].properties.unresolvedMatches`.

The same instinct runs through the rest: a feed that fails halfway is rolled back rather than half-committed, a **withdrawn** advisory is dropped rather than reported, and a constraint file with no lockfile beside it is named as a coverage gap rather than skipped in silence.

## Severity and confidence are separate

Severity is a property of the weakness. Confidence is a property of *this particular match*. Collapsing them into one number destroys the only signal you can act on — a CVSS 9.8 matched through a bound that would not parse is not the same claim as one matched exactly.

| Confidence | What produced it |
|---|---|
| `certain` | A version range **and** the advisory's own version list agree |
| `very-high` | A bounded version range, or an enumeration where no ranges are published |
| `high` | An open-ended range — introduced, with no published fix |
| `medium` | The advisory lists this exact version although its ranges exclude it |

CI applies both axes:

```bash
dep-intel scan . --fail-on high --min-confidence high --format sarif --output results.sarif
```

That fails a well-evidenced high finding and only **warns** on a critical one that is not. A **CISA Known Exploited** entry fails regardless of either axis, because *someone is exploiting this today* is a different kind of fact from *this would be bad if exploited*.

## Lockfiles only, and that is deliberate

`composer.json` and `pyproject.toml` carry a *constraint* — `^8.1`, `>=2,<3` — and what is installed is whatever resolution picked on the day. Matching an advisory against a constraint answers *could this be vulnerable*, which is a much weaker question than *is it*. Where only a constraint file exists, `dep-intel` reports it as **unlocked** rather than guessing.

`requirements.txt` is the one exception: an `==` pin is exact and is used, and anything else is counted as unpinned and reported.

**A GitHub Action tag is the same problem wearing different clothes.** `actions/checkout@v5` is not a version — it is a major tag GitHub repoints as releases land, so the commit behind it today is not the commit behind it tomorrow. Resolving it to `5.0.0` would decide an advisory range against a version nobody pinned.

Only an exact `x.y.z` tag counts as locked; a floating tag is reported as unpinned, and a 40-character commit SHA — the strongest pin there is, and the one thing no version range can be ordered against — is reported as unmatchable rather than counted as checked.

## The trap in a Gemfile.lock

**Indentation is the grammar.** A gem locked to a version sits at four spaces; the six-space lines beneath it are that gem's *constraints*. Reading `rubocop (>= 1.75.0, < 2.0)` as a version invents a dependency at a version nothing installed — and in one real lockfile there are 27 such lines against 28 real gems, so getting it wrong roughly doubles the inventory with fiction.

**A platform suffix looks exactly like a prerelease and means the opposite.** Bundler writes `nokogiri (1.13.0-x86_64-linux)`, and `Gem::Version` reads a hyphen as the start of a prerelease — so left alone that version sorts *below* plain `1.13.0` and an advisory range would miss it. The suffix is stripped using the lockfile's own `PLATFORMS` section rather than a guess at what a platform looks like: any pattern loose enough to catch `arm64` also mangles a legitimate `1.0.0-armadillo`.

**A `PATH` gem is the project itself** and a `GIT` gem is pinned to a revision no advisory range can speak about. Both are reported as coverage gaps rather than dropped.

## Two ecosystems that are not what they look like

**Ubuntu.** Advisories name the **source** package and `dpkg` lists **binary** packages: a notice for `apache2` covers `apache2-bin`, `apache2-data` and `apache2-utils`, none of which is called `apache2`. On a typical desktop 3,439 binary packages come from 1,820 sources, so matching binary names would miss most of the machine in silence. The source name is matched and the binary name is carried into the finding, so the result still says what to update.

The source *version* is used too — `bsdutils` is `1:2.39.3-9ubuntu6.6` as a binary and `2.39.3-9ubuntu6.6` as a source, a different epoch, and 39 packages here differ that way.

Ubuntu also needs its own comparator, and the reason is worth stating because the failure would have been silent: **semver's regex matches a dpkg version and gives it the wrong meaning.** It reads the `-1028.33` of `6.8.0-1028.33` as a *prerelease*, which sorts below plain `6.8.0` — so an advisory bounded at `introduced: 6.8.0` would have cleared a vulnerable kernel.

`dep-intel` implements Debian policy 5.6.12 instead, including the two rungs nothing else here has: a `~` that sorts below the *end of a string* (`1.0~rc1` < `1.0`), and an epoch. It is checked against `dpkg --compare-versions` itself over 20,231 pairs.

**Terraform.** A provider is locked as `registry.terraform.io/hashicorp/aws` and its advisories are published in the **Go** ecosystem as `github.com/hashicorp/terraform-provider-aws`. The translation is the registry's own naming convention, and it is a convention rather than a lookup — a provider whose repository is named differently derives to a module nothing has published an advisory for, and **a name that matches nothing looks exactly like a name with nothing against it**. Every derivation is reported for that reason, and a provider from a private registry is named as not checked.

## Across many repositories

```bash
dep-intel sweep
```

Walks every git repository under `$DEP_INTEL_ROOTS` and prints a table. With no roots set, it walks the current directory, so `cd` to the folder that holds your projects first, or set the roots once: `export DEP_INTEL_ROOTS=~/code:~/work`. It stops at nested repositories, so a parent does not absorb its children's dependencies. Then:

```bash
dep-intel affected CVE-2021-44228
```

answers *which of my repositories carry this*, from the local inventory, with no network at all.

## Commands

| | |
|---|---|
| `sync` | download OSV + KEV. **The only command that touches the network.** |
| `scan` | match one repository against the store |
| `sweep` | every repository under the configured roots |
| `host` | the operating system's own packages. Separate from `scan` because the host is not a repository: nothing commits it, and no CI gate can fire on it |
| `inventory` | what is installed where, without matching |
| `affected ID` | which repositories carry a given CVE / GHSA / PYSEC id |
| `cve ID` | one advisory, from the local store |
| `status` | store freshness, feed dates, counts |
| `doctor` | what is degraded, and why |
| `test` | the unit suite, standard library only |

## Environment

| | |
|---|---|
| `DEP_INTEL_DB` | store path (default `$XDG_DATA_HOME/dep-intel/dep-intel.db`) |
| `DEP_INTEL_ROOTS` | colon-separated roots for `sweep` (default: the current directory) |
| `NVD_API_KEY` | raises the Magento feed's request rate. Optional — the feed works without one, only slower |
| `NO_COLOR` | disable colour |

Exit `0` clean, `1` a finding breached the policy, `2` usage or environment error.

## What it cannot tell you

A clean result means **no advisory in your local store on the sync date names an installed version**. It says nothing about your code, and it goes stale the moment a new advisory is published. Every report prints the sync date, and a store older than seven days says so on every scan.

It also does not know about:

- private registries and vendored code, which no public feed describes;
- transitive dependencies not written into a lockfile;
- **Adobe Commerce modules and themes**, as opposed to the application itself. NVD carries CPE data for Commerce and Magento Open Source; a third-party extension has no advisory anywhere.
- **Terraform providers whose repository does not follow the registry naming convention**, and any provider served from a private registry. Both are reported, never absorbed.
- **Actions on a moving tag or a commit SHA**, for the reasons above. Both are reported.
- Ecosystems it does not support. It knows Composer, npm, PyPI, RubyGems, crates.io, Go, GitHub Actions, Magento and the Debian family; an Alpine or Red Hat release resolves to **no comparator at all**, so every match against one is `unresolved` rather than decided by the nearest available scheme. Adding one is a parser plus a comparator, not an architecture change.

## Licence

MIT — see [LICENSE](LICENSE). Advisory data is redistributed by nobody here: `sync` fetches it from [OSV](https://osv.dev) and [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) directly, under their own terms.
