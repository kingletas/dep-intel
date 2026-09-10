# Contributing

Thanks for looking. This is a small tool with a narrow purpose, so the most
useful contributions are usually a wrong answer you can reproduce.

## The one rule that is not negotiable

**Undecided is never clean.**

When the tool cannot decide whether an installed version is affected, it must
say so. It must never fall through to *not affected*. A change that makes a
previously-`unresolved` case silently pass is a regression even if every test
is green, because the whole value of a scanner is that its silence means
something.

If you are adding a comparator, a parser or an ecosystem, the question to
answer in the pull request is: **what does this do when it cannot tell?**

## Getting set up

There is nothing to install:

```bash
git clone https://github.com/kingletas/dep-intel && cd dep-intel
```

```bash
make check
```

You get the linters, the unit suite and the end-to-end suite, and none of them needs the network. `tests/run.sh` builds a temporary store and a
throwaway lockfile, so it never touches your real one.

## No third-party imports

The standard library only, and this is a hard constraint rather than a
preference. A security tool that needs a package manager is a security tool
that stops being run on the machine where it matters. **Python 3.9 is the
floor**, which is why `ruff.toml` pins `target-version = "py39"` — otherwise
a linter suggestion quietly raises it.

The one exception is `tomli` on 3.9 and 3.10, and it is optional: without it
the TOML lockfile parsers report that they were skipped.

## Reporting a wrong answer

The most valuable issue is a **false negative** — a dependency that is
vulnerable and was not reported. Please include:

- the ecosystem, the package, and the exact installed version;
- the advisory id (`GHSA-…`, `PYSEC-…`, `CVE-…`);
- what `dep-intel cve <id>` prints, which shows the stored ranges.

A false positive is worth reporting too, but a false negative is the one that
matters, because nothing else will find it.

## Adding an ecosystem

Four things, in this order:

1. A version comparator in `versions.py`, with an ordering table in the tests.
   **Include the cases you got wrong while writing it** — the existing tests
   name theirs, because those are what a later refactor breaks first.
2. A lockfile parser in `manifests.py`, plus a fixture in the test suite.
3. An entry in `ecosystems.REGISTRY`, declaring the storage key, the scheme
   **by name**, and where the feed comes from.
4. Name normalisation in `versions.normalize_name` if the ecosystem is
   case-insensitive or has a canonical form. PyPI's PEP 503 folding is the
   worked example — and Go is the counter-example, because a module path is
   case-sensitive and folding it matches the wrong module.

Four questions the registry exists to keep separate, because they stopped
having the same answer once anything but a language registry was added:

| | |
|---|---|
| What key identifies the advisory? | `Packagist` collapses its mirror suffix. `Ubuntu:24.04:LTS` must keep its release, or one release's advisories decide another's machine. |
| Which comparator orders it? | Declared by name in the registry so `ecosystems.py` imports nothing. An ecosystem with no comparator resolves to **no scheme**, which makes every match `unresolved` — never decided by the nearest available one. |
| Where does the feed come from? | An OSV bucket, or something else. Magento has no bulk feed at all and is built from NVD's CPE data. |
| Is the manifest name the advisory name? | Usually. A Terraform provider is locked as `registry.terraform.io/hashicorp/aws` and published as a Go module, so `MANIFEST_TO_ADVISORY` translates. |

**The bar is the same as everywhere else in this tool: say what you cannot
tell.** If a name is derived by convention rather than looked up, report the
derivation — a name that matches nothing is indistinguishable from a name
with nothing against it. If a version is a moving tag rather than a pin, say
it is unpinned rather than resolving it to a number nobody chose.

## Style

Comments explain **why**, including what an earlier version got wrong. That
is most of the value in a file like `versions.py`, where the code is short
and the reasoning is not.

`make check` runs `ruff` and `shellcheck` when they're installed and says "skipped" when they aren't. CI installs both, so a pull request has to pass them.
