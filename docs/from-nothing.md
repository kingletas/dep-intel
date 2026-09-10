# From nothing to a working dep-intel

This guide takes you from a machine that has never seen dep-intel to a real scan of a real lockfile. It takes about five minutes and a 12 MB download.

Every command below was run on a clean home folder on Ubuntu 24.04 with Python 3.12, and the output is copied from that run. Paths in the output are shortened to `~`.

## Contents

- [What you need](#what-you-need)
- [Step 1: install it](#step-1-install-it)
- [Step 2: download the advisories](#step-2-download-the-advisories)
- [Step 3: scan a project](#step-3-scan-a-project)
- [Step 4: fix it and scan again](#step-4-fix-it-and-scan-again)
- [Step 5: check every project at once](#step-5-check-every-project-at-once)
- [What the exit codes mean](#what-the-exit-codes-mean)
- [Where to go next](#where-to-go-next)

## What you need

- Python 3.9 or newer, and `bash`. Nothing else: dep-intel uses only Python's standard library.
- `git` and `make`, to fetch and install it.
- An internet connection for the download in step 2. After that, nothing touches the network.

Check your Python version:

```bash
python3 --version
```

## Step 1: install it

```bash
git clone https://github.com/kingletas/dep-intel && cd dep-intel
```

The run behind this guide cloned a local copy instead, because the GitHub address was not live yet, so this one command is not verified.

`make install` copies the tool into `~/bin`. Create that folder first if you don't have it:

```bash
mkdir -p ~/bin
make install
```

```text
installed dep-intel -> ~/bin
note: ~/bin is not on your PATH
dep-intel 1.2.0
```

The last line is the installed copy running, so you know the install worked. If you see the PATH note, add the folder for this terminal:

```bash
export PATH="$HOME/bin:$PATH"
```

On Ubuntu and Debian you only need that once: the default `~/.profile` adds `~/bin` to your PATH at your next login, as long as the folder exists. To install somewhere else, pass a folder that already exists, for example `make install PREFIX=~/.local/bin`.

## Step 2: download the advisories

dep-intel checks your dependencies against a copy of the advisory data that lives on your machine. Until you download it, the store is empty, and `doctor` says so:

```bash
dep-intel doctor
```

```text
dep-intel doctor

  python            3.12.3
  store             ~/.local/share/dep-intel/dep-intel.db   (not created yet)
  toml              tomllib
  advisories        EMPTY — run `dep-intel sync`
  inventory         empty — `dep-intel sweep` populates it
  host packages     Ubuntu:24.04:LTS
  root              ~/dep-intel
```

It exits with status 2, because a scan against an empty store could not find anything. The `root` line is the folder `sweep` would walk, which is wherever you run it from; step 5 covers that.

A full download covers nine ecosystems and is about 400 MB. For this guide, download only the PHP advisories (the Packagist feed) and CISA's list of vulnerabilities known to be exploited. Add `-n` to see what would be fetched without fetching it:

```bash
dep-intel sync --ecosystem Packagist -n
```

```text
dep-intel sync will download:

  osv:Packagist         10 MB   https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip
  kev                 unknown   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

  total 10 MB (plus anything sent without a length)
  into  ~/.local/share/dep-intel/dep-intel.db
```

Then run it for real. `-y` skips the confirmation prompt:

```bash
dep-intel sync --ecosystem Packagist -y
```

```text
osv:Packagist
  fetching https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip
  6989 advisories, 13319 affected packages, 131 withdrawn skipped, 0 malformed
  77 affected block(s) in 5 unregistered ecosystem(s) not stored: NuGet (52), Maven (21), SwiftURL (2), Pub (1), +1 more
kev
  fetching https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  1703 catalogue entries, 31 matched an advisory in the store

store: 6989 advisories, 31 known-exploited
```

The plan from `-n` prints again first; it's left out above. This took about six seconds. Your numbers will be a little higher, because new advisories are published every day. When you want every ecosystem, run `dep-intel sync` with no `--ecosystem`.

## Step 3: scan a project

dep-intel reads lockfiles, the files that record the exact version of every dependency you installed. Make a small example project whose lockfile pins an old version of Guzzle, a popular PHP HTTP client:

```bash
mkdir -p ~/projects/demo-shop && cd ~/projects/demo-shop
cat > composer.lock <<'JSON'
{
  "packages": [
    {"name": "guzzlehttp/guzzle", "version": "6.5.0"},
    {"name": "monolog/monolog", "version": "3.9.0"}
  ],
  "packages-dev": []
}
JSON
```

Scan it:

```bash
dep-intel scan .
```

```text
dep-intel — ~/projects/demo-shop
  2 package(s) from 1 lockfile(s) · store synced 2026-09-10T17:51:44+00:00

  HIGH CVSS 7.7  guzzlehttp/guzzle 6.5.0 (runtime)
      GHSA-25mq-v84q-4j7r  CVE-2022-31090
      CURLOPT_HTTPAUTH option not cleared on change of origin
      confidence: certain — version range and the advisory's version list agree (0 .. 6.5.8)
      manifest:   composer.lock
      fixed in:   6.5.8

  ...twelve more findings for guzzlehttp/guzzle...

  MEDIUM CVSS 5.9  guzzlehttp/guzzle 6.5.0 (runtime)
      GHSA-wpwq-4j6v-78m3  CVE-2026-55568
      guzzlehttp/guzzle: Silent HTTPS-Proxy Downgrade to Cleartext
      confidence: certain — version range and the advisory's version list agree (0 .. 7.12.1)
      manifest:   composer.lock
      fixed in:   7.12.1

  🟠 6 high · 🟡 8 medium
```

The output is trimmed in the middle. Here is how to read one finding:

- **The first line** is the severity, the package, and the version your lockfile pins.
- **The IDs** are the advisory's names. Search for any of them to read the full advisory.
- **`confidence`** says how sure the match is. `certain` means two independent parts of the advisory agree that your version is affected. Severity and confidence are separate on purpose: a severe advisory matched on weak evidence is a different claim from one matched exactly.
- **`fixed in`** is the first version without this problem.

The scan exits with status 1, because at least one finding is high severity.

## Step 4: fix it and scan again

Upgrading is your package manager's job. For this example, write a second project whose lockfile already has a fixed Guzzle:

```bash
mkdir -p ~/projects/demo-api && cd ~/projects/demo-api
cat > composer.lock <<'JSON'
{
  "packages": [
    {"name": "guzzlehttp/guzzle", "version": "7.15.2"},
    {"name": "monolog/monolog", "version": "3.9.0"}
  ],
  "packages-dev": []
}
JSON
dep-intel scan .
```

```text
dep-intel — ~/projects/demo-api
  2 package(s) from 1 lockfile(s) · store synced 2026-09-10T17:51:44+00:00

  no known vulnerable dependencies

  clean
```

This exits with status 0. "Clean" means no advisory in your local copy names these versions. It doesn't mean the code is safe, and it goes out of date as new advisories appear, so sync again before you rely on it.

## Step 5: check every project at once

`sweep` scans every git repository under a folder. Turn the two examples into repositories, then sweep the folder that holds them:

```bash
git -C ~/projects/demo-shop init -q
git -C ~/projects/demo-api init -q
cd ~/projects
dep-intel sweep
```

```text
dep-intel sweep — 2 repositories under ~/projects

  repository    pkgs  crit  high   med   low  KEV    ?
  demo-api        2     0     0     0     0    0    0
  demo-shop       2     0     6     8     0    0    0

  4 packages across 2 repositories in the inventory
```

It exits with status 1, because `demo-shop` still has high findings. With nothing else set, `sweep` walks the folder you run it from. To sweep the same folders from anywhere, list them in `DEP_INTEL_ROOTS`, separated by colons:

```bash
export DEP_INTEL_ROOTS=~/projects:~/work
```

A sweep also remembers what it found. When a new vulnerability makes the news, ask which of your projects carry it, with no network at all:

```bash
dep-intel affected CVE-2022-31090
```

```text
GHSA-25mq-v84q-4j7r
  CURLOPT_HTTPAUTH option not cleared on change of origin
  severity: high (CVSS 7.7), from cvss
  ✗ ~/projects/demo-shop
      guzzlehttp/guzzle 6.5.0 (composer.lock), confidence certain, fixed in 6.5.8
```

It exits with status 1 when any project carries the advisory, so you can use it in a script.

## What the exit codes mean

| Exit | Meaning |
|---|---|
| `0` | Nothing breached the policy, or you passed `--no-fail` |
| `1` | A finding breached the policy: high severity or worse by default, or anything on CISA's known-exploited list |
| `2` | A usage error, or the environment can't support the command, such as `doctor` finding an empty store |

That makes `dep-intel scan .` usable as a CI step as it stands. The README shows how to tune the policy with `--fail-on` and `--min-confidence`, and how to write SARIF for GitHub's code scanning.

## Where to go next

- [README](../README.md): every command, every lockfile format, and what a clean result can't tell you.
- [Architecture](architecture.md): how the download, the store and the matcher fit together.
- [CONTRIBUTING.md](../CONTRIBUTING.md): how to run the tests and add an ecosystem.
