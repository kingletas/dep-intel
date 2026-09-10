# Security Policy

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability
reporting on this repository (*Security* → *Report a vulnerability*), or
email **code@kingletas.com**.

Include what you did, what happened, and what you expected. A proof of
concept is welcome but not required. This is a personal project maintained by
one person, so expect a first response in days rather than hours.

## Supported versions

The latest release on `main` is the supported version. There are no long-term
support branches; fixes ship forward.

## What this tool is, and what it is not

**A clean result means no advisory in your local store on the sync date names
an installed version.** It does not mean your dependencies are safe, and it
does not mean your code is. The store goes stale the moment a new advisory is
published, which is why every report prints its sync date and a store older
than seven days says so on every scan.

**A missed vulnerable dependency is a bug worth reporting.** So is a case
where the tool reports *not affected* rather than *unresolved* — see below.

## The failure mode this project treats as most serious

**A silent false negative.** A version bound the comparator cannot parse, an
advisory shape the ingester drops, a lockfile format it half-reads — anything
that produces a confident *no findings* where the honest answer is *I could
not check*.

That is why undecided cases are reported rather than cleared, why a feed that
fails halfway is rolled back rather than half-committed, and why an
interpreter without a TOML parser makes the tool announce that it did not
read your `uv.lock`.

If you find a case where the tool says nothing and should have said something,
that is the report this project most wants.

## The scanner's own attack surface

`dep-intel` parses input it does not control, and treats it that way.

| Surface | Handling |
|---|---|
| **Advisory feeds** | HTTPS only — a plain-`http` URL is refused, not upgraded. The archive is bounded before it is trusted: entry count, per-entry uncompressed size, and total expansion. A record that is not the documented shape is counted and skipped. |
| **Lockfiles** | Parsed as data. No file is executed, no `setup.py` is imported, no resolver is invoked. A malformed lockfile is reported, never fatal. |
| **The repository tree** | Walked with a depth limit; symlinked directories are not followed, so a symlink pointing up the tree cannot make the walk cycle. |
| **The local store** | SQLite, parameterised queries throughout, outside every repository being scanned. |
| **The network** | Only `sync` touches it. `scan`, `sweep`, `affected`, `cve`, `inventory`, `status` and `test` never do. |

## What it deliberately does not do

- **It never sends your dependency graph anywhere.** There is no telemetry,
  no API call per package, and no opt-out needed because there is nothing to
  opt out of.
- **It does not modify your project.** No lockfile is rewritten, no version
  is bumped, nothing is installed. It reports the fixed version and stops.
