#!/usr/bin/env python3
"""dep-intel — dependency vulnerability intelligence, offline.

Ingests the OSV advisory feeds and the CISA Known Exploited Vulnerabilities
catalogue into a local SQLite store, then matches every locked dependency in
a repository against it. The whole feed is downloaded and the matching runs
locally, so no package name, version, path or repository name is ever sent
anywhere -- an API that answers "is this package vulnerable" per query learns
exactly what you run.

Usage:
    dep-intel sync [--ecosystem NAME]... [-n] [-y]
    dep-intel scan [PATH ...] [--format FMT] [--output FILE]
    dep-intel sweep [--format FMT] [--output DIR]
    dep-intel host [--format FMT] [--output FILE]
    dep-intel inventory [PATH ...] [--format FMT]
    dep-intel affected ID
    dep-intel cve ID
    dep-intel status
    dep-intel doctor
    dep-intel test [-v]

Commands:
    sync        download OSV + KEV into the local store. The only command
                that touches the network.
    scan        match one repository's lockfiles against the store
    sweep       scan every git repository under the configured roots
    host        match the operating system's own packages. Separate from
                scan because the host is not a repository: nothing commits
                it, and no CI gate can fire on it
    inventory   list what is installed where, without matching
    affected    which repositories carry a given CVE / GHSA / PYSEC id
    cve         show one advisory from the local store
    status      store freshness, feed dates and counts
    doctor      check the environment and report what is degraded
    test        the tool's own gate -- comparators, parsers, matcher,
                ingestion and output, standard library only

Options:
    --ecosystem NAME    repeatable; default is every ecosystem with a feed,
                        plus this host's own Ubuntu release. `ubuntu` on its
                        own resolves to that release rather than to the
                        670 MB whole-distribution feed.
                        npm | PyPI | Packagist | crates.io | Go |
                        GitHub Actions | Magento | Ubuntu:<release>
    --format FMT        text | json | sarif | markdown        (default: text)
    --output FILE       write to a file instead of stdout
    --fail-on SEV       severity that fails the run            (default: high)
    --min-confidence C  confidence required to fail rather than warn
                                                              (default: high)
    --no-kev-fail       do not fail on a known-exploited finding
    --no-dev            ignore dev-scope dependencies
    --no-fail           always exit 0; report only
    -n, --dry-run       sync: show what would be fetched, and its size
    -y, --yes           sync: do not prompt
    -v, --verbose       show every undecided match rather than the first five

Environment overrides:
    DEP_INTEL_DB        path to the SQLite store
                        (default: $XDG_DATA_HOME/dep-intel/dep-intel.db)
    DEP_INTEL_ROOTS     colon-separated roots for `sweep`
                        (default: the current directory)
    NVD_API_KEY         raises the Magento feed's request rate. Optional;
                        the feed works without one, only slower.
    NO_COLOR            disable terminal colour

Exit status:
    0   clean, or reporting only
    1   a finding breached the policy
    2   usage error, or the environment cannot support the command
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ecosystems
import feeds
import hostpkgs
import manifests
import match
import nvd
import report
import store
import versions as V

VERSION = "1.2.0"


def _roots():
    env = os.environ.get("DEP_INTEL_ROOTS")
    if env:
        return [Path(p).expanduser() for p in env.split(":") if p]
    return [Path.cwd()]


def _human(n):
    if n is None:
        return "unknown size"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n / 1:.0f}{unit}"
        n /= 1024.0
    return f"{n:.0f}GB"


def _size(n):
    if n is None:
        return "unknown"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _store_meta(conn):
    rows = store.feed_status(conn)
    synced = max((r["synced_at"] for r in rows if r["synced_at"]), default=None)
    return {
        "synced": synced or "never",
        "store_vulns": store.counts(conn)["vulnerabilities"],
        "feeds": [r["name"] for r in rows],
        "tool_version": VERSION,
    }


def _warn_unsynced(conn, packages, notes):
    """Name any ecosystem whose packages were matched against nothing.

    A repository holding Rust or Go dependencies while the crates.io or Go
    feed has never been synced produces a clean report for a reason that has
    nothing to do with the code. Without this the report is indistinguishable
    from a genuine all-clear, which is the one thing this tool refuses to be.
    """
    present = {ecosystems.advisory_ecosystem(p.ecosystem) for p in packages}
    synced = {r["name"].split(":", 1)[1] for r in store.feed_status(conn)
              if r["name"] != "kev" and ":" in r["name"]}
    missing = sorted(e for e in present if e and e not in synced)
    if missing:
        notes.append(
            "no advisory feed has been synced for " + ", ".join(missing)
            + " — packages in those ecosystems were NOT checked, and this "
              "report says nothing about them")


def _warn_if_stale(conn, notes):
    rows = store.feed_status(conn)
    if not rows:
        notes.append("the advisory store is EMPTY — run `dep-intel sync` "
                     "before believing a clean result")
        return
    newest = max((r["synced_at"] for r in rows if r["synced_at"]), default=None)
    if not newest:
        return
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(newest)).days
    except ValueError:
        return
    if age >= 7:
        notes.append(f"the advisory store is {age} days old; a clean result "
                     "only speaks for advisories published before then")


# --------------------------------------------------------------------------

def cmd_sync(args) -> int:
    conn = store.connect()
    host_eco = hostpkgs.osv_ecosystem() or ""

    if args.ecosystem:
        ecos, unknown = [], []
        for name in args.ecosystem:
            # `Ubuntu` on its own means the release this machine runs. The
            # whole-Ubuntu feed is 670 MB against 142 MB for one release, and
            # advisories for a release nothing here runs cannot produce a
            # finding -- only a longer sync and a larger store.
            if name.strip().lower() == "ubuntu":
                if not host_eco:
                    print("dep-intel: this host's Ubuntu release could not be "
                          "read from /etc/os-release, so `--ecosystem ubuntu` "
                          "cannot be resolved. Name the release explicitly, "
                          "e.g. --ecosystem Ubuntu:24.04:LTS", file=sys.stderr)
                    return 2
                ecos.append(host_eco)
                continue
            entry = ecosystems.resolve(name)
            if entry is None:
                unknown.append(name)
            else:
                ecos.append(entry.key)
        if unknown:
            print(f"dep-intel: unknown ecosystem(s): {', '.join(unknown)}",
                  file=sys.stderr)
            print(f"           known: {', '.join(ecosystems.names())}",
                  file=sys.stderr)
            return 2
    else:
        ecos = ecosystems.default_sync_set(host_eco)

    plan = []
    for e in ecos:
        entry = ecosystems.REGISTRY[e]
        if entry.feed_kind == ecosystems.NVD:
            # A CPE query has no content-length to ask for, and it is a
            # handful of small pages rather than an archive.
            plan.append((f"nvd:{e}", nvd.NVD_API, None))
        else:
            url = feeds.osv_url(entry.bucket)
            plan.append((f"osv:{e}", url, feeds.head_size(url)))
    plan.append(("kev", feeds.KEV_URL, feeds.head_size(feeds.KEV_URL)))

    total = sum(s for _, _, s in plan if s)
    print("dep-intel sync will download:\n")
    for name, url, size in plan:
        print(f"  {name:<16} {_size(size):>10}   {url}")
    print(f"\n  total {_size(total)} (plus anything sent without a length)")
    print(f"  into  {store.default_path()}\n")

    if args.dry_run:
        return 0
    if not args.yes and sys.stdin.isatty():
        try:
            if input("proceed? [y/N] ").strip().lower() not in ("y", "yes"):
                print("aborted")
                return 0
        except (EOFError, KeyboardInterrupt):
            print("\naborted")
            return 0

    for e in ecos:
        entry = ecosystems.REGISTRY[e]
        kind = "nvd" if entry.feed_kind == ecosystems.NVD else "osv"
        print(f"{kind}:{e}")
        try:
            if kind == "nvd":
                s = feeds.sync_nvd(conn, e, os.environ.get("NVD_API_KEY", ""))
            else:
                s = feeds.sync_osv(conn, e)
        except feeds.FeedError as err:
            print(f"  FAILED: {err}", file=sys.stderr)
            print("  the previous store is intact — a partial feed is never "
                  "committed", file=sys.stderr)
            return 2
        print(f"  {s['records']} advisories, {s['affected']} affected packages, "
              f"{s['withdrawn']} withdrawn skipped, {s['skipped']} malformed")
        other = s.get("other_ecosystems") or {}
        if other:
            top = sorted(other.items(), key=lambda kv: -kv[1])[:4]
            shown = ", ".join(f"{k} ({v})" for k, v in top)
            more = "" if len(other) <= 4 else f", +{len(other) - 4} more"
            print(f"  {sum(other.values())} affected block(s) in "
                  f"{len(other)} unregistered ecosystem(s) not stored: "
                  f"{shown}{more}")

    print("kev")
    try:
        k = feeds.sync_kev(conn)
    except feeds.FeedError as err:
        print(f"  FAILED: {err}", file=sys.stderr)
        return 2
    print(f"  {k['catalogue']} catalogue entries, {k['matched']} matched an "
          "advisory in the store")

    c = store.counts(conn)
    print(f"\nstore: {c['vulnerabilities']} advisories, {c['kev']} known-exploited")
    return 0


def _scan_one(conn, root: Path, args, meta_extra=None):
    packages, skipped, locks = manifests.collect(root)
    findings, unresolved = match.scan_packages(
        conn, str(root), packages, include_dev=not args.no_dev)
    meta = {
        "repo": str(root),
        "packages": len(packages),
        "lockfiles": len(locks),
        "skipped": skipped,
        "notes": [],
    }
    meta.update(_store_meta(conn))
    if manifests.TOML_BACKEND is None:
        meta["notes"].append(
            "no TOML parser on this interpreter: uv.lock, poetry.lock and "
            "Cargo.lock were NOT read, so Python and Rust dependencies are "
            "under-reported")
    _warn_unsynced(conn, packages, meta["notes"])
    # Raised only when there is something for it to be about, so it is a note
    # on a finding rather than a banner on every scan.
    if any(f.ecosystem == "Magento" for f in findings):
        meta["notes"].append(
            "Magento findings come from NVD's CPE data, and its version "
            "ranges for Adobe products are not always consistent with the "
            "advisory text — CVE-2024-49521 is filed against Adobe Commerce "
            "'3.2.5 and earlier' on a product line that is 2.4.x. The range "
            "is reported as published rather than second-guessed; read the "
            "advisory before acting on a Magento range match")
    _warn_if_stale(conn, meta["notes"])
    if meta_extra:
        meta.update(meta_extra)
    return findings, unresolved, meta, packages


def _emit(findings, unresolved, meta, args, default_stream=sys.stdout):
    fmt = args.format
    if fmt == "json":
        text = report.render_json(findings, unresolved, meta)
    elif fmt == "sarif":
        text = report.render_sarif(findings, unresolved, meta)
    elif fmt == "markdown":
        text = report.render_markdown(findings, unresolved, meta)
    else:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                report.render_text(findings, unresolved, meta, fh,
                                   verbose=args.verbose)
            return
        report.render_text(findings, unresolved, meta, default_stream,
                           verbose=args.verbose)
        return
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        default_stream.write(text + "\n")


def _record_inventory(conn, root: Path, packages):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute("DELETE FROM package WHERE repo = ?", (str(root),))
    conn.executemany(
        "INSERT OR REPLACE INTO package"
        "(repo, manifest, ecosystem, name, version, scope, seen_at) "
        "VALUES (?,?,?,?,?,?,?)",
        [(str(root), p.manifest, p.ecosystem, p.name, p.version, p.scope, now)
         for p in packages])
    conn.commit()


def cmd_scan(args) -> int:
    conn = store.connect()
    paths = [Path(p).expanduser().resolve() for p in (args.path or ["."])]
    worst = 0
    for root in paths:
        if not root.is_dir():
            print(f"dep-intel: not a directory: {root}", file=sys.stderr)
            return 2
        findings, unresolved, meta, packages = _scan_one(conn, root, args)
        _record_inventory(conn, root, packages)
        conn.execute(
            "INSERT INTO scan(repo, started_at, packages, findings, "
            "unresolved, tool_version) VALUES (?,?,?,?,?,?)",
            (str(root), meta["synced"], len(packages), len(findings),
             len(unresolved), VERSION))
        conn.commit()
        _emit(findings, unresolved, meta, args)
        failing, _ = match.policy_verdict(
            findings, args.fail_on, args.min_confidence,
            fail_on_kev=not args.no_kev_fail)
        if failing and not args.no_fail:
            worst = 1
    return worst


def cmd_sweep(args) -> int:
    conn = store.connect()
    repos = []
    for r in _roots():
        if not r.is_dir():
            continue
        if (r / ".git").is_dir():
            repos.append(r)
        for child in sorted(r.rglob(".git")):
            if child.is_dir() and len(child.relative_to(r).parts) <= 4:
                repos.append(child.parent)
    repos = sorted({p.resolve() for p in repos})

    print(f"dep-intel sweep — {len(repos)} repositories under "
          f"{', '.join(str(r) for r in _roots())}\n")
    rows, worst = [], 0
    for root in repos:
        findings, unresolved, meta, packages = _scan_one(conn, root, args)
        _record_inventory(conn, root, packages)
        s = report.summarise(findings)
        rows.append((root, meta, s, len(unresolved)))
        if args.output:
            out = Path(args.output)
            out.mkdir(parents=True, exist_ok=True)
            name = str(root).replace(str(Path.home()), "").strip("/").replace("/", "-")
            sub = argparse.Namespace(**vars(args))
            ext = {"json": "json", "sarif": "sarif", "markdown": "md"}.get(
                args.format, "txt")
            sub.output = str(out / f"{name}.{ext}")
            _emit(findings, unresolved, meta, sub)
        failing, _ = match.policy_verdict(
            findings, args.fail_on, args.min_confidence,
            fail_on_kev=not args.no_kev_fail)
        if failing and not args.no_fail:
            worst = 1

    width = max((len(r.name) for r, _, _, _ in rows), default=10)
    print(f"  {'repository':<{width}}  {'pkgs':>6} {'crit':>5} {'high':>5} "
          f"{'med':>5} {'low':>5} {'KEV':>4} {'?':>4}")
    for root, meta, s, unres in rows:
        b = s["by_severity"]
        flag = " 🔥" if s["kev"] else ""
        print(f"  {root.name:<{width}}  {meta['packages']:>6} "
              f"{b['critical']:>5} {b['high']:>5} {b['medium']:>5} "
              f"{b['low']:>5} {s['kev']:>4} {unres:>4}{flag}")
    tot = store.counts(conn)
    print(f"\n  {tot['packages']} packages across {tot['repos']} repositories "
          f"in the inventory")
    if args.output:
        print(f"  reports written to {args.output}")
    return worst


def cmd_inventory(args) -> int:
    conn = store.connect()
    paths = [Path(p).expanduser().resolve() for p in (args.path or ["."])]
    all_pkgs = []
    for root in paths:
        packages, skipped, locks = manifests.collect(root)
        _record_inventory(conn, root, packages)
        all_pkgs.extend((root, p) for p in packages)
        if args.format == "text":
            print(f"\n{root}  —  {len(packages)} packages, {len(locks)} lockfiles")
            for path, why in skipped:
                print(f"  skipped {path}: {why}")
    if args.format == "json":
        import json as _json
        print(_json.dumps([{
            "repo": str(r), "ecosystem": p.ecosystem, "name": p.name,
            "version": p.version, "scope": p.scope, "manifest": p.manifest,
        } for r, p in all_pkgs], indent=2))
    else:
        by_eco = {}
        for _, p in all_pkgs:
            by_eco.setdefault(p.ecosystem, set()).add((p.name, p.version))
        print()
        for eco in sorted(by_eco):
            print(f"  {eco:<12} {len(by_eco[eco])} distinct package@version")
        print()
    return 0


def _collapse_by_package(findings, ecosystem):
    """One row per (source package, advisory), not one per installed version.

    Without this the host report is unreadable and therefore unread. A machine
    that keeps its superseded kernels carries 69 versions of source `linux` at
    once, and every kernel advisory matches most of them -- 179,983 findings
    on a fully-updated desktop, of which the actionable content is a few
    hundred. An alert nobody can read is an alert nobody acts on, and volume
    is what makes it unreadable.

    Nothing is dropped: the highest affected version is kept, because that is
    the one that says whether you are exposed now rather than only carrying
    old packages, and the number of other affected versions is stated on the
    finding. `--format json` still carries every row.
    """
    best, extra = {}, {}
    for f in findings:
        key = (f.package, f.vuln_id)
        extra[key] = extra.get(key, 0) + 1
        seen = best.get(key)
        if seen is None:
            best[key] = f
            continue
        # Highest affected version wins. An undecidable comparison keeps
        # whichever was already there rather than guessing an order.
        if V.compare(ecosystem, f.version, seen.version) == 1:
            best[key] = f
    out = []
    for key, f in best.items():
        others = extra[key] - 1
        if others:
            f.evidence = (f"{f.evidence}; also matches {others} older "
                          "installed version(s) of this source package")
        out.append(f)
    out.sort(key=lambda f: f.sort_key)
    return out, len(findings) - len(out)


def cmd_host(args) -> int:
    """Match the operating system's own packages against the store.

    Its own command rather than part of `scan` or `sweep`, because the host is
    not a repository: nothing commits it, no lockfile changes when it moves,
    and no CI gate could ever fire on it. Folding it into `sweep`
    would also attribute 2,000 system packages to whichever repository
    happened to be walked first.
    """
    conn = store.connect()
    rel = hostpkgs.os_release()
    eco = hostpkgs.osv_ecosystem(rel)
    pretty = rel.get("PRETTY_NAME") or rel.get("ID") or "unknown"

    if eco is None:
        print(f"dep-intel: this host is {pretty}, which has no advisory "
              "ecosystem dep-intel knows.", file=sys.stderr)
        print("           Only Debian-family systems are supported, and the "
              "release has to be readable from /etc/os-release.",
              file=sys.stderr)
        return 2
    if eco not in ecosystems.REGISTRY:
        print(f"dep-intel: {pretty} maps to the OSV ecosystem {eco}, which is "
              "not registered.", file=sys.stderr)
        print("           Refusing to match against a different release: an "
              "advisory set for the wrong release clears real findings and "
              "invents others.", file=sys.stderr)
        return 2

    try:
        packages, skipped = hostpkgs.collect(eco)
    except hostpkgs.HostError as e:
        print(f"dep-intel: {e}", file=sys.stderr)
        return 2

    findings, unresolved = match.scan_packages(conn, pretty, packages)
    findings, collapsed = _collapse_by_package(findings, eco)

    # The binary package is what a person runs `apt install` on, so a finding
    # that names only the source package is correct and unactionable.
    #
    # Keyed on the source VERSION as well as the name, and it has to be: this
    # machine carries 66 versions of source `linux` at once, one per kernel
    # left installed. Keying on the name alone put an arbitrary binary
    # against every one of them, so a finding about 5.15.0-100.110 was
    # labelled `linux-modules-6.8.0-94-generic` -- a package that is not the
    # one the advisory is about.
    by_source = {(p.name, p.version): p.binary for p in packages}
    for f in findings:
        binary = by_source.get((f.package, f.version), "")
        if binary and binary != f.package:
            f.manifest = f"dpkg ({binary})"

    meta = {
        "repo": pretty,
        "packages": len(packages),
        "lockfiles": 1,
        "skipped": [("dpkg", why) for _n, why in skipped],
        "notes": [],
    }
    meta.update(_store_meta(conn))
    if not any(r["name"] == f"osv:{eco}" for r in store.feed_status(conn)):
        meta["notes"].append(
            f"the {eco} feed has never been synced — every system package was "
            "matched against nothing, so this result is not an all-clear")
    graded = conn.execute(
        "SELECT COUNT(*) FROM vulnerability WHERE feed = ? AND severity != "
        "'unknown'", (f"osv:{eco}",)).fetchone()[0]
    total = conn.execute(
        "SELECT COUNT(*) FROM vulnerability WHERE feed = ?",
        (f"osv:{eco}",)).fetchone()[0]
    if total and graded < total:
        meta["notes"].append(
            f"{total - graded} of {total} {eco} advisories carry neither a "
            "CVSS vector nor a Canonical priority, so they read as 'unknown' "
            "severity and --fail-on cannot grade them")
    # Installed is not running, and on a machine that keeps its old kernels
    # the difference is most of the report.
    versions_of = {}
    for pkg in packages:
        versions_of.setdefault(pkg.name, set()).add(pkg.version)
    multi = sorted((n for n, v in versions_of.items() if len(v) > 3),
                   key=lambda n: -len(versions_of[n]))
    if multi:
        worst = ", ".join(f"{n} ({len(versions_of[n])})" for n in multi[:3])
        meta["notes"].append(
            f"{len(multi)} source package(s) are installed at more than three "
            f"versions at once — {worst}. Superseded kernels and their modules "
            "stay installed until they are purged, and every one of them is "
            "matched: installed is not the same as running")
    if collapsed:
        meta["notes"].append(
            f"{collapsed} finding(s) collapsed: a source package installed at "
            "several versions is reported once per advisory, at its highest "
            "affected version, with the others counted on the finding")
    _warn_if_stale(conn, meta["notes"])

    _emit(findings, unresolved, meta, args)
    failing, _ = match.policy_verdict(
        findings, args.fail_on, args.min_confidence,
        fail_on_kev=not args.no_kev_fail)
    return 1 if (failing and not args.no_fail) else 0


def cmd_affected(args) -> int:
    conn = store.connect()
    ident = args.id.strip()
    ids = [r[0] for r in conn.execute(
        "SELECT id FROM vulnerability WHERE id = ? UNION "
        "SELECT vuln_id FROM alias WHERE alias = ? UNION "
        "SELECT vuln_id FROM related WHERE ref = ?", (ident, ident, ident))]
    if not ids:
        print(f"dep-intel: {ident} is not in the local store")
        print("           `dep-intel sync` if the store is stale, or the "
              "advisory may not affect a synced ecosystem")
        return 0

    total = 0
    for vid in ids:
        v = conn.execute("SELECT * FROM vulnerability WHERE id = ?",
                         (vid,)).fetchone()
        kev = "  [CISA KNOWN EXPLOITED]" if v["kev"] else ""
        print(f"\n{vid}{kev}")
        if v["summary"]:
            print(f"  {v['summary']}")
        print(f"  severity: {v['severity']}"
              + (f" (CVSS {v['cvss_score']})" if v["cvss_score"] else "")
              + f", from {v['severity_source']}")
        rows = list(conn.execute(
            """SELECT DISTINCT p.repo, p.manifest, p.name, p.version, a.id AS aid
               FROM affected a
               JOIN package p ON p.ecosystem = a.ecosystem
               WHERE a.vuln_id = ?
                 AND p.name = a.package COLLATE NOCASE""", (vid,)))
        hits = []
        for r in rows:
            # The ecosystem has to come from the affected row, not from the
            # package row: version comparison is ecosystem-specific, and
            # deciding a Packagist range with npm semver rules is how a
            # comparator silently returns the wrong answer.
            eco = conn.execute("SELECT ecosystem FROM affected WHERE id = ?",
                               (r["aid"],)).fetchone()[0]
            affected, conf, _evidence, fixed, _ = match.decide(
                conn, r["aid"], eco, r["version"])
            if affected:
                hits.append((r, conf, fixed))
        if not hits:
            print("  ✓ no repository in the inventory carries an affected version")
        for r, conf, fixed in hits:
            total += 1
            print(f"  ✗ {r['repo']}")
            print(f"      {r['name']} {r['version']} ({r['manifest']}), "
                  f"confidence {conf}, fixed in "
                  f"{', '.join(fixed) or 'nothing published'}")
    if not store.counts(conn)["packages"]:
        print("\n  the inventory is empty — run `dep-intel sweep` first, "
              "otherwise this only ever answers 'no'")
    return 1 if total else 0


def cmd_cve(args) -> int:
    conn = store.connect()
    ident = args.id.strip()
    row = conn.execute(
        "SELECT * FROM vulnerability WHERE id = ? "
        "OR id IN (SELECT vuln_id FROM alias WHERE alias = ?) "
        "OR id IN (SELECT vuln_id FROM related WHERE ref = ?)",
        (ident, ident, ident)).fetchone()
    if not row:
        print(f"dep-intel: {ident} is not in the local store")
        return 0
    print(f"\n{row['id']}" + ("   [CISA KNOWN EXPLOITED]" if row["kev"] else ""))
    aliases = [a[0] for a in conn.execute(
        "SELECT alias FROM alias WHERE vuln_id = ?", (row["id"],))]
    if aliases:
        print(f"  aliases:  {', '.join(aliases)}")
    # Printed under its own label rather than merged into aliases: a USN
    # bundles several CVEs and is not the same record as any one of them.
    rel = [u[0] for u in conn.execute(
        "SELECT ref FROM related WHERE vuln_id = ? ORDER BY kind, ref",
        (row["id"],))]
    if rel:
        print(f"  related:  {', '.join(rel[:12])}"
              + (f"  (+{len(rel) - 12} more)" if len(rel) > 12 else ""))
    print(f"  severity: {row['severity']}"
          + (f"  CVSS {row['cvss_score']}" if row["cvss_score"] else "")
          + f"  ({row['severity_source']})")
    if row["cvss_vector"]:
        print(f"  vector:   {row['cvss_vector']}")
    if row["cwe"]:
        print(f"  cwe:      {row['cwe']}")
    if row["kev"]:
        print(f"  kev:      added {row['kev_added']}, "
              f"ransomware: {row['kev_ransomware'] or 'unknown'}")
    print(f"  published:{row['published']}")
    if row["summary"]:
        print(f"\n  {row['summary']}")
    print("\n  affected:")
    for a in conn.execute(
            "SELECT ecosystem, package, id FROM affected WHERE vuln_id = ?",
            (row["id"],)):
        rngs = list(conn.execute(
            "SELECT introduced, fixed, last_affected FROM affected_range "
            "WHERE affected_id = ?", (a["id"],)))
        spans = ", ".join(
            f"[{r['introduced'] or '0'}, "
            f"{r['fixed'] or r['last_affected'] or '∞'})" for r in rngs) or "—"
        print(f"    {a['ecosystem']:<10} {a['package']}  {spans}")
    if row["refs"]:
        print("\n  references:")
        for r in row["refs"].split("\n")[:6]:
            print(f"    {r}")
    print()
    return 0


def cmd_status(args) -> int:
    conn = store.connect()
    c = store.counts(conn)
    print(f"\nstore: {store.default_path()}")
    print(f"  {c['vulnerabilities']} advisories, {c['kev']} known-exploited, "
          f"{c['affected']} affected-package rows")
    print(f"  inventory: {c['packages']} packages across {c['repos']} repositories\n")
    rows = store.feed_status(conn)
    if not rows:
        print("  no feed has ever been synced — run `dep-intel sync`\n")
        return 0
    print(f"  {'feed':<18} {'synced':<22} {'records':>9} {'size':>10}")
    for r in rows:
        print(f"  {r['name']:<18} {r['synced_at'] or '—':<22} "
              f"{r['records']:>9} {_size(r['bytes']):>10}")
    synced = {r["name"].split(":", 1)[1] for r in rows
              if r["name"] != "kev" and ":" in r["name"]}
    absent = [e for e in ecosystems.names()
              if e not in synced and not ecosystems.REGISTRY[e].release_scoped]
    host_eco = hostpkgs.osv_ecosystem() or ""
    if host_eco and host_eco not in synced:
        absent.append(host_eco)
    if absent:
        print(f"\n  never synced: {', '.join(sorted(absent))}")
        print("  a scan finds nothing in those, which is not the same as "
              "finding nothing wrong")
    notes = []
    _warn_if_stale(conn, notes)
    for n in notes:
        print(f"\n  note: {n}")
    print()
    return 0


def cmd_test(args) -> int:
    here = Path(__file__).resolve().parent
    argv = ["-v"] if args.verbose else []
    return subprocess.run([sys.executable, str(here / "test.py"), *argv],
                          check=False).returncode


def cmd_doctor(args) -> int:
    ok = True
    print("\ndep-intel doctor\n")
    print(f"  python            {sys.version.split()[0]}")
    print(f"  store             {store.default_path()}"
          f"{'' if store.default_path().exists() else '   (not created yet)'}")
    backend = manifests.TOML_BACKEND
    if backend:
        print(f"  toml              {backend}")
    else:
        ok = False
        print("  toml              MISSING — uv.lock, poetry.lock and")
        print("                    Cargo.lock cannot be read, so Python and")
        print("                    Rust dependencies from those projects are")
        print("                    absent. Install tomli, or run under")
        print("                    python 3.11+.")
    conn = store.connect()
    c = store.counts(conn)
    if c["vulnerabilities"] == 0:
        ok = False
        print("  advisories        EMPTY — run `dep-intel sync`")
    else:
        print(f"  advisories        {c['vulnerabilities']}")
    if c["packages"] == 0:
        print("  inventory         empty — `dep-intel sweep` populates it")
    else:
        print(f"  inventory         {c['packages']} packages, "
              f"{c['repos']} repositories")
    host_eco = hostpkgs.osv_ecosystem()
    if not hostpkgs.available():
        print("  host packages     dpkg-query not on PATH — `dep-intel host` "
              "cannot run here")
    elif host_eco is None:
        print("  host packages     release unreadable from /etc/os-release — "
              "`dep-intel host` refuses rather than guess")
    else:
        print(f"  host packages     {host_eco}")
    for r in _roots():
        print(f"  root              {r}"
              f"{'' if r.is_dir() else '   (does not exist)'}")
    print()
    return 0 if ok else 2


# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dep-intel", add_help=True,
        description=(__doc__ or "").split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"dep-intel {VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--format", choices=["text", "json", "sarif", "markdown"],
                        default="text")
        sp.add_argument("--output")
        sp.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low"])
        sp.add_argument("--min-confidence", default="high",
                        choices=["certain", "very-high", "high", "medium", "low"])
        sp.add_argument("--no-kev-fail", action="store_true")
        sp.add_argument("--no-dev", action="store_true")
        sp.add_argument("--no-fail", action="store_true")
        sp.add_argument("-v", "--verbose", action="store_true")

    sp = sub.add_parser("sync", help="download OSV + KEV into the local store")
    sp.add_argument("--ecosystem", action="append")
    sp.add_argument("-n", "--dry-run", action="store_true")
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_sync)

    sp = sub.add_parser("scan", help="match a repository against the store")
    sp.add_argument("path", nargs="*")
    common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("sweep", help="scan every repository under the roots")
    common(sp)
    sp.set_defaults(func=cmd_sweep)

    sp = sub.add_parser("inventory", help="list installed packages")
    sp.add_argument("path", nargs="*")
    sp.add_argument("--format", choices=["text", "json"], default="text")
    sp.set_defaults(func=cmd_inventory)

    sp = sub.add_parser("host", help="match the operating system's own packages")
    common(sp)
    sp.set_defaults(func=cmd_host)

    sp = sub.add_parser("affected", help="which repositories carry an advisory")
    sp.add_argument("id")
    sp.set_defaults(func=cmd_affected)

    sp = sub.add_parser("cve", help="show one advisory")
    sp.add_argument("id")
    sp.set_defaults(func=cmd_cve)

    sp = sub.add_parser("test", help="run the tool's own gate")
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.set_defaults(func=cmd_test)

    sub.add_parser("status", help="store freshness and counts").set_defaults(
        func=cmd_status)
    sub.add_parser("doctor", help="environment check").set_defaults(
        func=cmd_doctor)
    return p


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 2
    except feeds.FeedError as e:
        print(f"dep-intel: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
