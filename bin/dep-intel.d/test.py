#!/usr/bin/env python3
"""dep-intel's gate: comparators, parsers, matcher, ingestion, output.

Standard library only, like the tool -- no pytest, because a security tool
whose tests need a package manager is a security tool whose tests stop being
run. `dep-intel test` calls this, and `make check` calls that.

Every case that is here because something was WRONG says so, because those
are the cases a later refactor is most likely to break back:

  * 1.0.dev1 sorts below 1.0a1 (the first PEP 440 key had it above)
  * a GIT range's commit-SHA bound must not poison a decidable advisory
  * torch's 2.6.0-cu124 is a local version PEP 440 does not permit
  * an unparseable bound is `unresolved`, never `not affected`
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cvss
import ecosystems
import feeds
import hostpkgs
import manifests
import match
import nvd
import report
import store
import versions as V

FAILURES: list[str] = []
COUNT = 0


def check(label, got, want):
    global COUNT
    COUNT += 1
    if got != want:
        FAILURES.append(f"{label}\n      got:  {got!r}\n      want: {want!r}")


def ordered(label, ecosystem, ascending):
    """Assert a list is in strictly ascending order under one scheme."""
    keys = [V.parse(ecosystem, s) for s in ascending]
    for i, k in enumerate(keys):
        check(f"{label}: {ascending[i]!r} parses", k is not None, True)
    # zip rather than itertools.pairwise: pairwise is 3.10+, and this
    # tool targets 3.9 so it runs on whatever interpreter is already there.
    for a, b in zip(ascending, ascending[1:]):
        check(f"{label}: {a} < {b}", V.compare(ecosystem, a, b), -1)


# --------------------------------------------------------------------------

def test_semver():
    ordered("semver", "npm", [
        "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
        "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
        "1.0.1", "1.1.0", "2.0.0",
    ])
    check("semver: build metadata ignored",
          V.compare("npm", "1.0.0+build.1", "1.0.0"), 0)
    check("semver: v prefix", V.compare("npm", "v1.2.3", "1.2.3"), 0)
    check("semver: partial version", V.compare("npm", "1.2", "1.2.0"), 0)
    check("semver: garbage is undecidable", V.parse("npm", "not-a-version"), None)


def test_composer():
    ordered("composer", "Packagist", [
        "1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta1", "1.0.0-RC1",
        "1.0.0", "1.0.0-p1", "1.0.1", "1.1.0", "2.0.0",
    ])
    # Magento ships patch-level releases; -p1 is NEWER than the plain release,
    # which is the rung people get backwards.
    check("composer: 1.0.0-p1 > 1.0.0",
          V.compare("Packagist", "1.0.0-p1", "1.0.0"), 1)
    check("composer: four-segment normalisation",
          V.compare("Packagist", "1.2", "1.2.0.0"), 0)
    check("composer: v prefix", V.compare("Packagist", "v2.4.7", "2.4.7"), 0)
    # A branch alias is not a point on the version line at all.
    check("composer: dev-main is undecidable",
          V.parse("Packagist", "dev-main"), None)


def test_pep440():
    ordered("pep440", "PyPI", [
        "1.0.dev1", "1.0a1.dev0", "1.0a1", "1.0b1", "1.0rc1", "1.0",
        "1.0.post1.dev0", "1.0.post1", "1.1", "2!0.1",
    ])
    check("pep440: trailing zeros not significant",
          V.compare("PyPI", "1.0", "1.0.0"), 0)
    check("pep440: 1.0-1 is 1.0.post1",
          V.compare("PyPI", "1.0-1", "1.0.post1"), 0)
    # Regression: PyTorch CUDA builds. PEP 440 wants 2.6.0+cu124; PYSEC
    # publishes 2.6.0-cu124, and nine real torch findings were sitting in the
    # unresolved bucket because of the hyphen.
    check("pep440: torch local version parses",
          V.parse("PyPI", "2.6.0-cu124") is not None, True)
    check("pep440: 2.6.0 is within (0, 2.6.0-cu124]",
          V.in_range("PyPI", "2.6.0", "0", None, "2.6.0-cu124"), True)


def test_name_normalisation():
    for name in ("Flask-WTF", "flask_wtf", "flask.wtf", "FLASK--WTF"):
        check(f"pep503: {name}", V.normalize_name("PyPI", name), "flask-wtf")
    check("packagist name is lowercased",
          V.normalize_name("Packagist", "Magento/Framework"), "magento/framework")
    # OSV labels an ecosystem with a suffix: Packagist:https://packages.drupal.org/8
    check("ecosystem suffix stripped",
          V.base_ecosystem("Packagist:https://packages.drupal.org/8"), "Packagist")


def test_in_range():
    check("below introduced", V.in_range("npm", "1.0.0", "2.0.0", "3.0.0", None), False)
    check("inside range", V.in_range("npm", "2.5.0", "2.0.0", "3.0.0", None), True)
    check("at fixed is not affected",
          V.in_range("npm", "3.0.0", "2.0.0", "3.0.0", None), False)
    check("at last_affected IS affected",
          V.in_range("npm", "3.0.0", "2.0.0", None, "3.0.0"), True)
    check("open-ended range", V.in_range("npm", "9.9.9", "1.0.0", None, None), True)
    # The rule the whole tool rests on: undecided is not clean.
    check("unparseable version is undecided",
          V.in_range("npm", "wat", "1.0.0", "2.0.0", None), None)
    check("unparseable bound is undecided",
          V.in_range("npm", "1.5.0", "1.0.0", "not-a-version", None), None)


def test_cvss():
    for vector, want in [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        # Roundup(1.7454) is 1.8, not 1.7 -- the spec defines it on integers
        # precisely because the naive version is wrong at the boundary.
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", 1.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ]:
        check(f"cvss {vector[-24:]}", cvss.base_score(vector), want)
    # v4 is a 270-entry lookup table, not a formula. Refuse rather than guess.
    check("cvss v4 is not computed",
          cvss.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"), None)
    check("cvss junk", cvss.base_score("nonsense"), None)
    check("rating bands", [cvss.rating(x) for x in (0, 3.9, 6.9, 8.9, 9.0)],
          ["none", "low", "medium", "high", "critical"])
    check("qualitative fallback is labelled",
          cvss.from_advisory(None, {"severity": "MODERATE"}),
          (None, "medium", "qualitative"))
    check("no severity at all",
          cvss.from_advisory(None, None), (None, "unknown", "none"))


# --------------------------------------------------------------------------

def _write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_manifests():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root, "composer.lock", json.dumps({
            "packages": [{"name": "magento/framework", "version": "v103.0.7"},
                         {"name": "guzzlehttp/guzzle", "version": "7.10.0"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}],
        }))
        _write(root, "package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/typescript": {"version": "5.4.0", "dev": True},
                "node_modules/linked": {"link": True},
            },
        }))
        _write(root, "requirements.txt",
               "requests==2.31.0\nflask>=2\n# comment\n-r other.txt\n")
        # A nested component manifest, covered by the root lockfile.
        _write(root, "app/code/Vendor/Mod/composer.json", json.dumps({
            "name": "vendor/mod", "type": "magento2-module",
            "require": {"magento/framework": "*"},
        }))
        pkgs, skipped, locks = manifests.collect(root)
        by = {(p.ecosystem, p.name): p for p in pkgs}

        check("composer runtime", by[("Packagist", "guzzlehttp/guzzle")].scope,
              "runtime")
        check("composer dev scope", by[("Packagist", "phpunit/phpunit")].scope, "dev")
        check("composer v prefix stripped",
              by[("Packagist", "magento/framework")].version, "103.0.7")
        check("npm runtime", by[("npm", "lodash")].version, "4.17.20")
        check("npm dev scope", by[("npm", "typescript")].scope, "dev")
        check("npm link entry not treated as a package",
              ("npm", "linked") in by, False)
        check("requirements: == pin used",
              by[("PyPI", "requests")].version, "2.31.0")
        check("requirements: non-pin not invented",
              ("PyPI", "flask") in by, False)
        reasons = " ".join(r for _, r in skipped)
        check("unpinned requirement is reported", "not pinned" in reasons, True)
        # Ancestor coverage: 66 Magento module descriptors must not each be
        # reported as an unlocked project.
        check("nested composer.json covered by the root lock",
              "app/code" in reasons, False)
        check("lockfiles found", len(locks), 3)


def test_manifest_skips_installed_trees():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root, "composer.lock", json.dumps({"packages": []}))
        _write(root, "vendor/other/composer.lock",
               json.dumps({"packages": [{"name": "x/y", "version": "1.0.0"}]}))
        _write(root, "node_modules/dep/package-lock.json",
               json.dumps({"lockfileVersion": 3, "packages": {}}))
        pkgs, _, locks = manifests.collect(root)
        check("vendor/ and node_modules/ are not walked", len(locks), 1)
        check("no third-party lockfile leaked in", len(pkgs), 0)


# --------------------------------------------------------------------------

def _osv(vid, eco, pkg, ranges, versions=None, **extra):
    adv = {"id": vid, "modified": "2026-01-01T00:00:00Z",
           "affected": [{"package": {"name": pkg, "ecosystem": eco},
                         "ranges": ranges, "versions": versions or []}]}
    adv.update(extra)
    return adv


def _zip_of(advisories):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for a in advisories:
            z.writestr(f"{a['id']}.json", json.dumps(a))
        z.writestr("README", "not json")
    return buf.getvalue()


def _ingest(conn, advisories, ecosystem="Packagist"):
    blob = _zip_of(advisories)
    z = zipfile.ZipFile(io.BytesIO(blob))
    conn.execute("BEGIN")
    n = 0
    for _, raw in feeds._safe_entries(z):
        adv = json.loads(raw)
        if adv.get("withdrawn"):
            continue
        feeds._record(conn, adv, f"osv:{ecosystem}")
        n += 1
    conn.execute("COMMIT")
    return n


class Pkg:
    def __init__(self, ecosystem, name, version, scope="runtime",
                 manifest="composer.lock"):
        self.ecosystem, self.name, self.version = ecosystem, name, version
        self.scope, self.manifest = scope, manifest


def test_matcher():
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        _ingest(conn, [
            _osv("ADV-RANGE", "Packagist", "acme/lib",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]),
            _osv("ADV-BOTH", "Packagist", "acme/both",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}],
                 versions=["1.0.0", "2.0.0"]),
            _osv("ADV-ENUM", "Packagist", "acme/enum", [], versions=["4.1.0"]),
            _osv("ADV-OPEN", "Packagist", "acme/open",
                 [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}]),
            _osv("ADV-TWO-WINDOWS", "Packagist", "acme/windows",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"},
                              {"introduced": "3.0.0"}, {"fixed": "3.5.0"}]}]),
            _osv("ADV-BADBOUND", "Packagist", "acme/bad",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "0"}, {"fixed": "not-a-version"}]}]),
            # A GIT range beside a good ECOSYSTEM one: the shape that turned
            # every decidable aiohttp advisory into "unresolved".
            _osv("ADV-GIT", "Packagist", "acme/git", [
                {"type": "GIT", "events": [{"introduced": "0"},
                                           {"fixed": "a" * 40}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                 {"fixed": "1.5.0"}]},
            ]),
        ])

        def scan(name, version):
            return match.scan_packages(
                conn, "/repo", [Pkg("Packagist", name, version)])

        f, u = scan("acme/lib", "1.5.0")
        check("range hit", (len(f), f[0].confidence if f else None),
              (1, "very-high"))
        check("range hit names the fix", f[0].fixed if f else None, ["2.0.0"])
        check("range miss below", scan("acme/lib", "0.9.0")[0], [])
        check("range miss at fix", scan("acme/lib", "2.0.0")[0], [])

        f, _ = scan("acme/both", "2.0.0")
        check("range and enumeration agree -> certain",
              f[0].confidence if f else None, "certain")

        f, _ = scan("acme/enum", "4.1.0")
        check("enumeration only", f[0].confidence if f else None, "very-high")
        check("enumeration miss", scan("acme/enum", "4.2.0")[0], [])

        f, _ = scan("acme/open", "9.0.0")
        check("open-ended range is lower confidence",
              f[0].confidence if f else None, "high")

        check("between two windows is not affected",
              scan("acme/windows", "2.0.0")[0], [])
        check("inside the second window is affected",
              len(scan("acme/windows", "3.2.0")[0]), 1)

        f, u = scan("acme/bad", "1.0.0")
        check("unparseable bound is unresolved, not clean", (len(f), len(u)), (0, 1))

        f, u = scan("acme/git", "2.0.0")
        check("GIT range does not poison a decidable advisory",
              (len(f), len(u)), (0, 0))
        check("GIT range still lets the version range decide",
              len(scan("acme/git", "1.0.0")[0]), 1)


def test_case_and_ecosystem_folding():
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        _ingest(conn, [
            _osv("ADV-PEP503", "PyPI", "Flask-WTF",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]),
            _osv("ADV-SUFFIX", "Packagist:https://packages.drupal.org/8",
                 "drupal/thing",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]),
        ], ecosystem="PyPI")
        f, _ = match.scan_packages(conn, "/r", [Pkg("PyPI", "flask_wtf", "0.9.0")])
        check("PEP 503 folding matches the advisory", len(f), 1)
        f, _ = match.scan_packages(
            conn, "/r", [Pkg("Packagist", "drupal/thing", "1.0.0")])
        check("suffixed ecosystem is normalised", len(f), 1)


def test_ingestion_hygiene():
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        _ingest(conn, [
            _osv("ADV-LIVE", "Packagist", "acme/live",
                 [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]),
            _osv("ADV-GONE", "Packagist", "acme/gone",
                 [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                 withdrawn="2026-01-02T00:00:00Z"),
            _osv("ADV-OTHER", "Hex", "acme/other",
                 [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]),
        ])
        ids = {r[0] for r in conn.execute("SELECT id FROM vulnerability")}
        check("withdrawn advisory is not stored", "ADV-GONE" in ids, False)
        check("live advisory is stored", "ADV-LIVE" in ids, True)
        n = conn.execute("SELECT COUNT(*) FROM affected WHERE vuln_id='ADV-OTHER'"
                         ).fetchone()[0]
        check("unsupported ecosystem is not stored as affected", n, 0)

        # Re-ingesting the same advisory with fewer packages must REMOVE the
        # old rows. An UPSERT cannot express a deletion.
        _ingest(conn, [_osv("ADV-LIVE", "Packagist", "acme/renamed",
                            [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}]}])])
        pkgs = {r[0] for r in conn.execute(
            "SELECT package FROM affected WHERE vuln_id='ADV-LIVE'")}
        check("re-ingest replaces affected rows", pkgs, {"acme/renamed"})


def test_archive_bounds():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("big.json", "x" * (feeds.MAX_ENTRY_BYTES + 1))
    z = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    try:
        list(feeds._safe_entries(z))
        check("oversize entry is refused", "no error", "FeedError")
    except feeds.FeedError:
        check("oversize entry is refused", True, True)


def test_non_https_refused():
    for fn in (feeds._fetch, feeds.head_size):
        try:
            fn("http://osv-vulnerabilities.storage.googleapis.com/x/all.zip")
            check(f"{fn.__name__} refuses plain http", "no error", "FeedError")
        except feeds.FeedError:
            check(f"{fn.__name__} refuses plain http", True, True)


# --------------------------------------------------------------------------

def _finding(**kw):
    base = {"repo": "/r", "manifest": "composer.lock",
            "ecosystem": "Packagist", "package": "acme/lib",
            "version": "1.0.0", "scope": "runtime", "vuln_id": "ADV-1",
            "aliases": ["CVE-2026-1"], "summary": "s", "severity": "high",
            "severity_source": "cvss", "cvss_score": 7.5, "cvss_vector": "",
            "cwe": "CWE-89", "kev": False, "kev_added": "",
            "kev_ransomware": "", "fixed": ["2.0.0"],
            "confidence": "very-high", "evidence": "e", "refs": []}
    base.update(kw)
    return match.Finding(**base)


def test_policy():
    high_sure = _finding()
    crit_unsure = _finding(severity="critical", confidence="low")
    low_kev = _finding(severity="low", confidence="low", kev=True)

    failing, warning = match.policy_verdict([high_sure], "high", "high")
    check("high at high confidence fails", (len(failing), len(warning)), (1, 0))

    failing, warning = match.policy_verdict([crit_unsure], "high", "high")
    check("critical at low confidence warns rather than failing",
          (len(failing), len(warning)), (0, 1))

    failing, _ = match.policy_verdict([low_kev], "critical", "certain")
    check("known-exploited fails regardless of both axes", len(failing), 1)

    failing, _ = match.policy_verdict([low_kev], "critical", "certain",
                                      fail_on_kev=False)
    check("kev failure can be turned off", len(failing), 0)

    ordered_findings = sorted([high_sure, low_kev, crit_unsure],
                              key=lambda f: f.sort_key)
    check("known-exploited sorts first", ordered_findings[0].kev, True)


def test_output_shapes():
    meta = {"repo": "/r", "packages": 3, "lockfiles": 1, "skipped": [],
            "notes": [], "synced": "2026-08-26T00:00:00+00:00",
            "store_vulns": 10, "feeds": ["osv:Packagist"], "tool_version": "1"}
    findings = [_finding(), _finding(vuln_id="ADV-2", kev=True,
                                     severity="critical", cvss_score=9.8)]
    unresolved = [match.Unresolved("/r", "composer.lock", "Packagist",
                                   "acme/x", "1.0", "ADV-3", "why")]

    doc = json.loads(report.render_json(findings, unresolved, meta))
    check("json summary total", doc["summary"]["total"], 2)
    check("json reports unresolved", len(doc["unresolved"]), 1)
    # Order-independent on purpose: sorting is scan_packages' job, done once,
    # and the renderers deliberately preserve whatever order they are handed.
    check("json marks known-exploited",
          sum(1 for f in doc["findings"] if f["known_exploited"]), 1)

    sarif = json.loads(report.render_sarif(findings, unresolved, meta))
    check("sarif version", sarif["version"], "2.1.0")
    check("sarif results", len(sarif["runs"][0]["results"]), 2)
    scores = {r["id"]: r["properties"]["security-severity"]
              for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    check("sarif carries security-severity per rule",
          (scores["ADV-1"], scores["ADV-2"]), ("7.5", "9.8"))
    check("sarif records unresolved count",
          sarif["runs"][0]["invocations"][0]["properties"]["unresolvedMatches"], 1)

    md = report.render_markdown(findings, unresolved, meta)
    check("markdown frontmatter starts at line 1", md.startswith("---\n"), True)
    check("markdown leads with the KEV verdict", "known-exploited" in md, True)
    check("markdown names the undecided section",
          "## Undecided matches" in md, True)

    clean = report.render_markdown([], [], meta)
    check("clean markdown does not claim safety",
          "no known vulnerable dependencies" in clean, True)
    check("clean markdown still states its own limits",
          "goes stale" in clean, True)


# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Ubuntu, Magento, Rust, Terraform and GitHub Actions
# --------------------------------------------------------------------------

def test_dpkg_ordering():
    eco = "Ubuntu:24.04:LTS"
    # Debian policy 5.6.12. The whole set was checked pair-by-pair against
    # `dpkg --compare-versions` itself over 20,231 pairs drawn from this
    # machine's own installed set; these are the rungs worth freezing.
    ordered("dpkg release line", eco, [
        "1.0~~", "1.0~~a", "1.0~", "1.0", "1.0-1", "1.0-2",
    ])
    # The upstream part is compared before the revision, so a letter in the
    # upstream outranks any revision: `1.0a` > `1.0-1`, verified against dpkg.
    ordered("dpkg upstream outranks revision", eco, ["1.0-9", "1.0a", "1.0a-1"])
    ordered("dpkg epoch beats everything", eco, [
        "1.0", "9.9.9", "1:0.1", "2:0.1",
    ])
    ordered("dpkg ubuntu revisions", eco, [
        "2.4.58-1ubuntu8.15", "2.4.58-1ubuntu8.16", "2.4.58-1ubuntu9",
    ])
    ordered("dpkg kernel revisions", eco, [
        "6.8.0-1028.33", "6.8.0-1030.35", "6.8.0-1030.36",
    ])
    # A tilde sorts below the END of a string, which no other scheme here has
    # and which a tuple key gets backwards.
    check("1.0~rc1 < 1.0", V.compare(eco, "1.0~rc1", "1.0"), -1)
    check("leading zeros are not significant",
          V.compare(eco, "1.01.0", "1.1.0"), 0)
    check("longer digit run is the larger number",
          V.compare(eco, "1.10", "1.9"), 1)


def test_dpkg_is_not_semver():
    """The regression this comparator exists to prevent.

    semver's regex MATCHES `6.8.0-1028.33` and gives it the wrong meaning: it
    reads the revision as a PRERELEASE, which sorts below plain `6.8.0`. An
    advisory bounded at `introduced: 6.8.0` would then clear a 6.8.0-1028
    kernel -- a silent false negative, which is the failure mode this whole
    tool exists to remove.
    """
    check("semver would put a dpkg revision below its release",
          V.compare("npm", "6.8.0-1028.33", "6.8.0"), -1)
    check("dpkg puts a revision ABOVE its release",
          V.compare("Ubuntu:24.04:LTS", "6.8.0-1028.33", "6.8.0"), 1)
    check("so the semver answer would have cleared a vulnerable kernel",
          V.in_range("npm", "6.8.0-1028.33", "6.8.0", None, None), False)
    check("and the dpkg answer does not",
          V.in_range("Ubuntu:24.04:LTS", "6.8.0-1028.33", "6.8.0", None, None),
          True)
    # An epoch is the other half: no other scheme here parses one at all, so
    # falling back would have made every epoch version undecidable.
    check("an epoch parses under dpkg",
          V.parse("Ubuntu:24.04:LTS", "1:2.39.2-1ubuntu1") is not None, True)
    check("and under no other scheme",
          V.parse("npm", "1:2.39.2-1ubuntu1"), None)


def test_ecosystem_keys_and_schemes():
    # A registry proxy suffix names a mirror and collapses.
    check("Packagist suffix collapses",
          V.storage_key("Packagist:https://packages.drupal.org/8"), "Packagist")
    # A distribution suffix names the RELEASE and must not.
    check("Ubuntu release is kept",
          V.storage_key("Ubuntu:24.04:LTS"), "Ubuntu:24.04:LTS")
    check("Ubuntu uses the dpkg scheme",
          V.scheme_for("Ubuntu:22.04:LTS"), "dpkg")
    check("crates.io uses semver", V.scheme_for("crates.io"), "semver")
    check("Magento uses the composer scheme", V.scheme_for("Magento"), "composer")
    # An unregistered ecosystem has NO scheme, so every match against it is
    # unresolved rather than quietly decided by whichever comparator is near.
    check("an unknown ecosystem has no scheme", V.scheme_for("Fictional"), "")
    # An unregistered Ubuntu variant must NOT truncate to bare `Ubuntu`: that
    # would store it under a key a different release could match.
    check("an unregistered distribution release keeps its full key",
          V.storage_key("Ubuntu:Pro:FIPS:16.04:LTS"), "Ubuntu:Pro:FIPS:16.04:LTS")
    check("and still has the distribution's scheme",
          V.scheme_for("Ubuntu:Pro:FIPS:16.04:LTS"), "dpkg")
    check("and therefore cannot parse", V.parse("Fictional", "1.0.0"), None)
    check("a Terraform lock is matched in Go",
          ecosystems.advisory_ecosystem("Terraform"), "Go")
    # A Go module path is case-sensitive; folding it would match the wrong one.
    check("Go names are not folded",
          V.normalize_name("Go", "github.com/Azure/foo"), "github.com/Azure/foo")
    check("crates.io names fold like PyPI",
          V.normalize_name("crates.io", "Serde_Derive"), "serde-derive")


def test_ubuntu_releases_do_not_cross_match():
    """The failure that release-scoping exists to prevent.

    22.04 and 24.04 ship different versions of one source package and fix
    them at different revisions. Truncating the ecosystem at the colon --
    correct for a Packagist mirror -- would let either release's advisory
    decide the other's machine, which is wrong in both directions at once.
    """
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        _ingest(conn, [
            _osv("USN-JAMMY", "Ubuntu:22.04:LTS", "expat",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "0"}, {"fixed": "2.4.7-1ubuntu0.2"}]}]),
            _osv("USN-NOBLE", "Ubuntu:24.04:LTS", "expat",
                 [{"type": "ECOSYSTEM",
                   "events": [{"introduced": "0"}, {"fixed": "2.6.1-2ubuntu0.1"}]}]),
        ], ecosystem="Ubuntu:24.04:LTS")

        keys = {r[0] for r in conn.execute("SELECT DISTINCT ecosystem FROM affected")}
        check("each release is stored under its own key", keys,
              {"Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS"})

        noble = [Pkg("Ubuntu:24.04:LTS", "expat", "2.6.1-2ubuntu0.1", "system",
                     "dpkg")]
        findings, unresolved = match.scan_packages(conn, "noble", noble)
        check("a patched 24.04 package is clean", len(findings), 0)
        check("and nothing was undecidable", len(unresolved), 0)

        # The same version is BELOW the 22.04 fix, so a collapsed key would
        # have reported it against the jammy advisory.
        vulnerable = [Pkg("Ubuntu:24.04:LTS", "expat", "2.5.0-1", "system",
                          "dpkg")]
        findings, _ = match.scan_packages(conn, "noble", vulnerable)
        check("only the matching release's advisory can fire",
              [f.vuln_id for f in findings], ["USN-NOBLE"])


def test_related_refs_are_not_aliases():
    """An Ubuntu record names its CVE under `related`, and has no aliases.

    Reading only `aliases` -- which is all the tool did -- meant the KEV
    catalogue reached NONE of the 11,853 Ubuntu advisories, so every Ubuntu
    finding came back not-known-exploited by construction. Both OSV fields
    are ingested because the bucket carries both: 11,850 CVE-shaped records
    use `related` and the 166 USN records use `upstream`.
    """
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        _ingest(conn, [
            _osv("USN-7000-1", "Ubuntu:24.04:LTS", "expat",
                 [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                 upstream=["CVE-2024-45490", "UBUNTU-CVE-2024-45490"]),
            _osv("UBUNTU-CVE-2024-45491", "Ubuntu:24.04:LTS", "expat",
                 [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                 related=["CVE-2024-45491"]),
        ], ecosystem="Ubuntu:24.04:LTS")

        ups = {r[0] for r in conn.execute(
            "SELECT ref FROM related WHERE vuln_id='USN-7000-1'")}
        check("upstream refs are stored", ups,
              {"CVE-2024-45490", "UBUNTU-CVE-2024-45490"})
        kinds = {r[0] for r in conn.execute("SELECT DISTINCT kind FROM related")}
        check("both OSV fields are ingested and kept apart", kinds,
              {"related", "upstream"})
        rel = {r[0] for r in conn.execute(
            "SELECT ref FROM related WHERE vuln_id='UBUNTU-CVE-2024-45491'")}
        check("a CVE-shaped record's `related` CVE is stored", rel,
              {"CVE-2024-45491"})
        aliases = conn.execute(
            "SELECT COUNT(*) FROM alias WHERE vuln_id='USN-7000-1'").fetchone()[0]
        check("and are NOT recorded as aliases: one USN bundles several CVEs",
              aliases, 0)

        # KEV joins through upstream, which is the point of storing it.
        conn.execute(
            """UPDATE vulnerability SET kev = 1
               WHERE id IN (SELECT vuln_id FROM related WHERE ref = ?)""",
            ("CVE-2024-45490",))
        kev = conn.execute(
            "SELECT kev FROM vulnerability WHERE id='USN-7000-1'").fetchone()[0]
        check("a KEV entry reaches a USN through upstream", kev, 1)


def test_uv_lock_skips_the_project_being_scanned():
    """The project itself is not a dependency, whatever its version key says.

    A project with `dynamic = ["version"]` carries no `version` in uv.lock, and
    the guard for a malformed entry used to run first -- so the repository being
    scanned reported itself as an unchecked coverage gap on every run.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "uv.lock").write_text(
            '[[package]]\n'
            'name = "my-app"\n'
            'source = { editable = "." }\n'
            '\n'
            '[[package]]\n'
            'name = "pytest"\n'
            'version = "8.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )
        res = manifests.parse(root / "uv.lock", root)
        check("the editable project is not reported as a gap", res.skipped, [])
        check("its dependency is still collected",
              [(p.ecosystem, p.name, p.version) for p in res.packages],
              [("PyPI", "pytest", "8.0.0")])


def test_cargo_lock():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "Cargo.lock").write_text(
            '[[package]]\nname = "serde"\nversion = "1.0.200"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
            '[[package]]\nname = "my-app"\nversion = "0.1.0"\n\n'
            '[[package]]\nname = "forked"\nversion = "2.0.0"\n'
            'source = "git+https://example.invalid/forked"\n')
        res = manifests.parse(root / "Cargo.lock", root)
        why = " ".join(w for _p, w in res.skipped)
        if manifests.TOML_BACKEND is None:
            # Cargo.lock is TOML, so it degrades with the Python lockfiles on
            # an interpreter without tomllib or tomli. What must hold is that
            # it degrades LOUDLY: no packages AND a stated reason, never an
            # empty result that reads as a project with no dependencies.
            check("with no TOML parser, Cargo.lock yields nothing",
                  res.packages, [])
            check("and says why", "no TOML parser" in why, True)
            return
        got = {(p.name, p.version, p.ecosystem) for p in res.packages}
        check("a registry crate is a dependency", got,
              {("serde", "1.0.200", "crates.io")})
        check("the workspace member is reported as local", "workspace" in why, True)
        check("a git source is reported as unmatchable",
              "non-registry" in why, True)


def test_terraform_lock():
    check("the registry naming convention derives the module",
          manifests.terraform_go_module("registry.terraform.io/hashicorp/aws"),
          "github.com/hashicorp/terraform-provider-aws")
    check("a private registry derives nothing",
          manifests.terraform_go_module("app.terraform.io/acme/thing"), None)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".terraform.lock.hcl").write_text(
            'provider "registry.terraform.io/hashicorp/aws" {\n'
            '  version     = "5.100.0"\n  constraints = "~> 5.70"\n'
            '  hashes = ["h1:abc="]\n}\n\n'
            'provider "app.terraform.io/acme/private" {\n'
            '  version = "1.2.3"\n}\n')
        res = manifests.parse(root / ".terraform.lock.hcl", root)
        check("a public provider is locked as its Go module",
              [(p.name, p.version, p.ecosystem) for p in res.packages],
              [("github.com/hashicorp/terraform-provider-aws", "5.100.0",
                "Terraform")])
        why = " ".join(w for _p, w in res.skipped)
        check("a private provider is named as NOT checked",
              "NOT checked" in why, True)
        check("and the convention itself is declared",
              "naming convention" in why, True)


def test_workflow_pinning():
    """A moving tag is not a version, and resolving one would invent an answer.

    `actions/checkout@v5` is a major tag GitHub repoints as releases land, so
    the commit behind it today is not the commit behind it tomorrow. Reading
    it as 5.0.0 would decide a range against a version nobody has pinned.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        wf = root / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "jobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v5\n"
            "      - uses: actions/setup-node@v4.0.2\n"
            "      - uses: some/action@" + "a" * 40 + "\n"
            "      - uses: other/thing@main\n"
            "      - uses: ./local-action\n"
            "      - uses: 'quoted/action@v1.2.3'  # trailing comment\n")
        locks, _unlocked = manifests.discover(root)
        check("a workflow is discovered under the dotted .github directory",
              [p.name for p in locks], ["ci.yml"])
        res = manifests.parse(locks[0], root)
        got = sorted((p.name, p.version) for p in res.packages)
        check("only exact x.y.z tags are treated as locked", got,
              [("actions/setup-node", "4.0.2"), ("quoted/action", "1.2.3")])
        check("an action is CI scope, so --no-dev never hides it",
              {p.scope for p in res.packages}, {"ci"})
        why = " ".join(w for _p, w in res.skipped)
        check("moving tags are named, not swallowed", "moving tag" in why, True)
        check("a SHA pin is named as unmatchable", "commit SHA" in why, True)
        check("local actions are accounted for", "local or docker" in why, True)


def test_magento_metapackage_is_cross_listed():
    """Commerce is not on Packagist, so its advisories are not in OSV.

    `magento/product-enterprise-edition` had ZERO affected rows in the whole
    store, so a Commerce store scanned clean on the one package that decides
    whether the shop is exploitable.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "composer.lock").write_text(json.dumps({"packages": [
            {"name": "magento/product-enterprise-edition", "version": "2.4.8-p2"},
            {"name": "magento/module-catalog", "version": "104.0.0"},
        ]}))
        res = manifests.parse(root / "composer.lock", root)
        pairs = sorted((p.ecosystem, p.name) for p in res.packages)
        check("the metapackage is listed under Magento as well as Packagist",
              pairs,
              [("Magento", "magento/product-enterprise-edition"),
               ("Packagist", "magento/module-catalog"),
               ("Packagist", "magento/product-enterprise-edition")])
        check("an ordinary module is not cross-listed",
              sum(1 for p in res.packages if p.name == "magento/module-catalog"),
              1)


def test_magento_patch_levels_order():
    # Composer ranks a patch level ABOVE the plain release, which is the rung
    # Magento's whole release line depends on.
    ordered("magento patch line", "Magento",
            ["2.4.7", "2.4.7-p1", "2.4.7-p2", "2.4.8", "2.4.8-p2"])
    check("2.4.8-p2 is not below 2.4.8",
          V.compare("Magento", "2.4.8-p2", "2.4.8"), 1)
    # An advisory bounded at "2.4.7 and earlier" must not clear 2.4.7-p1,
    # which is how "and earlier" is written as an OSV last_affected bound.
    check("a patch release is inside a last_affected bound at its release",
          V.in_range("Magento", "2.4.7-p1", "0", None, "2.4.7"), False)


def test_nvd_to_osv():
    cve = {
        "id": "CVE-2026-0001",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "An example."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"description": [{"value": "CWE-89"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:adobe:commerce:*:*:*:*:*:*:*:*",
             "vulnerable": True, "versionStartIncluding": "2.4.0",
             "versionEndExcluding": "2.4.8"},
            {"criteria": "cpe:2.3:a:adobe:commerce:2.4.8:p1:*:*:*:*:*:*",
             "vulnerable": True},
            {"criteria": "cpe:2.3:a:adobe:commerce:2.4.9:-:*:*:*:*:*:*",
             "vulnerable": True},
            {"criteria": "cpe:2.3:a:adobe:commerce:2.4.99:*:*:*:*:*:*:*",
             "vulnerable": False},
            {"criteria": "cpe:2.3:a:adobe:magento:1.0:*:*:*:*:*:*:*",
             "vulnerable": True},
        ]}, {"negate": True, "cpeMatch": [
            {"criteria": "cpe:2.3:a:adobe:commerce:3.0:*:*:*:*:*:*:*",
             "vulnerable": True}]}]}],
    }
    prods = (("cpe:2.3:a:adobe:commerce", "magento/product-enterprise-edition"),)
    adv = nvd.to_osv(cve, prods)
    check("the CVE id is the advisory id", adv["id"], "CVE-2026-0001")
    check("the CVSS vector is carried for local scoring",
          adv["severity"][0]["score"].startswith("CVSS:3.1/"), True)
    check("the CWE is carried", adv["database_specific"]["cwe_ids"], ["CWE-89"])
    block = adv["affected"][0]
    check("one affected block per product", len(adv["affected"]), 1)
    check("a bounded CPE range becomes an OSV range", block["ranges"],
          [{"type": "ECOSYSTEM", "events": [{"introduced": "2.4.0"},
                                            {"fixed": "2.4.8"}]}])
    # The CPE `update` field is where Magento's patch level lives, and
    # rejoining it is what the composer comparator needs to decide the match.
    check("the update field is rejoined as a patch level",
          block["versions"], ["2.4.8-p1", "2.4.9"])
    check("a non-vulnerable CPE is not an affected version",
          "2.4.99" in block["versions"], False)
    check("a negated node is not read as affected",
          "3.0" in block["versions"], False)

    # CPE 2.3 gives `*` and `-` OPPOSITE meanings in the version field: `*` is
    # ANY, `-` is NOT APPLICABLE -- the versionless entry a CNA files for a
    # product. Reading `-` as a wildcard turned a versionless row into "every
    # version ever", and CVE-2024-20758, whose own text says "2.4.6-p4 and
    # earlier", was reported against 2.4.8-p2. A false positive on the single
    # most important package in a Commerce store.
    na_only = {
        "id": "CVE-2026-0003",
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:adobe:commerce:-:*:*:*:*:*:*:*",
             "vulnerable": True},
            {"criteria": "cpe:2.3:a:adobe:commerce:2.4.6:p4:*:*:*:*:*:*",
             "vulnerable": True},
        ]}]}],
    }
    out = nvd.to_osv(na_only, prods)["affected"][0]
    check("a not-applicable version field yields no range at all",
          out.get("ranges"), None)
    check("and the enumerated versions are still kept",
          out["versions"], ["2.4.6-p4"])

    # `*` genuinely does mean every version, and must keep working.
    any_ver = {
        "id": "CVE-2026-0004",
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:adobe:commerce:*:*:*:*:*:*:*:*",
             "vulnerable": True},
        ]}]}],
    }
    check("a wildcard version field still means every version",
          nvd.to_osv(any_ver, prods)["affected"][0]["ranges"],
          [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])

    # adobe:magento is a string prefix of adobe:magento_open_source and a
    # different product; the comparison is field by field for that reason.
    check("product matching is field by field",
          nvd._product_prefix("cpe:2.3:a:adobe:magento_open_source:1:*",
                              "cpe:2.3:a:adobe:magento"), False)
    check("an escaped colon does not shift the fields",
          nvd._cpe_parts(r"cpe:2.3:a:v\:x:prod:1.0")[3:5], ["v:x", "prod"])
    check("a rejected CVE is withdrawn",
          bool(nvd.to_osv({**cve, "vulnStatus": "Rejected"}, prods)["withdrawn"]),
          True)
    check("a CVE affecting none of our products yields nothing",
          nvd.to_osv({"id": "CVE-2026-0002", "configurations": []}, prods), {})


def test_host_release_detection():
    check("an LTS release maps to the LTS bucket",
          hostpkgs.osv_ecosystem({"ID": "ubuntu", "VERSION_ID": "24.04"}),
          "Ubuntu:24.04:LTS")
    check("an interim release does not claim to be LTS",
          hostpkgs.osv_ecosystem({"ID": "ubuntu", "VERSION_ID": "25.04"}),
          "Ubuntu:25.04")
    check("debian maps to its major release",
          hostpkgs.osv_ecosystem({"ID": "debian", "VERSION_ID": "12.4"}),
          "Debian:12")
    # None rather than a guess: matching a machine against the wrong release
    # clears real findings and invents others.
    check("an unknown distribution yields no ecosystem",
          hostpkgs.osv_ecosystem({"ID": "arch", "VERSION_ID": ""}), None)
    check("a missing version yields no ecosystem",
          hostpkgs.osv_ecosystem({"ID": "ubuntu"}), None)



def test_ubuntu_priority_fills_in_for_a_missing_cvss():
    """Canonical publishes a vector on ~7 advisories in 10 and a band on the
    rest, per affected package rather than per advisory. Without lifting it,
    3,426 of 11,853 advisories would grade as `unknown` and no --fail-on
    threshold could ever reach them.
    """
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        adv = _osv("UBUNTU-CVE-2026-1", "Ubuntu:24.04:LTS", "expat",
                   [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])
        adv["affected"][0]["ecosystem_specific"] = {"ubuntu_priority": "high"}
        _ingest(conn, [adv], ecosystem="Ubuntu:24.04:LTS")
        row = conn.execute(
            "SELECT severity, severity_source FROM vulnerability "
            "WHERE id='UBUNTU-CVE-2026-1'").fetchone()
        check("the priority band becomes the severity", row[0], "high")
        # Recorded as qualitative, so a report never shows a band as a score.
        check("and is never presented as a computed score", row[1], "qualitative")

        # A real vector must still win over the band.
        adv2 = _osv("UBUNTU-CVE-2026-2", "Ubuntu:24.04:LTS", "expat",
                    [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    severity=[{"type": "CVSS_V3", "score":
                               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])
        adv2["affected"][0]["ecosystem_specific"] = {"ubuntu_priority": "low"}
        _ingest(conn, [adv2], ecosystem="Ubuntu:24.04:LTS")
        row = conn.execute(
            "SELECT severity, severity_source FROM vulnerability "
            "WHERE id='UBUNTU-CVE-2026-2'").fetchone()
        check("a published vector outranks the band", tuple(row),
              ("critical", "cvss"))


def test_unregistered_ecosystem_blocks_are_counted():
    """One Ubuntu bucket carries 21 ecosystem strings -- FIPS variants, Pro
    tiers, a BlueField image. Only registered releases are stored, and the
    number left out is reported rather than absorbed into a total that looks
    complete.
    """
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        feeds._SKIPPED_ECOSYSTEMS.clear()
        _ingest(conn, [
            _osv("A-1", "Ubuntu:Pro:FIPS:16.04:LTS", "expat",
                 [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]),
        ], ecosystem="Ubuntu:24.04:LTS")
        check("an unregistered ecosystem is counted, not dropped in silence",
              feeds._SKIPPED_ECOSYSTEMS.get("Ubuntu:Pro:FIPS:16.04:LTS"), 1)
        stored = conn.execute("SELECT COUNT(*) FROM affected").fetchone()[0]
        check("and is not stored", stored, 0)



def test_dpkg_matches_dpkg_itself():
    """Differential check against `dpkg --compare-versions`, where available.

    A hand-written comparator for somebody else's ordering rules is a claim,
    and the reference implementation is sitting on the machine. This asserts
    the claim rather than restating it: on a Debian-family host it compares
    every pair from a fixed edge-case pool, and it is skipped elsewhere
    rather than faked.
    """
    if not shutil.which("dpkg"):
        return
    eco = "Ubuntu:24.04:LTS"
    pool = [
        "1.0", "1.0~", "1.0~~", "1.0~~a", "1.0~rc1", "1.0a", "1.0+b",
        "1.0-1", "1.0-2", "1.0-1ubuntu1", "1:1.0", "2:1.0", "0:1.0",
        "1.00.0", "1.0.010", "1.10", "1.9",
        "6.8.0-1028.33", "6.8.0-1030.35", "2.4.58-1ubuntu8.15",
        "2.4.58-1ubuntu8.16", "1.0.25+dfsg-0ubuntu7", "1:2.39.2-1ubuntu1",
        "1:2.39.2-1ubuntu2", "2.39.3-9ubuntu6.6", "1:2.39.3-9ubuntu6.6",
    ]
    disagreements = []
    for i, a in enumerate(pool):
        for b in pool[i + 1:]:
            ours = V.compare(eco, a, b)
            if subprocess.run(["dpkg", "--compare-versions", a, "lt", b],
                              check=False).returncode == 0:
                theirs = -1
            elif subprocess.run(["dpkg", "--compare-versions", a, "gt", b],
                                check=False).returncode == 0:
                theirs = 1
            else:
                theirs = 0
            if ours != theirs:
                disagreements.append(f"{a} vs {b}: ours={ours} dpkg={theirs}")
    check("every pair agrees with dpkg --compare-versions", disagreements, [])
    check("and every version in the pool parsed",
          [v for v in pool if V.parse(eco, v) is None], [])



def test_release_scoped_feed_stores_only_its_release():
    """One Ubuntu archive carries sixteen releases, and fifteen are dead weight.

    A `Ubuntu:24.04:LTS` bucket also holds 20.04, 22.04, Pro tiers and FIPS
    variants. None can match a 24.04 host, and keeping them cost 199,880 rows
    and roughly half a gigabyte to answer no question. They are dropped and
    the number dropped is reported -- a silent trim would read as a feed that
    simply had less in it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        conn = store.connect(Path(tmp) / "t.db")
        feeds._SKIPPED_ECOSYSTEMS.clear()
        adv = {"id": "UBUNTU-CVE-2026-9", "modified": "2026-01-01T00:00:00Z",
               "affected": [
                   {"package": {"name": "expat", "ecosystem": "Ubuntu:24.04:LTS"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}]}]},
                   {"package": {"name": "expat", "ecosystem": "Ubuntu:22.04:LTS"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}]}]},
               ]}
        conn.execute("BEGIN")
        kept = feeds._record(conn, adv, "osv:Ubuntu:24.04:LTS",
                             "Ubuntu:24.04:LTS")
        conn.execute("COMMIT")
        check("only the synced release is stored", kept, 1)
        check("and it is the right one",
              {r[0] for r in conn.execute("SELECT ecosystem FROM affected")},
              {"Ubuntu:24.04:LTS"})
        check("the other release is counted, not silently dropped",
              feeds._SKIPPED_ECOSYSTEMS.get("Ubuntu:22.04:LTS"), 1)

        # A non-release bucket must NOT be trimmed: a crates.io archive
        # legitimately carries npm and Go advisories, and dropping them would
        # lose real coverage.
        feeds._SKIPPED_ECOSYSTEMS.clear()
        mixed = {"id": "GHSA-mixed", "modified": "2026-01-01T00:00:00Z",
                 "affected": [
                     {"package": {"name": "serde", "ecosystem": "crates.io"},
                      "ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": "0"}]}]},
                     {"package": {"name": "left-pad", "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": "0"}]}]},
                 ]}
        conn.execute("BEGIN")
        kept = feeds._record(conn, mixed, "osv:crates.io", "")
        conn.execute("COMMIT")
        check("a cross-ecosystem bucket keeps every registered ecosystem",
              kept, 2)



def test_host_findings_collapse_per_source_package():
    """179,983 findings on a fully-updated desktop is noise, not a signal.

    A machine that keeps its superseded kernels carries 69 versions of source
    `linux`, and every kernel advisory matches most of them. Collapsing to one
    row per (source package, advisory) brings that to 6,073 without dropping
    anything: the highest affected version is kept -- it is the one that says
    whether you are exposed now -- and the rest are counted on the finding.
    """
    import cli

    def f(package, version, vuln_id):
        return match.Finding(
            repo="host", manifest="dpkg", ecosystem="Ubuntu:24.04:LTS",
            package=package, version=version, scope="system", vuln_id=vuln_id,
            aliases=[], summary="", severity="high", severity_source="cvss",
            cvss_score=7.8, cvss_vector="", cwe="", kev=False, kev_added="",
            kev_ransomware="", fixed=["6.5.0-9.9"], confidence="very-high",
            evidence="version range 0 .. 6.5.0-9.9")

    findings = [
        f("linux", "5.15.0-100.110", "UBUNTU-CVE-2018-14634"),
        f("linux", "6.8.0-49.49", "UBUNTU-CVE-2018-14634"),
        f("linux", "5.15.0-92.102", "UBUNTU-CVE-2018-14634"),
        f("linux", "6.8.0-49.49", "UBUNTU-CVE-2019-13272"),
        f("expat", "2.5.0-1", "UBUNTU-CVE-2024-45490"),
    ]
    out, collapsed = cli._collapse_by_package(findings, "Ubuntu:24.04:LTS")
    check("one row per (source package, advisory)", len(out), 3)
    check("and the rest are counted, not lost", collapsed, 2)

    kernel = next(x for x in out if x.vuln_id == "UBUNTU-CVE-2018-14634")
    # The HIGHEST affected version is kept, because that is the one that says
    # whether the machine is exposed now rather than merely carrying old
    # packages. Under dpkg ordering 6.8.0-49.49 is the highest of the three.
    check("the highest affected version is the one reported",
          kernel.version, "6.8.0-49.49")
    check("and the others are stated on the finding",
          "also matches 2 older installed version(s)" in kernel.evidence, True)

    single = next(x for x in out if x.package == "expat")
    check("a package installed once gains no note",
          "also matches" in single.evidence, False)



def test_text_report_never_says_clean_over_a_gap():
    """The default format is what the CI gate prints, and it dropped the gaps.

    Only the Markdown renderer showed `meta["skipped"]`, so a repository whose
    single manifest could not be read printed "clean" -- a workflow pinned to
    a moving tag, a provider from a private registry, a lockfile no parser
    could open. Not checked is not the same as nothing wrong, and the format
    a gate prints is the one where that matters most.
    """
    meta = {"repo": "/x", "packages": 0, "lockfiles": 1, "synced": "2026-01-01",
            "notes": [],
            "skipped": [("ci.yml",
                         "1 action(s) on a moving tag, NOT checked")]}
    buf = io.StringIO()
    report.render_text([], [], meta, buf)
    out = buf.getvalue()
    check("the gap is printed", "moving tag" in out, True)
    check("it is labelled as not checked", "NOT checked" in out, True)
    check("and the verdict does not say clean", "clean" in out, False)

    # With genuinely nothing skipped, "clean" is the honest word and stays.
    buf = io.StringIO()
    report.render_text([], [], {**meta, "skipped": []}, buf)
    check("a real all-clear still says clean", "clean" in buf.getvalue(), True)


def test_rubygems_ordering():
    ordered("rubygems", "RubyGems", [
        "1.0.0.alpha", "1.0.0.beta", "1.0.0.beta.1", "1.0.0.beta.2",
        "1.0.0.rc1", "1.0.0", "1.0.1", "1.2.3", "1.2.3.1", "2.0", "10.0",
    ])
    check("rubygems: trailing zeros do not count",
          V.compare("RubyGems", "1.0", "1.0.0"), 0)
    check("rubygems: four numeric segments order numerically",
          V.compare("RubyGems", "3.17.0.6", "3.17.0.10"), -1)
    check("rubygems: a hyphen starts a prerelease",
          V.compare("RubyGems", "1.0-rc1", "1.0"), -1)
    check("rubygems: garbage is undecidable",
          V.parse("RubyGems", "not a version"), None)

    # Canonical segments, and the four pairs that were WRONG before they were
    # used. Gem::Version cuts at the first letter run and strips trailing zeros
    # from the two halves separately, so 1.0.pre is [1, "pre"] and 1.0.0.beta
    # is [1, "beta"] -- which makes beta the smaller. Comparing the raw
    # segments puts "pre" against a numeric 0 and reverses the pair.
    check("rubygems: 1.0.0.beta is below 1.0.pre",
          V.compare("RubyGems", "1.0.0.beta", "1.0.pre"), -1)
    check("rubygems: 1.0.0.alpha is below 1.0.pre",
          V.compare("RubyGems", "1.0.0.alpha", "1.0.pre"), -1)
    check("rubygems: 1.0.pre is above 1.0.0.a",
          V.compare("RubyGems", "1.0.pre", "1.0.0.a"), 1)
    check("rubygems: a trailing zero after a letter run is dropped too",
          V.compare("RubyGems", "1.0.beta.0", "1.0.beta"), 0)


def test_rubygems_is_not_semver():
    """Why RubyGems needs its own comparator rather than borrowing semver.

    semver's expression stops after the third numeric segment, so it REJECTS
    the four-segment versions RubyGems uses everywhere -- `parser` ships
    3.3.12.0 and rack was fixed in 2.2.6.3. An advisory bounded at a version
    semver cannot parse is `unresolved` for every package in the ecosystem,
    which is the whole feed reporting that it did not check.
    """
    check("semver cannot parse a four-segment gem version",
          V.parse_semver("2.2.6.3"), None)
    check("rubygems can", V.parse("RubyGems", "2.2.6.3") is not None, True)
    check("so semver leaves a real advisory bound undecidable",
          V.in_range("npm", "2.2.6.2", "2.2.0", "2.2.6.3", None), None)
    check("and rubygems decides it",
          V.in_range("RubyGems", "2.2.6.2", "2.2.0", "2.2.6.3", None), True)
    check("the fixed version itself is not affected",
          V.in_range("RubyGems", "2.2.6.3", "2.2.0", "2.2.6.3", None), False)


def test_gemfile_lock():
    """Indentation is the grammar, and a constraint is not a version."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root, "Gemfile.lock", (
            "GIT\n"
            "  remote: https://github.com/someone/thing.git\n"
            "  revision: 0d5ef3f\n"
            "  specs:\n"
            "    thing (1.2.3)\n"
            "\n"
            "PATH\n"
            "  remote: .\n"
            "  specs:\n"
            "    myapp (0.1.0)\n"
            "      nokogiri (~> 1.13)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    nokogiri (1.13.0-x86_64-linux)\n"
            "    puma (6.0.0)\n"
            "      nio4r (~> 2.0)\n"
            "    rack (2.2.6.3)\n"
            "    weird (1.0.0-armadillo)\n"
            "\n"
            "PLATFORMS\n"
            "  ruby\n"
            "  x86_64-linux\n"
            "\n"
            "DEPENDENCIES\n"
            "  myapp!\n"
            "  puma (~> 6.0)\n"
        ))
        pkgs, skipped, locks = manifests.collect(root)
        by = {p.name: p for p in pkgs if p.ecosystem == "RubyGems"}

        check("a locked gem is captured", by["puma"].version, "6.0.0")
        check("a four-segment version survives", by["rack"].version, "2.2.6.3")
        # The six-space lines are that gem's requirements. Reading one as a
        # version invents a dependency at a version nothing installed.
        check("a constraint line is not a package", "nio4r" in by, False)
        check("nor is a constraint under a PATH gem", "nokogiri" in by, True)
        check("the project's own PATH gem is not its own dependency",
              "myapp" in by, False)
        check("a git-sourced gem has no version to match", "thing" in by, False)
        # Bundler appends the platform to the version, and Gem::Version reads
        # the hyphen as a prerelease -- so 1.13.0-x86_64-linux would sort
        # BELOW 1.13.0 and an advisory range would miss it.
        check("a declared platform suffix is stripped",
              by["nokogiri"].version, "1.13.0")
        check("and the stripped version compares as the plain one",
              V.compare("RubyGems", by["nokogiri"].version, "1.13.0"), 0)
        # The suffix is stripped from the PLATFORMS list, not from a guess at
        # what a platform looks like: any pattern loose enough to catch `arm64`
        # also mangles this one.
        check("an undeclared suffix is left alone",
              by["weird"].version, "1.0.0-armadillo")
        check("both non-registry sources are reported, not dropped",
              len([r for r in skipped if "Gemfile.lock" in r[0]]), 2)
        check("Gemfile.lock is discovered as a lockfile",
              any(str(p).endswith("Gemfile.lock") for p in locks), True)


def main(argv) -> int:
    verbose = "-v" in argv or "--verbose" in argv
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        before = len(FAILURES)
        try:
            t()
        except Exception as e:  # noqa: BLE001 - a crashing test is a failure
            FAILURES.append(f"{t.__name__} raised {type(e).__name__}: {e}")
        if verbose:
            status = "ok  " if len(FAILURES) == before else "FAIL"
            print(f"  {status} {t.__name__}")
    for f in FAILURES:
        print(f"\n  FAIL {f}")
    print(f"\n  {COUNT - len(FAILURES)}/{COUNT} assertion(s) pass "
          f"across {len(tests)} test(s)\n")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
