"""Match an inventory of installed packages against the local advisory store.

Two rules govern everything here.

**Severity and confidence are independent.** Severity is a property of the
weakness; confidence is a property of *this* match. A CVSS 9.8 matched
through a range whose lower bound would not parse is high severity and low
confidence, and collapsing the two into one number destroys the only signal a
developer can act on.

**Undecided is not clean.** When a comparator cannot parse a bound, the
package goes into `unresolved` and is reported as such. It never falls
through to "not affected", because a scanner that converts "I could not
check" into "you are fine" is worse than no scanner at all.

Precedence, following the OSV specification: `ranges` is the normative form
and `versions` is a convenience enumeration. So ranges decide when present,
and the enumeration is used to corroborate -- an installed version that both
a range and the enumeration agree on is `certain`, a range alone is
`very-high`, an enumeration alone (no ranges published) is `very-high`, and
a range with no upper bound is `high` because "everything from here on" is
the weakest useful claim an advisory can make.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import ecosystems as E
import versions as V

# Severity ordering, used for sorting and for policy thresholds.
SEVERITY_ORDER = {
    "critical": 4, "high": 3, "medium": 2, "low": 1,
    "none": 0, "unknown": 0,
}
CONFIDENCE_ORDER = {
    "certain": 4, "very-high": 3, "high": 2, "medium": 1, "low": 0,
}
# What the application runs, then what only builds it. An unknown scope sorts
# with runtime rather than below it: a scope nobody recognised is not evidence
# that the package is harmless.
SCOPE_ORDER = {"runtime": 0, "dev": 2}


@dataclass
class Finding:
    repo: str
    manifest: str
    ecosystem: str
    package: str
    version: str
    scope: str
    vuln_id: str
    aliases: list
    summary: str
    severity: str
    severity_source: str
    cvss_score: object
    cvss_vector: str
    cwe: str
    kev: bool
    kev_added: str
    kev_ransomware: str
    fixed: list
    confidence: str
    evidence: str
    refs: list = field(default_factory=list)
    superseded: list = field(default_factory=list)  # published fixes already at or below `version`
    also_affects: list = field(default_factory=list)  # editions this store ships that carry the same advisory
    mapped_to: object = None    # manifests.MatchedAs when matched under another name

    @property
    def sort_key(self):
        # KEV first, then severity, then runtime before dev, then confidence.
        # KEV outranks CVSS because "someone is exploiting this today" is a
        # different kind of fact from "this would be bad if exploited", and it
        # outranks scope for the same reason: an exploited build dependency is
        # a supply chain, not a footnote.
        #
        # Scope sits below severity and above confidence: what the application
        # runs outranks what only builds it, but not by enough to lift a low
        # finding over a critical one. On a Magento tree the build toolchain
        # carries more advisories than the store does, so without this the
        # findings that reach production read last.
        return (
            0 if self.kev else 1,
            -SEVERITY_ORDER.get(self.severity, 0),
            SCOPE_ORDER.get(self.scope, 1),
            -CONFIDENCE_ORDER.get(self.confidence, 0),
            self.package,
        )


@dataclass
class Unresolved:
    repo: str
    manifest: str
    ecosystem: str
    package: str
    version: str
    vuln_id: str
    reason: str


def _advisories_for(conn, ecosystem: str, norm: str):
    return list(conn.execute(
        """SELECT a.id AS aid, a.package, v.*
           FROM affected a JOIN vulnerability v ON v.id = a.vuln_id
           WHERE a.ecosystem = ? AND a.package_norm = ?""",
        (ecosystem, norm),
    ))


def decide(conn, aid: int, ecosystem: str, version: str):
    """(affected, confidence, evidence, fixed_versions, reason_if_unresolved)."""
    # GIT ranges are excluded: their bounds are commit SHAs, which no version
    # comparator can order against a package version. An advisory that
    # publishes ONLY a GIT range is genuinely undecidable and falls through to
    # the unresolved path below, which is the correct answer -- what was wrong
    # was letting a GIT range sit beside a perfectly good ECOSYSTEM range and
    # drag the whole decision into "undecided".
    ranges = list(conn.execute(
        "SELECT introduced, fixed, last_affected FROM affected_range "
        "WHERE affected_id = ? AND range_type IN ('ECOSYSTEM','SEMVER')",
        (aid,)))
    enumerated = [r[0] for r in conn.execute(
        "SELECT version FROM affected_version WHERE affected_id = ?", (aid,))]

    fixed = sorted({r["fixed"] for r in ranges if r["fixed"]})
    in_enum = version in enumerated

    if not ranges:
        if enumerated:
            if in_enum:
                return (True, "very-high",
                        "listed in the advisory's affected versions", fixed, None)
            return False, None, None, fixed, None
        return None, None, None, fixed, "advisory publishes neither ranges nor versions"

    undecided = False
    open_ended = False
    for r in ranges:
        verdict = V.in_range(
            ecosystem, version, r["introduced"], r["fixed"], r["last_affected"]
        )
        if verdict is None:
            undecided = True
            continue
        if verdict:
            bound = r["fixed"] or r["last_affected"]
            if bound:
                if in_enum:
                    evidence = (
                        "version range and the advisory's version list agree "
                        f"({r['introduced'] or '0'} .. {bound})"
                    )
                    return True, "certain", evidence, fixed, None
                return (True, "very-high",
                        f"version range {r['introduced'] or '0'} .. {bound}",
                        fixed, None)
            open_ended = True

    if open_ended:
        return (True, "high",
                "range is open-ended: introduced with no published fix", fixed, None)
    if undecided:
        return (None, None, None, fixed,
                (f"version {version!r} or an advisory bound will not parse "
                 f"under {ecosystem} version rules"))
    # Ranges parsed cleanly and none matched, but the enumeration names this
    # exact version. That is the same direct claim an enumeration-only
    # advisory makes, so it is graded the same. A range that does not cover
    # the version says nothing about it and cannot weaken a statement that
    # names it -- NVD caps a Magento range where its CPE enumeration takes
    # over, so the range is the older half of the record and the list is the
    # newer one.
    if in_enum:
        evidence = ("listed in the advisory's affected versions, which its "
                    "published ranges do not cover")
        return True, "very-high", evidence, fixed, None
    return False, None, None, fixed, None


def remediation(ecosystem: str, version: str, fixed):
    """(fixes worth upgrading to, fixes already behind `version`).

    A published fix at or below what is installed is not a remediation. It is
    the upper bound of an earlier range, or the point where a CPE record
    stopped using a range and began listing versions one by one -- and an
    advisory carries every bound it has ever published, not only the one that
    matched. Printing it tells a store on 2.4.8-p2 to upgrade to 2.4.4, which
    is worse advice than none: it reads as actionable, it is not, and acting
    on it moves the store backwards into everything fixed since.

    A bound that will not parse stays in the actionable list. Dropping it
    would be a scanner deciding silently that a fix it could not read is a
    fix nobody needs.
    """
    ahead, behind = [], []
    for v in fixed:
        try:
            order = V.compare(ecosystem, v, version)
        except (TypeError, ValueError):
            order = None
        (behind if order is not None and order <= 0 else ahead).append(v)
    return ahead, behind


def scan_packages(conn, repo: str, packages, include_dev: bool = True):
    """Match one repository's inventory. Returns (findings, unresolved)."""
    findings, unresolved = [], []
    for pkg in packages:
        if pkg.scope == "dev" and not include_dev:
            continue
        unmatchable = getattr(pkg, "unmatchable", "")
        if unmatchable:
            unresolved.append(Unresolved(
                repo, pkg.manifest, pkg.ecosystem, pkg.name, pkg.version,
                "", unmatchable))
            continue
        # A Terraform provider is locked under `Terraform` and its advisories
        # are published under `Go`. The advisory ecosystem is what decides
        # both which rows to look at and which comparator orders them --
        # using the manifest name would find nothing and, worse, would leave
        # the version scheme undefined so every match came back unresolved.
        eco = E.advisory_ecosystem(pkg.ecosystem)
        seen = set()
        for name, version, mapped in _lookups(pkg):
            for row in _advisories_for(conn, eco, V.normalize_name(eco, name)):
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                affected, conf, evidence, fixed, reason = decide(
                    conn, row["aid"], eco, version
                )
                fixed, superseded = remediation(eco, version, fixed)
                if affected is None:
                    reason = reason or "undecided"
                    if mapped:
                        reason = f"{reason}; matched as {mapped.describe()}"
                    unresolved.append(Unresolved(
                        repo, pkg.manifest, pkg.ecosystem, pkg.name, pkg.version,
                        row["id"], reason))
                    continue
                if not affected:
                    continue
                aliases = [a[0] for a in conn.execute(
                    "SELECT alias FROM alias WHERE vuln_id = ?", (row["id"],))]
                findings.append(Finding(
                    repo=repo, manifest=pkg.manifest, ecosystem=pkg.ecosystem,
                    package=pkg.name, version=pkg.version, scope=pkg.scope,
                    vuln_id=row["id"], aliases=aliases,
                    summary=row["summary"] or "",
                    severity=row["severity"] or "unknown",
                    severity_source=row["severity_source"] or "none",
                    cvss_score=row["cvss_score"], cvss_vector=row["cvss_vector"] or "",
                    cwe=row["cwe"] or "", kev=bool(row["kev"]),
                    kev_added=row["kev_added"] or "",
                    kev_ransomware=row["kev_ransomware"] or "",
                    fixed=fixed, confidence=conf, evidence=evidence,
                    refs=(row["refs"] or "").split("\n") if row["refs"] else [],
                    superseded=superseded,
                    mapped_to=mapped,
                ))
    findings = _fold_contained_editions(findings, packages)
    findings.sort(key=lambda f: f.sort_key)
    return findings, unresolved


def _fold_contained_editions(findings, packages):
    """One advisory against one store is one finding, not one per edition.

    Adobe Commerce ships Magento Open Source inside it at the same version, so
    a Commerce lockfile holds both metapackages and NVD files the same CVE
    against both CPE products. Left alone that prints every Adobe advisory
    twice -- and the two lines disagree, because each CPE product caps its
    range at a different release, so the reader is handed two remediations for
    one store and no way to tell which is theirs.

    The contained edition's finding is folded into the container's and named
    there, so nothing is dropped: an advisory that reaches only the contained
    edition never had a container finding to fold into and is reported as it
    stands.
    """
    contained = {p.name: p.contained_by for p in packages
                 if getattr(p, "contained_by", "")}
    if not contained:
        return findings
    by_key = {(f.manifest, f.vuln_id, f.package, f.version): f for f in findings}
    kept = []
    for f in findings:
        container = contained.get(f.package)
        host = by_key.get((f.manifest, f.vuln_id, container, f.version)) if container else None
        if host is None:
            kept.append(f)
            continue
        if f.package not in host.also_affects:
            host.also_affects.append(f.package)
    return kept


def _lookups(pkg):
    """(name, version, mapping) for the package's own name, then for each package it is also matched as."""
    yield pkg.name, pkg.version, None
    for mapped in getattr(pkg, "matched_as", ()):
        yield mapped.name, mapped.version, mapped


@dataclass
class InventoryHit:
    repo: str
    manifest: str
    package: str
    version: str
    matched_as: str     # "name version" of the mapping that matched, or ""
    confidence: str     # "" when undecided
    fixed: list
    reason: str         # why it could not be decided, or ""


def inventory_hits(conn, vuln_id: str) -> list:
    """Every inventoried package one advisory affects or cannot be decided for."""
    blocks = list(conn.execute(
        "SELECT id, ecosystem, package FROM affected WHERE vuln_id = ?", (vuln_id,)))
    hits = []
    for block, r in _inventory_rows(conn, blocks):
        # Decided under the advisory's ecosystem, whose comparator orders its bounds.
        version = r["match_version"] or r["version"]
        affected, conf, _evidence, fixed, reason = decide(
            conn, block["id"], block["ecosystem"], version)
        if affected is False:
            continue
        mapped = f"{r['match_name']} {version}" if r["match_name"] else ""
        hits.append(InventoryHit(r["repo"], r["manifest"], r["name"], r["version"],
                                 mapped, conf or "", fixed, reason or ""))
    ecosystems = {e for b in blocks for e in E.manifest_ecosystems(b["ecosystem"])}
    for eco in sorted(ecosystems):
        for r in conn.execute(
                """SELECT DISTINCT repo, manifest, name, version, unmatchable
                   FROM package WHERE ecosystem = ? AND unmatchable != ''""", (eco,)):
            hits.append(InventoryHit(r["repo"], r["manifest"], r["name"], r["version"],
                                     "", "", [], r["unmatchable"]))
    return hits


def _inventory_rows(conn, blocks):
    """(block, package row) for each inventoried package an affected block names, directly or through a mapping."""
    for block in blocks:
        for eco in E.manifest_ecosystems(block["ecosystem"]):
            for r in conn.execute(
                    """SELECT DISTINCT repo, manifest, name, version, match_name, match_version
                       FROM package
                       WHERE ecosystem = ? AND unmatchable = ''
                         AND (CASE match_name WHEN '' THEN name ELSE match_name END)
                             = ? COLLATE NOCASE""", (eco, block["package"])):
                yield block, r


def policy_verdict(findings, fail_on="high", min_confidence="high",
                   fail_on_kev=True):
    """Which findings breach the policy. Returns (failing, warning).

    Both axes are applied, which is the whole point of keeping them separate:
    a critical finding at low confidence warns rather than failing, and any
    KEV entry fails regardless of either axis.
    """
    fail_rank = SEVERITY_ORDER.get(fail_on, 3)
    conf_rank = CONFIDENCE_ORDER.get(min_confidence, 2)
    failing, warning = [], []
    for f in findings:
        sev = SEVERITY_ORDER.get(f.severity, 0)
        conf = CONFIDENCE_ORDER.get(f.confidence, 0)
        if (fail_on_kev and f.kev) or (sev >= fail_rank and conf >= conf_rank):
            failing.append(f)
        elif sev >= fail_rank:
            warning.append(f)
    return failing, warning
