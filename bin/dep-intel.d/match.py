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

    @property
    def sort_key(self):
        # KEV first, then severity, then confidence. KEV outranks CVSS because
        # "someone is exploiting this today" is a different kind of fact from
        # "this would be bad if exploited".
        return (
            0 if self.kev else 1,
            -SEVERITY_ORDER.get(self.severity, 0),
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
    # Ranges parsed cleanly and none matched. If the enumeration disagrees,
    # believe the enumeration and say why -- it is a published statement about
    # this exact version, which a range is not.
    if in_enum:
        return (True, "medium",
                "advisory lists this exact version although its ranges exclude it",
                fixed, None)
    return False, None, None, fixed, None


def scan_packages(conn, repo: str, packages, include_dev: bool = True):
    """Match one repository's inventory. Returns (findings, unresolved)."""
    findings, unresolved = [], []
    for pkg in packages:
        if pkg.scope == "dev" and not include_dev:
            continue
        # A Terraform provider is locked under `Terraform` and its advisories
        # are published under `Go`. The advisory ecosystem is what decides
        # both which rows to look at and which comparator orders them --
        # using the manifest name would find nothing and, worse, would leave
        # the version scheme undefined so every match came back unresolved.
        eco = E.advisory_ecosystem(pkg.ecosystem)
        norm = V.normalize_name(eco, pkg.name)
        for row in _advisories_for(conn, eco, norm):
            affected, conf, evidence, fixed, reason = decide(
                conn, row["aid"], eco, pkg.version
            )
            if affected is None:
                unresolved.append(Unresolved(
                    repo, pkg.manifest, pkg.ecosystem, pkg.name, pkg.version,
                    row["id"], reason or "undecided"))
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
            ))
    findings.sort(key=lambda f: f.sort_key)
    return findings, unresolved


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
