"""Render findings as terminal text, JSON, SARIF or Markdown.

The Markdown report uses Obsidian-style callouts: the verdict comes first in
an at-a-glance callout, magnitudes are block-character bars, and each verdict
carries an emoji against a stated budget.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

SEV_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🔵", "none": "⚪", "unknown": "⚪",
}
SEV_ORDER_DESC = ["critical", "high", "medium", "low", "none", "unknown"]

_ANSI = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "none": "\033[2m", "unknown": "\033[2m",
    "kev": "\033[1;97;41m", "dim": "\033[2m", "bold": "\033[1m",
    "reset": "\033[0m",
}


def _colour_enabled(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _c(key: str, text: str, on: bool) -> str:
    return f"{_ANSI[key]}{text}{_ANSI['reset']}" if on else text


def summarise(findings) -> dict:
    by_sev = dict.fromkeys(SEV_ORDER_DESC, 0)
    for f in findings:
        by_sev[f.severity if f.severity in by_sev else "unknown"] += 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "kev": sum(1 for f in findings if f.kev),
        "packages": len({(f.ecosystem, f.package) for f in findings}),
    }


def bar(n: int, total: int, width: int = 10) -> str:
    if total <= 0:
        return "░" * width
    filled = min(width, round(width * n / total))
    return "█" * filled + "░" * (width - filled)


# --------------------------------------------------------------------------
# terminal
# --------------------------------------------------------------------------

def render_text(findings, unresolved, meta, stream=sys.stdout, verbose=False):
    on = _colour_enabled(stream)
    w = stream.write
    s = summarise(findings)

    w(_c("bold", f"\ndep-intel — {meta['repo']}\n", on))
    w(f"  {meta['packages']} package(s) from {meta['lockfiles']} lockfile(s)"
      f" · store synced {meta.get('synced', 'never')}\n\n")

    if not findings:
        w("  no known vulnerable dependencies\n\n"
          if not (meta.get("skipped") or unresolved) else
          "  no known vulnerable dependencies among what could be checked\n\n")
    for f in findings:
        tag = _c("kev", " KEV ", on) + " " if f.kev else ""
        score = f" CVSS {f.cvss_score}" if f.cvss_score is not None else ""
        w(f"  {tag}{_c(f.severity, f.severity.upper(), on)}{score}"
          f"  {_c('bold', f.package, on)} {f.version}"
          f" {_c('dim', f'({f.scope})', on)}\n")
        w(f"      {f.vuln_id}"
          + (f"  {', '.join(f.aliases[:3])}" if f.aliases else "") + "\n")
        if f.summary:
            w(f"      {f.summary[:150]}\n")
        w(f"      {_c('dim', 'confidence: ' + f.confidence + ' — ' + f.evidence, on)}\n")
        w(f"      {_c('dim', 'manifest:   ' + f.manifest, on)}\n")
        w("      fixed in:   " + (", ".join(f.fixed) if f.fixed
                                  else _c("dim", "no fixed version published", on))
          + "\n")
        if f.kev and f.kev_ransomware.lower() == "known":
            w("      " + _c("kev", "used in known ransomware campaigns", on) + "\n")
        w("\n")

    if unresolved:
        w(_c("bold", f"  {len(unresolved)} advisory match(es) could not be "
                     "decided — reported, not cleared\n", on))
        shown = unresolved if verbose else unresolved[:5]
        for u in shown:
            w(f"      {u.package} {u.version} vs {u.vuln_id}: {u.reason}\n")
        if not verbose and len(unresolved) > len(shown):
            w(f"      … {len(unresolved) - len(shown)} more (--verbose)\n")
        w("\n")

    # Coverage gaps belong in the DEFAULT format, not only in Markdown. This
    # is the format the CI gate prints, and without these lines a repository
    # whose only manifest could not be read reported "clean" -- a workflow
    # pinned to a moving tag, a provider from a private registry, a lockfile
    # no parser could open. That is the exact claim this tool exists to
    # refuse: not checked is not the same as nothing wrong.
    skipped = meta.get("skipped") or []
    if skipped:
        w(_c("bold", f"  {len(skipped)} coverage gap(s) — NOT checked\n", on))
        shown = skipped if verbose else skipped[:5]
        for path, why in shown:
            w(f"      {path}: {why}\n")
        if not verbose and len(skipped) > len(shown):
            w(f"      … {len(skipped) - len(shown)} more (--verbose)\n")
        w("\n")

    parts = [f"{SEV_EMOJI[k]} {v} {k}" for k, v in s["by_severity"].items() if v]
    if parts:
        verdict = " · ".join(parts)
    elif skipped or unresolved:
        # Never the word "clean" when something was not looked at.
        verdict = "no findings, but see the gap(s) above"
    else:
        verdict = "clean"
    w("  " + verdict
      + (f"  ·  {s['kev']} known-exploited" if s["kev"] else "") + "\n")
    for line in meta.get("notes", []):
        w(f"  note: {line}\n")
    w("\n")


# --------------------------------------------------------------------------
# json
# --------------------------------------------------------------------------

def render_json(findings, unresolved, meta) -> str:
    return json.dumps({
        "tool": "dep-intel",
        "tool_version": meta.get("tool_version"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repo": meta["repo"],
        "store": {
            "synced": meta.get("synced"),
            "vulnerabilities": meta.get("store_vulns"),
            "feeds": meta.get("feeds", []),
        },
        "inventory": {
            "packages": meta["packages"],
            "lockfiles": meta["lockfiles"],
            "skipped": meta.get("skipped", []),
        },
        "summary": summarise(findings),
        "findings": [{
            "package": f.package, "version": f.version, "ecosystem": f.ecosystem,
            "scope": f.scope, "manifest": f.manifest,
            "id": f.vuln_id, "aliases": f.aliases, "summary": f.summary,
            "severity": f.severity, "severity_source": f.severity_source,
            "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
            "cwe": f.cwe.split(",") if f.cwe else [],
            "known_exploited": f.kev, "kev_added": f.kev_added,
            "kev_ransomware": f.kev_ransomware,
            "fixed_versions": f.fixed,
            "confidence": f.confidence, "evidence": f.evidence,
            "references": f.refs[:5],
        } for f in findings],
        "unresolved": [{
            "package": u.package, "version": u.version, "ecosystem": u.ecosystem,
            "manifest": u.manifest, "id": u.vuln_id, "reason": u.reason,
        } for u in unresolved],
    }, indent=2)


# --------------------------------------------------------------------------
# sarif
# --------------------------------------------------------------------------

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "none": "note", "unknown": "note"}


def render_sarif(findings, unresolved, meta) -> str:
    rules, seen = [], {}
    for f in findings:
        if f.vuln_id in seen:
            continue
        seen[f.vuln_id] = len(rules)
        rules.append({
            "id": f.vuln_id,
            "name": f.vuln_id,
            "shortDescription": {"text": (f.summary or f.vuln_id)[:200]},
            "fullDescription": {"text": f.summary or ""},
            "helpUri": (f.refs[0] if f.refs else
                        f"https://osv.dev/vulnerability/{f.vuln_id}"),
            "properties": {
                "security-severity": (str(f.cvss_score)
                                      if f.cvss_score is not None else "0.0"),
                "tags": ["security", "dependency"]
                        + (["known-exploited"] if f.kev else [])
                        + ([f.cwe] if f.cwe else []),
            },
        })

    results = [{
        "ruleId": f.vuln_id,
        "ruleIndex": seen[f.vuln_id],
        "level": _SARIF_LEVEL.get(f.severity, "warning"),
        "message": {"text":
            f"{f.package} {f.version} is affected by {f.vuln_id}"
            + (" (CISA known-exploited)" if f.kev else "")
            + (f"; fixed in {', '.join(f.fixed)}" if f.fixed
               else "; no fixed version published")
            + f". Confidence {f.confidence}: {f.evidence}."},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.manifest},
            "region": {"startLine": 1},
        }}],
        "partialFingerprints": {
            "depIntel/v1": f"{f.ecosystem}|{f.package}|{f.version}|{f.vuln_id}"},
    } for f in findings]

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dep-intel",
                "version": str(meta.get("tool_version", "0")),
                "informationUri": "https://osv.dev",
                "rules": rules,
            }},
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "unresolvedMatches": len(unresolved),
                    "storeSynced": meta.get("synced"),
                },
            }],
            "results": results,
        }],
    }, indent=2)


# --------------------------------------------------------------------------
# markdown -- a report meant to be read, verdict first
# --------------------------------------------------------------------------

def render_markdown(findings, unresolved, meta) -> str:
    s = summarise(findings)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    name = os.path.basename(meta["repo"].rstrip("/")) or meta["repo"]

    if s["kev"]:
        verdict = (f"🔴 **{s['kev']} known-exploited "
                   f"{'vulnerability' if s['kev'] == 1 else 'vulnerabilities'}** "
                   "present — CISA lists these as exploited in the wild")
    elif s["by_severity"]["critical"]:
        verdict = f"🔴 **{s['by_severity']['critical']} critical**"
    elif s["by_severity"]["high"]:
        verdict = f"🟠 **{s['by_severity']['high']} high**"
    elif s["total"]:
        verdict = f"🟡 **{s['total']} finding(s)**, none high or critical"
    else:
        verdict = "🟢 **no known vulnerable dependencies**"

    out = [
        "---",
        f"date: {today}",
        "type: findings",
        "status: draft",
        f"project: {name}",
        "tags:",
        "  - findings",
        "  - security",
        "  - dependencies",
        "  - cve",
        "---",
        "",
        f"# Dependency Vulnerabilities — {name}",
        "",
        "> [!abstract] What this is",
        (f"> Every package locked in `{meta['repo']}`, matched against a local "
         "copy of the OSV advisory feeds and the CISA Known Exploited "
         "Vulnerabilities catalogue."),
        ">",
        ("> Generated by `dep-intel`. Nothing about this "
         "repository left the machine: the whole advisory feed is downloaded "
         "and the matching happens offline."),
        "",
        "> [!info] At a glance",
        f"> - **Verdict — {verdict}.**",
        (f"> - **Inventory** — **{meta['packages']}** packages from "
         f"**{meta['lockfiles']}** lockfile(s)."),
        (f"> - **Findings** — **{s['total']}** across **{s['packages']}** "
         "distinct packages."),
        (f"> - **Store** — **{meta.get('store_vulns', 0)}** advisories, "
         f"last synced `{meta.get('synced', 'never')}`."),
    ]
    if unresolved:
        out.append(
            f"> - **Undecided — {len(unresolved)} match(es) could not be "
            "resolved** and are reported rather than cleared. See "
            "[[#Undecided matches]].")
    out += ["", "## Severity", ""]

    if s["total"]:
        out += ["| | Severity | Count | Share |", "|:--:|---|--:|---|"]
        for k in SEV_ORDER_DESC:
            n = s["by_severity"][k]
            if n:
                out.append(f"| {SEV_EMOJI[k]} | **{k.title()}** | {n} | "
                           f"`{bar(n, s['total'])}` |")
        out.append("")
    else:
        out += [("Nothing matched. That is a statement about the advisories "
                 "in the local store on the date above, not a guarantee."), ""]

    kevs = [f for f in findings if f.kev]
    if kevs:
        out += [
            "> [!danger] Known exploited — treat these first",
            ("> CISA lists the following as exploited in the wild. This "
             "ranking is deliberately independent of CVSS: *someone is using "
             "this today* is a different kind of fact from *this would be bad "
             "if used*."),
            "",
            "| Package | Version | Advisory | Added to KEV | Ransomware | Fixed in |",
            "|---|---|---|---|:--:|---|",
        ]
        for f in kevs:
            ransom = "⚠️ yes" if f.kev_ransomware.lower() == "known" else "—"
            out.append(
                f"| `{f.package}` | `{f.version}` | {f.vuln_id} | "
                f"{f.kev_added or '—'} | {ransom} | "
                f"{', '.join(f'`{v}`' for v in f.fixed) or '**none published**'} |")
        out.append("")

    if findings:
        out += ["## Findings", "",
                ("Severity is a property of the weakness; confidence is a "
                 "property of *this* match. They are reported separately on "
                 "purpose — a high-severity advisory matched through a bound "
                 "that would not parse is not the same claim as one matched "
                 "exactly."), "",
                "| | Package | Version | Advisory | CVSS | Confidence | Fixed in | Scope |",
                "|:--:|---|---|---|--:|---|---|---|"]
        for f in findings:
            score = f"{f.cvss_score}" if f.cvss_score is not None else "—"
            kev = "🔥 " if f.kev else ""
            out.append(
                f"| {SEV_EMOJI[f.severity]} | {kev}`{f.package}` | "
                f"`{f.version}` | {f.vuln_id} | {score} | {f.confidence} | "
                f"{', '.join(f'`{v}`' for v in f.fixed) or '—'} | {f.scope} |")
        out.append("")

    if unresolved:
        out += ["## Undecided matches", "",
                "> [!warning] These are not clean results",
                ("> An advisory named one of these packages and the version "
                 "comparison could not be completed. They are listed because "
                 "the alternative — letting them fall through as *not "
                 "affected* — turns *I could not check* into *you are fine*."),
                "",
                "| Package | Version | Advisory | Why |", "|---|---|---|---|"]
        for u in unresolved[:60]:
            out.append(f"| `{u.package}` | `{u.version}` | {u.vuln_id} | {u.reason} |")
        if len(unresolved) > 60:
            out.append(f"| … | | | {len(unresolved) - 60} more |")
        out.append("")

    if meta.get("skipped"):
        out += ["## Coverage gaps", "",
                ("Files that were found but could not contribute an exact "
                 "version. Listed so the report's silence about them is "
                 "visible."),
                "", "| Path | Reason |", "|---|---|"]
        for path, why in meta["skipped"][:40]:
            out.append(f"| `{path}` | {why} |")
        out.append("")

    out += ["## Method", "",
            "| | |", "|---|---|",
            f"| Repository | `{meta['repo']}` |",
            f"| Lockfiles read | {meta['lockfiles']} |",
            f"| Packages | {meta['packages']} |",
            (f"| Advisory store | {meta.get('store_vulns', 0)} advisories, "
             f"synced `{meta.get('synced', 'never')}` |"),
            f"| Feeds | {', '.join(meta.get('feeds', [])) or '—'} |",
            f"| Tool | `dep-intel` {meta.get('tool_version', '')} |",
            "",
            "> [!warning] What this cannot tell you",
            ("> A clean result means no advisory **in the local store on the "
             "sync date** names an installed version. It does not mean the "
             "code is safe, and it goes stale the moment a new advisory is "
             "published — `dep-intel sync` is what moves that date."),
            ""]
    return "\n".join(out) + "\n"
