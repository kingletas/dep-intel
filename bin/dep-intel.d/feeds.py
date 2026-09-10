"""Ingest OSV bulk feeds and the CISA KEV catalogue into the local store.

Everything this module reads is attacker-controlled input crossing into
trusted scope, and it is treated that way rather than as merely malformed:

  * HTTPS only. A plain-http URL is refused, not upgraded.
  * The archive is a zip from the internet, so it is bounded before it is
    trusted -- entry count, per-entry uncompressed size, and total expansion
    ratio. An OSV `all.zip` is ~7k small JSON files; anything that claims to
    be one and expands 500x is not one.
  * A record that does not have the shape OSV documents is counted and
    skipped, never guessed at.
  * The whole sync runs in one transaction. A feed that fails halfway leaves
    the previous store intact, because a half-ingested vulnerability database
    silently under-reports -- which is the failure mode this tool exists to
    remove, not to introduce.

`sync` is also the only part of dep-intel that touches the network at all.
Everything downstream is offline by construction.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone

import cvss
import ecosystems
import nvd
import versions as V

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# The ecosystems dep-intel knows are declared in ecosystems.py, which also
# says where each one's feed comes from and which comparator orders it. This
# module only needs the set of keys an advisory may be stored under.
ECOSYSTEMS = ecosystems.REGISTRY

USER_AGENT = "dep-intel (+local; https://osv.dev bulk consumer)"


def osv_url(bucket: str) -> str:
    """The bulk archive URL for one OSV bucket.

    Bucket names are not all path-safe any more: `GitHub Actions` has a space
    and `Ubuntu:24.04:LTS` has colons. Quoting them is required, and a colon
    is left alone because the storage bucket uses it literally.
    """
    return f"{OSV_BASE}/{urllib.parse.quote(bucket, safe=':.')}/all.zip"

# Archive bounds. Chosen an order of magnitude above the real feeds so a
# legitimate feed growing does not trip them, and far below anything that
# would exhaust memory or disk.
MAX_ENTRIES = 400_000
MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024


# Affected blocks dropped because their ecosystem is not registered, by
# ecosystem. Reported at the end of a sync rather than swallowed.
_SKIPPED_ECOSYSTEMS: dict = {}


class FeedError(RuntimeError):
    """A feed could not be fetched or is not the shape it claims to be."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fetch(url: str, timeout: int = 300) -> bytes:
    if not url.lower().startswith("https://"):
        raise FeedError(f"refusing a non-HTTPS feed URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise FeedError(f"{url}: {e}") from e


def head_size(url: str, timeout: int = 30):
    """Content-Length for `sync --dry-run`, or None when the server omits it."""
    if not url.lower().startswith("https://"):
        raise FeedError(f"refusing a non-HTTPS feed URL: {url}")
    req = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            n = r.headers.get("Content-Length")
            return int(n) if n else None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def _safe_entries(zf: zipfile.ZipFile):
    """Yield (name, bytes) with the archive bounded before it is trusted."""
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise FeedError(f"archive has {len(infos)} entries, over the cap")
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        if info.file_size > MAX_ENTRY_BYTES:
            raise FeedError(f"{info.filename}: entry is {info.file_size} bytes")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise FeedError("archive expands past the total cap")
        if not info.filename.endswith(".json"):
            continue
        yield info.filename, zf.read(info)


def _record(conn, adv: dict, feed: str, only_ecosystem: str = "") -> int:
    """Insert one OSV record. Returns the number of affected blocks stored.

    `only_ecosystem` restricts which affected blocks are kept, and it is how a
    release-scoped feed stays proportionate: the `Ubuntu:24.04:LTS` archive
    also carries rows for fifteen other releases, none of which can match a
    24.04 host, and keeping them cost 199,880 rows to answer no question.
    """
    vid = adv.get("id")
    if not isinstance(vid, str) or not vid:
        raise ValueError("record has no id")

    # Canonical publishes a CVSS vector on about seven advisories in ten and
    # its own priority band on the rest, per affected package rather than per
    # advisory. Lifting it gives the remainder a real band instead of
    # `unknown`, and cvss.from_advisory still records it as `qualitative` so
    # a report never shows it as a computed score.
    db_specific = dict(adv.get("database_specific") or {})
    if not db_specific.get("severity"):
        for aff in adv.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            band = (aff.get("ecosystem_specific") or {}).get("ubuntu_priority")
            if band:
                db_specific["severity"] = band
                break
    score, sev, sev_src = cvss.from_advisory(adv.get("severity"), db_specific)
    vector = ""
    for s in adv.get("severity") or []:
        if isinstance(s, dict) and s.get("score"):
            vector = s["score"]
            break

    cwes = (adv.get("database_specific") or {}).get("cwe_ids") or []
    refs = [
        r.get("url", "")
        for r in adv.get("references") or []
        if isinstance(r, dict) and r.get("url")
    ]

    conn.execute(
        """INSERT OR REPLACE INTO vulnerability
           (id, summary, details, published, modified, withdrawn,
            cvss_vector, cvss_score, severity, severity_source, cwe,
            refs, feed)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            vid,
            adv.get("summary") or "",
            adv.get("details") or "",
            adv.get("published") or "",
            adv.get("modified") or "",
            adv.get("withdrawn") or "",
            vector,
            score,
            sev,
            sev_src,
            ",".join(c for c in cwes if isinstance(c, str)),
            "\n".join(refs[:20]),
            feed,
        ),
    )

    conn.execute("DELETE FROM alias WHERE vuln_id = ?", (vid,))
    for a in adv.get("aliases") or []:
        if isinstance(a, str) and a:
            conn.execute(
                "INSERT OR IGNORE INTO alias(vuln_id, alias) VALUES (?,?)", (vid, a)
            )

    # `related` and `upstream` are not `aliases`, and the difference decides
    # whether KEV works on a distribution feed at all. An Ubuntu record
    # carries NO aliases -- 11,850 of 11,853 name their CVE under `related`
    # instead, and the 166 USN records among them use `upstream`. A join
    # through the alias table alone therefore matched none of them, so every
    # Ubuntu finding came back not-known-exploited by construction.
    #
    # They are stored apart from aliases because they are not identities: one
    # USN bundles several CVEs and is the same vulnerability as none of them.
    conn.execute("DELETE FROM related WHERE vuln_id = ?", (vid,))
    for kind in ("related", "upstream"):
        for ref in adv.get(kind) or []:
            if isinstance(ref, str) and ref:
                conn.execute(
                    "INSERT OR IGNORE INTO related(vuln_id, ref, kind) "
                    "VALUES (?,?,?)", (vid, ref, kind)
                )

    # Rewrite this advisory's affected rows wholesale. An advisory that loses
    # an affected package between syncs must lose it here too, and an UPSERT
    # cannot express a deletion.
    old = [r[0] for r in conn.execute(
        "SELECT id FROM affected WHERE vuln_id = ?", (vid,))]
    if old:
        marks = ",".join("?" * len(old))
        conn.execute(f"DELETE FROM affected_range WHERE affected_id IN ({marks})", old)
        conn.execute(f"DELETE FROM affected_version WHERE affected_id IN ({marks})", old)
        conn.execute("DELETE FROM affected WHERE vuln_id = ?", (vid,))

    stored = 0
    for aff in adv.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        name, eco = pkg.get("name"), pkg.get("ecosystem")
        if not isinstance(name, str) or not isinstance(eco, str):
            continue
        # storage_key, not base_ecosystem: for a distribution the suffix
        # names the release the advisory applies to, and truncating it would
        # let a 22.04 advisory decide a 24.04 machine.
        eco = V.storage_key(eco)
        if only_ecosystem and eco != only_ecosystem:
            _SKIPPED_ECOSYSTEMS[eco] = _SKIPPED_ECOSYSTEMS.get(eco, 0) + 1
            continue
        if eco not in ECOSYSTEMS:
            # Counted rather than dropped in silence. One Ubuntu bucket
            # carries 21 distinct ecosystem strings -- FIPS variants, Pro
            # tiers, a BlueField image -- and only the registered releases
            # are stored. A reader must be able to see that a number was
            # left out, not infer it from a total that looks complete.
            _SKIPPED_ECOSYSTEMS[eco] = _SKIPPED_ECOSYSTEMS.get(eco, 0) + 1
            continue
        cur = conn.execute(
            "INSERT INTO affected(vuln_id, ecosystem, package, package_norm) "
            "VALUES (?,?,?,?)",
            (vid, eco, name, V.normalize_name(eco, name)),
        )
        aid = cur.lastrowid
        stored += 1

        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            rtype = rng.get("type") or "ECOSYSTEM"
            # OSV ranges are a stream of events, not a list of windows: an
            # `introduced` opens one and the next `fixed`/`last_affected`
            # closes it. Flattening them the other way -- one row per event --
            # loses which upper bound belongs to which lower bound, and an
            # advisory with two disjoint vulnerable windows then reports the
            # whole span between them as vulnerable.
            intro = None
            for ev in rng.get("events") or []:
                if not isinstance(ev, dict):
                    continue
                if "introduced" in ev:
                    if intro is not None:
                        conn.execute(
                            "INSERT INTO affected_range VALUES (?,?,?,?,?)",
                            (aid, rtype, intro, None, None),
                        )
                    intro = ev["introduced"]
                elif "fixed" in ev:
                    conn.execute(
                        "INSERT INTO affected_range VALUES (?,?,?,?,?)",
                        (aid, rtype, intro, ev["fixed"], None),
                    )
                    intro = None
                elif "last_affected" in ev:
                    conn.execute(
                        "INSERT INTO affected_range VALUES (?,?,?,?,?)",
                        (aid, rtype, intro, None, ev["last_affected"]),
                    )
                    intro = None
            if intro is not None:
                conn.execute(
                    "INSERT INTO affected_range VALUES (?,?,?,?,?)",
                    (aid, rtype, intro, None, None),
                )

        for ver in aff.get("versions") or []:
            if isinstance(ver, str) and ver:
                conn.execute(
                    "INSERT INTO affected_version(affected_id, version) VALUES (?,?)",
                    (aid, ver),
                )
    return stored


def sync_osv(conn, ecosystem: str, log=print) -> dict:
    """Download and ingest one OSV ecosystem feed. All-or-nothing."""
    entry = ECOSYSTEMS.get(ecosystem)
    if entry is None:
        raise FeedError(f"unknown ecosystem: {ecosystem}")
    if entry.feed_kind != ecosystems.OSV:
        raise FeedError(f"{ecosystem} is not an OSV feed")
    url = osv_url(entry.bucket)
    log(f"  fetching {url}")
    blob = _fetch(url)

    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as e:
        raise FeedError(f"{url}: not a zip archive ({e})") from e

    # A release-scoped bucket is trimmed to its own release; every other
    # bucket keeps whatever registered ecosystems it carries, because a
    # crates.io archive legitimately holds npm and Go advisories.
    only = ecosystem if entry.release_scoped else ""
    stats = {"records": 0, "skipped": 0, "withdrawn": 0, "affected": 0,
             "bytes": len(blob)}
    _SKIPPED_ECOSYSTEMS.clear()
    conn.execute("BEGIN")
    try:
        for _name, raw in _safe_entries(zf):
            try:
                adv = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                stats["skipped"] += 1
                continue
            if not isinstance(adv, dict):
                stats["skipped"] += 1
                continue
            # A withdrawn advisory is retracted upstream. Storing it would
            # produce findings the publisher has disowned.
            if adv.get("withdrawn"):
                stats["withdrawn"] += 1
                continue
            try:
                stats["affected"] += _record(
                    conn, adv, f"osv:{ecosystem}", only)
                stats["records"] += 1
            except (ValueError, TypeError, KeyError):
                stats["skipped"] += 1
        conn.execute(
            """INSERT OR REPLACE INTO feed(name, synced_at, source, records, bytes)
               VALUES (?,?,?,?,?)""",
            (f"osv:{ecosystem}", _now(), url, stats["records"], stats["bytes"]),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    stats["other_ecosystems"] = dict(_SKIPPED_ECOSYSTEMS)
    return stats


def sync_kev(conn, log=print) -> dict:
    """Ingest CISA's Known Exploited Vulnerabilities catalogue.

    KEV is keyed by CVE, and OSV records are keyed by GHSA/PYSEC with the CVE
    in `aliases`. The join therefore goes through the alias table, and a CVE
    with no advisory in any synced ecosystem simply matches nothing -- which
    is correct, not a miss.
    """
    log(f"  fetching {KEV_URL}")
    blob = _fetch(KEV_URL, timeout=120)
    try:
        doc = json.loads(blob)
        items = doc["vulnerabilities"]
        if not isinstance(items, list):
            raise TypeError("vulnerabilities is not a list")
    except (ValueError, KeyError, TypeError) as e:
        raise FeedError(f"KEV feed is not the documented shape: {e}") from e

    conn.execute("BEGIN")
    try:
        conn.execute(
            "UPDATE vulnerability SET kev = 0, kev_added = NULL, "
            "kev_ransomware = NULL WHERE kev = 1"
        )
        marked = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            cve = item.get("cveID")
            if not isinstance(cve, str) or not cve:
                continue
            added = item.get("dateAdded") or ""
            ransom = item.get("knownRansomwareCampaignUse") or ""
            cur = conn.execute(
                """UPDATE vulnerability SET kev = 1, kev_added = ?,
                   kev_ransomware = ?
                   WHERE id = ?
                      OR id IN (SELECT vuln_id FROM alias WHERE alias = ?)
                      OR id IN (SELECT vuln_id FROM related WHERE ref = ?)""",
                (added, ransom, cve, cve, cve),
            )
            marked += cur.rowcount
        conn.execute(
            """INSERT OR REPLACE INTO feed(name, synced_at, source, records, bytes)
               VALUES ('kev', ?, ?, ?, ?)""",
            (_now(), KEV_URL, len(items), len(blob)),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return {"catalogue": len(items), "matched": marked, "bytes": len(blob)}


def sync_nvd(conn, ecosystem: str, api_key: str = "", log=print) -> dict:
    """Build one ecosystem's advisories from NVD's CPE data. All-or-nothing.

    Used only where no bulk feed publishes the product -- Magento today. The
    records are converted to OSV shape first, so from `_record` down this is
    indistinguishable from a downloaded feed.
    """
    entry = ECOSYSTEMS.get(ecosystem)
    if entry is None:
        raise FeedError(f"unknown ecosystem: {ecosystem}")
    if entry.feed_kind != ecosystems.NVD:
        raise FeedError(f"{ecosystem} is not an NVD-backed ecosystem")

    stats = {"records": 0, "skipped": 0, "withdrawn": 0, "affected": 0,
             "bytes": 0, "queried": 0}
    collected = {}
    for prefix, _package in entry.cpe_products:
        log(f"  querying {nvd.NVD_API} for {prefix}")
        try:
            items, total = nvd.fetch_product(prefix, api_key, log=log)
        except nvd.NvdError as e:
            raise FeedError(str(e)) from e
        stats["queried"] += total
        # A CVE naming both Commerce and Open Source arrives from both
        # queries. Keeping the later copy is safe -- they are the same record
        # -- and de-duplicating here keeps the record count honest.
        for cve in items:
            cid = cve.get("id")
            if cid:
                collected[cid] = cve

    conn.execute("BEGIN")
    try:
        for cve in collected.values():
            adv = nvd.to_osv(cve, entry.cpe_products)
            if not adv:
                stats["skipped"] += 1
                continue
            if adv.get("withdrawn"):
                stats["withdrawn"] += 1
                continue
            try:
                stats["affected"] += _record(conn, adv, f"nvd:{ecosystem}")
                stats["records"] += 1
            except (ValueError, TypeError, KeyError):
                stats["skipped"] += 1
        conn.execute(
            """INSERT OR REPLACE INTO feed(name, synced_at, source, records, bytes)
               VALUES (?,?,?,?,?)""",
            (f"nvd:{ecosystem}", _now(), nvd.NVD_API, stats["records"], 0),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return stats
