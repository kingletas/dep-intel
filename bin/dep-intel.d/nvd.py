"""Build a Magento advisory feed from NVD, because no bulk feed publishes one.

Adobe Commerce ships from repo.magento.com, not Packagist, so OSV has no
record for `magento/product-enterprise-edition` at all -- the Packagist feed's
366 Magento advisories are for `magento/community-edition`, `magento/core` and
the Magento 1 packages, none of which is what a Commerce store installs. A
store on 2.4.8-p2 therefore scanned completely clean on its single most
important package, and did so silently.

Adobe's own bulletin pages are the obvious source and are not usable: they do
not fetch, so anything built on them would be a scraper against a wall. NVD
carries the same advisories as structured CPE data -- version ranges, CVSS
vectors, and the CVE id itself as the record id, which is what lets the KEV
catalogue join straight to it.

> This is the one feed that is a query rather than a download, and that is a
> weaker privacy property than the rest of dep-intel has. It is narrowed as
> far as it can be: the query names a PRODUCT and nothing else. No installed
> version, no package list, no repository name and no path is ever sent, so
> what NVD can learn is that someone asked about Adobe Commerce -- not what
> they are running. The bulk feeds remain the preferred shape, and this one
> exists only where no bulk feed covers the product.

Everything here converts NVD's shape into OSV's, so the record then travels
through exactly the same ingestion, bounds, range-flattening and matching
code as every other advisory. Nothing downstream knows this feed is different.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD allows 5 requests per rolling 30 seconds without a key and 50 with one.
# The unauthenticated pace is the default because a key is a credential and
# this tool does not require one to work.
PAGE_SIZE = 2000
DELAY_ANON = 6.5
DELAY_KEYED = 0.7

USER_AGENT = "dep-intel (+local; NVD CPE consumer)"

# A cap on what one product query may return. NVD's own totalResults is
# trusted only this far: a feed that suddenly claims a million records for one
# product is not a feed, and pulling it would be the same unbounded-input
# mistake the zip bounds in feeds.py exist to prevent.
MAX_RECORDS_PER_PRODUCT = 20_000


class NvdError(RuntimeError):
    """NVD could not be reached, or did not answer in its documented shape."""


def _fetch(url: str, api_key: str = "", timeout: int = 90) -> dict:
    if not url.lower().startswith("https://"):
        raise NvdError(f"refusing a non-HTTPS feed URL: {url}")
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NvdError(f"{url}: {e}") from e
    except ValueError as e:
        raise NvdError(f"{url}: response is not JSON ({e})") from e


def _cpe_parts(criteria: str) -> list:
    """Split a CPE 2.3 string, honouring its backslash escaping.

    A CPE field may contain an escaped colon, so a plain split loses the
    field boundaries. Getting this wrong shifts every field right and turns a
    version into a vendor.
    """
    parts, cur, esc = [], [], False
    for ch in criteria:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _version_field(criteria: str) -> str:
    parts = _cpe_parts(criteria)
    return parts[5] if len(parts) > 5 else ""


def _exact_version(criteria: str):
    """The single version a non-wildcard CPE names, or None if it names none.

    Magento's patch releases live in the CPE `update` field: version `2.4.3`
    with update `p1` is the release Composer calls `2.4.3-p1`. Rejoining them
    is what makes the composer comparator -- which already ranks a patch level
    above the plain release -- able to decide the match.

    In the UPDATE field, `-` means there is no patch level, so `2.4.3:-` is
    plain `2.4.3`. In the VERSION field it means something entirely different
    -- see _ranges_and_versions.
    """
    parts = _cpe_parts(criteria)
    if len(parts) < 6:
        return None
    version, update = parts[5], parts[6] if len(parts) > 6 else "*"
    if version in ("*", "-", ""):
        return None
    if update in ("*", "-", ""):
        return version
    return f"{version}-{update}"


def _product_prefix(criteria: str, prefix: str) -> bool:
    """Does this CPE name the product we asked for?

    Compared field by field rather than as a string prefix: `adobe:magento`
    is a string prefix of `adobe:magento_open_source` and they are different
    products.
    """
    want = _cpe_parts(prefix)
    have = _cpe_parts(criteria)
    if len(have) < len(want):
        return False
    for i, (w, h) in enumerate(zip(want, have)):
        # Past the product, `*` on either side is ANY, so it covers the attribute asked for.
        if w != h and not (i > 4 and "*" in (w, h)):
            return False
    return True


def _ranges_and_versions(cve: dict, prefix: str):
    """(osv_ranges, exact_versions) for one product, out of NVD's CPE matches."""
    ranges, exact = [], []
    seen_range, seen_exact = set(), set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            # A negated node states what is NOT affected. Reading it as an
            # affected set would invert the finding.
            if node.get("negate"):
                continue
            for cpe in node.get("cpeMatch") or []:
                if not isinstance(cpe, dict) or not cpe.get("vulnerable"):
                    continue
                criteria = cpe.get("criteria") or ""
                if not _product_prefix(criteria, prefix):
                    continue

                one = _exact_version(criteria)
                if one is not None:
                    if one not in seen_exact:
                        seen_exact.add(one)
                        exact.append(one)
                    continue

                start_in = cpe.get("versionStartIncluding")
                start_ex = cpe.get("versionStartExcluding")
                end_in = cpe.get("versionEndIncluding")
                end_ex = cpe.get("versionEndExcluding")
                if not any((start_in, start_ex, end_in, end_ex)):
                    # CPE 2.3 gives `*` and `-` opposite meanings in the
                    # version field: `*` is ANY and `-` is NOT APPLICABLE, the
                    # versionless entry for a product. Reading `-` as a
                    # wildcard turns a versionless row into "every version
                    # ever", and CVE-2024-20758 -- an advisory whose own text
                    # says "2.4.6-p4 and earlier" -- then reported against
                    # 2.4.8-p2, which is newer than everything it names.
                    if _version_field(criteria) != "*":
                        continue
                    introduced, fixed, last = "0", None, None
                else:
                    # OSV has no exclusive lower bound, so an exclusive start
                    # is widened to an inclusive one. That over-reports by
                    # exactly the boundary version and never under-reports,
                    # which is the direction this tool is allowed to be wrong
                    # in -- a spurious finding is read by a person, a missing
                    # one is not read by anybody.
                    introduced = start_in or start_ex or "0"
                    fixed = end_ex
                    last = end_in
                key = (introduced, fixed, last)
                if key in seen_range:
                    continue
                seen_range.add(key)
                events = [{"introduced": introduced}]
                if fixed:
                    events.append({"fixed": fixed})
                elif last:
                    events.append({"last_affected": last})
                ranges.append({"type": "ECOSYSTEM", "events": events})
    return ranges, exact


def _severity(cve: dict):
    """(osv severity list, qualitative band) out of NVD's metrics block."""
    vectors, band = [], ""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            data = (entry or {}).get("cvssData") or {}
            vec = data.get("vectorString")
            if vec:
                vectors.append({"type": key, "score": vec})
            band = band or data.get("baseSeverity") or entry.get("baseSeverity") or ""
    return vectors, band


def to_osv(cve: dict, products) -> dict:
    """One NVD CVE record as an OSV advisory, or {} when it affects nothing.

    Emitting OSV rather than a private shape is the whole design: the record
    then goes through the same ingestion, the same archive-free range
    flattening and the same matcher as every downloaded feed, so this source
    gets no special path and no second implementation to keep in step.
    """
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id:
        return {}

    summary = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en" and d.get("value"):
            summary = d["value"]
            break

    vectors, band = _severity(cve)
    cwes = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)

    # Merged per package: two CPE products can name one package, and two blocks would report the CVE twice.
    blocks = {}
    for prefix, package in products:
        ranges, exact = _ranges_and_versions(cve, prefix)
        if not ranges and not exact:
            continue
        block = blocks.setdefault(
            package, {"package": {"name": package, "ecosystem": "Magento"}})
        for key, items in (("ranges", ranges), ("versions", exact)):
            merged = block.setdefault(key, [])
            merged.extend(x for x in items if x not in merged)
    affected = [{k: v for k, v in b.items() if v} for b in blocks.values()]
    if not affected:
        return {}

    return {
        "id": cve_id,
        "summary": summary[:400],
        "details": summary,
        "published": cve.get("published") or "",
        "modified": cve.get("lastModified") or "",
        # A CVE rejected by its CNA is withdrawn in OSV's sense, and the
        # ingester already drops those.
        "withdrawn": ("rejected" if (cve.get("vulnStatus") or "").lower()
                      == "rejected" else ""),
        "severity": vectors,
        "database_specific": {"severity": band, "cwe_ids": cwes},
        "references": [{"url": r["url"]} for r in (cve.get("references") or [])
                       if isinstance(r, dict) and r.get("url")],
        "affected": affected,
    }


def fetch_product(prefix: str, api_key: str = "", log=print):
    """Every CVE NVD holds for one CPE product, paged."""
    out, start, total = [], 0, None
    delay = DELAY_KEYED if api_key else DELAY_ANON
    while True:
        query = urllib.parse.urlencode({
            "virtualMatchString": prefix,
            "resultsPerPage": PAGE_SIZE,
            "startIndex": start,
        })
        doc = _fetch(f"{NVD_API}?{query}", api_key)
        try:
            items = doc["vulnerabilities"]
            total = int(doc["totalResults"])
            if not isinstance(items, list):
                raise TypeError("vulnerabilities is not a list")
        except (KeyError, TypeError, ValueError) as e:
            raise NvdError(f"NVD response is not the documented shape: {e}") from e

        if total > MAX_RECORDS_PER_PRODUCT:
            raise NvdError(
                f"{prefix}: NVD reports {total} records, over the "
                f"{MAX_RECORDS_PER_PRODUCT} cap for one product")

        out.extend(v.get("cve") or {} for v in items if isinstance(v, dict))
        start += len(items)
        if not items or start >= total:
            break
        log(f"    {start}/{total}")
        time.sleep(delay)
    return out, (total or 0)
