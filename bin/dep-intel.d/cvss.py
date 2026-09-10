"""CVSS vector -> base score, for the vectors OSV actually carries.

OSV gives a `severity` list of {type, score} where score is a vector string,
not a number. Sorting findings by "severity" therefore means computing the
base score locally. CVSS v3.0/v3.1 is a closed formula and is computed here.

**CVSS v4.0 is deliberately not computed.** Its base score comes from a
lookup table of 270 macro-vector entries, not a formula, and a wrong number
in a security report is worse than an absent one. A v4 vector yields None and
the caller falls back to the qualitative rating the advisory ships in
`database_specific.severity` -- which is recorded as such, so a report never
presents a guess as a measurement.
"""

from __future__ import annotations

import math

# CVSS v3.1 specification, section 7.1.
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope: Unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},    # Scope: Changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    """CVSS v3.1's Roundup, which is not round().

    The spec defines it on integer arithmetic precisely because floating
    point makes the naive version wrong at the boundaries -- ceil(8.6*10)/10
    can yield 8.7 for a value that is exactly 8.6 in decimal.
    """
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    out = {}
    for part in (vector or "").strip().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().upper()] = v.strip().upper()
    return out


def base_score(vector: str):
    """Base score for a CVSS v3.x vector, or None if not computable."""
    m = parse_vector(vector)
    ver = m.get("CVSS", "")
    if not ver.startswith("3."):
        return None
    try:
        scope_changed = m["S"] == "C"
        pr = _W["PR_C" if scope_changed else "PR_U"][m["PR"]]
        exploitability = (
            8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        )
        iss = 1 - (
            (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        )
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        if impact <= 0:
            return 0.0
        raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
        return _roundup(raw)
    except KeyError:
        return None


# The v3.1 qualitative bands, section 5. Used for both a computed score and
# for a rating imported from an advisory that shipped one.
def rating(score) -> str:
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# GitHub / OSV ship LOW / MODERATE / HIGH / CRITICAL in database_specific.
_QUALITATIVE = {
    "LOW": "low",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def from_advisory(severity_list, database_specific):
    """Best available (score, rating, source) for one advisory.

    `source` is the honest part: `cvss` means the number was computed from a
    vector, `qualitative` means the advisory supplied a band and no score was
    computable, `none` means neither. A report must not present the second as
    if it were the first.
    """
    best = None
    for entry in severity_list or []:
        s = base_score(entry.get("score", ""))
        if s is not None and (best is None or s > best):
            best = s
    if best is not None:
        return best, rating(best), "cvss"

    band = (database_specific or {}).get("severity")
    if band and band.upper() in _QUALITATIVE:
        return None, _QUALITATIVE[band.upper()], "qualitative"
    return None, "unknown", "none"
