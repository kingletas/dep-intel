"""Version comparators for the ecosystems dep-intel supports.

Why these are hand-written rather than delegated to `packaging` or a semver
library: a security tool that stops working because a pyenv global was
rebuilt is worse than one that carries a hundred lines of comparator.

The cardinal rule here is that **an unparseable version is never "not
affected"**. Every entry point returns None rather than a bool when it cannot
decide, and the caller is required to surface that as `unresolved`. A silent
false negative in a vulnerability scanner is the one failure mode that makes
the whole tool worse than nothing, because it converts "I did not check" into
"you are clean".

Three schemes:

  semver     npm. https://semver.org -- numeric triple, optional prerelease
             compared identifier by identifier, build metadata ignored.
  composer   Packagist. Semver-ish, but with a stability ladder
             (dev < alpha < beta < RC < stable < patch) and a leading `v`
             that is decorative. Composer itself normalises to four numeric
             segments, and so do we.
  pep440     PyPI. epoch!release[pre][post][dev][+local], with the ordering
             dev < pre < release < post and `local` ignored for ranges.
  rubygems   RubyGems. Any number of segments, letters included, with a
             letter run sorting BELOW the number it sits beside -- so
             1.0.0.beta is below 1.0.0. Four numeric segments are ordinary.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# semver -- npm
# --------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^v?(?P<major>\d+)"
    r"(?:\.(?P<minor>\d+))?"
    r"(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?$"
)


def _pre_key(pre: str | None) -> tuple:
    """Order a prerelease string against the release it precedes.

    An absent prerelease sorts ABOVE any prerelease -- 1.0.0 > 1.0.0-rc.1 --
    which is why the leading element is 1 for a release and 0 otherwise.
    Within a prerelease, numeric identifiers sort below alphanumeric ones,
    and a shorter identifier list sorts below a longer one with the same
    prefix (1.0.0-alpha < 1.0.0-alpha.1).
    """
    if pre is None or pre == "":
        return (1,)
    parts = []
    for ident in pre.split("."):
        if ident.isdigit():
            parts.append((0, int(ident), ""))
        else:
            parts.append((1, 0, ident))
    return (0, tuple(parts))


def parse_semver(v: str):
    m = _SEMVER_RE.match(v.strip())
    if not m:
        return None
    return (
        int(m["major"]),
        int(m["minor"] or 0),
        int(m["patch"] or 0),
        _pre_key(m["pre"]),
    )


# --------------------------------------------------------------------------
# composer -- Packagist
# --------------------------------------------------------------------------

# The stability ladder Composer applies. `pl`/`p` (patch level) sorts ABOVE a
# plain stable release, which is the one rung people get wrong: 1.0.0-p1 is
# newer than 1.0.0, not older. Magento ships patch-level releases, so this
# rung is load-bearing rather than academic.
_STABILITY = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "stable": 4,
    "": 4,
    "pl": 5,
    "p": 5,
}

_COMPOSER_RE = re.compile(
    r"^v?(?P<rel>\d+(?:\.\d+)*)"
    r"(?:[-_.+]?(?P<stab>dev|alpha|a|beta|b|rc|stable|patch|pl|p)"
    r"[-_.]?(?P<num>\d+)?)?"
    r"(?:\+[0-9A-Za-z.-]+)?$",
    re.IGNORECASE,
)


def parse_composer(v: str):
    v = v.strip()
    # A branch alias such as `dev-main` or `1.x-dev` is not a point on the
    # version line at all. Refusing it is correct: it means "unresolved", and
    # the caller reports the package rather than clearing it.
    if v.lower().startswith("dev-"):
        return None
    m = _COMPOSER_RE.match(v)
    if not m:
        return None
    rel = [int(x) for x in m["rel"].split(".")]
    # Composer normalises to four segments so 1.2 and 1.2.0.0 compare equal.
    rel = [*rel, 0, 0, 0, 0][:4]
    stab = (m["stab"] or "").lower()
    if stab == "patch":
        stab = "pl"
    rank = _STABILITY.get(stab, 4)
    num = int(m["num"] or 0)
    return (tuple(rel), rank, num)


# --------------------------------------------------------------------------
# pep440 -- PyPI
# --------------------------------------------------------------------------

_PEP440_RE = re.compile(
    r"^\s*v?"
    r"(?:(?P<epoch>\d+)!)?"
    r"(?P<rel>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:(?:-(?P<post_n1>\d+))"
    r"|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$",
    re.IGNORECASE,
)

_PRE_NORM = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


# PyPI publishes versions that PEP 440 does not actually permit, and the
# advisory feeds repeat them verbatim. PyTorch is the one that shows up here:
# a CUDA build is `2.6.0+cu124` under PEP 440, and PYSEC advisories write it
# `2.6.0-cu124`. Nine torch advisories sat in the unresolved bucket because of
# that single character -- unresolved is honest, but it was hiding nine real
# findings rather than surfacing a genuine ambiguity.
_LOCAL_HYPHEN_RE = re.compile(
    r"^(?P<head>\d+(?:\.\d+)*)-(?P<local>[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*)$"
)


def parse_pep440(v: str):
    m = _PEP440_RE.match(v)
    if not m:
        # Retry once, reading a trailing `-<alnum>` as the local segment it
        # was meant to be. Only reached when strict parsing has already
        # failed, so it can never change the meaning of a valid version.
        alt = _LOCAL_HYPHEN_RE.match((v or "").strip())
        if alt:
            m = _PEP440_RE.match(f"{alt['head']}+{alt['local']}")
        if not m:
            return None
    epoch = int(m["epoch"] or 0)
    rel = tuple(int(x) for x in m["rel"].split("."))
    # Trailing zeros are not significant: 1.0 == 1.0.0.
    while len(rel) > 1 and rel[-1] == 0:
        rel = rel[:-1]

    # The tiering below is PEP 440's ordering as implemented by `packaging`'s
    # own _cmpkey, reproduced because we carry no third-party dependency.
    # The rung that is easy to get wrong, and that a naive key gets backwards:
    # a pure dev release sorts BELOW every prerelease of the same release, so
    # 1.0.dev1 < 1.0a1, while an absent prerelease otherwise sorts ABOVE them
    # so that 1.0 > 1.0rc1. One flag cannot express both; two tiers can.
    pre_l, post_l = m["pre_l"], (m["post_l"] or m["post_n1"])
    dev_l = m["dev_l"]

    if pre_l:
        label = _PRE_NORM.get(pre_l.lower(), pre_l.lower())
        pre = (0, label, int(m["pre_n"] or 0))
    elif post_l is None and dev_l:
        pre = (-1, "", 0)          # dev-only: below every prerelease
    else:
        pre = (1, "", 0)           # no prerelease: above every prerelease

    if m["post_n1"] is not None:
        post = (0, int(m["post_n1"]))
    elif m["post_l"]:
        post = (0, int(m["post_n2"] or 0))
    else:
        post = (-1, 0)             # absent post sorts below any .postN

    # Absent dev sorts ABOVE any .devN, which is why the tier is 1 not -1.
    dev = (0, int(m["dev_n"] or 0)) if dev_l else (1, 0)

    return (epoch, rel, pre, post, dev)


# --------------------------------------------------------------------------
# dpkg -- Ubuntu and Debian
# --------------------------------------------------------------------------

# `[epoch:]upstream[-revision]`, and the comparison is Debian policy 5.6.12
# rather than anything semver-shaped. Two rungs make it genuinely different
# from every other scheme here, and both are load-bearing on a real machine:
#
#   `~` sorts BEFORE the end of a string, so 1.0~rc1 < 1.0. Nothing else here
#   has a character that sorts below "nothing".
#   Letters sort before every other non-digit, so 1.0a < 1.0.1 but 1.0a < 1.0+.
#
# The reason this is a comparator rather than a fallback to semver: semver's
# regex MATCHES a dpkg version and answers with the wrong meaning. It reads
# the `-1028.33` of `6.8.0-1028.33` as a PRERELEASE, which sorts below plain
# `6.8.0` -- so an advisory bounded at `introduced: 6.8.0` would report a
# 6.8.0-1028 kernel as not affected. A silent false negative, which is the
# one outcome this tool exists to prevent.
_DPKG_RE = re.compile(
    r"^(?:(?P<epoch>\d+):)?"
    r"(?P<upstream>[A-Za-z0-9][A-Za-z0-9.+~:-]*?)"
    r"(?:-(?P<revision>[A-Za-z0-9+.~]+))?$"
)


def _dpkg_order(ch: str) -> int:
    """Debian's collation for one character.

    A tilde is below everything including the end of the string, which is
    encoded as 0 by the caller. Letters keep their ASCII value so they sort
    below every other punctuation mark, which is shifted up by 256.
    """
    if ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    if ch == "~":
        return -1
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Compare one upstream or revision part. Debian policy 5.6.12 verbatim."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        # Non-digit run, compared character by character under the collation
        # above. It ends only when BOTH sides are sitting on a digit.
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < la else 0
            bc = _dpkg_order(b[j]) if j < lb else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1

        # Digit run, compared numerically. Leading zeros are not significant,
        # so they are stripped before the lengths are used to decide.
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        first_diff = 0
        while i < la and j < lb and a[i].isdigit() and b[j].isdigit():
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        # A longer digit run is the larger number, whatever its digits.
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


class DpkgVersion:
    """A dpkg version that orders itself, because a tuple key cannot.

    The collation puts `~` below the end of a string, and no tuple of
    comparable parts expresses that -- Python reads a shorter tuple as a
    prefix and therefore smaller, which is backwards for `1.0~rc1` against
    `1.0`. So the comparison is the algorithm rather than a key derived from
    it.
    """

    __slots__ = ("epoch", "raw", "revision", "upstream")

    def __init__(self, epoch: int, upstream: str, revision: str, raw: str):
        self.epoch = epoch
        self.upstream = upstream
        self.revision = revision
        self.raw = raw

    def _cmp(self, other) -> int:
        if not isinstance(other, DpkgVersion):
            return NotImplemented
        if self.epoch != other.epoch:
            return -1 if self.epoch < other.epoch else 1
        c = _verrevcmp(self.upstream, other.upstream)
        if c:
            return c
        return _verrevcmp(self.revision, other.revision)

    def __eq__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c == 0

    def __lt__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c < 0

    def __le__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c <= 0

    def __gt__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c > 0

    def __ge__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c >= 0

    def __hash__(self):
        return hash(self.raw)

    def __repr__(self):
        return f"DpkgVersion({self.raw!r})"


def parse_dpkg(v: str):
    s = (v or "").strip()
    if not s:
        return None
    m = _DPKG_RE.match(s)
    if not m:
        return None
    return DpkgVersion(
        int(m["epoch"] or 0), m["upstream"], m["revision"] or "", s
    )


# --------------------------------------------------------------------------
# rubygems -- RubyGems
# --------------------------------------------------------------------------

# Gem::Version accepts digits, dots and letters, with an optional hyphenated
# tail. Four and five numeric segments are ordinary here -- `parser` ships
# 3.3.12.0 -- which is why semver cannot stand in for this scheme: its
# expression stops after the third segment and rejects the version outright.
_GEM_VERSION_RE = re.compile(
    r"\A[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z.-]+)?\Z"
)
_GEM_SEGMENT = re.compile(r"[0-9]+|[A-Za-z]+")

# A segment that is absent is a zero, and that zero is NUMERIC -- which is the
# whole reason a letter sorts below it.
_GEM_ZERO = (1, 0, "")


def _gem_segments(v: str) -> list:
    """Split a gem version into Gem::Version's CANONICAL segments.

    Each segment becomes a sortable triple whose first element carries the
    kind: 0 for a letter run, 1 for a number. That single bit is what puts
    every prerelease below the release it precedes, because Gem::Version
    orders a String below a Numeric and a missing segment counts as 0.

    Canonical is not the same as raw, and the difference decides real pairs.
    Gem::Version cuts the segments at the first letter run and drops trailing
    zeros from the two halves SEPARATELY, so 1.0.pre is [1, "pre"] and
    1.0.0.beta is [1, "beta"] -- which makes 1.0.0.beta the smaller of the
    two. Comparing the raw segments instead puts "pre" against a numeric 0
    and gets the pair backwards.
    """
    raw = []
    for token in _GEM_SEGMENT.findall(v):
        if token.isdigit():
            raw.append((1, int(token), ""))
        else:
            raw.append((0, 0, token.lower()))
    first_letter = next((i for i, seg in enumerate(raw) if seg[0] == 0), len(raw))
    return _drop_trailing_zeros(raw[:first_letter]) + _drop_trailing_zeros(raw[first_letter:])


def _drop_trailing_zeros(segments: list) -> list:
    end = len(segments)
    while end and segments[end - 1] == _GEM_ZERO:
        end -= 1
    return segments[:end]


class GemVersion:
    """A RubyGems version that orders itself, for DpkgVersion's reason.

    Padding is what a tuple key cannot express. `1.0.a` and `1.0` have to
    compare as prerelease-below-release, and Python reads the shorter tuple as
    a prefix and therefore smaller -- exactly backwards. So the shorter side is
    padded with numeric zeros and the comparison is the algorithm.
    """

    __slots__ = ("raw", "segments")

    def __init__(self, segments: list, raw: str):
        self.segments = segments
        self.raw = raw

    def _cmp(self, other) -> int:
        if not isinstance(other, GemVersion):
            return NotImplemented
        mine, theirs = self.segments, other.segments
        for i in range(max(len(mine), len(theirs))):
            a = mine[i] if i < len(mine) else _GEM_ZERO
            b = theirs[i] if i < len(theirs) else _GEM_ZERO
            if a != b:
                return -1 if a < b else 1
        return 0

    def __eq__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c == 0

    def __lt__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c < 0

    def __le__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c <= 0

    def __gt__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c > 0

    def __ge__(self, other):
        c = self._cmp(other)
        return NotImplemented if c is NotImplemented else c >= 0

    def __hash__(self):
        return hash(tuple(self.segments))

    def __repr__(self):
        return f"GemVersion({self.raw!r})"


def parse_rubygems(v: str):
    s = (v or "").strip()
    if not s or not _GEM_VERSION_RE.match(s):
        return None
    # Gem::Version reads a hyphen as the start of a prerelease: 1.0-rc1 is
    # 1.0.pre.rc1, which sorts below 1.0. A platform suffix looks identical
    # and means the opposite, so parse_gemfile_lock strips that before this
    # ever sees it -- using the lockfile's own PLATFORMS list rather than a
    # guess at what a platform looks like.
    return GemVersion(_gem_segments(s.replace("-", ".pre.")), s)


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------

# Comparator by scheme name. ecosystems.py names the scheme; this maps the
# name to the function, which is what keeps the registry free of imports.
_BY_SCHEME = {
    "semver": parse_semver,
    "composer": parse_composer,
    "pep440": parse_pep440,
    "dpkg": parse_dpkg,
    "rubygems": parse_rubygems,
}


def base_ecosystem(ecosystem: str) -> str:
    """The part of an OSV ecosystem string before its first colon.

    `Packagist:https://packages.drupal.org/8` is a real value in the feed and
    only `Packagist` identifies the version scheme. This is NOT the storage
    key -- see storage_key below, which is the same thing for every ecosystem
    except the release-scoped ones.
    """
    return (ecosystem or "").split(":", 1)[0].strip()


def storage_key(ecosystem: str) -> str:
    """The key an advisory is stored and looked up under.

    For almost everything this is base_ecosystem: the suffix names a mirror
    or a registry proxy and does not change which package is meant. For a
    distribution it is the opposite -- `Ubuntu:24.04:LTS` and
    `Ubuntu:22.04:LTS` ship different versions of the same source package
    and fix them at different revisions, so collapsing them would let a
    22.04 advisory decide a 24.04 machine. The whole string is the key there.
    """
    eco = (ecosystem or "").strip()
    if not eco:
        return ""
    import ecosystems
    # The distribution decides, not whether this particular release happens
    # to be registered. An unregistered `Ubuntu:Pro:FIPS:16.04:LTS` truncated
    # to bare `Ubuntu` would be stored under a key that a different release
    # could then match.
    if base_ecosystem(eco) in ecosystems.RELEASE_SCOPED_BASES:
        return eco
    if eco in _registry():
        return eco
    return base_ecosystem(eco)


def _registry():
    # Imported lazily so versions.py stays usable on its own, which the test
    # suite relies on.
    import ecosystems
    return ecosystems.REGISTRY


def scheme_for(ecosystem: str) -> str:
    """Which comparator orders this ecosystem's versions, by name."""
    import ecosystems
    reg = _registry()
    eco = (ecosystem or "").strip()
    if eco in reg:
        return reg[eco].scheme
    base = base_ecosystem(eco)
    # A distribution release that is not registered still has its
    # distribution's comparator, so an unregistered Ubuntu variant orders
    # correctly rather than falling through to "no scheme".
    if base in ecosystems.DISTRO_SCHEMES:
        return ecosystems.DISTRO_SCHEMES[base]
    for key, entry in reg.items():
        if key.lower() == base.lower():
            return entry.scheme
    # An unregistered ecosystem has no scheme, and saying so is the point:
    # parse() then returns None and every match against it is unresolved
    # rather than quietly decided by whichever comparator was closest.
    return ""


def parse(ecosystem: str, version: str):
    """Parse `version` under `ecosystem`'s scheme, or None if undecidable."""
    fn = _BY_SCHEME.get(scheme_for(ecosystem))
    if fn is None or not version:
        return None
    try:
        return fn(version)
    except (ValueError, TypeError):
        return None


def compare(ecosystem: str, a: str, b: str):
    """-1, 0, 1 -- or None when either side will not parse."""
    pa, pb = parse(ecosystem, a), parse(ecosystem, b)
    if pa is None or pb is None:
        return None
    return (pa > pb) - (pa < pb)


def in_range(ecosystem: str, version: str, introduced, fixed, last_affected):
    """Is `version` inside [introduced, fixed) or [introduced, last_affected]?

    Returns None -- never False -- when any bound will not parse under this
    ecosystem's scheme. See the module docstring: undecided is not clean.
    """
    v = parse(ecosystem, version)
    if v is None:
        return None

    if introduced not in (None, "", "0"):
        lo = parse(ecosystem, introduced)
        if lo is None:
            return None
        if v < lo:
            return False

    if fixed not in (None, ""):
        hi = parse(ecosystem, fixed)
        if hi is None:
            return None
        return v < hi

    if last_affected not in (None, ""):
        hi = parse(ecosystem, last_affected)
        if hi is None:
            return None
        return v <= hi

    # `introduced` with no upper bound means everything from there on.
    return True


# --------------------------------------------------------------------------
# name normalisation
# --------------------------------------------------------------------------

def normalize_name(ecosystem: str, name: str) -> str:
    """Fold a package name to the form its ecosystem considers canonical.

    PyPI is the one that bites: PEP 503 says Flask-WTF, flask_wtf and
    flask.wtf are the same project, and an advisory naming one of the three
    must match a lockfile naming another. crates.io normalises the same way,
    treating `-` and `_` as interchangeable.

    Go, and therefore Terraform providers, is the exception that must NOT be
    folded: a Go module path is case-sensitive and its punctuation is part of
    the path, so `github.com/Azure/foo` and `github.com/azure/foo` are
    genuinely different modules. Lowercasing it would match the wrong one.
    """
    eco = storage_key(ecosystem)
    scheme = scheme_for(eco)
    n = (name or "").strip()
    if eco in ("PyPI", "crates.io"):
        return re.sub(r"[-_.]+", "-", n).lower()
    if eco == "Go":
        return n
    if scheme == "dpkg":
        # Distribution package names are already lowercase by policy, and a
        # source package name carries no case to fold.
        return n.lower()
    return n.lower()
