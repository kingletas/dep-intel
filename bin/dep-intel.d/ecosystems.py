"""The registry of ecosystems dep-intel knows, and where each one's feed comes from.

This is the single place that answers four questions about an ecosystem, and
they are deliberately four rather than one, because for several ecosystems the
answers differ:

  1. What key identifies its advisories in the store?
  2. Which version comparator orders its versions?
  3. Where does its advisory feed come from?
  4. What does a lockfile in it look like?

Collapsing those into one identifier worked while the tool knew npm, PyPI and
Packagist, where all four answers were the same word. It stops working the
moment a real distribution or a registry proxy is added:

  Ubuntu       The OSV ecosystem string is `Ubuntu:24.04:LTS`, and the
               suffix is NOT decoration -- it names the release the advisory
               applies to. Truncating it at the colon, which is right for
               `Packagist:https://packages.drupal.org/8`, would let a 22.04
               advisory match a 24.04 machine. So Ubuntu is release-scoped:
               the whole string is the key.
  Terraform    A provider is locked as `registry.terraform.io/hashicorp/aws`
               and its advisories are published in the Go ecosystem under
               `github.com/hashicorp/terraform-provider-aws`. The manifest
               ecosystem and the advisory ecosystem are different words for
               the same thing, and something has to translate.
  Magento      Commerce ships from repo.magento.com rather than Packagist, so
               OSV has no advisory for `magento/product-enterprise-edition`
               at all. Its feed is built from NVD's CPE data instead.

A `scheme` here is a NAME, not a function. versions.py maps the name to the
comparator. Keeping this module import-free is what stops the registry and
the comparators from depending on each other in a circle.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Feed kinds. `osv` is a bucket under the OSV bulk storage; `nvd` is a CPE
# query against the NVD API, used only where no bulk feed publishes the
# product at all.
OSV = "osv"
NVD = "nvd"


@dataclass(frozen=True)
class Ecosystem:
    key: str            # what goes in affected.ecosystem
    scheme: str         # which comparator in versions.py orders it
    feed_kind: str      # OSV | NVD | "" for an ecosystem with no feed
    bucket: str = ""    # OSV bucket name, when feed_kind is OSV
    release_scoped: bool = False
    # CPE products to pull, when feed_kind is NVD. Each entry is
    # (cpe_product_prefix, package_name_it_maps_to).
    cpe_products: tuple = field(default_factory=tuple)
    note: str = ""


# Ubuntu buckets are per release, and a host syncs the release it runs.
# `Ubuntu` on the command line expands to the host's own bucket rather than
# to all of them: the whole-Ubuntu feed is 670 MB against 136 MB for one
# release, and advisories for a release nothing here runs cannot produce a
# finding -- only a longer sync.
#
# The list is the releases a machine might BE, which is not the same as the
# ecosystem strings a bucket carries. One `Ubuntu:24.04:LTS` archive also
# holds rows for fifteen others -- FIPS variants, Pro tiers, a BlueField
# image -- and none of them can ever match a 24.04 host. Storing them cost
# 199,880 rows and roughly half a gigabyte to answer no question, so a
# release-scoped feed now stores only the release it was asked for.
UBUNTU_RELEASES = (
    "Ubuntu:24.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:20.04:LTS",
    "Ubuntu:18.04:LTS", "Ubuntu:16.04:LTS", "Ubuntu:14.04:LTS",
    "Ubuntu:25.10", "Ubuntu:25.04", "Ubuntu:24.10", "Ubuntu:23.10",
    "Ubuntu:Pro:24.04:LTS", "Ubuntu:Pro:22.04:LTS", "Ubuntu:Pro:20.04:LTS",
    "Ubuntu:Pro:18.04:LTS", "Ubuntu:Pro:16.04:LTS", "Ubuntu:Pro:14.04:LTS",
)

# Every ecosystem whose name carries a RELEASE after the colon, whether or
# not that particular release is registered. This is keyed on the
# distribution rather than on the registry because the two are not the same
# question: one Ubuntu bucket carries 21 distinct ecosystem strings -- FIPS
# variants, Pro tiers, a BlueField image -- and a name that is merely
# unregistered must still never be truncated to bare `Ubuntu`. Truncating it
# would let one release's advisories be stored under a key another release
# could match.
RELEASE_SCOPED_BASES = frozenset({
    "Ubuntu", "Debian", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux",
    "SUSE", "openSUSE", "Mageia", "Photon OS", "Azure Linux", "Alpaquita",
    "Chainguard", "Wolfi", "Echo", "MinimOS", "CleanStart", "TuxCare",
    "openEuler", "BellSoft Hardened Containers",
})

# The comparator for a release-scoped distribution, by distribution. Only the
# Debian family is here because dpkg is the only distribution comparator that
# exists in versions.py -- an Alpine or Red Hat release therefore resolves to
# no scheme at all, which makes every match against it `unresolved`. That is
# the correct answer: apk and rpm order versions differently from dpkg, and
# borrowing the nearest comparator is exactly how a scanner returns a
# confident wrong answer.
DISTRO_SCHEMES = {
    "Ubuntu": "dpkg",
    "Debian": "dpkg",
}

REGISTRY = {
    "npm": Ecosystem("npm", "semver", OSV, "npm"),
    "PyPI": Ecosystem("PyPI", "pep440", OSV, "PyPI"),
    "Packagist": Ecosystem("Packagist", "composer", OSV, "Packagist"),
    "crates.io": Ecosystem("crates.io", "semver", OSV, "crates.io"),
    "Go": Ecosystem(
        "Go", "semver", OSV, "Go",
        note="also carries Terraform provider advisories, which are Go modules",
    ),
    "GitHub Actions": Ecosystem("GitHub Actions", "semver", OSV, "GitHub Actions"),
    "RubyGems": Ecosystem(
        "RubyGems", "rubygems", OSV, "RubyGems",
        note="four numeric segments are ordinary, so semver cannot order it",
    ),
    "Magento": Ecosystem(
        "Magento", "composer", NVD,
        cpe_products=(
            ("cpe:2.3:a:adobe:commerce", "magento/product-enterprise-edition"),
            ("cpe:2.3:a:adobe:magento_open_source",
             "magento/product-community-edition"),
            # NVD files Open Source advisories since 2023 under this edition, not the product above.
            ("cpe:2.3:a:adobe:magento:*:*:*:*:open_source",
             "magento/product-community-edition"),
        ),
        note="Commerce is not on Packagist, so OSV has no advisory for it",
    ),
}

for _rel in UBUNTU_RELEASES:
    REGISTRY[_rel] = Ecosystem(_rel, "dpkg", OSV, _rel, release_scoped=True)


# The manifest ecosystem a lockfile parser emits, mapped to the advisory
# ecosystem its findings are matched in. Only the rows where the two differ
# need an entry; everything else matches under its own name.
MANIFEST_TO_ADVISORY = {
    "Terraform": "Go",
}


def resolve(name: str):
    """One ecosystem by name, or None. Matching is case-insensitive."""
    if name in REGISTRY:
        return REGISTRY[name]
    lowered = name.strip().lower()
    for key, eco in REGISTRY.items():
        if key.lower() == lowered:
            return eco
    return None


def advisory_ecosystem(manifest_ecosystem: str) -> str:
    """Where a manifest ecosystem's advisories are actually published."""
    return MANIFEST_TO_ADVISORY.get(manifest_ecosystem, manifest_ecosystem)


def manifest_ecosystems(advisory: str) -> list:
    """Every manifest ecosystem whose advisories are published under this one, itself first."""
    return [advisory, *sorted(k for k, v in MANIFEST_TO_ADVISORY.items() if v == advisory)]


def names() -> list:
    return sorted(REGISTRY)


def default_sync_set(host_ubuntu: str = "") -> list:
    """What a bare `dep-intel sync` fetches.

    Every ecosystem with a bulk or queryable feed, plus exactly one Ubuntu
    bucket -- the host's own when it could be detected, and none at all when
    it could not. Guessing a release would be worse than skipping one: a
    24.04 machine matched against 22.04 advisories is wrong in both
    directions at once.
    """
    out = [n for n, e in REGISTRY.items() if not e.release_scoped]
    if host_ubuntu and host_ubuntu in REGISTRY:
        out.append(host_ubuntu)
    return sorted(out)
