"""The host's own installed packages, for the distribution advisory feeds.

Everything else dep-intel reads is a lockfile inside a repository. The
operating system is not, and pretending otherwise would have been the easy
mistake: there is no manifest to walk, no commit that changes it, and
therefore no CI gate that could ever fire on it. It gets its own
command instead, and `sweep` leaves it alone.

Two things about a Debian-family inventory are counter-intuitive enough that
getting either wrong produces a scanner that reports clean and is not:

**An advisory names the SOURCE package; dpkg lists BINARY packages.** A USN
for `apache2` covers `apache2-bin`, `apache2-data` and `apache2-utils`, none
of which is called `apache2`. On this machine 3,439 binary packages come from
1,820 source packages, so matching binary names against advisory names would
miss most of the machine silently. The source name is what is matched, and the
binary name is carried alongside so a finding can still say which installed
package to update.

**The source version is not always the binary version.** `bsdutils` is
`1:2.39.3-9ubuntu6.6` as a binary and `2.39.3-9ubuntu6.6` as a source -- a
different epoch, which under dpkg ordering makes the binary version compare
as strictly greater than every source version an advisory could name. 39
packages here differ that way, and every one of them would have decided its
range against the wrong number.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class HostPackage:
    ecosystem: str      # the release-scoped OSV key, e.g. Ubuntu:24.04:LTS
    name: str           # SOURCE package name -- what an advisory names
    version: str        # SOURCE version -- what an advisory's range bounds
    scope: str          # always "system"
    manifest: str       # "dpkg"
    binary: str = ""    # the installed binary package, for the report


class HostError(RuntimeError):
    """The host's package inventory could not be read."""


def os_release(path: str = "/etc/os-release") -> dict:
    out = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "=" not in line or line.startswith("#"):
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return {}
    return out


def osv_ecosystem(release: dict | None = None):
    """The OSV bucket for this host, or None when it cannot be determined.

    None rather than a guess, and the caller must refuse to scan on it. A
    22.04 advisory set matched against a 24.04 machine is wrong in both
    directions at once -- it clears real findings and invents others -- and
    an unhelpful "I do not know which release this is" is the only honest
    answer when /etc/os-release does not say.
    """
    rel = release if release is not None else os_release()
    distro = (rel.get("ID") or "").lower()
    version = (rel.get("VERSION_ID") or "").strip()
    if not distro or not version:
        return None
    if distro == "ubuntu":
        # OSV marks the long-term releases and only those.
        lts = version.split(".")[0] in ("14", "16", "18", "20", "22", "24") \
            and version.endswith(".04")
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    if distro == "debian":
        return f"Debian:{version.split('.')[0]}"
    return None


def available() -> bool:
    return shutil.which("dpkg-query") is not None


def collect(ecosystem: str):
    """Every installed package as (source name, source version).

    Deduplicated on the source pair, because many binaries share one source
    and matching each of them would report the same advisory a dozen times
    for one update.
    """
    if not available():
        raise HostError("dpkg-query is not on PATH: this is not a "
                        "Debian-family system, and no other host package "
                        "manager is supported yet")
    fmt = "${binary:Package}\\t${source:Package}\\t${source:Version}\\t${Version}\\n"
    try:
        proc = subprocess.run(
            ["dpkg-query", "-f", fmt, "-W"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise HostError(f"dpkg-query failed: {e}") from e
    if proc.returncode != 0:
        raise HostError(f"dpkg-query exited {proc.returncode}: "
                        f"{proc.stderr.strip()[:200]}")

    packages, skipped, seen = [], [], {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        binary, source, source_version, binary_version = (p.strip() for p in parts)
        if not binary:
            continue
        # dpkg leaves the source fields empty when the binary is its own
        # source, which is the common case rather than an error.
        name = source or binary
        version = source_version or binary_version
        if not version:
            skipped.append((binary, "installed with no version recorded"))
            continue
        key = (name, version)
        if key in seen:
            continue
        seen[key] = binary
        packages.append(HostPackage(
            ecosystem=ecosystem, name=name, version=version,
            scope="system", manifest="dpkg", binary=binary,
        ))
    return packages, skipped
