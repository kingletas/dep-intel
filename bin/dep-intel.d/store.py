"""The local intelligence store -- SQLite, offline, and the whole point.

Design note that is easy to miss: dep-intel downloads the ENTIRE advisory
feed and matches locally. It never sends a package name, a version, a path or
a repository name anywhere. That is not an optimisation, it is the privacy
property -- a tool that queries an API per package tells that API exactly
what software you run and which versions of it, which is a target
list. Bulk-and-match-offline is the only shape that avoids it.

Two tables exist only for the matcher:

  affected_range   ranges normalised out of the OSV `ranges` array, one row
                   per (introduced, fixed, last_affected) window, so matching
                   is a query rather than a JSON walk in Python.
  affected_version the explicit `versions` array where the advisory ships
                   one. 84% of Packagist affected-blocks do, and exact
                   membership needs no comparator -- which removes the
                   comparator from the trust path for most findings.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 5

_DDL = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed (
    name        TEXT PRIMARY KEY,       -- 'osv:Packagist', 'kev'
    synced_at   TEXT,
    source      TEXT,
    records     INTEGER DEFAULT 0,
    bytes       INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vulnerability (
    id              TEXT PRIMARY KEY,   -- OSV id: GHSA-..., PYSEC-..., CVE-...
    summary         TEXT,
    details         TEXT,
    published       TEXT,
    modified        TEXT,
    withdrawn       TEXT,
    cvss_vector     TEXT,
    cvss_score      REAL,
    severity        TEXT,               -- critical|high|medium|low|none|unknown
    severity_source TEXT,               -- cvss|qualitative|none
    cwe             TEXT,               -- comma-separated CWE ids
    kev             INTEGER DEFAULT 0,
    kev_added       TEXT,
    kev_ransomware  TEXT,
    refs            TEXT,               -- newline-separated URLs
    feed            TEXT
);

CREATE TABLE IF NOT EXISTS alias (
    vuln_id     TEXT NOT NULL,
    alias       TEXT NOT NULL,
    PRIMARY KEY (vuln_id, alias)
);
CREATE INDEX IF NOT EXISTS alias_by_alias ON alias(alias);

-- References to other advisory identities that are NOT aliases -- OSV's
-- `related` and `upstream` fields. The distinction is what makes the CISA KEV
-- catalogue usable on a distribution feed at all: an Ubuntu record carries no
-- aliases whatsoever, and names the CVE it addresses here instead, so a join
-- through `alias` alone matched exactly zero of 11,853 Ubuntu advisories.
--
-- They are not folded into `alias` because they are not identities. One USN
-- bundles several CVEs, so it is the same vulnerability as none of them, and
-- `dep-intel cve` must not claim otherwise. `kind` keeps the two OSV fields
-- apart rather than flattening them into one word they do not share.
CREATE TABLE IF NOT EXISTS related (
    vuln_id     TEXT NOT NULL,
    ref         TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'related',   -- related | upstream
    PRIMARY KEY (vuln_id, ref, kind)
);
CREATE INDEX IF NOT EXISTS related_by_ref ON related(ref);

CREATE TABLE IF NOT EXISTS affected (
    id          INTEGER PRIMARY KEY,
    vuln_id     TEXT NOT NULL,
    -- The advisory's ecosystem key. For most this is the bare name, but a
    -- distribution keeps its release suffix -- `Ubuntu:24.04:LTS` -- because
    -- the release is part of which versions the advisory speaks about.
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    -- Ecosystem-normalised name, so lookup is an indexed equality rather than
    -- a function applied to every row. PyPI in particular treats Flask-WTF,
    -- flask_wtf and flask.wtf as one project (PEP 503); matching on the raw
    -- string silently misses the advisory.
    package_norm TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS affected_by_pkg ON affected(ecosystem, package_norm);
-- Ingest rewrites an advisory's affected rows wholesale, so every record
-- issues DELETE FROM affected WHERE vuln_id = ?. Without this index that is a
-- full table scan per record: 258k records against a table growing to 272k
-- rows, which is quadratic and took the first npm sync 43 minutes. The
-- lookup index above does not help -- it is keyed by package, not by
-- advisory.
CREATE INDEX IF NOT EXISTS affected_by_vuln ON affected(vuln_id);

CREATE TABLE IF NOT EXISTS affected_range (
    affected_id     INTEGER NOT NULL,
    -- OSV range type. This is load-bearing, not metadata: a GIT range's
    -- bounds are COMMIT SHAs, and comparing a SHA to a package version is
    -- not a comparison that can succeed. PYSEC advisories routinely publish
    -- a GIT range beside the ECOSYSTEM one, and treating both as version
    -- ranges turned every decidable aiohttp advisory into "unresolved" --
    -- 37 of them in one repository, 74 in another.
    range_type      TEXT NOT NULL DEFAULT 'ECOSYSTEM',
    introduced      TEXT,
    fixed           TEXT,
    last_affected   TEXT
);
CREATE INDEX IF NOT EXISTS range_by_affected ON affected_range(affected_id);

CREATE TABLE IF NOT EXISTS affected_version (
    affected_id INTEGER NOT NULL,
    version     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ver_by_affected ON affected_version(affected_id);

-- The inventory: what is installed where. Written by `scan`, read by
-- `affected` and `inventory`, and the reason a cross-repository CVE query is
-- possible at all.
CREATE TABLE IF NOT EXISTS package (
    repo        TEXT NOT NULL,
    manifest    TEXT NOT NULL,          -- repo-relative lockfile path
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    scope       TEXT NOT NULL,          -- runtime|dev
    seen_at     TEXT NOT NULL,
    -- `version` is part of the key, and it has to be. npm installs several
    -- versions of one package in nested node_modules, and a lockfile
    -- legitimately lists lodash twice at different versions. Keying without
    -- the version collapsed them to whichever row was written last, so the
    -- inventory lost 2,483 packages in one sweep and a cross-repository
    -- CVE query could answer "not affected" about a nested copy that was.
    PRIMARY KEY (repo, manifest, ecosystem, name, version, scope)
);
CREATE INDEX IF NOT EXISTS package_by_name ON package(ecosystem, name);

CREATE TABLE IF NOT EXISTS scan (
    id          INTEGER PRIMARY KEY,
    repo        TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    packages    INTEGER,
    findings    INTEGER,
    unresolved  INTEGER,
    tool_version TEXT
);
"""


def default_path() -> Path:
    """XDG data dir, overridable. Never inside a repository being scanned."""
    env = os.environ.get("DEP_INTEL_DB")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return Path(base) / "dep-intel" / "dep-intel.db"


def _migrate(conn) -> bool:
    """Bring an older store forward. Returns True if a re-sync is needed.

    There is no in-place upgrade path for an advisory schema change, and
    faking one would be worse than admitting it: the missing column has to be
    populated from the feed, and the feed is the only place the value exists.
    So the advisory tables are dropped and the feed records cleared, which
    makes `status` and every scan say plainly that the store is empty rather
    than quietly matching against half-migrated rows.
    """
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    have = int(row[0]) if row else 0
    if have == SCHEMA_VERSION:
        return False
    # `package` is dropped too, and unlike the advisory tables it costs
    # nothing: the inventory is local and `dep-intel sweep` rebuilds it in
    # seconds.
    for table in ("affected_version", "affected_range", "affected", "alias",
                  "related", "upstream", "vulnerability", "feed", "package"):
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    conn.executescript(_DDL)
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                 (str(SCHEMA_VERSION),))
    conn.commit()
    # Dropping the tables frees pages without shrinking the file, so a store
    # that has been through two migrations keeps the high-water mark of both.
    # Vacuuming here is close to free because the database is empty at this
    # exact point, and it is the only moment that is true.
    conn.execute("VACUUM")
    return True


def connect(path: Path | None = None) -> sqlite3.Connection:
    path = Path(path) if path else default_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()
    _migrate(conn)
    return conn


def feed_status(conn) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM feed ORDER BY name"))


def counts(conn) -> dict:
    def one(sql):
        return conn.execute(sql).fetchone()[0]

    return {
        "vulnerabilities": one("SELECT COUNT(*) FROM vulnerability"),
        "kev": one("SELECT COUNT(*) FROM vulnerability WHERE kev = 1"),
        "affected": one("SELECT COUNT(*) FROM affected"),
        "ecosystems": one("SELECT COUNT(DISTINCT ecosystem) FROM affected"),
        "packages": one("SELECT COUNT(*) FROM package"),
        "repos": one("SELECT COUNT(DISTINCT repo) FROM package"),
    }
