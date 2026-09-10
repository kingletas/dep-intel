"""Find and parse dependency lockfiles across a repository.

Lockfiles only, and that is a correctness decision rather than laziness. A
`composer.json` or a `pyproject.toml` carries a *constraint* -- `^8.1`,
`>=2,<3` -- and the version actually installed is whatever resolution picked
on the day. Matching an advisory against a constraint answers "could this
repository be vulnerable", which is a different and much weaker question than
"is it". Where only a constraint file exists, the file is reported as
unlocked rather than silently resolved to a guess.

The one exception is `requirements.txt`, which is a constraint file that is
very often used as a lockfile. An `==` pin there is exact and is used; any
other operator is counted as unpinned and reported.

Supported:

  composer.lock          Packagist    packages + packages-dev
  package-lock.json      npm          lockfileVersion 1, 2 and 3
  uv.lock                PyPI         TOML [[package]]
  poetry.lock            PyPI         TOML [[package]]
  requirements.txt       PyPI         `==` pins only
  Cargo.lock             crates.io    TOML [[package]] with a registry source
  .terraform.lock.hcl    Terraform    provider blocks, matched in Go
  .github/workflows/*    GH Actions   `uses:` steps, exact tags only

Two of those three carry a caveat that the report has to state rather than
absorb, because in both cases the honest answer is "this was not checked":

  Terraform  A provider is locked as `registry.terraform.io/hashicorp/aws`
             and its advisories are published as the Go module
             `github.com/hashicorp/terraform-provider-aws`. The translation
             is the registry's own naming convention and it is a CONVENTION,
             not a lookup -- a provider whose repository is named differently
             derives to a module nothing has ever published an advisory for,
             and a name that matches nothing is indistinguishable from a name
             with nothing against it. Every derived name is reported.
  Actions    `actions/checkout@v5` is not a version, it is a moving major
             tag, and resolving it to 5.0.0 would answer a question nobody
             asked. Only an exact `x.y.z` tag is treated as locked; a
             floating tag is reported as unpinned and a commit SHA is
             reported as unmatchable, since a SHA cannot be ordered against
             a version range.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# TOML: stdlib from 3.11, `tomli` before it. If neither is importable the
# TOML lockfiles are SKIPPED AND REPORTED -- never treated as absent, because
# "this repository has no Python dependencies" and "I could not read them"
# must not look the same in a report.
try:
    import tomllib as _toml
    TOML_BACKEND = "tomllib"
except ImportError:  # pragma: no cover - depends on interpreter version
    try:
        import tomli as _toml
        TOML_BACKEND = "tomli"
    except ImportError:
        _toml = None
        TOML_BACKEND = None

# Directories that are never a repository's own source. `vendor` and
# `node_modules` hold installed third-party trees whose own lockfiles describe
# their upstream projects, not this one -- walking into them multiplies the
# inventory by a hundred and attributes other people's dependencies here.
SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "generated", "var", "pub", ".idea", ".cache", "dist", "build",
    ".terraform", "archive", "webroot_archive",
}

LOCKFILES = {
    "composer.lock": "Packagist",
    "package-lock.json": "npm",
    "uv.lock": "PyPI",
    "poetry.lock": "PyPI",
    "requirements.txt": "PyPI",
    "Cargo.lock": "crates.io",
    "Gemfile.lock": "RubyGems",
    ".terraform.lock.hcl": "Terraform",
}

# A workflow is a manifest too, but it is identified by where it sits rather
# than by its name -- any `.yml` under `.github/workflows` is one, and a
# `.yml` anywhere else is not.
def _is_workflow(path) -> bool:
    parts = path.parts
    return (
        path.suffix in (".yml", ".yaml")
        and len(parts) >= 3
        and parts[-2] == "workflows"
        and parts[-3] == ".github"
    )

UNLOCKED = {"composer.json", "package.json", "pyproject.toml", "setup.py"}

# The Composer names for the Magento application itself, as opposed to the
# hundreds of `magento/module-*` components that are on Packagist normally.
MAGENTO_METAPACKAGES = {
    "magento/product-enterprise-edition",
    "magento/product-community-edition",
    "magento/project-enterprise-edition",
    "magento/project-community-edition",
}


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    scope: str          # runtime | dev
    manifest: str       # repo-relative path


@dataclass
class ParseResult:
    packages: list
    skipped: list       # (path, reason) -- always reported, never swallowed


def _is_repo_root(path: Path) -> bool:
    """Is this directory its own git repository?

    Named behaviour on failure rather than a bare except: a path we are not
    allowed to stat cannot be CLAIMED to be a repository root, so it is
    treated as an ordinary directory and the walk's own permission guard
    deals with whatever is inside it. A rootless container's bind-mounted
    .git, for example, raises PermissionError from exists() itself.
    """
    try:
        return (path / ".git").exists()
    except OSError:
        return False


def discover(root: Path, max_depth: int = 8):
    """Walk for lockfiles, skipping installed trees. Returns (locks, unlocked)."""
    root = Path(root)
    locks, unlocked = [], []
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = list(d.iterdir())
        except (PermissionError, OSError):
            continue
        for e in entries:
            # A symlinked directory can point back up the tree; following one
            # turns the walk into a cycle. Symlinked files are read normally.
            if e.is_symlink() and e.is_dir():
                continue
            if e.is_dir():
                # `.github` is the one dotted directory that holds manifests
                # rather than tool state, and the blanket dot rule would hide
                # every workflow in the repository.
                if e.name in SKIP_DIRS:
                    continue
                if e.name.startswith(".") and e.name != ".github":
                    continue
                # Stop at a nested repository: it is swept in its own right,
                # and walking into it would count its packages twice.
                if _is_repo_root(e):
                    continue
                stack.append((e, depth + 1))
            elif e.name in LOCKFILES or _is_workflow(e):
                locks.append(e)
            elif e.name in UNLOCKED:
                unlocked.append(e)
    return sorted(locks), sorted(unlocked)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _read_json(path: Path):
    with path.open("rb") as fh:
        return json.load(fh)


def parse_composer_lock(path: Path, root: Path) -> ParseResult:
    doc = _read_json(path)
    rel, out, skipped = _rel(path, root), [], []
    for key, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for p in doc.get(key) or []:
            name, ver = p.get("name"), p.get("version")
            if not name or not ver:
                skipped.append((rel, f"entry without name/version: {name!r}"))
                continue
            clean = str(ver).lstrip("vV")
            out.append(Package("Packagist", name, clean, scope, rel))
            # Adobe Commerce and Magento Open Source ship from
            # repo.magento.com rather than Packagist, so OSV holds no
            # advisory for these two names and a store scanned clean on the
            # one package that matters most. They are listed a second time
            # under the Magento ecosystem, whose feed is built from NVD.
            if name in MAGENTO_METAPACKAGES:
                out.append(Package("Magento", name, clean, scope, rel))
    return ParseResult(out, skipped)


def parse_package_lock(path: Path, root: Path) -> ParseResult:
    doc = _read_json(path)
    rel, out, skipped = _rel(path, root), [], []
    version = doc.get("lockfileVersion", 1)

    if "packages" in doc:                      # lockfileVersion 2 and 3
        for key, meta in (doc.get("packages") or {}).items():
            if not key or not isinstance(meta, dict):
                continue                        # "" is the root project
            # `name` is present for an aliased install, where the directory
            # under node_modules is the alias and not the package.
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            ver = meta.get("version")
            if meta.get("link"):
                skipped.append((rel, f"{name}: local link, not a registry package"))
                continue
            if not ver:
                skipped.append((rel, f"{name}: no version in lock entry"))
                continue
            scope = "dev" if meta.get("dev") or meta.get("devOptional") else "runtime"
            out.append(Package("npm", name, str(ver), scope, rel))
    else:                                       # lockfileVersion 1
        def walk(tree, scope_default="runtime"):
            for name, meta in (tree or {}).items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                scope = "dev" if meta.get("dev") else scope_default
                if ver:
                    out.append(Package("npm", name, str(ver), scope, rel))
                walk(meta.get("dependencies"), scope)

        walk(doc.get("dependencies"))
    if not out and version:
        skipped.append((rel, f"lockfileVersion {version} yielded no packages"))
    return ParseResult(out, skipped)


def _parse_toml(path: Path):
    if _toml is None:
        raise RuntimeError(
            "no TOML parser: this interpreter has neither tomllib (3.11+) "
            "nor tomli"
        )
    with path.open("rb") as fh:
        return _toml.load(fh)


def parse_uv_lock(path: Path, root: Path) -> ParseResult:
    doc = _parse_toml(path)
    rel, out, skipped = _rel(path, root), [], []
    for p in doc.get("package") or []:
        # uv records the project itself as a package, with a `source` of
        # {virtual|editable} rather than a registry. A project whose version is
        # dynamic carries no `version` key, so this is decided before the guard.
        src = p.get("source") or {}
        if "virtual" in src or "editable" in src:
            continue
        name, ver = p.get("name"), p.get("version")
        if not name or not ver:
            skipped.append((rel, f"package without name/version: {name!r}"))
            continue
        out.append(Package("PyPI", name, str(ver), "runtime", rel))
    return ParseResult(out, skipped)


def parse_poetry_lock(path: Path, root: Path) -> ParseResult:
    doc = _parse_toml(path)
    rel, out, skipped = _rel(path, root), [], []
    for p in doc.get("package") or []:
        name, ver = p.get("name"), p.get("version")
        if not name or not ver:
            skipped.append((rel, f"package without name/version: {name!r}"))
            continue
        # Poetry 1.2+ uses `groups`; earlier lockfiles use `category`.
        groups = p.get("groups") or ([p["category"]] if p.get("category") else [])
        scope = "runtime" if (not groups or "main" in groups) else "dev"
        out.append(Package("PyPI", name, str(ver), scope, rel))
    return ParseResult(out, skipped)


_REQ_PIN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*(?P<ver>[^\s;#]+)"
)


def parse_requirements(path: Path, root: Path) -> ParseResult:
    rel, out, skipped = _rel(path, root), [], []
    unpinned = 0
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return ParseResult([], [(rel, f"unreadable: {e}")])
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            # -r other.txt, -e ., --index-url ...
            if s.startswith(("-r", "--requirement")):
                skipped.append((rel, f"include not followed: {s}"))
            continue
        m = _REQ_PIN.match(s)
        if m:
            out.append(Package("PyPI", m["name"], m["ver"], "runtime", rel))
        else:
            unpinned += 1
    if unpinned:
        skipped.append((rel, f"{unpinned} requirement(s) not pinned with =="))
    return ParseResult(out, skipped)


def parse_cargo_lock(path: Path, root: Path) -> ParseResult:
    """Cargo.lock v1, v2 and v3 -- TOML `[[package]]` blocks.

    A package with no `source` is a workspace member of this repository, not
    a dependency, and including it would report the project against advisories
    for somebody else's crate of the same name.
    """
    doc = _parse_toml(path)
    rel, out, skipped = _rel(path, root), [], []
    local = 0
    for pkg in doc.get("package") or []:
        name, ver = pkg.get("name"), pkg.get("version")
        if not name or not ver:
            skipped.append((rel, f"package without name/version: {name!r}"))
            continue
        src = pkg.get("source") or ""
        if not src:
            local += 1
            continue
        # A git or path dependency has a source but no registry version that
        # an advisory range can speak about.
        if not str(src).startswith("registry+"):
            skipped.append((rel, f"{name}: non-registry source, not matchable"))
            continue
        out.append(Package("crates.io", name, str(ver), "runtime", rel))
    if local:
        skipped.append((rel, f"{local} workspace member(s) skipped as local"))
    return ParseResult(out, skipped)


# `provider "registry.terraform.io/hashicorp/aws" {` ... `version = "5.100.0"`
_TF_PROVIDER = re.compile(
    r'provider\s+"(?P<source>[^"]+)"\s*\{(?P<body>[^}]*)\}', re.DOTALL
)
_TF_VERSION = re.compile(r'version\s*=\s*"(?P<v>[^"]+)"')


def terraform_go_module(source: str):
    """The Go module a Terraform provider's advisories are published under.

    The registry requires a provider named `<namespace>/<type>` to live in a
    repository called `terraform-provider-<type>` under that namespace, so
    the module path is derivable. It is derivable, not looked up: a provider
    served from a private registry, or one whose repository does not follow
    the convention, produces a name no advisory uses -- and a name that
    matches nothing looks exactly like a name with nothing against it. The
    caller reports every derivation for that reason.
    """
    parts = (source or "").strip().split("/")
    if len(parts) != 3:
        return None
    host, namespace, kind = parts
    if host != "registry.terraform.io":
        return None
    if not namespace or not kind:
        return None
    return f"github.com/{namespace}/terraform-provider-{kind}"


def parse_terraform_lock(path: Path, root: Path) -> ParseResult:
    rel, out, skipped = _rel(path, root), [], []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return ParseResult([], [(rel, f"unreadable: {e}")])

    found = 0
    for m in _TF_PROVIDER.finditer(text):
        source = m["source"]
        vm = _TF_VERSION.search(m["body"])
        if not vm:
            skipped.append((rel, f"{source}: provider block has no version"))
            continue
        found += 1
        module = terraform_go_module(source)
        if module is None:
            skipped.append((
                rel,
                (f"{source}: not a registry.terraform.io provider, so no Go "
                 "module name can be derived and it is NOT checked")))
            continue
        out.append(Package("Terraform", module, vm["v"], "runtime", rel))
    if found and out:
        skipped.append((
            rel,
            (f"{len(out)} provider(s) matched as Go modules by the registry "
             "naming convention; a provider whose repository is named "
             "differently would not match and would look clean")))
    return ParseResult(out, skipped)


# `uses: owner/repo@ref` or `uses: owner/repo/sub/path@ref`, with the quoting
# and comment forms that appear in real workflows.
_USES = re.compile(
    r"^\s*-?\s*uses\s*:\s*[\"']?(?P<ref>[^\s\"'#]+)", re.MULTILINE
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_EXACT_TAG = re.compile(r"^v?\d+\.\d+\.\d+")


def parse_workflow(path: Path, root: Path) -> ParseResult:
    """`uses:` steps in one GitHub Actions workflow.

    Only an exact `x.y.z` tag is a lock. `actions/checkout@v5` is a major tag
    that GitHub moves as new releases land, so the commit behind it today is
    not the commit behind it tomorrow -- reading it as 5.0.0 would answer a
    question about a version nobody has pinned, and would report clean on a
    range the moving tag currently sits inside. A commit SHA is the strongest
    pin there is and is also the one thing no version range can be compared
    against, so it is named as unmatchable rather than counted as checked.
    """
    rel, out, skipped = _rel(path, root), [], []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return ParseResult([], [(rel, f"unreadable: {e}")])

    floating, sha, local = [], 0, 0
    seen = set()
    for m in _USES.finditer(text):
        spec = m["ref"]
        if spec.startswith(("./", "docker://")):
            local += 1
            continue
        if "@" not in spec:
            floating.append(spec)
            continue
        name, _, ref = spec.rpartition("@")
        # `owner/repo/path/to/action` -- the advisory names the repository.
        parts = name.split("/")
        if len(parts) < 2:
            continue
        repo = "/".join(parts[:2])
        if _SHA.match(ref):
            sha += 1
            continue
        if not _EXACT_TAG.match(ref):
            floating.append(f"{repo}@{ref}")
            continue
        key = (repo, ref.lstrip("v"))
        if key in seen:
            continue
        seen.add(key)
        out.append(Package("GitHub Actions", repo, ref.lstrip("v"), "ci", rel))

    if floating:
        shown = ", ".join(sorted(set(floating))[:6])
        more = "" if len(set(floating)) <= 6 else f" (+{len(set(floating)) - 6} more)"
        skipped.append((
            rel,
            (f"{len(set(floating))} action(s) on a moving tag, NOT checked: "
             f"{shown}{more}")))
    if sha:
        skipped.append((
            rel,
            (f"{sha} action(s) pinned to a commit SHA: the strongest pin, and "
             "not orderable against a version range, so not checked")))
    if local:
        skipped.append((rel, f"{local} local or docker action(s) skipped"))
    return ParseResult(out, skipped)


# A locked gem sits at exactly four spaces; its constraints sit at six.
_GEM_SPEC = re.compile(r"^ {4}(?P<name>\S+) \((?P<version>[^)]+)\)\s*$")
_GEM_PLATFORM_LINE = re.compile(r"^ {2}(?P<platform>\S+)\s*$")


def _gemfile_platforms(lines: list) -> list:
    """The platforms this lockfile declares, longest first.

    Bundler writes a platform-specific gem as `nokogiri (1.13.0-x86_64-linux)`,
    and Gem::Version reads a hyphen as the start of a PRERELEASE -- so left
    alone that version sorts below plain 1.13.0 and an advisory range would
    miss it. The suffix has to go, and this reads the PLATFORMS section rather
    than guessing what a platform looks like: a guess that recognises `arm`
    also mangles a legitimate 1.0.0-armadillo.
    """
    out, in_platforms = [], False
    for line in lines:
        if line[:1].isalpha():
            in_platforms = line.strip() == "PLATFORMS"
            continue
        m = _GEM_PLATFORM_LINE.match(line)
        if in_platforms and m and m["platform"] != "ruby":
            out.append(m["platform"])
    return sorted(out, key=len, reverse=True)


def parse_gemfile_lock(path: Path, root: Path) -> ParseResult:
    """Gemfile.lock -- the GEM section's specs, and only those.

    Indentation is the entire grammar, and it is the thing to get right. A gem
    locked to a version sits at four spaces. The six-space lines beneath it are
    that gem's CONSTRAINTS -- `rubocop (>= 1.75.0, < 2.0)` -- and reading one as
    a version invents a dependency at a version nothing installed.

    A PATH section is a gem checked out here, usually the project itself, and
    is local the way a Cargo workspace member is. A GIT section is pinned to a
    revision rather than to a released version, so no advisory range can speak
    about it. Both are reported rather than dropped.

    Every gem is recorded as runtime scope because a lockfile carries no
    groups: `group :development` lives in the Gemfile, and calling a gem dev
    on a guess would quietly downgrade a real finding.
    """
    rel, out, skipped = _rel(path, root), [], []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return ParseResult([], [(rel, f"unreadable: {e}")])

    platforms = _gemfile_platforms(lines)
    section, in_specs, local, git = "", False, 0, 0
    for line in lines:
        if line[:1].isalpha():
            section, in_specs = line.strip(), False
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        m = _GEM_SPEC.match(line)
        if not (in_specs and m):
            continue
        if section == "PATH":
            local += 1
            continue
        if section == "GIT":
            git += 1
            continue
        if section != "GEM":
            continue
        version = _strip_gem_platform(m["version"], platforms)
        out.append(Package("RubyGems", m["name"], version, "runtime", rel))

    if local:
        skipped.append((rel, f"{local} path-sourced gem(s) skipped as local"))
    if git:
        skipped.append((rel, f"{git} git-sourced gem(s) skipped: pinned to a revision, not a version"))
    return ParseResult(out, skipped)


def _strip_gem_platform(version: str, platforms: list) -> str:
    for platform in platforms:
        if version.endswith(f"-{platform}"):
            return version[: -len(platform) - 1]
    return version


_PARSERS = {
    "composer.lock": parse_composer_lock,
    "package-lock.json": parse_package_lock,
    "uv.lock": parse_uv_lock,
    "poetry.lock": parse_poetry_lock,
    "requirements.txt": parse_requirements,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    ".terraform.lock.hcl": parse_terraform_lock,
}


def parse(path: Path, root: Path) -> ParseResult:
    """Parse one lockfile. A parser failure is reported, never fatal."""
    fn = _PARSERS.get(path.name)
    if fn is None and _is_workflow(path):
        fn = parse_workflow
    if fn is None:
        return ParseResult([], [(_rel(path, root), "no parser for this filename")])
    try:
        return fn(path, root)
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as e:
        return ParseResult([], [(_rel(path, root), f"{type(e).__name__}: {e}")])


# Runtimes are not dependencies. A `require` of nothing but the interpreter
# says "this component runs on PHP 8.1", not "this project pulls in code".
_RUNTIME_KEYS = {"php", "python", "node", "npm", "composer-plugin-api",
                 "composer-runtime-api", "ext-", "lib-"}


def _declares_dependencies(path: Path) -> bool:
    """Does this constraint file name any third-party package at all?"""
    try:
        if path.name in ("composer.json", "package.json"):
            doc = _read_json(path)
            keys = []
            for field in ("require", "require-dev", "dependencies",
                          "devDependencies", "peerDependencies"):
                keys.extend((doc.get(field) or {}).keys())
            return any(
                not any(k == r or k.startswith(r) for r in _RUNTIME_KEYS)
                for k in keys
            )
        if path.name == "pyproject.toml":
            doc = _parse_toml(path)
            proj = doc.get("project") or {}
            if proj.get("dependencies") or proj.get("optional-dependencies"):
                return True
            poetry = ((doc.get("tool") or {}).get("poetry") or {})
            deps = set(poetry.get("dependencies") or {})
            return bool(deps - _RUNTIME_KEYS)
        return True                       # setup.py: cannot tell without running it
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        return True                       # unreadable is a gap, and is reported


def collect(root: Path):
    """Every package in a repository, plus everything that could not be read."""
    root = Path(root).resolve()
    locks, unlocked = discover(root)
    # Deduplicated, because npm hoists. One package-lock.json lists lodash at
    # node_modules/lodash and again at node_modules/x/node_modules/lodash --
    # the same package, the same version, installed twice. Left as two rows it
    # produced two identical findings for one advisory, and made the report's
    # package count disagree with the inventory it had just written.
    # Package is a frozen dataclass, so set() is the whole implementation.
    seen, packages, skipped = set(), [], []
    for lock in locks:
        res = parse(lock, root)
        for pkg in res.packages:
            if pkg not in seen:
                seen.add(pkg)
                packages.append(pkg)
        skipped.extend(res.skipped)

    # A constraint file with no lockfile beside it is a real gap in coverage
    # and is named as one -- but only when it actually declares dependencies.
    # Magento gives every module its own composer.json as a *component
    # descriptor*: a name, a type, and a `require` holding nothing but the PHP
    # version. Reporting 66 of those as unlocked projects buries the one entry
    # that matters, which is what makes a report noise.
    locked_dirs = {p.parent for p in locks}
    for u in unlocked:
        # Covered by an ANCESTOR lockfile, not merely a sibling one. A Magento
        # module's composer.json genuinely requires magento/framework, so the
        # "declares dependencies" test passes and it still is not an unlocked
        # project -- the root composer.lock is where those requirements were
        # resolved. Same shape as a workspace package.json under a monorepo
        # root lock.
        if any(a in locked_dirs for a in (u.parent, *u.parent.parents)):
            continue
        if not _declares_dependencies(u):
            continue
        skipped.append((_rel(u, root), "constraint file with no lockfile beside it"))
    return packages, skipped, locks
