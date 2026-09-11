#!/usr/bin/env bash
#
# run.sh -- end-to-end check that the installed pair actually works.
#
# The unit suite (bin/dep-intel.d/test.py) covers comparators, parsers, the
# matcher and the output shapes offline. This covers the thing a unit test
# cannot: that the wrapper finds its payload, that the CLI parses its own
# arguments, and that an EMPTY store produces an honest answer rather than a
# clean-looking one.
#
# No network. `sync` is never called here.

set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
bin="$here/bin/dep-intel"
tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT

export DEP_INTEL_DB="$tmp/store.db"
export NO_COLOR=1

fail=0
check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  ok   $label"
  else
    echo "  FAIL $label (exit $?)"
    fail=1
  fi
}
check_out() {
  local label="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1 || true)"
  if [[ "$out" == *"$needle"* ]]; then
    echo "  ok   $label"
  else
    echo "  FAIL $label -- expected to see: $needle"
    printf '%s\n' "$out" | sed 's/^/         /' | head -8
    fail=1
  fi
}
check_status() {
  local label="$1" want="$2"; shift 2
  local out got=0
  out="$("$@" 2>&1)" || got=$?
  if [[ $got -eq $want ]]; then
    echo "  ok   $label"
  else
    echo "  FAIL $label -- exit $got, expected $want"
    printf '%s\n' "$out" | sed 's/^/         /' | head -8
    fail=1
  fi
}

echo "dep-intel end to end"

check      "the unit suite passes"            "$bin" test
check      "--version"                        "$bin" --version
check_out  "-h prints usage"                  "dep-intel sync"     "$bin" -h
check_out  "an unknown command is refused"    "invalid choice"     "$bin" nonsense

# An empty store must SAY it is empty. This is the property that matters most:
# a scanner with no advisories loaded and a cheerful "no findings" is the exact
# lie the tool exists to avoid.
check_out  "doctor reports an empty store"    "EMPTY"              "$bin" doctor
check_out  "status says nothing is synced"    "no feed has ever been synced"  "$bin" status

# A repository with a real lockfile, matched against an empty store.
mkdir -p "$tmp/repo"
cat > "$tmp/repo/composer.lock" <<'JSON'
{"packages":[{"name":"acme/widget","version":"1.2.3"}],"packages-dev":[]}
JSON
check_out  "scan reads the lockfile"          "1 package(s)"       "$bin" scan "$tmp/repo"
check_out  "scan warns the store is empty"    "advisory store is EMPTY" "$bin" scan "$tmp/repo"
check_out  "inventory lists the ecosystem"    "Packagist"          "$bin" inventory "$tmp/repo"

# Machine-readable output has to be parseable, not merely produced.
"$bin" scan "$tmp/repo" --format json  --output "$tmp/out.json"
"$bin" scan "$tmp/repo" --format sarif --output "$tmp/out.sarif"
check_out  "json is valid and names the repo" "$tmp/repo" \
           python3 -c "import json;d=json.load(open('$tmp/out.json'));print(d['tool'],d['repo'],d['summary']['total'])"
check_out  "json inventory lists the package" "acme/widget" \
           "$bin" inventory "$tmp/repo" --format json
check      "sarif is valid json"              python3 -c "import json;json.load(open('$tmp/out.sarif'))"
check_out  "sarif declares 2.1.0"             "2.1.0" \
           python3 -c "import json;print(json.load(open('$tmp/out.sarif'))['version'])"

# Exit 1 means a finding and nothing else, so a caller can trust it. The store
# is seeded with the unit suite's own helpers, since `sync` needs the network.
mkdir -p "$tmp/found" "$tmp/seeded"
seeded="$tmp/seeded/store.db"
cat > "$tmp/found/composer.lock" <<'JSON'
{"packages":[{"name":"acme/lib","version":"1.5.0"}],"packages-dev":[]}
JSON
DEP_INTEL_DB="$seeded" python3 - "$here/bin/dep-intel.d" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import store, test
test._ingest(store.connect(), [test._osv(
    "ADV-CRITICAL", "Packagist", "acme/lib",
    [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
    severity=[{"type": "CVSS_V3",
               "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])])
PY
check_status "a finding at --fail-on exits 1"   1 \
             env DEP_INTEL_DB="$seeded" "$bin" scan "$tmp/found" --fail-on high
check_status "a clean scan exits 0"             0 "$bin" scan "$tmp/repo" --fail-on high

# A store that cannot be written stops the scan before it decides anything.
if [[ $EUID -ne 0 ]]; then
  chmod 444 "$seeded"; chmod 555 "$tmp/seeded"
  check_status "a read-only store exits 2, not 1" 2 \
               env DEP_INTEL_DB="$seeded" "$bin" scan "$tmp/found" --fail-on high
  ro_out="$(DEP_INTEL_DB="$seeded" "$bin" scan "$tmp/found" 2>&1 || true)"
  chmod 755 "$tmp/seeded"; chmod 644 "$seeded"
  check_out  "a read-only store is named"         "is not writable" \
             printf '%s\n' "$ro_out"
  if [[ "$ro_out" == *Traceback* ]]; then
    echo "  FAIL a read-only store printed a traceback"
    fail=1
  else
    echo "  ok   a read-only store prints no traceback"
  fi
else
  echo "  skip read-only store checks: root writes through file modes"
fi

# The new manifest formats, end to end through the installed wrapper. Each
# one asserts the HONEST answer as much as the parsed one: a moving action
# tag and a private Terraform registry must be named as not checked rather
# than counted as clean.
mkdir -p "$tmp/multi/.github/workflows"
cat > "$tmp/multi/Cargo.lock" <<'TOML'
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
TOML
cat > "$tmp/multi/.terraform.lock.hcl" <<'HCL'
provider "registry.terraform.io/hashicorp/aws" {
  version = "5.100.0"
}
provider "app.terraform.io/acme/private" {
  version = "1.0.0"
}
HCL
cat > "$tmp/multi/.github/workflows/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v4.0.2
YAML
cat > "$tmp/multi/composer.lock" <<'JSON'
{"packages":[{"name":"magento/product-enterprise-edition","version":"2.4.8-p2"}],"packages-dev":[]}
JSON

# Reading Cargo.lock needs tomllib (3.11+) or tomli; without either it must say so.
if python3 -c 'import tomllib' 2>/dev/null || python3 -c 'import tomli' 2>/dev/null; then
  check_out  "a Cargo.lock crate is inventoried"    "crates.io"            "$bin" inventory "$tmp/multi"
else
  check_out  "a Cargo.lock is named as unread without a TOML parser" "no TOML parser" "$bin" inventory "$tmp/multi"
fi
check_out  "a Terraform provider becomes a Go module"            "github.com/hashicorp/terraform-provider-aws"            "$bin" inventory "$tmp/multi" --format json
check_out  "a private Terraform registry is named as unchecked" "NOT checked"            "$bin" inventory "$tmp/multi"
check_out  "an exact action tag is locked"        "actions/setup-node"            "$bin" inventory "$tmp/multi" --format json
check_out  "a moving action tag is not"           "moving tag"            "$bin" inventory "$tmp/multi"
check_out  "the Magento metapackage is cross-listed" "Magento"            "$bin" inventory "$tmp/multi"
check_out  "a scan names the ecosystems it could not check"            "no advisory feed has been synced"            "$bin" scan "$tmp/multi"

# A Mage-OS store locks no magento/* package; it must still be matched as one.
mkdir -p "$tmp/mageos"
cat > "$tmp/mageos/composer.lock" <<'JSON'
{"packages":[{"name":"mage-os/framework","version":"9.1.0","replace":{"magento/framework":"103.0.1"}},{"name":"mage-os/product-community-edition","version":"9.1.0"}],"packages-dev":[]}
JSON
check_out  "a Mage-OS module is matched as the package it replaces" '"package": "magento/framework"'            "$bin" inventory "$tmp/mageos" --format json
check_out  "a Mage-OS edition with no Magento version is undecided"  "no extra.magento_version"            "$bin" scan "$tmp/mageos"

# The host command must either name the release it is matching against, or
# refuse. Matching a machine against the WRONG release clears real findings
# and invents others, so refusing is the only honest third option -- and this
# suite runs on macOS too, where refusing is the expected outcome.
host_out="$("$bin" host --no-fail 2>&1 || true)"
if [[ "$host_out" == *"Ubuntu:"* || "$host_out" == *"Debian:"*    || "$host_out" == *"dpkg-query is not on PATH"*    || "$host_out" == *"no advisory ecosystem dep-intel knows"* ]]; then
  echo "  ok   host names its release or refuses to guess"
else
  echo "  FAIL host neither named a release nor refused"
  printf '%s\n' "$host_out" | sed 's/^/         /' | head -8
  fail=1
fi

# An unknown advisory id must not be reported as absence of risk.
check_out  "an unknown CVE says the store lacks it" "not in the local store" \
           "$bin" cve CVE-1999-0001

# sync must refuse a non-HTTPS feed even in a dry run.
check_out  "sync -n prints a plan without fetching" "will download" "$bin" sync -n

# With no roots configured, sweep walks the directory it was started in.
git init -q "$tmp/repo"
sweep_out="$( { cd "$tmp" && env -u DEP_INTEL_ROOTS "$bin" sweep --no-fail; } 2>&1 )" || true
check_out  "sweep defaults to the current directory" "1 repositories under $(cd "$tmp" && pwd -P)" \
           printf '%s\n' "$sweep_out"

echo
if [[ $fail -eq 0 ]]; then
  echo "  all end-to-end checks passed"
else
  echo "  FAILURES above"
fi
exit $fail
