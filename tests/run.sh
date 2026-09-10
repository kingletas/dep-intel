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
trap 'rm -rf "$tmp"' EXIT

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

check_out  "a Cargo.lock crate is inventoried"    "crates.io"            "$bin" inventory "$tmp/multi"
check_out  "a Terraform provider becomes a Go module"            "github.com/hashicorp/terraform-provider-aws"            "$bin" inventory "$tmp/multi" --format json
check_out  "a private Terraform registry is named as unchecked" "NOT checked"            "$bin" inventory "$tmp/multi"
check_out  "an exact action tag is locked"        "actions/setup-node"            "$bin" inventory "$tmp/multi" --format json
check_out  "a moving action tag is not"           "moving tag"            "$bin" inventory "$tmp/multi"
check_out  "the Magento metapackage is cross-listed" "Magento"            "$bin" inventory "$tmp/multi"
check_out  "a scan names the ecosystems it could not check"            "no advisory feed has been synced"            "$bin" scan "$tmp/multi"

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
