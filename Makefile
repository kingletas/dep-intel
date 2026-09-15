# dep-intel — offline dependency vulnerability intelligence
#
# Run `make` with no arguments for the list.

SHELL       := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PREFIX ?= $(HOME)/bin

.PHONY: help
help: ## Show this help
	@echo
	@echo "  dep-intel — offline dependency vulnerability intelligence"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo

# --- install ----------------------------------------------------------------

.PHONY: install
install: ## Copy this tool into ~/bin (PREFIX= to change)
	@scripts/install "$(PREFIX)"

.PHONY: uninstall
uninstall: ## Remove the installed copy
	@rm -f "$(PREFIX)/dep-intel"
	@rm -rf "$(PREFIX)/dep-intel.d"
	@echo "removed dep-intel from $(PREFIX)"
	@echo "the advisory store was not touched"

# --- checks -----------------------------------------------------------------

.PHONY: test
test: ## The end-to-end suite
	@tests/run.sh

.PHONY: lint
lint: ## Static checks
	@scripts/lint-tool shellcheck bin/dep-intel scripts/install scripts/lint-tool tests/run.sh packaging/release-notes.sh
	@scripts/lint-tool ruff check --quiet bin/dep-intel.d/

.PHONY: check
check: lint test ## Everything a commit has to pass
	@echo
	@echo "  lint and tests pass"
