SHELL := /bin/bash
PREFIX ?= $(HOME)/.local
SCRIPTS := bin/mac-secure jobs/daily jobs/enforcer root/macos-update root/install-root.sh lib/*.sh tests/*.sh

.PHONY: verify lint test install uninstall

# The same gate CI runs.
verify: lint test

lint:
	shellcheck -x -S warning $(SCRIPTS)
	@if command -v actionlint >/dev/null; then actionlint; else echo "actionlint not installed; CI runs it"; fi

test:
	/bin/bash tests/run.sh

install:
	mkdir -p "$(PREFIX)/bin"
	ln -sf "$(CURDIR)/bin/mac-secure" "$(PREFIX)/bin/mac-secure"

uninstall:
	rm -f "$(PREFIX)/bin/mac-secure"
