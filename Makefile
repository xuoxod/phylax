# ==============================================================================
# 🛡️ Phylax — Sovereign Edge Defense & Reverse Proxy WAF Makefile
# ==============================================================================

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

.PHONY: all build release test test-analytics install clean help

all: build

help:
	@echo "Phylax Build & Management Targets:"
	@echo "  make build           - Build debug binary"
	@echo "  make release         - Build optimized release binary"
	@echo "  make test            - Run standard unit and integration tests"
	@echo "  make test-analytics  - Run analytics TDD and red-team fuzzer"
	@echo "  make install         - Install phylax and analytics tools to $(BINDIR)"
	@echo "  make clean           - Clean build artifacts"

build:
	cargo build

release:
	cargo build --release --features "cli,abuse-reporting"

test:
	cargo test

test-analytics:
	@if [ -x tools/tests/test_analytics.sh ]; then ./tools/tests/test_analytics.sh; fi
	@if [ -x tools/tests/redteam_fuzzer.sh ]; then ./tools/tests/redteam_fuzzer.sh; fi

install:
	@mkdir -p $(BINDIR)
	@if [ -f target/release/phylax ]; then \
		cp -f target/release/phylax $(BINDIR)/phylax; \
	elif [ -f target/debug/phylax ]; then \
		cp -f target/debug/phylax $(BINDIR)/phylax; \
	else \
		cargo build --release --features cli && cp -f target/release/phylax $(BINDIR)/phylax; \
	fi
	@chmod +x $(BINDIR)/phylax
	@if [ -f tools/analytics/phylax-analyze-traffic.sh ]; then \
		cp -f tools/analytics/phylax-analyze-traffic.sh $(BINDIR)/phylax-analyze-traffic && \
		chmod +x $(BINDIR)/phylax-analyze-traffic; \
	fi
	@if [ -f tools/analytics/phylax-threat-recon.sh ]; then \
		cp -f tools/analytics/phylax-threat-recon.sh $(BINDIR)/phylax-threat-recon && \
		chmod +x $(BINDIR)/phylax-threat-recon; \
	fi
	@echo "✅ Installed phylax and analytics suite to $(BINDIR)"

clean:
	cargo clean
