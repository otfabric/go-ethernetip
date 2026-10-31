# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help

.PHONY: help all build examples fmt fmt-check lint lint-ci vet vuln test test-short coverage coverage-check cover bench fuzz fuzz-long check clean interop test-interop generate generate-check coverpkg-check cross e2e chaos stress

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Parent otfabric/go.work does not list this module; isolate toolchain commands.
export GOWORK := off

# CI formats and lints with the Go version from go.mod, not with the toolchain installed here.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

BIN_DIR := bin
# Library packages: tests and coverage (the examples and the generated
# sample package are not library code).
TEST_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/interop')
# Packages whose coverage counts, including what the e2e suite exercises.
COVER_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/internal/cmd' | grep -v '/e2e' | grep -v '/sampledevice' | grep -v '/internal/testenv' | grep -v '/interop' | paste -sd, -)
# Minimum total statement coverage enforced by coverage-check (and CI).
COVERAGE_MIN ?= 90
# Per-package floor (TEST-012); needs the -coverpkg coverage.out of `make coverage`.
COVER_PKG_MIN := 90

INTEROP_TAGS := interop

all: build ## Default target: build the examples

build: ## Build the examples into ./bin
	@echo "Building examples"
	@mkdir -p $(BIN_DIR)
	@for dir in examples/*/; do \
		name="$$(basename "$$dir")"; \
		go build -o "$(BIN_DIR)/example-$$name" "./$$dir"; \
	done

# The self-contained examples: each starts both sides and exits by itself.
RUN_EXAMPLES := quickstart io logix eds

examples: ## Run the self-contained examples (each must exit successfully)
	@for e in $(RUN_EXAMPLES); do \
		echo "Running example $$e"; \
		go run ./examples/$$e >/dev/null || { echo "example $$e failed"; exit 1; }; \
	done

fmt: ## Format Go code with the gofmt of the Go version in go.mod (what CI uses)
	@echo "Running gofmt (go$(GO_MOD_VERSION))"
	@$(GOFMT_CI) -w .

fmt-check: ## Fail if the go.mod-version gofmt or the local gofmt would change any file
	@echo "Checking formatting (gofmt go$(GO_MOD_VERSION) and local $$(go env GOVERSION))"
	@ci="$$($(GOFMT_CI) -l .)"; loc="$$(gofmt -l .)"; \
	if [ -n "$$ci$$loc" ]; then \
		[ -z "$$ci" ] || { echo "Not formatted for gofmt go$(GO_MOD_VERSION) (CI):"; echo "$$ci"; }; \
		[ -z "$$loc" ] || { echo "Not formatted for the local gofmt:"; echo "$$loc"; }; \
		echo "Files must be stable under both. Run 'make fmt'."; \
		exit 1; \
	fi

lint: ## Run staticcheck (includes -tags=interop for ./interop)
	@echo "Running staticcheck"
	@staticcheck -tags=$(INTEROP_TAGS) ./...

lint-ci: ## Run golangci-lint (build-tags include interop; see .golangci.yml)
	@echo "Running golangci-lint"
	@golangci-lint run ./...

vet: ## Run go vet (includes -tags=interop compile of ./interop)
	@echo "Running go vet"
	@go vet -tags=$(INTEROP_TAGS) ./...

cross: ## Build for every supported platform (cross-compilation only; see TESTING.md for where tests run)
	@for p in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64; do \
		echo "Building $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} go build ./... || exit 1; \
	done

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck ./...

test: ## Run the tests with the race detector
	@echo "Running tests"
	@go test -count=1 -race $(TEST_PKGS)

test-short: ## Run the tests without the slow ones (no race detector)
	@go test -count=1 -short $(TEST_PKGS)

coverage: ## Run tests with coverage across the library packages (writes coverage.out)
	@echo "Running coverage"
	@go test -count=1 -race -covermode=atomic -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out $(TEST_PKGS)
	@go tool cover -func=coverage.out | tail -1

coverage-check: coverage ## Fail when the total coverage is below COVERAGE_MIN percent
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ { sub("%", "", $$3); print $$3 }'); \
	echo "Total coverage: $$total% (minimum $(COVERAGE_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVERAGE_MIN)" 'BEGIN { exit (t + 0 < m + 0) ? 1 : 0 }' || \
		{ echo "Coverage $$total% is below the required $(COVERAGE_MIN)%"; exit 1; }

coverage-pkg-check: coverage ## Fail when a package is below COVER_PKG_MIN
	@awk -v m="$(COVER_PKG_MIN)" 'NR > 1 { n[$$1] = $$2; if ($$3 > 0) h[$$1] = 1 } \
	END { for (k in n) { p = k; sub(/\/[^\/]*$$/, "", p); s[p] += n[k]; if (k in h) c[p] += n[k] } \
	for (p in s) { v = 100 * c[p] / s[p]; if (v < m) { printf "%s: %.1f%% < %s%%\n", p, v, m; bad = 1 } } exit bad }' coverage.out

cover: coverage ## Open coverage report in browser
	@go tool cover -html=coverage.out

bench: ## Run the codec and end-to-end benchmarks
	@echo "Running benchmarks"
	@go test -count=1 -run='^$$' -bench=. -benchmem ./cip ./encap ./implicit ./e2e

e2e: ## Run the end-to-end suite (client, scanner and server over loopback) with the race detector
	@go test -count=1 -race ./e2e

chaos: ## Run the chaos tests 10 times (ETHERNETIP_CHAOS_SEED=... repeats a seed)
	@go test -count=10 -race -run 'Chaos' ./implicit ./e2e

stress: ## Run the stress and parallel tests 10 times with the race detector
	@go test -count=10 -race -run 'Stress|Concurrent|Parallel' ./e2e ./client ./server ./scanner ./implicit

# Duration each fuzz target runs. Override with FUZZTIME=... (e.g. FUZZTIME=5m).
FUZZTIME ?= 30s
FUZZ_TARGETS := \
	cip:FuzzDecodePath cip:FuzzDecodeRequest cip:FuzzDecodeResponse cip:FuzzSplitMultiple \
	cip:FuzzDecodeForwardOpen cip:FuzzDecodeUnconnectedSend cip:FuzzDecodeIdentity \
	encap:FuzzDecodeHeader encap:FuzzReadPacket encap:FuzzDecodeCPF encap:FuzzDecodeIdentityItem \
	implicit:FuzzDecodeImplicit eds:FuzzParse logix:FuzzServeSymbol logix:FuzzTemplateDecode

fuzz: ## Run every fuzz target for FUZZTIME each (default 30s)
	@echo "Fuzzing (FUZZTIME=$(FUZZTIME))"
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t#*:}; \
		echo "$$pkg $$name"; \
		go test -run='^$$' -fuzz="^$$name$$" -fuzztime=$(FUZZTIME) ./$$pkg || exit 1; \
	done

# Images of otfabric/ethernetip-interop: the release pinned in
# interop/harness_test.go (interopRelease), or ETHERNETIP_INTEROP_VERSION=dev
# for images built locally with its "make images".
test-interop: ## Run the interop suite against the ethernetip-interop images (needs Docker)
	@echo "Running interop tests"
	@go test -tags=$(INTEROP_TAGS) -count=1 -timeout=30m ./interop/...

interop: test-interop ## Alias for test-interop

generate: ## Generate the CIP catalog code and CATALOG.md, and the sample EDS package
	@echo "Generating"
	@go generate ./...

generate-check: ## Fail when the generated files differ from their sources
	@echo "Checking the generated files"
	@go run ./internal/cmd/gencatalog -check
	@go run ./internal/cmd/gensample -check

coverpkg-check: ## Fail when CI's coverpkg (.github/workflows/ci.yml) is not COVER_PKGS
	@grep -qF -- "$(COVER_PKGS)" .github/workflows/ci.yml || { echo "coverpkg in .github/workflows/ci.yml must be: $(COVER_PKGS)"; exit 1; }

check: generate-check coverpkg-check fmt fmt-check lint lint-ci vet vuln test coverage-check coverage-pkg-check examples ## Run every check (pre-push gate)

clean: ## Remove generated binaries and coverage artifacts
	@echo "Cleaning up"
	@rm -rf $(BIN_DIR) coverage.out coverage.html
