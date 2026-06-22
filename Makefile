GO ?= go
GOFLAGS ?=
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS ?= -s -w -X github.com/jm/security-automation-go/internal/buildmeta.Version=$(VERSION) -X github.com/jm/security-automation-go/internal/buildmeta.Commit=$(GIT_COMMIT) -X github.com/jm/security-automation-go/internal/buildmeta.BuildDate=$(BUILD_DATE)
BUILD_FLAGS ?= -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"
STATIC_ENV = CGO_ENABLED=0
VERSION ?= 1.7.4
GOPATH_BIN := $(shell $(GO) env GOPATH)/bin

GOFMT_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: all build build-linux-amd64 build-linux-arm64 verify-release package test fmt vet verify clean

all: build

# Build all 5 binaries for host platform
build:
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/crowdsec-sync ./cmd/crowdsec-sync
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/cf-allowlist-sync ./cmd/cf-allowlist-sync
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/cf-cleanup ./cmd/cf-cleanup
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/cf-sync ./cmd/cf-sync
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/security-automation-mcp ./cmd/security-automation-mcp

# linux/amd64 static binaries (for .deb packaging and CI artifact)
build-linux-amd64:
	@mkdir -p bin/linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-amd64/crowdsec-sync ./cmd/crowdsec-sync
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-amd64/cf-allowlist-sync ./cmd/cf-allowlist-sync
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-amd64/cf-cleanup ./cmd/cf-cleanup
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-amd64/cf-sync ./cmd/cf-sync
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-amd64/security-automation-mcp ./cmd/security-automation-mcp

# linux/arm64 static binaries (for CI artifact; modernc.org/sqlite is pure Go, no cross-compiler needed)
build-linux-arm64:
	@mkdir -p bin/linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-arm64/crowdsec-sync ./cmd/crowdsec-sync
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-arm64/cf-allowlist-sync ./cmd/cf-allowlist-sync
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-arm64/cf-cleanup ./cmd/cf-cleanup
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-arm64/cf-sync ./cmd/cf-sync
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/linux-arm64/security-automation-mcp ./cmd/security-automation-mcp

# Full pre-release gate: gofmt, vet, test, race, build, govulncheck, gitleaks, trufflehog
# Requires: govulncheck, gitleaks, trufflehog — see docs/releases/RELEASE_CHECKLIST.md for install instructions
# govulncheck findings are documented NO-GO (see docs/releases/RELEASE_CHECKLIST.md); all steps always run.
verify-release:
	@FAIL=0; \
	echo "==> [1/7] gofmt check"; \
	unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "ERROR: unformatted files:"; echo "$$unformatted"; exit 1; fi; \
	echo "==> [2/7] go vet"; \
	$(GO) vet ./... || exit 1; \
	echo "==> [3/7] go test"; \
	$(GO) test -timeout 120s ./... || exit 1; \
	echo "==> [4/7] go test -race"; \
	$(GO) test -race -timeout 300s ./... || exit 1; \
	echo "==> [5/7] go build (all 5 binaries)"; \
	$(MAKE) build || exit 1; \
	echo "==> [6/7] govulncheck"; \
	GOVULNCHECK=$$(command -v govulncheck 2>/dev/null || echo "$(GOPATH_BIN)/govulncheck"); \
	if [ ! -x "$$GOVULNCHECK" ]; then \
		echo "ERROR: govulncheck not found. Install: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; \
	fi; \
	"$$GOVULNCHECK" ./... || { FAIL=1; echo "WARN: govulncheck FINDINGS — NO-GO for production. See docs/releases/RELEASE_CHECKLIST.md."; }; \
	echo "==> [7a/7] secret scan — gitleaks"; \
	GITLEAKS=$$(command -v gitleaks 2>/dev/null || echo "$(GOPATH_BIN)/gitleaks"); \
	if [ ! -x "$$GITLEAKS" ]; then \
		echo "ERROR: gitleaks not found. Install: go install github.com/zricethezav/gitleaks/v8@latest"; exit 1; \
	fi; \
	"$$GITLEAKS" detect --source . --config .gitleaks.toml || exit 1; \
	echo "==> [7b/7] secret scan — trufflehog (informational; known pre-existing finding documented)"; \
	if command -v trufflehog >/dev/null 2>&1; then \
		echo "NOTE: trufflehog may report a pre-existing AbuseIPDB finding. See docs/releases/RELEASE_CHECKLIST.md."; \
		trufflehog git file://. --only-verified || true; \
	else \
		echo "WARNING: trufflehog not found — scan skipped"; \
	fi; \
	echo ""; \
	if [ $$FAIL -ne 0 ]; then \
		echo "ERROR: verify-release FAILED — govulncheck found vulnerabilities (see above)."; \
		echo "       Update OTEL to v1.40.0+/v1.43.0+ and OPA to v0.68.0+ to clear findings."; \
		echo "       See docs/releases/RELEASE_CHECKLIST.md for full decision record."; \
		exit 1; \
	fi; \
	echo "==> verify-release COMPLETE — all gates passed. See docs/releases/RELEASE_CHECKLIST.md for GO/NO-GO."

# Build .deb package for linux/amd64
# RPM: requires rpmbuild (rpm-build package on Fedora/RHEL/SUSE) — skipped if not present
package: build-linux-amd64
	@echo "==> Assembling .deb for v$(VERSION)"
	@mkdir -p dist
	@mkdir -p packaging/deb/usr/local/bin
	@mkdir -p packaging/deb/lib/systemd/system
	@mkdir -p packaging/deb/usr/lib/sysusers.d
	@mkdir -p packaging/deb/usr/lib/tmpfiles.d
	@cp bin/linux-amd64/crowdsec-sync packaging/deb/usr/local/bin/
	@cp bin/linux-amd64/cf-allowlist-sync packaging/deb/usr/local/bin/
	@cp bin/linux-amd64/cf-cleanup packaging/deb/usr/local/bin/
	@cp bin/linux-amd64/cf-sync packaging/deb/usr/local/bin/
	@cp bin/linux-amd64/security-automation-mcp packaging/deb/usr/local/bin/
	@cp deployments/systemd/*.service packaging/deb/lib/systemd/system/
	@cp deployments/systemd/*.timer packaging/deb/lib/systemd/system/ 2>/dev/null || true
	@cp packaging/shared/sysusers.d/security-automation-go.conf packaging/deb/usr/lib/sysusers.d/
	@cp packaging/shared/tmpfiles.d/security-automation-go.conf packaging/deb/usr/lib/tmpfiles.d/
	@chmod 755 packaging/deb/DEBIAN/postinst packaging/deb/DEBIAN/postrm packaging/deb/DEBIAN/prerm
	@chmod 755 packaging/deb/usr/local/bin/*
	@sed -i "s/^Version:.*/Version: $(VERSION)/" packaging/deb/DEBIAN/control
	@dpkg-deb --build packaging/deb dist/security-automation-go_$(VERSION)_amd64.deb
	@echo "==> Built: dist/security-automation-go_$(VERSION)_amd64.deb"
	@if [ -z "$(NO_RPM)" ] && command -v rpmbuild >/dev/null 2>&1; then \
		echo "==> Building RPM..."; \
		rpmbuild -bb packaging/rpm/security-automation-go.spec \
			--define "_topdir $$(pwd)/dist/rpm-build" \
			--define "_rpmdir $$(pwd)/dist" 2>&1; \
	else \
		echo "==> SKIP RPM: rpmbuild not available or NO_RPM=1 (install rpm-build on Fedora/RHEL/SUSE)"; \
	fi

test:
	$(GO) test $(GOFLAGS) ./...

fmt:
	gofmt -w $(GOFMT_FILES)

vet:
	$(GO) vet ./...

verify: fmt vet test build

clean:
	rm -rf bin dist
	rm -rf packaging/deb/usr packaging/deb/lib
