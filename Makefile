GO ?= go
GOFLAGS ?=
LDFLAGS ?= -s -w
BUILD_FLAGS ?= -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"
STATIC_ENV = CGO_ENABLED=0

GOFMT_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: all build test fmt vet verify clean

all: build

build:
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/crowdsec-sync ./cmd/crowdsec-sync
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/cf-allowlist-sync ./cmd/cf-allowlist-sync
	$(STATIC_ENV) $(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o bin/cf-cleanup ./cmd/cf-cleanup

test:
	$(GO) test $(GOFLAGS) ./...

fmt:
	gofmt -w $(GOFMT_FILES)

vet:
	$(GO) vet ./...

verify: fmt vet test build

clean:
	rm -rf bin
