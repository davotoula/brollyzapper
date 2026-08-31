# BrollyZapper
#
# Tool versions are pinned here rather than in go.mod: they are code-generation
# tools, not build or runtime dependencies, and keeping them out of the module
# graph is the point of ADR 0001.
BUF_VERSION               ?= v1.72.0
PROTOC_GEN_GO_VERSION     ?= v1.36.12
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2
GOVULNCHECK_VERSION       ?= v1.7.0
# How long the gate fuzzes. Short on purpose: this runs on every push, and the
# job of a gate-length fuzz run is to re-exercise the corpus and catch a crasher
# that a change just made reachable — not to search. Raise it by hand
# (FUZZTIME=5m make fuzz) when hunting.
FUZZTIME                  ?= 10s
VERSION                   ?= dev
REGISTRY                  ?= ghcr.io/davotoula

GOBIN ?= $(shell go env GOPATH)/bin

.PHONY: all build test vet check cross vuln fuzz proto proto-tools docker release clean

all: check

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

# The one fuzz target, on the app's principal untrusted-input surface: a zap
# request is hex, JSON, tags and a signature, arriving from anyone on the
# internet over the public route group.
#
# go test fuzzes ONE target per invocation, so it is named here rather than
# discovered. `-run ^$` keeps this to fuzzing: the ordinary tests are the `test`
# target's job and running them twice slows the gate for nothing.
fuzz:
	go test -run '^$$' -fuzz FuzzParseZapRequest -fuzztime $(FUZZTIME) ./internal/lnurl/

check: build vet test

# Proves both binaries build for both target platforms without cgo, which is
# what gcr.io/distroless/static requires. This is the part of the Docker
# acceptance that does not need a running daemon.
cross:
	@for os_arch in linux/amd64 linux/arm64; do \
		os=$${os_arch%/*}; arch=$${os_arch#*/}; \
		for cmd in brollyzapper brollyguard; do \
			echo "==> $$cmd $$os/$$arch"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
				go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
				-o /dev/null ./cmd/$$cmd || exit 1; \
		done; \
	done

# The gate's supply-chain half. govulncheck reports only vulnerabilities in code
# paths this module actually reaches, so a finding here is a finding about us
# rather than about the dependency tree — and with the Docker base images now
# pinned by digest, an upstream Go patch no longer arrives on its own, which
# makes this the thing that says one is needed (review L12).
#
# The version is pinned here, once, and ci.yml runs this target rather than
# repeating the command: a CI and a local gate that state the same version
# separately are two statements of one fact, and they drift.
vuln:
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GOBIN)/govulncheck ./...

proto-tools:
	go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

# Regenerates internal/lnd/lnrpc from the vendored protos in proto/. The
# generated files are committed; run this only when the pinned LND version in
# proto/lnrpc/README.md changes.
proto: proto-tools
	PATH="$(GOBIN):$$PATH" buf generate

docker:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) -f Dockerfile.server -t brollyzapper-server:$(VERSION) .
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) -f Dockerfile.guard -t brollyzapper-guard:$(VERSION) .

# Publishes the images the Umbrel package pins. It refuses to run without an
# explicit VERSION: .dockerignore excludes .git, so the Go toolchain embeds no
# VCS revision, and an image built with the default would report bare "dev" and
# be unable to say what it was built from.
release:
ifeq ($(VERSION),dev)
	$(error set VERSION, e.g. make release VERSION=0.1.0 REGISTRY=ghcr.io/davotoula — \
	  a release image must be able to say what it was built from)
endif
	docker buildx build --platform linux/amd64,linux/arm64 --push \
		--build-arg VERSION=$(VERSION) -f Dockerfile.server \
		-t $(REGISTRY)/brollyzapper:$(VERSION) .
	docker buildx build --platform linux/amd64,linux/arm64 --push \
		--build-arg VERSION=$(VERSION) -f Dockerfile.guard \
		-t $(REGISTRY)/brollyzapper-guard:$(VERSION) .
	@echo "Now pin the index digests in umbrel/brollyzapper/docker-compose.yml:"
	docker buildx imagetools inspect $(REGISTRY)/brollyzapper:$(VERSION) --format '{{.Manifest.Digest}}'
	docker buildx imagetools inspect $(REGISTRY)/brollyzapper-guard:$(VERSION) --format '{{.Manifest.Digest}}'

clean:
	go clean -cache -testcache

# Refuses private material in the tracked tree; see scripts/public-scan.sh.
# Part of the CI gate, and worth running before any push.
public-scan:
	sh scripts/public-scan.sh
