# nftgeo build / test / packaging.
VERSION := $(shell sed -n 's/^NFTGEO_VERSION="\(.*\)"/\1/p' bin/nftgeo-update)
GO      ?= go
ARCHES  := amd64 arm64
DIST    := dist

.PHONY: all build test lint units package tarball clean
all: build

## build: cross-compile the nftgeo-ui binary for each arch into dist/
build:
	@mkdir -p $(DIST)
	@for a in $(ARCHES); do \
	  echo ">> nftgeo-ui linux/$$a"; \
	  GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "-s -w" -o $(DIST)/nftgeo-ui-linux-$$a ./ui; \
	done

## test: go vet + go test + offline render tests
test:
	$(GO) vet ./ui/
	$(GO) test ./ui/
	sh tests/render/run.sh

## lint: shellcheck the shell tools and check gofmt
lint:
	shellcheck -S warning --exclude=SC1090 bin/nftgeo-update bin/nftgeo tests/render/*.sh
	@test -z "$$(gofmt -l ui/)" || { echo "gofmt needed:"; gofmt -l ui/; exit 1; }

## units: package systemd units, rewritten to the /usr/sbin install prefix
units:
	@mkdir -p $(DIST)/units
	@for u in nftgeo.service nftgeo.timer nftgeo-ui.service; do \
	  sed 's#/usr/local/sbin#/usr/sbin#g' systemd/$$u > $(DIST)/units/$$u; \
	done

## package: build .deb and .rpm for each arch (needs nfpm)
package: build units
	@command -v nfpm >/dev/null || { echo "install nfpm: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	@for a in $(ARCHES); do \
	  cp $(DIST)/nftgeo-ui-linux-$$a $(DIST)/nftgeo-ui; \
	  for p in deb rpm; do \
	    echo ">> $$p $$a"; \
	    VERSION=$(VERSION) ARCH=$$a nfpm package -f packaging/nfpm.yaml -p $$p -t $(DIST); \
	  done; \
	done
	@rm -f $(DIST)/nftgeo-ui

## tarball: source tarball for the manual install.sh path
tarball:
	@mkdir -p $(DIST)
	@tar -czf $(DIST)/nftgeo-$(VERSION).tar.gz \
	  bin systemd etc tests install.sh uninstall.sh \
	  README.md CHANGELOG.md CHEATSHEET.md ROADMAP.md LICENSE Makefile
	@echo "wrote $(DIST)/nftgeo-$(VERSION).tar.gz"

clean:
	rm -rf $(DIST)
