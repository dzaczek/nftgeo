# nftgeo build / test / packaging.
VERSION := $(shell sed -n 's/^NFTGEO_VERSION="\(.*\)"/\1/p' bin/nftgeo-update)
GO      ?= go
ARCHES  := amd64 arm64
DIST    := dist

.PHONY: all build test lint units manpages package tarball clean
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
	sh tests/migrate/run.sh
	sh tests/man/run.sh

## lint: shellcheck the shell tools and check gofmt
lint:
	shellcheck -S warning --exclude=SC1090 bin/nftgeo-update bin/nftgeo tests/render/*.sh tests/migrate/*.sh tests/man/*.sh
	@test -z "$$(gofmt -l ui/)" || { echo "gofmt needed:"; gofmt -l ui/; exit 1; }

## units: stage systemd units for packaging (source already uses /usr/sbin; the
## sed keeps any stray /usr/local/sbin reference correct for the package)
units:
	@mkdir -p $(DIST)/units
	@for u in nftgeo.service nftgeo.timer nftgeo-ui.service; do \
	  sed 's#/usr/local/sbin#/usr/sbin#g' systemd/$$u > $(DIST)/units/$$u; \
	done

## manpages: compress package manual pages without modifying their sources
manpages:
	@mkdir -p $(DIST)/man
	@for page in man/*.[1-9]; do \
	  gzip -9 -n -c "$$page" > "$(DIST)/man/$$(basename "$$page").gz"; \
	done

## package: build .deb and .rpm for each arch (needs nfpm)
package: build units manpages
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
	  bin systemd etc man examples tests install.sh uninstall.sh \
	  docs README.md CHANGELOG.md CHEATSHEET.md ROADMAP.md TESTING.md \
	  TESTING_PL.md TEST_REQUEST.md TEST_REQUEST_PL.md CONTRIBUTING.md \
	  CONTRIBUTING_PL.md LICENSE Makefile
	@echo "wrote $(DIST)/nftgeo-$(VERSION).tar.gz"

clean:
	rm -rf $(DIST)
