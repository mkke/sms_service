GO ?= go
GOMAKE ?= gomake
FREEBSDPKGCTL ?= freebsdpkgctl

GITINFO := $(shell git rev-parse --short=8 HEAD)

PLUGIN := opnsense/comms/sms_service
PLUGIN_VERSION := $(shell sed -n 's/^PLUGIN_VERSION=[[:space:]]*//p' $(PLUGIN)/Makefile)
PLUGIN_FILES := $(shell find $(PLUGIN) -type f)
PACKAGE := build/os-sms_service-$(PLUGIN_VERSION).pkg

.DELETE_ON_ERROR:

sms_service:
	@echo [go build] $@ for freebsd/amd64
	@CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 $(GO) build -o $@ -ldflags="-X main.GitInfo=$(GITINFO)" .

plugin: $(PACKAGE)

$(PACKAGE): sms_service $(PLUGIN_FILES)
	@echo [freebsdpkgctl plugin lint] $(PLUGIN)
	@$(FREEBSDPKGCTL) plugin lint $(PLUGIN)
	@echo [freebsdpkgctl plugin build] $@
	@$(FREEBSDPKGCTL) plugin build $(PLUGIN) --add /usr/local/bin/sms_service=sms_service --hash $(shell git rev-parse --short=9 HEAD) --tree $(shell git rev-parse 'HEAD^{tree}') --output build

clean:
	rm -rf sms_service build .depends .gomake

.depends: FORCE
	@$(GOMAKE) deps -o $@ sms_service=.:goos=freebsd:goarch=amd64
-include .depends
FORCE:

.PHONY: plugin clean FORCE
