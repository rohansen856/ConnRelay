# Private Remote Workspace: developer entry points.
# Go modules are listed in go.work; the mobile spike probe builds separately
# with GOWORK=off (see apps/mobile_spike/build-aar.sh).

GO      ?= go
FLUTTER ?= flutter
MODULES := core/prwcore services/control agents/host tests
# The toolchain is pinned by the toolchain line in go.mod (GOTOOLCHAIN=auto).

.PHONY: all fmt vet test test-race test-short spike-app netlab spike-s4 devicelab aar ci

all: vet test

fmt:
	gofmt -w $(MODULES)

vet:
	@for m in $(MODULES); do (cd $$m && $(GO) vet ./...) || exit 1; done

test:
	@for m in $(MODULES); do (cd $$m && $(GO) test ./...) || exit 1; done

test-race:
	@for m in $(MODULES); do (cd $$m && $(GO) test -race ./...) || exit 1; done

test-short:
	@for m in $(MODULES); do (cd $$m && $(GO) test -short ./...) || exit 1; done

spike-app:
	cd apps/mobile_spike/app && $(FLUTTER) analyze && $(FLUTTER) test

# Docker network lab: NAT types, TURN/UDP/TCP/TLS-443, HTTPS-proxy-only (S2/S3).
netlab:
	tests/netlab/run.sh

# tmux survives an agent restart under systemd --user (S4).
spike-s4:
	tests/spikes/s4_systemd_restart.sh

# Real Android phone over adb (S1/S6). Set LAN_IP to this machine's address.
devicelab:
	tests/devicelab/run.sh

aar:
	apps/mobile_spike/build-aar.sh

ci: vet test-race spike-app
