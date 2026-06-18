#!/usr/bin/env bash
# Build the gomobile AAR for the spike app (Android arm64).
#
# x/mobile requires Go >= 1.26, so this module is built outside the main Go
# workspace with its own toolchain. -checklinkname=0 is needed because
# github.com/wlynxg/anet (used by Pion for Android interface enumeration)
# links against a net package internal.
set -euo pipefail
cd "$(dirname "$0")/probe"
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.26.0} GOWORK=off GOFLAGS=
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
export ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}
command -v gomobile >/dev/null || go install golang.org/x/mobile/cmd/gomobile@latest golang.org/x/mobile/cmd/gobind@latest
export PATH=$PATH:$(go env GOPATH)/bin
mkdir -p ../android-libs
gomobile bind -target=android/arm64 -androidapi 26 -javapkg dev.prw.spike \
  -ldflags="-checklinkname=0 -s -w" -trimpath -o ../android-libs/prwprobe.aar .
ls -l ../android-libs/prwprobe.aar
