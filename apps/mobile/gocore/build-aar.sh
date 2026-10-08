#!/usr/bin/env bash
# Build the shared Go core as an Android AAR for the app.
# Output: apps/mobile/android/app/libs/prwcore.aar (gitignored).
#
# -checklinkname=0: github.com/wlynxg/anet (Pion's Android interface
# enumeration) links against a net package internal.
set -euo pipefail
cd "$(dirname "$0")"
export GOWORK=off GOFLAGS=
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
export ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}
command -v gomobile >/dev/null || go install golang.org/x/mobile/cmd/gomobile@latest
export PATH=$PATH:$(go env GOPATH)/bin
mkdir -p ../android/app/libs
gomobile bind -target=android/arm64,android/amd64 -androidapi 26 -javapkg dev.prw.core \
  -ldflags="-checklinkname=0 -s -w" -trimpath -o ../android/app/libs/prwcore.aar \
  github.com/rohansen856/connrelay/core/prwcore/mobile
ls -l ../android/app/libs/prwcore.aar
