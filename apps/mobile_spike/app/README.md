# PRW transport spike app

Throwaway Flutter app for Phase 1 spikes S1 (shared Go core on the phone via
gomobile) and S6 (hardware-backed device key). Not the product app.

```sh
../build-aar.sh                                   # gomobile AAR -> ../android-libs/
flutter build apk --release --target-platform android-arm64
adb install -r build/app/outputs/flutter-apk/app-release.apk
LAN_IP=<this machine> ../../../tests/devicelab/run.sh
```
