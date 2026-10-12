# ConnRelay phone app (Flutter)

The phone side of ConnRelay: Google sign-in, device inventory,
host pairing (QR or code), access grants and the terminal. All networking to
computers goes through the shared Go core (`core/connrelaycore/mobile`, bound with
gomobile); the device key lives in the Android Keystore / iOS Secure Enclave.

```sh
flutter pub get
flutter analyze && flutter test
flutter run \
  --dart-define=CONNRELAY_API=https://api.example.invalid \
  --dart-define=CONNRELAY_GOOGLE_SERVER_CLIENT_ID=<web client id>.apps.googleusercontent.com
```

`third_party/xterm` is a vendored fork of xterm.dart 4.0.0 with two fixes
found in spike S5 (see its CHANGELOG). `test/fixtures/` (gitignored) holds
recorded TUI streams for `test/xterm_tui_test.dart`; record them with
`tests/spikes/s5_capture_tui.sh`.
