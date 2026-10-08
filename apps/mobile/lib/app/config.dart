/// Build-time configuration, passed with --dart-define:
///
///   flutter run --dart-define=PRW_API=https://api.example.invalid \
///               --dart-define=PRW_GOOGLE_SERVER_CLIENT_ID=xxxx.apps.googleusercontent.com
class AppConfig {
  const AppConfig({required this.apiBase, required this.googleServerClientId});

  /// Control plane base URL, without a trailing slash.
  final String apiBase;

  /// OAuth "Web" client ID of the control plane; Google issues the ID token
  /// to this audience.
  final String googleServerClientId;

  static AppConfig fromEnvironment() => const AppConfig(
        apiBase: String.fromEnvironment('PRW_API', defaultValue: 'https://api.example.invalid'),
        googleServerClientId: String.fromEnvironment('PRW_GOOGLE_SERVER_CLIENT_ID'),
      );
}
