import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Signed-in session data kept in the platform secure store (Keystore /
/// Keychain backed). The device private key is not here: it never leaves the
/// hardware keystore.
class Session {
  Session({required this.accountId, required this.deviceId, required this.accessToken, required this.refreshToken, this.displayName = ''});

  final String accountId, deviceId, displayName;
  String accessToken, refreshToken;

  Map<String, dynamic> toJson() =>
      {'account_id': accountId, 'device_id': deviceId, 'access': accessToken, 'refresh': refreshToken, 'name': displayName};

  static Session fromJson(Map<String, dynamic> j) => Session(
      accountId: j['account_id'] as String,
      deviceId: j['device_id'] as String,
      accessToken: j['access'] as String,
      refreshToken: j['refresh'] as String,
      displayName: j['name'] as String? ?? '');
}

/// Storage abstraction (fake in tests).
abstract class KeyValueStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

class SecureStore implements KeyValueStore {
  const SecureStore();
  static const _s = FlutterSecureStorage();
  @override
  Future<String?> read(String key) => _s.read(key: key);
  @override
  Future<void> write(String key, String value) => _s.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _s.delete(key: key);
}

class SessionStore {
  SessionStore(this._kv);
  final KeyValueStore _kv;

  Future<Session?> load() async {
    final raw = await _kv.read('session');
    if (raw == null) return null;
    try {
      return Session.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  Future<void> save(Session s) => _kv.write('session', jsonEncode(s.toJson()));
  Future<void> clear() => _kv.delete('session');

  /// Host key fingerprints confirmed by the user (pairing or first connect).
  /// Connecting refuses any host whose key does not match its pin.
  Future<Map<String, String>> pins() async {
    final raw = await _kv.read('host_pins');
    return raw == null ? {} : (jsonDecode(raw) as Map<String, dynamic>).cast<String, String>();
  }

  Future<void> pin(String hostId, String fingerprint) async {
    final p = await pins();
    p[hostId] = fingerprint;
    await _kv.write('host_pins', jsonEncode(p));
  }
}
