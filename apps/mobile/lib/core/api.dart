import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

/// An error response from the control plane (API error envelope).
class ApiException implements Exception {
  ApiException(this.status, this.code, this.message, {this.retryable = false, this.requestId});

  final int status;
  final String code;
  final String message;
  final bool retryable;
  final String? requestId;

  @override
  String toString() => 'ApiException($status $code)';
}

/// Supplies and refreshes the access token.
abstract class TokenSource {
  String? get accessToken;

  /// Refreshes tokens; returns false if the user must sign in again.
  Future<bool> refresh();
}

/// JSON client for the control plane REST API.
class ApiClient {
  ApiClient(this.base, {http.Client? httpClient, this.tokens}) : _http = httpClient ?? http.Client();

  final String base;
  final http.Client _http;
  TokenSource? tokens;

  static String newIdempotencyKey() {
    final r = Random.secure();
    return List.generate(24, (_) => r.nextInt(16).toRadixString(16)).join();
  }

  Future<Map<String, dynamic>> get(String path) => _send('GET', path);
  Future<Map<String, dynamic>> post(String path, [Object? body, Map<String, String>? headers]) =>
      _send('POST', path, body: body, headers: headers);
  Future<Map<String, dynamic>> patch(String path, Object? body, {Map<String, String>? headers}) =>
      _send('PATCH', path, body: body, headers: headers);

  Future<Map<String, dynamic>> _send(String method, String path,
      {Object? body, Map<String, String>? headers, bool retried = false}) async {
    final req = http.Request(method, Uri.parse('$base$path'));
    req.headers['Content-Type'] = 'application/json';
    final token = tokens?.accessToken;
    if (token != null) req.headers['Authorization'] = 'Bearer $token';
    if (headers != null) req.headers.addAll(headers);
    if (body != null) req.body = jsonEncode(body);
    final resp = await http.Response.fromStream(await _http.send(req).timeout(const Duration(seconds: 30)));
    final decoded = resp.body.isEmpty ? <String, dynamic>{} : jsonDecode(resp.body);
    final json = decoded is Map<String, dynamic> ? decoded : <String, dynamic>{};
    if (resp.statusCode < 300) return json;

    final err = (json['error'] as Map<String, dynamic>?) ?? const {};
    final code = err['code'] as String? ?? 'http_${resp.statusCode}';
    // An expired access token: refresh once, then retry once.
    if (resp.statusCode == 401 && code == 'unauthenticated' && !retried && tokens != null && path != '/v1/auth/refresh') {
      if (await tokens!.refresh()) {
        return _send(method, path, body: body, headers: headers, retried: true);
      }
    }
    throw ApiException(resp.statusCode, code, err['message'] as String? ?? 'Request failed.',
        retryable: err['retryable'] as bool? ?? false, requestId: err['request_id'] as String?);
  }
}

/// A device as returned by GET /v1/devices.
class Device {
  Device.fromJson(Map<String, dynamic> j)
      : id = j['id'] as String,
        kind = j['kind'] as String,
        platform = j['platform'] as String,
        name = j['display_name'] as String,
        fingerprint = j['key_fingerprint'] as String,
        presence = j['presence'] as String? ?? 'unknown',
        adminState = j['admin_state'] as String,
        lastSeen = j['last_seen_at'] == null ? null : DateTime.parse(j['last_seen_at'] as String),
        version = j['version'] as int? ?? 1,
        softwareVersion = j['software_version'] as String?,
        myGrant = j['my_grant'] == null ? null : Grant.fromJson(j['my_grant'] as Map<String, dynamic>);

  final String id, kind, platform, name, fingerprint, presence, adminState;
  final DateTime? lastSeen;
  final int version;
  final String? softwareVersion;
  final Grant? myGrant;

  bool get isHost => kind == 'host';
  bool get revoked => adminState == 'revoked';
}

/// An access grant.
class Grant {
  Grant.fromJson(Map<String, dynamic> j)
      : id = j['id'] as String,
        phone = j['phone_device_id'] as String,
        host = j['host_device_id'] as String,
        version = j['version'] as int? ?? 1,
        revokedAt = j['revoked_at'] == null ? null : DateTime.parse(j['revoked_at'] as String);

  final String id, phone, host;
  final int version;
  final DateTime? revokedAt;
}
