import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:connrelay/core/auth.dart';
import 'package:connrelay/core/native.dart';
import 'package:connrelay/core/session_store.dart';

class MemoryStore implements KeyValueStore {
  final m = <String, String>{};
  @override
  Future<String?> read(String key) async => m[key];
  @override
  Future<void> write(String key, String value) async => m[key] = value;
  @override
  Future<void> delete(String key) async => m.remove(key);
}

class FakeIdTokens implements IdTokenProvider {
  String? lastNonce;
  @override
  Future<String> idToken(String nonce) async {
    lastNonce = nonce;
    return 'google-id-token';
  }

  @override
  Future<void> signOut() async {}
}

/// Scriptable stand-in for the Go core.
class FakeCore implements NativeCore {
  final calls = <String>[];
  final ctrl = StreamController<CoreEvent>.broadcast();
  Object? connectError;
  List<Map<String, dynamic>> sessions = [];
  int nextStream = 1;
  final inputs = <String>[];

  @override
  Stream<CoreEvent> get events => ctrl.stream;
  @override
  Future<Uint8List> publicKey() async => Uint8List.fromList(List.filled(91, 7));
  @override
  Future<String> fingerprint(Uint8List spki) async => 'ab' * 32;
  @override
  Future<String> signPoP(String purpose, String nonce, {String spkiFp = '', String deviceId = ''}) async =>
      'sig($purpose,$nonce,$spkiFp,$deviceId)';
  @override
  Future<String> connect({required String api, required String accessToken, required String deviceId,
      required String hostId, required String pinnedFingerprint, String mode = 'auto'}) async {
    calls.add('connect:$hostId:$pinnedFingerprint');
    if (connectError != null) throw connectError!;
    return 'direct';
  }

  TermSession _sess(String id, bool resumed) =>
      TermSession.fromJson({'terminal_session_id': id, 'stream_id': nextStream++, 'persistent': true, 'resumed': resumed});
  @override
  Future<TermSession> open(int cols, int rows) async {
    calls.add('open:${cols}x$rows');
    return _sess('s-new', false);
  }

  @override
  Future<TermSession> attach(String id, int cols, int rows) async {
    calls.add('attach:$id');
    if (!sessions.any((s) => s['id'] == id) && id != 's-new') {
      throw PlatformException(code: 'session_not_found');
    }
    return _sess(id, true);
  }

  @override
  Future<List<Map<String, dynamic>>> list() async => sessions;
  @override
  Future<void> input(int stream, Uint8List data) async => inputs.add(utf8.decode(data));
  @override
  Future<void> resize(int stream, int cols, int rows) async => calls.add('resize:${cols}x$rows');
  @override
  Future<void> detach(int stream) async => calls.add('detach:$stream');
  @override
  Future<void> terminate(String id) async => calls.add('terminate:$id');
  @override
  Future<void> close() async => calls.add('close');
}
