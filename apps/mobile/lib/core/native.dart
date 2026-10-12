import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';

/// Output or lifecycle event from the Go core.
class CoreEvent {
  CoreEvent.output(this.stream, this.data)
      : kind = 'output',
        detail = '';
  CoreEvent.event(this.kind, this.detail)
      : stream = 0,
        data = null;

  final String kind; // output, exit, revoked, closed
  final String detail;
  final int stream;
  final Uint8List? data;
}

/// A terminal session description from Open/Attach.
class TermSession {
  TermSession.fromJson(Map<String, dynamic> j)
      : id = j['terminal_session_id'] as String,
        stream = j['stream_id'] as int,
        persistent = j['persistent'] as bool? ?? false,
        resumed = j['resumed'] as bool? ?? false;

  final String id;
  final int stream;
  final bool persistent, resumed;
}

/// Bridge to the platform: the hardware device key and the Go core (gomobile).
abstract class NativeCore {
  /// DER SubjectPublicKeyInfo of the device key (created on first use).
  Future<Uint8List> publicKey();

  /// Proof of possession: purpose connrelay.auth.v1 (with spkiFp) or connrelay.refresh.v1
  /// (with deviceId).
  Future<String> signPoP(String purpose, String nonce, {String spkiFp = '', String deviceId = ''});

  /// SHA-256 fingerprint (hex) of an SPKI.
  Future<String> fingerprint(Uint8List spki);

  /// Connects to a host; returns the path ("direct", "turn", "wss_relay").
  Future<String> connect({required String api, required String accessToken, required String deviceId,
      required String hostId, required String pinnedFingerprint, String mode = 'auto'});
  Future<TermSession> open(int cols, int rows);
  Future<TermSession> attach(String id, int cols, int rows);
  Future<List<Map<String, dynamic>>> list();
  Future<void> input(int stream, Uint8List data);
  Future<void> resize(int stream, int cols, int rows);
  Future<void> detach(int stream);
  Future<void> terminate(String id);
  Future<void> close();

  Stream<CoreEvent> get events;
}

/// MethodChannel implementation (Android: MainActivity.kt).
class ChannelCore implements NativeCore {
  ChannelCore() {
    _events.receiveBroadcastStream().listen((e) {
      final m = (e as Map).cast<String, dynamic>();
      if (m['kind'] == 'output') {
        _ctrl.add(CoreEvent.output(m['stream'] as int, m['data'] as Uint8List));
      } else {
        _ctrl.add(CoreEvent.event(m['kind'] as String, m['detail'] as String? ?? ''));
      }
    });
  }

  static const _m = MethodChannel('connrelay/core');
  static const _events = EventChannel('connrelay/core/events');
  final _ctrl = StreamController<CoreEvent>.broadcast();

  @override
  Stream<CoreEvent> get events => _ctrl.stream;

  @override
  Future<Uint8List> publicKey() async => (await _m.invokeMethod<Uint8List>('publicKey'))!;

  @override
  Future<String> signPoP(String purpose, String nonce, {String spkiFp = '', String deviceId = ''}) async =>
      (await _m.invokeMethod<String>('signPoP', {'purpose': purpose, 'nonce': nonce, 'spkiFp': spkiFp, 'deviceId': deviceId}))!;

  @override
  Future<String> fingerprint(Uint8List spki) async => (await _m.invokeMethod<String>('fingerprint', {'spki': spki}))!;

  @override
  Future<String> connect({required String api, required String accessToken, required String deviceId,
          required String hostId, required String pinnedFingerprint, String mode = 'auto'}) async =>
      (await _m.invokeMethod<String>('connect', {
        'api': api, 'accessToken': accessToken, 'deviceId': deviceId, 'hostId': hostId,
        'pinnedFp': pinnedFingerprint, 'mode': mode,
      }))!;

  @override
  Future<TermSession> open(int cols, int rows) async =>
      TermSession.fromJson(jsonDecode((await _m.invokeMethod<String>('open', {'cols': cols, 'rows': rows}))!) as Map<String, dynamic>);

  @override
  Future<TermSession> attach(String id, int cols, int rows) async => TermSession.fromJson(
      jsonDecode((await _m.invokeMethod<String>('attach', {'id': id, 'cols': cols, 'rows': rows}))!) as Map<String, dynamic>);

  @override
  Future<List<Map<String, dynamic>>> list() async {
    final raw = await _m.invokeMethod<String>('list');
    final decoded = jsonDecode(raw ?? 'null');
    return decoded == null ? [] : (decoded as List).cast<Map<String, dynamic>>();
  }

  @override
  Future<void> input(int stream, Uint8List data) => _m.invokeMethod('input', {'stream': stream, 'data': data});

  @override
  Future<void> resize(int stream, int cols, int rows) => _m.invokeMethod('resize', {'stream': stream, 'cols': cols, 'rows': rows});

  @override
  Future<void> detach(int stream) => _m.invokeMethod('detach', {'stream': stream});

  @override
  Future<void> terminate(String id) => _m.invokeMethod('terminate', {'id': id});

  @override
  Future<void> close() => _m.invokeMethod('close');
}
