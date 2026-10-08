import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:xterm/xterm.dart';

import '../../core/auth.dart';
import '../../core/native.dart';

/// Applies Ctrl to a typed character (a..z, @ [ \ ] ^ _).
List<int>? ctrlOf(String typed) {
  if (typed.length != 1) return null;
  final c = typed.toUpperCase().codeUnitAt(0);
  if (c >= 0x40 && c <= 0x5f) return [c - 0x40];
  return null;
}

/// Connection phases shown to the user (each is a distinct state).
enum Phase { connecting, choosing, attached, reconnecting, failed, revoked }

class TermState {
  const TermState({required this.phase, this.path, this.message, this.sessions = const [], this.session});
  final Phase phase;
  final String? path; // direct, turn, wss_relay
  final String? message;
  final List<Map<String, dynamic>> sessions;
  final TermSession? session;

  TermState copy({Phase? phase, String? path, String? message, List<Map<String, dynamic>>? sessions, TermSession? session}) =>
      TermState(
          phase: phase ?? this.phase,
          path: path ?? this.path,
          message: message,
          sessions: sessions ?? this.sessions,
          session: session ?? this.session);
}

/// Maps core error codes to plain-language messages.
String describeError(Object e) {
  final code = e is PlatformException ? e.code : e.toString();
  return switch (code) {
    'access_grant_missing' => 'This phone does not have access to this computer.',
    'agent_offline' => 'The computer is offline.',
    'device_revoked' => 'This phone or computer was removed.',
    'host_key_mismatch' => 'The computer\'s key changed. Do not connect: re-pair it if you expected this.',
    'session_not_found' => 'That session has ended.',
    'host_capacity_reached' => 'The computer has too many open sessions.',
    'lease_expired' => 'The computer cannot reach the server right now.',
    _ when code.contains('connect_timeout') => 'Could not reach the computer from this network.',
    _ => 'Connection failed ($code).',
  };
}

final terminalProvider = StateNotifierProvider.autoDispose.family<TermController, TermState, String>(
    (ref, hostId) => TermController(ref, hostId));

class TermController extends StateNotifier<TermState> {
  TermController(this.ref, this.hostId) : super(const TermState(phase: Phase.connecting)) {
    terminal = Terminal(maxLines: 10000, onOutput: _onTyped, onResize: _onResize);
    _sub = _core.events.listen(_onEvent);
  }

  final Ref ref;
  final String hostId;
  late final Terminal terminal;
  StreamSubscription<CoreEvent>? _sub;
  String? _sessionId; // survives reconnects
  int _cols = 80, _rows = 24;
  int _backoff = 0;
  bool _disposed = false;
  final _utf8 = const Utf8Encoder();

  NativeCore get _core => ref.read(nativeCoreProvider);

  /// Connects; [pinnedFingerprint] must have been confirmed by the user.
  Future<void> connect(String pinnedFingerprint) async {
    final auth = ref.read(authProvider.notifier);
    final s = auth.session;
    if (s == null) return;
    state = state.copy(phase: _sessionId == null ? Phase.connecting : Phase.reconnecting);
    try {
      // Make sure the access token is fresh before a long-lived connect.
      await auth.refresh();
      final fresh = auth.session ?? s;
      final path = await _core.connect(
          api: ref.read(configProvider).apiBase,
          accessToken: fresh.accessToken,
          deviceId: fresh.deviceId,
          hostId: hostId,
          pinnedFingerprint: pinnedFingerprint);
      _backoff = 0;
      if (_sessionId != null) {
        await _attach(_sessionId!, path);
        return;
      }
      final sessions = await _core.list();
      state = state.copy(phase: Phase.choosing, path: path, sessions: sessions);
    } catch (e) {
      final code = e is PlatformException ? e.code : '';
      if (code == 'device_revoked' || code == 'access_grant_missing' || code == 'host_key_mismatch') {
        state = state.copy(phase: Phase.revoked, message: describeError(e));
      } else {
        state = state.copy(phase: Phase.failed, message: describeError(e));
      }
    }
  }

  Future<void> openNew() async {
    try {
      final sess = await _core.open(_cols, _rows);
      _sessionId = sess.id;
      state = state.copy(phase: Phase.attached, session: sess);
    } catch (e) {
      state = state.copy(phase: Phase.failed, message: describeError(e));
    }
  }

  Future<void> attach(String id) => _attach(id, state.path);

  Future<void> _attach(String id, String? path) async {
    try {
      final sess = await _core.attach(id, _cols, _rows);
      _sessionId = sess.id;
      state = state.copy(phase: Phase.attached, session: sess, path: path);
    } catch (e) {
      final code = e is PlatformException ? e.code : '';
      if (code == 'session_not_found') {
        _sessionId = null;
        state = state.copy(phase: Phase.choosing, sessions: await _core.list().catchError((_) => <Map<String, dynamic>>[]), message: describeError(e));
      } else {
        state = state.copy(phase: Phase.failed, message: describeError(e));
      }
    }
  }

  /// Set by the accessory bar's sticky Ctrl; applies to the next typed key.
  bool ctrlLatch = false;
  void Function()? onCtrlConsumed;

  void _onTyped(String data) {
    if (ctrlLatch) {
      final b = ctrlOf(data);
      if (b != null) {
        ctrlLatch = false;
        onCtrlConsumed?.call();
        sendBytes(b);
        return;
      }
    }
    final s = state.session;
    // Input is frozen unless a live, attached stream exists: keystrokes are
    // never queued against a stale connection.
    if (s == null || state.phase != Phase.attached) return;
    _core.input(s.stream, _utf8.convert(data)).catchError((_) {});
  }

  /// Sends text exactly as typed or pasted (after any paste confirmation).
  void sendText(String text) => _onTyped(text);

  void sendBytes(List<int> bytes) {
    final s = state.session;
    if (s == null || state.phase != Phase.attached) return;
    _core.input(s.stream, Uint8List.fromList(bytes)).catchError((_) {});
  }

  void _onResize(int cols, int rows, int _, int _) {
    _cols = cols;
    _rows = rows;
    final s = state.session;
    if (s != null && state.phase == Phase.attached) {
      _core.resize(s.stream, cols, rows).catchError((_) {});
    }
  }

  void _onEvent(CoreEvent e) {
    if (_disposed) return;
    switch (e.kind) {
      case 'output':
        terminal.write(utf8.decode(e.data!, allowMalformed: true));
      case 'exit':
        if (e.detail == _sessionId) {
          _sessionId = null;
          terminal.write('\r\n[session ended]\r\n');
          state = state.copy(phase: Phase.choosing, session: null);
        }
      case 'revoked':
        state = state.copy(phase: Phase.revoked, message: 'Access to this computer was removed (${e.detail}).');
      case 'closed':
        if (state.phase == Phase.attached || state.phase == Phase.choosing) {
          _scheduleReconnect();
        }
    }
  }

  /// Reconnects with backoff (0.5 s .. 15 s), re-attaching the same session.
  void _scheduleReconnect() {
    state = state.copy(phase: Phase.reconnecting, message: 'Reconnecting…');
    final delays = [500, 1000, 2000, 4000, 8000, 15000];
    final d = delays[_backoff.clamp(0, delays.length - 1)];
    _backoff++;
    Timer(Duration(milliseconds: d), () async {
      if (_disposed || state.phase != Phase.reconnecting) return;
      final pin = (await ref.read(sessionStoreProvider).pins())[hostId];
      if (pin != null) await connect(pin);
    });
  }

  /// Detach (session keeps running) and leave.
  Future<void> disconnect() async {
    final s = state.session;
    if (s != null) await _core.detach(s.stream).catchError((_) {});
    await _core.close().catchError((_) {});
  }

  Future<void> terminate() async {
    final id = _sessionId;
    if (id == null) return;
    await _core.terminate(id).catchError((_) {});
  }

  @override
  void dispose() {
    _disposed = true;
    _sub?.cancel();
    _core.close().catchError((_) {});
    super.dispose();
  }
}
