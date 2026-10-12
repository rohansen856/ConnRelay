import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:connrelay/app/config.dart';
import 'package:connrelay/core/api.dart';
import 'package:connrelay/core/auth.dart';
import 'package:connrelay/core/native.dart';
import 'package:connrelay/core/session_store.dart';
import 'package:connrelay/features/terminal/terminal_controller.dart';

import 'fakes.dart';

void main() {
  late MemoryStore kv;
  late FakeCore core;
  late FakeIdTokens ids;
  final requests = <String, Map<String, dynamic>>{};

  ProviderContainer container(http.Client client) => ProviderContainer(overrides: [
        configProvider.overrideWithValue(const AppConfig(apiBase: 'https://api.test', googleServerClientId: 'web')),
        sessionStoreProvider.overrideWithValue(SessionStore(kv)),
        nativeCoreProvider.overrideWithValue(core),
        idTokenProvider.overrideWithValue(ids),
        apiProvider.overrideWithValue(ApiClient('https://api.test', httpClient: client)),
      ]);

  final server = MockClient((r) async {
    final body = r.body.isEmpty ? <String, dynamic>{} : jsonDecode(r.body) as Map<String, dynamic>;
    requests[r.url.path] = body;
    switch (r.url.path) {
      case '/v1/auth/challenge':
        return http.Response(jsonEncode({'nonce': 'server-nonce'}), 200);
      case '/v1/auth/exchange':
        return http.Response(
            jsonEncode({
              'access_token': 'a1', 'refresh_token': 'r1', 'device_id': 'phone-1',
              'account': {'id': 'acct', 'display_name': 'Owner'},
            }),
            200);
      case '/v1/auth/refresh':
        return http.Response(jsonEncode({'access_token': 'a2', 'refresh_token': 'r2', 'device_id': 'phone-1'}), 200);
    }
    return http.Response('{}', 404);
  });

  setUp(() {
    kv = MemoryStore();
    core = FakeCore();
    ids = FakeIdTokens();
    requests.clear();
  });

  test('sign-in binds the Google token, nonce and hardware key', () async {
    final c = container(server);
    final auth = c.read(authProvider.notifier);
    await auth.restore();
    expect(c.read(authProvider), isA<SignedOut>());
    await auth.signIn();
    expect(c.read(authProvider), isA<SignedIn>());
    final ex = requests['/v1/auth/exchange']!;
    expect(ex['id_token'], 'google-id-token');
    expect(ex['oidc_nonce'], ids.lastNonce, reason: 'the nonce given to Google must be sent to the server');
    expect(ex['pop'], {'nonce': 'server-nonce', 'sig': 'sig(connrelay.auth.v1,server-nonce,${'ab' * 32},)'});
    expect(ex['device']['public_key_spki'], isNotEmpty);
    expect((await SessionStore(kv).load())!.refreshToken, 'r1');

    // Refresh is device-bound and stores the rotated token.
    expect(await auth.refresh(), isTrue);
    expect(requests['/v1/auth/refresh']!['pop']['sig'], 'sig(connrelay.refresh.v1,server-nonce,,phone-1)');
    expect((await SessionStore(kv).load())!.refreshToken, 'r2');
  });

  test('a disallowed account gets a clear message', () async {
    final c = container(MockClient((r) async => r.url.path == '/v1/auth/challenge'
        ? http.Response(jsonEncode({'nonce': 'n'}), 200)
        : http.Response(jsonEncode({'error': {'code': 'account_not_allowed', 'message': 'x'}}), 403)));
    await c.read(authProvider.notifier).signIn();
    final st = c.read(authProvider) as SignedOut;
    expect(st.error, contains('not allowed'));
  });

  test('terminal: connect, open, type, lose the connection, re-attach the same session', () async {
    final c = container(server);
    await c.read(authProvider.notifier).signIn();
    await SessionStore(kv).pin('host-1', 'cd' * 32);
    final sub = c.listen(terminalProvider('host-1'), (_, _) {});
    final t = c.read(terminalProvider('host-1').notifier);

    await t.connect('cd' * 32);
    expect(core.calls.first, 'connect:host-1:${'cd' * 32}');
    expect(c.read(terminalProvider('host-1')).phase, Phase.choosing);

    await t.openNew();
    expect(c.read(terminalProvider('host-1')).phase, Phase.attached);
    t.terminal.textInput('ls\r');
    await Future<void>.delayed(Duration.zero);
    expect(core.inputs, ['ls\r']);

    core.ctrl.add(CoreEvent.output(1, Uint8List.fromList(utf8.encode('hello\r\n'))));
    await Future<void>.delayed(Duration.zero);
    expect(t.terminal.buffer.lines[0].toString().trim(), 'hello');

    // Transport loss: input freezes, then reconnect re-attaches the session.
    core.ctrl.add(CoreEvent.event('closed', 'eof'));
    await Future<void>.delayed(Duration.zero);
    expect(c.read(terminalProvider('host-1')).phase, Phase.reconnecting);
    t.terminal.textInput('dropped');
    expect(core.inputs, ['ls\r'], reason: 'no input while reconnecting');
    await Future<void>.delayed(const Duration(milliseconds: 700));
    expect(core.calls, contains('attach:s-new'));
    expect(c.read(terminalProvider('host-1')).phase, Phase.attached);
    sub.close();
  });

  test('terminal: a revoked grant stops retrying', () async {
    final c = container(server);
    await c.read(authProvider.notifier).signIn();
    core.connectError = PlatformException(code: 'access_grant_missing');
    final sub = c.listen(terminalProvider('h'), (_, _) {});
    await c.read(terminalProvider('h').notifier).connect('x');
    final st = c.read(terminalProvider('h'));
    expect(st.phase, Phase.revoked);
    expect(st.message, contains('does not have access'));
    sub.close();
  });
}
