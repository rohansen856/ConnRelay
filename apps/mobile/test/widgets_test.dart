import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:prw/app/app.dart';
import 'package:prw/app/config.dart';
import 'package:prw/core/api.dart';
import 'package:prw/core/auth.dart';
import 'package:prw/core/session_store.dart';

import 'fakes.dart';

Map<String, dynamic> host(String id, String name, String presence, {bool granted = true}) => {
      'id': id, 'kind': 'host', 'platform': 'linux', 'display_name': name, 'key_fingerprint': 'ab' * 32,
      'presence': presence, 'admin_state': 'active', 'last_seen_at': DateTime.now().toIso8601String(), 'version': 1,
      'my_grant': granted ? {'id': 'g-$id', 'phone_device_id': 'p', 'host_device_id': id, 'version': 1} : null,
    };

Widget app(MemoryStore kv, List<Map<String, dynamic>> devices) => ProviderScope(overrides: [
      configProvider.overrideWithValue(const AppConfig(apiBase: 'https://api.test', googleServerClientId: 'web')),
      sessionStoreProvider.overrideWithValue(SessionStore(kv)),
      nativeCoreProvider.overrideWithValue(FakeCore()),
      idTokenProvider.overrideWithValue(FakeIdTokens()),
      apiProvider.overrideWithValue(ApiClient('https://api.test',
          httpClient: MockClient((r) async => http.Response(jsonEncode({'items': devices, 'next_cursor': null}), 200)))),
    ], child: const PrwApp());

void main() {
  testWidgets('signed out: only the sign-in screen is reachable', (t) async {
    await t.pumpWidget(app(MemoryStore(), []));
    await t.pumpAndSettle();
    expect(find.text('Sign in with Google'), findsOneWidget);
    expect(find.text('Computers'), findsNothing);
  });

  testWidgets('devices: status words, connect only when online and granted', (t) async {
    final kv = MemoryStore();
    await SessionStore(kv).save(Session(accountId: 'a', deviceId: 'p', accessToken: 't', refreshToken: 'r'));
    await t.pumpWidget(app(kv, [
      host('h1', 'workstation', 'online'),
      host('h2', 'laptop', 'offline'),
      host('h3', 'server', 'online', granted: false),
    ]));
    await t.pumpAndSettle();
    expect(find.text('workstation'), findsOneWidget);
    expect(find.text('Online'), findsNWidgets(2));
    expect(find.text('Offline'), findsOneWidget);
    expect(find.widgetWithText(FilledButton, 'Connect'), findsNWidgets(2)); // the ungranted host shows a lock
    FilledButton connectFor(String name) => t.widget<FilledButton>(find.descendant(
        of: find.ancestor(of: find.text(name), matching: find.byType(ListTile)),
        matching: find.widgetWithText(FilledButton, 'Connect')));
    expect(connectFor('workstation').onPressed, isNotNull);
    expect(connectFor('laptop').onPressed, isNull, reason: 'offline host');
    expect(find.byIcon(Icons.lock_outline), findsOneWidget);
  });

  testWidgets('devices: empty state explains pairing', (t) async {
    final kv = MemoryStore();
    await SessionStore(kv).save(Session(accountId: 'a', deviceId: 'p', accessToken: 't', refreshToken: 'r'));
    await t.pumpWidget(app(kv, []));
    await t.pumpAndSettle();
    expect(find.text('Add your first computer'), findsOneWidget);
    expect(find.textContaining('prw-agent pair'), findsOneWidget);
  });
}
