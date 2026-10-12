import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:connrelay/app/app.dart';
import 'package:connrelay/app/config.dart';
import 'package:connrelay/core/api.dart';
import 'package:connrelay/features/devices/devices_providers.dart' show devicesPollInterval;
import 'package:connrelay/core/auth.dart';
import 'package:connrelay/core/session_store.dart';

import 'fakes.dart';

Map<String, dynamic> host(String id, String name, String presence, {bool granted = true}) => {
  'id': id,
  'kind': 'host',
  'platform': 'linux',
  'display_name': name,
  'key_fingerprint': 'ab' * 32,
  'presence': presence,
  'admin_state': 'active',
  'last_seen_at': DateTime.now().toIso8601String(),
  'version': 1,
  'my_grant': granted ? {'id': 'g-$id', 'phone_device_id': 'p', 'host_device_id': id, 'version': 1} : null,
};

/// [onFetch] runs on every API call; a non-null response replaces the default.
Widget app(MemoryStore kv, List<Map<String, dynamic>> devices, {http.Response? Function()? onFetch}) => ProviderScope(
  overrides: [
    configProvider.overrideWithValue(const AppConfig(apiBase: 'https://api.test', googleServerClientId: 'web')),
    sessionStoreProvider.overrideWithValue(SessionStore(kv)),
    nativeCoreProvider.overrideWithValue(FakeCore()),
    idTokenProvider.overrideWithValue(FakeIdTokens()),
    apiProvider.overrideWithValue(
      ApiClient(
        'https://api.test',
        httpClient: MockClient((r) async {
          return onFetch?.call() ?? http.Response(jsonEncode({'items': devices, 'next_cursor': null}), 200);
        }),
      ),
    ),
  ],
  child: const ConnRelayApp(),
);

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
    await t.pumpWidget(
      app(kv, [
        host('h1', 'workstation', 'online'),
        host('h2', 'laptop', 'offline'),
        host('h3', 'server', 'online', granted: false),
      ]),
    );
    await t.pumpAndSettle();
    expect(find.text('workstation'), findsOneWidget);
    expect(find.text('Online'), findsNWidgets(2));
    expect(find.text('Offline'), findsOneWidget);
    expect(find.widgetWithText(FilledButton, 'Connect'), findsNWidgets(2)); // the ungranted host shows a lock
    FilledButton connectFor(String name) => t.widget<FilledButton>(
      find.descendant(
        of: find.ancestor(of: find.text(name), matching: find.byType(ListTile)),
        matching: find.widgetWithText(FilledButton, 'Connect'),
      ),
    );
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
    expect(find.textContaining('connrelay-agent pair'), findsOneWidget);
  });

  testWidgets('devices: pull to refresh works for short, empty and failed lists', (t) async {
    // A tall phone screen (1080x2392 at 2.75x), where a short list leaves
    // most of the viewport empty.
    t.view.physicalSize = const Size(1080, 2392);
    t.view.devicePixelRatio = 2.75;
    addTearDown(t.view.reset);
    for (final (devices, failFirst) in [
      (<Map<String, dynamic>>[], false),
      ([host('h1', 'workstation', 'online')], false),
      ([host('h1', 'workstation', 'online')], true), // first load fails: the error view must be pullable
    ]) {
      final kv = MemoryStore();
      await SessionStore(kv).save(Session(accountId: 'a', deviceId: 'p', accessToken: 't', refreshToken: 'r'));
      var fetches = 0;
      await t.pumpWidget(
        app(
          kv,
          devices,
          onFetch: () {
            fetches++;
            return failFirst && fetches == 1
                ? http.Response(jsonEncode({'code': 'unavailable', 'message': 'down'}), 503)
                : null;
          },
        ),
      );
      await t.pumpAndSettle();
      final before = fetches;
      // A slow pull from near the top of the list, like a finger.
      final g = await t.startGesture(t.getTopLeft(find.byType(Scrollable).first) + const Offset(150, 40));
      for (var i = 0; i < 20; i++) {
        await g.moveBy(const Offset(0, 20));
        await t.pump(const Duration(milliseconds: 16));
      }
      await g.up();
      await t.pumpAndSettle();
      expect(
        fetches,
        greaterThan(before),
        reason: 'pull did not refetch (${devices.length} devices, failFirst=$failFirst)',
      );
      if (devices.isNotEmpty) expect(find.text('workstation'), findsOneWidget);
    }
  });

  testWidgets('devices: the list refreshes itself while open', (t) async {
    final kv = MemoryStore();
    await SessionStore(kv).save(Session(accountId: 'a', deviceId: 'p', accessToken: 't', refreshToken: 'r'));
    var presence = 'offline';
    await t.pumpWidget(
      app(
        kv,
        const [],
        onFetch: () => http.Response(
          jsonEncode({
            'items': [host('h1', 'workstation', presence)],
            'next_cursor': null,
          }),
          200,
        ),
      ),
    );
    await t.pumpAndSettle();
    expect(find.text('Offline'), findsOneWidget);
    presence = 'online';
    await t.pump(devicesPollInterval);
    await t.pumpAndSettle();
    expect(find.text('Online'), findsOneWidget);
  });
}
