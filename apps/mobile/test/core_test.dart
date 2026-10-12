import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:connrelay/core/api.dart';
import 'package:connrelay/features/pairing/pairing_logic.dart';
import 'package:connrelay/features/terminal/terminal_controller.dart';
import 'package:connrelay/features/terminal/terminal_screen.dart';

class Tokens implements TokenSource {
  String token = 'old';
  int refreshes = 0;
  bool canRefresh = true;
  @override
  String? get accessToken => token;
  @override
  Future<bool> refresh() async {
    refreshes++;
    token = 'new';
    return canRefresh;
  }
}

http.Response err(int status, String code) =>
    http.Response(jsonEncode({'error': {'code': code, 'message': 'm', 'retryable': false, 'request_id': 'r1'}}), status);

void main() {
  group('ApiClient', () {
    test('refreshes once on 401 and retries with the new token', () async {
      final seen = <String>[];
      final api = ApiClient('https://api.test', httpClient: MockClient((r) async {
        seen.add(r.headers['Authorization']!);
        return r.headers['Authorization'] == 'Bearer new' ? http.Response('{"ok":true}', 200) : err(401, 'unauthenticated');
      }));
      final t = Tokens();
      api.tokens = t;
      expect(await api.get('/v1/me'), {'ok': true});
      expect(seen, ['Bearer old', 'Bearer new']);
      expect(t.refreshes, 1);
    });

    test('gives up after one refresh and surfaces the error envelope', () async {
      final api = ApiClient('https://api.test', httpClient: MockClient((_) async => err(401, 'unauthenticated')));
      final t = Tokens();
      api.tokens = t;
      await expectLater(api.get('/v1/me'), throwsA(isA<ApiException>().having((e) => e.code, 'code', 'unauthenticated')));
      expect(t.refreshes, 1);
    });

    test('does not refresh for other errors', () async {
      final api = ApiClient('https://api.test', httpClient: MockClient((_) async => err(403, 'device_revoked')));
      final t = Tokens();
      api.tokens = t;
      await expectLater(api.get('/v1/me'), throwsA(isA<ApiException>().having((e) => e.status, 'status', 403)));
      expect(t.refreshes, 0);
    });
  });

  group('pairing QR', () {
    final fp = 'a1' * 32;
    const api = 'https://api.example.invalid';
    test('parses a valid payload', () {
      final q = parsePairingQr('connrelay://pair?v=1&ref=REF&fp=$fp&api=${Uri.encodeComponent(api)}', '$api/');
      expect(q.ref, 'REF');
      expect(q.fingerprint, fp);
    });
    for (final bad in {
      'not a pairing code': 'https://example.invalid',
      'other server': 'connrelay://pair?v=1&ref=R&fp=$fp&api=https://evil.invalid',
      'short fingerprint': 'connrelay://pair?v=1&ref=R&fp=abcd&api=$api',
      'newer version': 'connrelay://pair?v=2&ref=R&fp=$fp&api=$api',
      'missing ref': 'connrelay://pair?v=1&fp=$fp&api=$api',
    }.entries) {
      test('rejects ${bad.key}', () => expect(() => parsePairingQr(bad.value, api), throwsA(isA<PairingError>())));
    }
    test('fingerprint mismatch is a hard failure', () {
      expect(() => checkFingerprint(fp, 'b2' * 32), throwsA(isA<PairingError>()));
      checkFingerprint(fp, fp.toUpperCase());
    });
  });

  test('paste confirmation rule', () {
    expect(needsPasteConfirmation('ls -la'), isFalse);
    expect(needsPasteConfirmation('ls\nrm -rf x'), isTrue);
    expect(needsPasteConfirmation('x' * 201), isTrue);
  });

  test('ctrl mapping', () {
    expect(ctrlOf('c'), [3]);
    expect(ctrlOf('D'), [4]);
    expect(ctrlOf('['), [0x1b]);
    expect(ctrlOf('1'), isNull);
    expect(ctrlOf('ab'), isNull);
  });

  test('error descriptions are plain language', () {
    expect(describeError(Exception('connect_timeout (last error: x)')), contains('Could not reach'));
  });
}
