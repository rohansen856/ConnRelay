import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:math';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_sign_in/google_sign_in.dart';

import '../app/config.dart';
import 'api.dart';
import 'native.dart';
import 'session_store.dart';

/// Obtains a Google ID token bound to [nonce].
abstract class IdTokenProvider {
  Future<String> idToken(String nonce);
  Future<void> signOut();
}

class GoogleIdTokens implements IdTokenProvider {
  GoogleIdTokens(this.serverClientId);
  final String serverClientId;

  @override
  Future<String> idToken(String nonce) async {
    final g = GoogleSignIn.instance;
    await g.initialize(serverClientId: serverClientId, nonce: nonce);
    final account = await g.authenticate();
    final t = account.authentication.idToken;
    if (t == null) throw StateError('Google did not return an ID token');
    return t;
  }

  @override
  Future<void> signOut() => GoogleSignIn.instance.signOut();
}

sealed class AuthState {
  const AuthState();
}

class AuthLoading extends AuthState {
  const AuthLoading();
}

class SignedOut extends AuthState {
  const SignedOut([this.error]);
  final String? error;
}

class SignedIn extends AuthState {
  const SignedIn(this.session);
  final Session session;
}

// ---- providers ----

final configProvider = Provider<AppConfig>((_) => AppConfig.fromEnvironment());
final sessionStoreProvider = Provider<SessionStore>((_) => SessionStore(const SecureStore()));
final nativeCoreProvider = Provider<NativeCore>((_) => ChannelCore());
final idTokenProvider = Provider<IdTokenProvider>((ref) => GoogleIdTokens(ref.watch(configProvider).googleServerClientId));
final apiProvider = Provider<ApiClient>((ref) => ApiClient(ref.watch(configProvider).apiBase));
final authProvider = StateNotifierProvider<AuthController, AuthState>((ref) => AuthController(ref)..restore());

/// Sign-in, refresh and logout. Implements [TokenSource] for the API client.
class AuthController extends StateNotifier<AuthState> implements TokenSource {
  AuthController(this.ref) : super(const AuthLoading()) {
    ref.read(apiProvider).tokens = this;
  }

  final Ref ref;
  Future<bool>? _refreshing;

  ApiClient get _api => ref.read(apiProvider);
  NativeCore get _native => ref.read(nativeCoreProvider);
  SessionStore get _store => ref.read(sessionStoreProvider);

  Session? get session => state is SignedIn ? (state as SignedIn).session : null;

  @override
  String? get accessToken => session?.accessToken;

  Future<void> restore() async {
    final s = await _store.load();
    state = s == null ? const SignedOut() : SignedIn(s);
  }

  static String _randomNonce() {
    final r = Random.secure();
    return base64Url.encode(List<int>.generate(24, (_) => r.nextInt(256))).replaceAll('=', '');
  }

  Future<String> _challenge() async => (await _api.post('/v1/auth/challenge'))['nonce'] as String;

  /// Google sign-in, then register this phone's hardware key.
  Future<void> signIn() async {
    state = const AuthLoading();
    try {
      final oidcNonce = _randomNonce();
      final idToken = await ref.read(idTokenProvider).idToken(oidcNonce);
      final spki = await _native.publicKey();
      final fp = await _native.fingerprint(spki);
      final nonce = await _challenge();
      final sig = await _native.signPoP('connrelay.auth.v1', nonce, spkiFp: fp);
      final r = await _api.post('/v1/auth/exchange', {
        'provider': 'google',
        'id_token': idToken,
        'oidc_nonce': oidcNonce,
        'device': {
          'platform': Platform.isIOS ? 'ios' : 'android',
          'display_name': _deviceName(),
          'app_version': '0.1.0',
          'public_key_spki': base64Url.encode(spki).replaceAll('=', ''),
          'proto': {'min': 1, 'max': 1},
        },
        'pop': {'nonce': nonce, 'sig': sig},
      });
      final s = Session(
          accountId: (r['account'] as Map)['id'] as String,
          displayName: (r['account'] as Map)['display_name'] as String? ?? '',
          deviceId: r['device_id'] as String,
          accessToken: r['access_token'] as String,
          refreshToken: r['refresh_token'] as String);
      await _store.save(s);
      state = SignedIn(s);
    } on ApiException catch (e) {
      state = SignedOut(e.code == 'account_not_allowed' ? 'This Google account is not allowed on this server.' : e.message);
    } catch (e) {
      state = SignedOut('Sign-in did not complete. ($e)');
    }
  }

  static String _deviceName() {
    try {
      return Platform.localHostname.isEmpty ? 'Phone' : Platform.localHostname;
    } catch (_) {
      return 'Phone';
    }
  }

  /// Rotates tokens with a fresh device signature. Concurrent callers share
  /// one refresh.
  @override
  Future<bool> refresh() => _refreshing ??= _doRefresh().whenComplete(() => _refreshing = null);

  Future<bool> _doRefresh() async {
    final s = session;
    if (s == null) return false;
    try {
      final nonce = await _challenge();
      final sig = await _native.signPoP('connrelay.refresh.v1', nonce, deviceId: s.deviceId);
      final r = await _api.post('/v1/auth/refresh', {'refresh_token': s.refreshToken, 'pop': {'nonce': nonce, 'sig': sig}});
      s.accessToken = r['access_token'] as String;
      s.refreshToken = r['refresh_token'] as String;
      await _store.save(s); // store the new refresh token before using it
      state = SignedIn(s);
      return true;
    } on ApiException catch (e) {
      if (e.status == 401 || e.status == 403) {
        await _forget(e.code == 'device_revoked' ? 'This phone was removed from your account.' : 'Please sign in again.');
      }
      return false;
    }
  }

  Future<void> logout() async {
    try {
      await _api.post('/v1/auth/logout');
    } catch (_) {
      // Signing out locally must work even offline.
    }
    await ref.read(idTokenProvider).signOut().catchError((_) {});
    await _forget(null);
  }

  Future<void> _forget(String? reason) async {
    await _store.clear();
    state = SignedOut(reason);
  }
}
