import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/auth.dart';
import '../features/devices/device_detail_screen.dart';
import '../features/devices/devices_screen.dart';
import '../features/pairing/pair_screen.dart';
import '../features/settings/settings_screen.dart';
import '../features/signin/signin_screen.dart';
import '../features/terminal/terminal_screen.dart';

/// Routes are guarded: nothing but sign-in is reachable while signed out, and
/// a deep link only names a resource; access is re-checked by the server.
final routerProvider = Provider<GoRouter>((ref) {
  final refresh = ValueNotifier(0);
  ref.listen(authProvider, (_, _) => refresh.value++);
  return GoRouter(
    initialLocation: '/devices',
    refreshListenable: refresh,
    redirect: (_, state) {
      final auth = ref.read(authProvider);
      if (auth is AuthLoading) return null;
      final signedIn = auth is SignedIn;
      final atSignIn = state.matchedLocation == '/signin';
      if (!signedIn && !atSignIn) return '/signin';
      if (signedIn && atSignIn) return '/devices';
      return null;
    },
    routes: [
      GoRoute(path: '/signin', builder: (_, _) => const SignInScreen()),
      GoRoute(path: '/devices', builder: (_, _) => const DevicesScreen()),
      GoRoute(path: '/devices/:id', builder: (_, s) => DeviceDetailScreen(id: s.pathParameters['id']!)),
      GoRoute(path: '/pair', builder: (_, _) => const PairScreen()),
      GoRoute(path: '/terminal/:id', builder: (_, s) => TerminalScreen(hostId: s.pathParameters['id']!)),
      GoRoute(path: '/settings', builder: (_, _) => const SettingsScreen()),
    ],
  );
});
