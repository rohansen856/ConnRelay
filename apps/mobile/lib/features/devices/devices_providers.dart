import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/api.dart';
import '../../core/auth.dart';

/// All devices of the account (hosts first).
final devicesProvider = FutureProvider.autoDispose<List<Device>>((ref) async {
  final api = ref.watch(apiProvider);
  ref.watch(authProvider); // refetch on sign-in changes
  final out = <Device>[];
  String? cursor;
  do {
    final r = await api.get('/v1/devices?limit=100${cursor == null ? '' : '&cursor=$cursor'}');
    out.addAll((r['items'] as List).map((e) => Device.fromJson(e as Map<String, dynamic>)));
    cursor = r['next_cursor'] as String?;
  } while (cursor != null);
  out.sort((a, b) {
    if (a.isHost != b.isHost) return a.isHost ? -1 : 1;
    return a.name.toLowerCase().compareTo(b.name.toLowerCase());
  });
  return out;
});

final deviceProvider = FutureProvider.autoDispose.family<Device, String>((ref, id) async {
  final r = await ref.watch(apiProvider).get('/v1/devices/$id');
  return Device.fromJson(r);
});

/// Grants this phone access to a host.
Future<void> grantAccess(ApiClient api, String phoneId, String hostId) => api.post('/v1/access-grants', {
      'phone_device_id': phoneId,
      'host_device_id': hostId,
      'capabilities': ['terminal'],
    });

Future<void> revokeGrant(ApiClient api, Grant g) =>
    api.post('/v1/access-grants/${g.id}/revoke', null, {'If-Match': '"${g.version}"'});

Future<void> revokeDevice(ApiClient api, Device d, String reason, {bool confirmLastPhone = false}) => api.post(
    '/v1/devices/${d.id}/revoke${confirmLastPhone ? '?confirm_last_phone=true' : ''}',
    {'reason': reason},
    {'If-Match': '"${d.version}"'});

String relativeTime(DateTime? t) {
  if (t == null) return 'never';
  final d = DateTime.now().difference(t);
  if (d.inSeconds < 60) return 'just now';
  if (d.inMinutes < 60) return '${d.inMinutes} min ago';
  if (d.inHours < 24) return '${d.inHours} h ago';
  return '${d.inDays} d ago';
}
