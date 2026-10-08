import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api.dart';
import '../../core/auth.dart';
import '../../widgets/error_view.dart';
import '../../widgets/status_badge.dart';
import 'devices_providers.dart';

/// Groups a fingerprint for reading aloud / comparing ("ABCD EF01 ...").
String groupFingerprint(String fp) {
  final up = fp.toUpperCase();
  final parts = <String>[];
  for (var i = 0; i + 4 <= up.length && i < 32; i += 4) {
    parts.add(up.substring(i, i + 4));
  }
  return parts.join(' ');
}

class DeviceDetailScreen extends ConsumerWidget {
  const DeviceDetailScreen({super.key, required this.id});
  final String id;

  Future<void> _run(BuildContext context, WidgetRef ref, Future<void> Function() op, String done) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      await op();
      ref.invalidate(deviceProvider(id));
      ref.invalidate(devicesProvider);
      messenger.showSnackBar(SnackBar(content: Text(done)));
    } on ApiException catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final dev = ref.watch(deviceProvider(id));
    final api = ref.watch(apiProvider);
    final me = ref.watch(authProvider) is SignedIn ? (ref.watch(authProvider) as SignedIn).session.deviceId : '';
    return Scaffold(
      appBar: AppBar(title: Text(dev.valueOrNull?.name ?? 'Computer')),
      body: dev.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => ErrorView(title: 'Could not load this computer', onAction: () => ref.invalidate(deviceProvider(id))),
        data: (d) => ListView(padding: const EdgeInsets.all(16), children: [
          Row(children: [StatusBadge(d.revoked ? 'revoked' : d.presence), const Spacer(), Text('seen ${relativeTime(d.lastSeen)}')]),
          const SizedBox(height: 16),
          ListTile(title: const Text('Key fingerprint'), subtitle: SelectableText(groupFingerprint(d.fingerprint))),
          ListTile(title: const Text('Agent version'), subtitle: Text(d.softwareVersion ?? 'unknown')),
          const Divider(),
          if (d.myGrant == null)
            ListTile(
              leading: const Icon(Icons.lock_outline),
              title: const Text('This phone has no terminal access'),
              trailing: FilledButton(
                  onPressed: d.revoked ? null : () => _run(context, ref, () => grantAccess(api, me, d.id), 'Access granted'),
                  child: const Text('Grant')),
            )
          else ...[
            ListTile(
              leading: const Icon(Icons.terminal),
              title: const Text('Terminal access'),
              subtitle: const Text('Sessions run with this computer\'s user permissions.'),
              trailing: FilledButton(
                  onPressed: d.presence == 'online' ? () => context.push('/terminal/${d.id}') : null, child: const Text('Connect')),
            ),
            TextButton(
                onPressed: () => _run(context, ref, () => revokeGrant(api, d.myGrant!), 'Access removed'),
                child: const Text('Remove this phone\'s access')),
          ],
          const Divider(),
          if (!d.revoked)
            TextButton.icon(
              icon: const Icon(Icons.delete_outline),
              style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
              label: const Text('Remove computer'),
              onPressed: () async {
                final ok = await showDialog<bool>(
                  context: context,
                  builder: (c) => AlertDialog(
                    title: const Text('Remove this computer?'),
                    content: const Text('No phone will be able to connect to it. Running terminal sessions on the '
                        'computer keep running until you end them there.'),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
                      FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Remove')),
                    ],
                  ),
                );
                if (ok == true && context.mounted) {
                  await _run(context, ref, () => revokeDevice(api, d, 'user'), 'Computer removed');
                }
              },
            ),
        ]),
      ),
    );
  }
}
