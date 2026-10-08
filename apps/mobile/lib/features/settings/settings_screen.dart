import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/api.dart';
import '../../core/auth.dart';
import '../devices/devices_providers.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final auth = ref.watch(authProvider);
    final me = auth is SignedIn ? auth.session : null;
    final devices = ref.watch(devicesProvider);
    final api = ref.watch(apiProvider);
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(children: [
        ListTile(title: const Text('Account'), subtitle: Text(me?.displayName.isNotEmpty == true ? me!.displayName : 'Signed in')),
        ListTile(title: const Text('Server'), subtitle: Text(ref.watch(configProvider).apiBase)),
        const Divider(),
        const Padding(padding: EdgeInsets.fromLTRB(16, 12, 16, 4), child: Text('Phones')),
        ...devices.maybeWhen(
          data: (list) => list.where((d) => !d.isHost && !d.revoked).map((d) => ListTile(
                leading: const Icon(Icons.smartphone),
                title: Text(d.name + (d.id == me?.deviceId ? ' (this phone)' : '')),
                subtitle: Text('seen ${relativeTime(d.lastSeen)}'),
                trailing: d.id == me?.deviceId
                    ? null
                    : TextButton(
                        onPressed: () async {
                          final ok = await showDialog<bool>(
                            context: context,
                            builder: (c) => AlertDialog(
                              title: Text('Remove "${d.name}"?'),
                              content: const Text('Use this for a lost phone. It is signed out and loses access to every '
                                  'computer immediately; open connections close within 30 seconds.'),
                              actions: [
                                TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
                                FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Remove phone')),
                              ],
                            ),
                          );
                          if (ok != true) return;
                          try {
                            await revokeDevice(api, d, 'lost');
                            ref.invalidate(devicesProvider);
                          } on ApiException catch (e) {
                            if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
                          }
                        },
                        child: const Text('Remove')),
              )),
          orElse: () => const [ListTile(title: Text('Loading…'))],
        ),
        const Divider(),
        const SizedBox(height: 48),
        ListTile(
          leading: const Icon(Icons.logout),
          title: const Text('Sign out of this phone'),
          subtitle: const Text('Other phones stay signed in.'),
          onTap: () => ref.read(authProvider.notifier).logout(),
        ),
      ]),
    );
  }
}
