import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api.dart';
import '../../widgets/error_view.dart';
import '../../widgets/status_badge.dart';
import 'devices_providers.dart';

class DevicesScreen extends ConsumerWidget {
  const DevicesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final devices = ref.watch(devicesProvider);
    return Scaffold(
      appBar: AppBar(title: const Text('Computers'), actions: [
        IconButton(tooltip: 'Settings', icon: const Icon(Icons.settings_outlined), onPressed: () => context.push('/settings')),
      ]),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => context.push('/pair'),
        icon: const Icon(Icons.add),
        label: const Text('Add computer'),
      ),
      body: RefreshIndicator(
        onRefresh: () => ref.refresh(devicesProvider.future),
        // Every state must be scrollable, or the pull gesture never starts
        // (a short list does not fill the screen).
        child: devices.when(
          loading: () => ListView(physics: const AlwaysScrollableScrollPhysics(), children: const [
            SizedBox(height: 160),
            Center(child: CircularProgressIndicator()),
          ]),
          error: (e, _) => ListView(physics: const AlwaysScrollableScrollPhysics(), children: [
            const SizedBox(height: 80),
            ErrorView(
                title: 'Could not load your computers',
                detail: e is ApiException ? e.message : 'Check your connection.',
                onAction: () => ref.invalidate(devicesProvider)),
          ]),
          data: (list) {
            final hosts = list.where((d) => d.isHost && !d.revoked).toList();
            if (hosts.isEmpty) {
              return ListView(physics: const AlwaysScrollableScrollPhysics(), children: const [
                SizedBox(height: 120),
                Icon(Icons.computer, size: 56),
                SizedBox(height: 12),
                Center(child: Text('Add your first computer')),
                Padding(
                  padding: EdgeInsets.all(24),
                  child: Text('Install connrelay-agent on a Linux computer, run "connrelay-agent pair --server <your server>", '
                      'then tap Add computer and scan the code it shows.',
                      textAlign: TextAlign.center),
                ),
              ]);
            }
            return ListView.separated(
              physics: const AlwaysScrollableScrollPhysics(),
              itemCount: hosts.length,
              separatorBuilder: (_, _) => const Divider(height: 1),
              itemBuilder: (_, i) => _HostTile(hosts[i]),
            );
          },
        ),
      ),
    );
  }
}

class _HostTile extends StatelessWidget {
  const _HostTile(this.d);
  final Device d;

  @override
  Widget build(BuildContext context) {
    final canConnect = d.myGrant != null;
    return ListTile(
      leading: const Icon(Icons.computer),
      title: Text(d.name),
      subtitle: Row(children: [
        StatusBadge(d.presence),
        const SizedBox(width: 8),
        Flexible(child: Text('seen ${relativeTime(d.lastSeen)}', overflow: TextOverflow.ellipsis)),
      ]),
      onTap: () => context.push('/devices/${d.id}'),
      trailing: canConnect
          ? FilledButton.tonal(
              onPressed: d.presence == 'online' ? () => context.push('/terminal/${d.id}') : null,
              child: const Text('Connect'))
          : const Tooltip(message: 'This phone has no access yet', child: Icon(Icons.lock_outline)),
    );
  }
}
