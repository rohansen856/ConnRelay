import 'package:flutter/material.dart';

/// Presence/connection status with an icon and a word, never colour alone.
class StatusBadge extends StatelessWidget {
  const StatusBadge(this.status, {super.key});
  final String status;

  static const _spec = <String, (IconData, String)>{
    'online': (Icons.circle, 'Online'),
    'stale': (Icons.schedule, 'Stale'),
    'offline': (Icons.circle_outlined, 'Offline'),
    'unknown': (Icons.help_outline, 'Never seen'),
    'revoked': (Icons.block, 'Removed'),
    'connecting': (Icons.sync, 'Connecting'),
    'direct': (Icons.bolt, 'Direct'),
    'turn': (Icons.alt_route, 'Relayed'),
    'wss_relay': (Icons.alt_route, 'Relayed (web)'),
    'reconnecting': (Icons.sync_problem, 'Reconnecting'),
  };

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (icon, label) = _spec[status] ?? (Icons.help_outline, status);
    final color = switch (status) {
      'online' || 'direct' => Colors.green.shade600,
      'stale' || 'reconnecting' || 'turn' || 'wss_relay' => Colors.amber.shade800,
      'revoked' => scheme.error,
      _ => scheme.outline,
    };
    return Semantics(
      label: 'Status: $label',
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 12, color: color),
        const SizedBox(width: 4),
        Text(label, style: Theme.of(context).textTheme.labelMedium),
      ]),
    );
  }
}
