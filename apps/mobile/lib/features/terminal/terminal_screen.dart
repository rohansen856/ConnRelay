import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:xterm/xterm.dart';

import '../../core/auth.dart';
import '../../widgets/error_view.dart';
import '../../widgets/status_badge.dart';
import '../devices/device_detail_screen.dart';
import '../devices/devices_providers.dart';
import 'accessory_bar.dart';
import 'terminal_controller.dart';

/// Pastes longer than this, or with several lines, need confirmation: a
/// stray paste must not run commands.
const pasteConfirmChars = 200;

bool needsPasteConfirmation(String text) => text.contains('\n') || text.length > pasteConfirmChars;

class TerminalScreen extends ConsumerStatefulWidget {
  const TerminalScreen({super.key, required this.hostId});
  final String hostId;
  @override
  ConsumerState<TerminalScreen> createState() => _TerminalScreenState();
}

class _TerminalScreenState extends ConsumerState<TerminalScreen> with WidgetsBindingObserver {
  bool _ctrl = false;
  final _focus = FocusNode();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _start());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _focus.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    // On resume, re-check the connection before any input is sent.
    final c = ref.read(terminalProvider(widget.hostId));
    if (s == AppLifecycleState.resumed && (c.phase == Phase.failed || c.phase == Phase.reconnecting)) {
      _start();
    }
  }

  /// Uses the fingerprint pinned at pairing. A host paired from another phone
  /// is pinned after the user confirms its fingerprint here.
  Future<void> _start() async {
    final store = ref.read(sessionStoreProvider);
    var pin = (await store.pins())[widget.hostId];
    if (pin == null) {
      final dev = await ref.read(deviceProvider(widget.hostId).future);
      if (!mounted) return;
      final ok = await showDialog<bool>(
        context: context,
        builder: (c) => AlertDialog(
          title: const Text('Trust this computer?'),
          content: Text('First connection from this phone. Check that the key matches `connrelay-agent status` on '
              '"${dev.name}":\n\n${groupFingerprint(dev.fingerprint)}'),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('It matches')),
          ],
        ),
      );
      if (ok != true) {
        if (mounted) context.pop();
        return;
      }
      await store.pin(widget.hostId, dev.fingerprint);
      pin = dev.fingerprint;
    }
    await ref.read(terminalProvider(widget.hostId).notifier).connect(pin);
  }

  Future<void> _paste(TermController c) async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text ?? '';
    if (text.isEmpty) return;
    if (needsPasteConfirmation(text) && mounted) {
      final ok = await showDialog<bool>(
        context: context,
        builder: (d) => AlertDialog(
          title: const Text('Paste into the terminal?'),
          content: SingleChildScrollView(child: Text(text, style: const TextStyle(fontFamily: 'monospace'))),
          actions: [
            TextButton(onPressed: () => Navigator.pop(d, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(d, true), child: const Text('Paste')),
          ],
        ),
      );
      if (ok != true) return;
    }
    c.terminal.paste(text);
  }

  @override
  Widget build(BuildContext context) {
    final st = ref.watch(terminalProvider(widget.hostId));
    final c = ref.read(terminalProvider(widget.hostId).notifier);
    final host = ref.watch(deviceProvider(widget.hostId)).valueOrNull;
    final status = switch (st.phase) {
      Phase.attached || Phase.choosing => st.path ?? 'connecting',
      Phase.reconnecting => 'reconnecting',
      Phase.connecting => 'connecting',
      _ => 'offline',
    };
    return Scaffold(
      appBar: AppBar(
        title: Text(host?.name ?? 'Terminal', overflow: TextOverflow.ellipsis),
        actions: [
          Center(child: StatusBadge(status)),
          IconButton(tooltip: 'Paste', icon: const Icon(Icons.content_paste), onPressed: () => _paste(c)),
          PopupMenuButton<String>(
            onSelected: (v) async {
              if (v == 'disconnect') {
                await c.disconnect();
                if (context.mounted) context.pop();
              } else if (v == 'terminate') {
                final ok = await showDialog<bool>(
                  context: context,
                  builder: (d) => AlertDialog(
                    title: const Text('End this session?'),
                    content: const Text('Everything running in it on the computer is stopped. '
                        'To leave it running, use Disconnect instead.'),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(d, false), child: const Text('Cancel')),
                      FilledButton(onPressed: () => Navigator.pop(d, true), child: const Text('End session')),
                    ],
                  ),
                );
                if (ok == true) await c.terminate();
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'disconnect', child: Text('Disconnect (keep running)')),
              PopupMenuItem(value: 'terminate', child: Text('End session…')),
            ],
          ),
        ],
      ),
      body: SafeArea(
        child: Column(children: [
          if (st.phase == Phase.reconnecting)
            MaterialBanner(
              content: const Text('Connection lost. Output below may be out of date; input is paused.'),
              actions: [TextButton(onPressed: _start, child: const Text('Retry now'))],
            ),
          Expanded(child: _body(st, c)),
          if (st.phase == Phase.attached || st.phase == Phase.reconnecting)
            AccessoryBar(
              ctrl: _ctrl,
              onCtrl: () {
                setState(() => _ctrl = !_ctrl);
                c.ctrlLatch = _ctrl;
                c.onCtrlConsumed = () => mounted ? setState(() => _ctrl = false) : null;
              },
              onBytes: (b) {
                if (_ctrl && b.length == 1) {
                  b = ctrlOf(String.fromCharCode(b[0])) ?? b;
                  setState(() => _ctrl = false);
                  c.ctrlLatch = false;
                }
                c.sendBytes(b);
                _focus.requestFocus();
              },
            ),
        ]),
      ),
    );
  }

  Widget _body(TermState st, TermController c) {
    switch (st.phase) {
      case Phase.connecting:
        return const Center(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
          CircularProgressIndicator(),
          SizedBox(height: 12),
          Text('Requesting secure connection…'),
        ]));
      case Phase.failed:
        return ErrorView(title: 'Could not connect', detail: st.message, onAction: _start);
      case Phase.revoked:
        return ErrorView(title: 'No access', detail: st.message);
      case Phase.choosing:
        return ListView(children: [
          if (st.message != null) Padding(padding: const EdgeInsets.all(12), child: Text(st.message!)),
          ListTile(leading: const Icon(Icons.add), title: const Text('New terminal'), onTap: c.openNew),
          if (st.sessions.isNotEmpty) const Padding(padding: EdgeInsets.fromLTRB(16, 16, 16, 4), child: Text('Running sessions')),
          for (final s in st.sessions)
            ListTile(
              leading: const Icon(Icons.terminal),
              title: Text('Session ${(s['id'] as String).substring(0, 8)}'),
              subtitle: Text('${s['status']} · started ${relativeTime(DateTime.tryParse(s['created_at'] as String? ?? ''))}'),
              trailing: const Text('Resume'),
              onTap: () => c.attach(s['id'] as String),
            ),
        ]);
      case Phase.attached:
      case Phase.reconnecting:
        return Opacity(
          opacity: st.phase == Phase.reconnecting ? 0.5 : 1,
          child: TerminalView(
            c.terminal,
            focusNode: _focus,
            autofocus: true,
            backgroundOpacity: 1,
            textStyle: const TerminalStyle(fontSize: 13),
            onKeyEvent: (_, _) => KeyEventResult.ignored,
            hardwareKeyboardOnly: false,
            readOnly: st.phase != Phase.attached,
            onTapUp: (_, _) => _focus.requestFocus(),
            simulateScroll: true,
            keyboardType: TextInputType.visiblePassword, // no autocorrect or suggestions
          ),
        );
    }
  }
}
