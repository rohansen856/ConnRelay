// PRW transport spike (S1/S6): a thin Flutter UI over the Go probe that runs
// the phone side of a real connection attempt in-process via gomobile.
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(const SpikeApp());

class SpikeApp extends StatelessWidget {
  const SpikeApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PRW spike',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      darkTheme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        brightness: Brightness.dark,
        useMaterial3: true,
      ),
      home: const SpikePage(),
    );
  }
}

class SpikePage extends StatefulWidget {
  const SpikePage({super.key});

  @override
  State<SpikePage> createState() => _SpikePageState();
}

class _SpikePageState extends State<SpikePage> {
  static const _channel = MethodChannel('prw/probe');
  final _server = TextEditingController(text: 'http://10.89.145.214:18443');
  final _log = <String>[];
  bool _busy = false;
  String _version = '';

  @override
  void initState() {
    super.initState();
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'log') _add(call.arguments as String);
    });
    _channel.invokeMethod<String>('version').then((v) => setState(() => _version = v ?? ''));
  }

  void _add(String line) => setState(() => _log.insert(0, line));

  Future<void> _call(String label, String method, [Map<String, Object?>? args]) async {
    setState(() => _busy = true);
    final sw = Stopwatch()..start();
    try {
      final raw = await _channel.invokeMethod<String>(method, args) ?? '';
      final pretty = const JsonEncoder.withIndent('  ').convert(jsonDecode(raw));
      _add('$label (${sw.elapsedMilliseconds} ms)\n$pretty');
    } catch (e) {
      _add('$label failed: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _run(String mode, {bool forceRelay = false}) => _call(
        'run $mode${forceRelay ? ' (relay only)' : ''}',
        'run',
        {
          'server': _server.text.trim(),
          'labId': 'ui',
          'mode': mode,
          'forceRelay': forceRelay,
          'bytes': 1 << 20,
          'hardwareKey': true,
        },
      );

  @override
  Widget build(BuildContext context) {
    final buttons = <(String, VoidCallback)>[
      ('Check device key', () => _call('check key', 'checkKey')),
      ('Auto', () => _run('auto')),
      ('Direct/ICE', () => _run('webrtc')),
      ('TURN only', () => _run('webrtc', forceRelay: true)),
      ('WSS relay', () => _run('wss')),
    ];
    return Scaffold(
      appBar: AppBar(title: const Text('PRW transport spike')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(_version, style: Theme.of(context).textTheme.bodySmall),
              const SizedBox(height: 8),
              TextField(
                controller: _server,
                decoration: const InputDecoration(labelText: 'Lab server URL'),
                keyboardType: TextInputType.url,
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final (label, onTap) in buttons)
                    FilledButton.tonal(onPressed: _busy ? null : onTap, child: Text(label)),
                ],
              ),
              if (_busy) const LinearProgressIndicator(),
              const SizedBox(height: 12),
              Expanded(
                child: ListView.separated(
                  itemCount: _log.length,
                  separatorBuilder: (_, _) => const Divider(),
                  itemBuilder: (_, i) => SelectableText(
                    _log[i],
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
