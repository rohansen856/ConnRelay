import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../core/api.dart';
import '../../core/auth.dart';
import '../devices/device_detail_screen.dart';
import '../devices/devices_providers.dart';
import 'pairing_logic.dart';

class PairScreen extends ConsumerStatefulWidget {
  const PairScreen({super.key});
  @override
  ConsumerState<PairScreen> createState() => _PairScreenState();
}

class _PairScreenState extends ConsumerState<PairScreen> {
  final _code = TextEditingController();
  bool _typing = false;
  bool _busy = false;
  String? _error;
  Map<String, dynamic>? _resolved; // challenge details from the server
  String? _qrFp; // fingerprint from the QR code, if scanned
  bool _grant = true;

  ApiClient get _api => ref.read(apiProvider);

  Future<void> _resolve({String? ref, String? code, String? qrFp}) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await _api.post('/v1/pairing/resolve', ref != null ? {'pairing_ref': ref} : {'display_code': code});
      if (qrFp != null) {
        try {
          checkFingerprint(qrFp, r['host_key_fingerprint'] as String);
        } on PairingError {
          await _api.post('/v1/pairing/challenges/${r['challenge_id']}/cancel').catchError((_) => <String, dynamic>{});
          rethrow;
        }
      }
      setState(() {
        _resolved = r;
        _qrFp = qrFp;
      });
    } on PairingError catch (e) {
      setState(() => _error = e.message);
    } on ApiException catch (e) {
      setState(() => _error = switch (e.code) {
            'pairing_expired' => 'This code expired. Run connrelay-agent pair again on the computer.',
            'pairing_used' => 'This code was already used.',
            'pairing_locked' => 'Too many failed attempts. Run connrelay-agent pair again.',
            'not_found' => 'No computer is waiting with that code.',
            _ => e.message,
          });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _approve() async {
    final r = _resolved!;
    final fp = r['host_key_fingerprint'] as String;
    setState(() => _busy = true);
    try {
      await _api.post('/v1/pairing/challenges/${r['challenge_id']}/approve',
          {'host_key_fingerprint': fp, 'grant_to_this_phone': _grant}, {'Idempotency-Key': ApiClient.newIdempotencyKey()});
      // The computer finishes enrolment by proving its key; wait for it,
      // then pin the fingerprint the user just confirmed.
      for (var i = 0; i < 60 && mounted; i++) {
        final list = await ref.refresh(devicesProvider.future);
        final host = list.where((d) => d.isHost && d.fingerprint == fp && !d.revoked).firstOrNull;
        if (host != null) {
          await ref.read(sessionStoreProvider).pin(host.id, fp);
          if (mounted) context.go('/devices/${host.id}');
          return;
        }
        await Future<void>.delayed(const Duration(seconds: 1));
      }
      setState(() => _error = 'The computer did not finish pairing. Check that connrelay-agent is still running.');
    } on ApiException catch (e) {
      setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final api = ref.watch(configProvider).apiBase;
    return Scaffold(
      appBar: AppBar(title: const Text('Add computer')),
      body: _resolved != null ? _confirm(context) : (_typing ? _typeCode() : _scanner(api)),
    );
  }

  Widget _scanner(String api) => Column(children: [
        Expanded(
          child: MobileScanner(onDetect: (capture) {
            final raw = capture.barcodes.firstOrNull?.rawValue;
            if (raw == null || _busy || _resolved != null) return;
            try {
              final qr = parsePairingQr(raw, api);
              _resolve(ref: qr.ref, qrFp: qr.fingerprint);
            } on PairingError catch (e) {
              setState(() => _error = e.message);
            }
          }),
        ),
        if (_error != null) Padding(padding: const EdgeInsets.all(12), child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
        Padding(
          padding: const EdgeInsets.all(16),
          child: Text('On the computer run:  connrelay-agent pair --server $api', textAlign: TextAlign.center),
        ),
        TextButton(onPressed: () => setState(() => _typing = true), child: const Text('Enter the code instead')),
        const SizedBox(height: 16),
      ]);

  Widget _typeCode() => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(children: [
          TextField(
            controller: _code,
            autofocus: true,
            textCapitalization: TextCapitalization.characters,
            decoration: InputDecoration(labelText: 'Pairing code (e.g. 7KQ2-M9XT)', errorText: _error),
            onSubmitted: (v) => _resolve(code: v),
          ),
          const SizedBox(height: 16),
          FilledButton(onPressed: _busy ? null : () => _resolve(code: _code.text), child: const Text('Continue')),
          TextButton(onPressed: () => setState(() => _typing = false), child: const Text('Scan the QR code instead')),
        ]),
      );

  Widget _confirm(BuildContext context) {
    final r = _resolved!;
    final fp = r['host_key_fingerprint'] as String;
    return ListView(padding: const EdgeInsets.all(24), children: [
      Text('Add "${r['hostname']}"?', style: Theme.of(context).textTheme.headlineSmall),
      const SizedBox(height: 16),
      Text(_qrFp != null
          ? 'The key matches the QR code on the computer.'
          : 'Check that this key matches the one connrelay-agent printed:'),
      const SizedBox(height: 8),
      SelectableText(groupFingerprint(fp), style: const TextStyle(fontFamily: 'monospace', fontSize: 16)),
      const SizedBox(height: 16),
      SwitchListTile(
        value: _grant,
        onChanged: (v) => setState(() => _grant = v),
        title: const Text('Give this phone terminal access'),
        subtitle: const Text('Terminal sessions run with the permissions of the user running connrelay-agent.'),
      ),
      if (_error != null) Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      const SizedBox(height: 16),
      FilledButton(onPressed: _busy ? null : _approve, child: Text(_busy ? 'Waiting for the computer…' : 'Add computer')),
      TextButton(onPressed: _busy ? null : () => context.pop(), child: const Text('Cancel')),
    ]);
  }
}
