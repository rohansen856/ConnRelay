/// A parsed pairing QR code: prw://pair?v=1&ref=..&fp=..&api=..
class PairingQr {
  PairingQr(this.ref, this.fingerprint, this.api);
  final String ref, fingerprint, api;
}

class PairingError implements Exception {
  PairingError(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Parses and validates a QR payload against the server this app uses.
PairingQr parsePairingQr(String raw, String expectedApi) {
  final uri = Uri.tryParse(raw.trim());
  if (uri == null || uri.scheme != 'prw' || uri.host != 'pair') {
    throw PairingError('This is not a pairing code from prw-agent.');
  }
  final q = uri.queryParameters;
  if (q['v'] != '1') throw PairingError('This pairing code needs a newer app.');
  final ref = q['ref'] ?? '', fp = (q['fp'] ?? '').toLowerCase(), api = q['api'] ?? '';
  if (ref.isEmpty || !RegExp(r'^[0-9a-f]{64}$').hasMatch(fp)) {
    throw PairingError('The pairing code is incomplete. Run prw-agent pair again.');
  }
  if (_norm(api) != _norm(expectedApi)) {
    throw PairingError('This computer is pairing with a different server ($api).');
  }
  return PairingQr(ref, fp, api);
}

String _norm(String u) => u.trim().replaceAll(RegExp(r'/+$'), '').toLowerCase();

/// Hard check: the key the server reports must be the key in the QR code.
void checkFingerprint(String fromQr, String fromServer) {
  if (fromQr.toLowerCase() != fromServer.toLowerCase()) {
    throw PairingError('The computer\'s key does not match the QR code. Pairing was stopped.');
  }
}
