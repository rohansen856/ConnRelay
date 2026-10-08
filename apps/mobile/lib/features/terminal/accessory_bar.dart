import 'package:flutter/material.dart';

/// Keys a phone keyboard lacks. Ctrl is sticky: it applies to the next key
/// typed on the keyboard or tapped here.
class AccessoryBar extends StatelessWidget {
  const AccessoryBar({super.key, required this.onBytes, required this.ctrl, required this.onCtrl});
  final void Function(List<int>) onBytes;
  final bool ctrl;
  final VoidCallback onCtrl;

  static const _esc = 0x1b;

  @override
  Widget build(BuildContext context) {
    Widget key(String label, List<int> bytes, {String? semantics}) => Padding(
          padding: const EdgeInsets.symmetric(horizontal: 2),
          child: OutlinedButton(
            style: OutlinedButton.styleFrom(minimumSize: const Size(44, 40), padding: const EdgeInsets.symmetric(horizontal: 8)),
            onPressed: () => onBytes(bytes),
            child: Text(label, semanticsLabel: semantics ?? label),
          ),
        );
    return Material(
      elevation: 2,
      child: SizedBox(
        height: 48,
        child: ListView(scrollDirection: Axis.horizontal, padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 4), children: [
          key('Esc', [_esc]),
          key('Tab', [0x09]),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 2),
            child: FilterChip(label: const Text('Ctrl'), selected: ctrl, onSelected: (_) => onCtrl()),
          ),
          key('↑', [_esc, 0x5b, 0x41], semantics: 'Up'),
          key('↓', [_esc, 0x5b, 0x42], semantics: 'Down'),
          key('←', [_esc, 0x5b, 0x44], semantics: 'Left'),
          key('→', [_esc, 0x5b, 0x43], semantics: 'Right'),
          key('PgUp', [_esc, 0x5b, 0x35, 0x7e]),
          key('PgDn', [_esc, 0x5b, 0x36, 0x7e]),
          key('^C', [0x03], semantics: 'Control C'),
          key('^D', [0x04], semantics: 'Control D'),
          key('|', [0x7c]),
          key('~', [0x7e]),
        ]),
      ),
    );
  }

}
