import 'package:flutter/material.dart';

/// Calm, restrained theme; status is always icon + text (see StatusBadge).
ThemeData buildTheme(Brightness b) {
  final scheme = ColorScheme.fromSeed(seedColor: const Color(0xFF4F5BD5), brightness: b);
  return ThemeData(
    colorScheme: scheme,
    useMaterial3: true,
    visualDensity: VisualDensity.standard,
    listTileTheme: const ListTileThemeData(minVerticalPadding: 10),
  );
}
