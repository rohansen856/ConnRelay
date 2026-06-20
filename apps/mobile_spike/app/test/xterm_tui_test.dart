// Spike S5: does xterm.dart reproduce what a reference terminal (tmux) shows
// for real coding-agent TUIs?
//
// Fixtures come from tests/spikes/s5_capture_tui.sh: the raw byte stream a
// TUI wrote, the byte offset at which the window was resized 100x30 -> 80x24,
// and tmux's screen before and after the resize. We replay the same bytes
// into an xterm.dart Terminal and diff the visible screens line by line.
// Fixtures are gitignored (they can contain user names and paths); the test
// skips when none are present.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xterm/xterm.dart';

const _fixtures = 'test/fixtures';

/// Defects found in xterm 4.0.0 by this spike; each is a reason to fork
/// (ADR-012). A listed fixture that stops failing should be removed here.
const _knownDefects = {
  'codex-main':
      'IndexAwareCircularBuffer asserts "attached" on a line feed inside a scroll '
      'region (Buffer.index -> insert); release builds skip the assert and may corrupt lines',
};

/// Renders visible rows the way a terminal displays them: never-written
/// cells show as spaces (BufferLine.getText drops them), and the trailing
/// cell of a wide character is skipped.
List<String> _screen(Terminal t) {
  final b = t.buffer;
  final top = b.height - t.viewHeight;
  final rows = <String>[];
  for (var r = 0; r < t.viewHeight; r++) {
    final line = b.lines[top + r];
    final sb = StringBuffer();
    for (var c = 0; c < line.length; c++) {
      if (c > 0 && line.getWidth(c - 1) == 2) continue;
      final cp = line.getCodePoint(c);
      sb.writeCharCode(cp == 0 ? 0x20 : cp);
    }
    rows.add(sb.toString().trimRight());
  }
  return rows;
}

List<String> _readScreen(String path, int rows) {
  final lines = File(path).readAsLinesSync().map((l) => l.trimRight()).toList();
  while (lines.length < rows) {
    lines.add('');
  }
  return lines.take(rows).toList();
}

/// Forwards each decoded chunk to the terminal immediately.
class _TerminalSink implements StringSink {
  _TerminalSink(this.t);
  final Terminal t;
  @override
  void write(Object? obj) => t.write('$obj');
  @override
  void writeCharCode(int charCode) => t.write(String.fromCharCode(charCode));
  @override
  void writeAll(Iterable<Object?> objects, [String separator = '']) => t.write(objects.join(separator));
  @override
  void writeln([Object? obj = '']) => t.write('$obj\n');
}

/// Returns human-readable differences between two screens.
List<String> _diff(List<String> want, List<String> got) => [
  for (var i = 0; i < want.length; i++)
    if (want[i] != got[i]) 'row ${i.toString().padLeft(2)}:\n  tmux : ${want[i]}\n  xterm: ${got[i]}',
];

void main() {
  _keyTests();

  final dir = Directory(_fixtures);
  final names = dir.existsSync()
      ? (dir
            .listSync()
            .map((e) => e.path)
            .where((p) => p.endsWith('.raw'))
            .map((p) => p.split('/').last.replaceAll('.raw', ''))
            // Skip incomplete captures (the program exited early).
            .where((n) => File('$_fixtures/$n.end_at').existsSync() && File('$_fixtures/$n.resize_at').existsSync())
            .toList()
          ..sort())
      : <String>[];

  if (names.isEmpty) {
    test('S5 fixtures present', () {}, skip: 'run tests/spikes/s5_capture_tui.sh to record TUI fixtures');
    return;
  }

  final report = <String>[];
  for (final name in names) {
    test('S5 replay $name', () {
      try {
        _replay(name, report);
      } catch (e) {
        final known = _knownDefects[name];
        if (known == null) rethrow;
        report.add('== $name: KNOWN DEFECT: $known\n  ${e.toString().split('\n').first}');
      }
    });
  }

  tearDownAll(() {
    final out = File('$_fixtures/s5-report.txt')..writeAsStringSync(report.join('\n'));
    // ignore: avoid_print
    print('S5 report written to ${out.path}\n${report.where((l) => l.startsWith('==')).join('\n')}');
  });
}

void _replay(String name, List<String> report) {
  final raw = File('$_fixtures/$name.raw').readAsBytesSync();
  final resizeAt = int.parse(File('$_fixtures/$name.resize_at').readAsStringSync().trim());
  final t = Terminal(maxLines: 2000);
  t.resize(100, 30);
  // Decode incrementally so a UTF-8 sequence split at the resize offset
  // is not corrupted, mirroring how the app consumes frames.
  final endAt = int.parse(File('$_fixtures/$name.end_at').readAsStringSync().trim());
  final sink = StringConversionSink.fromStringSink(_TerminalSink(t));
  final dec = const Utf8Decoder(allowMalformed: true).startChunkedConversion(sink);

  dec.add(raw.sublist(0, resizeAt));
  final before = _diff(_readScreen('$_fixtures/$name.before.screen', 30), _screen(t));

  t.resize(80, 24);
  dec.add(raw.sublist(resizeAt, endAt));
  dec.close();
  final after = _diff(_readScreen('$_fixtures/$name.screen', 24), _screen(t));

  report.add(
    '== $name: ${raw.length} bytes; mismatched rows before resize ${before.length}/30, after ${after.length}/24',
  );
  report.addAll(before.map((d) => '  [100x30] $d'));
  report.addAll(after.map((d) => '  [80x24]  $d'));
  // The spike's outcome is the defect list; only a gross failure (most
  // of the screen wrong) fails the test.
  expect(before.length, lessThan(15), reason: before.join('\n'));
  expect(after.length, lessThan(12), reason: after.join('\n'));
}

void _keyTests() {
  group('S5 key input encodings', () {
    String encode(TerminalKey key, {bool ctrl = false, bool appCursor = false}) {
      var out = '';
      final t = Terminal(onOutput: (s) => out += s);
      if (appCursor) t.write('\x1b[?1h');
      t.keyInput(key, ctrl: ctrl);
      return out;
    }

    test('arrows, escape, tab, enter, backspace', () {
      expect(encode(TerminalKey.arrowUp), '\x1b[A');
      expect(encode(TerminalKey.escape), '\x1b');
      expect(encode(TerminalKey.tab), '\t');
      expect(encode(TerminalKey.enter), '\r');
      expect(encode(TerminalKey.backspace), '\x7f');
    });

    // Known defect in xterm 4.0.0: core/input/handler.dart passes
    // appKeypadMode where cursorKeysMode (DECCKM) belongs, so arrow keys
    // ignore application cursor mode. Fix in the fork (ADR-012).
    test('arrows honour application cursor mode (DECCKM)', () {
      expect(encode(TerminalKey.arrowUp, appCursor: true), '\x1bOA');
    }, skip: 'xterm 4.0.0 defect: DECCKM ignored (handler.dart:119)');

    test('ctrl chords', () {
      expect(encode(TerminalKey.keyC, ctrl: true), '\x03');
      expect(encode(TerminalKey.keyD, ctrl: true), '\x04');
      expect(encode(TerminalKey.keyZ, ctrl: true), '\x1a');
    });

    test('bracketed paste wraps pasted text when the app enables it', () {
      var out = '';
      final t = Terminal(onOutput: (s) => out += s);
      t.write('\x1b[?2004h');
      t.paste('ls -la\nrm x');
      expect(out, '\x1b[200~ls -la\nrm x\x1b[201~');
    });
  });
}
