// Regression tests for the fixes in the vendored xterm fork (third_party/xterm).
import 'package:flutter_test/flutter_test.dart';
import 'package:xterm/xterm.dart';

void main() {
  test('reverse index then scroll-region line feeds keep every line attached', () {
    // Minimal reproducer delta-debugged from Codex's TUI output: in 4.0.0
    // this asserted ('attached') in debug builds and corrupted lines in
    // release builds.
    final t = Terminal(maxLines: 2000);
    t.resize(100, 30);
    t.write('\x1bM\x1b[1;7r\r\n\r\n\r\n\r\n\r\n\r\n\r\n');
    final lines = t.buffer.lines;
    for (var i = 0; i < lines.length; i++) {
      expect(lines[i].attached, isTrue, reason: 'line $i detached');
      expect(lines[i].index, i, reason: 'line $i has a stale index');
    }
  });

  test('arrow keys honour application cursor mode (DECCKM)', () {
    var out = '';
    final t = Terminal(onOutput: (s) => out += s);
    t.keyInput(TerminalKey.arrowUp);
    expect(out, '\x1b[A');
    out = '';
    t.write('\x1b[?1h');
    t.keyInput(TerminalKey.arrowUp);
    expect(out, '\x1bOA');
  });
}
