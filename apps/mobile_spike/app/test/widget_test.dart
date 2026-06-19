import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:prw_spike/main.dart';

void main() {
  testWidgets('shows spike actions', (tester) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('prw/probe'), (call) async => 'test');
    await tester.pumpWidget(const SpikeApp());
    expect(find.text('Check device key'), findsOneWidget);
    expect(find.text('WSS relay'), findsOneWidget);
  });
}
