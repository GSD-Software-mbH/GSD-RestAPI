import 'package:gsd_restapi/src/v1/extensions.dart';
import 'package:test/test.dart';

void main() {
  group('DurationIsoFormat.toISOFormatString', () {
    final cases = <(Duration, String)>[
      (Duration.zero, 'P'),
      (const Duration(minutes: 15), 'PT0H15M0S'),
      (const Duration(hours: 2), 'PT2H0M0S'),
      (const Duration(seconds: 30), 'PT0H0M30S'),
      (const Duration(days: 1), 'P1D'),
      (const Duration(days: 45), 'P45D'),
      (const Duration(days: 1, hours: 2, minutes: 30), 'P1DT2H30M0S'),
      (const Duration(minutes: 1, milliseconds: 500), 'PT0H1M0S'),
    ];
    for (final (duration, expected) in cases) {
      test('$duration → $expected', () {
        expect(duration.toISOFormatString(), expected);
      });
    }
  });

  group('DateTimeExtention.toISOFormatString', () {
    test('schreibt UTC ohne Mikrosekunden', () {
      final date = DateTime.utc(2026, 7, 20, 10, 30, 0, 123, 456);

      expect(date.toISOFormatString(), '2026-07-20T10:30:00.123Z');
    });

    test('lässt lokale Zeit mit utc: false lokal', () {
      final date = DateTime(2026, 7, 20, 10, 30);

      expect(date.toISOFormatString(utc: false), '2026-07-20T10:30:00.000');
    });
  });
}
