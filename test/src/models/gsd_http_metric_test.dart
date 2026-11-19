import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

void main() {
  final start = DateTime.utc(2026, 10, 26, 12);
  final stop = start.add(const Duration(milliseconds: 1250));

  group('GsdHttpMetric.duration', () {
    final cases = <String, (DateTime?, DateTime?, Duration?)>{
      'Start und Ende': (start, stop, const Duration(milliseconds: 1250)),
      'ohne Ende': (start, null, null),
      'ohne Start': (null, stop, null),
      'ohne beides': (null, null, null),
    };
    for (final MapEntry(key: name, value: (startTime, stopTime, expected))
        in cases.entries) {
      test('$name ergibt $expected', () {
        final metric = GsdHttpMetric(
          path: '/v1/objects',
          method: GsdHttpMethod.get,
          startTime: startTime,
          stopTime: stopTime,
        );

        expect(metric.duration, expected);
      });
    }
  });

  group('GsdHttpMetric.toMap', () {
    test('enthält alle Felder samt Dauer in Millisekunden', () {
      final metric = GsdHttpMetric(
        path: '/v1/objects',
        method: GsdHttpMethod.post,
        startTime: start,
        stopTime: stop,
        responseCode: 201,
        requestPayloadSize: 12,
        responsePayloadSize: 345,
        responseContentType: 'application/json',
      );

      expect(metric.toMap(), {
        'path': '/v1/objects',
        'method': GsdHttpMethod.post,
        'startTime': '2026-10-26T12:00:00.000Z',
        'stopTime': '2026-10-26T12:00:01.250Z',
        'duration': 1250,
        'responseCode': 201,
        'requestPayloadSize': 12,
        'responsePayloadSize': 345,
        'responseContentType': 'application/json',
      });
    });

    test('fehlende Werte stehen als null in der Map', () {
      const metric = GsdHttpMetric(
        path: '/v3/system',
        method: GsdHttpMethod.get,
      );

      expect(metric.toMap(), {
        'path': '/v3/system',
        'method': GsdHttpMethod.get,
        'startTime': null,
        'stopTime': null,
        'duration': null,
        'responseCode': null,
        'requestPayloadSize': null,
        'responsePayloadSize': null,
        'responseContentType': null,
      });
    });
  });
}
