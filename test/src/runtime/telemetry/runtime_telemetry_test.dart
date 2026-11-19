// Unit-Tests für RuntimeTelemetry: Events, Metriken und Redaction von
// sessionid/appkey-Headern sowie Request-/Response-Bodies.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/runtime_events.dart';
import 'package:gsd_restapi/src/runtime/telemetry/runtime_telemetry.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

void main() {
  final testUri = Uri.parse('https://server.example:8443/dfapp/v1/ping');

  late List<String> logs;
  late List<GsdHttpMetric> metrics;
  late RuntimeTelemetry telemetry;

  setUp(() {
    logs = [];
    metrics = [];
    telemetry = RuntimeTelemetry(
      events: RuntimeEvents()
        ..logs.listen(logs.add)
        ..httpMetrics.listen(metrics.add),
    );
  });

  TransportResponse buildResponse({
    int statusCode = 200,
    String body = '{"ok":true}',
  }) {
    return TransportResponse(
      statusCode: statusCode,
      headers: const {'content-type': 'application/json'},
      bodyBytes: Uint8List.fromList(utf8.encode(body)),
      body: body,
    );
  }

  group('RuntimeTelemetry-Events', () {
    test('requestStarted emittiert Log mit operationId, Methode und URI', () {
      telemetry.requestStarted(
        operationId: 'test.op',
        method: GsdHttpMethod.get,
        uri: testUri,
      );

      expect(logs, hasLength(1));
      expect(logs.single, contains('Request started'));
      expect(logs.single, contains('operationId=test.op'));
      expect(logs.single, contains('method=GET'));
      expect(logs.single, contains(testUri.toString()));
    });

    test('succeeded emittiert Log mit durationMs und statusCode', () {
      telemetry
          .requestStarted(
            operationId: 'test.op',
            method: GsdHttpMethod.get,
            uri: testUri,
          )
          .succeeded(buildResponse(statusCode: 201));

      expect(logs, hasLength(2));
      expect(logs.last, contains('Request succeeded'));
      expect(logs.last, contains('operationId=test.op'));
      expect(logs.last, contains('durationMs='));
      expect(logs.last, contains('statusCode=201'));
    });

    test('succeeded zeichnet die Metrik mit Legacy-Feldern auf', () {
      telemetry
          .requestStarted(
            operationId: 'test.op',
            method: GsdHttpMethod.post,
            uri: testUri,
            body: '{"name":"x"}',
          )
          .succeeded(buildResponse());

      expect(metrics, hasLength(1));
      final metric = metrics.single;
      expect(metric.path, equals('/dfapp/v1/ping'));
      expect(metric.method, equals(GsdHttpMethod.post));
      expect(metric.responseCode, equals(200));
      expect(metric.requestPayloadSize, equals('{"name":"x"}'.length));
      expect(metric.responsePayloadSize, equals('{"ok":true}'.length));
      expect(metric.responseContentType, equals('application/json'));
      expect(metric.duration, isNotNull);
    });

    test('failed emittiert Log und Metrik ohne responseCode', () {
      telemetry
          .requestStarted(
            operationId: 'test.op',
            method: GsdHttpMethod.get,
            uri: testUri,
          )
          .failed(TimeoutException('zu langsam'));

      expect(logs.last, contains('Request failed'));
      expect(logs.last, contains('operationId=test.op'));
      expect(logs.last, contains('durationMs='));
      // Metrik wird wie im Legacy-Manager (finally) auch im Fehlerfall
      // aufgezeichnet, dann ohne responseCode.
      expect(metrics, hasLength(1));
      expect(metrics.single.responseCode, isNull);
    });

    test('Ausgang wird nur einmal gemeldet (weitere Aufrufe sind No-Ops)', () {
      telemetry.requestStarted(
          operationId: 'test.op',
          method: GsdHttpMethod.get,
          uri: testUri,
        )
        ..succeeded(buildResponse())
        ..succeeded(buildResponse())
        ..failed(Exception('spät'));

      expect(metrics, hasLength(1));
      expect(logs, hasLength(2)); // started + succeeded
    });

    test(
      'HEAD hat keine Legacy-GsdHttpMethod-Entsprechung: Logs ja, Metrik nein',
      () {
        telemetry
            .requestStarted(
              operationId: 'test.head',
              method: GsdHttpMethod.head,
              uri: testUri,
            )
            .succeeded(buildResponse());

        expect(logs, hasLength(2));
        expect(metrics, isEmpty);
      },
    );

    test('ohne Ereignisse stürzt nichts ab', () {
      final silent = RuntimeTelemetry();

      silent
          .requestStarted(
            operationId: 'test.op',
            method: GsdHttpMethod.get,
            uri: testUri,
          )
          .succeeded(buildResponse());
    });
  });

  group('Redaction', () {
    test('sessionid- und appkey-Werte erscheinen nie im Log', () {
      telemetry.requestStarted(
        operationId: 'test.op',
        method: GsdHttpMethod.get,
        uri: testUri,
        headers: {
          'Content-type': 'application/json; charset=utf-8',
          'appkey': 'SECRET-APP-KEY',
          'sessionid': 'secret-session-id',
        },
      );

      expect(logs.single, isNot(contains('SECRET-APP-KEY')));
      expect(logs.single, isNot(contains('secret-session-id')));
      expect(logs.single, contains('[REDACTED len=14]')); // SECRET-APP-KEY
      expect(logs.single, contains('[REDACTED len=17]')); // secret-session-id
      // Nicht-sensible Header bleiben lesbar.
      expect(logs.single, contains('application/json'));
    });

    test('Redaction ist case-insensitive', () {
      telemetry.requestStarted(
        operationId: 'test.op',
        method: GsdHttpMethod.get,
        uri: testUri,
        headers: {'SessionId': 'secret-session-id', 'APPKEY': 'SECRET'},
      );

      expect(logs.single, isNot(contains('secret-session-id')));
      expect(logs.single, isNot(contains('SECRET')));
    });

    test('Request-Body wird nie wörtlich geloggt, nur die Länge', () {
      const body = '{"password":"streng-geheim"}';

      telemetry.requestStarted(
        operationId: 'test.op',
        method: GsdHttpMethod.post,
        uri: testUri,
        body: body,
      );

      expect(logs.single, isNot(contains('streng-geheim')));
      expect(logs.single, contains('bodyLength=${body.length}'));
    });

    test('Response-Body wird nie wörtlich geloggt, nur die Länge', () {
      final tracker = telemetry.requestStarted(
        operationId: 'test.op',
        method: GsdHttpMethod.get,
        uri: testUri,
      );

      const responseBody = '{"secret":"vertraulich"}';
      tracker.succeeded(buildResponse(body: responseBody));

      expect(logs.last, isNot(contains('vertraulich')));
      expect(
        logs.last,
        contains('bodyLength=${utf8.encode(responseBody).length}'),
      );
    });

    test('redactHeaders lässt null-Header als leere Map zu', () {
      expect(telemetry.redactHeaders(null), isEmpty);
    });

    test('Query-WERTE erscheinen nie im Log, Schlüssel bleiben lesbar', () {
      final uriWithQuery = Uri.parse(
        'https://server.example:8443/dfapp/v1/objects/Vorgang'
        '?query=geheime%20kundennummer&serialization=vertraulich',
      );

      telemetry
          .requestStarted(
            operationId: 'test.op',
            method: GsdHttpMethod.get,
            uri: uriWithQuery,
          )
          .succeeded(buildResponse());

      for (final log in logs) {
        expect(log, isNot(contains('geheime')));
        expect(log, isNot(contains('kundennummer')));
        expect(log, isNot(contains('vertraulich')));
      }
      // Pfad und Query-Schlüssel bleiben zur Diagnose erhalten.
      expect(logs.first, contains('/dfapp/v1/objects/Vorgang'));
      expect(logs.first, contains('query=[REDACTED]'));
      expect(logs.first, contains('serialization=[REDACTED]'));
      expect(logs.last, contains('query=[REDACTED]'));
    });

    test('qb64-Query-Wert wird ebenfalls redigiert', () {
      final uriWithQb64 = Uri.parse(
        'https://server.example:8443/dfapp/v1/object/OID1'
        '?qb64=a2xhc3NlPWdlaGVpbQ',
      );

      telemetry
          .requestStarted(
            operationId: 'test.op',
            method: GsdHttpMethod.get,
            uri: uriWithQb64,
          )
          .failed(Exception('fehler'));

      for (final log in logs) {
        expect(log, isNot(contains('a2xhc3NlPWdlaGVpbQ')));
      }
      expect(logs.first, contains('qb64=[REDACTED]'));
      expect(logs.last, contains('qb64=[REDACTED]'));
    });

    test('URI ohne Query bleibt unverändert im Log', () {
      telemetry.requestStarted(
        operationId: 'test.op',
        method: GsdHttpMethod.get,
        uri: testUri,
      );

      expect(logs.single, contains('uri=$testUri '));
    });
  });

  group('failed mit vorhandener HTTP-Antwort (Dekodier-Fehler)', () {
    test('Metrik und Log erhalten den Statuscode der Antwort', () {
      telemetry
          .requestStarted(
            operationId: 'test.op',
            method: GsdHttpMethod.get,
            uri: testUri,
          )
          .failed(
            Exception('mapping-fehler'),
            response: buildResponse(),
          );

      expect(logs.last, contains('Request failed'));
      expect(logs.last, contains('statusCode=200'));
      expect(metrics, hasLength(1));
      expect(metrics.single.responseCode, equals(200));
      expect(metrics.single.responsePayloadSize, equals('{"ok":true}'.length));
    });
  });
}
