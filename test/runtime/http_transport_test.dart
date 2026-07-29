// Unit-Tests für HttpTransport: Methoden-/URI-/Header-/Body-Weitergabe,
// Response-Timeout, TransportResponse-Inhalte und Client-Ownership.

import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/src/runtime/transport/http_transport.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'runtime_test_helpers.dart';

void main() {
  final testUri = Uri.parse('https://server.example:8443/dfapp/v1/ping');

  group('HttpTransport.send', () {
    test('Methode, URI, Header und Body kommen beim Client an', () async {
      http.Request? captured;
      final client = MockClient((request) async {
        captured = request;
        return http.Response('{}', 200);
      });
      final transport = HttpTransport(
        client: client,
        responseTimeout: const Duration(seconds: 5),
      );

      await transport.send(
        method: ApiHttpMethod.post,
        uri: testUri,
        headers: {
          'Content-type': 'application/json; charset=utf-8',
          'x-custom': 'yes',
        },
        body: '{"name":"test"}',
      );

      expect(captured, isNotNull);
      expect(captured!.method, equals('POST'));
      expect(captured!.url, equals(testUri));
      expect(
        captured!.headers['Content-type'],
        equals('application/json; charset=utf-8'),
      );
      expect(captured!.headers['x-custom'], equals('yes'));
      expect(captured!.body, equals('{"name":"test"}'));
    });

    test('alle ApiHttpMethod-Werte werden korrekt abgebildet', () async {
      for (final method in ApiHttpMethod.values) {
        String? capturedMethod;
        final client = MockClient((request) async {
          capturedMethod = request.method;
          return http.Response('', 200);
        });
        final transport = HttpTransport(
          client: client,
          responseTimeout: const Duration(seconds: 5),
        );

        await transport.send(method: method, uri: testUri, headers: {});

        expect(
          capturedMethod,
          equals(method.name.toUpperCase()),
          reason: 'Methode ${method.name} falsch abgebildet',
        );
      }
    });

    test('TransportResponse trägt Status, Header und Bytes', () async {
      final client = MockClient((request) async {
        return http.Response.bytes(
          utf8.encode('{"ok":true}'),
          201,
          headers: {'content-type': 'application/json', 'x-test': 'yes'},
        );
      });
      final transport = HttpTransport(
        client: client,
        responseTimeout: const Duration(seconds: 5),
      );

      final response = await transport.send(
        method: ApiHttpMethod.get,
        uri: testUri,
        headers: {},
      );

      expect(response.statusCode, equals(201));
      expect(response.headers['x-test'], equals('yes'));
      expect(response.bodyBytes, equals(utf8.encode('{"ok":true}')));
      expect(response.body, equals('{"ok":true}'));
    });

    test(
      'Überschreiten des Response-Timeouts wirft TimeoutException',
      () async {
        final client = MockClient((request) async {
          await Future.delayed(const Duration(milliseconds: 300));
          return http.Response('late', 200);
        });
        final transport = HttpTransport(
          client: client,
          responseTimeout: const Duration(milliseconds: 50),
        );

        await expectLater(
          () => transport.send(
            method: ApiHttpMethod.get,
            uri: testUri,
            headers: {},
          ),
          throwsA(isA<TimeoutException>()),
        );
      },
    );
  });

  group('HttpTransport-Client-Ownership', () {
    test('injizierter Client wird von close() NICHT geschlossen', () {
      final tracking = TrackingClient(
        MockClient((request) async => http.Response('', 200)),
      );
      final transport = HttpTransport(
        client: tracking,
        responseTimeout: const Duration(seconds: 5),
      );

      expect(transport.ownsClient, isFalse);
      transport.close();
      transport.close(); // idempotent

      expect(tracking.closed, isFalse);
    });

    test(
      'withDefaultClient besitzt seinen Client und close() ist idempotent',
      () {
        final transport = HttpTransport.withDefaultClient(
          buildRuntimeConfiguration(),
        );

        expect(transport.ownsClient, isTrue);
        transport.close();
        transport.close(); // idempotent, kein Fehler
      },
    );
  });
}
