@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';

import 'package:gsd_restapi/src/http/http_client_factory.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

import '../../fixtures/self_signed_certificate.dart';

void main() {
  // Lokaler HTTPS-Server mit dem selbstsignierten Zertifikat (CN=localhost,
  // SAN `DNS:localhost` und `IP:127.0.0.1`). Keine CA hat es ausgestellt,
  // also ruft der `HttpClient` bei jeder Verbindung den
  // `badCertificateCallback` der Factory.
  late HttpServer server;
  var requestCount = 0;

  setUpAll(() async {
    server =
        await HttpServer.bindSecure(
            InternetAddress.loopbackIPv4,
            0,
            selfSignedServerContext(),
          )
          ..listen((request) {
            requestCount++;
            request.response.write('ok');
            unawaited(request.response.close());
          });
  });

  tearDownAll(() => server.close(force: true));

  setUp(() => requestCount = 0);

  http.Client client({required bool allowSslError}) {
    final client = HttpClientFactory.create(
      const Duration(seconds: 5),
      allowSslError: allowSslError,
    );
    addTearDown(client.close);
    return client;
  }

  final targets = <String, String>{
    'localhost': 'über den Namen',
    '127.0.0.1': 'über die IP-Adresse',
  };
  for (final MapEntry(key: host, value: label) in targets.entries) {
    group('selbstsigniertes Zertifikat $label (https://$host)', () {
      Uri uri() => Uri.parse('https://$host:${server.port}/');

      test('allowSslError: false lehnt es im Handshake ab', () async {
        await expectLater(
          client(allowSslError: false).get(uri()),
          throwsA(isA<HandshakeException>()),
        );
        expect(requestCount, 0);
      });

      test('allowSslError: true akzeptiert es', () async {
        final response = await client(allowSslError: true).get(uri());

        expect(response.statusCode, HttpStatus.ok);
        expect(response.body, 'ok');
        expect(requestCount, 1);
      });
    });
  }
}
