// ignore_for_file: deprecated_member_use_from_same_package
//
// Regressionstests: `allowSslError` muss für ALLE Requests des
// Legacy-Managers gelten, nicht nur für die über `_http` gebündelten.
//
// Hintergrund: getFile, getPreview und der Multipart-Schritt von uploadFile
// liefen über das globale `http.get` bzw. `request.send()` und damit über
// einen eigenen HttpClient ohne badCertificateCallback. Bei Servern mit
// internem oder selbstsigniertem Zertifikat funktionierte der Login,
// Download und Vorschau scheiterten aber mit
// `HandshakeException: CERTIFICATE_VERIFY_FAILED`.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import '../fixtures/self_signed_certificate.dart';
import 'legacy_test_server.dart';

void main() {
  ensureLegacyCryptoTestEnvironment();

  late LegacyTestServer server;
  final managers = <RestApiDOCUframeManager>[];

  RestApiDOCUframeManager newManager(RestApiDOCUframeConfig config) {
    final manager = RestApiDOCUframeManager(config: config);
    managers.add(manager);
    return manager;
  }

  setUp(() async {
    HttpOverrides.global = null;
    server = LegacyTestServer();
    await server.start(securityContext: selfSignedServerContext());
  });

  tearDown(() async {
    for (final m in managers) {
      m.dispose();
    }
    managers.clear();
    await server.close();
  });

  group('allowSslError: true akzeptiert ein selbstsigniertes Zertifikat', () {
    test('getFile() lädt die Datei', () async {
      server.enqueue(
        'GET',
        '/dfapp/v1/file/DOC-1',
        (_) => ScriptedResponse('DATEI-INHALT'),
      );
      final manager = newManager(buildLegacyConfig(server));

      final response = await manager.getFile('DOC-1');

      expect(response.isOk, isTrue);
      expect(response.httpResponse.body, equals('DATEI-INHALT'));
    });

    test('getPreview() lädt die Vorschau', () async {
      server.enqueue(
        'GET',
        '/dfapp/v1/preview/200x150.jpg/keep-ratio/DOC-1/1',
        (_) => ScriptedResponse('VORSCHAU'),
      );
      final manager = newManager(buildLegacyConfig(server));

      final bytes = await manager.getPreview('DOC-1', '200x150.jpg', page: 1);

      expect(bytes, equals(utf8.encode('VORSCHAU')));
    });

    test('uploadFile() sendet auch den Multipart-Schritt', () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'UP-1'}),
      );
      server.enqueueJson(
        'POST',
        '/dfapp/v1/uploadFile/UP-1',
        body: v1Envelope(data: {'received': true}),
      );
      server.enqueueJson(
        'PATCH',
        '/dfapp/v1/uploadFile/UP-1',
        body: v1Envelope(data: {'objectId': 'DOC-1'}),
      );
      final manager = newManager(buildLegacyConfig(server));

      final response = await manager.uploadFile(
        RestApiUploadFile.fromBytes(
          name: 'test.txt',
          bytes: utf8.encode('hello world'),
        ),
      );

      expect(response.isOk, isTrue);
      expect(
        server.requests.map((r) => r.method),
        equals(['GET', 'POST', 'PATCH']),
      );
    });

    test('checkServiceWithUri() erreicht den Service', () async {
      server.enqueueJson(
        'GET',
        '/dfapp/_CheckService',
        body: v1Envelope(data: {'applicationName': 'DOCUframe'}),
      );

      final response = await RestApiDOCUframeManager.checkServiceWithUri(
        Uri.parse('${server.baseUrl}/dfapp/_CheckService'),
        allowSslError: true,
      );

      expect(response.applicationName, equals('DOCUframe'));
    });
  });

  group('allowSslError: false lehnt ein selbstsigniertes Zertifikat ab', () {
    test('getFile() wirft HandshakeException', () async {
      final manager = newManager(
        buildLegacyConfig(server, allowSslError: false),
      );

      await expectLater(
        manager.getFile('DOC-1'),
        throwsA(isA<HandshakeException>()),
      );
    });

    test(
      'checkServiceWithUri() ohne allowSslError wirft HandshakeException',
      () async {
        await expectLater(
          RestApiDOCUframeManager.checkServiceWithUri(
            Uri.parse('${server.baseUrl}/dfapp/_CheckService'),
          ),
          throwsA(isA<HandshakeException>()),
        );
      },
    );
  });
}
