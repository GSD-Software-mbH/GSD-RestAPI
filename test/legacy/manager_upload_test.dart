// ignore_for_file: deprecated_member_use_from_same_package
//
// Charakterisierungstests: 3-Schritt Upload-Flow (uploadFile) und
// Multipart-Form der zweiten Anfrage.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

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
    await server.start();
  });

  tearDown(() async {
    for (final m in managers) {
      m.dispose();
    }
    managers.clear();
    await server.close();
  });

  test(
    'uploadFile(): 3 Schritte in Reihenfolge - GET uploadId, POST multipart, '
    'PATCH mit fetchToObject - und liefert die PATCH-Antwort zurück',
    () async {
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
      final file = RestApiUploadFile.fromBytes(
        name: 'test.txt',
        bytes: utf8.encode('hello world'),
      );

      final response = await manager.uploadFile(file);

      expect(response.isOk, isTrue);
      expect(
        jsonDecode(response.httpResponse.body)['data']['objectId'],
        equals('DOC-1'),
      );

      expect(server.requests, hasLength(3));
      expect(server.requests[0].method, equals('GET'));
      expect(server.requests[0].path, equals('/dfapp/v1/uploadFile'));
      expect(server.requests[1].method, equals('POST'));
      expect(server.requests[1].path, equals('/dfapp/v1/uploadFile/UP-1'));
      expect(server.requests[2].method, equals('PATCH'));
      expect(server.requests[2].path, equals('/dfapp/v1/uploadFile/UP-1'));
    },
  );

  test(
    'PATCH-Schritt: replaceOID wird nur als Query-Parameter gesetzt, wenn nicht-leer; '
    'ist er leer, bleibt wegen des "leere Query-Map"-Verhaltens ein Query-String mit '
    'einem alleinstehenden "?" übrig',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'UP-2'}),
      );
      server.enqueueJson(
        'POST',
        '/dfapp/v1/uploadFile/UP-2',
        body: v1Envelope(data: {}),
      );
      server.enqueueJson(
        'PATCH',
        '/dfapp/v1/uploadFile/UP-2',
        body: v1Envelope(data: {}),
      );

      final manager = newManager(buildLegacyConfig(server));
      final file = RestApiUploadFile.fromBytes(
        name: 'a.txt',
        bytes: utf8.encode('x'),
      );

      await manager.uploadFile(file);

      final patchReq = server.requests.last;
      expect(patchReq.query, isEmpty);
    },
  );

  test(
    'PATCH-Schritt: replaceOID wird als Query-Parameter übernommen, wenn angegeben',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'UP-3'}),
      );
      server.enqueueJson(
        'POST',
        '/dfapp/v1/uploadFile/UP-3',
        body: v1Envelope(data: {}),
      );
      server.enqueueJson(
        'PATCH',
        '/dfapp/v1/uploadFile/UP-3',
        body: v1Envelope(data: {}),
      );

      final manager = newManager(buildLegacyConfig(server));
      final file = RestApiUploadFile.fromBytes(
        name: 'a.txt',
        bytes: utf8.encode('x'),
      );

      await manager.uploadFile(file, replaceOID: 'OLD-DOC');

      final patchReq = server.requests.last;
      expect(patchReq.query, equals({'replaceOID': 'OLD-DOC'}));
    },
  );

  test(
    'fetchToObject:false liefert die uploadId-Antwort zurück und überspringt den '
    'PATCH-Schritt, führt aber weiterhin den POST-Upload-Schritt aus',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'UP-4'}),
      );
      server.enqueueJson(
        'POST',
        '/dfapp/v1/uploadFile/UP-4',
        body: v1Envelope(data: {}),
      );

      final manager = newManager(buildLegacyConfig(server));
      final file = RestApiUploadFile.fromBytes(
        name: 'a.txt',
        bytes: utf8.encode('x'),
      );

      final response = await manager.uploadFile(file, fetchToObject: false);

      expect(response.isOk, isTrue);
      expect(
        jsonDecode(response.httpResponse.body)['data']['uploadId'],
        equals('UP-4'),
      );
      expect(server.requests, hasLength(2));
      expect(server.requests.map((r) => r.method), equals(['GET', 'POST']));
    },
  );

  test(
    'Multipart-Request: Feldname ist der leere String, Content-Type wird von '
    'MultipartRequest beim Senden auf "multipart/form-data; boundary=..." '
    'überschrieben - DISKREPANZ zur Absicht des Codes, der per _getHeader('
    'contentType: "application/x-www-form-urlencoded") einen anderen Content-Type '
    'setzen wollte',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'UP-5'}),
      );
      server.enqueueJson(
        'POST',
        '/dfapp/v1/uploadFile/UP-5',
        body: v1Envelope(data: {}),
      );
      server.enqueueJson(
        'PATCH',
        '/dfapp/v1/uploadFile/UP-5',
        body: v1Envelope(data: {}),
      );

      final manager = newManager(
        buildLegacyConfig(server, sessionId: 'sess-x'),
      );
      final file = RestApiUploadFile.fromBytes(
        name: 'test.txt',
        bytes: utf8.encode('hello world'),
      );

      await manager.uploadFile(file);

      final uploadReq = server.requests[1];
      // NICHT application/x-www-form-urlencoded, sondern multipart/form-data.
      expect(
        uploadReq.header('content-type'),
        startsWith('multipart/form-data; boundary='),
      );
      // appkey/sessionid Header bleiben trotzdem erhalten.
      expect(uploadReq.header('appkey'), equals('TEST-APP-KEY'));
      expect(uploadReq.header('sessionid'), equals('sess-x'));

      // Der multipart-Body enthält den leeren Feldnamen `name=""` und den
      // Dateiinhalt.
      expect(uploadReq.body, contains('name=""'));
      expect(uploadReq.body, contains('filename="test.txt"'));
      expect(uploadReq.body, contains('hello world'));
    },
  );

  test(
    'uploadFileWithController(): liefert Ergebnis über den Controller nach vollständigem Ablauf',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'UP-6'}),
      );
      server.enqueueJson(
        'POST',
        '/dfapp/v1/uploadFile/UP-6',
        body: v1Envelope(data: {}),
      );
      server.enqueueJson(
        'PATCH',
        '/dfapp/v1/uploadFile/UP-6',
        body: v1Envelope(data: {'objectId': 'DOC-6'}),
      );

      final manager = newManager(buildLegacyConfig(server));
      final file = RestApiUploadFile.fromBytes(
        name: 'a.txt',
        bytes: utf8.encode('x'),
      );

      final controller = await manager.uploadFileWithController(file);
      expect(controller.uploadId, equals('UP-6'));

      final response = await controller.result;
      expect(response.isOk, isTrue);
      expect(
        jsonDecode(response.httpResponse.body)['data']['objectId'],
        equals('DOC-6'),
      );
    },
  );
}
