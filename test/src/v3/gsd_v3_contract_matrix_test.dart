@TestOn('vm')
library;

// Contract-Matrix je `operationId` der V3-JSON-Endpunkte: Pfad, Fehlerstatus
// im Umschlag und eine Antwort, deren `data` nicht zur Rückgabe passt.
// Pfad, Body und Rückgabe im Erfolgsfall prüfen die Tests je Gruppe.

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v3_test_support.dart';

/// Ein V3-Endpunkt: Verb, Pfad, Aufruf und ein `data`, das nicht zur
/// Rückgabe passt.
typedef _Endpoint = ({
  String method,
  String path,
  Future<Object?> Function(GsdApiClient api) call,
  Object? wrongData,
});

final _endpoints = <String, _Endpoint>{
  'v3.model.structure': (
    method: 'POST',
    path: '/dfapp/v3/model/structure',
    call: (api) => api.v3.model.structure(const []),
    wrongData: <String, Object?>{},
  ),
  'v3.system.versionInfo': (
    method: 'GET',
    path: '/dfapp/v3/versionInfo',
    call: (api) => api.v3.system.versionInfo(),
    wrongData: <Object?>[],
  ),
  'v3.system.appConfig': (
    method: 'GET',
    path: '/dfapp/v3/appConfig',
    call: (api) => api.v3.system.appConfig(),
    wrongData: <String, Object?>{},
  ),
  'v3.system.appTheme': (
    method: 'GET',
    path: '/dfapp/v3/appTheme',
    call: (api) => api.v3.system.appTheme(),
    wrongData: null,
  ),
  'v3.view.load': (
    method: 'POST',
    path: '/dfapp/v3/view/load',
    call: (api) => api.v3.view.load(const []),
    wrongData: 'kein Array',
  ),
  'v3.objectData.getById': (
    method: 'POST',
    path: '/dfapp/v3/objectdata/byid',
    call: (api) => api.v3.objectData.getById(const []),
    wrongData: <String, Object?>{},
  ),
  'v3.objectData.getByQuery': (
    method: 'POST',
    path: '/dfapp/v3/objectdata/byQuery',
    call: (api) => api.v3.objectData.getByQuery(const []),
    wrongData: <String, Object?>{},
  ),
  'v3.objectData.getByParentObject': (
    method: 'POST',
    path: '/dfapp/v3/objectdata/byParentObject',
    call: (api) => api.v3.objectData.getByParentObject(const []),
    wrongData: <String, Object?>{},
  ),
};

void main() {
  late V3TestHarness harness;

  setUp(() async {
    harness = await V3TestHarness.start();
  });

  tearDown(() => harness.close());

  for (final MapEntry(key: operationId, value: endpoint)
      in _endpoints.entries) {
    group(operationId, () {
      test('ein Fehlerstatus im Umschlag wirft GsdServerException', () async {
        harness.server.enqueueJson(
          endpoint.method,
          endpoint.path,
          body: TestServer.v1Envelope(
            internalStatus: '500',
            statusMessage: 'kaputt',
          ),
        );

        await expectLater(
          endpoint.call(harness.api),
          throwsA(
            isA<GsdServerException>()
                .having((e) => e.internalStatus, 'internalStatus', '500')
                .having((e) => e.statusMessage, 'statusMessage', 'kaputt'),
          ),
        );
      });

      test('data in falscher Form wirft GsdParseException an "data"', () async {
        harness.enqueueData(endpoint.method, endpoint.path, endpoint.wrongData);

        await expectLater(
          endpoint.call(harness.api),
          throwsA(
            isA<GsdParseException>()
                .having((e) => e.operationId, 'operationId', operationId)
                .having((e) => e.path, 'path', 'data'),
          ),
        );
      });
    });
  }

  group('v3.view.action', () {
    Future<Map<String, Object?>> action(GsdApiClient api) => api.v3.view.action(
      const GsdViewActionRequest(actionOid: '4TOF', tryCount: 0),
    );

    test('ein Fehlerstatus im Umschlag wirft GsdServerException', () async {
      harness.server.enqueueJson(
        'POST',
        '/dfapp/v3/view/action',
        body: TestServer.v1Envelope(internalStatus: '500'),
      );

      await expectLater(
        action(harness.api),
        throwsA(isA<GsdServerException>()),
      );
    });

    test('ein Body ohne JSON wirft GsdParseException', () async {
      harness.server.enqueue(
        'POST',
        '/dfapp/v3/view/action',
        (_) => ScriptedResponse('<html>'),
      );

      await expectLater(
        action(harness.api),
        throwsA(
          isA<GsdParseException>().having(
            (e) => e.operationId,
            'operationId',
            'v3.view.action',
          ),
        ),
      );
    });
  });

  group('v3.file.get', () {
    test('ein HTTP-Fehlerstatus wirft GsdHttpException', () async {
      harness.server.enqueue(
        'GET',
        '/dfapp/v3/file/1PTF',
        (_) => ScriptedResponse('', statusCode: 503),
      );

      await expectLater(
        harness.api.v3.file.get('1PTF'),
        throwsA(
          isA<GsdHttpException>().having((e) => e.statusCode, 'status', 503),
        ),
      );
    });
  });
}
