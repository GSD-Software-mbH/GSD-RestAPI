@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
// V3-Endpunkt-Tests für `api.v3.objectData` und `/v3/`-Pfade.
//
// Die Tests laufen gegen den lokalen Mock-Server und prüfen den
// Client-Vertrag (Pfad, Verb, Body, Rückgabe, kein v1/multi).

import 'package:test/test.dart';

import 'v3_test_support.dart';

void main() {
  late V3TestHarness harness;

  setUp(() async {
    harness = await V3TestHarness.start();
  });

  tearDown(() => harness.close());

  final data = [
    {'className': 'Dokument', 'classID': 100, 'values': <Object?>[]},
  ];

  final cases =
      <(String, String, String, Future<List<Object?>> Function(GsdApiClient))>[
        (
          'getById',
          '/dfapp/v3/objectdata/byid',
          'objectdata_byid_request.json',
          (api) => api.v3.objectData.getById([
            const GsdObjectsByIdRequest(
              classId: 100,
              ids: [200, 201],
              context: 'edit',
            ),
          ]),
        ),
        (
          'getByQuery',
          '/dfapp/v3/objectdata/byQuery',
          'objectdata_by_query_request.json',
          (api) => api.v3.objectData.getByQuery([
            const GsdObjectsByQueryRequest(
              className: 'Dokument',
              query: 'Name=Test',
            ),
          ]),
        ),
        (
          'getByParentObject',
          '/dfapp/v3/objectdata/byParentObject',
          'objectdata_by_parent_object_request.json',
          (api) => api.v3.objectData.getByParentObject([
            const GsdObjectsByParentRequest(
              parentOid: 'PARENT-OID',
              member: 'Dokumente',
              context: 'edit',
              idList: true,
              query: 'Status=Offen',
              order: 'Name ASC',
              seFulltext: 'rechnung',
              seFulltextStem: true,
              seTextContent: 'rechnung',
              seTextContentStem: true,
            ),
          ]),
        ),
      ];

  for (final (name, path, fixture, call) in cases) {
    test('objectData.$name übernimmt den DOCUframe-App-Body', () async {
      harness.enqueueData('POST', path, data);

      final blocks = await call(harness.api);

      expect(blocks, data);
      harness.expectSingleRequest(
        method: 'POST',
        path: path,
        body: loadV3Fixture(fixture),
      );
    });
  }

  test(
    'objectData.getById erhält den String "null" der aktuellen App',
    () async {
      harness.enqueueData('POST', '/dfapp/v3/objectdata/byid', data);

      await harness.api.v3.objectData.getById([
        const GsdObjectsByIdRequest(classId: 100, ids: [200]),
      ]);

      harness.expectSingleRequest(
        method: 'POST',
        path: '/dfapp/v3/objectdata/byid',
        body: loadV3Fixture('objectdata_byid_null_context_request.json'),
      );
    },
  );

  test(
    'objectData.getByParentObject übernimmt den minimalen App-Body',
    () async {
      harness.enqueueData('POST', '/dfapp/v3/objectdata/byParentObject', [
        {'ids': '100,200,1|100,201,4'},
      ]);

      final blocks = await harness.api.v3.objectData.getByParentObject([
        const GsdObjectsByParentRequest(
          parentOid: 'PARENT-OID',
          member: 'Dokumente',
          idList: true,
        ),
      ]);

      expect(blocks, [
        {'ids': '100,200,1|100,201,4'},
      ]);
      harness.expectSingleRequest(
        method: 'POST',
        path: '/dfapp/v3/objectdata/byParentObject',
        body: loadV3Fixture(
          'objectdata_by_parent_object_minimal_request.json',
        ),
      );
    },
  );
}
