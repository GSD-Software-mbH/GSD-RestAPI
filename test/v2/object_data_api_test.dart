import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import 'v2_test_support.dart';

void main() {
  late V2TestHarness harness;

  setUp(() async {
    harness = await V2TestHarness.start();
  });

  tearDown(() => harness.close());

  final cases =
      <
        (
          String,
          String,
          String,
          Future<RestApiResponse> Function(DOCUframeApi, String),
        )
      >[
        (
          'getById',
          '/dfapp/v2/objectdata/byid',
          'objectdata_byid_request.json',
          (api, body) => api.v2.objectData.getById(body: body),
        ),
        (
          'getByQuery',
          '/dfapp/v2/objectdata/byQuery',
          'objectdata_by_query_request.json',
          (api, body) => api.v2.objectData.getByQuery(body: body),
        ),
        (
          'getByParentObject',
          '/dfapp/v2/objectdata/byParentObject',
          'objectdata_by_parent_object_request.json',
          (api, body) => api.v2.objectData.getByParentObject(body: body),
        ),
      ];

  for (final (name, path, fixture, call) in cases) {
    test('objectData.$name übernimmt den DOCUframe-App-Body', () async {
      final String body = loadV2Fixture(fixture);
      harness.enqueueSuccess('POST', path);

      final RestApiResponse response = await call(harness.api, body);

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(method: 'POST', path: path, body: body);
    });
  }

  test(
    'objectData.getById erhält den String "null" der aktuellen App',
    () async {
      final String body = loadV2Fixture(
        'objectdata_byid_null_context_request.json',
      );
      harness.enqueueSuccess('POST', '/dfapp/v2/objectdata/byid');

      final RestApiResponse response = await harness.api.v2.objectData.getById(
        body: body,
      );

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(
        method: 'POST',
        path: '/dfapp/v2/objectdata/byid',
        body: body,
      );
    },
  );

  test(
    'objectData.getByParentObject übernimmt den minimalen App-Body',
    () async {
      final String body = loadV2Fixture(
        'objectdata_by_parent_object_minimal_request.json',
      );
      harness.enqueueSuccess('POST', '/dfapp/v2/objectdata/byParentObject');

      final RestApiResponse response = await harness.api.v2.objectData
          .getByParentObject(body: body);

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(
        method: 'POST',
        path: '/dfapp/v2/objectdata/byParentObject',
        body: body,
      );
    },
  );
}
