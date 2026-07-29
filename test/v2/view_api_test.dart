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
          'load',
          '/dfapp/v2/view/load',
          'view_load_request.json',
          (api, body) => api.v2.view.load(body: body),
        ),
        (
          'action',
          '/dfapp/v2/view/action',
          'view_action_request.json',
          (api, body) => api.v2.view.action(body: body),
        ),
      ];

  for (final (name, path, fixture, call) in cases) {
    test('view.$name übernimmt den DOCUframe-App-Body', () async {
      final String body = loadV2Fixture(fixture);
      harness.enqueueSuccess('POST', path);

      final RestApiResponse response = await call(harness.api, body);

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(method: 'POST', path: path, body: body);
    });
  }
}
