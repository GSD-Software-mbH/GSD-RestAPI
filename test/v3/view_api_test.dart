// V3-Endpunkt-Tests für `api.v3.view` und `/v3/`-Pfade.
//
// Die Tests laufen gegen den lokalen Mock-Server und prüfen den
// Client-Vertrag (Pfad, Verb, Body, kein v1/multi).

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import 'v3_test_support.dart';

void main() {
  late V3TestHarness harness;

  setUp(() async {
    harness = await V3TestHarness.start();
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
          '/dfapp/v3/view/load',
          'view_load_request.json',
          (api, body) => api.v3.view.load(body: body),
        ),
        (
          'action',
          '/dfapp/v3/view/action',
          'view_action_request.json',
          (api, body) => api.v3.view.action(body: body),
        ),
      ];

  for (final (name, path, fixture, call) in cases) {
    test('view.$name übernimmt den DOCUframe-App-Body', () async {
      final String body = loadV3Fixture(fixture);
      harness.enqueueSuccess('POST', path);

      final RestApiResponse response = await call(harness.api, body);

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(method: 'POST', path: path, body: body);
    });
  }
}
