// V3-Endpunkt-Tests für `api.v3.model` und `/v3/`-Pfade.
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

  test(
    'model.structure übernimmt den realen DOCUframe-App-Request unverändert',
    () async {
      final String body = loadV3Fixture('model_structure_request.json');
      harness.enqueueSuccess('POST', '/dfapp/v3/model/structure');

      final RestApiResponse response = await harness.api.executeWithPriority(
        () => harness.api.v3.model.structure(body: body),
        RequestPriority.low,
      );

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(
        method: 'POST',
        path: '/dfapp/v3/model/structure',
        body: body,
      );
    },
  );

  test('model.structure akzeptiert den Übergangsbody optional', () async {
    harness.enqueueSuccess('POST', '/dfapp/v3/model/structure');

    final RestApiResponse response = await harness.api.v3.model.structure();

    expect(response.isOk, isTrue);
    harness.expectSingleRequest(
      method: 'POST',
      path: '/dfapp/v3/model/structure',
    );
  });
}
