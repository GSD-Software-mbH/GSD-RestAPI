import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import 'v2_test_support.dart';

void main() {
  late V2TestHarness harness;

  setUp(() async {
    harness = await V2TestHarness.start();
  });

  tearDown(() => harness.close());

  test(
    'model.structure übernimmt den realen DOCUframe-App-Request unverändert',
    () async {
      final String body = loadV2Fixture('model_structure_request.json');
      harness.enqueueSuccess('POST', '/dfapp/v2/model/structure');

      final RestApiResponse response = await harness.api.executeWithPriority(
        () => harness.api.v2.model.structure(body: body),
        RequestPriority.low,
      );

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(
        method: 'POST',
        path: '/dfapp/v2/model/structure',
        body: body,
      );
    },
  );

  test('model.structure akzeptiert den Übergangsbody optional', () async {
    harness.enqueueSuccess('POST', '/dfapp/v2/model/structure');

    final RestApiResponse response = await harness.api.v2.model.structure();

    expect(response.isOk, isTrue);
    harness.expectSingleRequest(
      method: 'POST',
      path: '/dfapp/v2/model/structure',
    );
  });
}
