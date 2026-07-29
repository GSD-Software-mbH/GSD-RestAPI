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
      <(String, String, Future<RestApiResponse> Function(DOCUframeApi))>[
        (
          'versionInfo',
          '/dfapp/v2/versionInfo',
          (api) => api.v2.system.versionInfo(),
        ),
        (
          'appConfig',
          '/dfapp/v2/appConfig',
          (api) => api.v2.system.appConfig(),
        ),
        ('appTheme', '/dfapp/v2/appTheme', (api) => api.v2.system.appTheme()),
      ];

  for (final (name, path, call) in cases) {
    test('system.$name ist bodyloses natives GET', () async {
      harness.enqueueSuccess('GET', path);

      final RestApiResponse response = await call(harness.api);

      expect(response.isOk, isTrue);
      harness.expectSingleRequest(method: 'GET', path: path);
    });
  }
}
