// V3-Endpunkt-Tests für `api.v3.system` und `/v3/`-Pfade.
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
      <(String, String, Future<RestApiResponse> Function(DOCUframeApi))>[
        (
          'versionInfo',
          '/dfapp/v3/versionInfo',
          (api) => api.v3.system.versionInfo(),
        ),
        (
          'appConfig',
          '/dfapp/v3/appConfig',
          (api) => api.v3.system.appConfig(),
        ),
        ('appTheme', '/dfapp/v3/appTheme', (api) => api.v3.system.appTheme()),
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
