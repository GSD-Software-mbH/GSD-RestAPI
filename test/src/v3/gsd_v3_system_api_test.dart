@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
// V3-Endpunkt-Tests für `api.v3.system` und `/v3/`-Pfade.
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

  final cases =
      <(String, String, Object?, Future<Object?> Function(GsdApiClient))>[
        (
          'versionInfo',
          '/dfapp/v3/versionInfo',
          {'version': '9.1', 'build': 42},
          (api) => api.v3.system.versionInfo(),
        ),
        (
          'appConfig',
          '/dfapp/v3/appConfig',
          [
            {'appName': 'GSD-DFApp', 'name': 'App'},
          ],
          (api) => api.v3.system.appConfig(),
        ),
        (
          'appTheme',
          '/dfapp/v3/appTheme',
          [
            {'appName': 'GSD-DFApp', 'primary': '#fff'},
          ],
          (api) => api.v3.system.appTheme(),
        ),
      ];

  for (final (name, path, data, call) in cases) {
    test('system.$name ist bodyloses natives GET', () async {
      harness.enqueueData('GET', path, data);

      final result = await call(harness.api);

      expect(result, data);
      harness.expectSingleRequest(method: 'GET', path: path);
    });
  }
}
