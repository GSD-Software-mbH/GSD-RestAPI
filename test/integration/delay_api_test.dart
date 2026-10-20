import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../fixtures/delay_docuframe_api.dart';

void main() {
  group('DelayDocuframeApi - Network Delay Simulation', () {
    late DelayDocuframeApi delayApi;
    late RestApiDOCUframeConfig testConfig;

    setUp(() {
      // Minimal test config für Delay-Tests
      testConfig = RestApiDOCUframeConfig(
        appKey: 'TEST-APP',
        userName: 'testuser',
        appNames: ['TestApp'],
        serverUrl: 'http://localhost:8080',
        alias: 'TEST',
      );
    });

    tearDown(() async {
      await delayApi.dispose();
    });

    test('postAction sollte 500ms Delay haben', () async {
      delayApi = DelayDocuframeApi(configuration: testConfig);

      final stopwatch = Stopwatch()..start();

      // Dieser Test wird fehlschlagen, wenn der Server nicht läuft,
      // aber die Verzögerung wird gemessen, bevor der Request fehlschlägt.
      try {
        await delayApi.v1.objects.postAction('TestClass');
      } catch (_) {
        // Fehler ignorieren - wir testen nur die Verzögerung
      }

      stopwatch.stop();

      // Erwartet mindestens 450ms (500ms ± 50ms Toleranz)
      expect(
        stopwatch.elapsedMilliseconds,
        greaterThanOrEqualTo(450),
        reason: 'postAction sollte mindestens 500ms verzögert sein',
      );
    });

    test('patchObject sollte 300ms Delay haben', () async {
      delayApi = DelayDocuframeApi(configuration: testConfig);

      final stopwatch = Stopwatch()..start();

      try {
        await delayApi.v1.objects.patchObject('test-oid', '{}');
      } catch (_) {
        // Fehler ignorieren - wir testen nur die Verzögerung
      }

      stopwatch.stop();

      // Erwartet mindestens 250ms (300ms ± 50ms Toleranz)
      expect(
        stopwatch.elapsedMilliseconds,
        greaterThanOrEqualTo(250),
        reason: 'patchObject sollte mindestens 300ms verzögert sein',
      );
    });

    test('getObject sollte KEIN Delay haben (nicht überschrieben)', () async {
      delayApi = DelayDocuframeApi(configuration: testConfig);

      final stopwatch = Stopwatch()..start();

      try {
        await delayApi.v1.objects.getObject('test-oid');
      } catch (_) {
        // Fehler ignorieren - wir testen nur die Verzögerung
      }

      stopwatch.stop();

      // getObject ist nicht überschrieben, daher sollte es schnell fehlschlagen (< 200ms)
      expect(
        stopwatch.elapsedMilliseconds,
        lessThan(200),
        reason: 'getObject sollte kein Delay haben, da nicht überschrieben',
      );
    });

    test(
      'DelayDocuframeApi.v1.objects sollte DelayV1ObjectsApi sein',
      () async {
        delayApi = DelayDocuframeApi(configuration: testConfig);

        // Verifiziere, dass die Hierarchie korrekt ist
        expect(
          delayApi.v1.runtimeType.toString(),
          contains('DelayDocuframeV1Api'),
          reason: 'v1 sollte DelayDocuframeV1Api sein',
        );
        expect(
          delayApi.v1.objects.runtimeType.toString(),
          contains('DelayV1ObjectsApi'),
          reason: 'v1.objects sollte DelayV1ObjectsApi sein',
        );
      },
    );

    test('Normale DOCUframeApi hat keine Delays', () async {
      // Verifiziere, dass die normale API ohne Delays funktioniert
      final normalApi = DOCUframeApi(configuration: testConfig);

      final stopwatch = Stopwatch()..start();

      try {
        await normalApi.v1.objects.postAction('TestClass');
      } catch (_) {
        // Fehler ignorieren
      }

      stopwatch.stop();

      // Normale API sollte schneller sein (< 200ms, da kein Delay)
      expect(
        stopwatch.elapsedMilliseconds,
        lessThan(200),
        reason: 'Normale API sollte kein Delay haben',
      );

      await normalApi.dispose();
    });
  });
}
