@TestOn('vm')
library;

// Tests für das V3-Grundgerüst der Fassade: Verfügbarkeit, Instanz-
// Stabilität und die Verdrahtung auf denselben Runtime/Sessionzustand wie
// V1.
//
// Die fachlichen V3-Endpunkt-Gruppen werden in den übrigen Tests unter
// test/v3/ geprüft. Hier geht es nur um das Grundgerüst; die geteilte
// Runtime wird auf zwei Wegen belegt:
// - verhaltensbasiert (wie test/facade/docuframe_api_test.dart): eine über
//   die V1-Gruppe gesetzte Session gilt für V3-versionierte Requests des
//   gemeinsamen Runtimes, inklusive `/v3/`-Routing unter dem Alias;
// - strukturell (wie test/runtime/runtime_isolation_test.dart): die Fassade
//   übergibt V3 dasselbe Runtime-Argument wie V1, und `lib/v3` baut keine
//   eigene Runtime-/Session-/HTTP-Infrastruktur auf.

import 'dart:io';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'v3_test_support.dart';

String _stripComments(String source) => source
    .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
    .replaceAll(RegExp('//.*'), '');

void main() {
  late V3TestHarness harness;

  setUp(() async {
    harness = await V3TestHarness.start();
  });

  tearDown(() => harness.close());

  test('api.v3 ist vorhanden und vom Typ GsdV3Api', () {
    expect(harness.api.v3, isNotNull);
    expect(harness.api.v3, isA<GsdV3Api>());
  });

  test('api.v3 liefert bei mehrfachem Zugriff dieselbe Instanz', () {
    final first = harness.api.v3;
    final second = harness.api.v3;

    expect(second, same(first));
    expect(harness.api.v3, same(first));
  });

  test('jede Fassade besitzt ihre eigene V3-Gruppe', () async {
    final other = await V3TestHarness.start();
    try {
      expect(other.api.v3, isA<GsdV3Api>());
      expect(other.api.v3, isNot(same(harness.api.v3)));
    } finally {
      await other.close();
    }
  });

  test(
    'V3-Requests der Fassade tragen den über V1 gesetzten Sessionzustand',
    () async {
      const sharedSession = 'v3-shared-session';

      // Session-Setup über die Fassade (V1-Authentifizierungsgruppe) ...
      harness.api.v1.authentication.restoreSession(
        sharedSession,
        md5Password: 'shared-md5',
      );
      expect(harness.api.sessionId, sharedSession);
      expect(harness.api.isAuthenticated, isTrue);

      // ... gilt für einen V3-versionierten Request desselben Runtimes.
      harness.enqueueSuccess('GET', '/dfapp/v3/probe');

      final response = await harness.api.raw.request(
        version: GsdApiVersion.v3,
        method: GsdHttpMethod.get,
        path: '/probe',
      );

      expect(response.statusCode, 200);
      harness.expectSingleRequest(
        method: 'GET',
        path: '/dfapp/v3/probe',
        sessionId: sharedSession,
      );
    },
  );

  test('Fassade verdrahtet V3 mit demselben Runtime wie V1', () {
    final source = _stripComments(
      File('lib/src/client/gsd_api_client.dart').readAsStringSync(),
    );

    String? runtimeArgumentOf(String groupClass) => RegExp(
      '\\b$groupClass\\.internal\\(\\s*(\\w+)',
    ).firstMatch(source)?.group(1);

    final v1Runtime = runtimeArgumentOf('GsdV1Api');
    final v3Runtime = runtimeArgumentOf('GsdV3Api');

    expect(
      source,
      contains("import 'package:gsd_restapi/src/v3/gsd_v3_api.dart';"),
    );
    expect(v1Runtime, isNotNull);
    expect(v3Runtime, isNotNull);
    expect(v3Runtime, equals(v1Runtime));
  });

  test('V3-Grundgerüst baut keine eigene Infrastruktur auf', () {
    final v3Files = Directory('lib/src/v3')
        .listSync(recursive: true)
        .whereType<File>()
        .where((file) => file.path.endsWith('.dart'));

    expect(v3Files, isNotEmpty);

    for (final file in v3Files) {
      final implementationSource = _stripComments(
        file.readAsStringSync(),
      );
      for (final forbidden in <RegExp>[
        RegExp(r'\bApiRuntime\s*\('),
        RegExp(r'\bSessionCoordinator\s*\('),
        RegExp(r'\bRuntimeConfiguration\.fromDocuframeConfig\s*\('),
        RegExp(r'\bClient\s*\('),
      ]) {
        expect(
          forbidden.hasMatch(implementationSource),
          isFalse,
          reason: '${file.path}: ${forbidden.pattern}',
        );
      }
    }
  });
}
