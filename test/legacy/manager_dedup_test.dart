// ignore_for_file: deprecated_member_use_from_same_package
//
// Charakterisierungstest: "Deduplizierung" identischer, gleichzeitiger
// Requests in RestApiDOCUframeManager._performRequest().
//
// WICHTIGER BEFUND (weicht vom ursprünglich angenommenen Verhalten ab):
// _pendingResponses dedupliziert NICHT den tatsächlichen HTTP-Traffic. Ein
// zweiter, identischer Request (gleiche URI|Header|Body-Hash), der eintrifft
// während der erste noch läuft, nimmt zwar den "dedup"-Zweig in
// _performRequest() (`_pendingResponses[requestHash]!.execute(_client)`),
// aber `RestApiRequest.execute` ist eine FUNKTION, kein gecachtes Future -
// jeder Aufruf von `.execute(_client)` baut ein neues `http.Request` und
// sendet es tatsächlich erneut über den Client. Der "dedup"-Mechanismus
// verhindert also nur einen zweiten Eintrag in der Pending-Map, NICHT einen
// zweiten echten Netzwerk-Request. Das wurde hier gegen einen echten
// HttpServer verifiziert (siehe Anzahl der aufgezeichneten Requests unten).

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import 'legacy_test_server.dart';

void main() {
  ensureLegacyCryptoTestEnvironment();

  late LegacyTestServer server;
  final managers = <RestApiDOCUframeManager>[];

  RestApiDOCUframeManager newManager(RestApiDOCUframeConfig config) {
    final manager = RestApiDOCUframeManager(config: config);
    managers.add(manager);
    return manager;
  }

  setUp(() async {
    HttpOverrides.global = null;
    server = LegacyTestServer();
    await server.start();
  });

  tearDown(() async {
    for (final m in managers) {
      m.dispose();
    }
    managers.clear();
    await server.close();
  });

  test(
    'zwei gleichzeitige, identische GET-Requests: BEIDE erreichen den Server '
    '(kein echtes Dedup), beide Aufrufer erhalten aber ein korrektes Ergebnis',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(data: {'oid': 'OID1', 'seq': 1}),
        delay: const Duration(milliseconds: 60),
      );
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(data: {'oid': 'OID1', 'seq': 2}),
        delay: const Duration(milliseconds: 60),
      );

      final manager = newManager(buildLegacyConfig(server));

      // Beide Calls werden OHNE await dazwischen gestartet, damit sie sich
      // zeitlich überlappen (der erste hat bereits _pendingResponses befüllt,
      // bevor der zweite _performRequest erreicht).
      final f1 = manager.getObject('OID1');
      final f2 = manager.getObject('OID1');

      final r1 = await f1;
      final r2 = await f2;

      expect(r1.isOk, isTrue);
      expect(r2.isOk, isTrue);

      // Charakterisierung: ZWEI echte HTTP-Requests haben den Server erreicht,
      // nicht einer.
      expect(server.requests, hasLength(2));
      expect(server.requests[0].path, equals('/dfapp/v1/object/OID1'));
      expect(server.requests[1].path, equals('/dfapp/v1/object/OID1'));
    },
  );

  test('unterschiedliche Requests (andere OID) werden nie zusammengeführt und '
      'erzeugen unabhängig je einen Request', () async {
    server.enqueueJson(
      'GET',
      '/dfapp/v1/object/OIDA',
      body: v1Envelope(data: {'oid': 'OIDA'}),
    );
    server.enqueueJson(
      'GET',
      '/dfapp/v1/object/OIDB',
      body: v1Envelope(data: {'oid': 'OIDB'}),
    );

    final manager = newManager(buildLegacyConfig(server));

    final results = await Future.wait([
      manager.getObject('OIDA'),
      manager.getObject('OIDB'),
    ]);

    expect(results[0].isOk, isTrue);
    expect(results[1].isOk, isTrue);
    expect(server.requests, hasLength(2));
  });

  test(
    'nacheinander (nicht überlappend) ausgeführte identische Requests erzeugen '
    'ebenfalls je einen eigenen Request (kein Caching über die Zeit hinweg)',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(data: {'seq': 1}),
      );
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(data: {'seq': 2}),
      );

      final manager = newManager(buildLegacyConfig(server));

      final r1 = await manager.getObject('OID1');
      final r2 = await manager.getObject('OID1');

      expect(r1.isOk, isTrue);
      expect(r2.isOk, isTrue);
      expect(server.requests, hasLength(2));
    },
  );
}
