// ignore_for_file: deprecated_member_use_from_same_package
//
// Charakterisierungstests: customRequest() - Pfad-Präfixierung, Query-Parameter,
// eigene Header/Body sowie handleResponse:false (keine Exception-Zuordnung).

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
    'präfixiert den Pfad mit /{alias}, wenn uriPath bereits mit "/" beginnt',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/custom/path',
        body: v1Envelope(data: {'ok': true}),
      );
      final manager = newManager(buildLegacyConfig(server));

      final response = await manager.customRequest(
        HttpMethod.get,
        '/custom/path',
      );

      expect(response.statusCode, equals(200));
      expect(server.requests.single.path, equals('/dfapp/custom/path'));
    },
  );

  test(
    'fügt bei uriPath ohne führenden "/" trotzdem genau einen "/" zwischen alias und Pfad ein',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/custom/path2',
        body: v1Envelope(data: {}),
      );
      final manager = newManager(buildLegacyConfig(server));

      await manager.customRequest(HttpMethod.get, 'custom/path2');

      expect(server.requests.single.path, equals('/dfapp/custom/path2'));
    },
  );

  test(
    'übernimmt params als Query-Parameter und body unverändert (POST)',
    () async {
      server.enqueueJson(
        'POST',
        '/dfapp/custom/create',
        body: v1Envelope(data: {'id': 1}),
      );
      final manager = newManager(buildLegacyConfig(server));

      final response = await manager.customRequest(
        HttpMethod.post,
        '/custom/create',
        params: {'foo': 'bar', 'x': '1'},
        body: '{"payload":true}',
      );

      expect(response.statusCode, equals(200));
      final req = server.requests.single;
      expect(req.method, equals('POST'));
      expect(req.query, equals({'foo': 'bar', 'x': '1'}));
      expect(req.body, equals('{"payload":true}'));
    },
  );

  test(
    'requestHeader ersetzt komplett die Standard-Header (kein appkey/sessionid mehr), '
    'wenn requestHeader explizit übergeben wird',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/custom/headers',
        body: v1Envelope(data: {}),
      );
      final manager = newManager(
        buildLegacyConfig(server, sessionId: 'sess-x'),
      );

      await manager.customRequest(
        HttpMethod.get,
        '/custom/headers',
        requestHeader: {'x-custom': 'value1'},
      );

      final req = server.requests.single;
      expect(req.header('x-custom'), equals('value1'));
      expect(req.headers.containsKey('appkey'), isFalse);
      expect(req.headers.containsKey('sessionid'), isFalse);
    },
  );

  test('handleResponse:false überspringt jegliche Exception-Zuordnung: ein '
      '201-Status-Envelope (normalerweise SessionInvalidException) wird als '
      'ganz normale http.Response zurückgegeben', () async {
    server.enqueueJson(
      'GET',
      '/dfapp/custom/broken',
      body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
    );
    final manager = newManager(buildLegacyConfig(server));

    final response = await manager.customRequest(
      HttpMethod.get,
      '/custom/broken',
      handleResponse: false,
    );

    expect(response.statusCode, equals(200));
    expect(response.body, contains('"internalStatus":"201"'));
  });

  test(
    'handleResponse:true (Default) wirft weiterhin die zugeordnete Exception '
    'für unbekannte internalStatus-Codes',
    () async {
      server.enqueueJson(
        'GET',
        '/dfapp/custom/broken2',
        body: v1Envelope(internalStatus: '999', statusMessage: 'server error'),
      );
      final manager = newManager(buildLegacyConfig(server));

      await expectLater(
        () => manager.customRequest(HttpMethod.get, '/custom/broken2'),
        throwsA(isA<WebServiceException>()),
      );
    },
  );

  test('unterstützt PUT/DELETE/PATCH Methoden korrekt', () async {
    server.enqueueJson('PUT', '/dfapp/custom/x', body: v1Envelope(data: {}));
    server.enqueueJson('DELETE', '/dfapp/custom/x', body: v1Envelope(data: {}));
    server.enqueueJson('PATCH', '/dfapp/custom/x', body: v1Envelope(data: {}));
    final manager = newManager(buildLegacyConfig(server));

    await manager.customRequest(HttpMethod.put, '/custom/x');
    await manager.customRequest(HttpMethod.delete, '/custom/x');
    await manager.customRequest(HttpMethod.patch, '/custom/x');

    expect(
      server.requests.map((r) => r.method),
      equals(['PUT', 'DELETE', 'PATCH']),
    );
  });
}
