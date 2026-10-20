// Tests für BatchCoordinator: Multi-Request-Buffering (v1/multi), Flush-
// Auslöser (Größe/Timer), Prioritäten (ApiRequestPriority.high umgeht das
// Puffern immer) und Einzel-Fallback bei Fehlern - inklusive Zusammenspiel
// mit dem Session-Retry aus ApiRuntime.
//
// Anders als der Legacy-Manager (`RestApiDOCUframeManager`, siehe
// `_performPriorityBufferedRequest`/`_flushPriorityRequestBuffer`/
// `_processPriorityMultiRequest`/`_processMultiRequestResponse`) werden hier
// drei per Task-1-Charakterisierung bekannte Bugs bewusst NICHT reproduziert:
// - kein `_shouldNeverBuffer`-String-Matching (siehe Test
//   "No-Buffer-Scope umgeht ..." unten sowie die bereits bestehende
//   `SessionCoordinator`-Verkabelung, die Login/Logout explizit über
//   `MultiRequestEligibility` und NICHT über Pfad-Strings ausschließt),
// - kein Verlust weiterer High-Priority-Requests beim Flush (siehe Test
//   "RequestPriority.high" unten: ZWEI High-Priority-Requests, beide
//   beantwortet),
// - ein Demux, der die tatsächliche Ergebnis-LISTENlänge (nicht die
//   Envelope-Map-Länge) auswertet (siehe Test "WENIGER Ergebnisse" unten).

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/batch/batch_coordinator.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/request_priority.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/rest_api_response_policy.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';

import 'session_test_support.dart';

/// Einfache Test-Policy: dekodiert den Body als JSON-Map.
class _JsonMapResponsePolicy implements ResponsePolicy<Map<String, dynamic>> {
  const _JsonMapResponsePolicy();

  @override
  Map<String, dynamic> decode(TransportResponse response) =>
      jsonDecode(response.body) as Map<String, dynamic>;
}

/// Baut eine [RuntimeConfiguration] mit konfigurierbaren Buffer-Einstellungen
/// für die BatchCoordinator-Tests. Der generische Helfer aus
/// `runtime_test_helpers.dart` bietet dafür bewusst keine Parameter an, da
/// `maxBufferSize`/`bufferFlushDelayMs` erst mit PR 3c existieren.
RuntimeConfiguration buildBatchRuntimeConfiguration({
  String serverUrl = 'https://server.example:8443',
  String alias = 'dfapp',
  String appKey = 'TEST-APP-KEY',
  String sessionId = '',
  bool multiRequest = true,
  int maxBufferSize = 10,
  int bufferFlushDelayMs = 20,
}) {
  return RuntimeConfiguration(
    serverUrl: serverUrl,
    baseUri: Uri.parse(serverUrl),
    alias: alias,
    appKey: appKey,
    userName: 'tester',
    appNames: const ['GSD-RestApi'],
    additionalAppNames: const [],
    device: null,
    connectionTimeout: const Duration(seconds: 5),
    responseTimeout: const Duration(seconds: 5),
    allowSslError: false,
    debugLogs: false,
    useBase64UrlParameter: false,
    initialSessionId: sessionId,
    multiRequest: multiRequest,
    maxBufferSize: maxBufferSize,
    bufferFlushDelayMs: bufferFlushDelayMs,
  );
}

/// Baut einen einfachen JSON-Map-Request auf einem gewöhnlichen (per
/// `MultiRequestEligibility` multi-fähigen) Pfad. Ob tatsächlich gepuffert
/// wird, entscheidet die zum Ausführungszeitpunkt aktive
/// `RuntimeExecutionPolicy` (siehe [_executeWithPriority]/
/// [RuntimeExecutionContext]) - nicht mehr der Request selbst.
ApiRequest<Map<String, dynamic>> _buildRequest({
  ApiHttpMethod method = ApiHttpMethod.get,
  ApiVersion version = ApiVersion.v1,
  String path = '/objects/1',
  String? body,
  AuthenticationPolicy authentication = AuthenticationPolicy.none,
  String operationId = 'test.batch',
}) {
  return ApiRequest<Map<String, dynamic>>(
    method: method,
    version: version,
    path: path,
    body: body,
    authentication: authentication,
    responsePolicy: const _JsonMapResponsePolicy(),
    operationId: operationId,
  );
}

/// Führt [request] über [runtime] aus und wendet dabei einen
/// `RuntimeExecutionContext`-Priority-Scope an - Ersatz für das entfernte
/// `ApiRequest.priority`. `ApiRequestPriority.normal` benötigt KEINEN Scope
/// (das ist bereits die Voreinstellung ohne aktiven Priority-Scope).
Future<T> _executeWithPriority<T>(
  ApiRuntime runtime,
  ApiRequest<T> request, {
  required ApiRequestPriority priority,
}) {
  final RequestPriority? scope = switch (priority) {
    ApiRequestPriority.normal => null,
    ApiRequestPriority.low => RequestPriority.low,
    ApiRequestPriority.high => RequestPriority.high,
  };

  if (scope == null) {
    return runtime.execute(request);
  }
  return RuntimeExecutionContext.runWithPriority(
    () => runtime.execute(request),
    scope,
  );
}

void main() {
  ensureLegacyCryptoTestEnvironment();

  group('BatchCoordinator: Multi-Request-Body und Demux', () {
    test('entschlüsselt äußere Multi-Response vor Demux', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueue('POST', '/dfapp/v1/multi', (request) async {
        final encryptionManager = EncryptionManager();
        await encryptionManager.initializeRSAKeyPair();
        final encryptedResponse = await encryptV2Response(
          jsonEncode(
            v1Envelope(
              data: [
                {
                  'httpStatus': 200,
                  'result': {'value': 'encrypted-a'},
                },
                {
                  'httpStatus': 200,
                  'result': {'value': 'encrypted-b'},
                },
              ],
            ),
          ),
          encryptionManager.keyRSA!.publicKey,
        );
        return ScriptedResponse(encryptedResponse);
      });

      final results = await Future.wait([
        runtime.execute(_buildRequest(path: '/objects/1')),
        runtime.execute(_buildRequest(path: '/objects/2')),
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'value': 'encrypted-a'}));
      expect(results[1], equals({'value': 'encrypted-b'}));
      expect(server.requests, hasLength(1));
      expect(server.requests.single.path, '/dfapp/v1/multi');
    });

    test('mehrere gepufferte Requests im Flush-Fenster: EIN v1/multi-POST mit '
        'korrektem Body (Methode groß, Pfad ab /v1/..., POST inkl. data, GET '
        'ohne data); jeder Aufrufer erhält sein eigenes demultiplextes '
        'Ergebnis', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson(
        'POST',
        '/dfapp/v1/multi',
        body: v1Envelope(
          data: [
            {
              'httpStatus': 200,
              'result': {'value': 'a'},
            },
            {
              'httpStatus': 200,
              'result': {'value': 'b'},
            },
          ],
        ),
      );

      final f1 = runtime.execute(_buildRequest(path: '/objects/1'));
      final f2 = runtime.execute(
        _buildRequest(
          method: ApiHttpMethod.post,
          path: '/objects/2',
          body: '{"name":"x"}',
        ),
      );

      final results = await Future.wait([
        f1,
        f2,
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'value': 'a'}));
      expect(results[1], equals({'value': 'b'}));

      final multiRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/multi')
          .toList();
      expect(multiRequests, hasLength(1));

      final bodyJson = jsonDecode(multiRequests.single.body) as List<dynamic>;
      expect(bodyJson, hasLength(2));
      expect(bodyJson[0], equals({'method': 'GET', 'path': '/v1/objects/1'}));
      expect(
        bodyJson[1],
        equals({
          'method': 'POST',
          'path': '/v1/objects/2',
          'data': {'name': 'x'},
        }),
      );
    });
  });

  group('BatchCoordinator: Flush-Auslöser', () {
    test('Buffer erreicht maxBufferSize: sofortiger Flush ohne auf den '
        '(sehr langen) Timer zu warten', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 3,
        bufferFlushDelayMs: 5000,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson(
        'POST',
        '/dfapp/v1/multi',
        body: v1Envelope(
          data: [
            {
              'httpStatus': 200,
              'result': {'v': 1},
            },
            {
              'httpStatus': 200,
              'result': {'v': 2},
            },
            {
              'httpStatus': 200,
              'result': {'v': 3},
            },
          ],
        ),
      );

      final futures = [
        runtime.execute(_buildRequest(path: '/a')),
        runtime.execute(_buildRequest(path: '/b')),
        runtime.execute(_buildRequest(path: '/c')),
      ];

      // Der Flush-Timer (5s) ist absichtlich viel länger als das Timeout
      // unten: Läuft der Test durch, kam der Flush nachweislich über die
      // Größen-Schwelle, nicht über den Timer.
      final results = await Future.wait(
        futures,
      ).timeout(const Duration(seconds: 2));

      expect(
        results,
        equals([
          {'v': 1},
          {'v': 2},
          {'v': 3},
        ]),
      );
      expect(
        server.requests.where((r) => r.path == '/dfapp/v1/multi'),
        hasLength(1),
      );
    });

    test('weniger als maxBufferSize: KEIN sofortiger (synchroner) Flush, aber '
        'Flush nach bufferFlushDelayMs', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 30,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson(
        'POST',
        '/dfapp/v1/multi',
        body: v1Envelope(
          data: [
            {
              'httpStatus': 200,
              'result': {'v': 1},
            },
            {
              'httpStatus': 200,
              'result': {'v': 2},
            },
          ],
        ),
      );

      final f1 = runtime.execute(_buildRequest(path: '/a'));
      final f2 = runtime.execute(_buildRequest(path: '/b'));

      // Timing-robuste Prüfung: Direkt nach dem Einreihen (noch in
      // derselben synchronen Ausführung, vor jedem Event-Loop-Turn) kann
      // noch KEIN Timer gefeuert haben - unabhängig von Rechnerlast. Der
      // Flush hängt also nachweislich vom Timer ab, nicht von einem
      // synchronen Trigger innerhalb von enqueue().
      expect(server.requests, isEmpty);

      final results = await Future.wait([
        f1,
        f2,
      ]).timeout(const Duration(seconds: 2));

      expect(
        results,
        equals([
          {'v': 1},
          {'v': 2},
        ]),
      );
      expect(
        server.requests.where((r) => r.path == '/dfapp/v1/multi'),
        hasLength(1),
      );
    });

    test('genau EIN gepufferter Request beim Flush: Einzelanfrage statt '
        'v1/multi', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 20,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson('GET', '/dfapp/v1/solo', body: {'value': 'solo'});

      final result = await runtime
          .execute(_buildRequest(path: '/solo'))
          .timeout(const Duration(seconds: 2));

      expect(result, equals({'value': 'solo'}));
      expect(
        server.requests.where((r) => r.path == '/dfapp/v1/multi'),
        isEmpty,
      );
      expect(
        server.requests.where((r) => r.path == '/dfapp/v1/solo'),
        hasLength(1),
      );
    });
  });

  group('BatchCoordinator: Prioritäten', () {
    test('trennt normal und low in unabhängige Multi-Requests', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 30,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      ScriptedResponse multiResponse(RecordedRequest request) {
        final requestItems = jsonDecode(request.body) as List<dynamic>;
        return ScriptedResponse(
          jsonEncode(
            v1Envelope(
              data: List.generate(
                requestItems.length,
                (index) => {
                  'httpStatus': 200,
                  'result': {'value': index},
                },
              ),
            ),
          ),
        );
      }

      server.enqueue('POST', '/dfapp/v1/multi', multiResponse);
      server.enqueue('POST', '/dfapp/v1/multi', multiResponse);

      await Future.wait([
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/normal/a'),
          priority: ApiRequestPriority.normal,
        ),
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/low/a'),
          priority: ApiRequestPriority.low,
        ),
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/normal/b'),
          priority: ApiRequestPriority.normal,
        ),
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/low/b'),
          priority: ApiRequestPriority.low,
        ),
      ]).timeout(const Duration(seconds: 2));

      final multiRequests = server.requests
          .where((request) => request.path == '/dfapp/v1/multi')
          .toList();
      final capturedPathSets = multiRequests.map((request) {
        final items = jsonDecode(request.body) as List<dynamic>;
        return items
            .map((item) => (item as Map<String, dynamic>)['path'] as String)
            .toSet();
      }).toList();

      expect(multiRequests, hasLength(2));
      expect(
        capturedPathSets,
        unorderedEquals([
          {'/v1/normal/a', '/v1/normal/b'},
          {'/v1/low/a', '/v1/low/b'},
        ]),
      );
    });

    test('ein normal und ein low nutzen unabhängige Timer und werden einzeln '
        'gesendet', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 30,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson(
        'GET',
        '/dfapp/v1/normal/solo',
        body: {'value': 'normal'},
      );
      server.enqueueJson('GET', '/dfapp/v1/low/solo', body: {'value': 'low'});

      final normal = _executeWithPriority(
        runtime,
        _buildRequest(path: '/normal/solo'),
        priority: ApiRequestPriority.normal,
      );
      final low = _executeWithPriority(
        runtime,
        _buildRequest(path: '/low/solo'),
        priority: ApiRequestPriority.low,
      );

      expect(server.requests, isEmpty);

      final results = await Future.wait([
        normal,
        low,
      ]).timeout(const Duration(seconds: 2));

      expect(
        results,
        equals([
          {'value': 'normal'},
          {'value': 'low'},
        ]),
      );
      expect(
        server.requests.where((request) => request.path == '/dfapp/v1/multi'),
        isEmpty,
      );
      expect(
        server.requests
            .where(
              (request) =>
                  request.path == '/dfapp/v1/normal/solo' ||
                  request.path == '/dfapp/v1/low/solo',
            )
            .length,
        2,
      );
    });

    test('enqueue lehnt ApiRequestPriority.high defensiv ab', () async {
      final config = buildBatchRuntimeConfiguration();
      final coordinator = BatchCoordinator(configuration: config);

      expect(
        () => coordinator.enqueue(
          method: ApiHttpMethod.get,
          uri: Uri.parse('https://server.example:8443/dfapp/v1/high'),
          headers: const {},
          needsSession: false,
          priority: ApiRequestPriority.high,
        ),
        throwsArgumentError,
      );

      await coordinator.dispose();
    });

    test(
      'ApiRequestPriority.high wird SOFORT als Einzelanfrage gesendet, nie '
      'gepuffert; ZWEI High-Priority-Requests werden BEIDE beantwortet '
      '(kein Legacy-Drop weiterer High-Priority-Requests beim Flush)',
      () async {
        final server = MockApiServer();
        final config = buildBatchRuntimeConfiguration(
          maxBufferSize: 10,
          bufferFlushDelayMs: 5000,
        );
        final runtime = ApiRuntime(
          configuration: config,
          httpClient: server.client,
          batchCoordinator: BatchCoordinator(configuration: config),
        );

        server.enqueueJson('GET', '/dfapp/v1/high-a', body: {'v': 'a'});
        server.enqueueJson('GET', '/dfapp/v1/high-b', body: {'v': 'b'});

        final fa = _executeWithPriority(
          runtime,
          _buildRequest(path: '/high-a'),
          priority: ApiRequestPriority.high,
        );
        final fb = _executeWithPriority(
          runtime,
          _buildRequest(path: '/high-b'),
          priority: ApiRequestPriority.high,
        );

        // Der (sehr lange) Flush-Timer würde diesen Test bei versehentlicher
        // Pufferung zuverlässig zum Timeout bringen.
        final results = await Future.wait([
          fa,
          fb,
        ]).timeout(const Duration(seconds: 1));

        expect(results[0], equals({'v': 'a'}));
        expect(results[1], equals({'v': 'b'}));
        expect(
          server.requests.where((r) => r.path == '/dfapp/v1/multi'),
          isEmpty,
        );
        expect(server.requests, hasLength(2));
      },
    );
  });

  group('BatchCoordinator: Fehler-Fallback', () {
    test('Multi-Antwort liefert WENIGER Ergebnisse als Requests: übrige '
        'Requests werden über den Einzel-Fallback abgeschlossen statt '
        'dauerhaft offen zu bleiben (Fix des Legacy-Envelope-Map-vs-Listen-'
        'Längen-Bugs)', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 20,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson(
        'POST',
        '/dfapp/v1/multi',
        body: v1Envelope(
          data: [
            {
              'httpStatus': 200,
              'result': {'v': 1},
            },
          ],
        ),
      );
      server.enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'});
      server.enqueueJson('GET', '/dfapp/v1/c', body: {'v': 'c-fallback'});

      final fa = runtime.execute(_buildRequest(path: '/a'));
      final fb = runtime.execute(_buildRequest(path: '/b'));
      final fc = runtime.execute(_buildRequest(path: '/c'));

      final results = await Future.wait([
        fa,
        fb,
        fc,
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'v': 1}));
      expect(results[1], equals({'v': 'b-fallback'}));
      expect(results[2], equals({'v': 'c-fallback'}));

      expect(
        server.requests.where((r) => r.path == '/dfapp/v1/multi'),
        hasLength(1),
      );
      expect(
        server.requests.where((r) => r.path == '/dfapp/v1/b'),
        hasLength(1),
      );
      expect(
        server.requests.where((r) => r.path == '/dfapp/v1/c'),
        hasLength(1),
      );
    });

    test('v1/multi antwortet mit HTTP 500: ALLE gepufferten Requests werden '
        'über den Einzel-Fallback abgeschlossen', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 20,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueue(
        'POST',
        '/dfapp/v1/multi',
        (req) async =>
            ScriptedResponse('Internal Server Error', statusCode: 500),
      );
      server.enqueueJson('GET', '/dfapp/v1/a', body: {'v': 'a-fallback'});
      server.enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'});

      final fa = runtime.execute(_buildRequest(path: '/a'));
      final fb = runtime.execute(_buildRequest(path: '/b'));

      final results = await Future.wait([
        fa,
        fb,
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'v': 'a-fallback'}));
      expect(results[1], equals({'v': 'b-fallback'}));
    });

    test('v1/multi liefert ein unparsbares (kein JSON-Objekt mit data-Liste) '
        'Envelope: ALLE gepufferten Requests werden über den Einzel-Fallback '
        'abgeschlossen', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 20,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueue(
        'POST',
        '/dfapp/v1/multi',
        (req) async => ScriptedResponse('not json at all'),
      );
      server.enqueueJson('GET', '/dfapp/v1/a', body: {'v': 'a-fallback'});
      server.enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'});

      final fa = runtime.execute(_buildRequest(path: '/a'));
      final fb = runtime.execute(_buildRequest(path: '/b'));

      final results = await Future.wait([
        fa,
        fb,
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'v': 'a-fallback'}));
      expect(results[1], equals({'v': 'b-fallback'}));
    });
  });

  group('BatchCoordinator: No-Buffer-Scope', () {
    test(
      'RuntimeExecutionContext.runWithoutBuffering umgeht das Buffering '
      'vollständig, auch bei angebundenem BatchCoordinator und einem '
      'ansonsten multi-fähigen Pfad (kein Legacy-String-Matching auf Pfade '
      'nötig - der No-Buffer-Scope wirkt unabhängig von der Pfad-Eignung)',
      () async {
        final server = MockApiServer();
        final config = buildBatchRuntimeConfiguration(
          maxBufferSize: 10,
          bufferFlushDelayMs: 5000,
        );
        final runtime = ApiRuntime(
          configuration: config,
          httpClient: server.client,
          batchCoordinator: BatchCoordinator(configuration: config),
        );

        server.enqueueJson('GET', '/dfapp/v1/direct', body: {'v': 'direct'});

        final result = await RuntimeExecutionContext.runWithoutBuffering(
          () => runtime.execute(_buildRequest(path: '/direct')),
        ).timeout(const Duration(seconds: 1));

        expect(result, equals({'v': 'direct'}));
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/direct'));
      },
    );
  });

  group('ApiRuntime: zentrale Never-Multi-Policy', () {
    test('gesperrte Auth-, Check- und xSync-Pfade laufen trotz '
        'multiRequest:true direkt', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(multiRequest: true);
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      final cases = <(ApiVersion, String, String)>[
        (ApiVersion.v1, '/logout', '/dfapp/v1/logout'),
        (ApiVersion.v2, '/login/secure/key', '/dfapp/v2/login/secure/key'),
        (ApiVersion.v2, '/login/key', '/dfapp/v2/login/key'),
        (ApiVersion.v2, '/login', '/dfapp/v2/login'),
        (ApiVersion.v1, '/_CheckSession', '/dfapp/v1/_CheckSession'),
        (ApiVersion.v1, '/_CheckService', '/dfapp/v1/_CheckService'),
        (ApiVersion.v1, '/xSync', '/dfapp/v1/xSync'),
        (
          ApiVersion.v1,
          '/xSync/ClassInfo/App1',
          '/dfapp/v1/xSync/ClassInfo/App1',
        ),
      ];

      for (final entry in cases) {
        server.enqueueJson('GET', entry.$3, body: {'direct': entry.$2});
      }

      final results = await Future.wait(
        cases.map(
          (entry) =>
              runtime.execute(_buildRequest(version: entry.$1, path: entry.$2)),
        ),
      );

      expect(results, hasLength(cases.length));
      expect(
        server.requests.where((request) => request.path.endsWith('/v1/multi')),
        isEmpty,
      );
      expect(server.requests, hasLength(cases.length));
    });

    test('ähnlicher xSync-Pfad bleibt multi-fähig', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(multiRequest: true);
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson(
        'POST',
        '/dfapp/v1/multi',
        body: v1Envelope(
          data: [
            {
              'httpStatus': 200,
              'result': {'value': 1},
            },
            {
              'httpStatus': 200,
              'result': {'value': 2},
            },
          ],
        ),
      );

      await Future.wait([
        runtime.execute(_buildRequest(path: '/xSyncArchive/one')),
        runtime.execute(_buildRequest(path: '/xSyncArchive/two')),
      ]);

      expect(server.requests, hasLength(1));
      expect(server.requests.single.path, equals('/dfapp/v1/multi'));
    });

    test('multiRequest:false sendet multi-fähige Requests direkt', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(multiRequest: false);
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson('GET', '/dfapp/v1/a', body: {'value': 'a'});
      server.enqueueJson('GET', '/dfapp/v1/b', body: {'value': 'b'});

      final results = await Future.wait([
        runtime.execute(_buildRequest(path: '/a')),
        runtime.execute(_buildRequest(path: '/b')),
      ]);

      expect(
        results,
        equals([
          {'value': 'a'},
          {'value': 'b'},
        ]),
      );
      expect(server.requests, hasLength(2));
      expect(
        server.requests.where((request) => request.path.endsWith('/v1/multi')),
        isEmpty,
      );
    });
  });

  group('BatchCoordinator: dispose()', () {
    test('dispose() mit noch gepufferten Requests: deren Futures schließen '
        '(mit Fehler) ab, keines hängt unbegrenzt', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 5000,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      final fa = runtime.execute(_buildRequest(path: '/a'));
      final fb = _executeWithPriority(
        runtime,
        _buildRequest(path: '/b'),
        priority: ApiRequestPriority.low,
      );

      // Die Matcher werden SOFORT (synchron, vor dispose()) angehängt:
      // Wird ein Future erst NACH seinem Fehlerabschluss beobachtet, meldet
      // Dart den Fehler bereits als "unhandled" an die Test-Zone - auch
      // wenn ein späterer Listener ihn technisch noch korrekt einsammelt.
      final faExpectation = expectLater(fa, throwsA(isA<StateError>()));
      final fbExpectation = expectLater(fb, throwsA(isA<StateError>()));

      await runtime.dispose();

      await faExpectation;
      await fbExpectation;
      expect(server.requests, isEmpty);
    });
  });

  group('BatchCoordinator: aktuelle Session-ID zum Sendezeitpunkt (Review-Fix '
      'PR3c)', () {
    test('Session-Refresh WÄHREND des Buffer-Fensters (z.B. durch einen '
        'parallelen Bypass-Request): sowohl der v1/multi-POST als auch ein '
        'Einzel-Fallback-Resend tragen die AKTUELLE sessionid, nicht die '
        'zum Enqueue-Zeitpunkt erfasste (veraltete) Session-ID', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 30,
        sessionId: 'stale-sid',
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      ApiRequest<Map<String, dynamic>> buildSessionRequest(String path) =>
          _buildRequest(
            path: path,
            authentication: AuthenticationPolicy.session,
          );

      // v1/multi liefert nur EIN Ergebnis für DREI gepufferte Requests:
      // Item 0 wird über den Demux abgeschlossen, Items 1+2 laufen über
      // den Einzel-Fallback (siehe Test "WENIGER Ergebnisse" oben) - so
      // lässt sich in EINEM Testlauf sowohl der v1/multi-POST- als auch
      // der Fallback-Header prüfen.
      server.enqueueJson(
        'POST',
        '/dfapp/v1/multi',
        body: v1Envelope(
          data: [
            {
              'httpStatus': 200,
              'result': {'v': 1},
            },
          ],
        ),
      );
      server.enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'});
      server.enqueueJson('GET', '/dfapp/v1/c', body: {'v': 'c-fallback'});

      final fa = runtime.execute(buildSessionRequest('/a'));
      final fb = runtime.execute(buildSessionRequest('/b'));
      final fc = runtime.execute(buildSessionRequest('/c'));

      // Simuliert einen Session-Refresh, der WÄHREND des Buffer-Fensters
      // abgeschlossen wird - NACH dem Enqueue (die Header der bereits
      // gepufferten Items tragen zu diesem Zeitpunkt noch die ALTE
      // Session-ID), aber VOR dem Timer-Flush. `runtime.sessionState` ist
      // exakt derselbe `SessionState`, den auch ein `SessionCoordinator`-
      // Refresh mutieren würde.
      runtime.sessionState.sessionId = 'refreshed-sid';

      final results = await Future.wait([
        fa,
        fb,
        fc,
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'v': 1}));
      expect(results[1], equals({'v': 'b-fallback'}));
      expect(results[2], equals({'v': 'c-fallback'}));

      final multiRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/multi')
          .toList();
      expect(multiRequests, hasLength(1));
      expect(multiRequests.single.header('sessionid'), equals('refreshed-sid'));

      final fallbackRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/b' || r.path == '/dfapp/v1/c')
          .toList();
      expect(fallbackRequests, hasLength(2));
      for (final request in fallbackRequests) {
        expect(request.header('sessionid'), equals('refreshed-sid'));
      }
    });

    test('erstes gepuffertes Item mit AuthenticationPolicy.none: der '
        'v1/multi-POST trägt trotzdem die sessionid der ÜBRIGEN, '
        'session-pflichtigen Items (Header werden für v1/multi explizit '
        'gebaut statt von items.first.headers kopiert)', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration(
        maxBufferSize: 10,
        bufferFlushDelayMs: 20,
        sessionId: 'sess-active',
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server.enqueueJson(
        'POST',
        '/dfapp/v1/multi',
        body: v1Envelope(
          data: [
            {
              'httpStatus': 200,
              'result': {'v': 1},
            },
            {
              'httpStatus': 200,
              'result': {'v': 2},
            },
          ],
        ),
      );

      // items.first hat AuthenticationPolicy.none (kein sessionid-Header
      // zum Enqueue-Zeitpunkt) - der zweite Request braucht dagegen eine
      // Session. Vor dem Fix hätte `Map.of(items.first.headers)` die
      // sessionid für den GESAMTEN Multi-Request unterdrückt.
      final fa = runtime.execute(
        _buildRequest(path: '/a', authentication: AuthenticationPolicy.none),
      );
      final fb = runtime.execute(
        _buildRequest(path: '/b', authentication: AuthenticationPolicy.session),
      );

      final results = await Future.wait([
        fa,
        fb,
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'v': 1}));
      expect(results[1], equals({'v': 2}));

      final multiRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/multi')
          .toList();
      expect(multiRequests, hasLength(1));
      expect(multiRequests.single.header('sessionid'), equals('sess-active'));
    });
  });

  group(
    'BatchCoordinator + SessionCoordinator (demultiplexter Session-Fehler)',
    () {
      test(
        'ein demultiplexter 201-Fehler EINES gepufferten Requests löst '
        'Session-Refresh + Retry aus; der Retry läuft NICHT erneut über '
        'v1/multi (Session-Retry umgeht den BatchCoordinator immer)',
        () async {
          final pair = await generateServerKeyPair();
          final serverPublicKey = pair.publicKey;
          final server = MockApiServer();
          final config = buildBatchRuntimeConfiguration(
            maxBufferSize: 10,
            bufferFlushDelayMs: 20,
          );
          final sessionCoordinator = SessionCoordinator(
            configuration: config,
            retryDelay: const Duration(milliseconds: 5),
          );
          final runtime = ApiRuntime(
            configuration: config,
            httpClient: server.client,
            sessionCoordinator: sessionCoordinator,
            batchCoordinator: BatchCoordinator(configuration: config),
          );

          void scriptLoginKey() {
            server.enqueueJson(
              'GET',
              '/dfapp/v2/login/key',
              body: v1Envelope(
                data: {'key': encodePublicKeyToCleanPem(serverPublicKey)},
              ),
            );
          }

          void scriptLoginSuccess(String sessionId) {
            server.enqueue('POST', '/dfapp/v2/login', (req) async {
              return ScriptedResponse(
                jsonEncode(v1Envelope(data: {'sessionId': sessionId})),
              );
            });
          }

          // Initialer Login, außerhalb des zu prüfenden Vorgangs.
          scriptLoginKey();
          scriptLoginSuccess('sess-initial');
          await sessionCoordinator.login('md5hash');
          final baseline = server.requests.length;

          // EIN Multi-Flush für beide gepufferten Requests: probe-a liefert
          // einen demultiplexten 201-Fehler (ungültige Session), probe-b
          // liefert direkt Erfolg.
          server.enqueueJson(
            'POST',
            '/dfapp/v1/multi',
            body: v1Envelope(
              data: [
                {
                  'httpStatus': 200,
                  'result': v1Envelope(
                    internalStatus: '201',
                    statusMessage: 'invalid',
                  ),
                },
                {
                  'httpStatus': 200,
                  'result': v1Envelope(data: {'ok': true}),
                },
              ],
            ),
          );

          // Retry nach dem Refresh: direkte Einzelanfrage, NICHT erneut über
          // v1/multi.
          scriptLoginKey();
          scriptLoginSuccess('sess-refreshed');
          server.enqueueJson(
            'GET',
            '/dfapp/v1/probe-a',
            body: v1Envelope(data: {'ok': 'retried'}),
          );

          ApiRequest<RestApiResponse> buildSessionRequest(String path) =>
              ApiRequest<RestApiResponse>(
                method: ApiHttpMethod.get,
                version: ApiVersion.v1,
                path: path,
                authentication: AuthenticationPolicy.session,
                responsePolicy: const RestApiResponsePolicy(),
                operationId: 'test.batch.session-retry',
              );

          final fa = runtime.execute(buildSessionRequest('/probe-a'));
          final fb = runtime.execute(buildSessionRequest('/probe-b'));

          final results = await Future.wait([
            fa,
            fb,
          ]).timeout(const Duration(seconds: 2));

          expect(results[0].isOk, isTrue);
          expect(results[1].isOk, isTrue);
          expect(
            sessionCoordinator.sessionState.sessionId,
            equals('sess-refreshed'),
          );

          final postRequests = server.requests.sublist(baseline);
          final multiRequests = postRequests
              .where((r) => r.path == '/dfapp/v1/multi')
              .toList();
          // GENAU EIN Multi-Request: Der Retry darf NICHT erneut gepuffert
          // werden.
          expect(multiRequests, hasLength(1));

          final retryRequests = postRequests
              .where((r) => r.path == '/dfapp/v1/probe-a')
              .toList();
          expect(retryRequests, hasLength(1));
          expect(
            postRequests.where((r) => r.path == '/dfapp/v1/probe-b'),
            isEmpty,
            reason:
                'Das bereits erfolgreiche Teilresultat darf keinen '
                'Retry auslösen.',
          );
          expect(
            retryRequests.single.header('sessionid'),
            equals('sess-refreshed'),
          );
        },
      );
    },
  );
}
