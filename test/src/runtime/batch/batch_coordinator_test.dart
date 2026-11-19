// Tests für BatchCoordinator: Multi-Request-Buffering (v1/multi), Flush-
// Auslöser (Größe/Timer), Prioritäten (GsdRequestPriority.high umgeht das
// Puffern immer) und Einzel-Fallback bei Fehlern - inklusive Zusammenspiel
// mit dem Session-Retry aus ApiRuntime.
//
// Anders als der Legacy-Manager (bis 0.2.x, siehe
// `_performPriorityBufferedRequest`/`_flushPriorityRequestBuffer`/
// `_processPriorityMultiRequest`/`_processMultiRequestResponse`) werden hier
// drei per Task-1-Charakterisierung bekannte Bugs bewusst NICHT reproduziert:
// - kein `_shouldNeverBuffer`-String-Matching (siehe Test
//   "No-Buffer-Scope umgeht ..." unten sowie die bereits bestehende
//   `SessionCoordinator`-Verkabelung, die Login/Logout explizit über
//   `MultiRequestEligibility` und NICHT über Pfad-Strings ausschließt),
// - kein Verlust weiterer High-Priority-Requests beim Flush (siehe Test
//   "GsdRequestPriority.high" unten: ZWEI High-Priority-Requests, beide
//   beantwortet),
// - ein Demux, der die tatsächliche Ergebnis-LISTENlänge (nicht die
//   Envelope-Map-Länge) auswertet (siehe Test "WENIGER Ergebnisse" unten).

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/crypto/client_key_pair.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/batch/batch_coordinator.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

import '../session_test_support.dart';

/// Einfache Test-Policy: dekodiert den Body als JSON-Map.
class _JsonMapResponsePolicy implements IResponsePolicy<Map<String, dynamic>> {
  const _JsonMapResponsePolicy();

  @override
  Map<String, dynamic> decode(
    TransportResponse response, {
    required String operationId,
  }) => jsonDecode(response.body) as Map<String, dynamic>;
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
  GsdHttpMethod method = GsdHttpMethod.get,
  GsdApiVersion version = GsdApiVersion.v1,
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
/// `ApiRequest.priority`. `GsdRequestPriority.normal` benötigt KEINEN Scope
/// (das ist bereits die Voreinstellung ohne aktiven Priority-Scope).
Future<T> _executeWithPriority<T>(
  ApiRuntime runtime,
  ApiRequest<T> request, {
  required GsdRequestPriority priority,
}) {
  final scope = switch (priority) {
    GsdRequestPriority.normal => null,
    GsdRequestPriority.low => GsdRequestPriority.low,
    GsdRequestPriority.high => GsdRequestPriority.high,
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
        final clientKeyPair = await ClientKeyPair.obtain();
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
          clientKeyPair.publicKey,
        );
        return ScriptedResponse(encryptedResponse);
      });

      final results = await Future.wait([
        runtime.execute(_buildRequest()),
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

      final f1 = runtime.execute(_buildRequest());
      final f2 = runtime.execute(
        _buildRequest(
          method: GsdHttpMethod.post,
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
      final config = buildBatchRuntimeConfiguration();
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

      server
        ..enqueue('POST', '/dfapp/v1/multi', multiResponse)
        ..enqueue('POST', '/dfapp/v1/multi', multiResponse);

      await Future.wait([
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/normal/a'),
          priority: GsdRequestPriority.normal,
        ),
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/low/a'),
          priority: GsdRequestPriority.low,
        ),
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/normal/b'),
          priority: GsdRequestPriority.normal,
        ),
        _executeWithPriority(
          runtime,
          _buildRequest(path: '/low/b'),
          priority: GsdRequestPriority.low,
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
        bufferFlushDelayMs: 30,
      );
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server
        ..enqueueJson(
          'GET',
          '/dfapp/v1/normal/solo',
          body: {'value': 'normal'},
        )
        ..enqueueJson('GET', '/dfapp/v1/low/solo', body: {'value': 'low'});

      final normal = _executeWithPriority(
        runtime,
        _buildRequest(path: '/normal/solo'),
        priority: GsdRequestPriority.normal,
      );
      final low = _executeWithPriority(
        runtime,
        _buildRequest(path: '/low/solo'),
        priority: GsdRequestPriority.low,
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

    test('enqueue lehnt GsdRequestPriority.high defensiv ab', () async {
      final config = buildBatchRuntimeConfiguration();
      final coordinator = BatchCoordinator(configuration: config);

      expect(
        () => coordinator.enqueue(
          method: GsdHttpMethod.get,
          uri: Uri.parse('https://server.example:8443/dfapp/v1/high'),
          headers: const {},
          needsSession: false,
          priority: GsdRequestPriority.high,
        ),
        throwsArgumentError,
      );

      await coordinator.dispose();
    });

    test(
      'GsdRequestPriority.high wird SOFORT als Einzelanfrage gesendet, nie '
      'gepuffert; ZWEI High-Priority-Requests werden BEIDE beantwortet '
      '(kein Legacy-Drop weiterer High-Priority-Requests beim Flush)',
      () async {
        final server = MockApiServer();
        final config = buildBatchRuntimeConfiguration(
          bufferFlushDelayMs: 5000,
        );
        final runtime = ApiRuntime(
          configuration: config,
          httpClient: server.client,
          batchCoordinator: BatchCoordinator(configuration: config),
        );

        server
          ..enqueueJson('GET', '/dfapp/v1/high-a', body: {'v': 'a'})
          ..enqueueJson('GET', '/dfapp/v1/high-b', body: {'v': 'b'});

        final fa = _executeWithPriority(
          runtime,
          _buildRequest(path: '/high-a'),
          priority: GsdRequestPriority.high,
        );
        final fb = _executeWithPriority(
          runtime,
          _buildRequest(path: '/high-b'),
          priority: GsdRequestPriority.high,
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
        'dauerhaft offen zu bleiben (Fix des '
        'Legacy-Envelope-Map-vs-Listen-Längen-Bugs)', () async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server
        ..enqueueJson(
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
        )
        ..enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'})
        ..enqueueJson('GET', '/dfapp/v1/c', body: {'v': 'c-fallback'});

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
      final config = buildBatchRuntimeConfiguration();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server
        ..enqueue(
          'POST',
          '/dfapp/v1/multi',
          (req) async =>
              ScriptedResponse('Internal Server Error', statusCode: 500),
        )
        ..enqueueJson('GET', '/dfapp/v1/a', body: {'v': 'a-fallback'})
        ..enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'});

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
      final config = buildBatchRuntimeConfiguration();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server
        ..enqueue(
          'POST',
          '/dfapp/v1/multi',
          (req) async => ScriptedResponse('not json at all'),
        )
        ..enqueueJson('GET', '/dfapp/v1/a', body: {'v': 'a-fallback'})
        ..enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'});

      final fa = runtime.execute(_buildRequest(path: '/a'));
      final fb = runtime.execute(_buildRequest(path: '/b'));

      final results = await Future.wait([
        fa,
        fb,
      ]).timeout(const Duration(seconds: 2));

      expect(results[0], equals({'v': 'a-fallback'}));
      expect(results[1], equals({'v': 'b-fallback'}));
    });

    /// Zwei gepufferte Requests; [multiResponse] beantwortet den
    /// `v1/multi`-POST. Erwartet, dass beide einzeln nachgesendet werden.
    Future<void> expectBothSentIndividually(
      ResponseBuilder multiResponse,
    ) async {
      final server = MockApiServer();
      final config = buildBatchRuntimeConfiguration();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      server
        ..enqueue('POST', '/dfapp/v1/multi', multiResponse)
        ..enqueueJson('GET', '/dfapp/v1/a', body: {'v': 'a-fallback'})
        ..enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'});

      final results = await Future.wait([
        runtime.execute(_buildRequest(path: '/a')),
        runtime.execute(_buildRequest(path: '/b')),
      ]).timeout(const Duration(seconds: 2));

      expect(results, [
        {'v': 'a-fallback'},
        {'v': 'b-fallback'},
      ]);
      expect(server.requests.map((r) => r.path), [
        '/dfapp/v1/multi',
        '/dfapp/v1/a',
        '/dfapp/v1/b',
      ]);
    }

    test('Transportfehler des v1/multi-POST: ALLE gepufferten Requests '
        'werden über den Einzel-Fallback abgeschlossen', () async {
      await expectBothSentIndividually(
        (_) => throw http.ClientException('Verbindung abgebrochen'),
      );
    });

    test('v1/multi-Antwort an einen fremden Schlüssel verschlüsselt: ALLE '
        'gepufferten Requests werden über den Einzel-Fallback '
        'abgeschlossen', () async {
      final foreignKeyPair = await generateServerKeyPair();
      final encryptedBody = await encryptV2Response(
        jsonEncode(
          v1Envelope(
            data: [
              {
                'httpStatus': 200,
                'result': {'v': 'aus-multi'},
              },
              {
                'httpStatus': 200,
                'result': {'v': 'aus-multi'},
              },
            ],
          ),
        ),
        foreignKeyPair.publicKey,
      );

      await expectBothSentIndividually((_) => ScriptedResponse(encryptedBody));
    });

    test('v1/multi-Antwort ist Müll mit einem |: ALLE gepufferten Requests '
        'werden über den Einzel-Fallback abgeschlossen', () async {
      await expectBothSentIndividually(
        (_) => ScriptedResponse('<html>Bad Gateway | nginx</html>'),
      );
    });

    final errorStatuses = <String, Matcher>{
      '302': isA<GsdInvalidCredentialsException>(),
      '999': isA<GsdServerException>().having(
        (e) => e.internalStatus,
        'internalStatus',
        '999',
      ),
    };
    for (final MapEntry(key: status, value: matcher) in errorStatuses.entries) {
      test(
        'ein Eintrag mit Status $status scheitert nur bei seinem Aufrufer; '
        'die anderen erhalten ihr Ergebnis, nichts wird nachgesendet',
        () async {
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
                {'httpStatus': 200, 'result': v1Envelope(data: 'a')},
                {
                  'httpStatus': 200,
                  'result': v1Envelope(
                    internalStatus: status,
                    statusMessage: 'fehler',
                  ),
                },
                {'httpStatus': 200, 'result': v1Envelope(data: 'c')},
              ],
            ),
          );

          ApiRequest<Object?> buildDataRequest(String path) =>
              ApiRequest<Object?>(
                method: GsdHttpMethod.get,
                version: GsdApiVersion.v1,
                path: path,
                authentication: AuthenticationPolicy.none,
                responsePolicy: const DataResponsePolicy<Object?>(),
                operationId: 'test.batch.data',
              );

          final fa = runtime.execute(buildDataRequest('/a'));
          final fb = runtime.execute(buildDataRequest('/b'));
          final fc = runtime.execute(buildDataRequest('/c'));
          final fbExpectation = expectLater(fb, throwsA(matcher));

          expect(await fa.timeout(const Duration(seconds: 2)), 'a');
          expect(await fc.timeout(const Duration(seconds: 2)), 'c');
          await fbExpectation;
          expect(server.requests.map((r) => r.path), ['/dfapp/v1/multi']);
        },
      );
    }

    final malformedEntries = <String, Object?>{
      'kein Objekt': 'kaputt',
      'httpStatus als String': {
        'httpStatus': '200',
        'result': {'v': 'b'},
      },
      'ohne httpStatus': {
        'result': {'v': 'b'},
      },
    };
    for (final MapEntry(key: name, value: entry) in malformedEntries.entries) {
      test('fehlerhafter Eintrag ($name): er und ALLE folgenden Requests '
          'laufen über den Einzel-Fallback, auch wenn deren Einträge '
          'gültig sind', () async {
        final server = MockApiServer();
        final config = buildBatchRuntimeConfiguration();
        final runtime = ApiRuntime(
          configuration: config,
          httpClient: server.client,
          batchCoordinator: BatchCoordinator(configuration: config),
        );

        server
          ..enqueueJson(
            'POST',
            '/dfapp/v1/multi',
            body: v1Envelope(
              data: [
                {
                  'httpStatus': 200,
                  'result': {'v': 'a'},
                },
                entry,
                {
                  'httpStatus': 200,
                  'result': {'v': 'c'},
                },
              ],
            ),
          )
          ..enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'})
          ..enqueueJson('GET', '/dfapp/v1/c', body: {'v': 'c-fallback'});

        final results = await Future.wait([
          runtime.execute(_buildRequest(path: '/a')),
          runtime.execute(_buildRequest(path: '/b')),
          runtime.execute(_buildRequest(path: '/c')),
        ]).timeout(const Duration(seconds: 2));

        expect(results, [
          {'v': 'a'},
          {'v': 'b-fallback'},
          {'v': 'c-fallback'},
        ]);
        expect(server.requests.map((r) => r.path), [
          '/dfapp/v1/multi',
          '/dfapp/v1/b',
          '/dfapp/v1/c',
        ]);
      });
    }
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
      final config = buildBatchRuntimeConfiguration();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        batchCoordinator: BatchCoordinator(configuration: config),
      );

      final cases = <(GsdApiVersion, String, String)>[
        (GsdApiVersion.v1, '/logout', '/dfapp/v1/logout'),
        (GsdApiVersion.v2, '/login/secure/key', '/dfapp/v2/login/secure/key'),
        (GsdApiVersion.v2, '/login/key', '/dfapp/v2/login/key'),
        (GsdApiVersion.v2, '/login', '/dfapp/v2/login'),
        (GsdApiVersion.v1, '/_CheckSession', '/dfapp/v1/_CheckSession'),
        (GsdApiVersion.v1, '/_CheckService', '/dfapp/v1/_CheckService'),
        (GsdApiVersion.v1, '/xSync', '/dfapp/v1/xSync'),
        (
          GsdApiVersion.v1,
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

      server
        ..enqueueJson('GET', '/dfapp/v1/a', body: {'value': 'a'})
        ..enqueueJson('GET', '/dfapp/v1/b', body: {'value': 'b'});

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
        priority: GsdRequestPriority.low,
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
      server
        ..enqueueJson(
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
        )
        ..enqueueJson('GET', '/dfapp/v1/b', body: {'v': 'b-fallback'})
        ..enqueueJson('GET', '/dfapp/v1/c', body: {'v': 'c-fallback'});

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
        _buildRequest(path: '/a'),
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
          final config = buildBatchRuntimeConfiguration();
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
                data: {
                  'key': encodePublicKeyToCleanPem(serverPublicKey),
                },
              ),
            );
          }

          void scriptLoginSuccess(String sessionId) {
            server.enqueue('POST', '/dfapp/v2/login', (req) async {
              return ScriptedResponse(
                jsonEncode(
                  v1Envelope(data: {'sessionId': sessionId}),
                ),
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

          ApiRequest<Object?> buildSessionRequest(String path) =>
              ApiRequest<Object?>(
                method: GsdHttpMethod.get,
                version: GsdApiVersion.v1,
                path: path,
                authentication: AuthenticationPolicy.session,
                responsePolicy: const DataResponsePolicy<Object?>(),
                operationId: 'test.batch.session-retry',
              );

          final fa = runtime.execute(buildSessionRequest('/probe-a'));
          final fb = runtime.execute(buildSessionRequest('/probe-b'));

          final results = await Future.wait([
            fa,
            fb,
          ]).timeout(const Duration(seconds: 2));

          expect(results, [
            {'ok': 'retried'},
            {'ok': true},
          ]);
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
