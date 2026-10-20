// Unit-Tests für ApiRuntime: End-to-End-Pipeline mit MockClient inkl.
// Dekodierung, Buffering-Naht, Sessionzustand, Telemetrie sowie
// idempotentes dispose() mit StateError-Guard und Client-Ownership.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/batch/batch_coordinator.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/binary_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'runtime_test_helpers.dart';
import 'session_test_support.dart';

/// Einfache Test-Policy: dekodiert den Body als JSON-Map.
class JsonMapResponsePolicy implements ResponsePolicy<Map<String, dynamic>> {
  const JsonMapResponsePolicy();

  @override
  Map<String, dynamic> decode(TransportResponse response) =>
      jsonDecode(response.body) as Map<String, dynamic>;
}

void main() {
  test('ApiRequest source contains no endpoint-owned execution policy', () {
    final source = File('lib/src/runtime/api_request.dart').readAsStringSync();

    expect(source, isNot(contains('BufferingPolicy')));
    expect(source, isNot(contains('ApiRequestPriority')));
    expect(source, isNot(contains('copyWith(')));
  });

  ApiRequest<Map<String, dynamic>> buildRequest({
    ApiHttpMethod method = ApiHttpMethod.get,
    ApiVersion version = ApiVersion.v1,
    String path = '/ping',
    Map<String, String>? queryParameters,
    String? body,
    AuthenticationPolicy authentication = AuthenticationPolicy.session,
  }) {
    return ApiRequest<Map<String, dynamic>>(
      method: method,
      version: version,
      path: path,
      queryParameters: queryParameters,
      body: body,
      authentication: authentication,
      responsePolicy: const JsonMapResponsePolicy(),
      operationId: 'test.ping',
    );
  }

  RuntimeConfiguration buildScopeRuntimeConfiguration() {
    return RuntimeConfiguration(
      serverUrl: 'https://server.example:8443',
      baseUri: Uri.parse('https://server.example:8443'),
      alias: 'dfapp',
      appKey: 'TEST-APP-KEY',
      userName: 'tester',
      appNames: const ['GSD-RestApi'],
      additionalAppNames: const [],
      device: null,
      connectionTimeout: const Duration(seconds: 5),
      responseTimeout: const Duration(seconds: 5),
      allowSslError: false,
      debugLogs: false,
      useBase64UrlParameter: false,
      initialSessionId: '',
      multiRequest: true,
      maxBufferSize: 10,
      bufferFlushDelayMs: 5000,
    );
  }

  ApiRequest<Map<String, dynamic>> buildBufferedProbe(String path) {
    return ApiRequest<Map<String, dynamic>>(
      method: ApiHttpMethod.get,
      version: ApiVersion.v1,
      path: path,
      authentication: AuthenticationPolicy.none,
      responsePolicy: const JsonMapResponsePolicy(),
      operationId: 'test.scope.buffered-probe',
    );
  }

  group('ApiRuntime.execute', () {
    test('V2 is direct even when multi-request is globally enabled', () async {
      http.Request? captured;
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(multiRequest: true),
        httpClient: MockClient((request) async {
          captured = request;
          return http.Response('{"direct":true}', 200);
        }),
      );

      final result = await runtime.execute(
        ApiRequest<Map<String, dynamic>>(
          method: ApiHttpMethod.get,
          version: ApiVersion.v2,
          path: '/system/versionInfo',
          authentication: AuthenticationPolicy.session,
          responsePolicy: const JsonMapResponsePolicy(),
          operationId: 'v2.system.versionInfo',
        ),
      );

      expect(result, {'direct': true});
      expect(captured?.url.path, '/dfapp/v2/system/versionInfo');
    });

    test('binary response marker bypasses response decryption', () async {
      final bytes = Uint8List.fromList(utf8.encode('not-base64|still-binary'));
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: MockClient(
          (request) async => http.Response.bytes(bytes, 200),
        ),
      );

      final result = await runtime.execute(
        ApiRequest<Uint8List>(
          method: ApiHttpMethod.get,
          version: ApiVersion.v1,
          path: '/file/oid-1',
          authentication: AuthenticationPolicy.session,
          responsePolicy: const _BinaryBytesPolicy(),
          operationId: 'v1.documents.file',
        ),
      );

      expect(result, bytes);
    });

    test(
      'absolute GET seam sends the exact URI without default headers',
      () async {
        http.Request? captured;
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: MockClient((request) async {
            captured = request;
            return http.Response('{"ok":true}', 200);
          }),
        );
        final uri = Uri.parse(
          'https://status.example:9443/root/_CheckService?probe=1',
        );

        final result = await runtime.executeAbsoluteGet(
          uri: uri,
          timeout: const Duration(seconds: 10),
          responsePolicy: const JsonMapResponsePolicy(),
          operationId: 'v1.service.checkWithUri',
        );

        expect(result, {'ok': true});
        expect(captured?.url, uri);
        expect(captured?.headers, isEmpty);
      },
    );

    test('absolute GET seam honors its caller-supplied timeout', () async {
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: MockClient((request) async {
          await Future<void>.delayed(const Duration(milliseconds: 25));
          return http.Response('{"ok":true}', 200);
        }),
      );

      await expectLater(
        runtime.executeAbsoluteGet(
          uri: Uri.parse('https://status.example/_CheckService'),
          timeout: const Duration(milliseconds: 1),
          responsePolicy: const JsonMapResponsePolicy(),
          operationId: 'test.absolute.timeout',
        ),
        throwsA(isA<TimeoutException>()),
      );
    });

    test('Pipeline: URI, Header, Transport und Dekodierung', () async {
      http.Request? captured;
      final client = MockClient((request) async {
        captured = request;
        return http.Response('{"ok":true}', 200);
      });
      final logs = <String>[];
      final metrics = <RestApiHttpMetric>[];
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(sessionId: 'sess-1'),
        callbacks: RestApiDOCUframeCallbacks(
          onLogMessage: (message) async => logs.add(message),
          onHttpMetricRecorded: (metric) async => metrics.add(metric),
        ),
        httpClient: client,
      );

      final result = await runtime.execute(
        buildRequest(queryParameters: {'a': 'b'}),
      );

      expect(result, equals({'ok': true}));
      expect(captured, isNotNull);
      expect(
        captured!.url.toString(),
        equals('https://server.example:8443/dfapp/v1/ping?a=b'),
      );
      expect(captured!.method, equals('GET'));
      expect(captured!.headers['appkey'], equals('TEST-APP-KEY'));
      expect(captured!.headers['sessionid'], equals('sess-1'));
      expect(
        captured!.headers['Content-type'],
        equals('application/json; charset=utf-8'),
      );
      // Telemetrie: Start- und Erfolgs-Event plus Metrik.
      expect(logs.where((l) => l.contains('Request started')), hasLength(1));
      expect(logs.where((l) => l.contains('Request succeeded')), hasLength(1));
      expect(metrics, hasLength(1));
      expect(metrics.single.responseCode, equals(200));
    });

    test(
      'ResponsePolicy erhält Status, Header und Bytes der Antwort',
      () async {
        final client = MockClient((request) async {
          return http.Response('{"x":1}', 207, headers: {'x-check': 'yes'});
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
        );
        TransportResponse? seen;
        final request = ApiRequest<void>(
          method: ApiHttpMethod.get,
          version: ApiVersion.v2,
          path: '/probe',
          authentication: AuthenticationPolicy.none,
          responsePolicy: _CapturingPolicy((response) => seen = response),
          operationId: 'test.probe',
        );

        await runtime.execute(request);

        expect(seen, isNotNull);
        expect(seen!.statusCode, equals(207));
        expect(seen!.headers['x-check'], equals('yes'));
        expect(seen!.body, equals('{"x":1}'));
        expect(seen!.bodyBytes, equals(utf8.encode('{"x":1}')));
      },
    );

    test(
      'Session-Änderung über SessionState wirkt auf Folge-Requests',
      () async {
        final capturedSessionIds = <String?>[];
        final client = MockClient((request) async {
          capturedSessionIds.add(request.headers['sessionid']);
          return http.Response('{}', 200);
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(sessionId: 'sess-old'),
          httpClient: client,
        );

        await runtime.execute(buildRequest());
        runtime.sessionState.sessionId = 'sess-new';
        await runtime.execute(buildRequest());

        expect(capturedSessionIds, equals(['sess-old', 'sess-new']));
      },
    );

    test('spätere sessionId-Mutation der Legacy-Config beeinflusst den '
        'Runtime nicht', () async {
      String? capturedSessionId;
      final client = MockClient((request) async {
        capturedSessionId = request.headers['sessionid'];
        return http.Response('{}', 200);
      });
      final config = buildDocuframeConfig(sessionId: 'sess-original');
      final runtime = ApiRuntime(
        configuration: RuntimeConfiguration.fromDocuframeConfig(config),
        httpClient: client,
      );

      config.sessionId = 'sess-mutiert';
      await runtime.execute(buildRequest());

      expect(capturedSessionId, equals('sess-original'));
    });

    test('Transport-Fehler wird propagiert und als failed gemeldet', () async {
      final client = MockClient((request) async {
        throw http.ClientException('Verbindung abgelehnt');
      });
      final logs = <String>[];
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        callbacks: RestApiDOCUframeCallbacks(
          onLogMessage: (message) async => logs.add(message),
        ),
        httpClient: client,
      );

      await expectLater(
        () => runtime.execute(buildRequest()),
        throwsA(isA<http.ClientException>()),
      );
      expect(logs.where((l) => l.contains('Request failed')), hasLength(1));
    });

    test('Dekodier-Fehler wird als failed telemetriert (kein success), '
        'Metrik genau einmal mit Statuscode', () async {
      final client = MockClient(
        (request) async => http.Response('{"kaputt": true}', 200),
      );
      final logs = <String>[];
      final metrics = <RestApiHttpMetric>[];
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        callbacks: RestApiDOCUframeCallbacks(
          onLogMessage: (message) async => logs.add(message),
          onHttpMetricRecorded: (metric) async => metrics.add(metric),
        ),
        httpClient: client,
      );
      final request = ApiRequest<void>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/probe',
        authentication: AuthenticationPolicy.none,
        responsePolicy: _ThrowingPolicy(),
        operationId: 'test.decode-fehler',
      );

      await expectLater(
        () => runtime.execute(request),
        throwsA(isA<FormatException>()),
      );

      expect(
        logs.where((l) => l.contains('Request succeeded')),
        isEmpty,
        reason: 'Dekodier-Fehler darf kein Erfolgs-Event erzeugen',
      );
      expect(logs.where((l) => l.contains('Request failed')), hasLength(1));
      expect(metrics, hasLength(1));
      expect(metrics.single.responseCode, equals(200));
    });

    test(
      'ein multi-fähiger Request läuft bei multiRequest:false direkt',
      () async {
        http.Request? captured;
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(multiRequest: false),
          httpClient: MockClient((request) async {
            captured = request;
            return http.Response('{"direct":true}', 200);
          }),
        );

        final result = await runtime.execute(buildRequest());

        expect(result, equals({'direct': true}));
        expect(captured?.url.path, equals('/dfapp/v1/ping'));
      },
    );

    test('ein multi-fähiger Request benötigt bei multiRequest:true einen '
        'BatchCoordinator', () async {
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(multiRequest: true),
        httpClient: MockClient((request) async => http.Response('{}', 200)),
      );

      await expectLater(
        () => runtime.execute(buildRequest()),
        throwsUnsupportedError,
      );
    });

    group('scope overlays', () {
      test('withoutBuffering sends a bufferable request immediately', () async {
        final server = MockApiServer();
        final configuration = buildScopeRuntimeConfiguration();
        final runtime = ApiRuntime(
          configuration: configuration,
          httpClient: server.client,
          batchCoordinator: BatchCoordinator(configuration: configuration),
        );
        addTearDown(runtime.dispose);
        server.enqueueJson(
          'GET',
          '/dfapp/v1/scope/no-buffer',
          body: {'ok': true},
        );

        final future = RuntimeExecutionContext.runWithoutBuffering(
          () => runtime.execute(buildBufferedProbe('/scope/no-buffer')),
        );

        await future.timeout(const Duration(seconds: 1));
        expect(server.requests.single.path, '/dfapp/v1/scope/no-buffer');
        expect(server.requests.single.path, isNot('/dfapp/v1/multi'));
      });

      test('high scope bypasses buffering for a bufferable request', () async {
        final server = MockApiServer();
        final configuration = buildScopeRuntimeConfiguration();
        final runtime = ApiRuntime(
          configuration: configuration,
          httpClient: server.client,
          batchCoordinator: BatchCoordinator(configuration: configuration),
        );
        addTearDown(runtime.dispose);
        server.enqueueJson('GET', '/dfapp/v1/scope/high', body: {'ok': true});

        await RuntimeExecutionContext.runWithPriority(
          () => runtime.execute(buildBufferedProbe('/scope/high')),
          RequestPriority.high,
        ).timeout(const Duration(seconds: 1));

        expect(server.requests.single.path, '/dfapp/v1/scope/high');
      });

      test(
        'external transport honors an active no-buffer/high-priority scope',
        () async {
          final runtime = ApiRuntime(
            configuration: buildRuntimeConfiguration(),
            httpClient: MockClient((request) async => http.Response('{}', 200)),
          );
          addTearDown(runtime.dispose);

          final result = await RuntimeExecutionContext.runWithoutBuffering(
            () => RuntimeExecutionContext.runWithPriority(
              () => runtime.executeExternalTransport(
                request: buildRequest(),
                send: (uri, headers) async => TransportResponse(
                  statusCode: 200,
                  headers: const {},
                  bodyBytes: utf8.encode('{"external":true}'),
                  body: '{"external":true}',
                ),
              ),
              RequestPriority.high,
            ),
          );

          expect(result, {'external': true});
        },
      );
    });
  });

  group('ApiRuntime.dispose', () {
    test('dispose ist idempotent', () async {
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: MockClient((request) async => http.Response('{}', 200)),
      );

      await runtime.dispose();
      await runtime.dispose();

      expect(runtime.isDisposed, isTrue);
    });

    test('execute nach dispose wirft StateError', () async {
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: MockClient((request) async => http.Response('{}', 200)),
      );

      await runtime.dispose();

      await expectLater(
        () => runtime.execute(buildRequest()),
        throwsStateError,
      );
    });

    test('injizierter Client wird von dispose NICHT geschlossen', () async {
      final tracking = TrackingClient(
        MockClient((request) async => http.Response('{}', 200)),
      );
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: tracking,
      );

      await runtime.dispose();

      expect(tracking.closed, isFalse);
    });

    test('selbst erzeugter Client: dispose läuft fehlerfrei durch', () async {
      final runtime = ApiRuntime(configuration: buildRuntimeConfiguration());

      await runtime.dispose();
      await runtime.dispose();

      expect(runtime.isDisposed, isTrue);
    });
  });
}

/// Policy, die die TransportResponse an den Test durchreicht.
class _CapturingPolicy implements ResponsePolicy<void> {
  final void Function(TransportResponse response) _onDecode;

  _CapturingPolicy(this._onDecode);

  @override
  void decode(TransportResponse response) => _onDecode(response);
}

/// Policy, die beim Dekodieren immer wirft (simuliert z.B. das
/// V1-Exception-Mapping).
class _ThrowingPolicy implements ResponsePolicy<void> {
  @override
  void decode(TransportResponse response) {
    throw const FormatException('Dekodierung fehlgeschlagen');
  }
}

class _BinaryBytesPolicy implements BinaryResponsePolicy<Uint8List> {
  const _BinaryBytesPolicy();

  @override
  Uint8List decode(TransportResponse response) => response.bodyBytes;
}
