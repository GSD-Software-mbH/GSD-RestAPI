import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/batch/batch_coordinator.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/request_priority.dart';
import 'package:gsd_restapi/src/runtime/policies/rest_api_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:pointycastle/export.dart';

import 'session_test_support.dart';

ApiRequest<RestApiResponse> _sessionRequest(String path) {
  return ApiRequest<RestApiResponse>(
    method: ApiHttpMethod.get,
    version: ApiVersion.v1,
    path: path,
    authentication: AuthenticationPolicy.session,
    responsePolicy: const RestApiResponsePolicy(),
    operationId: 'test.multi.session-recovery',
  );
}

final class _Harness {
  final MockApiServer server;
  final ApiRuntime runtime;
  final SessionCoordinator sessions;
  final AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> serverKeyPair;

  const _Harness({
    required this.server,
    required this.runtime,
    required this.sessions,
    required this.serverKeyPair,
  });

  void enqueueLoginKey() {
    server.enqueueJson(
      'GET',
      '/dfapp/v2/login/key',
      body: v1Envelope(
        data: {'key': encodePublicKeyToCleanPem(serverKeyPair.publicKey)},
      ),
    );
  }

  void enqueueLoginSuccess(
    String sessionId, {
    Future<void> Function(RecordedRequest request)? inspect,
  }) {
    server.enqueue('POST', '/dfapp/v2/login', (request) async {
      await inspect?.call(request);
      return ScriptedResponse(
        jsonEncode(v1Envelope(data: {'sessionId': sessionId})),
      );
    });
  }
}

Future<_Harness> _buildLoggedInHarness({
  RestApiDOCUframeCallbacks? callbacks,
}) async {
  final server = MockApiServer();
  final keyPair = await generateServerKeyPair();
  final configuration = buildSessionRuntimeConfiguration(
    multiRequest: true,
    bufferFlushDelayMs: 10,
  );
  final sessions = SessionCoordinator(
    configuration: configuration,
    callbacks: callbacks,
    retryDelay: const Duration(milliseconds: 5),
  );
  final runtime = ApiRuntime(
    configuration: configuration,
    callbacks: callbacks,
    httpClient: server.client,
    sessionCoordinator: sessions,
    batchCoordinator: BatchCoordinator(configuration: configuration),
  );
  final harness = _Harness(
    server: server,
    runtime: runtime,
    sessions: sessions,
    serverKeyPair: keyPair,
  );

  harness.enqueueLoginKey();
  harness.enqueueLoginSuccess('session-initial');
  await sessions.login('md5hash');
  return harness;
}

void main() {
  ensureLegacyCryptoTestEnvironment();

  test('mehrere demultiplexte 201/204-Fehler teilen genau einen Refresh und '
      'werden danach einzeln wiederholt', () async {
    final harness = await _buildLoggedInHarness();
    final baseline = harness.server.requests.length;

    harness.server.enqueueJson(
      'POST',
      '/dfapp/v1/multi',
      body: v1Envelope(
        data: [
          {
            'httpStatus': 200,
            'result': v1Envelope(
              internalStatus: '201',
              statusMessage: 'expired',
            ),
          },
          {
            'httpStatus': 200,
            'result': v1Envelope(
              internalStatus: '204',
              statusMessage: 'missing session',
            ),
          },
        ],
      ),
    );
    harness.enqueueLoginKey();
    harness.enqueueLoginSuccess('session-refreshed');
    harness.server.enqueueJson(
      'GET',
      '/dfapp/v1/a',
      body: v1Envelope(data: {'value': 'a'}),
    );
    harness.server.enqueueJson(
      'GET',
      '/dfapp/v1/b',
      body: v1Envelope(data: {'value': 'b'}),
    );

    final responses = await Future.wait([
      harness.runtime.execute(_sessionRequest('/a')),
      harness.runtime.execute(_sessionRequest('/b')),
    ]).timeout(const Duration(seconds: 3));

    expect(responses.every((response) => response.isOk), isTrue);
    expect(harness.sessions.sessionState.sessionId, 'session-refreshed');

    final requests = harness.server.requests.sublist(baseline);
    expect(
      requests.where((request) => request.path == '/dfapp/v1/multi'),
      hasLength(1),
    );
    expect(
      requests.where((request) => request.path == '/dfapp/v2/login/key'),
      hasLength(1),
    );
    expect(
      requests.where((request) => request.path == '/dfapp/v2/login'),
      hasLength(1),
    );
    final retries = requests
        .where(
          (request) =>
              request.path == '/dfapp/v1/a' || request.path == '/dfapp/v1/b',
        )
        .toList();
    expect(retries, hasLength(2));
    expect(
      retries.every(
        (request) => request.header('sessionid') == 'session-refreshed',
      ),
      isTrue,
    );
  });

  test('äußerer 201-Fehler des Multi-Envelopes wird ohne stale Einzel-Fallback '
      'über denselben Single-Flight-Refresh behandelt', () async {
    final harness = await _buildLoggedInHarness();
    final baseline = harness.server.requests.length;

    harness.server.enqueueJson(
      'POST',
      '/dfapp/v1/multi',
      statusCode: 401,
      body: v1Envelope(
        internalStatus: '201',
        statusMessage: 'outer session expired',
      ),
    );
    harness.enqueueLoginKey();
    harness.enqueueLoginSuccess('session-outer-refreshed');
    harness.server.enqueueJson(
      'GET',
      '/dfapp/v1/a',
      body: v1Envelope(data: {'value': 'a'}),
    );
    harness.server.enqueueJson(
      'GET',
      '/dfapp/v1/b',
      body: v1Envelope(data: {'value': 'b'}),
    );

    await Future.wait([
      harness.runtime.execute(_sessionRequest('/a')),
      harness.runtime.execute(_sessionRequest('/b')),
    ]).timeout(const Duration(seconds: 3));

    final requests = harness.server.requests.sublist(baseline);
    expect(
      requests.where((request) => request.path == '/dfapp/v2/login/key'),
      hasLength(1),
    );
    expect(
      requests.where((request) => request.path == '/dfapp/v2/login'),
      hasLength(1),
    );
    expect(
      requests
          .where(
            (request) =>
                request.path == '/dfapp/v1/a' || request.path == '/dfapp/v1/b',
          )
          .length,
      2,
      reason: 'Vor dem Refresh darf kein zusätzlicher stale Fallback laufen.',
    );
  });

  test('mehrere 341-Teilfehler lösen genau einen 2FA-Callback aus', () async {
    var tokenCallbackCount = 0;
    final callbacks = RestApiDOCUframeCallbacks(
      onMissing2FAToken: () async {
        tokenCallbackCount++;
        await Future<void>.delayed(const Duration(milliseconds: 2));
        return '654321';
      },
    );
    final harness = await _buildLoggedInHarness(callbacks: callbacks);
    final baseline = harness.server.requests.length;

    harness.server.enqueueJson(
      'POST',
      '/dfapp/v1/multi',
      body: v1Envelope(
        data: [
          {
            'httpStatus': 200,
            'result': v1Envelope(
              internalStatus: '341',
              statusMessage: '2fa required',
            ),
          },
          {
            'httpStatus': 200,
            'result': v1Envelope(
              internalStatus: '341',
              statusMessage: '2fa required',
            ),
          },
        ],
      ),
    );
    harness.enqueueLoginKey();
    harness.enqueueLoginSuccess(
      'session-2fa',
      inspect: (request) async {
        final clearBody =
            jsonDecode(
                  await decryptV2LoginBody(
                    request.body,
                    harness.serverKeyPair.privateKey,
                  ),
                )
                as Map<String, dynamic>;
        expect(clearBody['2faToken'], '654321');
      },
    );
    harness.server.enqueueJson(
      'GET',
      '/dfapp/v1/a',
      body: v1Envelope(data: {'value': 'a'}),
    );
    harness.server.enqueueJson(
      'GET',
      '/dfapp/v1/b',
      body: v1Envelope(data: {'value': 'b'}),
    );

    await Future.wait([
      harness.runtime.execute(_sessionRequest('/a')),
      harness.runtime.execute(_sessionRequest('/b')),
    ]).timeout(const Duration(seconds: 3));

    expect(tokenCallbackCount, 1);
    final requests = harness.server.requests.sublist(baseline);
    expect(
      requests.where((request) => request.path == '/dfapp/v2/login/key'),
      hasLength(1),
    );
    expect(
      requests.where((request) => request.path == '/dfapp/v2/login'),
      hasLength(1),
    );
  });

  test(
    'scope policies remain effective across session refresh and retry',
    () async {
      final harness = await _buildLoggedInHarness();
      final baseline = harness.server.requests.length;
      final observedPolicies = <RuntimeExecutionPolicy>[];

      harness.server.enqueueJson(
        'GET',
        '/dfapp/v1/scope/recovery',
        body: v1Envelope(internalStatus: '201', statusMessage: 'expired'),
      );
      harness.enqueueLoginKey();
      harness.enqueueLoginSuccess('session-scoped');
      harness.server.enqueueJson(
        'GET',
        '/dfapp/v1/scope/recovery',
        body: v1Envelope(data: {'ok': true}),
      );

      // Der Request selbst kennt keine Priorität/Buffering-Policy mehr -
      // die Response-Policy beobachtet stattdessen die zum Zeitpunkt jedes
      // Dekodierversuchs (initialer 201-Fehlversuch UND Retry) über
      // `RuntimeExecutionContext.capture()` sichtbare effektive Policy.
      final request = ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/scope/recovery',
        authentication: AuthenticationPolicy.session,
        responsePolicy: _ScopedRecoveryResponsePolicy(observedPolicies),
        operationId: 'test.scope.session-recovery',
      );

      final response = await RuntimeExecutionContext.runWithoutBuffering(
        () => RuntimeExecutionContext.runWithPriority(
          () => harness.runtime.execute(request),
          RequestPriority.high,
        ),
      ).timeout(const Duration(seconds: 3));

      expect(response.isOk, isTrue);
      expect(observedPolicies, hasLength(2));
      for (final policy in observedPolicies) {
        expect(policy.skipBuffering, isTrue);
        expect(policy.priority, ApiRequestPriority.high);
      }

      final requests = harness.server.requests.sublist(baseline);
      final attempts = requests
          .where((request) => request.path == '/dfapp/v1/scope/recovery')
          .toList();
      expect(attempts, hasLength(2));
      expect(attempts.map((request) => request.header('sessionid')), [
        'session-initial',
        'session-scoped',
      ]);
      expect(
        requests.where((request) => request.path == '/dfapp/v1/multi'),
        isEmpty,
      );
    },
  );
}

/// Beobachtet die zum Zeitpunkt jedes Dekodierversuchs (initialer
/// Fehlversuch UND Session-Retry) über `RuntimeExecutionContext.capture()`
/// sichtbare effektive [RuntimeExecutionPolicy], bevor an die normale
/// [RestApiResponsePolicy]-Validierung (inkl. Exception-Mapping) delegiert
/// wird. Ersetzt den früheren `copyWith`-basierten Overlay-Mechanismus, der
/// mit dem Wegfall von `ApiRequest.buffering`/`priority` entfallen ist.
class _ScopedRecoveryResponsePolicy implements ResponsePolicy<RestApiResponse> {
  final List<RuntimeExecutionPolicy> observations;

  _ScopedRecoveryResponsePolicy(this.observations);

  @override
  RestApiResponse decode(TransportResponse response) {
    observations.add(RuntimeExecutionContext.capture());
    return const RestApiResponsePolicy().decode(response);
  }
}
