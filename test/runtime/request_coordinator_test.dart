// Unit-Tests für RequestCoordinator: reine Future-Dedup-Semantik
// (Completer-basiert, unabhängig von ApiRuntime) sowie die Integration in
// ApiRuntime (MockClient-basierte HTTP-Zähltests inkl. Zusammenspiel mit
// dem Session-Retry aus session_coordinator_test.dart).
//
// Anders als der Legacy-Dedup (`RestApiDOCUframeManager._performRequest`,
// per Task-1-Charakterisierung nachweislich wirkungslos) wird hier ECHT
// dedupliziert: Nebenläufige, schlüsselgleiche Requests teilen sich EINE
// HTTP-Anfrage und EIN Ergebnis (Erfolg wie Fehler).

import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/rest_api_response_policy.dart';
import 'package:gsd_restapi/src/runtime/request/request_coordinator.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'runtime_test_helpers.dart';
import 'session_test_support.dart';

/// Einfache Test-Policy: dekodiert den Body als JSON-Map.
class _JsonMapResponsePolicy implements ResponsePolicy<Map<String, dynamic>> {
  const _JsonMapResponsePolicy();

  @override
  Map<String, dynamic> decode(TransportResponse response) =>
      jsonDecode(response.body) as Map<String, dynamic>;
}

class _StringResponsePolicy implements ResponsePolicy<String> {
  const _StringResponsePolicy();

  @override
  String decode(TransportResponse response) => response.body;
}

class _TaggedMapResponsePolicy implements ResponsePolicy<Map<String, dynamic>> {
  final String tag;

  const _TaggedMapResponsePolicy(this.tag);

  @override
  Map<String, dynamic> decode(TransportResponse response) => {
    ...jsonDecode(response.body) as Map<String, dynamic>,
    'tag': tag,
  };
}

void main() {
  ensureLegacyCryptoTestEnvironment();

  group('RequestCoordinator.deduplicate (isoliert, Completer-basiert)', () {
    test(
      'teilt ein In-Flight-Future (dieselbe Instanz); nach Abschluss wird '
      'der Schlüssel freigegeben und ein neuer Aufruf führt erneut aus',
      () async {
        final coordinator = RequestCoordinator();
        var calls = 0;
        var completer = Completer<int>();
        Future<int> action() {
          calls++;
          return completer.future;
        }

        final f1 = coordinator.deduplicate('k', action);
        final f2 = coordinator.deduplicate('k', action);

        // action() wurde nur EINMAL aufgerufen; beide Aufrufer teilen sich
        // dasselbe Future-Objekt.
        expect(calls, equals(1));
        expect(identical(f1, f2), isTrue);

        completer.complete(42);
        expect(await f1, equals(42));
        expect(await f2, equals(42));

        // Schlüssel ist nach Abschluss frei: ein neuer, nicht überlappender
        // Aufruf führt die Aktion erneut aus.
        completer = Completer<int>();
        final f3 = coordinator.deduplicate('k', action);
        expect(calls, equals(2));
        completer.complete(7);
        expect(await f3, equals(7));
      },
    );

    test('Fehler propagieren an ALLE geteilten Aufrufer; der Schlüssel wird '
        'trotzdem freigegeben', () async {
      final coordinator = RequestCoordinator();
      var calls = 0;
      final completer = Completer<int>();
      Future<int> action() {
        calls++;
        return completer.future;
      }

      final f1 = coordinator.deduplicate('k', action);
      final f2 = coordinator.deduplicate('k', action);

      completer.completeError(StateError('boom'));

      await expectLater(f1, throwsA(isA<StateError>()));
      await expectLater(f2, throwsA(isA<StateError>()));
      expect(calls, equals(1));

      final f3 = coordinator.deduplicate('k', () async {
        calls++;
        return 99;
      });
      expect(await f3, equals(99));
      expect(calls, equals(2));
    });

    test('unterschiedliche Schlüssel laufen unabhängig voneinander', () async {
      final coordinator = RequestCoordinator();
      var calls = 0;
      Future<int> action() async {
        calls++;
        return calls;
      }

      final results = await Future.wait([
        coordinator.deduplicate('a', action),
        coordinator.deduplicate('b', action),
      ]);

      expect(calls, equals(2));
      expect(results, equals([1, 2]));
    });

    test('synchron geworfener Fehler wird als Future-Fehler geliefert und '
        'blockiert den Schlüssel nicht', () async {
      final coordinator = RequestCoordinator();

      final failed = coordinator.deduplicate<int>('k', () {
        throw StateError('synchronous boom');
      });
      await expectLater(failed, throwsA(isA<StateError>()));

      expect(await coordinator.deduplicate('k', () async => 7), equals(7));
    });
  });

  group('ApiRuntime + RequestCoordinator (MockClient)', () {
    ApiRequest<Map<String, dynamic>> buildRequest({
      ApiHttpMethod method = ApiHttpMethod.get,
      ApiVersion version = ApiVersion.v1,
      String path = '/ping',
      Map<String, String>? queryParameters,
      String? body,
      Map<String, String>? additionalHeaders,
      DeduplicationPolicy deduplication = DeduplicationPolicy.enabled,
      ResponsePolicy<Map<String, dynamic>> responsePolicy =
          const _JsonMapResponsePolicy(),
      String operationId = 'test.dedup',
    }) {
      return ApiRequest<Map<String, dynamic>>(
        method: method,
        version: version,
        path: path,
        queryParameters: queryParameters,
        body: body,
        additionalHeaders: additionalHeaders,
        authentication: AuthenticationPolicy.none,
        deduplication: deduplication,
        responsePolicy: responsePolicy,
        operationId: operationId,
      );
    }

    test(
      'zwei nebenläufige identische GETs: genau EIN HTTP-Request erreicht '
      'den MockClient, beide Aufrufer erhalten das gleiche Ergebnis',
      () async {
        var hits = 0;
        final client = MockClient((request) async {
          hits++;
          return http.Response('{"ok":true,"hit":$hits}', 200);
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          requestCoordinator: RequestCoordinator(),
        );

        final f1 = runtime.execute(buildRequest());
        final f2 = runtime.execute(buildRequest());
        final results = await Future.wait([f1, f2]);

        expect(hits, equals(1));
        expect(results[0], equals({'ok': true, 'hit': 1}));
        expect(results[0], equals(results[1]));
      },
    );

    test(
      'different priority scopes produce distinct dedup executions',
      () async {
        var hits = 0;
        final client = MockClient((request) async {
          hits++;
          await Future<void>.delayed(const Duration(milliseconds: 10));
          return http.Response('{"ok":true}', 200);
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          requestCoordinator: RequestCoordinator(),
        );
        addTearDown(runtime.dispose);
        final request = buildRequest();

        await Future.wait([
          RuntimeExecutionContext.runWithPriority(
            () => runtime.execute(request),
            RequestPriority.low,
          ),
          RuntimeExecutionContext.runWithPriority(
            () => runtime.execute(request),
            RequestPriority.high,
          ),
        ]);

        expect(hits, equals(2));
      },
    );

    test(
      'ohne explizite Freigabe werden identische POSTs nicht dedupliziert',
      () async {
        var hits = 0;
        final client = MockClient((request) async {
          hits++;
          await Future<void>.delayed(const Duration(milliseconds: 10));
          return http.Response('{"ok":true}', 200);
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          requestCoordinator: RequestCoordinator(),
        );

        final request = ApiRequest<Map<String, dynamic>>(
          method: ApiHttpMethod.post,
          version: ApiVersion.v1,
          path: '/ping',
          body: '{"action":"run"}',
          authentication: AuthenticationPolicy.none,
          responsePolicy: const _JsonMapResponsePolicy(),
          operationId: 'test.no-dedup-by-default',
        );
        await Future.wait([runtime.execute(request), runtime.execute(request)]);

        expect(hits, equals(2));
      },
    );

    test('unterschiedliche Zusatzheader teilen keine Ausführung', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        await Future<void>.delayed(const Duration(milliseconds: 10));
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      await Future.wait([
        runtime.execute(buildRequest(additionalHeaders: {'x-scope': 'a'})),
        runtime.execute(buildRequest(additionalHeaders: {'x-scope': 'b'})),
      ]);

      expect(hits, equals(2));
    });

    test('explizit unterschiedliche sessionid-Zusatzheader teilen keine '
        'Ausführung', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        await Future<void>.delayed(const Duration(milliseconds: 10));
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      await Future.wait([
        runtime.execute(
          buildRequest(additionalHeaders: {'sessionid': 'explicit-a'}),
        ),
        runtime.execute(
          buildRequest(additionalHeaders: {'sessionid': 'explicit-b'}),
        ),
      ]);

      expect(hits, equals(2));
    });

    test('identische Header in anderer Einfügereihenfolge werden weiterhin '
        'dedupliziert', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        await Future<void>.delayed(const Duration(milliseconds: 10));
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      await Future.wait([
        runtime.execute(
          buildRequest(additionalHeaders: {'x-a': '1', 'x-b': '2'}),
        ),
        runtime.execute(
          buildRequest(additionalHeaders: {'x-b': '2', 'x-a': '1'}),
        ),
      ]);

      expect(hits, equals(1));
    });

    test(
      'unterschiedliche Ergebnis- und ResponsePolicy-Typen teilen kein Future',
      () async {
        var hits = 0;
        final client = MockClient((request) async {
          hits++;
          await Future<void>.delayed(const Duration(milliseconds: 10));
          return http.Response('{"ok":true}', 200);
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          requestCoordinator: RequestCoordinator(),
        );
        final mapRequest = buildRequest();
        final stringRequest = ApiRequest<String>(
          method: ApiHttpMethod.get,
          version: ApiVersion.v1,
          path: '/ping',
          authentication: AuthenticationPolicy.none,
          deduplication: DeduplicationPolicy.enabled,
          responsePolicy: const _StringResponsePolicy(),
          operationId: 'test.dedup',
        );

        final results = await Future.wait<Object>([
          runtime.execute(mapRequest),
          runtime.execute(stringRequest),
        ]);

        expect(hits, equals(2));
        expect(results[0], equals({'ok': true}));
        expect(results[1], equals('{"ok":true}'));
      },
    );

    test('unterschiedliche ResponsePolicy-Instanzen desselben Ergebnistyps '
        'teilen kein Future', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        await Future<void>.delayed(const Duration(milliseconds: 10));
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      final results = await Future.wait([
        runtime.execute(
          buildRequest(responsePolicy: const _TaggedMapResponsePolicy('a')),
        ),
        runtime.execute(
          buildRequest(responsePolicy: const _TaggedMapResponsePolicy('b')),
        ),
      ]);

      expect(hits, equals(2));
      expect(results[0]['tag'], equals('a'));
      expect(results[1]['tag'], equals('b'));
    });

    test('unterschiedliche operationId teilt wegen getrennter Telemetrie keine '
        'Ausführung', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        await Future<void>.delayed(const Duration(milliseconds: 10));
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      await Future.wait([
        runtime.execute(buildRequest(operationId: 'test.operation.a')),
        runtime.execute(buildRequest(operationId: 'test.operation.b')),
      ]);

      expect(hits, equals(2));
    });

    test(
      'deduplizierter 302-Fehler löst den Fehler-Callback nur einmal aus',
      () async {
        var hits = 0;
        var callbackCount = 0;
        final callbacks = RestApiDOCUframeCallbacks(
          onUserAndPassWrong: (_) async => callbackCount++,
        );
        final client = MockClient((request) async {
          hits++;
          await Future<void>.delayed(const Duration(milliseconds: 10));
          return http.Response(
            jsonEncode(
              v1Envelope(internalStatus: '302', statusMessage: 'wrong'),
            ),
            200,
          );
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          callbacks: callbacks,
          httpClient: client,
          requestCoordinator: RequestCoordinator(),
        );
        const request = ApiRequest<RestApiResponse>(
          method: ApiHttpMethod.get,
          version: ApiVersion.v1,
          path: '/protected',
          authentication: AuthenticationPolicy.none,
          deduplication: DeduplicationPolicy.enabled,
          responsePolicy: RestApiResponsePolicy(),
          operationId: 'test.dedup.callback',
        );

        await expectLater(
          Future.wait([runtime.execute(request), runtime.execute(request)]),
          throwsA(isA<UserAndPassWrongException>()),
        );

        expect(hits, equals(1));
        expect(callbackCount, equals(1));
      },
    );

    test('zwei nebenläufige Requests mit unterschiedlichem Body: ZWEI '
        'HTTP-Requests', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      final f1 = runtime.execute(
        buildRequest(method: ApiHttpMethod.post, body: 'a'),
      );
      final f2 = runtime.execute(
        buildRequest(method: ApiHttpMethod.post, body: 'b'),
      );
      await Future.wait([f1, f2]);

      expect(hits, equals(2));
    });

    test('zwei nebenläufige Requests mit unterschiedlicher Query: ZWEI '
        'HTTP-Requests', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      final f1 = runtime.execute(buildRequest(queryParameters: {'x': '1'}));
      final f2 = runtime.execute(buildRequest(queryParameters: {'x': '2'}));
      await Future.wait([f1, f2]);

      expect(hits, equals(2));
    });

    test('Fehlerfall: nebenläufige identische Requests teilen den Fehler; der '
        'Schlüssel wird danach freigegeben (ein späterer Aufruf führt erneut '
        'aus und löst einen zweiten HTTP-Request aus)', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        if (hits == 1) {
          throw http.ClientException('boom');
        }
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      final f1 = runtime.execute(buildRequest());
      final f2 = runtime.execute(buildRequest());

      await expectLater(f1, throwsA(isA<http.ClientException>()));
      await expectLater(f2, throwsA(isA<http.ClientException>()));
      expect(hits, equals(1));

      final result = await runtime.execute(buildRequest());
      expect(result, equals({'ok': true}));
      expect(hits, equals(2));
    });

    test('sequentielle (nicht überlappende) identische Requests: JEDER Aufruf '
        'führt aus, da der Schlüssel nach Abschluss entfernt wird', () async {
      var hits = 0;
      final client = MockClient((request) async {
        hits++;
        return http.Response('{"ok":true}', 200);
      });
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        requestCoordinator: RequestCoordinator(),
      );

      await runtime.execute(buildRequest());
      await runtime.execute(buildRequest());

      expect(hits, equals(2));
    });

    test(
      'ohne RequestCoordinator (null): unverändertes Verhalten, kein Dedup',
      () async {
        var hits = 0;
        final client = MockClient((request) async {
          hits++;
          return http.Response('{"ok":true}', 200);
        });
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
        );

        final f1 = runtime.execute(buildRequest());
        final f2 = runtime.execute(buildRequest());
        await Future.wait([f1, f2]);

        expect(hits, equals(2));
      },
    );
  });

  group('RequestCoordinator + SessionCoordinator (Zusammenspiel)', () {
    test('zwei nebenläufige identische Session-GETs, deren erste Antwort ein '
        '201-Envelope ist: die geteilte Ausführung macht GENAU EINEN Refresh '
        '(Key+Login) und EINEN Retry; beide Aufrufer erhalten den '
        'erfolgreichen Retry', () async {
      final pair = await generateServerKeyPair();
      final serverPublicKey = pair.publicKey;
      final server = MockApiServer();
      final config = buildSessionRuntimeConfiguration();
      final sessionCoordinator = SessionCoordinator(
        configuration: config,
        retryDelay: const Duration(milliseconds: 5),
      );
      final requestCoordinator = RequestCoordinator();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: server.client,
        sessionCoordinator: sessionCoordinator,
        requestCoordinator: requestCoordinator,
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

      // Initialer Login, außerhalb des zu prüfenden Dedup-Vorgangs.
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      await sessionCoordinator.login('md5hash');
      final baseline = server.requests.length;

      // Erster Probe-Versuch scheitert an einer ungültigen Session (201),
      // danach greift der Refresh-und-Retry des ApiRuntime.
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
      );
      scriptLoginKey();
      scriptLoginSuccess('sess-refreshed');
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(data: {'ok': true}),
      );

      ApiRequest<RestApiResponse> buildProbeRequest() =>
          ApiRequest<RestApiResponse>(
            method: ApiHttpMethod.get,
            version: ApiVersion.v1,
            path: '/probe',
            authentication: AuthenticationPolicy.session,
            deduplication: DeduplicationPolicy.enabled,
            responsePolicy: const RestApiResponsePolicy(),
            operationId: 'test.probe.dedup',
          );

      final f1 = runtime.execute(buildProbeRequest());
      final f2 = runtime.execute(buildProbeRequest());
      final results = await Future.wait([f1, f2]);

      expect(results[0].isOk, isTrue);
      expect(results[1].isOk, isTrue);
      expect(
        sessionCoordinator.sessionState.sessionId,
        equals('sess-refreshed'),
      );

      final postRequests = server.requests.sublist(baseline);
      final loginKeyCount = postRequests
          .where((r) => r.path == '/dfapp/v2/login/key')
          .length;
      final loginPostCount = postRequests
          .where((r) => r.path == '/dfapp/v2/login')
          .length;
      // GENAU EIN Refresh (Key+Login) für BEIDE geteilten Aufrufer
      // zusammen - nicht zwei.
      expect(loginKeyCount, equals(1));
      expect(loginPostCount, equals(1));

      final probeRequests = postRequests
          .where((r) => r.path == '/dfapp/v1/probe')
          .toList();
      // Original (201) + EIN Retry (Erfolg) - für BEIDE geteilten
      // Aufrufer zusammen, nicht vier.
      expect(probeRequests, hasLength(2));
      expect(probeRequests[0].header('sessionid'), equals('sess-initial'));
      expect(probeRequests[1].header('sessionid'), equals('sess-refreshed'));
    });
  });
}
