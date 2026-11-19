// Unit-Tests für SessionCoordinator (Login-Krypto, Logout, Single-Flight-
// Refresh) sowie für den Session-Retry im ApiRuntime (genau ein Refresh +
// ein Retry bei 201/204/2FA, kein Retry-Loop).
//
// Der Login-/Refresh-Roundtrip wird mit ECHTER RSA/AES-Verschlüsselung
// (lib/src/crypto) gegen einen selbst erzeugten "Server"-Schlüssel
// verifiziert - der Request-Body wird server-seitig entschlüsselt und mit
// dem erwarteten Klartext verglichen (kein Mock-testet-Mock).

import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/crypto/client_key_pair.dart';
import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/crypto/pem.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/runtime_events.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/session/session_state.dart'
    show SessionState;
import 'package:pointycastle/export.dart' show RSAPrivateKey, RSAPublicKey;
import 'package:test/test.dart';

import '../session_test_support.dart';

/// Bündelt einen [SessionCoordinator] mit dem darauf angebundenen
/// [ApiRuntime] (beide teilen dieselbe [RuntimeConfiguration] und denselben
/// [SessionState]).
class _Harness {
  const _Harness(this.coordinator, this.runtime);
  final SessionCoordinator coordinator;
  final ApiRuntime runtime;
}

void main() {
  late MockApiServer server;
  late RSAPublicKey serverPublicKey;
  late RSAPrivateKey serverPrivateKey;

  setUpAll(() async {
    final pair = await generateServerKeyPair();
    serverPublicKey = pair.publicKey;
    serverPrivateKey = pair.privateKey;
  });

  setUp(() {
    server = MockApiServer();
  });

  _Harness buildHarness({
    RuntimeConfiguration? configuration,
    RuntimeEvents? events,
    Duration retryDelay = const Duration(milliseconds: 5),
  }) {
    final config = configuration ?? buildSessionRuntimeConfiguration();
    final coordinator = SessionCoordinator(
      configuration: config,
      events: events,
      retryDelay: retryDelay,
    );
    final runtime = ApiRuntime(
      configuration: config,
      events: events,
      httpClient: server.client,
      sessionCoordinator: coordinator,
    );
    return _Harness(coordinator, runtime);
  }

  void scriptLoginKey({int times = 1}) {
    for (var i = 0; i < times; i++) {
      server.enqueueJson(
        'GET',
        '/dfapp/v2/login/key',
        body: v1Envelope(
          data: {'key': encodePublicKeyToCleanPem(serverPublicKey)},
        ),
      );
    }
  }

  void scriptLoginSuccess(String sessionId) {
    server.enqueue('POST', '/dfapp/v2/login', (req) async {
      return ScriptedResponse(
        jsonEncode(v1Envelope(data: {'sessionId': sessionId})),
      );
    });
  }

  ApiRequest<Object?> buildProbeRequest({
    AuthenticationPolicy authentication = AuthenticationPolicy.session,
    String path = '/probe',
  }) {
    return ApiRequest<Object?>(
      method: GsdHttpMethod.get,
      version: GsdApiVersion.v1,
      path: path,
      authentication: authentication,
      responsePolicy: const DataResponsePolicy<Object?>(),
      operationId: 'test.probe',
    );
  }

  group('SessionCoordinator.login', () {
    test('holt zuerst den Public Key (v2/login/key), verschlüsselt den Body '
        'echt per RSA/AES ({aesKey,data,publicKey}) und speichert die vom '
        'Server gelieferte Session-ID; sessionIdChanges meldet genau einmal '
        'ausgelöst', () async {
      scriptLoginKey();
      String? decryptedBody;
      server.enqueue('POST', '/dfapp/v2/login', (req) async {
        decryptedBody = await decryptV2LoginBody(
          req.body,
          serverPrivateKey,
        );
        return ScriptedResponse(
          jsonEncode(v1Envelope(data: {'sessionId': 'sess-1'})),
        );
      });

      final device = GsdDocuframeDevice(
        'dev-1',
        device: 'Test Device',
        systemVersion: '1.0',
        fireBaseToken: 'fb-token',
        deviceType: GsdDocuframeDeviceType.android,
        systemString: 'sys-info',
      );
      final sessionEvents = <String>[];
      final events = RuntimeEvents()
        ..sessionIdChanges.listen(sessionEvents.add);
      final harness = buildHarness(
        configuration: buildSessionRuntimeConfiguration(
          userName: 'demo',
          appNames: ['App1'],
          additionalAppNames: ['App2'],
          device: device,
        ),
        events: events,
      );

      final response = await harness.coordinator.login('md5hash');

      expect(response.sessionId, equals('sess-1'));
      expect(harness.coordinator.sessionState.sessionId, equals('sess-1'));
      expect(sessionEvents, equals(['sess-1']));

      // Request-Reihenfolge: erst der Key-Fetch, dann der Login-POST.
      expect(server.requests, hasLength(2));
      expect(server.requests[0].method, equals('GET'));
      expect(server.requests[0].path, equals('/dfapp/v2/login/key'));
      expect(server.requests[1].method, equals('POST'));
      expect(server.requests[1].path, equals('/dfapp/v2/login'));
      // Login läuft ohne Session-Header (AuthenticationPolicy.none).
      expect(server.requests[0].header('sessionid'), isNull);
      expect(server.requests[1].header('sessionid'), isNull);

      // Der Request-Body ist NICHT der Klartext, sondern ein JSON mit
      // genau den 3 Feldern aesKey/data/publicKey.
      final rawBody =
          jsonDecode(server.requests[1].body) as Map<String, dynamic>;
      expect(rawBody.keys.toSet(), equals({'aesKey', 'data', 'publicKey'}));
      expect(rawBody['data'], isNot(contains('demo')));

      // Server-seitig entschlüsselt entspricht der Body exakt den
      // erwarteten Klartext-Login-Daten (Legacy-Vertrag).
      final decodedClear = jsonDecode(decryptedBody!) as Map<String, dynamic>;
      expect(decodedClear['user'], equals('demo'));
      expect(decodedClear['pass'], equals('md5hash'));
      expect(decodedClear.containsKey('2faToken'), isFalse);
      expect(decodedClear['appNames'], equals(['App1', 'App2']));
      expect(decodedClear['device'], equals(device.toJson()));
      expect(decodedClear['furtherencryption'], isFalse);
    });

    test(
      'entschlüsselt eine verschlüsselte Login-Antwort '
      'vor dem Response-Parsing',
      () async {
        scriptLoginKey();
        server.enqueue('POST', '/dfapp/v2/login', (request) async {
          final requestBody = jsonDecode(request.body) as Map<String, dynamic>;
          final clientPublicKey = Pem.parsePublicKey(
            (requestBody['publicKey'] as String)
                .split('\n')
                .map((line) => line.trim())
                .join('\n'),
          );
          final encryptedResponse = await encryptV2Response(
            jsonEncode(
              v1Envelope(data: {'sessionId': 'sess-encrypted'}),
            ),
            clientPublicKey,
          );
          return ScriptedResponse(encryptedResponse);
        });
        final harness = buildHarness();

        final response = await harness.coordinator.login('md5hash');

        expect(response.sessionId, 'sess-encrypted');
        expect(harness.coordinator.sessionState.sessionId, 'sess-encrypted');
      },
    );

    test('zwei Logins hintereinander nutzen verschiedene AES-Schlüssel, aber '
        'dasselbe Schlüsselpaar', () async {
      final harness = buildHarness();
      scriptLoginKey(times: 2);
      scriptLoginSuccess('sess-a');
      scriptLoginSuccess('sess-b');

      await harness.coordinator.login('md5hash');
      await harness.coordinator.login('md5hash');

      final bodies = [
        for (final request in server.requests.where(
          (request) => request.method == 'POST',
        ))
          jsonDecode(request.body) as Map<String, dynamic>,
      ];
      expect(bodies, hasLength(2));
      final aesKeys = [
        for (final body in bodies)
          HandshakeCrypto.rsaDecrypt(
            base64Decode(body['aesKey'] as String),
            serverPrivateKey,
          ),
      ];
      expect(aesKeys[0], isNot(equals(aesKeys[1])));
      expect(bodies[0]['publicKey'], bodies[1]['publicKey']);
    });

    test('zwei Clients im selben Isolate teilen das Schlüsselpaar', () async {
      final first = buildHarness();
      final second = buildHarness();
      scriptLoginKey(times: 2);
      scriptLoginSuccess('sess-a');
      scriptLoginSuccess('sess-b');

      await first.coordinator.login('md5hash');
      await second.coordinator.login('md5hash');

      final publicKeys = [
        for (final request in server.requests.where(
          (request) => request.method == 'POST',
        ))
          (jsonDecode(request.body) as Map<String, dynamic>)['publicKey'],
      ];
      expect(publicKeys, hasLength(2));
      expect(publicKeys[0], publicKeys[1]);
      expect(publicKeys[0], (await ClientKeyPair.obtain()).publicKeyPem);
    });

    test(
      'login-Fehler via 302-Envelope (v2/login): GsdInvalidCredentialsException '
      'propagiert; Session wird geleert; sessionIdChanges meldet ""',
      () async {
        scriptLoginKey();
        server.enqueueJson(
          'POST',
          '/dfapp/v2/login',
          body: v1Envelope(
            internalStatus: '302',
            statusMessage: 'wrong',
          ),
        );

        final sessionEvents = <String>[];
        final events = RuntimeEvents()
          ..sessionIdChanges.listen(sessionEvents.add);
        final harness = buildHarness(
          configuration: buildSessionRuntimeConfiguration(
            initialSessionId: 'pre-existing',
          ),
          events: events,
        );

        await expectLater(
          () => harness.coordinator.login('md5hash'),
          throwsA(isA<GsdInvalidCredentialsException>()),
        );

        expect(harness.coordinator.sessionState.sessionId, equals(''));
        expect(sessionEvents, equals(['']));
      },
    );

    test(
      'fehlgeschlagener neuer Login verwirft vorherige Refresh-Credentials',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('old-session');
        final harness = buildHarness();
        await harness.coordinator.login('old-md5');

        scriptLoginKey();
        server.enqueueJson(
          'POST',
          '/dfapp/v2/login',
          body: v1Envelope(
            internalStatus: '302',
            statusMessage: 'wrong',
          ),
        );
        await expectLater(
          () => harness.coordinator.login('wrong-md5'),
          throwsA(isA<GsdInvalidCredentialsException>()),
        );

        final baseline = server.requests.length;
        server.enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: v1Envelope(
            internalStatus: '204',
            statusMessage: 'missing',
          ),
        );
        await expectLater(
          () => harness.runtime.execute(buildProbeRequest()),
          throwsA(isA<GsdSessionMissingException>()),
        );

        expect(server.requests.sublist(baseline), hasLength(1));
        expect(server.requests.last.path, equals('/dfapp/v1/probe'));
      },
    );
  });

  group('SessionCoordinator.refreshSession (single-flight)', () {
    test(
      'initialSessionId ohne Login-Credentials startet keinen Netzwerk-Refresh',
      () async {
        final harness = buildHarness(
          configuration: buildSessionRuntimeConfiguration(
            initialSessionId: 'restored-session',
          ),
        );

        final refreshed = await harness.coordinator.refreshSession();

        expect(refreshed, isFalse);
        expect(server.requests, isEmpty);
      },
    );

    test(
      'setPassword erlaubt wie im Legacy-Manager einen initialen Login',
      () async {
        final harness = buildHarness();
        harness.coordinator.setPassword('restored-md5');
        scriptLoginKey();
        scriptLoginSuccess('initial-login-session');

        final refreshed = await harness.coordinator.refreshSession();

        expect(refreshed, isTrue);
        expect(
          harness.coordinator.sessionState.sessionId,
          'initial-login-session',
        );
        expect(server.requests.map((request) => request.path), <String>[
          '/dfapp/v2/login/key',
          '/dfapp/v2/login',
        ]);
      },
    );

    test('N parallele refreshSession()-Aufrufe lösen nur EINE '
        'Key-Fetch-plus-Login-Sequenz aus und liefern alle dieselbe neue '
        'Session-ID', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      scriptLoginKey();
      server.enqueue('POST', '/dfapp/v2/login', (req) async {
        return ScriptedResponse(
          jsonEncode(
            v1Envelope(data: {'sessionId': 'sess-refreshed'}),
          ),
          delay: const Duration(milliseconds: 20),
        );
      });

      final futures = List.generate(
        5,
        (_) => harness.coordinator.refreshSession(),
      );
      final results = await Future.wait(futures);

      expect(results, everyElement(isTrue));
      expect(
        harness.coordinator.sessionState.sessionId,
        equals('sess-refreshed'),
      );

      final loginKeyCount = server.requests
          .where((r) => r.path == '/dfapp/v2/login/key')
          .length;
      final loginPostCount = server.requests
          .where((r) => r.path == '/dfapp/v2/login')
          .length;
      // 1x initialer Login + 1x geteilter Refresh = 2, NICHT 1+5.
      expect(loginKeyCount, equals(2));
      expect(loginPostCount, equals(2));
    });

    test(
      'temporärer technischer Fehler wird genau einmal wiederholt',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        final harness = buildHarness();
        await harness.coordinator.login('md5hash');

        server.enqueue('GET', '/dfapp/v2/login/key', (_) async {
          throw Exception('temporary transport failure');
        });
        scriptLoginKey();
        scriptLoginSuccess('sess-after-retry');

        final refreshed = await harness.coordinator.refreshSession();

        expect(refreshed, isTrue);
        expect(
          harness.coordinator.sessionState.sessionId,
          equals('sess-after-retry'),
        );
        // 1x initialer Login + 2x Refresh-Versuch (Fehlschlag, Erfolg).
        expect(
          server.requests.where((r) => r.path == '/dfapp/v2/login/key'),
          hasLength(3),
        );
      },
    );

    test('unbekannter/transienter Webservice-Fehler (bare GsdServerException, '
        'z.B. interner Status 999) im Refresh-Login wird genau einmal '
        'wiederholt und führt beim zweiten Versuch zum Erfolg', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      scriptLoginKey();
      server.enqueueJson(
        'POST',
        '/dfapp/v2/login',
        body: v1Envelope(
          internalStatus: '999',
          statusMessage: 'server error',
        ),
      );
      scriptLoginKey();
      scriptLoginSuccess('sess-after-retry');

      final refreshed = await harness.coordinator.refreshSession();

      expect(refreshed, isTrue);
      expect(
        harness.coordinator.sessionState.sessionId,
        equals('sess-after-retry'),
      );

      final loginKeyCount = server.requests
          .where((r) => r.path == '/dfapp/v2/login/key')
          .length;
      final loginPostCount = server.requests
          .where((r) => r.path == '/dfapp/v2/login')
          .length;
      // 1x initialer Login + 2x Refresh-Versuche (1 Fehlschlag + 1 Erfolg).
      expect(loginKeyCount, equals(3));
      expect(loginPostCount, equals(3));
    });

    test(
      'GsdInvalidCredentialsException (302) im Refresh-Login löst KEINEN '
      'zweiten Versuch aus und propagiert unverfälscht',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        final harness = buildHarness();
        await harness.coordinator.login('md5hash');

        scriptLoginKey();
        server.enqueueJson(
          'POST',
          '/dfapp/v2/login',
          body: v1Envelope(
            internalStatus: '302',
            statusMessage: 'wrong',
          ),
        );

        await expectLater(
          harness.coordinator.refreshSession,
          throwsA(isA<GsdInvalidCredentialsException>()),
        );

        final loginKeyCount = server.requests
            .where((r) => r.path == '/dfapp/v2/login/key')
            .length;
        final loginPostCount = server.requests
            .where((r) => r.path == '/dfapp/v2/login')
            .length;
        // 1x initialer Login + genau 1x Refresh-Versuch (kein zweiter
        // Versuch, da GsdInvalidCredentialsException terminal ist).
        expect(loginKeyCount, equals(2));
        expect(loginPostCount, equals(2));
      },
    );
  });

  group('SessionCoordinator.refreshSession (2FA)', () {
    late int providerCalls;
    late List<Map<String, dynamic>> refreshBodies;

    setUp(() {
      providerCalls = 0;
      refreshBodies = [];
    });

    /// Meldet sich initial an; [token] ist die Antwort des 2FA-Providers.
    Future<_Harness> loggedInHarness({required String token}) async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness(
        events: RuntimeEvents(
          twoFactorTokenProvider: () async {
            providerCalls++;
            return token;
          },
        ),
      );
      await harness.coordinator.login('md5hash');
      return harness;
    }

    /// Plant einen Refresh-Versuch (Key + Login) ein und legt den
    /// entschlüsselten Login-Body in [refreshBodies] ab. Ohne [sessionId]
    /// antwortet der Login mit 341.
    void scriptRefreshAttempt({String? sessionId}) {
      scriptLoginKey();
      server.enqueue('POST', '/dfapp/v2/login', (req) async {
        refreshBodies.add(
          jsonDecode(await decryptV2LoginBody(req.body, serverPrivateKey))
              as Map<String, dynamic>,
        );
        return ScriptedResponse(
          jsonEncode(
            sessionId == null
                ? v1Envelope(internalStatus: '341', statusMessage: '2fa')
                : v1Envelope(data: {'sessionId': sessionId}),
          ),
        );
      });
    }

    test('341 im Refresh-Login: holt das Token genau einmal beim Provider '
        'und meldet sich damit an', () async {
      final harness = await loggedInHarness(token: '123456');
      scriptRefreshAttempt();
      scriptRefreshAttempt(sessionId: 'sess-2fa');

      final refreshed = await harness.coordinator.refreshSession();

      expect(refreshed, isTrue);
      expect(providerCalls, 1);
      expect(harness.coordinator.sessionState.sessionId, 'sess-2fa');
      expect(refreshBodies.map((body) => body['2faToken']), ['', '123456']);
    });

    test('ein übergebenes twoFaToken wird ohne Provider verwendet', () async {
      final harness = await loggedInHarness(token: 'vom-provider');
      scriptRefreshAttempt(sessionId: 'sess-2fa');

      final refreshed = await harness.coordinator.refreshSession(
        twoFaToken: '777777',
      );

      expect(refreshed, isTrue);
      expect(providerCalls, 0);
      expect(harness.coordinator.sessionState.sessionId, 'sess-2fa');
      expect(refreshBodies.single['2faToken'], '777777');
    });

    test('341 auch mit dem Token vom Provider: wirft statt erneut zu '
        'fragen', () async {
      final harness = await loggedInHarness(token: '123456');
      scriptRefreshAttempt();
      scriptRefreshAttempt();

      await expectLater(
        harness.coordinator.refreshSession(),
        throwsA(isA<GsdTwoFactorTokenMissingException>()),
      );

      expect(providerCalls, 1);
      expect(refreshBodies.map((body) => body['2faToken']), ['', '123456']);
      expect(harness.coordinator.sessionState.sessionId, isEmpty);
    });

    test('341 trotz übergebenem Token: wirft nach einem Versuch', () async {
      final harness = await loggedInHarness(token: 'vom-provider');
      scriptRefreshAttempt();

      await expectLater(
        harness.coordinator.refreshSession(twoFaToken: '777777'),
        throwsA(isA<GsdTwoFactorTokenMissingException>()),
      );

      expect(providerCalls, 0);
      expect(refreshBodies.single['2faToken'], '777777');
      // Kein zweiter Versuch mit demselben Token.
      expect(
        server.requests.where((r) => r.path == '/dfapp/v2/login/key'),
        hasLength(2),
      );
    });

    test('341 im Refresh-Login und der Provider liefert "": refreshSession '
        'liefert false ohne weiteren Login', () async {
      final harness = await loggedInHarness(token: '');
      scriptRefreshAttempt();

      final refreshed = await harness.coordinator.refreshSession();

      expect(refreshed, isFalse);
      expect(providerCalls, 1);
      expect(refreshBodies.single['2faToken'], '');
      expect(harness.coordinator.sessionState.sessionId, isEmpty);
      expect(
        server.requests.where((r) => r.path == '/dfapp/v2/login'),
        hasLength(2),
      );
    });
  });

  group('SessionCoordinator.logout', () {
    test('sendet POST v1/logout mit sessionid-Header; Session wird IMMER '
        'geleert und sessionIdChanges meldet "" - auch wenn der Server '
        'ein Fehler-Envelope liefert', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-1');
      final sessionEvents = <String>[];
      final events = RuntimeEvents()
        ..sessionIdChanges.listen(sessionEvents.add);
      final harness = buildHarness(events: events);
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'POST',
        '/dfapp/v1/logout',
        body: v1Envelope(
          internalStatus: '999',
          statusMessage: 'server error',
        ),
      );

      await expectLater(
        harness.coordinator.logout,
        throwsA(isA<GsdServerException>()),
      );

      final logoutRequest = server.requests.last;
      expect(logoutRequest.method, equals('POST'));
      expect(logoutRequest.path, equals('/dfapp/v1/logout'));
      expect(logoutRequest.header('sessionid'), equals('sess-1'));
      expect(harness.coordinator.sessionState.sessionId, equals(''));
      expect(sessionEvents.last, equals(''));
    });

    test('geschützter Request nach Logout führt keinen automatischen Re-Login '
        'aus', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-1');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'POST',
        '/dfapp/v1/logout',
        body: v1Envelope(),
      );
      await harness.coordinator.logout();

      final baseline = server.requests.length;
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '204',
          statusMessage: 'missing',
        ),
      );

      await expectLater(
        () => harness.runtime.execute(buildProbeRequest()),
        throwsA(isA<GsdSessionMissingException>()),
      );

      final requestsAfterLogout = server.requests.sublist(baseline);
      expect(requestsAfterLogout, hasLength(1));
      expect(requestsAfterLogout.single.path, equals('/dfapp/v1/probe'));
      expect(requestsAfterLogout.single.header('sessionid'), isNull);
    });

    test('Logout invalidiert einen bereits laufenden Refresh (Abbruch VOR dem '
        'Login-POST, verzögerter Key-Fetch)', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-1');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      server.enqueue('GET', '/dfapp/v2/login/key', (_) async {
        return ScriptedResponse(
          jsonEncode(
            v1Envelope(
              data: {
                'key': encodePublicKeyToCleanPem(serverPublicKey),
              },
            ),
          ),
          delay: const Duration(milliseconds: 30),
        );
      });
      scriptLoginSuccess('must-not-be-restored');
      server.enqueueJson(
        'POST',
        '/dfapp/v1/logout',
        body: v1Envelope(),
      );

      final refreshFuture = harness.coordinator.refreshSession();
      await Future<void>.delayed(const Duration(milliseconds: 5));
      await harness.coordinator.logout();
      final refreshed = await refreshFuture;

      expect(refreshed, isFalse);
      expect(harness.coordinator.sessionState.sessionId, isEmpty);
      expect(
        server.requests
            .where((request) => request.path == '/dfapp/v2/login')
            .length,
        equals(1),
      );
    });

    test(
      'Logout invalidiert einen bereits laufenden Refresh, dessen Login-POST '
      'bereits unterwegs ist: ein NOCH ERFOLGREICH ANTWORTENDER Login darf '
      'die per Logout beendete Session NICHT wiederherstellen',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-1');
        final sessionEvents = <String>[];
        final events = RuntimeEvents()
          ..sessionIdChanges.listen(sessionEvents.add);
        final harness = buildHarness(events: events);
        await harness.coordinator.login('md5hash');
        sessionEvents.clear();

        // Key-Fetch antwortet sofort, der Login-POST bleibt noch offen -
        // Logout muss also einlaufen, WÄHREND der Login-POST bereits beim
        // Server ist (nicht vorher, wie im obigen Test).
        scriptLoginKey();
        server
          ..enqueue('POST', '/dfapp/v2/login', (_) async {
            return ScriptedResponse(
              jsonEncode(
                v1Envelope(
                  data: {'sessionId': 'must-not-be-restored'},
                ),
              ),
              delay: const Duration(milliseconds: 30),
            );
          })
          ..enqueueJson(
            'POST',
            '/dfapp/v1/logout',
            body: v1Envelope(),
          );

        final refreshFuture = harness.coordinator.refreshSession();
        await Future<void>.delayed(const Duration(milliseconds: 5));
        await harness.coordinator.logout();
        final refreshed = await refreshFuture;

        expect(refreshed, isFalse);
        expect(harness.coordinator.sessionState.sessionId, isEmpty);
        expect(sessionEvents, equals(['']));

        // Beweis, dass der erfolgreiche Login-POST tatsächlich dequeued und
        // beantwortet wurde (nicht bloß nie gesendet) - der gefährliche Pfad
        // wird also wirklich durchlaufen und trotzdem verworfen.
        expect(
          server.requests
              .where((request) => request.path == '/dfapp/v2/login')
              .length,
          equals(2),
        );
        expect(server.pendingCount('POST', '/dfapp/v2/login'), equals(0));
      },
    );

    test('erfolgreicher Login nach Logout aktiviert Refresh wieder', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-before-logout');
      final harness = buildHarness();
      await harness.coordinator.login('old-md5');

      server.enqueueJson(
        'POST',
        '/dfapp/v1/logout',
        body: v1Envelope(),
      );
      await harness.coordinator.logout();
      expect(harness.coordinator.canRefreshSession, isFalse);

      scriptLoginKey();
      scriptLoginSuccess('sess-after-login');
      await harness.coordinator.login('new-md5');

      expect(harness.coordinator.canRefreshSession, isTrue);
      expect(
        harness.coordinator.sessionState.sessionId,
        equals('sess-after-login'),
      );
    });
  });

  group('ApiRuntime Fehler-Ereignisse', () {
    test('302 meldet invalidCredentials genau einmal', () async {
      var eventCount = 0;
      final events = RuntimeEvents()
        ..invalidCredentials.listen((_) => eventCount++);
      final harness = buildHarness(events: events);
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '302',
          statusMessage: 'wrong',
        ),
      );

      await expectLater(
        () => harness.runtime.execute(
          buildProbeRequest(authentication: AuthenticationPolicy.none),
        ),
        throwsA(isA<GsdInvalidCredentialsException>()),
      );

      expect(eventCount, equals(1));
    });

    test('306 meldet licenseErrors genau einmal', () async {
      var eventCount = 0;
      final events = RuntimeEvents()..licenseErrors.listen((_) => eventCount++);
      final harness = buildHarness(events: events);
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '306',
          statusMessage: 'license',
        ),
      );

      await expectLater(
        () => harness.runtime.execute(
          buildProbeRequest(authentication: AuthenticationPolicy.none),
        ),
        throwsA(isA<GsdLicenseException>()),
      );

      expect(eventCount, equals(1));
    });

    test(
      'werfender Listener ersetzt die ursprüngliche API-Exception nicht',
      () async {
        final listenerErrors = <Object>[];
        final events = RuntimeEvents();
        // Der Fehler eines Listeners geht an die Zone, in der er zuhört.
        runZonedGuarded(
          () => events.invalidCredentials.listen(
            (_) => throw StateError('listener failed'),
          ),
          (error, _) => listenerErrors.add(error),
        );
        final harness = buildHarness(events: events);
        server.enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: v1Envelope(
            internalStatus: '302',
            statusMessage: 'wrong',
          ),
        );

        await expectLater(
          () => harness.runtime.execute(
            buildProbeRequest(authentication: AuthenticationPolicy.none),
          ),
          throwsA(isA<GsdInvalidCredentialsException>()),
        );
        expect(listenerErrors, [isA<StateError>()]);
      },
    );

    test(
      '302 im Refresh-Login wird nur einmal gemeldet und nicht wiederholt',
      () async {
        var eventCount = 0;
        final events = RuntimeEvents()
          ..invalidCredentials.listen((_) => eventCount++);
        final harness = buildHarness(events: events);
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        await harness.coordinator.login('md5hash');

        server.enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: v1Envelope(
            internalStatus: '201',
            statusMessage: 'invalid',
          ),
        );
        scriptLoginKey();
        server.enqueueJson(
          'POST',
          '/dfapp/v2/login',
          body: v1Envelope(
            internalStatus: '302',
            statusMessage: 'wrong',
          ),
        );

        await expectLater(
          () => harness.runtime.execute(buildProbeRequest()),
          throwsA(isA<GsdInvalidCredentialsException>()),
        );

        expect(eventCount, equals(1));
        expect(
          server.requests
              .where((request) => request.path == '/dfapp/v2/login/key')
              .length,
          equals(2),
        );
        expect(
          server.requests
              .where((request) => request.path == '/dfapp/v2/login')
              .length,
          equals(2),
        );
      },
    );
  });

  group('ApiRuntime Session-Retry', () {
    test('initialSessionId ohne Login-Credentials führt keinen Auto-Refresh '
        'aus', () async {
      final harness = buildHarness(
        configuration: buildSessionRuntimeConfiguration(
          initialSessionId: 'restored-session',
        ),
      );
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '201',
          statusMessage: 'invalid',
        ),
      );

      await expectLater(
        () => harness.runtime.execute(buildProbeRequest()),
        throwsA(isA<GsdSessionInvalidException>()),
      );

      expect(server.requests, hasLength(1));
      expect(server.requests.single.path, equals('/dfapp/v1/probe'));
    });

    test(
      'fehlende Refresh-Credentials fragen bei 341 nicht den 2FA-Provider',
      () async {
        var eventCount = 0;
        final events = RuntimeEvents(
          twoFactorTokenProvider: () async {
            eventCount++;
            return '123456';
          },
        );
        final harness = buildHarness(
          configuration: buildSessionRuntimeConfiguration(
            initialSessionId: 'restored-session',
          ),
          events: events,
        );
        server.enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: v1Envelope(
            internalStatus: '341',
            statusMessage: 'missing 2fa',
          ),
        );

        await expectLater(
          () => harness.runtime.execute(buildProbeRequest()),
          throwsA(isA<GsdTwoFactorTokenMissingException>()),
        );

        expect(eventCount, equals(0));
        expect(server.requests, hasLength(1));
      },
    );

    test('201-Envelope: genau EIN Refresh (Key+Login) plus EIN Retry mit neuer '
        'sessionid führt zum Erfolg', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '201',
          statusMessage: 'invalid',
        ),
      );
      scriptLoginKey();
      scriptLoginSuccess('sess-refreshed');
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(data: {'ok': true}),
      );

      final response = await harness.runtime.execute(buildProbeRequest());

      expect(response, {'ok': true});
      expect(
        harness.coordinator.sessionState.sessionId,
        equals('sess-refreshed'),
      );

      final probeRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/probe')
          .toList();
      expect(probeRequests, hasLength(2));
      expect(probeRequests[0].header('sessionid'), equals('sess-initial'));
      expect(probeRequests[1].header('sessionid'), equals('sess-refreshed'));
    });

    test('204-Envelope (TokenOrSessionIsMissing): dieselbe '
        'Refresh-und-Retry-Sequenz wie bei 201', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '204',
          statusMessage: 'missing',
        ),
      );
      scriptLoginKey();
      scriptLoginSuccess('sess-refreshed-204');
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(data: {'ok': true}),
      );

      final response = await harness.runtime.execute(buildProbeRequest());

      expect(response, {'ok': true});
      final probeRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/probe')
          .toList();
      expect(probeRequests, hasLength(2));
      expect(probeRequests[0].header('sessionid'), equals('sess-initial'));
      expect(
        probeRequests[1].header('sessionid'),
        equals('sess-refreshed-204'),
      );
    });

    test('bleibt der Retry NACH erfolgreichem Refresh weiterhin bei 201: die '
        'Exception propagiert und es gibt KEINEN dritten Versuch', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '201',
          statusMessage: 'invalid',
        ),
      );
      scriptLoginKey();
      scriptLoginSuccess('sess-refreshed');
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '201',
          statusMessage: 'still invalid',
        ),
      );

      await expectLater(
        () => harness.runtime.execute(buildProbeRequest()),
        throwsA(isA<GsdSessionInvalidException>()),
      );

      final probeRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/probe')
          .toList();
      // Genau 2 Versuche (Original + EIN Retry) - kein dritter Versuch.
      expect(probeRequests, hasLength(2));
      expect(server.pendingCount('GET', '/dfapp/v1/probe'), equals(0));
    });

    test('2FA (341): der 2FA-Provider liefert ein Token -> der '
        'Refresh-Login-Body trägt das Token als 2faToken -> '
        'Retry ist erfolgreich', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      const suppliedToken = '654321';
      final events = RuntimeEvents(
        twoFactorTokenProvider: () async => suppliedToken,
      );
      final harness = buildHarness(events: events);
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '341',
          statusMessage: 'missing 2fa',
        ),
      );

      scriptLoginKey();
      String? decryptedRefreshBody;
      server
        ..enqueue('POST', '/dfapp/v2/login', (req) async {
          decryptedRefreshBody = await decryptV2LoginBody(
            req.body,
            serverPrivateKey,
          );
          return ScriptedResponse(
            jsonEncode(v1Envelope(data: {'sessionId': 'sess-2fa'})),
          );
        })
        ..enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: v1Envelope(data: {'ok': true}),
        );

      final response = await harness.runtime.execute(buildProbeRequest());

      expect(response, {'ok': true});
      expect(harness.coordinator.sessionState.sessionId, equals('sess-2fa'));
      final decodedRefreshBody =
          jsonDecode(decryptedRefreshBody!) as Map<String, dynamic>;
      expect(decodedRefreshBody['2faToken'], equals(suppliedToken));
    });

    test(
      '2FA (341): der 2FA-Provider liefert einen leeren String -> '
      'GsdTwoFactorTokenMissingException propagiert, KEIN Refresh und KEIN '
      'Retry',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        final events = RuntimeEvents(
          twoFactorTokenProvider: () async => '',
        );
        final harness = buildHarness(events: events);
        await harness.coordinator.login('md5hash');

        server.enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: v1Envelope(
            internalStatus: '341',
            statusMessage: 'missing 2fa',
          ),
        );

        await expectLater(
          () => harness.runtime.execute(buildProbeRequest()),
          throwsA(isA<GsdTwoFactorTokenMissingException>()),
        );

        final probeRequests = server.requests
            .where((r) => r.path == '/dfapp/v1/probe')
            .toList();
        expect(probeRequests, hasLength(1));
        // Nur der initiale Login - kein zusätzlicher Refresh-Versuch.
        final loginKeyCount = server.requests
            .where((r) => r.path == '/dfapp/v2/login/key')
            .length;
        expect(loginKeyCount, equals(1));
      },
    );

    test('AuthenticationPolicy.sessionNoRefresh: sessionid-Header wird '
        'gesendet, aber eine 201-Antwort löst KEINEN Refresh aus - die '
        'Exception propagiert direkt', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '201',
          statusMessage: 'invalid',
        ),
      );

      await expectLater(
        () => harness.runtime.execute(
          buildProbeRequest(
            authentication: AuthenticationPolicy.sessionNoRefresh,
          ),
        ),
        throwsA(isA<GsdSessionInvalidException>()),
      );

      final probeRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/probe')
          .toList();
      expect(probeRequests, hasLength(1));
      expect(probeRequests.single.header('sessionid'), equals('sess-initial'));
      final loginKeyCount = server.requests
          .where((r) => r.path == '/dfapp/v2/login/key')
          .length;
      expect(loginKeyCount, equals(1));
    });

    test('AuthenticationPolicy.none: kein sessionid-Header, eine 201-Antwort '
        'löst KEINEN Refresh aus', () async {
      scriptLoginKey();
      scriptLoginSuccess('sess-initial');
      final harness = buildHarness();
      await harness.coordinator.login('md5hash');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(
          internalStatus: '201',
          statusMessage: 'invalid',
        ),
      );

      await expectLater(
        () => harness.runtime.execute(
          buildProbeRequest(authentication: AuthenticationPolicy.none),
        ),
        throwsA(isA<GsdSessionInvalidException>()),
      );

      final probeRequests = server.requests
          .where((r) => r.path == '/dfapp/v1/probe')
          .toList();
      expect(probeRequests, hasLength(1));
      expect(probeRequests.single.header('sessionid'), isNull);
      final loginKeyCount = server.requests
          .where((r) => r.path == '/dfapp/v2/login/key')
          .length;
      expect(loginKeyCount, equals(1));
    });
  });
}
