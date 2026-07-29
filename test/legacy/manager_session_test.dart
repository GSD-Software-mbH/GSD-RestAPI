// ignore_for_file: deprecated_member_use_from_same_package
//
// Charakterisierungstests: Login (v2/login-Key-Fetch + AES/RSA-verschlüsselter
// Body + Session-ID-Speicherung + Callback), automatische Session-Erneuerung
// bei internalStatus 201/204 samt Retry, Logout und Single-Flight-Refresh.
//
// Der Login-Roundtrip wird mit ECHTER RSA/AES-Verschlüsselung (gsd_encryption)
// gegen einen selbst erzeugten "Server"-Schlüssel verifiziert - es wird also
// nicht nur die Form des Bodys geprüft, sondern der Body wird server-seitig
// entschlüsselt und mit dem erwarteten Klartext verglichen.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:pointycastle/export.dart' show RSAPublicKey, RSAPrivateKey;

import 'legacy_test_server.dart';

void main() {
  ensureLegacyCryptoTestEnvironment();

  late LegacyTestServer server;
  late RSAPublicKey serverPublicKey;
  late RSAPrivateKey serverPrivateKey;
  final managers = <RestApiDOCUframeManager>[];

  RestApiDOCUframeManager newManager(
    RestApiDOCUframeConfig config, {
    RestApiDOCUframeCallbacks? callbacks,
  }) {
    final manager = RestApiDOCUframeManager(
      config: config,
      callbacks: callbacks,
    );
    managers.add(manager);
    return manager;
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

  setUpAll(() async {
    final pair = await generateServerKeyPair();
    serverPublicKey = pair.publicKey;
    serverPrivateKey = pair.privateKey;
  });

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

  group('login()', () {
    test(
      'holt zuerst den Public Key (v2/login/key), verschlüsselt den Body echt '
      'per RSA/AES und speichert die vom Server gelieferte Session-ID; '
      'onSessionIdChanged wird ausgelöst',
      () async {
        scriptLoginKey();
        String? decryptedBody;
        server.enqueue('POST', '/dfapp/v2/login', (req) async {
          decryptedBody = await decryptV2LoginBody(req.body, serverPrivateKey);
          return ScriptedResponse(
            jsonEncode(v1Envelope(data: {'sessionId': 'sess-1'})),
          );
        });

        final config = buildLegacyConfig(
          server,
          userName: 'demo',
          appNames: ['App1', 'App2'],
        );
        final sessionEvents = <String>[];
        final callbacks = RestApiDOCUframeCallbacks(
          onSessionIdChanged: (id) async {
            sessionEvents.add(id);
          },
        );
        final manager = newManager(config, callbacks: callbacks);

        final response = await manager.login('md5hash');

        expect(response.isOk, isTrue);
        expect(response.sessionId, equals('sess-1'));
        expect(config.sessionId, equals('sess-1'));
        expect(sessionEvents, equals(['sess-1']));

        // Request-Reihenfolge: erst der Key-Fetch, dann der Login-POST.
        expect(server.requests, hasLength(2));
        expect(server.requests[0].method, equals('GET'));
        expect(server.requests[0].path, equals('/dfapp/v2/login/key'));
        expect(server.requests[1].method, equals('POST'));
        expect(server.requests[1].path, equals('/dfapp/v2/login'));

        // Der Request-Body ist NICHT der Klartext, sondern ein JSON mit
        // genau den 3 Feldern aesKey/data/publicKey.
        final rawBody =
            jsonDecode(server.requests[1].body) as Map<String, dynamic>;
        expect(rawBody.keys.toSet(), equals({'aesKey', 'data', 'publicKey'}));
        expect(rawBody['data'], isNot(contains('demo')));

        // Server-seitig entschlüsselt entspricht der Body exakt den erwarteten
        // Klartext-Login-Daten.
        final decodedClear = jsonDecode(decryptedBody!) as Map<String, dynamic>;
        expect(decodedClear['user'], equals('demo'));
        expect(decodedClear['pass'], equals('md5hash'));
        expect(decodedClear['appNames'], equals(['App1', 'App2']));
        expect(decodedClear['furtherencryption'], isFalse);
        expect(decodedClear.containsKey('2faToken'), isFalse);
      },
    );

    test(
      'sessionid-Header wird beim Login NICHT gesendet (addSessionId:false)',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-2');
        final config = buildLegacyConfig(server, sessionId: 'old-session');
        final manager = newManager(config);

        await manager.login('md5hash');

        final loginKeyReq = server.requests[0];
        final loginReq = server.requests[1];
        expect(loginKeyReq.headers.containsKey('sessionid'), isFalse);
        expect(loginReq.headers.containsKey('sessionid'), isFalse);
      },
    );

    test(
      'schlägt der Key-Fetch fehl (kein isOk), wirft login() eine Exception und '
      'löscht die sessionId (onSessionIdChanged("") wird gefeuert)',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v2/login/key',
          statusCode: 200,
          body: v1Envelope(
            internalStatus: '999',
            statusMessage: 'key unavailable',
          ),
        );
        final config = buildLegacyConfig(server, sessionId: 'pre-existing');
        final sessionEvents = <String>[];
        final callbacks = RestApiDOCUframeCallbacks(
          onSessionIdChanged: (id) async => sessionEvents.add(id),
        );
        final manager = newManager(config, callbacks: callbacks);

        // Der fehlgeschlagene Key-Fetch (internalStatus 999) wird bereits in
        // _http() als WebServiceException geworfen, bevor login() seine
        // eigene Exception("Secure Key can not be provided") erreichen kann.
        await expectLater(
          () => manager.login('md5hash'),
          throwsA(isA<WebServiceException>()),
        );

        expect(config.sessionId, equals(''));
        expect(sessionEvents, equals(['']));
        // Login-POST wurde nie versucht, da der Key-Fetch schon fehlschlug.
        expect(server.requests, hasLength(1));
      },
    );

    test(
      '2faToken wird nur bei explizitem twoFactorAuthToken-Argument in den Klartext-Body aufgenommen',
      () async {
        scriptLoginKey();
        String? decryptedBody;
        server.enqueue('POST', '/dfapp/v2/login', (req) async {
          decryptedBody = await decryptV2LoginBody(req.body, serverPrivateKey);
          return ScriptedResponse(
            jsonEncode(v1Envelope(data: {'sessionId': 'sess-3'})),
          );
        });
        final manager = newManager(buildLegacyConfig(server));

        await manager.login('md5hash', twoFactorAuthToken: '123456');

        final decoded = jsonDecode(decryptedBody!) as Map<String, dynamic>;
        expect(decoded['2faToken'], equals('123456'));
      },
    );
  });

  group('automatische Session-Erneuerung bei 201/204', () {
    test(
      'bereits eingeloggter Manager: 201 bei normalem Request löst _synchronizedRefreshSession '
      'aus (erneuter Login-Key-Fetch + Login), der Original-Request wird mit neuer '
      'sessionid wiederholt und liefert dann Erfolg',
      () async {
        // Initialer Login, um _loggedIn == true zu erreichen.
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        final config = buildLegacyConfig(server);
        final manager = newManager(config);
        await manager.login('md5hash');
        expect(manager.loggedIn, isTrue);

        // Erster Objektaufruf schlägt mit 201 fehl (Session ungültig).
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
        );
        // Refresh-Login-Sequenz.
        scriptLoginKey();
        scriptLoginSuccess('sess-refreshed');
        // Retry des Original-Requests - diesmal erfolgreich.
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(data: {'oid': 'OID1'}),
        );

        final response = await manager.getObject('OID1');

        expect(response.isOk, isTrue);
        expect(config.sessionId, equals('sess-refreshed'));

        // Request-Reihenfolge nachvollziehen:
        // 0: login/key, 1: login (initial), 2: object (201),
        // 3: login/key (refresh), 4: login (refresh), 5: object (retry, mit neuer sessionid)
        expect(server.requests, hasLength(6));
        expect(server.requests[2].path, equals('/dfapp/v1/object/OID1'));
        expect(server.requests[2].header('sessionid'), equals('sess-initial'));
        expect(server.requests[5].path, equals('/dfapp/v1/object/OID1'));
        expect(
          server.requests[5].header('sessionid'),
          equals('sess-refreshed'),
        );
      },
    );

    test(
      'bereits eingeloggter Manager: 204 (TokenOrSessionIsMissing) bei normalem '
      'Request löst dieselbe Refresh-und-Retry-Sequenz aus wie 201',
      () async {
        // Initialer Login, um _loggedIn == true zu erreichen.
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        final config = buildLegacyConfig(server);
        final manager = newManager(config);
        await manager.login('md5hash');
        expect(manager.loggedIn, isTrue);

        // Erster Objektaufruf schlägt mit 204 fehl (Token/Session fehlt).
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(
            internalStatus: '204',
            statusMessage: 'token missing',
          ),
        );
        // Refresh-Login-Sequenz.
        scriptLoginKey();
        scriptLoginSuccess('sess-refreshed-204');
        // Retry des Original-Requests - diesmal erfolgreich.
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(data: {'oid': 'OID1'}),
        );

        final response = await manager.getObject('OID1');

        expect(response.isOk, isTrue);
        expect(config.sessionId, equals('sess-refreshed-204'));

        // Gleiche Abfolge wie beim 201-Fall:
        // 0: login/key, 1: login (initial), 2: object (204),
        // 3: login/key (refresh), 4: login (refresh), 5: object (retry)
        expect(server.requests, hasLength(6));
        expect(server.requests[2].header('sessionid'), equals('sess-initial'));
        expect(
          server.requests[5].header('sessionid'),
          equals('sess-refreshed-204'),
        );
      },
    );

    test(
      'single-flight: zwei parallele Requests, die beide mit 201 antworten, '
      'lösen nur EINE Login-Sequenz aus (_ongoingLogin wird geteilt)',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        final config = buildLegacyConfig(server);
        final manager = newManager(config);
        await manager.login('md5hash');

        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OIDA',
          body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
          delay: const Duration(milliseconds: 30),
        );
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OIDB',
          body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
          delay: const Duration(milliseconds: 30),
        );

        // Nur EINE Refresh-Login-Sequenz eingeplant.
        scriptLoginKey();
        scriptLoginSuccess('sess-shared-refresh');

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

        final fA = manager.getObject('OIDA');
        final fB = manager.getObject('OIDB');

        final rA = await fA;
        final rB = await fB;

        expect(rA.isOk, isTrue);
        expect(rB.isOk, isTrue);
        expect(config.sessionId, equals('sess-shared-refresh'));

        // Genau EIN login/key + EIN login-POST für den Refresh (plus die 2
        // initialen für den Erstlogin) - macht in Summe 2 Key-Fetches und
        // 2 Login-POSTs über den gesamten Testverlauf.
        final loginKeyCount = server.requests
            .where((r) => r.path == '/dfapp/v2/login/key')
            .length;
        final loginPostCount = server.requests
            .where((r) => r.path == '/dfapp/v2/login')
            .length;
        expect(loginKeyCount, equals(2));
        expect(loginPostCount, equals(2));
      },
    );

    test(
      'handleSession:false via customRequest(): eine 201-Antwort löst KEINEN Refresh aus und wird '
      'auch NICHT als Exception sichtbar - customRequest() gibt die rohe http.Response mit dem '
      '201-Envelope im Body zurück, ohne sie (wie z.B. getObject()) ein zweites Mal über '
      'RestApiResponse zu parsen',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-initial');
        final config = buildLegacyConfig(server);
        final manager = newManager(config);
        await manager.login('md5hash');

        server.enqueueJson(
          'GET',
          '/dfapp/x/y',
          body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
        );

        final response = await manager.customRequest(
          HttpMethod.get,
          '/x/y',
          handleSession: false,
        );

        expect(response.statusCode, equals(200));
        final decoded = jsonDecode(response.body) as Map<String, dynamic>;
        expect(decoded['status']['internalStatus'], equals('201'));
        // Genau 1 login/key-Aufruf (der initiale Login) - kein zusätzlicher
        // Refresh-Versuch durch die 201-Antwort auf /x/y.
        expect(
          server.requests.where((r) => r.path == '/dfapp/v2/login/key'),
          hasLength(1),
        );
      },
    );
  });

  group('logout()', () {
    test(
      'sendet POST v1/logout, leert die Session-ID auch bei Erfolg und feuert onSessionIdChanged(""); '
      'loggedIn wird durch den generischen Erfolgspfad in _http() aber wieder auf true gesetzt (Bug: '
      'logout() setzt _loggedIn=false VOR dem Request, doch _http() setzt es nach jedem erfolgreich '
      'geparsten Response wieder unbedingt auf true)',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-1');
        final config = buildLegacyConfig(server);
        final events = <String>[];
        final callbacks = RestApiDOCUframeCallbacks(
          onSessionIdChanged: (id) async => events.add(id),
        );
        final manager = newManager(config, callbacks: callbacks);
        await manager.login('md5hash');

        server.enqueueJson(
          'POST',
          '/dfapp/v1/logout',
          body: v1Envelope(data: {}),
        );

        final response = await manager.logout();

        expect(response.isOk, isTrue);
        expect(config.sessionId, equals(''));
        expect(events.last, equals(''));
        expect(manager.loggedIn, isTrue);
      },
    );

    test(
      'leert die Session-ID auch dann, wenn der Logout-Request fehlschlägt',
      () async {
        scriptLoginKey();
        scriptLoginSuccess('sess-1');
        final config = buildLegacyConfig(server);
        final manager = newManager(config);
        await manager.login('md5hash');

        server.enqueueJson(
          'POST',
          '/dfapp/v1/logout',
          body: v1Envelope(
            internalStatus: '999',
            statusMessage: 'server error',
          ),
        );

        await expectLater(
          () => manager.logout(),
          throwsA(isA<WebServiceException>()),
        );
        expect(config.sessionId, equals(''));
      },
    );
  });
}
