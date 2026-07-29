// ignore_for_file: deprecated_member_use_from_same_package
//
// Charakterisierungstests: Request-Pfad (URI/Header/Query), Response-Parsing
// und Exception-Mapping von RestApiDOCUframeManager.
//
// Diese Tests dokumentieren das TATSÄCHLICHE Verhalten des eingefrorenen
// Legacy-Codes - inklusive bekannter Bugs/Kuriositäten. Sie sind KEIN
// Vorschlag, wie sich der Code verhalten SOLLTE.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import 'legacy_test_server.dart';

void main() {
  ensureLegacyCryptoTestEnvironment();

  late LegacyTestServer server;
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

  group('URI- und Header-Konstruktion', () {
    test(
      'getObject: alias-Präfix, class/serialization als Query nur wenn gesetzt, Header vollständig',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(data: {'oid': 'OID1'}),
        );
        final config = buildLegacyConfig(
          server,
          alias: 'dfapp',
          sessionId: 'sess-abc',
        );
        final manager = newManager(config);

        final response = await manager.getObject(
          'OID1',
          className: 'Vorgang',
          serialization: '{"type":"full"}',
        );

        expect(response.isOk, isTrue);
        expect(server.requests, hasLength(1));
        final req = server.requests.single;
        expect(req.method, equals('GET'));
        expect(req.path, equals('/dfapp/v1/object/OID1'));
        expect(
          req.query,
          equals({'class': 'Vorgang', 'serialization': '{"type":"full"}'}),
        );
        expect(req.header('appkey'), equals('TEST-APP-KEY'));
        expect(
          req.header('content-type'),
          equals('application/json; charset=utf-8'),
        );
        expect(req.header('sessionid'), equals('sess-abc'));
      },
    );

    test(
      'getObject: class/serialization werden bei leerem String weggelassen',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(data: {}),
        );
        final config = buildLegacyConfig(server);
        final manager = newManager(config);

        await manager.getObject('OID1');

        final req = server.requests.single;
        expect(req.query, isEmpty);
      },
    );

    test('leerer alias entfernt das alias-Segment aus dem Pfad', () async {
      server.enqueueJson('GET', '/v1/object/OID1', body: v1Envelope(data: {}));
      final config = buildLegacyConfig(server, alias: '');
      final manager = newManager(config);

      await manager.getObject('OID1');

      expect(server.requests.single.path, equals('/v1/object/OID1'));
    });

    test('sessionid-Header fehlt, wenn config.sessionId leer ist', () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(data: {}),
      );
      final config = buildLegacyConfig(server, sessionId: '');
      final manager = newManager(config);

      await manager.getObject('OID1');

      final req = server.requests.single;
      expect(req.headers.containsKey('sessionid'), isFalse);
      expect(req.header('appkey'), equals('TEST-APP-KEY'));
    });

    test(
      'getObjects: perPage wird immer gesetzt, page nur wenn != 0, weitere Parameter nur wenn nicht-leer',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/objects/Vorgang',
          body: v1Envelope(data: []),
        );
        final config = buildLegacyConfig(server);
        final manager = newManager(config);

        await manager.getObjects('Vorgang');

        final req = server.requests.single;
        expect(req.path, equals('/dfapp/v1/objects/Vorgang'));
        // perPage wird immer aus config.perPageCount (Default 50) gesetzt.
        expect(req.query, equals({'perPage': '50'}));
      },
    );

    test(
      'getObjects: alle optionalen Parameter werden übernommen, page != 0 erscheint',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/objects/Vorgang',
          body: v1Envelope(data: []),
        );
        final config = buildLegacyConfig(server);
        final manager = newManager(config);

        await manager.getObjects(
          'Vorgang',
          query: 'foo=bar',
          page: 2,
          perPage: 25,
          serialization: '{"type":"preview"}',
          actions: '[{"type":"x"}]',
          rightsControlKey: 'rck',
        );

        final req = server.requests.single;
        expect(
          req.query,
          equals({
            'query': 'foo=bar',
            'page': '2',
            'perPage': '25',
            'serialization': '{"type":"preview"}',
            'actions': '[{"type":"x"}]',
            'rightsControlKey': 'rck',
          }),
        );
      },
    );

    test(
      'postObject: POST-Methode, Body wird unverändert gesendet, storeMode 0 wird nicht als Query gesendet',
      () async {
        server.enqueueJson(
          'POST',
          '/dfapp/v1/object/Vorgang',
          body: v1Envelope(data: {'oid': 'NEW1'}),
        );
        final config = buildLegacyConfig(server);
        final manager = newManager(config);

        final body = '{"name":"Testvorgang"}';
        final response = await manager.postObject('Vorgang', body);

        expect(response.isOk, isTrue);
        final req = server.requests.single;
        expect(req.method, equals('POST'));
        expect(req.path, equals('/dfapp/v1/object/Vorgang'));
        expect(req.query, isEmpty);
        expect(req.body, equals(body));
      },
    );
  });

  group('Response-Parsing / Exception-Mapping', () {
    test('internalStatus "0" => isOk true', () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(data: {'x': 1}),
      );
      final manager = newManager(buildLegacyConfig(server));

      final response = await manager.getObject('OID1');
      expect(response.isOk, isTrue);
      expect(response.internalStatus, equals('0'));
    });

    test('internalStatus "200" => isOk true', () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(data: {'x': 1}, internalStatus: '200'),
      );
      final manager = newManager(buildLegacyConfig(server));

      final response = await manager.getObject('OID1');
      expect(response.isOk, isTrue);
    });

    test(
      'internalStatus "201" auf frischem (nie eingeloggtem) Manager: SessionInvalidException, '
      'aber loggedIn wird als Seiteneffekt trotzdem auf true gesetzt (Bug)',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(
            internalStatus: '201',
            statusMessage: 'session invalid',
          ),
        );
        final manager = newManager(buildLegacyConfig(server));

        expect(manager.loggedIn, isFalse);
        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<SessionInvalidException>()),
        );
        // Da _loggedIn zu Beginn false war, greift der Session-Refresh-Zweig
        // in _http() nicht (handleSession && _loggedIn && !_manualLoggedOut
        // ist false) -> die Exception wird im catch verschluckt (kein
        // rethrow), die Schleife endet regulär, _http() setzt _loggedIn=true
        // und liefert die UNVERÄNDERTE Antwort zurück. getObject() parst sie
        // ein zweites Mal (RestApiResponse(...)), was erneut wirft - dieser
        // zweite Wurf verlässt getObject(). Nur EIN echter HTTP-Request.
        expect(manager.loggedIn, isTrue);
        expect(server.requests, hasLength(1));
      },
    );

    test(
      'internalStatus "204" auf frischem Manager: TokenOrSessionIsMissingException, '
      'gleicher loggedIn-Seiteneffekt wie bei 201',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(
            internalStatus: '204',
            statusMessage: 'token missing',
          ),
        );
        final manager = newManager(buildLegacyConfig(server));

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<TokenOrSessionIsMissingException>()),
        );
        expect(manager.loggedIn, isTrue);
        expect(server.requests, hasLength(1));
      },
    );

    test(
      'internalStatus "302" => UserAndPassWrongException + Callback wird ausgelöst',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(internalStatus: '302', statusMessage: 'wrong'),
        );
        UserAndPassWrongException? seen;
        final callbacks = RestApiDOCUframeCallbacks(
          onUserAndPassWrong: (e) async {
            seen = e;
          },
        );
        final manager = newManager(
          buildLegacyConfig(server),
          callbacks: callbacks,
        );

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<UserAndPassWrongException>()),
        );
        expect(seen, isNotNull);
      },
    );

    test(
      'internalStatus "306" => LicenseException + Callback wird ausgelöst',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(internalStatus: '306', statusMessage: 'license'),
        );
        LicenseException? seen;
        final callbacks = RestApiDOCUframeCallbacks(
          onLicenseWrong: (e) async {
            seen = e;
          },
        );
        final manager = newManager(
          buildLegacyConfig(server),
          callbacks: callbacks,
        );

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<LicenseException>()),
        );
        expect(seen, isNotNull);
      },
    );

    test('internalStatus "101" => ebenfalls LicenseException', () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(internalStatus: '101', statusMessage: 'license 101'),
      );
      final manager = newManager(buildLegacyConfig(server));

      await expectLater(
        () => manager.getObject('OID1'),
        throwsA(isA<LicenseException>()),
      );
    });

    test(
      'internalStatus "340" => Require2FALoginException (direkt propagiert)',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(
            internalStatus: '340',
            statusMessage: '2fa required',
          ),
        );
        final manager = newManager(buildLegacyConfig(server));

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<Require2FALoginException>()),
        );
        // Kein Sonderfall in _http() -> generischer catch(e){rethrow} -> _loggedIn bleibt false.
        expect(manager.loggedIn, isFalse);
      },
    );

    test(
      'internalStatus "341" => Missing2FATokenException wird direkt weitergereicht, '
      'solange der Aufruf nicht Teil eines refreshSession-Vorgangs ist',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(
            internalStatus: '341',
            statusMessage: 'missing token',
          ),
        );
        final manager = newManager(buildLegacyConfig(server));

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<Missing2FATokenException>()),
        );
      },
    );

    test('internalStatus "342" => Invalid2FATokenException', () async {
      server.enqueueJson(
        'GET',
        '/dfapp/v1/object/OID1',
        body: v1Envelope(internalStatus: '342', statusMessage: 'invalid token'),
      );
      final manager = newManager(buildLegacyConfig(server));

      await expectLater(
        () => manager.getObject('OID1'),
        throwsA(isA<Invalid2FATokenException>()),
      );
    });

    test(
      'unbekannter internalStatus (z.B. "999") => WebServiceException',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(internalStatus: '999', statusMessage: 'unknown'),
        );
        final manager = newManager(buildLegacyConfig(server));

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<WebServiceException>()),
        );
      },
    );

    test(
      'fehlendes "status"-Feld => TypeError statt HttpRequestException '
      '(Bug: httpResponse.statusCode as String castet int auf String)',
      () async {
        server.enqueue(
          'GET',
          '/dfapp/v1/object/OID1',
          (req) => ScriptedResponse('{"foo":"bar"}', statusCode: 200),
        );
        final manager = newManager(buildLegacyConfig(server));

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<TypeError>()),
        );
      },
    );

    test('fehlendes "status.internalStatus"-Feld => FormatException', () async {
      server.enqueue(
        'GET',
        '/dfapp/v1/object/OID1',
        (req) => ScriptedResponse('{"status":{"statusMessage":"oops"}}'),
      );
      final manager = newManager(buildLegacyConfig(server));

      await expectLater(
        () => manager.getObject('OID1'),
        throwsA(isA<FormatException>()),
      );
    });

    test('fehlendes "status.statusMessage"-Feld => FormatException', () async {
      server.enqueue(
        'GET',
        '/dfapp/v1/object/OID1',
        (req) => ScriptedResponse('{"status":{"internalStatus":"0"}}'),
      );
      final manager = newManager(buildLegacyConfig(server));

      await expectLater(
        () => manager.getObject('OID1'),
        throwsA(isA<FormatException>()),
      );
    });

    test(
      'komplett ungültiges JSON im Body => RangeError, NICHT FormatException '
      '(Bug/Kuriosität: _http() prüft body.isValidJson() VOR dem eigentlichen '
      'RestApiResponse-Parsing und interpretiert jeden nicht-JSON-Body als '
      'Pipe-getrennte AES/RSA-verschlüsselte Antwort ("aesKey|body"). Ohne "|" '
      'im Text wirft `responseBodyParts[1]` ein RangeError, bevor RestApiResponse '
      'überhaupt jsonDecode versucht.)',
      () async {
        server.enqueue(
          'GET',
          '/dfapp/v1/object/OID1',
          (req) => ScriptedResponse('this is not json'),
        );
        final manager = newManager(buildLegacyConfig(server));

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<RangeError>()),
        );
      },
    );

    test(
      'JSON-Body, der syntaktisch aber nicht strukturell gültig ist (z.B. ein JSON-Array) '
      'wird von isValidJson() als "valid JSON" akzeptiert, aber RestApiResponse '
      'scheitert dann am impliziten Downcast auf Map<String, dynamic> => TypeError',
      () async {
        server.enqueue(
          'GET',
          '/dfapp/v1/object/OID1',
          (req) => ScriptedResponse('[1,2,3]'),
        );
        final manager = newManager(buildLegacyConfig(server));

        await expectLater(
          () => manager.getObject('OID1'),
          throwsA(isA<TypeError>()),
        );
      },
    );
  });
}
