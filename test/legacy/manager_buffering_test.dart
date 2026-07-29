// ignore_for_file: deprecated_member_use_from_same_package
//
// Charakterisierungstests: MultiRequest-Buffering (config.multiRequest),
// Flush per maxBufferSize und per Timer, Einzelrequest-Fallback bei genau
// einem gepufferten Request, RequestPriority.high, executeWithoutBuffering()
// und die never-buffer Endpunkte.

import 'dart:convert';
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

  group('Flush durch maxBufferSize', () {
    test(
      'zwei gepufferte Requests bei maxBufferSize:2 werden sofort (ohne auf den '
      'Timer zu warten) als EIN POST /v1/multi mit 2 Items in Aufrufreihenfolge gebündelt',
      () async {
        server.enqueue('POST', '/dfapp/v1/multi', (req) async {
          final items = jsonDecode(req.body) as List<dynamic>;
          final results = items.map((item) {
            final path = item['path'] as String;
            final oid = path.split('/').last;
            return {
              'httpStatus': 200,
              'result': v1Envelope(data: {'oid': oid}),
            };
          }).toList();
          return ScriptedResponse(jsonEncode(v1Envelope(data: results)));
        });

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 2,
          bufferFlushDelayMs:
              5000, // absichtlich lang, damit der Timer NICHT feuert
        );
        final manager = newManager(config);

        final fA = manager.getObject('OIDA');
        final fB = manager.getObject('OIDB');

        final rA = await fA;
        final rB = await fB;

        expect(rA.isOk, isTrue);
        expect(rB.isOk, isTrue);

        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/multi'));
        expect(server.requests.single.method, equals('POST'));

        final sentItems =
            jsonDecode(server.requests.single.body) as List<dynamic>;
        expect(sentItems, hasLength(2));
        expect(sentItems[0]['method'], equals('GET'));
        // Kuriosität: getObject() übergibt _getUri() ein LEERES (nicht null)
        // Query-Parameter-Map, wenn class/serialization nicht gesetzt sind.
        // Uri.replace(queryParameters: {}) erzeugt trotzdem ein "?" am Ende.
        expect(sentItems[0]['path'], equals('/v1/object/OIDA?'));
        expect(sentItems[1]['path'], equals('/v1/object/OIDB?'));
      },
    );
  });

  group('Gepufferte Requests mit Body', () {
    test(
      'ein gepufferter POST mit Body (postObject) erscheint im /v1/multi-Array '
      'mit method "POST" und dem JSON-dekodierten Body im "data"-Feld',
      () async {
        server.enqueue('POST', '/dfapp/v1/multi', (req) async {
          final items = jsonDecode(req.body) as List<dynamic>;
          final results = items.map((item) {
            return {
              'httpStatus': 200,
              'result': v1Envelope(data: {'ok': true}),
            };
          }).toList();
          return ScriptedResponse(jsonEncode(v1Envelope(data: results)));
        });

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 2,
          bufferFlushDelayMs: 5000, // Flush wird durch maxBufferSize ausgelöst
        );
        final manager = newManager(config);

        final postBody = '{"name":"Neuer Vorgang","prio":3}';
        // Zweiter Request dazu, damit der Multi-Zweig genommen wird
        // (ein einzelner gepufferter Request würde als Einzelrequest rausgehen).
        final fPost = manager.postObject('Vorgang', postBody);
        final fGet = manager.getObject('OIDX');

        final rPost = await fPost;
        final rGet = await fGet;

        expect(rPost.isOk, isTrue);
        expect(rGet.isOk, isTrue);
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/multi'));

        final items = jsonDecode(server.requests.single.body) as List<dynamic>;
        expect(items, hasLength(2));

        final postItem = items.firstWhere((i) => i['method'] == 'POST');
        // Der Body wird per jsonDecode als JSON-Objekt (nicht als String)
        // in das "data"-Feld des Multi-Request-Items übernommen.
        expect(postItem['data'], equals({'name': 'Neuer Vorgang', 'prio': 3}));
        expect(postItem['path'], equals('/v1/object/Vorgang?'));

        final getItem = items.firstWhere((i) => i['method'] == 'GET');
        // GET ohne Body hat KEIN "data"-Feld.
        expect((getItem as Map).containsKey('data'), isFalse);
      },
    );
  });

  group('Multi-Request-Fehlerfall (Fallback auf Einzelrequests)', () {
    test(
      'antwortet /v1/multi mit HTTP != 200, werden alle gepufferten Requests '
      'einzeln an ihre Original-Pfade erneut gesendet und regulär abgeschlossen',
      () async {
        server.enqueue(
          'POST',
          '/dfapp/v1/multi',
          (req) => ScriptedResponse('server kaputt', statusCode: 500),
        );
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

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 2,
          bufferFlushDelayMs: 5000, // Flush durch maxBufferSize
        );
        final manager = newManager(config);

        final fA = manager.getObject('OIDA');
        final fB = manager.getObject('OIDB');

        final rA = await fA;
        final rB = await fB;

        // Beide Aufrufer bekommen trotz fehlgeschlagenem Multi-Request ein
        // korrektes Ergebnis über den Einzelrequest-Fallback.
        expect(rA.isOk, isTrue);
        expect(rB.isOk, isTrue);

        // Request-Abfolge: 1x /v1/multi (500), danach je 1 Einzelrequest.
        expect(server.requests, hasLength(3));
        expect(server.requests[0].path, equals('/dfapp/v1/multi'));
        expect(
          server.requests.skip(1).map((r) => r.path).toSet(),
          equals({'/dfapp/v1/object/OIDA', '/dfapp/v1/object/OIDB'}),
        );
      },
    );
  });

  group('Flush durch Timer', () {
    test('zwei gepufferte Requests unterhalb von maxBufferSize werden nach '
        'bufferFlushDelayMs als ein POST /v1/multi gebündelt', () async {
      server.enqueue('POST', '/dfapp/v1/multi', (req) async {
        final items = jsonDecode(req.body) as List<dynamic>;
        final results = items.map((item) {
          final path = item['path'] as String;
          final oid = path.split('/').last;
          return {
            'httpStatus': 200,
            'result': v1Envelope(data: {'oid': oid}),
          };
        }).toList();
        return ScriptedResponse(jsonEncode(v1Envelope(data: results)));
      });

      final config = buildLegacyConfig(
        server,
        multiRequest: true,
        maxBufferSize: 10,
        bufferFlushDelayMs: 300,
      );
      final manager = newManager(config);

      final fA = manager.getObject('OIDA');
      final fB = manager.getObject('OIDB');

      // Bevor der Timer feuert, wurde noch nichts an den Server gesendet.
      // (Großzügige Marge 50ms << 300ms, um Flakiness auf langsamen
      // CI-Event-Loops zu vermeiden.)
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(server.requests, isEmpty);

      final rA = await fA;
      final rB = await fB;

      expect(rA.isOk, isTrue);
      expect(rB.isOk, isTrue);
      expect(server.requests, hasLength(1));
      expect(server.requests.single.path, equals('/dfapp/v1/multi'));
    });

    test(
      'genau EIN gepufferter Request wird beim Flush NICHT als Multi-Request, '
      'sondern als normaler Einzelrequest an seinen ursprünglichen Pfad gesendet',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(data: {'oid': 'OID1'}),
        );

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 10,
          bufferFlushDelayMs: 30,
        );
        final manager = newManager(config);

        final response = await manager.getObject('OID1');

        expect(response.isOk, isTrue);
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/object/OID1'));
      },
    );
  });

  group('executeWithoutBuffering', () {
    test(
      'umgeht das Buffering vollständig, auch wenn multiRequest aktiv ist',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(data: {'oid': 'OID1'}),
        );

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 10,
          bufferFlushDelayMs: 5000,
        );
        final manager = newManager(config);

        final response = await manager.executeWithoutBuffering(
          () => manager.getObject('OID1'),
        );

        expect(response.isOk, isTrue);
        // Direkt als Einzelrequest, kein Warten auf einen Timer nötig.
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/object/OID1'));
      },
    );
  });

  group('RequestPriority.high', () {
    test(
      'ein einzelner high-priority Request wird beim Flush als Einzelrequest '
      'gesendet (nie in einen Multi-Request eingebettet), wartet aber weiterhin '
      'bufferFlushDelayMs',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/OID1',
          body: v1Envelope(data: {'oid': 'OID1'}),
        );

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 10,
          bufferFlushDelayMs: 300,
        );
        final manager = newManager(config);

        final future = manager.executeWithPriority(
          () => manager.getObject('OID1'),
          RequestPriority.high,
        );

        // Auch High-Priority wartet auf den Flush-Timer (kein sofortiger Versand).
        // (Großzügige Marge 50ms << 300ms gegen Flakiness.)
        await Future<void>.delayed(const Duration(milliseconds: 50));
        expect(server.requests, isEmpty);

        final response = await future;
        expect(response.isOk, isTrue);
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/object/OID1'));
      },
    );

    test(
      'normal- und high-priority Requests landen in getrennten Puffern: ein '
      'normal-priority Paar wird gebündelt (Multi-Request), der parallele '
      'high-priority Request bleibt davon unberührt und geht einzeln raus',
      () async {
        server.enqueue('POST', '/dfapp/v1/multi', (req) async {
          final items = jsonDecode(req.body) as List<dynamic>;
          final results = items.map((item) {
            return {
              'httpStatus': 200,
              'result': v1Envelope(data: {'path': item['path']}),
            };
          }).toList();
          return ScriptedResponse(jsonEncode(v1Envelope(data: results)));
        });
        server.enqueueJson(
          'GET',
          '/dfapp/v1/object/HIGH1',
          body: v1Envelope(data: {'oid': 'HIGH1'}),
        );

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 10,
          bufferFlushDelayMs: 40,
        );
        final manager = newManager(config);

        final normalA = manager.getObject('NORMALA');
        final normalB = manager.getObject('NORMALB');
        final high = manager.executeWithPriority(
          () => manager.getObject('HIGH1'),
          RequestPriority.high,
        );

        await Future.wait([normalA, normalB, high]);

        expect(server.requests, hasLength(2));
        final multiReq = server.requests.firstWhere(
          (r) => r.path == '/dfapp/v1/multi',
        );
        final singleReq = server.requests.firstWhere(
          (r) => r.path == '/dfapp/v1/object/HIGH1',
        );
        final multiItems = jsonDecode(multiReq.body) as List<dynamic>;
        expect(multiItems, hasLength(2));
        expect(singleReq.method, equals('GET'));
      },
    );
  });

  group('Never-Buffer Endpunkte', () {
    test(
      'logout() wird trotz multiRequest:true NIE gepuffert, sondern sofort einzeln gesendet',
      () async {
        server.enqueueJson(
          'POST',
          '/dfapp/v1/logout',
          body: v1Envelope(data: {}),
        );

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 10,
          bufferFlushDelayMs: 5000,
        );
        final manager = newManager(config);

        final response = await manager.logout();

        expect(response.isOk, isTrue);
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/logout'));
      },
    );

    test(
      'checkSession() (_CheckSession) wird trotz multiRequest:true nie gepuffert',
      () async {
        server.enqueueJson(
          'GET',
          '/dfapp/_CheckSession',
          body: v1Envelope(data: {}),
        );

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          bufferFlushDelayMs: 5000,
        );
        final manager = newManager(config);

        final response = await manager.checkSession();

        expect(response.isOk, isTrue);
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/_CheckSession'));
      },
    );

    test(
      'DISKREPANZ: Sync-Endpunkte (getSyncClassInfo, function "/v1/xSync/ClassInfo/...") werden '
      'TROTZDEM gepuffert, obwohl "/v1/xSync" im never-buffer-Set steht - der Eintrag matcht nie, '
      'weil _shouldNeverBuffer() den vollen Funktionsnamen inkl. Suffix exakt vergleicht. '
      '(Ein einzelner gepufferter Sync-Request würde beim Flush ohnehin als Einzelrequest an '
      'einen wegen eines Doppel-Slash-Bugs in getSyncClassInfo() falschen Pfad gehen - daher wird '
      'hier zusätzlich ein zweiter Request gepuffert, um den Multi-Zweig zu erzwingen und zu '
      'zeigen, dass der Sync-Call überhaupt im Puffer landet statt sofort einzeln versendet zu werden.)',
      () async {
        server.enqueue('POST', '/dfapp/v1/multi', (req) async {
          final items = jsonDecode(req.body) as List<dynamic>;
          final results = items.map((item) {
            return {
              'httpStatus': 200,
              'result': v1Envelope(data: {'path': item['path']}),
            };
          }).toList();
          return ScriptedResponse(jsonEncode(v1Envelope(data: results)));
        });

        final config = buildLegacyConfig(
          server,
          multiRequest: true,
          maxBufferSize: 10,
          bufferFlushDelayMs: 30,
        );
        final manager = newManager(config);

        final syncFuture = manager.getSyncClassInfo('App1');
        final objFuture = manager.getObject('OID1');

        final syncResponse = await syncFuture;
        await objFuture;

        expect(syncResponse.isOk, isTrue);
        // Beide Requests wurden über /v1/multi gebündelt - kein direkter
        // Request an einen /xSync-Pfad hat den Server erreicht.
        expect(server.requests, hasLength(1));
        expect(server.requests.single.path, equals('/dfapp/v1/multi'));
        final items = jsonDecode(server.requests.single.body) as List<dynamic>;
        expect(items, hasLength(2));
        expect(
          items.any((i) => (i['path'] as String).contains('xSync')),
          isTrue,
          reason:
              'Der Sync-Request muss als Teil des Multi-Requests auftauchen',
        );
      },
    );
  });
}
