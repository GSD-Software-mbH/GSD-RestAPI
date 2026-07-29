// Tests für RawApi: versionsgebundene relative Requests, Pfadvalidierung,
// Status-/Header-/Body-Durchreichung und Session-Verhalten.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/raw/raw_api.dart';
import 'package:gsd_restapi/raw/raw_api_response.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:pointycastle/export.dart' show RSAPublicKey;

import '../runtime/runtime_test_helpers.dart';
import '../runtime/session_test_support.dart';

void main() {
  ensureLegacyCryptoTestEnvironment();

  late List<http.Request> capturedRequests;
  late RSAPublicKey serverPublicKey;

  setUpAll(() async {
    serverPublicKey = (await generateServerKeyPair()).publicKey;
  });

  /// Baut eine RawApi mit MockClient; [respond] liefert die Antwort.
  (RawApi, ApiRuntime) buildRawApi({
    String alias = 'dfapp',
    String sessionId = '',
    Future<http.Response> Function(http.Request request)? respond,
  }) {
    final runtime = ApiRuntime(
      configuration: buildRuntimeConfiguration(
        alias: alias,
        sessionId: sessionId,
      ),
      httpClient: MockClient((request) async {
        capturedRequests.add(request);
        return respond != null
            ? await respond(request)
            : http.Response('{"ok":true}', 200);
      }),
    );
    return (RawApi(runtime), runtime);
  }

  setUp(() {
    capturedRequests = [];
  });

  group('RawApi Happy Path', () {
    test('v1-Request: URL enthält Alias und v1-Präfix', () async {
      final (rawApi, _) = buildRawApi();

      final response = await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/customer-specific/endpoint',
        queryParameters: {'a': 'b'},
      );

      expect(response.statusCode, equals(200));
      expect(response.body, equals('{"ok":true}'));
      expect(capturedRequests, hasLength(1));
      expect(
        capturedRequests.single.url.toString(),
        equals(
          'https://server.example:8443/dfapp/v1/customer-specific/endpoint?a=b',
        ),
      );
      expect(capturedRequests.single.method, equals('GET'));
    });

    test('v2-Request: URL enthält Alias und v2-Präfix', () async {
      final (rawApi, _) = buildRawApi();

      await rawApi.request(
        version: ApiVersion.v2,
        method: ApiHttpMethod.get,
        path: 'customer-specific/endpoint',
      );

      expect(
        capturedRequests.single.url.toString(),
        equals(
          'https://server.example:8443/dfapp/v2/customer-specific/endpoint',
        ),
      );
    });

    test('Pfad mit und ohne führenden Slash liefert dieselbe URL', () async {
      final (rawApi, _) = buildRawApi();

      await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/custom/x',
      );
      await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: 'custom/x',
      );

      expect(capturedRequests[0].url, equals(capturedRequests[1].url));
    });

    test('Body, Content-Type und eigene Header werden durchgereicht', () async {
      final (rawApi, _) = buildRawApi();

      await rawApi.request(
        version: ApiVersion.v2,
        method: ApiHttpMethod.post,
        path: '/custom/upload',
        body: '{"name":"test"}',
        contentType: 'application/xml',
        headers: {'x-custom': 'yes'},
      );

      final request = capturedRequests.single;
      expect(request.method, equals('POST'));
      expect(request.body, equals('{"name":"test"}'));
      expect(request.headers['Content-type'], contains('application/xml'));
      expect(request.headers['x-custom'], equals('yes'));
      expect(request.headers['appkey'], equals('TEST-APP-KEY'));
    });
  });

  group('RawApi Session', () {
    for (final internalStatus in const ['201', '204', '341']) {
      test('RawApi erneuert recoverbare Session bei $internalStatus und '
          'wiederholt genau einmal', () async {
        final server = MockApiServer();
        final config = buildSessionRuntimeConfiguration();
        final callbacks = internalStatus == '341'
            ? RestApiDOCUframeCallbacks(onMissing2FAToken: () async => '654321')
            : null;
        final coordinator = SessionCoordinator(
          configuration: config,
          callbacks: callbacks,
          retryDelay: const Duration(milliseconds: 1),
        );
        final runtime = ApiRuntime(
          configuration: config,
          callbacks: callbacks,
          httpClient: server.client,
          sessionCoordinator: coordinator,
        );
        final rawApi = RawApi(runtime);

        for (var i = 0; i < 2; i++) {
          server.enqueueJson(
            'GET',
            '/dfapp/v2/login/key',
            body: v1Envelope(
              data: {'key': encodePublicKeyToCleanPem(serverPublicKey)},
            ),
          );
        }
        server.enqueue(
          'POST',
          '/dfapp/v2/login',
          (_) => ScriptedResponse(
            jsonEncode(v1Envelope(data: {'sessionId': 'sess-initial'})),
          ),
        );
        server.enqueueJson(
          'GET',
          '/dfapp/v1/custom/session-aware',
          body: v1Envelope(
            internalStatus: internalStatus,
            statusMessage: 'refresh required',
          ),
        );
        server.enqueue(
          'POST',
          '/dfapp/v2/login',
          (_) => ScriptedResponse(
            jsonEncode(v1Envelope(data: {'sessionId': 'sess-refreshed'})),
          ),
        );
        server.enqueueJson(
          'GET',
          '/dfapp/v1/custom/session-aware',
          body: v1Envelope(data: {'ok': true}),
        );

        await coordinator.login('md5hash');
        final response = await rawApi.request(
          version: ApiVersion.v1,
          method: ApiHttpMethod.get,
          path: '/custom/session-aware',
        );

        expect(response.statusCode, 200);
        expect(jsonDecode(response.body)['data'], {'ok': true});
        final rawRequests = server.requests
            .where(
              (request) => request.path == '/dfapp/v1/custom/session-aware',
            )
            .toList();
        expect(rawRequests, hasLength(2));
        expect(rawRequests.first.header('sessionid'), 'sess-initial');
        expect(rawRequests.last.header('sessionid'), 'sess-refreshed');
        expect(
          server.requests
              .where((request) => request.path == '/dfapp/v2/login')
              .length,
          2,
        );
      });
    }

    test('sessionid wird gesendet, wenn eine Session vorhanden ist', () async {
      final (rawApi, _) = buildRawApi(sessionId: 'sess-raw');

      await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/custom/x',
      );

      expect(capturedRequests.single.headers['sessionid'], equals('sess-raw'));
    });

    test('sessionid fehlt, wenn keine Session vorhanden ist', () async {
      final (rawApi, _) = buildRawApi(sessionId: '');

      await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/custom/x',
      );

      expect(capturedRequests.single.headers.containsKey('sessionid'), isFalse);
    });

    test(
      'Session-Änderung im Runtime wirkt auf RawApi-Folge-Requests',
      () async {
        final (rawApi, runtime) = buildRawApi(sessionId: 'sess-1');

        await rawApi.request(
          version: ApiVersion.v1,
          method: ApiHttpMethod.get,
          path: '/custom/x',
        );
        runtime.sessionState.sessionId = 'sess-2';
        await rawApi.request(
          version: ApiVersion.v1,
          method: ApiHttpMethod.get,
          path: '/custom/x',
        );

        expect(capturedRequests[0].headers['sessionid'], equals('sess-1'));
        expect(capturedRequests[1].headers['sessionid'], equals('sess-2'));
      },
    );
  });

  group('RawApi Fehler-Durchreichung', () {
    test(
      'nicht recoverbarer interner Status bleibt eine RawApiResponse',
      () async {
        final (rawApi, _) = buildRawApi(
          respond: (_) async => http.Response(
            jsonEncode(
              v1Envelope(internalStatus: '302', statusMessage: 'wrong login'),
            ),
            200,
          ),
        );

        final response = await rawApi.request(
          version: ApiVersion.v1,
          method: ApiHttpMethod.get,
          path: '/custom/raw-error',
        );

        expect(response, isA<RawApiResponse>());
        expect(jsonDecode(response.body)['status']['internalStatus'], '302');
      },
    );

    test('HTTP-Fehlerstatus wird zurückgegeben, nicht geworfen', () async {
      final (rawApi, _) = buildRawApi(
        respond: (request) async =>
            http.Response('interner Fehler', 500, headers: {'x-err': '1'}),
      );

      final response = await rawApi.request(
        version: ApiVersion.v2,
        method: ApiHttpMethod.get,
        path: '/custom/broken',
      );

      expect(response, isA<RawApiResponse>());
      expect(response.statusCode, equals(500));
      expect(response.body, equals('interner Fehler'));
      expect(response.headers['x-err'], equals('1'));
    });

    test('Transport-Fehler (Netzwerk) wird geworfen', () async {
      final (rawApi, _) = buildRawApi(
        respond: (request) async =>
            throw http.ClientException('Verbindung abgelehnt'),
      );

      await expectLater(
        () => rawApi.request(
          version: ApiVersion.v1,
          method: ApiHttpMethod.get,
          path: '/custom/x',
        ),
        throwsA(isA<http.ClientException>()),
      );
    });

    test('Response-Header und -Bytes kommen unverändert an', () async {
      final (rawApi, _) = buildRawApi(
        respond: (request) async => http.Response.bytes(
          [1, 2, 3],
          200,
          headers: {'content-type': 'application/octet-stream'},
        ),
      );

      final response = await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/custom/binary',
      );

      expect(response.bodyBytes, equals([1, 2, 3]));
      expect(
        response.headers['content-type'],
        equals('application/octet-stream'),
      );
    });

    test('RawApiResponse-Header sind unveränderlich', () async {
      final (rawApi, _) = buildRawApi();

      final response = await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/custom/x',
      );

      expect(() => response.headers['neu'] = 'wert', throwsUnsupportedError);
    });
  });

  group('RawApi Pfadvalidierung', () {
    Future<void> expectRejected(String path, {String alias = 'dfapp'}) async {
      final (rawApi, _) = buildRawApi(alias: alias);

      await expectLater(
        () => rawApi.request(
          version: ApiVersion.v1,
          method: ApiHttpMethod.get,
          path: path,
        ),
        throwsArgumentError,
        reason: 'Pfad "$path" hätte abgelehnt werden müssen',
      );
      expect(
        capturedRequests,
        isEmpty,
        reason: 'Pfad "$path" darf keinen HTTP-Request auslösen',
      );
    }

    test('absolute URL wird abgelehnt', () async {
      await expectRejected('https://evil.example/hack');
    });

    test('protokoll-relative URL (//host) wird abgelehnt', () async {
      await expectRejected('//evil.example/hack');
    });

    test('anderes Schema wird abgelehnt', () async {
      await expectRejected('ftp://evil.example/hack');
    });

    test('Pfad-Traversierung am Anfang wird abgelehnt', () async {
      await expectRejected('../geheim');
    });

    test('Pfad-Traversierung in der Mitte wird abgelehnt', () async {
      await expectRejected('custom/../geheim');
    });

    test('eigenes v1-Präfix wird abgelehnt', () async {
      await expectRejected('v1/custom');
    });

    test('eigenes v2-Präfix mit führendem Slash wird abgelehnt', () async {
      await expectRejected('/v2/custom');
    });

    test('Versions-Präfix wird case-insensitive abgelehnt', () async {
      await expectRejected('V1/custom');
    });

    test('Backslash-Traversierung (roh) wird abgelehnt', () async {
      await expectRejected(r'..\..\geheim');
      await expectRejected(r'custom\..\geheim');
      await expectRejected(r'custom\x');
    });

    test('prozentkodierter Backslash (%5c) wird abgelehnt', () async {
      await expectRejected('..%5c..%5cgeheim');
      await expectRejected('..%5C..%5Cgeheim');
      await expectRejected('custom%5Cx');
    });

    test('eigenes Alias-Präfix wird abgelehnt', () async {
      await expectRejected('dfapp/custom');
    });

    test('Alias-Präfix wird case-insensitive abgelehnt', () async {
      await expectRejected('DFAPP/custom');
      await expectRejected('DfApp/custom');
    });

    test('leerer Pfad wird abgelehnt', () async {
      await expectRejected('');
      await expectRejected('   ');
      await expectRejected('/');
    });

    test('Query im Pfad wird abgelehnt (queryParameters verwenden)', () async {
      await expectRejected('custom/x?a=b');
    });

    test('Fragment im Pfad wird abgelehnt', () async {
      await expectRejected('custom/x#frag');
    });

    test('bei leerem Alias ist ein alias-ähnliches Segment erlaubt', () async {
      final (rawApi, _) = buildRawApi(alias: '');

      await rawApi.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/dfapp/custom',
      );

      expect(
        capturedRequests.single.url.toString(),
        equals('https://server.example:8443/v1/dfapp/custom'),
      );
    });
  });
}
