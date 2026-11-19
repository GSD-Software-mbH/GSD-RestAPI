@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

void main() {
  late V1TestHarness harness;

  tearDown(() async {
    await harness.close();
  });

  test(
    'login: 341 wirft an den Aufrufer, ohne den 2FA-Provider zu fragen',
    () async {
      final keyPair = await TestServer.generateServerKeyPair();
      var tokenRequests = 0;
      harness = await V1TestHarness.start(
        initialSessionId: '',
        twoFactorTokenProvider: () async {
          tokenRequests++;
          return '654321';
        },
      );

      harness.server
        ..enqueueJson(
          'GET',
          '/dfapp/v2/login/key',
          body: TestServer.v1Envelope(
            data: <String, dynamic>{
              'key': TestServer.encodePublicKeyToCleanPem(keyPair.publicKey),
            },
          ),
        )
        ..enqueue('POST', '/dfapp/v2/login', (request) async {
          final clearBody = await TestServer.decryptV2LoginBody(
            request.body,
            keyPair.privateKey,
          );
          expect(jsonDecode(clearBody), <String, dynamic>{
            'user': 'tester',
            'pass': 'already-md5',
            'appNames': <String>['TestApp'],
            'furtherencryption': false,
          });
          return ScriptedResponse(
            jsonEncode(
              TestServer.v1Envelope(
                internalStatus: '341',
                statusMessage: '2FA token missing',
              ),
            ),
          );
        });

      await expectLater(
        harness.api.v1.authentication.login('already-md5'),
        throwsA(isA<GsdTwoFactorTokenMissingException>()),
      );

      expect(harness.api.sessionId, isEmpty);
      expect(tokenRequests, 0);
      expect(harness.server.requests.map((request) => request.path), <String>[
        '/dfapp/v2/login/key',
        '/dfapp/v2/login',
      ]);
    },
  );

  test(
    'checkSession bleibt unversioniert, direkt und session-authentifiziert',
    () async {
      harness = await V1TestHarness.start(multiRequest: true)
        ..enqueueSuccess('GET', '/dfapp/_CheckSession');

      final data = await harness.api.v1.authentication.checkSession();

      expect(data, isNull);
      expect(harness.server.requests, hasLength(1));
      harness.expectRequest(
        harness.server.requests.single,
        method: 'GET',
        path: '/dfapp/_CheckSession',
      );
      expect(
        harness.server.requests.where(
          (request) => request.path.endsWith('/v1/multi'),
        ),
        isEmpty,
      );
    },
  );

  test(
    'checkSession nutzt den gemeinsamen Session-Refresh und direkten Retry',
    () async {
      final keyPair = await TestServer.generateServerKeyPair();
      harness = await V1TestHarness.start(initialSessionId: '');

      void enqueueLogin(String sessionId) {
        harness.server.enqueueJson(
          'GET',
          '/dfapp/v2/login/key',
          body: TestServer.v1Envelope(
            data: <String, dynamic>{
              'key': TestServer.encodePublicKeyToCleanPem(keyPair.publicKey),
            },
          ),
        );
        harness.server.enqueueJson(
          'POST',
          '/dfapp/v2/login',
          body: TestServer.v1Envelope(
            data: <String, dynamic>{'sessionId': sessionId},
          ),
        );
      }

      enqueueLogin('OLD-SESSION');
      await harness.api.v1.authentication.login('already-md5');

      harness.server.enqueueJson(
        'GET',
        '/dfapp/_CheckSession',
        body: TestServer.v1Envelope(
          internalStatus: '201',
          statusMessage: 'expired',
        ),
      );
      enqueueLogin('NEW-SESSION');
      harness.enqueueSuccess('GET', '/dfapp/_CheckSession');

      await harness.api.v1.authentication.checkSession();

      expect(harness.api.sessionId, 'NEW-SESSION');
      final checks = harness.server.requests
          .where((request) => request.path == '/dfapp/_CheckSession')
          .toList(growable: false);
      expect(checks, hasLength(2));
      expect(checks.first.header('sessionid'), 'OLD-SESSION');
      expect(checks.last.header('sessionid'), 'NEW-SESSION');
    },
  );

  test('validate2FASecret bewahrt Query, Body und typisierte Fehler', () async {
    harness = await V1TestHarness.start();
    harness.server.enqueueJson(
      'POST',
      '/dfapp/v1/2fa/validate',
      body: TestServer.v1Envelope(
        internalStatus: '342',
        statusMessage: 'invalid token',
      ),
    );

    await expectLater(
      () => harness.api.v1.authentication.validate2FASecret(
        'GSD-DFApp',
        '123456',
      ),
      throwsA(isA<GsdTwoFactorTokenInvalidException>()),
    );

    harness.expectRequest(
      harness.server.requests.single,
      method: 'POST',
      path: '/dfapp/v1/2fa/validate',
      query: const <String, String>{'app': 'GSD-DFApp'},
      body: '{"token":"123456"}',
    );
  });

  test('get2FASecret liefert GsdTwoFactorSecret', () async {
    harness = await V1TestHarness.start()
      ..enqueueSuccess(
        'GET',
        '/dfapp/v1/2fa/secret',
        data: <String, dynamic>{
          'isActivated': true,
          'isConfirmed': false,
          '2faStatus': 3,
        },
      );

    final response = await harness.api.v1.authentication.get2FASecret(
      'GSD-DFApp',
      'tester',
    );

    expect(response.isActivated, isTrue);
    expect(response.isConfirmed, isFalse);
    expect(response.status, GsdTwoFactorStatus.forced);
    harness.expectRequest(
      harness.server.requests.single,
      method: 'GET',
      path: '/dfapp/v1/2fa/secret',
      query: const <String, String>{'app': 'GSD-DFApp', 'username': 'tester'},
    );
  });

  final mutationCases =
      <
        (
          String,
          String,
          String,
          Future<Object?> Function(GsdV1AuthenticationApi),
        )
      >[
        (
          'create2FASecret',
          'POST',
          '',
          (api) => api.create2FASecret('GSD-DFApp'),
        ),
        (
          'refresh2FASecret',
          'PATCH',
          '{"token":"123456"}',
          (api) => api.refresh2FASecret('GSD-DFApp', '123456'),
        ),
        (
          'delete2FASecret',
          'DELETE',
          '{"token":"123456"}',
          (api) => api.delete2FASecret('GSD-DFApp', '123456'),
        ),
      ];

  for (final (name, method, body, call) in mutationCases) {
    test('$name bewahrt Verb, app-Query und optionalen JSON-Body', () async {
      harness = await V1TestHarness.start()
        ..enqueueSuccess(
          method,
          '/dfapp/v1/2fa/secret',
          data: const {'secret': 'otpauth://totp/x'},
        );

      final data = await call(harness.api.v1.authentication);

      expect(data, const {'secret': 'otpauth://totp/x'});
      harness.expectRequest(
        harness.server.requests.single,
        method: method,
        path: '/dfapp/v1/2fa/secret',
        query: const <String, String>{'app': 'GSD-DFApp'},
        body: body,
      );
    });
  }
}
