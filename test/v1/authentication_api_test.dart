import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
  ensureLegacyCryptoTestEnvironment();

  late V1TestHarness harness;

  tearDown(() async {
    await harness.close();
  });

  test(
    'login behält die positionale Legacy-Signatur und refreshSession-2FA',
    () async {
      final keyPair = await generateServerKeyPair();
      var tokenRequests = 0;
      harness = await V1TestHarness.start(
        initialSessionId: '',
        callbacks: RestApiDOCUframeCallbacks(
          onMissing2FAToken: () async {
            tokenRequests++;
            return '654321';
          },
        ),
      );

      for (var index = 0; index < 2; index++) {
        harness.server.enqueueJson(
          'GET',
          '/dfapp/v2/login/key',
          body: v1Envelope(
            data: <String, dynamic>{
              'key': encodePublicKeyToCleanPem(keyPair.publicKey),
            },
          ),
        );
      }
      harness.server.enqueueJson(
        'POST',
        '/dfapp/v2/login',
        body: v1Envelope(
          internalStatus: '341',
          statusMessage: '2FA token missing',
        ),
      );
      harness.server.enqueue('POST', '/dfapp/v2/login', (request) async {
        final String clearBody = await decryptV2LoginBody(
          request.body,
          keyPair.privateKey,
        );
        expect(jsonDecode(clearBody), <String, dynamic>{
          'user': 'tester',
          'pass': 'already-md5',
          '2faToken': '654321',
          'appNames': <String>['TestApp'],
          'furtherencryption': false,
        });
        return ScriptedResponse(
          jsonEncode(
            v1Envelope(data: <String, dynamic>{'sessionId': 'LOGIN-SESSION'}),
          ),
        );
      });

      final RestApiLoginResponse response = await harness.api.v1.authentication
          .login('already-md5', refreshSession: true);

      expect(response.sessionId, 'LOGIN-SESSION');
      expect(harness.api.sessionId, 'LOGIN-SESSION');
      expect(tokenRequests, 1);
      expect(harness.server.requests.map((request) => request.path), <String>[
        '/dfapp/v2/login/key',
        '/dfapp/v2/login',
        '/dfapp/v2/login/key',
        '/dfapp/v2/login',
      ]);
    },
  );

  test(
    'checkSession bleibt unversioniert, direkt und session-authentifiziert',
    () async {
      harness = await V1TestHarness.start(multiRequest: true);
      harness.enqueueSuccess('GET', '/dfapp/_CheckSession');

      final RestApiResponse response = await harness.api.v1.authentication
          .checkSession();

      expect(response.isOk, isTrue);
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
      final keyPair = await generateServerKeyPair();
      harness = await V1TestHarness.start(initialSessionId: '');

      void enqueueLogin(String sessionId) {
        harness.server.enqueueJson(
          'GET',
          '/dfapp/v2/login/key',
          body: v1Envelope(
            data: <String, dynamic>{
              'key': encodePublicKeyToCleanPem(keyPair.publicKey),
            },
          ),
        );
        harness.server.enqueueJson(
          'POST',
          '/dfapp/v2/login',
          body: v1Envelope(data: <String, dynamic>{'sessionId': sessionId}),
        );
      }

      enqueueLogin('OLD-SESSION');
      await harness.api.v1.authentication.login('already-md5');

      harness.server.enqueueJson(
        'GET',
        '/dfapp/_CheckSession',
        body: v1Envelope(internalStatus: '201', statusMessage: 'expired'),
      );
      enqueueLogin('NEW-SESSION');
      harness.enqueueSuccess('GET', '/dfapp/_CheckSession');

      final RestApiResponse response = await harness.api.v1.authentication
          .checkSession();

      expect(response.isOk, isTrue);
      expect(harness.api.sessionId, 'NEW-SESSION');
      final List<RecordedRequest> checks = harness.server.requests
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
      body: v1Envelope(internalStatus: '342', statusMessage: 'invalid token'),
    );

    await expectLater(
      () => harness.api.v1.authentication.validate2FASecret(
        'GSD-DFApp',
        '123456',
      ),
      throwsA(isA<Invalid2FATokenException>()),
    );

    harness.expectRequest(
      harness.server.requests.single,
      method: 'POST',
      path: '/dfapp/v1/2fa/validate',
      query: const <String, String>{'app': 'GSD-DFApp'},
      body: '{"token":"123456"}',
    );
  });

  test('get2FASecret liefert den bestehenden typisierten Response', () async {
    harness = await V1TestHarness.start();
    harness.enqueueSuccess(
      'GET',
      '/dfapp/v1/2fa/secret',
      data: <String, dynamic>{
        'isActivated': true,
        'isConfirmed': false,
        '2faStatus': 3,
      },
    );

    final RestApi2FASecretResponse response = await harness
        .api
        .v1
        .authentication
        .get2FASecret('GSD-DFApp', 'tester');

    expect(response.isActivated, isTrue);
    expect(response.isConfirmed, isFalse);
    expect(response.twoFaStatus, RestApi2FAStatus.forced);
    harness.expectRequest(
      harness.server.requests.single,
      method: 'GET',
      path: '/dfapp/v1/2fa/secret',
      query: const <String, String>{'app': 'GSD-DFApp', 'username': 'tester'},
    );
  });

  final List<
    (
      String,
      String,
      String,
      Future<RestApiResponse> Function(V1AuthenticationApi),
    )
  >
  mutationCases =
      <
        (
          String,
          String,
          String,
          Future<RestApiResponse> Function(V1AuthenticationApi),
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
      harness = await V1TestHarness.start();
      harness.enqueueSuccess(method, '/dfapp/v1/2fa/secret');

      final RestApiResponse response = await call(
        harness.api.v1.authentication,
      );

      expect(response.isOk, isTrue);
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
