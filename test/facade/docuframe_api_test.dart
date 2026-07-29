import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../legacy/legacy_test_server.dart';

void main() {
  late LegacyTestServer server;
  final List<DOCUframeApi> apis = <DOCUframeApi>[];

  setUpAll(ensureLegacyCryptoTestEnvironment);

  setUp(() async {
    HttpOverrides.global = null;
    server = LegacyTestServer();
    await server.start();
  });

  tearDown(() async {
    for (final DOCUframeApi api in apis) {
      await api.dispose();
    }
    apis.clear();
    await server.close();
  });

  test('Fassade verwendet einen unveraenderlichen Config-Snapshot', () async {
    final RestApiDOCUframeConfig configuration = buildLegacyConfig(
      server,
      sessionId: 'snapshot-session',
    );
    final DOCUframeApi api = DOCUframeApi(configuration: configuration);
    apis.add(api);

    configuration.sessionId = 'nachtraeglich-geaendert';
    configuration.appNames.add('NachtraeglicheApp');

    server.enqueueJson('GET', '/dfapp/v1/probe', body: {'snapshot': true});

    final RawApiResponse response = await api.raw.request(
      version: ApiVersion.v1,
      method: ApiHttpMethod.get,
      path: '/probe',
    );

    expect(response.statusCode, 200);
    expect(jsonDecode(response.body), {'snapshot': true});
    expect(api.sessionId, 'snapshot-session');
    expect(api.isAuthenticated, isTrue);
    expect(server.requests.single.header('sessionid'), 'snapshot-session');

    await api.dispose();
    await api.dispose();

    expect(
      server.requests.where((request) => request.path.endsWith('/logout')),
      isEmpty,
    );
  });

  test('Login, Raw-Folgeanfrage und Logout teilen denselben Zustand', () async {
    final keyPair = await generateServerKeyPair();
    final List<String> sessionChanges = <String>[];
    final RestApiDOCUframeCallbacks callbacks = RestApiDOCUframeCallbacks(
      onSessionIdChanged: (sessionId) async {
        sessionChanges.add(sessionId);
      },
    );
    final RestApiDOCUframeConfig configuration = buildLegacyConfig(
      server,
      appNames: <String>['SnapshotApp'],
    );
    final DOCUframeApi api = DOCUframeApi(
      configuration: configuration,
      callbacks: callbacks,
    );
    apis.add(api);

    configuration.appNames.add('NachtraeglicheApp');

    server.enqueueJson(
      'GET',
      '/dfapp/v2/login/key',
      body: v1Envelope(
        data: {'key': encodePublicKeyToCleanPem(keyPair.publicKey)},
      ),
    );
    server.enqueue('POST', '/dfapp/v2/login', (request) async {
      final String clearBody = await decryptV2LoginBody(
        request.body,
        keyPair.privateKey,
      );
      final Map<String, dynamic> loginBody =
          jsonDecode(clearBody) as Map<String, dynamic>;

      expect(loginBody['user'], 'tester');
      expect(loginBody['pass'], 'already-md5');
      expect(loginBody['2faToken'], '654321');
      expect(loginBody['appNames'], <String>['SnapshotApp']);

      return ScriptedResponse(
        jsonEncode(v1Envelope(data: {'sessionId': 'facade-session'})),
      );
    });

    final RestApiLoginResponse loginResponse = await api.v1.authentication
        .login('already-md5', twoFactorAuthToken: '654321');

    expect(loginResponse.sessionId, 'facade-session');
    expect(api.sessionId, 'facade-session');
    expect(api.isAuthenticated, isTrue);

    server.enqueueJson('GET', '/dfapp/v1/probe', body: {'raw': true});
    final RawApiResponse rawResponse = await api.raw.request(
      version: ApiVersion.v1,
      method: ApiHttpMethod.get,
      path: 'probe',
    );

    expect(rawResponse.statusCode, 200);
    expect(
      server.requests
          .singleWhere((request) => request.path == '/dfapp/v1/probe')
          .header('sessionid'),
      'facade-session',
    );

    server.enqueueJson('POST', '/dfapp/v1/logout', body: v1Envelope());
    final RestApiResponse logoutResponse = await api.v1.authentication.logout();

    expect(logoutResponse.isOk, isTrue);
    expect(api.sessionId, isEmpty);
    expect(api.isAuthenticated, isFalse);
    expect(sessionChanges, <String>['facade-session', '']);

    await api.dispose();
    await api.dispose();
  });

  test(
    'setPassword aktiviert Recovery für eine konfigurierte Start-Session',
    () async {
      final keyPair = await generateServerKeyPair();
      final DOCUframeApi api = DOCUframeApi(
        configuration: buildLegacyConfig(
          server,
          sessionId: 'persisted-session',
        ),
      );
      apis.add(api);
      api.v1.authentication.setPassword('persisted-md5');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
      );
      server.enqueueJson(
        'GET',
        '/dfapp/v2/login/key',
        body: v1Envelope(
          data: {'key': encodePublicKeyToCleanPem(keyPair.publicKey)},
        ),
      );
      server.enqueueJson(
        'POST',
        '/dfapp/v2/login',
        body: v1Envelope(data: {'sessionId': 'refreshed-session'}),
      );
      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: v1Envelope(data: {'ok': true}),
      );

      final RawApiResponse response = await api.raw.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/probe',
      );

      expect(response.statusCode, 200);
      expect(api.sessionId, 'refreshed-session');
      expect(server.requests.map((request) => request.path), <String>[
        '/dfapp/v1/probe',
        '/dfapp/v2/login/key',
        '/dfapp/v2/login',
        '/dfapp/v1/probe',
      ]);
      expect(server.requests.first.header('sessionid'), 'persisted-session');
      expect(server.requests.last.header('sessionid'), 'refreshed-session');
    },
  );

  test('restoreSession und öffentliche Callbacks sind gruppiert nutzbar', () {
    final DOCUframeApi api = DOCUframeApi(
      configuration: buildLegacyConfig(server),
    );
    apis.add(api);
    final List<String> sessionChanges = <String>[];
    api.management.callbacks.onSessionIdChanged = (String sessionId) async {
      sessionChanges.add(sessionId);
    };

    api.v1.authentication.restoreSession(
      'restored-session',
      md5Password: 'restored-md5',
    );

    expect(api.sessionId, 'restored-session');
    expect(api.isAuthenticated, isTrue);
    expect(sessionChanges, <String>['restored-session']);
  });

  test(
    'Management meldet Pending/Idle und schützt laufende Einstellungen',
    () async {
      final DOCUframeApi api = DOCUframeApi(
        configuration: buildLegacyConfig(server),
      );
      apis.add(api);
      final Completer<void> responseGate = Completer<void>();
      server.enqueue('GET', '/dfapp/v1/slow', (request) async {
        await responseGate.future;
        return ScriptedResponse('{"slow":true}');
      });

      final Future<RawApiResponse> request = api.raw.request(
        version: ApiVersion.v1,
        method: ApiHttpMethod.get,
        path: '/slow',
      );
      final Future<void> idle = api.management.waitForIdle();
      var idleCompleted = false;
      unawaited(idle.whenComplete(() => idleCompleted = true));

      expect(api.management.hasPendingRequests, isTrue);
      expect(api.management.pendingRequestCount, 1);
      expect(
        () => api.management.updateRuntimeSettings(perPageCount: 25),
        throwsStateError,
      );
      await Future<void>.delayed(Duration.zero);
      expect(idleCompleted, isFalse);

      responseGate.complete();
      await request;
      await idle;

      expect(api.management.hasPendingRequests, isFalse);
      expect(api.management.pendingRequestCount, 0);
      expect(idleCompleted, isTrue);

      api.management.updateRuntimeSettings(
        appNames: <String>['RuntimeApp'],
        additionalAppNames: <String>['RuntimeAddon'],
        perPageCount: 25,
        multiRequest: true,
        useBase64UrlParameter: true,
        useFolderPathEncoding: true,
      );
      final DocuframeRuntimeSettings settings = api.management.runtimeSettings;
      expect(settings.appNames, <String>['RuntimeApp']);
      expect(settings.additionalAppNames, <String>['RuntimeAddon']);
      expect(settings.perPageCount, 25);
      expect(settings.multiRequest, isTrue);
      expect(settings.useBase64UrlParameter, isTrue);
      expect(settings.useFolderPathEncoding, isTrue);
      expect(() => settings.appNames.add('mutate'), throwsUnsupportedError);
      expect(
        () => api.management.updateRuntimeSettings(perPageCount: 0),
        throwsArgumentError,
      );
      expect(
        () => api.management.updateRuntimeSettings(maxBufferSize: 0),
        throwsArgumentError,
      );
      expect(
        () => api.management.updateRuntimeSettings(bufferFlushDelayMs: -1),
        throwsArgumentError,
      );
      final RestApiDevice device = RestApiDevice('runtime-device');
      api.management.setDevice(device);
      expect(api.management.device, same(device));
      api.management.setDevice(null);
      expect(api.management.device, isNull);
    },
  );
}
