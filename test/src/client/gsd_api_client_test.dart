@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';

void main() {
  late TestServer server;
  final apis = <GsdApiClient>[];

  setUp(() async {
    HttpOverrides.global = null;
    server = TestServer();
    await server.start();
  });

  tearDown(() async {
    for (final api in apis) {
      await api.dispose();
    }
    apis.clear();
    await server.close();
  });

  /// Plant `v2/login/key` und einen erfolgreichen `v2/login` mit
  /// [sessionId] ein.
  Future<void> enqueueLogin(String sessionId) async {
    final keyPair = await TestServer.generateServerKeyPair();
    server
      ..enqueueJson(
        'GET',
        '/dfapp/v2/login/key',
        body: TestServer.v1Envelope(
          data: {
            'key': TestServer.encodePublicKeyToCleanPem(keyPair.publicKey),
          },
        ),
      )
      ..enqueueJson(
        'POST',
        '/dfapp/v2/login',
        body: TestServer.v1Envelope(data: {'sessionId': sessionId}),
      );
  }

  Future<GsdRawApiResponse> probe(GsdApiClient api) => api.raw.request(
    version: GsdApiVersion.v1,
    method: GsdHttpMethod.get,
    path: '/probe',
  );

  test('Fassade verwendet einen unveraenderlichen Config-Snapshot', () async {
    final configuration = TestServer.buildTestConfig(server);
    final api = GsdApiClient(
      configuration: configuration,
      sessionId: 'snapshot-session',
    );
    apis.add(api);

    configuration.appNames.add('NachtraeglicheApp');

    server.enqueueJson('GET', '/dfapp/v1/probe', body: {'snapshot': true});

    final response = await probe(api);

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

  test('gespeicherte sessionId löst kein Ereignis aus', () async {
    final api = GsdApiClient(
      configuration: TestServer.buildTestConfig(server),
      sessionId: 'persisted-session',
    );
    apis.add(api);
    final sessionChanges = <String>[];
    api.sessionIdChanges.listen(sessionChanges.add);

    await Future<void>.delayed(Duration.zero);

    expect(api.sessionId, 'persisted-session');
    expect(sessionChanges, isEmpty);
  });

  test('Login, Raw-Folgeanfrage und Logout teilen denselben Zustand', () async {
    final keyPair = await TestServer.generateServerKeyPair();
    final configuration = TestServer.buildTestConfig(
      server,
      appNames: <String>['SnapshotApp'],
    );
    final api = GsdApiClient(configuration: configuration);
    apis.add(api);
    final sessionChanges = <String>[];
    api.sessionIdChanges.listen(sessionChanges.add);

    configuration.appNames.add('NachtraeglicheApp');

    server
      ..enqueueJson(
        'GET',
        '/dfapp/v2/login/key',
        body: TestServer.v1Envelope(
          data: {
            'key': TestServer.encodePublicKeyToCleanPem(keyPair.publicKey),
          },
        ),
      )
      ..enqueue('POST', '/dfapp/v2/login', (request) async {
        final clearBody = await TestServer.decryptV2LoginBody(
          request.body,
          keyPair.privateKey,
        );
        final loginBody = jsonDecode(clearBody) as Map<String, dynamic>;

        expect(loginBody['user'], 'tester');
        expect(loginBody['pass'], 'already-md5');
        expect(loginBody['2faToken'], '654321');
        expect(loginBody['appNames'], <String>['SnapshotApp']);

        return ScriptedResponse(
          jsonEncode(
            TestServer.v1Envelope(data: {'sessionId': 'facade-session'}),
          ),
        );
      });

    final loginResponse = await api.v1.authentication.login(
      'already-md5',
      twoFactorAuthToken: '654321',
    );

    expect(loginResponse.sessionId, 'facade-session');
    expect(api.sessionId, 'facade-session');
    expect(api.isAuthenticated, isTrue);
    expect(sessionChanges, <String>['facade-session']);

    server.enqueueJson('GET', '/dfapp/v1/probe', body: {'raw': true});
    final rawResponse = await api.raw.request(
      version: GsdApiVersion.v1,
      method: GsdHttpMethod.get,
      path: 'probe',
    );

    expect(rawResponse.statusCode, 200);
    expect(
      server.requests
          .singleWhere((request) => request.path == '/dfapp/v1/probe')
          .header('sessionid'),
      'facade-session',
    );

    server.enqueueJson(
      'POST',
      '/dfapp/v1/logout',
      body: TestServer.v1Envelope(),
    );
    await api.v1.authentication.logout();

    expect(api.sessionId, isEmpty);
    expect(api.isAuthenticated, isFalse);
    expect(sessionChanges, <String>['facade-session', '']);

    await api.dispose();
    await api.dispose();
  });

  test('Logout und sofort dispose(): der Listener erhielt ""', () async {
    final api = GsdApiClient(configuration: TestServer.buildTestConfig(server));
    final sessionChanges = <String>[];
    final subscription = api.sessionIdChanges.listen(sessionChanges.add);
    await enqueueLogin('logout-session');
    await api.v1.authentication.login('md5');

    server.enqueueJson(
      'POST',
      '/dfapp/v1/logout',
      body: TestServer.v1Envelope(),
    );
    await api.v1.authentication.logout();
    await api.dispose();
    await subscription.cancel();

    expect(sessionChanges, <String>['logout-session', '']);
  });

  test(
    'Lizenz-Ereignis kommt beim Listener an, bevor die Exception beim '
    'Aufrufer ankommt',
    () async {
      final api = GsdApiClient(
        configuration: TestServer.buildTestConfig(server),
        sessionId: 'license-session',
      );
      apis.add(api);
      final order = <String>[];
      api.licenseErrors.listen((_) => order.add('event'));
      server.enqueueJson(
        'GET',
        '/dfapp/_CheckSession',
        body: TestServer.v1Envelope(
          internalStatus: '306',
          statusMessage: 'license',
        ),
      );

      try {
        await api.v1.authentication.checkSession();
        fail('GsdLicenseException erwartet');
      } on GsdLicenseException {
        order.add('exception');
      }

      expect(order, <String>['event', 'exception']);
    },
  );

  test('341 im Refresh fragt den 2FA-Provider genau einmal', () async {
    var tokenRequests = 0;
    final api = GsdApiClient(
      configuration: TestServer.buildTestConfig(server),
      twoFactorTokenProvider: () async {
        tokenRequests++;
        return '123456';
      },
    );
    apis.add(api);
    await enqueueLogin('first-session');
    await api.v1.authentication.login('md5');

    server.enqueueJson(
      'GET',
      '/dfapp/v1/probe',
      body: TestServer.v1Envelope(
        internalStatus: '341',
        statusMessage: 'missing 2fa',
      ),
    );
    await enqueueLogin('second-session');
    server.enqueueJson(
      'GET',
      '/dfapp/v1/probe',
      body: TestServer.v1Envelope(data: {'ok': true}),
    );

    final response = await probe(api);

    expect(response.statusCode, 200);
    expect(api.sessionId, 'second-session');
    expect(tokenRequests, 1);
  });

  test(
    'wirft der 2FA-Provider, gilt das wie "" und erscheint im Log',
    () async {
      final api = GsdApiClient(
        configuration: TestServer.buildTestConfig(server),
        twoFactorTokenProvider: () => throw StateError('Dialog kaputt'),
      );
      apis.add(api);
      final logs = <String>[];
      api.logs.listen(logs.add);
      await enqueueLogin('first-session');
      await api.v1.authentication.login('md5');

      server.enqueueJson(
        'GET',
        '/dfapp/v1/probe',
        body: TestServer.v1Envelope(
          internalStatus: '341',
          statusMessage: 'missing 2fa',
        ),
      );

      await expectLater(
        probe(api),
        throwsA(isA<GsdTwoFactorTokenMissingException>()),
      );

      expect(
        logs,
        contains(
          allOf(contains('2FA-Token-Provider'), contains('Dialog kaputt')),
        ),
      );
      expect(
        server.requests.where((request) => request.path == '/dfapp/v2/login'),
        hasLength(1),
      );
    },
  );

  group('dispose()', () {
    test(
      'während eines Refresh: kein StateError, danach kein Ereignis',
      () async {
        final api = GsdApiClient(
          configuration: TestServer.buildTestConfig(server),
        );
        final events = <String>[];
        api.sessionIdChanges.listen((id) => events.add('session:$id'));
        api.logs.listen((_) => events.add('log'));
        await enqueueLogin('first-session');
        await api.v1.authentication.login('md5');

        final keyRequested = Completer<void>();
        final keyGate = Completer<void>();
        server
          ..enqueueJson(
            'GET',
            '/dfapp/v1/probe',
            body: TestServer.v1Envelope(
              internalStatus: '201',
              statusMessage: 'invalid',
            ),
          )
          ..enqueue('GET', '/dfapp/v2/login/key', (_) async {
            keyRequested.complete();
            await keyGate.future;
            return ScriptedResponse(jsonEncode(TestServer.v1Envelope()));
          });

        final failure = expectLater(
          probe(api),
          throwsA(isNot(isA<StateError>())),
        );
        await keyRequested.future;

        await api.dispose();
        final eventsAtDispose = List<String>.of(events);

        await failure;
        keyGate.complete();
        await Future<void>.delayed(const Duration(milliseconds: 10));

        expect(api.isDisposed, isTrue);
        expect(events, eventsAtDispose);
      },
    );

    test(
      'während eines offenen 2FA-Prompts: kein StateError, danach kein '
      'Ereignis',
      () async {
        final promptOpened = Completer<void>();
        final prompt = Completer<String>();
        final api = GsdApiClient(
          configuration: TestServer.buildTestConfig(server),
          twoFactorTokenProvider: () {
            promptOpened.complete();
            return prompt.future;
          },
        );
        final events = <String>[];
        api.sessionIdChanges.listen((id) => events.add('session:$id'));
        api.logs.listen((_) => events.add('log'));
        await enqueueLogin('first-session');
        await api.v1.authentication.login('md5');

        server.enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: TestServer.v1Envelope(
            internalStatus: '341',
            statusMessage: 'missing 2fa',
          ),
        );

        final failure = expectLater(
          probe(api),
          throwsA(isA<GsdTwoFactorTokenMissingException>()),
        );
        await promptOpened.future;

        await api.dispose();
        final eventsAtDispose = List<String>.of(events);

        await failure;
        prompt.complete('too-late');
        await Future<void>.delayed(Duration.zero);

        expect(events, eventsAtDispose);
        expect(
          server.requests.where((r) => r.path == '/dfapp/v2/login/key'),
          hasLength(1),
        );
      },
    );

    test('schließt die Streams', () async {
      final api = GsdApiClient(
        configuration: TestServer.buildTestConfig(server),
      );
      final done = Completer<void>();
      api.sessionIdChanges.listen(null, onDone: done.complete);

      await api.dispose();

      await expectLater(done.future, completes);
    });
  });

  test(
    'setPassword aktiviert Recovery für eine konfigurierte Start-Session',
    () async {
      final keyPair = await TestServer.generateServerKeyPair();
      final api = GsdApiClient(
        configuration: TestServer.buildTestConfig(server),
        sessionId: 'persisted-session',
      );
      apis.add(api);
      api.v1.authentication.setPassword('persisted-md5');

      server
        ..enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: TestServer.v1Envelope(
            internalStatus: '201',
            statusMessage: 'invalid',
          ),
        )
        ..enqueueJson(
          'GET',
          '/dfapp/v2/login/key',
          body: TestServer.v1Envelope(
            data: {
              'key': TestServer.encodePublicKeyToCleanPem(keyPair.publicKey),
            },
          ),
        )
        ..enqueueJson(
          'POST',
          '/dfapp/v2/login',
          body: TestServer.v1Envelope(data: {'sessionId': 'refreshed-session'}),
        )
        ..enqueueJson(
          'GET',
          '/dfapp/v1/probe',
          body: TestServer.v1Envelope(data: {'ok': true}),
        );

      final response = await probe(api);

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

  test('restoreSession meldet die Session an sessionIdChanges', () {
    final api = GsdApiClient(
      configuration: TestServer.buildTestConfig(server),
    );
    apis.add(api);
    final sessionChanges = <String>[];
    api.sessionIdChanges.listen(sessionChanges.add);

    api.v1.authentication.restoreSession(
      'restored-session',
      md5Password: 'restored-md5',
    );

    expect(api.sessionId, 'restored-session');
    expect(api.isAuthenticated, isTrue);
    expect(sessionChanges, <String>['restored-session']);
  });

  test(
    'Client meldet Pending/Idle und schützt laufende Einstellungen',
    () async {
      final api = GsdApiClient(
        configuration: TestServer.buildTestConfig(server),
      );
      apis.add(api);
      final responseGate = Completer<void>();
      server.enqueue('GET', '/dfapp/v1/slow', (request) async {
        await responseGate.future;
        return ScriptedResponse('{"slow":true}');
      });

      final request = api.raw.request(
        version: GsdApiVersion.v1,
        method: GsdHttpMethod.get,
        path: '/slow',
      );
      final idle = api.waitForIdle();
      var idleCompleted = false;
      unawaited(idle.whenComplete(() => idleCompleted = true));

      expect(api.hasPendingRequests, isTrue);
      expect(api.pendingRequestCount, 1);
      expect(
        () => api.updateRuntimeSettings(perPageCount: 25),
        throwsStateError,
      );
      await Future<void>.delayed(Duration.zero);
      expect(idleCompleted, isFalse);

      responseGate.complete();
      await request;
      await idle;

      expect(api.hasPendingRequests, isFalse);
      expect(api.pendingRequestCount, 0);
      expect(idleCompleted, isTrue);

      api.updateRuntimeSettings(
        appNames: <String>['RuntimeApp'],
        additionalAppNames: <String>['RuntimeAddon'],
        perPageCount: 25,
        multiRequest: true,
        useBase64UrlParameter: true,
        useFolderPathEncoding: true,
      );
      final settings = api.runtimeSettings;
      expect(settings.appNames, <String>['RuntimeApp']);
      expect(settings.additionalAppNames, <String>['RuntimeAddon']);
      expect(settings.perPageCount, 25);
      expect(settings.multiRequest, isTrue);
      expect(settings.useBase64UrlParameter, isTrue);
      expect(settings.useFolderPathEncoding, isTrue);
      expect(() => settings.appNames.add('mutate'), throwsUnsupportedError);
      expect(
        () => api.updateRuntimeSettings(perPageCount: 0),
        throwsArgumentError,
      );
      expect(
        () => api.updateRuntimeSettings(maxBufferSize: 0),
        throwsArgumentError,
      );
      expect(
        () => api.updateRuntimeSettings(bufferFlushDelayMs: -1),
        throwsArgumentError,
      );
      final device = GsdDocuframeDevice('runtime-device');
      api.setDevice(device);
      expect(api.device, same(device));
      api.setDevice(null);
      expect(api.device, isNull);
    },
  );
}
