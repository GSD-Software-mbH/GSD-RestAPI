import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

void main() {
  group('Config und Callbacks Integration Tests', () {
    late RestApiDOCUframeConfig config;
    late RestApiDOCUframeCallbacks callbacks;

    setUp(() {
      config = RestApiDOCUframeConfig(
        appKey: 'INTEGRATION-TEST-KEY',
        userName: 'integration-user',
        appNames: ['IntegrationTestApp'],
        serverUrl: 'https://localhost:8080',
        alias: 'integration-test',
        perPageCount: 25,
        bufferFlushDelayMs: 50,
        maxBufferSize: 5,
        multiRequest: true,
      );

      callbacks = RestApiDOCUframeCallbacks();
    });

    tearDown(() {
      callbacks.clearAllCallbacks();
    });

    group('Manager-Erstellung Tests', () {
      test('Sollte Manager mit Config und Callbacks erstellen', () {
        // Arrange & Act
        RestApiDOCUframeManager manager = RestApiDOCUframeManager(
          config: config,
          callbacks: callbacks,
        );

        // Assert
        expect(manager.config, equals(config));
        expect(manager.callbacks, equals(callbacks));
        expect(manager.loggedIn, equals(false));
        expect(manager.pendingResponses, isEmpty);
      });

      test('Sollte Manager nur mit Config erstellen (Standard-Callbacks)', () {
        // Arrange & Act
        RestApiDOCUframeManager manager = RestApiDOCUframeManager(
          config: config,
        );

        // Assert
        expect(manager.config, equals(config));
        expect(manager.callbacks, isNotNull);
        expect(manager.callbacks, isA<RestApiDOCUframeCallbacks>());
      });
    });

    group('Header-Generation Integration Tests', () {
      test('Sollte Header mit Session-ID aus Config erstellen', () {
        // Arrange
        config.sessionId = 'test-session-123';

        // Act
        Map<String, String> headers = config.getHeaders();

        // Assert
        expect(headers['sessionid'], equals('test-session-123'));
        expect(headers['appkey'], equals('INTEGRATION-TEST-KEY'));
        expect(
          headers['Content-type'],
          equals('application/json; charset=utf-8'),
        );
      });

      test('Sollte Header ohne Session-ID erstellen wenn leer', () {
        // Arrange
        config.sessionId = '';

        // Act
        Map<String, String> headers = config.getHeaders();

        // Assert
        expect(headers.containsKey('sessionid'), isFalse);
        expect(headers['appkey'], equals('INTEGRATION-TEST-KEY'));
      });
    });

    group('URI-Generation Tests', () {
      test('Sollte korrekte API-URIs generieren', () {
        // Arrange & Act
        Uri apiUri = config.getUri('/v1/objects/Vorgang');
        Uri searchUri = config.getUri(
          '/v1/search',
          params: {'query': 'test', 'page': '1'},
        );

        // Assert
        expect(
          apiUri.toString(),
          equals('https://localhost:8080/v1/objects/Vorgang'),
        );
        expect(
          searchUri.toString(),
          contains('https://localhost:8080/v1/search'),
        );
        expect(searchUri.queryParameters['query'], equals('test'));
        expect(searchUri.queryParameters['page'], equals('1'));
      });

      test('Sollte URIs mit Alias korrekt erstellen', () {
        // Arrange
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080/dfapp',
          alias: 'production',
        );

        // Act
        Uri uri = config.getUri('/v1/folders/type/Eingang');

        // Assert
        expect(uri.path, equals('/dfapp/v1/folders/type/Eingang'));
      });
    });

    group('App-Namen Integration Tests', () {
      test('Sollte Standard- und zusätzliche App-Namen kombinieren', () {
        // Arrange
        config.additionalAppNames.addAll(['ExtraApp1', 'ExtraApp2']);

        // Act
        List<String> allNames = config.getAllAppNames();

        // Assert
        expect(allNames.length, equals(3));
        expect(allNames, contains('IntegrationTestApp'));
        expect(allNames, contains('ExtraApp1'));
        expect(allNames, contains('ExtraApp2'));
      });
    });

    group('Callback Integration Tests', () {
      test('Sollte Session-Änderungen über Callbacks verfolgen', () async {
        // Arrange
        List<String> sessionHistory = [];

        callbacks.onSessionIdChanged = (String sessionId) async {
          sessionHistory.add(sessionId);
        };

        // Act
        await callbacks.triggerSessionIdChangedEvent('session-1');
        await callbacks.triggerSessionIdChangedEvent('session-2');
        await callbacks.triggerSessionIdChangedEvent('');

        // Assert
        expect(sessionHistory.length, equals(3));
        expect(sessionHistory[0], equals('session-1'));
        expect(sessionHistory[1], equals('session-2'));
        expect(sessionHistory[2], equals(''));
      });

      test('Sollte komplexe Event-Abfolge verarbeiten', () async {
        // Arrange
        List<String> eventLog = [];

        callbacks.onLogMessage = (String message) async {
          eventLog.add('LOG: $message');
        };

        callbacks.onSessionIdChanged = (String sessionId) async {
          if (sessionId.isNotEmpty) {
            eventLog.add('LOGIN: $sessionId');
          } else {
            eventLog.add('LOGOUT');
          }
        };

        callbacks.onLicenseWrong = (LicenseException e) async {
          eventLog.add('LICENSE_ERROR: ${e.message}');
        };

        // Act - Simuliere einen kompletten Anmelde-/Abmelde-Zyklus
        await callbacks.triggerLogEvent('Application started');
        await callbacks.triggerSessionIdChangedEvent('session-abc-123');
        await callbacks.triggerLogEvent('User working...');
        await callbacks.triggerLicenseWrongEvent(
          LicenseException('License expired'),
        );
        await callbacks.triggerSessionIdChangedEvent('');
        await callbacks.triggerLogEvent('Application closed');

        // Assert
        expect(eventLog.length, equals(6));
        expect(eventLog[0], equals('LOG: Application started'));
        expect(eventLog[1], equals('LOGIN: session-abc-123'));
        expect(eventLog[2], equals('LOG: User working...'));
        expect(eventLog[3], equals('LICENSE_ERROR: License expired'));
        expect(eventLog[4], equals('LOGOUT'));
        expect(eventLog[5], equals('LOG: Application closed'));
      });
    });

    group('Performance Integration Tests', () {
      test('Sollte schnelle Konfigurationsänderungen unterstützen', () {
        // Arrange
        Stopwatch stopwatch = Stopwatch()..start();

        // Act - Viele Konfigurationsänderungen
        for (int i = 1; i <= 1000; i++) {
          config.setMaxBufferSize(i);
          config.setBufferFlushDelayMs(i);
          config.setPerPageCount(i);
          config.additionalAppNames.clear();
          config.additionalAppNames.add('DynamicApp$i');
        }

        stopwatch.stop();

        // Assert
        expect(
          stopwatch.elapsedMilliseconds,
          lessThan(100),
        ); // Sollte sehr schnell sein
        expect(config.maxBufferSize, equals(1000)); // 1000
        expect(config.additionalAppNames.length, equals(1));
        expect(config.additionalAppNames.first, equals('DynamicApp1000'));
      });

      test('Sollte viele Callback-Events schnell verarbeiten', () async {
        // Arrange
        int eventCount = 0;
        callbacks.onLogMessage = (String message) async {
          eventCount++;
        };

        Stopwatch stopwatch = Stopwatch()..start();

        // Act
        List<Future<void>> futures = [];
        for (int i = 0; i < 500; i++) {
          futures.add(callbacks.triggerLogEvent('Message $i'));
        }
        await Future.wait(futures);

        stopwatch.stop();

        // Assert
        expect(eventCount, equals(500));
        expect(
          stopwatch.elapsedMilliseconds,
          lessThan(500),
        ); // Sollte unter 500ms sein
      });
    });

    group('Device Integration Tests', () {
      test('Sollte Device-Konfiguration korrekt verwenden', () {
        // Arrange
        RestApiDevice testDevice = RestApiDevice(
          'integration-device-123',
          device: 'Integration Test Device',
          systemVersion: 'Test OS 1.0',
          deviceType: RestApiDeviceType.web,
          fireBaseToken: 'integration-firebase-token',
        );

        config = RestApiDOCUframeConfig(
          appKey: 'DEVICE-TEST-KEY',
          userName: 'device-user',
          appNames: ['DeviceApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'device-test',
          device: testDevice,
        );

        // Act
        Map<String, dynamic> deviceJson = config.device!.toJson();

        // Assert
        expect(config.device, equals(testDevice));
        expect(deviceJson['deviceId'], equals('integration-device-123'));
        expect(deviceJson['device'], equals('Integration Test Device'));
        expect(deviceJson['systemVersion'], equals('Test OS 1.0'));
        expect(
          deviceJson['deviceType'].toString(),
          equals(RestApiDeviceType.web.id.toString()),
        );
      });
    });
  });
}
