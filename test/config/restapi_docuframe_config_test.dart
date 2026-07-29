import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

void main() {
  group('RestApiDOCUframeConfig Tests', () {
    late RestApiDOCUframeConfig config;

    setUp(() {
      // Setup wird vor jedem Test ausgeführt
    });

    tearDown(() {
      // Cleanup nach jedem Test
    });

    group('Konstruktor Tests', () {
      test('Sollte gültige Konfiguration mit Minimal-Parametern erstellen', () {
        // Arrange & Act
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-APP-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );

        // Assert
        expect(config.appKey, equals('TEST-APP-KEY'));
        expect(config.userName, equals('testuser'));
        expect(config.appNames, equals(['TestApp']));
        expect(config.serverUrl, equals('https://localhost:8080'));
        expect(config.alias, equals('testdb'));
        expect(config.perPageCount, equals(50)); // Default
        expect(config.maxBufferSize, equals(10)); // Default
        expect(config.bufferFlushDelayMs, equals(100)); // Default
        expect(config.allowSslError, equals(false)); // Default
        expect(config.multiRequest, equals(false)); // Default
        expect(config.sessionId, equals(''));
        expect(config.device, isNull);
        expect(config.additionalAppNames, isEmpty);
      });

      test('Sollte gültige Konfiguration mit allen Parametern erstellen', () {
        // Arrange
        RestApiDevice testDevice = RestApiDevice(
          'test-device-123',
          device: 'Test iPhone',
          systemVersion: 'iOS 15.0',
          fireBaseToken: 'push-token-123',
          deviceType: RestApiDeviceType.ios,
          systemString: 'iPhone 13 Pro',
        );

        // Act
        config = RestApiDOCUframeConfig(
          appKey: 'FULL-TEST-KEY',
          userName: 'fulltestuser',
          appNames: ['App1', 'App2'],
          serverUrl: 'https://api.example.com:8443',
          alias: 'production',
          device: testDevice,
          perPageCount: 25,
          bufferFlushDelayMs: 200,
          maxBufferSize: 20,
          allowSslError: true,
          multiRequest: true,
          sessionId: 'initial-session-123',
        );

        // Assert
        expect(config.appKey, equals('FULL-TEST-KEY'));
        expect(config.userName, equals('fulltestuser'));
        expect(config.appNames, equals(['App1', 'App2']));
        expect(config.serverUrl, equals('https://api.example.com:8443'));
        expect(config.alias, equals('production'));
        expect(config.perPageCount, equals(25));
        expect(config.maxBufferSize, equals(20));
        expect(config.bufferFlushDelayMs, equals(200));
        expect(config.allowSslError, equals(true));
        expect(config.multiRequest, equals(true));
        expect(config.sessionId, equals('initial-session-123'));
        expect(config.device, equals(testDevice));
      });

      test('Sollte Exception werfen bei ungültigem perPageCount', () {
        // Arrange, Act & Assert
        expect(
          () => RestApiDOCUframeConfig(
            appKey: 'TEST-KEY',
            userName: 'testuser',
            appNames: ['TestApp'],
            serverUrl: 'https://localhost:8080',
            alias: 'testdb',
            perPageCount: 0,
          ),
          throwsA(isA<ArgumentError>()),
        );

        expect(
          () => RestApiDOCUframeConfig(
            appKey: 'TEST-KEY',
            userName: 'testuser',
            appNames: ['TestApp'],
            serverUrl: 'https://localhost:8080',
            alias: 'testdb',
            perPageCount: -1,
          ),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('Sollte Exception werfen bei ungültigem maxBufferSize', () {
        // Arrange, Act & Assert
        expect(
          () => RestApiDOCUframeConfig(
            appKey: 'TEST-KEY',
            userName: 'testuser',
            appNames: ['TestApp'],
            serverUrl: 'https://localhost:8080',
            alias: 'testdb',
            maxBufferSize: 0,
          ),
          throwsA(isA<ArgumentError>()),
        );

        expect(
          () => RestApiDOCUframeConfig(
            appKey: 'TEST-KEY',
            userName: 'testuser',
            appNames: ['TestApp'],
            serverUrl: 'https://localhost:8080',
            alias: 'testdb',
            maxBufferSize: -5,
          ),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('Sollte Exception werfen bei negativem bufferFlushDelayMs', () {
        // Arrange, Act & Assert
        expect(
          () => RestApiDOCUframeConfig(
            appKey: 'TEST-KEY',
            userName: 'testuser',
            appNames: ['TestApp'],
            serverUrl: 'https://localhost:8080',
            alias: 'testdb',
            bufferFlushDelayMs: -1,
          ),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('Sollte bufferFlushDelayMs von 0 akzeptieren', () {
        // Arrange & Act
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
          bufferFlushDelayMs: 0,
        );

        // Assert
        expect(config.bufferFlushDelayMs, equals(0));
      });
    });

    group('URI-Erstellung Tests', () {
      setUp(() {
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );
      });

      test('Sollte einfache URI erstellen', () {
        // Arrange & Act
        Uri uri = config.getUri('/api/test');

        // Assert
        expect(uri.scheme, equals('https'));
        expect(uri.host, equals('localhost'));
        expect(uri.port, equals(8080));
        expect(uri.path, equals('/api/test'));
        expect(uri.queryParameters, isEmpty);
      });

      test('Sollte URI mit Query-Parametern erstellen', () {
        // Arrange & Act
        Uri uri = config.getUri(
          '/api/search',
          params: {'query': 'test', 'page': '1', 'limit': '50'},
        );

        // Assert
        expect(uri.scheme, equals('https'));
        expect(uri.host, equals('localhost'));
        expect(uri.port, equals(8080));
        expect(uri.path, equals('/api/search'));
        expect(uri.queryParameters['query'], equals('test'));
        expect(uri.queryParameters['page'], equals('1'));
        expect(uri.queryParameters['limit'], equals('50'));
      });

      test('Sollte URI mit Server-Pfad korrekt kombinieren', () {
        // Arrange
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080/dfapp',
          alias: 'testdb',
        );

        // Act
        Uri uri = config.getUri('/v1/objects');

        // Assert
        expect(uri.path, equals('/dfapp/v1/objects'));
      });
    });

    group('Header-Erstellung Tests', () {
      setUp(() {
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-APP-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
          sessionId: 'test-session-123',
        );
      });

      test('Sollte Standard-Header erstellen', () {
        // Arrange & Act
        Map<String, String> headers = config.getHeaders();

        // Assert
        expect(
          headers['Content-type'],
          equals('application/json; charset=utf-8'),
        );
        expect(headers['appkey'], equals('TEST-APP-KEY'));
        expect(headers['sessionid'], equals('test-session-123'));
        expect(headers.length, equals(3));
      });

      test('Sollte Header ohne Content-Type erstellen', () {
        // Arrange & Act
        Map<String, String> headers = config.getHeaders(contentType: '');

        // Assert
        expect(headers.containsKey('Content-type'), isFalse);
        expect(headers['appkey'], equals('TEST-APP-KEY'));
        expect(headers['sessionid'], equals('test-session-123'));
        expect(headers.length, equals(2));
      });

      test('Sollte Header ohne App-Key erstellen', () {
        // Arrange & Act
        Map<String, String> headers = config.getHeaders(addAppKey: false);

        // Assert
        expect(
          headers['Content-type'],
          equals('application/json; charset=utf-8'),
        );
        expect(headers.containsKey('appkey'), isFalse);
        expect(headers['sessionid'], equals('test-session-123'));
        expect(headers.length, equals(2));
      });

      test('Sollte Header ohne Session-ID erstellen', () {
        // Arrange & Act
        Map<String, String> headers = config.getHeaders(addSessionId: false);

        // Assert
        expect(
          headers['Content-type'],
          equals('application/json; charset=utf-8'),
        );
        expect(headers['appkey'], equals('TEST-APP-KEY'));
        expect(headers.containsKey('sessionid'), isFalse);
        expect(headers.length, equals(2));
      });

      test('Sollte benutzerdefinierten Content-Type verwenden', () {
        // Arrange & Act
        Map<String, String> headers = config.getHeaders(
          contentType: 'application/xml',
        );

        // Assert
        expect(headers['Content-type'], equals('application/xml'));
      });

      test('Sollte Session-ID nicht hinzufügen wenn leer', () {
        // Arrange
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
          sessionId: '',
        );

        // Act
        Map<String, String> headers = config.getHeaders();

        // Assert
        expect(headers.containsKey('sessionid'), isFalse);
        expect(headers.length, equals(2));
      });
    });

    group('App-Namen Tests', () {
      setUp(() {
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['App1', 'App2'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );
      });

      test('Sollte Standard-App-Namen zurückgeben', () {
        // Arrange & Act
        List<String> allNames = config.getAllAppNames();

        // Assert
        expect(allNames, equals(['App1', 'App2']));
      });

      test('Sollte zusätzliche App-Namen hinzufügen', () {
        // Arrange
        config.additionalAppNames.addAll(['App3', 'App4']);

        // Act
        List<String> allNames = config.getAllAppNames();

        // Assert
        expect(allNames, equals(['App1', 'App2', 'App3', 'App4']));
      });

      test('Sollte leere zusätzliche App-Namen handhaben', () {
        // Arrange & Act
        List<String> allNames = config.getAllAppNames();

        // Assert
        expect(allNames, equals(['App1', 'App2']));
      });
    });

    group('Setter Tests', () {
      setUp(() {
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );
      });

      test('Sollte maxBufferSize setzen', () {
        // Arrange & Act
        config.setMaxBufferSize(25);

        // Assert
        expect(config.maxBufferSize, equals(25));
      });

      test('Sollte Exception werfen bei ungültigem maxBufferSize', () {
        // Arrange, Act & Assert
        expect(() => config.setMaxBufferSize(0), throwsA(isA<ArgumentError>()));

        expect(
          () => config.setMaxBufferSize(-1),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('Sollte bufferFlushDelayMs setzen', () {
        // Arrange & Act
        config.setBufferFlushDelayMs(300);

        // Assert
        expect(config.bufferFlushDelayMs, equals(300));
      });

      test('Sollte Exception werfen bei negativem bufferFlushDelayMs', () {
        // Arrange, Act & Assert
        expect(
          () => config.setBufferFlushDelayMs(-1),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('Sollte bufferFlushDelayMs von 0 akzeptieren', () {
        // Arrange & Act
        config.setBufferFlushDelayMs(0);

        // Assert
        expect(config.bufferFlushDelayMs, equals(0));
      });

      test('Sollte perPageCount setzen', () {
        // Arrange & Act
        config.setPerPageCount(100);

        // Assert
        expect(config.perPageCount, equals(100));
      });

      test('Sollte Exception werfen bei ungültigem perPageCount', () {
        // Arrange, Act & Assert
        expect(() => config.setPerPageCount(0), throwsA(isA<ArgumentError>()));

        expect(
          () => config.setPerPageCount(-10),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    group('ToString Tests', () {
      test('Sollte korrekte String-Repräsentation liefern', () {
        // Arrange
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );

        // Act
        String result = config.toString();

        // Assert
        expect(result, contains('RestApiConfig'));
        expect(result, contains('TEST-KEY'));
        expect(result, contains('testuser'));
        expect(result, contains('https://localhost:8080'));
        expect(result, contains('testdb'));
      });
    });

    group('Device Tests', () {
      test('Sollte Device korrekt setzen und abrufen', () {
        // Arrange
        RestApiDevice testDevice = RestApiDevice(
          'pc-123',
          device: 'Test PC',
          systemVersion: 'Windows 11',
          deviceType: RestApiDeviceType.web,
          systemString: 'Desktop Application',
        );

        // Act
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
          device: testDevice,
        );

        // Assert
        expect(config.device, equals(testDevice));
        expect(config.device?.deviceType, equals(RestApiDeviceType.web));
        expect(config.device?.systemVersion, equals('Windows 11'));
      });
    });

    group('Edge Cases', () {
      test('Sollte mit vielen App-Namen funktionieren', () {
        // Arrange
        List<String> manyApps = List.generate(100, (index) => 'App$index');

        // Act
        config = RestApiDOCUframeConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: manyApps,
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );

        // Assert
        expect(config.appNames.length, equals(100));
        expect(config.appNames.first, equals('App0'));
        expect(config.appNames.last, equals('App99'));
      });

      test('Sollte mit Unicode-Zeichen funktionieren', () {
        // Arrange & Act
        config = RestApiDOCUframeConfig(
          appKey: 'ТЕСТ-КЕЙ',
          userName: 'тестюзер',
          appNames: ['Приложение1', 'アプリ2'],
          serverUrl: 'https://localhost:8080',
          alias: 'тестдб',
        );

        // Assert
        expect(config.appKey, equals('ТЕСТ-КЕЙ'));
        expect(config.userName, equals('тестюзер'));
        expect(config.appNames, contains('Приложение1'));
        expect(config.appNames, contains('アプリ2'));
        expect(config.alias, equals('тестдб'));
      });

      test('Sollte mit sehr langen Strings funktionieren', () {
        // Arrange
        String longKey = 'A' * 1000;
        String longUser = 'U' * 500;

        // Act
        config = RestApiDOCUframeConfig(
          appKey: longKey,
          userName: longUser,
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );

        // Assert
        expect(config.appKey.length, equals(1000));
        expect(config.userName.length, equals(500));
      });
    });

    group('Integration Tests', () {
      test(
        'Sollte alle Konfigurationswerte nach Änderungen korrekt behalten',
        () {
          // Arrange
          config = RestApiDOCUframeConfig(
            appKey: 'INTEGRATION-KEY',
            userName: 'integration-user',
            appNames: ['IntegrationApp'],
            serverUrl: 'https://integration.example.com:9443',
            alias: 'integration-db',
            perPageCount: 75,
            bufferFlushDelayMs: 150,
            maxBufferSize: 15,
            allowSslError: true,
            multiRequest: true,
            sessionId: 'integration-session',
          );

          // Act - Multiple Setter-Aufrufe
          config.setMaxBufferSize(30);
          config.setBufferFlushDelayMs(250);
          config.setPerPageCount(125);
          config.setAllowSslError(false);
          config.additionalAppNames.add('ExtraApp');

          // Assert - Alle Werte überprüfen
          expect(config.appKey, equals('INTEGRATION-KEY'));
          expect(config.userName, equals('integration-user'));
          expect(config.appNames, equals(['IntegrationApp']));
          expect(
            config.serverUrl,
            equals('https://integration.example.com:9443'),
          );
          expect(config.alias, equals('integration-db'));
          expect(config.perPageCount, equals(125));
          expect(config.maxBufferSize, equals(30));
          expect(config.bufferFlushDelayMs, equals(250));
          expect(config.allowSslError, equals(false));
          expect(config.multiRequest, equals(true));
          expect(config.sessionId, equals('integration-session'));
          expect(config.additionalAppNames, contains('ExtraApp'));
        },
      );
    });
  });
}
