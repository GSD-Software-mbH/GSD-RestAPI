import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

void main() {
  group('GsdApiConfig Tests', () {
    late GsdApiConfig config;

    setUp(() {
      // Setup wird vor jedem Test ausgeführt
    });

    tearDown(() {
      // Cleanup nach jedem Test
    });

    group('Konstruktor Tests', () {
      test('Sollte gültige Konfiguration mit Minimal-Parametern erstellen', () {
        // Arrange & Act
        config = GsdApiConfig(
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
        expect(config.device, isNull);
        expect(config.additionalAppNames, isEmpty);
      });

      test('Sollte gültige Konfiguration mit allen Parametern erstellen', () {
        // Arrange
        final testDevice = GsdDocuframeDevice(
          'test-device-123',
          device: 'Test iPhone',
          systemVersion: 'iOS 15.0',
          fireBaseToken: 'push-token-123',
          deviceType: GsdDocuframeDeviceType.ios,
          systemString: 'iPhone 13 Pro',
        );

        // Act
        config = GsdApiConfig(
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
          additionalAppNames: ['App3'],
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
        expect(config.additionalAppNames, equals(['App3']));
        expect(config.device, equals(testDevice));
      });

      test('Sollte Exception werfen bei ungültigem perPageCount', () {
        // Arrange, Act & Assert
        expect(
          () => GsdApiConfig(
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
          () => GsdApiConfig(
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
          () => GsdApiConfig(
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
          () => GsdApiConfig(
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
          () => GsdApiConfig(
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
        config = GsdApiConfig(
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

    group('ToString Tests', () {
      test('Sollte korrekte String-Repräsentation liefern', () {
        // Arrange
        config = GsdApiConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
        );

        // Act
        final result = config.toString();

        // Assert
        expect(result, contains('GsdApiConfig'));
        expect(result, contains('TEST-KEY'));
        expect(result, contains('testuser'));
        expect(result, contains('https://localhost:8080'));
        expect(result, contains('testdb'));
      });
    });

    group('Device Tests', () {
      test('Sollte Device korrekt setzen und abrufen', () {
        // Arrange
        final testDevice = GsdDocuframeDevice(
          'pc-123',
          device: 'Test PC',
          systemVersion: 'Windows 11',
          deviceType: GsdDocuframeDeviceType.web,
          systemString: 'Desktop Application',
        );

        // Act
        config = GsdApiConfig(
          appKey: 'TEST-KEY',
          userName: 'testuser',
          appNames: ['TestApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'testdb',
          device: testDevice,
        );

        // Assert
        expect(config.device, equals(testDevice));
        expect(config.device?.deviceType, equals(GsdDocuframeDeviceType.web));
        expect(config.device?.systemVersion, equals('Windows 11'));
      });
    });

    group('Edge Cases', () {
      test('Sollte mit vielen App-Namen funktionieren', () {
        // Arrange
        final manyApps = List<String>.generate(100, (index) => 'App$index');

        // Act
        config = GsdApiConfig(
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
        config = GsdApiConfig(
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
        final longKey = 'A' * 1000;
        final longUser = 'U' * 500;

        // Act
        config = GsdApiConfig(
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
        'Sollte alle Konfigurationswerte unverändert behalten',
        () {
          // Arrange & Act
          config = GsdApiConfig(
            appKey: 'INTEGRATION-KEY',
            userName: 'integration-user',
            appNames: ['IntegrationApp'],
            additionalAppNames: ['ExtraApp'],
            serverUrl: 'https://integration.example.com:9443',
            alias: 'integration-db',
            perPageCount: 125,
            bufferFlushDelayMs: 250,
            maxBufferSize: 30,
            multiRequest: true,
          );

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
          expect(config.additionalAppNames, contains('ExtraApp'));
        },
      );
    });
  });

  group('GsdApiConfig Basis-Werte', () {
    late GsdApiConfig config;

    setUp(() {
      // Setup wird vor jedem Test ausgeführt
    });

    tearDown(() {
      // Cleanup nach jedem Test
    });

    group('Konstruktor Tests', () {
      test('Sollte gültige Konfiguration erstellen', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('https://localhost:8080'));
        expect(config.alias, equals('testapp'));
        expect(config.allowSslError, equals(false));
        expect(config.connectionTimeout, equals(const Duration(seconds: 5)));
        expect(config.responseTimeout, equals(const Duration(minutes: 10)));
      });

      test('Sollte allowSslError Standard auf false setzen', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.allowSslError, equals(false));
      });

      test('Sollte Exception werfen bei ungültiger Server-URL', () {
        // Arrange, Act & Assert
        expect(
          () => _baseConfig(serverUrl: 'invalid-url', alias: 'testapp'),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('Sollte Exception werfen bei Server-URL ohne Scheme', () {
        // Arrange, Act & Assert
        expect(
          () => _baseConfig(serverUrl: 'localhost:8080', alias: 'testapp'),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    group('Validierung Tests', () {
      test('Sollte HTTP-URLs akzeptieren', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'http://localhost:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('http://localhost:8080'));
      });

      test('Sollte HTTPS-URLs akzeptieren', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'https://example.com:443',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('https://example.com:443'));
      });

      test('Sollte URLs mit IP-Adressen akzeptieren', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'https://192.168.1.1:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('https://192.168.1.1:8080'));
      });

      test('Sollte URLs mit Pfaden akzeptieren', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'https://example.com:8080/api',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('https://example.com:8080/api'));
      });
    });

    group('ToString Tests', () {
      test('Sollte korrekte String-Repräsentation liefern', () {
        // Arrange
        config = _baseConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
          allowSslError: true,
        );

        // Act
        final result = config.toString();

        // Assert
        expect(result, contains('GsdApiConfig'));
        expect(result, contains('https://localhost:8080'));
        expect(result, contains('testapp'));
        expect(result, contains('true'));
      });
    });

    group('Edge Cases', () {
      test('Sollte mit minimaler URL funktionieren', () {
        // Arrange & Act
        config = _baseConfig(serverUrl: 'http://a', alias: 'x');

        // Assert
        expect(config.serverUrl, equals('http://a'));
        expect(config.alias, equals('x'));
      });

      test('Sollte mit langen URLs funktionieren', () {
        // Arrange
        const longUrl =
            'https://very-long-domain-name-for-testing-purposes.example.com:8080/very/long/path/with/many/segments';

        // Act
        config = _baseConfig(serverUrl: longUrl, alias: 'testapp');

        // Assert
        expect(config.serverUrl, equals(longUrl));
      });

      test('Sollte mit Unicode in Alias funktionieren', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testäöü',
        );

        // Assert
        expect(config.alias, equals('testäöü'));
      });
    });

    group('Konstanten Tests', () {
      test('Sollte korrekte Timeout-Werte haben', () {
        // Arrange & Act
        config = _baseConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.connectionTimeout.inSeconds, equals(5));
        expect(config.responseTimeout.inMinutes, equals(10));
      });
    });
  });
}

/// Konfiguration nur mit den Basis-Werten; der Rest ist Pflichtfüllung.
GsdApiConfig _baseConfig({
  required String serverUrl,
  required String alias,
  bool allowSslError = false,
}) => GsdApiConfig(
  appKey: 'TEST-KEY',
  userName: 'testuser',
  appNames: const ['TestApp'],
  serverUrl: serverUrl,
  alias: alias,
  allowSslError: allowSslError,
);
