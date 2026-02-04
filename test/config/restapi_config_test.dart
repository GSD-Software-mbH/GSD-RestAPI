import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

void main() {
  group('RestApiConfig Tests', () {
    late RestApiConfig config;

    setUp(() {
      // Setup wird vor jedem Test ausgeführt
    });

    tearDown(() {
      // Cleanup nach jedem Test
    });

    group('Konstruktor Tests', () {
      test('Sollte gültige Konfiguration erstellen', () {
        // Arrange & Act
        config = RestApiConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
          allowSslError: false,
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
        config = RestApiConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.allowSslError, equals(false));
      });

      test('Sollte Exception werfen bei ungültiger Server-URL', () {
        // Arrange, Act & Assert
        expect(
          () => RestApiConfig(serverUrl: 'invalid-url', alias: 'testapp'),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('Sollte Exception werfen bei Server-URL ohne Scheme', () {
        // Arrange, Act & Assert
        expect(
          () => RestApiConfig(serverUrl: 'localhost:8080', alias: 'testapp'),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    group('Validierung Tests', () {
      test('Sollte HTTP-URLs akzeptieren', () {
        // Arrange & Act
        config = RestApiConfig(
          serverUrl: 'http://localhost:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('http://localhost:8080'));
      });

      test('Sollte HTTPS-URLs akzeptieren', () {
        // Arrange & Act
        config = RestApiConfig(
          serverUrl: 'https://example.com:443',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('https://example.com:443'));
      });

      test('Sollte URLs mit IP-Adressen akzeptieren', () {
        // Arrange & Act
        config = RestApiConfig(
          serverUrl: 'https://192.168.1.1:8080',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('https://192.168.1.1:8080'));
      });

      test('Sollte URLs mit Pfaden akzeptieren', () {
        // Arrange & Act
        config = RestApiConfig(
          serverUrl: 'https://example.com:8080/api',
          alias: 'testapp',
        );

        // Assert
        expect(config.serverUrl, equals('https://example.com:8080/api'));
      });
    });

    group('Setter Tests', () {
      setUp(() {
        config = RestApiConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
          allowSslError: false,
        );
      });

      test('Sollte allowSslError setzen können', () {
        // Arrange
        expect(config.allowSslError, equals(false));

        // Act
        config.setAllowSslError(true);

        // Assert
        expect(config.allowSslError, equals(true));
      });

      test('Sollte allowSslError zurücksetzen können', () {
        // Arrange
        config.setAllowSslError(true);
        expect(config.allowSslError, equals(true));

        // Act
        config.setAllowSslError(false);

        // Assert
        expect(config.allowSslError, equals(false));
      });
    });

    group('ToString Tests', () {
      test('Sollte korrekte String-Repräsentation liefern', () {
        // Arrange
        config = RestApiConfig(
          serverUrl: 'https://localhost:8080',
          alias: 'testapp',
          allowSslError: true,
        );

        // Act
        String result = config.toString();

        // Assert
        expect(result, contains('RestApiConfig'));
        expect(result, contains('https://localhost:8080'));
        expect(result, contains('testapp'));
        expect(result, contains('true'));
      });
    });

    group('Edge Cases', () {
      test('Sollte mit minimaler URL funktionieren', () {
        // Arrange & Act
        config = RestApiConfig(serverUrl: 'http://a', alias: 'x');

        // Assert
        expect(config.serverUrl, equals('http://a'));
        expect(config.alias, equals('x'));
      });

      test('Sollte mit langen URLs funktionieren', () {
        // Arrange
        String longUrl =
            'https://very-long-domain-name-for-testing-purposes.example.com:8080/very/long/path/with/many/segments';

        // Act
        config = RestApiConfig(serverUrl: longUrl, alias: 'testapp');

        // Assert
        expect(config.serverUrl, equals(longUrl));
      });

      test('Sollte mit Unicode in Alias funktionieren', () {
        // Arrange & Act
        config = RestApiConfig(
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
        config = RestApiConfig(
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
