// Unit-Tests für RuntimeConfiguration: vollständige Momentaufnahme aus
// RestApiDOCUframeConfig und Entkopplung von späteren Mutationen der
// Legacy-Konfiguration.

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';

import 'runtime_test_helpers.dart';

void main() {
  group('RuntimeConfiguration.fromDocuframeConfig', () {
    test('kopiert alle Verbindungs- und Authentifizierungseinstellungen', () {
      final config = buildDocuframeConfig(
        serverUrl: 'https://server.example:8443',
        alias: 'dfapp',
        appKey: 'TEST-APP-KEY',
        sessionId: 'sess-1',
        useBase64UrlParameter: true,
        multiRequest: true,
      );
      config.additionalAppNames = ['Extra-App'];
      config.device = RestApiDevice('dev-1', device: 'Testgerät');
      config.debugLogs = true;
      config.allowSslError = true;
      config.setPerPageCount(73);

      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

      expect(runtimeConfig.serverUrl, equals('https://server.example:8443'));
      expect(
        runtimeConfig.baseUri,
        equals(Uri.parse('https://server.example:8443')),
      );
      expect(runtimeConfig.alias, equals('dfapp'));
      expect(runtimeConfig.appKey, equals('TEST-APP-KEY'));
      expect(runtimeConfig.userName, equals('tester'));
      expect(runtimeConfig.appNames, equals(['GSD-RestApi']));
      expect(runtimeConfig.additionalAppNames, equals(['Extra-App']));
      expect(
        runtimeConfig.getAllAppNames(),
        equals(['GSD-RestApi', 'Extra-App']),
      );
      // Das Gerät wird bewusst als Referenz übernommen (keine tiefe Kopie).
      expect(identical(runtimeConfig.device, config.device), isTrue);
      expect(runtimeConfig.connectionTimeout, equals(config.connectionTimeout));
      expect(runtimeConfig.responseTimeout, equals(config.responseTimeout));
      expect(runtimeConfig.allowSslError, isTrue);
      expect(runtimeConfig.debugLogs, isTrue);
      expect(runtimeConfig.useBase64UrlParameter, isTrue);
      expect(runtimeConfig.initialSessionId, equals('sess-1'));
      expect(runtimeConfig.multiRequest, isTrue);
      expect(runtimeConfig.perPageCount, 73);
    });

    test('spätere perPageCount-Mutation der Quelle ändert Snapshot nicht', () {
      final config = buildDocuframeConfig();
      config.setPerPageCount(25);
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

      config.setPerPageCount(99);

      expect(runtimeConfig.perPageCount, 25);
    });

    test('spätere sessionId-Mutation der Quelle ändert den Snapshot nicht', () {
      final config = buildDocuframeConfig(sessionId: 'original');
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

      config.sessionId = 'mutiert';

      expect(runtimeConfig.initialSessionId, equals('original'));
    });

    test('spätere appNames-Mutation der Quelle ändert den Snapshot nicht', () {
      final config = buildDocuframeConfig();
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

      config.appNames.add('Nachzügler');
      config.additionalAppNames.add('Noch-Einer');

      expect(runtimeConfig.appNames, equals(['GSD-RestApi']));
    });

    test(
      'spätere allowSslError-Mutation der Quelle ändert den Snapshot nicht',
      () {
        final config = buildDocuframeConfig();
        final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

        config.setAllowSslError(true);

        expect(runtimeConfig.allowSslError, isFalse);
      },
    );

    test('appNames-Snapshot ist unveränderlich', () {
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(
        buildDocuframeConfig(),
      );

      expect(
        () => runtimeConfig.appNames.add('Verboten'),
        throwsUnsupportedError,
      );
    });

    test('additionalAppNames-Snapshot ist unveränderlich und entkoppelt', () {
      final config = buildDocuframeConfig();
      config.additionalAppNames = ['Extra-App'];
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

      config.additionalAppNames.add('Nachzügler');

      expect(runtimeConfig.additionalAppNames, equals(['Extra-App']));
      expect(
        () => runtimeConfig.additionalAppNames.add('Verboten'),
        throwsUnsupportedError,
      );
    });
  });

  group('RuntimeConfiguration Basis-URI-Normalisierung', () {
    test('trailing Slash im Server-Pfad wird entfernt', () {
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(
        buildDocuframeConfig(serverUrl: 'https://server.example:8443/gateway/'),
      );

      expect(runtimeConfig.baseUri.path, equals('/gateway'));
      expect(
        runtimeConfig.serverUrl,
        equals('https://server.example:8443/gateway/'),
      );
    });

    test('Server-URL ohne trailing Slash bleibt unverändert', () {
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(
        buildDocuframeConfig(serverUrl: 'https://server.example:8443/gateway'),
      );

      expect(runtimeConfig.baseUri.path, equals('/gateway'));
    });

    test('reine Host-Root-URL mit trailing Slash wird normalisiert', () {
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(
        buildDocuframeConfig(serverUrl: 'https://server.example/'),
      );

      expect(runtimeConfig.baseUri.path, isEmpty);
    });
  });
}
