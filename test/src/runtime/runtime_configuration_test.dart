// Unit-Tests für RuntimeConfiguration: vollständige Momentaufnahme aus
// GsdApiConfig und Entkopplung von den übergebenen Listen.

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:test/test.dart';

import 'runtime_test_helpers.dart';

void main() {
  group('RuntimeConfiguration.fromDocuframeConfig', () {
    test('kopiert alle Verbindungs- und Authentifizierungseinstellungen', () {
      final config = GsdApiConfig(
        appKey: 'TEST-APP-KEY',
        userName: 'tester',
        appNames: ['GSD-RestApi'],
        additionalAppNames: ['Extra-App'],
        serverUrl: 'https://server.example:8443',
        alias: 'dfapp',
        device: GsdDocuframeDevice('dev-1', device: 'Testgerät'),
        perPageCount: 73,
        useBase64UrlParameter: true,
        allowSslError: true,
        multiRequest: true,
      );

      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(
        config,
        sessionId: 'sess-1',
      );

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
      expect(runtimeConfig.useBase64UrlParameter, isTrue);
      expect(runtimeConfig.initialSessionId, equals('sess-1'));
      expect(runtimeConfig.multiRequest, isTrue);
      expect(runtimeConfig.perPageCount, 73);
    });

    test('ohne sessionId startet der Snapshot ohne Session', () {
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(
        buildDocuframeConfig(),
      );

      expect(runtimeConfig.initialSessionId, isEmpty);
    });

    test('spätere appNames-Mutation der Quelle ändert den Snapshot nicht', () {
      final config = buildDocuframeConfig();
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

      config.appNames.add('Nachzügler');

      expect(runtimeConfig.appNames, equals(['GSD-RestApi']));
    });

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
      final additionalAppNames = ['Extra-App'];
      final config = GsdApiConfig(
        appKey: 'TEST-APP-KEY',
        userName: 'tester',
        appNames: ['GSD-RestApi'],
        additionalAppNames: additionalAppNames,
        serverUrl: 'https://server.example:8443',
        alias: 'dfapp',
      );
      final runtimeConfig = RuntimeConfiguration.fromDocuframeConfig(config);

      additionalAppNames.add('Nachzügler');

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
