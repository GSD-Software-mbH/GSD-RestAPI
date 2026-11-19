import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:test/test.dart';

RuntimeConfiguration _configuration() => RuntimeConfiguration(
  serverUrl: 'https://server.example:8443',
  baseUri: Uri.parse('https://server.example:8443'),
  alias: 'dfapp',
  appKey: 'KEY',
  userName: 'tester',
  appNames: const ['App1', 'App2'],
  additionalAppNames: const ['Extra'],
  device: null,
  connectionTimeout: const Duration(seconds: 5),
  responseTimeout: const Duration(seconds: 5),
  allowSslError: false,
  useBase64UrlParameter: true,
  useFolderPathEncoding: true,
  initialSessionId: '',
  multiRequest: true,
  maxBufferSize: 7,
  bufferFlushDelayMs: 250,
  perPageCount: 33,
);

void main() {
  group('GsdRuntimeSettings.fromConfiguration', () {
    test('übernimmt alle Laufzeitwerte', () {
      final settings = GsdRuntimeSettings.fromConfiguration(_configuration());

      expect(settings.appNames, ['App1', 'App2']);
      expect(settings.additionalAppNames, ['Extra']);
      expect(settings.multiRequest, isTrue);
      expect(settings.useBase64UrlParameter, isTrue);
      expect(settings.useFolderPathEncoding, isTrue);
      expect(settings.perPageCount, 33);
      expect(settings.maxBufferSize, 7);
      expect(settings.bufferFlushDelayMs, 250);
    });

    test('die Listen sind unveränderlich', () {
      final settings = GsdRuntimeSettings.fromConfiguration(_configuration());

      expect(() => settings.appNames.add('x'), throwsUnsupportedError);
      expect(
        () => settings.additionalAppNames.add('x'),
        throwsUnsupportedError,
      );
    });

    test('ist ein Abzug: spätere Änderungen wirken nicht', () {
      final configuration = _configuration();
      final settings = GsdRuntimeSettings.fromConfiguration(configuration);

      configuration
        ..appNames = ['Neu']
        ..additionalAppNames = []
        ..updateRuntimeSettings(
          multiRequest: false,
          useBase64UrlParameter: false,
          useFolderPathEncoding: false,
          perPageCount: 1,
          maxBufferSize: 1,
          bufferFlushDelayMs: 0,
        );

      expect(settings.appNames, ['App1', 'App2']);
      expect(settings.additionalAppNames, ['Extra']);
      expect(settings.multiRequest, isTrue);
      expect(settings.useBase64UrlParameter, isTrue);
      expect(settings.useFolderPathEncoding, isTrue);
      expect(settings.perPageCount, 33);
      expect(settings.maxBufferSize, 7);
      expect(settings.bufferFlushDelayMs, 250);
    });

    test('kopiert eine veränderliche Liste der Konfiguration', () {
      final appNames = ['App1'];
      final configuration = _configuration()..appNames = appNames;
      final settings = GsdRuntimeSettings.fromConfiguration(configuration);

      appNames.add('App2');

      expect(settings.appNames, ['App1']);
    });
  });
}
