// Läuft mit `dart test -p chrome`; `flutter test` überspringt ihn.
@TestOn('browser')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:http/browser_client.dart';
import 'package:test/test.dart';

void main() {
  group('GsdApiClient im Browser', () {
    test('createHttpClient liefert einen BrowserClient', () {
      final client = GsdApiClient.createHttpClient(allowSslError: false);
      addTearDown(client.close);

      expect(client, isA<BrowserClient>());
    });

    test(
      'ein Client über das Barrel lässt sich erzeugen und freigeben',
      () async {
        final api = GsdApiClient(
          configuration: GsdApiConfig(
            appKey: 'app-key',
            userName: 'user',
            appNames: const ['GSD-RestApi'],
            serverUrl: 'https://127.0.0.1:8080',
            alias: 'dfapp',
          ),
        );

        expect(api.isAuthenticated, isFalse);
        await api.dispose();
        expect(api.isDisposed, isTrue);
      },
    );
  });
}
