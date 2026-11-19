// Tests für den injizierbaren http.Client der Fassade: Weitergabe der
// Requests, HTTPS-Pflicht in der Runtime und Ownership beim dispose().

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:http/http.dart' as http;
import 'package:mocktail/mocktail.dart';
import 'package:test/test.dart';

class _MockHttpClient extends Mock implements http.Client {}

class _FakeBaseRequest extends Fake implements http.BaseRequest {}

void main() {
  setUpAll(() {
    registerFallbackValue(_FakeBaseRequest());
  });

  late _MockHttpClient client;

  setUp(() {
    client = _MockHttpClient();
    when(() => client.send(any())).thenAnswer(
      (_) async => http.StreamedResponse(
        Stream.value(utf8.encode('{"ok":true}')),
        200,
      ),
    );
  });

  GsdApiClient buildApi({
    required String serverUrl,
    bool allowSslError = false,
  }) {
    return GsdApiClient(
      configuration: GsdApiConfig(
        appKey: 'TEST-APP-KEY',
        userName: 'tester',
        appNames: ['TestApp'],
        serverUrl: serverUrl,
        alias: 'dfapp',
        allowSslError: allowSslError,
      ),
      httpClient: client,
    );
  }

  Future<GsdRawApiResponse> probe(GsdApiClient api) {
    return api.raw.request(
      version: GsdApiVersion.v1,
      method: GsdHttpMethod.get,
      path: '/probe',
    );
  }

  group('GsdApiClient(httpClient:)', () {
    test('sendet ueber den injizierten Client', () async {
      final api = buildApi(serverUrl: 'https://server.example:8443');
      addTearDown(api.dispose);

      final response = await probe(api);

      expect(response.statusCode, 200);
      final request =
          verify(() => client.send(captureAny())).captured.single
              as http.BaseRequest;
      expect(
        request.url,
        Uri.parse('https://server.example:8443/dfapp/v1/probe'),
      );
    });

    test(
      'http:// ohne allowSslError wirft GsdSecurityException vor dem Client',
      () async {
        final api = buildApi(serverUrl: 'http://server.example:8080');
        addTearDown(api.dispose);

        await expectLater(probe(api), throwsA(isA<GsdSecurityException>()));
        verifyNever(() => client.send(any()));
      },
    );

    test('http:// mit allowSslError erreicht den Client', () async {
      final api = buildApi(
        serverUrl: 'http://server.example:8080',
        allowSslError: true,
      );
      addTearDown(api.dispose);

      await probe(api);

      verify(() => client.send(any())).called(1);
    });

    test('dispose() schliesst den injizierten Client genau einmal', () async {
      final api = buildApi(serverUrl: 'https://server.example:8443');

      await api.dispose();
      await api.dispose();

      verify(() => client.close()).called(1);
    });
  });

  group('GsdApiClient.createHttpClient', () {
    test('liefert einen Client, der sich schliessen laesst', () {
      final created = GsdApiClient.createHttpClient(
        allowSslError: false,
        connectionTimeout: const Duration(seconds: 1),
      );

      expect(created, isA<http.Client>());
      created.close();
    });
  });
}
