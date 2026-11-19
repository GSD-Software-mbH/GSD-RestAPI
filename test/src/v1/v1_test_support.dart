import 'dart:convert';
import 'dart:io';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';

final class V1TestHarness {
  V1TestHarness._(this.server, this.api);
  static const String sessionId = 'V1-SESSION';

  final TestServer server;
  final GsdApiClient api;

  static Future<V1TestHarness> start({
    String initialSessionId = sessionId,
    bool multiRequest = false,
    GsdTwoFactorTokenProvider? twoFactorTokenProvider,
  }) async {
    HttpOverrides.global = null;
    final server = TestServer();
    await server.start();
    final api = GsdApiClient(
      configuration: TestServer.buildTestConfig(
        server,
        multiRequest: multiRequest,
        bufferFlushDelayMs: 5,
      ),
      sessionId: initialSessionId,
      twoFactorTokenProvider: twoFactorTokenProvider,
    );
    return V1TestHarness._(server, api);
  }

  void enqueueSuccess(String method, String path, {dynamic data}) {
    server.enqueueJson(method, path, body: TestServer.v1Envelope(data: data));
  }

  void expectRequest(
    RecordedRequest request, {
    required String method,
    required String path,
    Map<String, String> query = const <String, String>{},
    String body = '',
    String? sessionId = V1TestHarness.sessionId,
  }) {
    expect(request.method, method);
    expect(request.path, path);
    expect(request.query, query);
    expect(request.body, body);
    expect(request.header('appkey'), 'TEST-APP-KEY');
    expect(request.header('content-type'), 'application/json; charset=utf-8');
    expect(request.header('sessionid'), sessionId);
  }

  /// Wire-Vertrag des entfernten Legacy-Managers je `<gruppe>.<fall>`, vor
  /// dessen Entfernung (0.3.x) aus den Paritätstests aufgezeichnet.
  static final Map<String, dynamic> _legacyWire =
      jsonDecode(
            File(
              'test/fixtures/v1/legacy_wire_contract.json',
            ).readAsStringSync(),
          )
          as Map<String, dynamic>;

  /// Prüft [request] gegen den aufgezeichneten Legacy-Wire-Vertrag [key].
  void expectLegacyWire(String key, RecordedRequest request) {
    final expected = _legacyWire[key] as Map<String, dynamic>?;
    expect(expected, isNotNull, reason: 'Kein Legacy-Wire-Vertrag für $key');
    expect(request.method, expected!['method'], reason: key);
    expect(request.path, expected['path'], reason: key);
    expect(request.query, expected['query'], reason: key);
    expect(request.body, expected['body'], reason: key);
    expect(request.header('sessionid'), expected['sessionid'], reason: key);
    expect(request.header('appkey'), expected['appkey'], reason: key);
  }

  Future<void> close() async {
    await api.dispose();
    await server.close();
  }
}
