import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../legacy/legacy_test_server.dart';

final class V1TestHarness {
  static const String sessionId = 'V1-SESSION';

  final LegacyTestServer server;
  final DOCUframeApi api;

  V1TestHarness._(this.server, this.api);

  static Future<V1TestHarness> start({
    String initialSessionId = sessionId,
    bool multiRequest = false,
    RestApiDOCUframeCallbacks? callbacks,
  }) async {
    HttpOverrides.global = null;
    final LegacyTestServer server = LegacyTestServer();
    await server.start();
    final DOCUframeApi api = DOCUframeApi(
      configuration: buildLegacyConfig(
        server,
        sessionId: initialSessionId,
        multiRequest: multiRequest,
        bufferFlushDelayMs: 5,
      ),
      callbacks: callbacks,
    );
    return V1TestHarness._(server, api);
  }

  void enqueueSuccess(String method, String path, {dynamic data}) {
    server.enqueueJson(method, path, body: v1Envelope(data: data));
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

  Future<void> close() async {
    await api.dispose();
    await server.close();
  }
}
