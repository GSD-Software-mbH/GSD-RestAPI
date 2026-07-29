import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../legacy/legacy_test_server.dart';

String loadV2Fixture(String name) =>
    File('test/fixtures/v2/$name').readAsStringSync().trim();

final class V2TestHarness {
  static const String sessionId = 'V2-SESSION';

  final LegacyTestServer server;
  final DOCUframeApi api;

  V2TestHarness._(this.server, this.api);

  static Future<V2TestHarness> start() async {
    HttpOverrides.global = null;
    final LegacyTestServer server = LegacyTestServer();
    await server.start();
    final DOCUframeApi api = DOCUframeApi(
      configuration: buildLegacyConfig(
        server,
        sessionId: sessionId,
        multiRequest: true,
        bufferFlushDelayMs: 5,
      ),
    );
    return V2TestHarness._(server, api);
  }

  void enqueueSuccess(String method, String path) {
    server.enqueueJson(
      method,
      path,
      body: v1Envelope(data: <String, dynamic>{'ok': true}),
    );
  }

  void expectSingleRequest({
    required String method,
    required String path,
    String body = '',
  }) {
    expect(server.requests, hasLength(1));
    final RecordedRequest request = server.requests.single;
    expect(request.method, method);
    expect(request.path, path);
    expect(request.query, isEmpty);
    expect(request.body, body);
    expect(request.header('appkey'), 'TEST-APP-KEY');
    expect(request.header('sessionid'), sessionId);
    expect(request.header('content-type'), 'application/json; charset=utf-8');
    expect(
      server.requests.where((entry) => entry.path.endsWith('/v1/multi')),
      isEmpty,
    );
  }

  Future<void> close() async {
    await api.dispose();
    await server.close();
  }
}
