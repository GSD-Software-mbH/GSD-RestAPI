import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../legacy/legacy_test_server.dart';

/// Lädt einen Request-Body aus `test/fixtures/v3/` für die V3-Endpunkt-Tests.
String loadV3Fixture(String name) =>
    File('test/fixtures/v3/$name').readAsStringSync().trim();

/// Test-Harness für die V3-Tests.
///
/// Startet einen eigenen [LegacyTestServer] und eine [DOCUframeApi]-Fassade,
/// die auf diesen Server zeigt (mit vorkonfigurierter Session [sessionId]).
final class V3TestHarness {
  static const String sessionId = 'V3-SESSION';

  final LegacyTestServer server;
  final DOCUframeApi api;

  V3TestHarness._(this.server, this.api);

  static Future<V3TestHarness> start() async {
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
    return V3TestHarness._(server, api);
  }

  void enqueueSuccess(String method, String path) {
    server.enqueueJson(
      method,
      path,
      body: v1Envelope(data: <String, dynamic>{'ok': true}),
    );
  }

  /// Prüft, dass genau ein Request beim Server angekommen ist, dieser direkt
  /// (nicht über `v1/multi`) lief und die erwarteten Standard-Header trägt.
  ///
  /// [sessionId] erlaubt es, eine über die Fassade geänderte Session zu
  /// prüfen; Default ist die vorkonfigurierte Harness-Session.
  void expectSingleRequest({
    required String method,
    required String path,
    String body = '',
    String sessionId = V3TestHarness.sessionId,
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
