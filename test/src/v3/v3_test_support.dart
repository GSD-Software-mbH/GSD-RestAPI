import 'dart:io';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';

/// Lädt einen Request-Body aus `test/fixtures/v3/` für die V3-Endpunkt-Tests.
String loadV3Fixture(String name) =>
    File('test/fixtures/v3/$name').readAsStringSync().trim();

/// Test-Harness für die V3-Tests.
///
/// Startet einen eigenen [TestServer] und eine [GsdApiClient]-Fassade,
/// die auf diesen Server zeigt (mit vorkonfigurierter Session [sessionId]).
final class V3TestHarness {
  V3TestHarness._(this.server, this.api);
  static const String sessionId = 'V3-SESSION';

  final TestServer server;
  final GsdApiClient api;

  static Future<V3TestHarness> start() async {
    HttpOverrides.global = null;
    final server = TestServer();
    await server.start();
    final api = GsdApiClient(
      configuration: TestServer.buildTestConfig(
        server,
        multiRequest: true,
        bufferFlushDelayMs: 5,
      ),
      sessionId: sessionId,
    );
    return V3TestHarness._(server, api);
  }

  void enqueueSuccess(String method, String path) {
    enqueueData(method, path, <String, dynamic>{'ok': true});
  }

  /// Plant eine OK-Antwort mit [data] ein.
  void enqueueData(String method, String path, Object? data) {
    server.enqueueJson(method, path, body: TestServer.v1Envelope(data: data));
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
    final request = server.requests.single;
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
