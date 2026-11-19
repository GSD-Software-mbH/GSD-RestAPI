// Gemeinsame Test-Helfer für die Unit-Tests der neuen Runtime-Komponenten
// (test/runtime/) und der GsdRawApi (test/raw/).

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:http/http.dart' as http;

/// Baut eine Legacy-Konfiguration mit Test-Defaults.
GsdApiConfig buildDocuframeConfig({
  String serverUrl = 'https://server.example:8443',
  String alias = 'dfapp',
  String appKey = 'TEST-APP-KEY',
  bool useBase64UrlParameter = false,
  bool multiRequest = false,
}) {
  return GsdApiConfig(
    appKey: appKey,
    userName: 'tester',
    appNames: ['GSD-RestApi'],
    serverUrl: serverUrl,
    alias: alias,
    useBase64UrlParameter: useBase64UrlParameter,
    multiRequest: multiRequest,
  );
}

/// Baut direkt eine unveränderliche [RuntimeConfiguration] mit
/// Test-Defaults.
RuntimeConfiguration buildRuntimeConfiguration({
  String serverUrl = 'https://server.example:8443',
  String alias = 'dfapp',
  String appKey = 'TEST-APP-KEY',
  String sessionId = '',
  bool useBase64UrlParameter = false,
  bool multiRequest = false,
}) {
  return RuntimeConfiguration.fromDocuframeConfig(
    buildDocuframeConfig(
      serverUrl: serverUrl,
      alias: alias,
      appKey: appKey,
      useBase64UrlParameter: useBase64UrlParameter,
      multiRequest: multiRequest,
    ),
    sessionId: sessionId,
  );
}

/// Delegierender HTTP-Client, der aufzeichnet, ob `close()` aufgerufen
/// wurde. Damit lässt sich prüfen, dass injizierte Clients von
/// `dispose()`/`close()` NICHT geschlossen werden.
class TrackingClient extends http.BaseClient {
  TrackingClient(this._inner);
  final http.Client _inner;

  /// Ob `close()` aufgerufen wurde.
  bool closed = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      _inner.send(request);

  @override
  void close() {
    closed = true;
    _inner.close();
  }
}
