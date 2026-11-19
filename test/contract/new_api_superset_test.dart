import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

/// Compile-Zeit-Vertrag für Fähigkeiten, die über die Legacy-Endpoint-Matrix
/// hinausgehen. Paritätsarbeiten dürfen diese Oberfläche nicht entfernen.
void _newApiSurface(GsdApiClient api) {
  // Strukturierte V3-Endpunkte (existieren im Legacy-Manager nicht).
  final _ = api.v3.model.structure;
  final _ = api.v3.system.versionInfo;
  final _ = api.v3.system.appConfig;
  final _ = api.v3.system.appTheme;
  final _ = api.v3.view.load;
  final _ = api.v3.view.action;
  final _ = api.v3.objectData.getById;
  final _ = api.v3.objectData.getByQuery;
  final _ = api.v3.objectData.getByParentObject;
  final _ = api.v3.file.get;

  // Kontrollierter Ersatz für customRequest.
  final _ = api.raw.request;

  // Neue Runtime- und Management-Fähigkeiten.
  final _ = api.sessionId;
  final _ = api.isAuthenticated;
  final _ = api.executeWithoutBuffering;
  final _ = api.executeWithPriority;
  final _ = api.sessionIdChanges;
  final _ = api.licenseErrors;
  final _ = api.invalidCredentials;
  final _ = api.logs;
  final _ = api.httpMetrics;
  final _ = api.isDisposed;
  final _ = api.hasPendingRequests;
  final _ = api.pendingRequestCount;
  final _ = api.device;
  final _ = api.waitForIdle;
  final _ = api.updateRuntimeSettings;
  final _ = api.setDevice;
  final _ = api.runtimeSettings;
  final _ = api.dispose;

  // Strukturierte Legacy-Management-Parität.
  final _ = api.v1.authentication.setPassword;
  final _ = api.v1.authentication.restoreSession;
}

void main() {
  test('neue API bleibt eine Obermenge aus V2, Raw und Management', () {
    expect(_newApiSurface, isA<void Function(GsdApiClient)>());
  });
}
