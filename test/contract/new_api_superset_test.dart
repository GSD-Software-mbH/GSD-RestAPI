import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

/// Compile-Zeit-Vertrag für Fähigkeiten, die über die Legacy-Endpoint-Matrix
/// hinausgehen. Paritätsarbeiten dürfen diese Oberfläche nicht entfernen.
void _newApiSurface(DOCUframeApi api) {
  // Strukturierte V2-Endpunkte (existieren im Legacy-Manager nicht).
  final _ = api.v2.model.structure;
  final _ = api.v2.system.versionInfo;
  final _ = api.v2.system.appConfig;
  final _ = api.v2.system.appTheme;
  final _ = api.v2.view.load;
  final _ = api.v2.view.action;
  final _ = api.v2.objectData.getById;
  final _ = api.v2.objectData.getByQuery;
  final _ = api.v2.objectData.getByParentObject;
  final Future<RestApiFileResponse> Function(
    String, {
    int? page,
    bool? usePdf,
    int? attachItem,
    int? zipItem,
    int? maxSize,
  })
  _ = api.v2.file.get;

  // Kontrollierter Ersatz für customRequest.
  final _ = api.raw.request;

  // Neue Runtime- und Management-Fähigkeiten.
  final _ = api.sessionId;
  final _ = api.isAuthenticated;
  final _ = api.executeWithoutBuffering;
  final _ = api.executeWithPriority;
  final _ = api.management.callbacks;
  final _ = api.management.hasPendingRequests;
  final _ = api.management.pendingRequestCount;
  final _ = api.management.device;
  final _ = api.management.waitForIdle;
  final _ = api.management.updateRuntimeSettings;
  final _ = api.management.setDevice;
  final DocuframeRuntimeSettings _ = api.management.runtimeSettings;

  // Strukturierte Legacy-Management-Parität.
  final _ = api.v1.authentication.setPassword;
  final _ = api.v1.authentication.restoreSession;
}

void main() {
  test('neue API bleibt eine Obermenge aus V2, Raw und Management', () {
    expect(_newApiSurface, isA<void Function(DOCUframeApi)>());
  });
}
