import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport/upload_executor.dart';

import 'delay_v1_objects_api.dart';

/// Test-Fixture: DocuframeV1Api mit Delays für bestimmte Operationen.
///
/// Ersetzt die `objects`-Property mit [DelayV1ObjectsApi], um Delays
/// für Action-Operationen zu simulieren.
///
/// Weitere Endpoints (appointments, authentication, etc.) laufen ohne Delays.
class DelayDocuframeV1Api extends DocuframeV1Api {
  DelayDocuframeV1Api(
    ApiRuntime runtime,
    SessionCoordinator sessionCoordinator,
    UploadExecutor uploadExecutor,
  ) : super.internal(runtime, sessionCoordinator, uploadExecutor) {
    // Ersetze objects mit Delay-Variante
    objects = DelayV1ObjectsApi(runtime);
  }
}
