library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:iso8601_duration/iso8601_duration.dart';
import 'package:gsd_restapi/raw/raw_api.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/batch/batch_coordinator.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/binary_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/legacy_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/rest_api_response_policy.dart';
import 'package:gsd_restapi/src/runtime/request/request_coordinator.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport/upload_executor.dart';

export 'package:gsd_restapi/gsd_restapi.dart'
    hide RestAPIBufferedRequest, RestApiDOCUframeManager, RestApiRequest;
export 'package:gsd_restapi/raw/api_types.dart';
export 'package:gsd_restapi/raw/raw_api.dart';
export 'package:gsd_restapi/raw/raw_api_request.dart';
export 'package:gsd_restapi/raw/raw_api_response.dart';

part 'v1/docuframe_v1_api.dart';
part 'v1/endpoints/account/v1_account_api.dart';
part 'v1/endpoints/appointments/v1_appointments_api.dart';
part 'v1/endpoints/authentication/v1_authentication_api.dart';
part 'v1/endpoints/documents/v1_documents_api.dart';
part 'v1/endpoints/folders/v1_folders_api.dart';
part 'v1/endpoints/integrations/v1_integrations_api.dart';
part 'v1/endpoints/x_sync/v1_x_sync_api.dart';
part 'v1/endpoints/mail/v1_mail_api.dart';
part 'v1/endpoints/messages/v1_messages_api.dart';
part 'v1/endpoints/models/v1_models_api.dart';
part 'v1/endpoints/objects/v1_objects_api.dart';
part 'v1/endpoints/personal/v1_personal_api.dart';
part 'v1/endpoints/service/v1_service_api.dart';
part 'v1/endpoints/settings/v1_settings_api.dart';
part 'v1/endpoints/time_recording/v1_time_recording_api.dart';
part 'management/docuframe_management_api.dart';
part 'v2/docuframe_v2_api.dart';
part 'v2/endpoints/model/v2_model_api.dart';
part 'v2/endpoints/system/v2_system_api.dart';
part 'v2/endpoints/view/v2_view_api.dart';
part 'v2/endpoints/object_data/v2_object_data_api.dart';
part 'v2/endpoints/file/v2_file_api.dart';

/// Öffentlicher Einstiegspunkt für die neue gruppierte DOCUframe-API.
///
/// Die Fassade besitzt einen eigenen Runtime, HTTP-Client und Sessionzustand.
/// Sie darf deshalb nicht innerhalb eines fachlichen Flows mit einem
/// [RestApiDOCUframeManager] gemischt werden.
class DOCUframeApi {
  final ApiRuntime _runtime;
  final SessionCoordinator _sessionCoordinator;

  /// Native V1-Endpoint-Gruppen.
  DocuframeV1Api v1;

  /// Native V2-Endpoint-Gruppen.
  DocuframeV2Api v2;

  /// Kontrollierter Zugang für noch nicht nativ implementierte Endpunkte.
  RawApi raw;

  /// Öffentliche Oberfläche für Lifecycle, Callbacks und kontrolliert
  /// veränderbare Laufzeiteinstellungen.
  final DocuframeManagementApi management;

  factory DOCUframeApi({
    required RestApiDOCUframeConfig configuration,
    RestApiDOCUframeCallbacks? callbacks,
  }) {
    final RestApiDOCUframeCallbacks effectiveCallbacks =
        callbacks ?? RestApiDOCUframeCallbacks();
    final RuntimeConfiguration runtimeConfiguration =
        RuntimeConfiguration.fromDocuframeConfig(configuration);
    final SessionCoordinator sessionCoordinator = SessionCoordinator(
      configuration: runtimeConfiguration,
      callbacks: effectiveCallbacks,
    );
    final UploadExecutor uploadExecutor = UploadExecutor();
    final ApiRuntime runtime = ApiRuntime(
      configuration: runtimeConfiguration,
      callbacks: effectiveCallbacks,
      sessionCoordinator: sessionCoordinator,
      requestCoordinator: RequestCoordinator(),
      batchCoordinator: BatchCoordinator(configuration: runtimeConfiguration),
      uploadExecutor: uploadExecutor,
    );

    return DOCUframeApi.internal(
      runtime: runtime,
      sessionCoordinator: sessionCoordinator,
      uploadExecutor: uploadExecutor,
      callbacks: effectiveCallbacks,
    );
  }

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  DOCUframeApi.internal({
    required ApiRuntime runtime,
    required SessionCoordinator sessionCoordinator,
    required UploadExecutor uploadExecutor,
    required RestApiDOCUframeCallbacks callbacks,
  }) : _runtime = runtime,
       _sessionCoordinator = sessionCoordinator,
       v1 = DocuframeV1Api.internal(
         runtime,
         sessionCoordinator,
         uploadExecutor,
       ),
       v2 = DocuframeV2Api.internal(runtime),
       raw = RawApi(runtime),
       management = DocuframeManagementApi.internal(runtime, callbacks);

  /// Aktuelle Session-ID des neuen Runtime; leer vor dem Login.
  String get sessionId => _sessionCoordinator.sessionState.sessionId;

  /// Ob der neue Runtime aktuell eine nicht-leere Session besitzt.
  bool get isAuthenticated => _sessionCoordinator.hasSession;

  Future<T> executeWithoutBuffering<T>(Future<T> Function() action) {
    return RuntimeExecutionContext.runWithoutBuffering(action);
  }

  Future<T> executeWithPriority<T>(
    Future<T> Function() action,
    RequestPriority priority,
  ) {
    return RuntimeExecutionContext.runWithPriority(action, priority);
  }

  /// Gibt Runtime, Batch-Timer und den eigenen HTTP-Client frei.
  ///
  /// Idempotent. Ein Server-Logout wird bewusst nicht automatisch ausgelöst.
  Future<void> dispose() => _runtime.dispose();
}
