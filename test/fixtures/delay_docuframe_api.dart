import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/batch/batch_coordinator.dart';
import 'package:gsd_restapi/src/runtime/request/request_coordinator.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport/upload_executor.dart';

import 'delay_docuframe_v1_api.dart';

/// Test-Fixture: DOCUframeApi mit simulierten Netzwerk-Delays.
///
/// Diese Klasse erbt von [DOCUframeApi] und ersetzt die `v1`-Property
/// mit [DelayDocuframeV1Api], um Delays in V1-Operationen zu ermöglichen.
///
/// Verwendung in Tests:
/// ```dart
/// final api = DelayDocuframeApi(configuration: config);
/// final stopwatch = Stopwatch()..start();
/// await api.v1.objects.postAction('MyClass');
/// stopwatch.stop();
/// expect(stopwatch.elapsedMilliseconds, greaterThan(450));
/// ```
class DelayDocuframeApi extends DOCUframeApi {
  DelayDocuframeApi._({
    required ApiRuntime runtime,
    required SessionCoordinator sessionCoordinator,
    required UploadExecutor uploadExecutor,
    required super.callbacks,
  }) : super.internal(
         runtime: runtime,
         sessionCoordinator: sessionCoordinator,
         uploadExecutor: uploadExecutor,
       ) {
    // Ersetze v1 mit Delay-Variante
    v1 = DelayDocuframeV1Api(runtime, sessionCoordinator, uploadExecutor);
  }

  /// Erstellt einen DelayDocuframeApi mit identischer Konfiguration wie [DOCUframeApi.factory].
  factory DelayDocuframeApi({
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

    return DelayDocuframeApi._(
      runtime: runtime,
      sessionCoordinator: sessionCoordinator,
      uploadExecutor: uploadExecutor,
      callbacks: effectiveCallbacks,
    );
  }
}
