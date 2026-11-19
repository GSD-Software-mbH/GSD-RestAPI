import 'package:gsd_restapi/src/client/gsd_api_config.dart';
import 'package:gsd_restapi/src/client/gsd_request_priority.dart';
import 'package:gsd_restapi/src/client/gsd_runtime_settings.dart';
import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/http/http_client_factory.dart';
import 'package:gsd_restapi/src/models/gsd_docuframe_device.dart';
import 'package:gsd_restapi/src/models/gsd_http_metric.dart';
import 'package:gsd_restapi/src/models/gsd_two_factor_token_provider.dart';
import 'package:gsd_restapi/src/raw/gsd_raw_api.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/batch/batch_coordinator.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/request/request_coordinator.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/runtime_events.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport/upload_executor.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_api.dart';
import 'package:gsd_restapi/src/v3/gsd_v3_api.dart';
import 'package:http/http.dart' as http;

/// Öffentlicher Einstiegspunkt für die neue gruppierte DOCUframe-API.
///
/// Die Fassade besitzt einen eigenen Runtime, HTTP-Client und Sessionzustand.
///
/// Ereignisse kommen als synchrone Broadcast-Streams ([sessionIdChanges],
/// [licenseErrors], [invalidCredentials], [logs], [httpMetrics]). Ohne
/// Listener geht ein Ereignis verloren: direkt nach dem Konstruktor zuhören
/// und das Abo erst nach `await dispose()` kündigen.
class GsdApiClient {
  /// Erzeugt die Fassade mit eigenem Runtime aus [configuration].
  ///
  /// [sessionId] - eine gespeicherte Session. Sie löst kein Ereignis aus;
  /// erneuern lässt sie sich erst nach `v1.authentication.setPassword`.
  ///
  /// [httpClient] - optionaler Client für alle Requests, etwa ein Wrapper um
  /// [createHttpClient]. Die Fassade übernimmt ihn und schließt ihn in
  /// [dispose]. Ohne ihn erzeugt sie einen eigenen über [createHttpClient].
  /// In beiden Fällen ist `http://` nur mit `allowSslError` erlaubt.
  ///
  /// [twoFactorTokenProvider] - wird nur bei einem 341 **innerhalb** einer
  /// Sitzung gerufen (Refresh), nie beim expliziten
  /// `v1.authentication.login`; dort wirft der 341 an den Aufrufer. Wirft der
  /// Provider, gilt das wie `''` und erscheint in [logs].
  factory GsdApiClient({
    required GsdApiConfig configuration,
    String sessionId = '',
    http.Client? httpClient,
    GsdTwoFactorTokenProvider? twoFactorTokenProvider,
  }) {
    final events = RuntimeEvents(
      twoFactorTokenProvider: twoFactorTokenProvider,
    );
    final runtimeConfiguration = RuntimeConfiguration.fromDocuframeConfig(
      configuration,
      sessionId: sessionId,
    );
    final sessionCoordinator = SessionCoordinator(
      configuration: runtimeConfiguration,
      events: events,
    );
    final uploadExecutor = UploadExecutor();
    final runtime = ApiRuntime(
      configuration: runtimeConfiguration,
      events: events,
      httpClient: httpClient,
      ownsHttpClient: true,
      sessionCoordinator: sessionCoordinator,
      requestCoordinator: RequestCoordinator(),
      batchCoordinator: BatchCoordinator(configuration: runtimeConfiguration),
      uploadExecutor: uploadExecutor,
    );

    return GsdApiClient._(
      runtime: runtime,
      sessionCoordinator: sessionCoordinator,
      uploadExecutor: uploadExecutor,
      events: events,
    );
  }

  GsdApiClient._({
    required ApiRuntime runtime,
    required SessionCoordinator sessionCoordinator,
    required UploadExecutor uploadExecutor,
    required RuntimeEvents events,
  }) : _runtime = runtime,
       _sessionCoordinator = sessionCoordinator,
       _events = events,
       v1 = GsdV1Api.internal(
         runtime,
         sessionCoordinator,
         uploadExecutor,
       ),
       v3 = GsdV3Api.internal(runtime),
       raw = GsdRawApi.internal(runtime);
  final ApiRuntime _runtime;
  final SessionCoordinator _sessionCoordinator;
  final RuntimeEvents _events;

  /// Erzeugt den plattformspezifischen Client, den die Fassade ohne
  /// `httpClient` selbst nutzt.
  ///
  /// IO: [allowSslError] lässt ungültige Zertifikate zu, [connectionTimeout]
  /// begrenzt den Verbindungsaufbau (Standard 5 Sekunden). Web: ein
  /// `BrowserClient`; beide Werte prüft dort der Browser.
  static http.Client createHttpClient({
    required bool allowSslError,
    Duration? connectionTimeout,
  }) => HttpClientFactory.create(
    connectionTimeout ?? const Duration(seconds: 5),
    allowSslError: allowSslError,
  );

  /// Native V1-Endpoint-Gruppen.
  final GsdV1Api v1;

  /// Native V3-Endpoint-Gruppen.
  final GsdV3Api v3;

  /// Kontrollierter Zugang für noch nicht nativ implementierte Endpunkte.
  final GsdRawApi raw;

  /// Jede neue Session-ID: nach Login, Refresh und `restoreSession`; `''`
  /// nach Logout und bei jedem Login-Fehler, auch doppelt. Kommt synchron
  /// an, während die Session wechselt.
  Stream<String> get sessionIdChanges => _events.sessionIdChanges;

  /// Lizenzfehler; das Ereignis kommt an, bevor die Exception beim Aufrufer
  /// ankommt.
  Stream<GsdLicenseException> get licenseErrors => _events.licenseErrors;

  /// Falsche Zugangsdaten; das Ereignis kommt an, bevor die Exception beim
  /// Aufrufer ankommt.
  Stream<GsdInvalidCredentialsException> get invalidCredentials =>
      _events.invalidCredentials;

  /// Log-Zeilen des Runtimes; Header-Werte und Bodies sind redigiert.
  Stream<String> get logs => _events.logs;

  /// Eine Metrik je abgeschlossenem HTTP-Request.
  Stream<GsdHttpMetric> get httpMetrics => _events.httpMetrics;

  /// Aktuelle Session-ID des neuen Runtime; leer vor dem Login.
  String get sessionId => _sessionCoordinator.sessionState.sessionId;

  /// Ob der neue Runtime aktuell eine nicht-leere Session besitzt.
  bool get isAuthenticated => _sessionCoordinator.hasSession;

  /// Führt [action] aus, ohne dass darin gestartete Requests gepuffert und
  /// zu einem `v1/multi`-Request gebündelt werden.
  Future<T> executeWithoutBuffering<T>(Future<T> Function() action) {
    return RuntimeExecutionContext.runWithoutBuffering(action);
  }

  /// Führt [action] mit der Priorität [priority] für alle darin gestarteten
  /// Requests aus.
  Future<T> executeWithPriority<T>(
    Future<T> Function() action,
    GsdRequestPriority priority,
  ) {
    return RuntimeExecutionContext.runWithPriority(action, priority);
  }

  /// Ob mindestens ein logischer API-Aufruf noch nicht abgeschlossen ist.
  bool get hasPendingRequests => _runtime.hasPendingRequests;

  /// Anzahl der aktuell offenen logischen API-Aufrufe.
  int get pendingRequestCount => _runtime.pendingRequestCount;

  /// Ob die API bereits freigegeben wurde.
  bool get isDisposed => _runtime.isDisposed;

  /// Aktuell für Login und Demo-Account verwendetes Gerät; austauschen
  /// lässt es sich über [setDevice].
  GsdDocuframeDevice? get device => _runtime.configuration.device;

  /// Wartet, bis alle aktuell laufenden API-Aufrufe abgeschlossen sind.
  Future<void> waitForIdle() => _runtime.waitForIdle();

  /// Liefert eine unveränderliche Momentaufnahme der zur Laufzeit
  /// veränderbaren Einstellungen.
  GsdRuntimeSettings get runtimeSettings =>
      GsdRuntimeSettings.fromConfiguration(_runtime.configuration);

  /// Ändert ausschließlich unterstützte Runtime-Werte. `null` bedeutet
  /// jeweils "unverändert"; mit einer leeren Liste lassen sich App-Namen
  /// bewusst leeren. Änderungen sind nur im Idle-Zustand erlaubt.
  void updateRuntimeSettings({
    List<String>? appNames,
    List<String>? additionalAppNames,
    bool? multiRequest,
    bool? useBase64UrlParameter,
    bool? useFolderPathEncoding,
    int? perPageCount,
    int? maxBufferSize,
    int? bufferFlushDelayMs,
  }) {
    _runtime.updateRuntimeSettings(
      appNames: appNames,
      additionalAppNames: additionalAppNames,
      multiRequest: multiRequest,
      useBase64UrlParameter: useBase64UrlParameter,
      useFolderPathEncoding: useFolderPathEncoding,
      perPageCount: perPageCount,
      maxBufferSize: maxBufferSize,
      bufferFlushDelayMs: bufferFlushDelayMs,
    );
  }

  /// Ersetzt oder entfernt (`null`) das bei Login und Demo-Account verwendete
  /// Gerät. Die Änderung ist wie alle Runtime-Änderungen nur idle erlaubt.
  void setDevice(GsdDocuframeDevice? device) {
    _runtime.setDevice(device);
  }

  /// Gibt die API frei:
  ///
  /// 1. ein laufender Session-Refresh bricht ab,
  /// 2. eine offene 2FA-Anfrage endet mit `''`,
  /// 3. Batch-Timer und HTTP-Client (auch ein übergebener) schließen,
  /// 4. danach geht kein Ereignis mehr hinaus, und die Streams schließen.
  ///
  /// Idempotent. Ein Server-Logout wird bewusst nicht automatisch ausgelöst.
  Future<void> dispose() => _runtime.dispose();
}
