import 'dart:async';

import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';

import 'api_request.dart';
import 'batch/batch_coordinator.dart';
import 'batch/multi_request_eligibility.dart';
import 'execution/runtime_execution_context.dart';
import 'execution/runtime_execution_policy.dart';
import 'headers/header_provider.dart';
import 'policies/authentication_policy.dart';
import 'policies/binary_response_policy.dart';
import 'policies/deduplication_policy.dart';
import 'policies/request_priority.dart';
import 'policies/response_policy.dart';
import 'request/request_coordinator.dart';
import 'response/response_decryptor.dart';
import 'runtime_configuration.dart';
import 'runtime_lifecycle.dart';
import 'session/session_coordinator.dart';
import 'session/session_state.dart';
import 'telemetry/runtime_telemetry.dart';
import 'transport/http_transport.dart';
import 'transport/upload_executor.dart';
import 'transport_response.dart';
import 'uri/uri_builder.dart';

/// Koordiniert die Request-Pipeline des neuen Runtimes:
/// URI-Aufbau -> Header -> Telemetrie-Start -> Transport ->
/// Telemetrie-Ende -> Response-Dekodierung, plus automatischem
/// Session-Refresh mit genau einem Retry bei Session-Fehlern sowie
/// optionaler Deduplizierung nebenläufiger, inhaltsgleicher Requests.
///
/// Der Runtime ist bewusst kein God Object: URI-Aufbau, Header, Transport,
/// Telemetrie, Session, Deduplizierung und Buffering sind eigene
/// Komponenten (letzteres optional über einen `BatchCoordinator`).
@internal
class ApiRuntime implements RuntimeLifecycle {
  /// Eigene Basiskonfiguration des Runtimes. Nur explizit freigegebene Werte
  /// sind kontrolliert über [updateRuntimeSettings] veränderbar.
  final RuntimeConfiguration configuration;

  /// Laufender Session-Zustand; getrennt vom Session-Lifecycle des
  /// Legacy-Managers.
  final SessionState sessionState;

  final UriBuilder _uriBuilder;
  final HeaderProvider _headerProvider;
  final HttpTransport _transport;
  final RuntimeTelemetry _telemetry;
  final SessionCoordinator? _sessionCoordinator;
  final RequestCoordinator? _requestCoordinator;
  final BatchCoordinator? _batchCoordinator;
  final RestApiDOCUframeCallbacks? _callbacks;

  bool _disposed = false;
  int _activeOperationCount = 0;
  Completer<void>? _idleCompleter;

  ApiRuntime._({
    required this.configuration,
    required this.sessionState,
    required UriBuilder uriBuilder,
    required HeaderProvider headerProvider,
    required HttpTransport transport,
    required RuntimeTelemetry telemetry,
    required SessionCoordinator? sessionCoordinator,
    required RequestCoordinator? requestCoordinator,
    required BatchCoordinator? batchCoordinator,
    required RestApiDOCUframeCallbacks? callbacks,
  }) : _uriBuilder = uriBuilder,
       _headerProvider = headerProvider,
       _transport = transport,
       _telemetry = telemetry,
       _sessionCoordinator = sessionCoordinator,
       _requestCoordinator = requestCoordinator,
       _batchCoordinator = batchCoordinator,
       _callbacks = callbacks;

  /// Erstellt einen Runtime.
  ///
  /// [httpClient] - optional injizierter Client (für Tests); wird von
  /// [dispose] NICHT geschlossen. Ohne Injektion erzeugt der Runtime einen
  /// eigenen Client über die plattformspezifische Factory und schließt ihn
  /// bei [dispose].
  ///
  /// [sessionCoordinator] - optionaler Session-Koordinator. Ist er gesetzt,
  /// verwendet der Runtime dessen [SessionState] und versucht bei
  /// Session-Fehlern (`SessionInvalidException`/
  /// `TokenOrSessionIsMissingException`/`Missing2FATokenException`) genau
  /// einen Refresh mit anschließendem Retry. Ohne Koordinator propagieren
  /// diese Exceptions unverändert (altes Verhalten).
  ///
  /// [requestCoordinator] - optionaler Dedup-Koordinator. Ist er gesetzt,
  /// teilen ausschließlich Requests mit [DeduplicationPolicy.enabled] und
  /// identischem technischem Vertrag EINE Ausführung samt
  /// Session-Retry-Sequenz. Ohne Koordinator oder ohne explizite Freigabe
  /// führt jeder [execute]-Aufruf eine eigene Anfrage aus.
  ///
  /// [batchCoordinator] - optionaler Buffering-Koordinator für Requests, die
  /// `MultiRequestEligibility` als multi-fähig einstuft und deren zu
  /// [execute]-Beginn über `RuntimeExecutionContext.capture()` erfasste
  /// [RuntimeExecutionPolicy] weder [RuntimeExecutionPolicy.skipBuffering]
  /// noch [ApiRequestPriority.high] ist. Ist er gesetzt, wird er hier mit
  /// demselben Transport, URI-Builder und `SessionState` wie der Runtime
  /// verbunden (`attachTransport`) - der `SessionState` erlaubt es dem
  /// Koordinator, die Session-ID beim SENDEN eines `v1/multi`-POSTs bzw.
  /// eines Einzel-Fallback-Resends frisch zu lesen, statt die zum
  /// Enqueue-Zeitpunkt erfassten Header ungeprüft zu übernehmen. Ohne
  /// Koordinator wirft `execute()` für einen ansonsten multi-fähigen Request
  /// nur dann ein [UnsupportedError], wenn Multi-Request global aktiv ist.
  /// Bei deaktiviertem Multi-Request wird direkt gesendet.
  /// [ApiRequestPriority.high] wird NIE gepuffert und umgeht den Koordinator
  /// auch bei gesetztem [batchCoordinator] immer.
  ///
  /// [uploadExecutor] - optionaler Datei-Upload-Ausführer (PR 3d,
  /// `UploadExecutor`, letzter Runtime-Koordinator). Ist er gesetzt, wird
  /// er hier mit demselben rohen HTTP-Client (`HttpTransport.client` -
  /// KEIN zweiter Client), `UriBuilder` und `HeaderProvider` wie der
  /// Runtime verbunden (`attachTransport`) sowie anschließend mit DIESEM
  /// Runtime selbst (`attachRuntime`, analog zu `sessionCoordinator`) -
  /// darüber laufen seine Schritte 1 (Upload-ID holen) und 3
  /// (Patch-auf-Objekt). Anders als die übrigen Koordinatoren hält
  /// `ApiRuntime` selbst keine Referenz auf den `UploadExecutor`: Uploads
  /// sind keine `execute()`-Requests, sondern eine vom Aufrufer direkt am
  /// selbst konstruierten `uploadExecutor` gestartete Operation (dieser
  /// wiederum ruft in `execute()` hinein) - `_dispatch` benötigt ihn daher
  /// nie.
  factory ApiRuntime({
    required RuntimeConfiguration configuration,
    RestApiDOCUframeCallbacks? callbacks,
    http.Client? httpClient,
    SessionCoordinator? sessionCoordinator,
    RequestCoordinator? requestCoordinator,
    BatchCoordinator? batchCoordinator,
    UploadExecutor? uploadExecutor,
  }) {
    final sessionState =
        sessionCoordinator?.sessionState ??
        SessionState(configuration.initialSessionId);
    final transport = httpClient != null
        ? HttpTransport(
            client: httpClient,
            responseTimeout: configuration.responseTimeout,
          )
        : HttpTransport.withDefaultClient(configuration);
    final uriBuilder = UriBuilder(configuration);
    final headerProvider = HeaderProvider(
      configuration: configuration,
      sessionState: sessionState,
    );

    batchCoordinator?.attachTransport(
      transport: transport,
      uriBuilder: uriBuilder,
      sessionState: sessionState,
    );
    uploadExecutor?.attachTransport(client: transport.client);

    final runtime = ApiRuntime._(
      configuration: configuration,
      sessionState: sessionState,
      uriBuilder: uriBuilder,
      headerProvider: headerProvider,
      transport: transport,
      telemetry: RuntimeTelemetry(callbacks: callbacks),
      sessionCoordinator: sessionCoordinator,
      requestCoordinator: requestCoordinator,
      batchCoordinator: batchCoordinator,
      callbacks: callbacks,
    );

    sessionCoordinator?.attachRuntime(runtime);
    uploadExecutor?.attachRuntime(runtime);

    return runtime;
  }

  /// Ob der Runtime bereits freigegeben wurde.
  bool get isDisposed => _disposed;

  /// Ob mindestens ein logischer API-Aufruf noch nicht abgeschlossen ist.
  bool get hasPendingRequests => _activeOperationCount > 0;

  /// Anzahl der aktuell offenen logischen API-Aufrufe.
  int get pendingRequestCount => _activeOperationCount;

  /// Wird abgeschlossen, sobald alle aktuell laufenden API-Aufrufe beendet
  /// sind. Ist der Runtime bereits idle, wird sofort abgeschlossen.
  Future<void> waitForIdle() {
    if (!hasPendingRequests) {
      return Future<void>.value();
    }
    return (_idleCompleter ??= Completer<void>()).future;
  }

  /// Ändert die explizit freigegebenen Laufzeitwerte. Änderungen sind nur im
  /// Idle-Zustand erlaubt, damit bereits gepufferte Requests und Timer nicht
  /// unter einem wechselnden Vertrag weiterlaufen.
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
    if (_disposed) {
      throw StateError(
        'ApiRuntime wurde bereits mit dispose() freigegeben; '
        'Runtime-Einstellungen können nicht mehr geändert werden.',
      );
    }
    if (hasPendingRequests) {
      throw StateError(
        'Runtime-Einstellungen dürfen nur ohne laufende Requests geändert '
        'werden; zuerst waitForIdle() abwarten.',
      );
    }

    configuration.updateRuntimeSettings(
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

  /// Ersetzt oder entfernt das Gerät der Laufzeitkonfiguration.
  void setDevice(RestApiDevice? device) {
    if (_disposed) {
      throw StateError(
        'ApiRuntime wurde bereits mit dispose() freigegeben; '
        'das Gerät kann nicht mehr geändert werden.',
      );
    }
    if (hasPendingRequests) {
      throw StateError(
        'Das Gerät darf nur ohne laufende Requests geändert werden; '
        'zuerst waitForIdle() abwarten.',
      );
    }
    configuration.setDevice(device);
  }

  /// Führt einen Request durch die Pipeline aus und liefert das über die
  /// `ResponsePolicy` dekodierte Ergebnis.
  ///
  /// Ist ein `RequestCoordinator` angebunden UND der Request explizit für
  /// Deduplizierung freigegeben, teilen sich technisch identische Aufrufe
  /// EINE Ausführung der kompletten Session-Retry-Sequenz. Fehler propagieren
  /// an alle geteilten Aufrufer.
  ///
  /// Wirft [StateError], wenn der Runtime bereits freigegeben wurde - DIESE
  /// Prüfung erfolgt VOR jeglicher Dedup-Arbeit.
  Future<T> execute<T>(ApiRequest<T> request) {
    if (_disposed) {
      throw StateError(
        'ApiRuntime wurde bereits mit dispose() freigegeben; '
        'execute() ist nicht mehr erlaubt.',
      );
    }

    return _trackOperation(() {
      // Erfasst die aktiven Zone-Scopes GENAU EINMAL, VOR jeglicher
      // Dedup-Arbeit - siehe RuntimeExecutionPolicy-Doku. Dedup-Schlüssel,
      // Session-Retry, Dispatch und Batch-Enqueue erhalten dieselbe Instanz.
      final RuntimeExecutionPolicy policy = RuntimeExecutionContext.capture();
      final RequestCoordinator? coordinator = _requestCoordinator;
      if (coordinator == null ||
          request.deduplication == DeduplicationPolicy.disabled) {
        return _executeWithSessionRetry(request, policy);
      }

      return coordinator.deduplicate(
        _buildDedupKey(request, policy),
        () => _executeWithSessionRetry(request, policy),
      );
    });
  }

  /// Führt einen spezialisierten physischen Transport durch dieselbe
  /// Response-, Telemetrie- und Session-Recovery-Pipeline wie [execute].
  ///
  /// Der [send]-Callback wird pro Versuch neu aufgerufen. Damit können
  /// gestreamte Requests wie Multipart-Uploads bei einem Session-Retry ihren
  /// Request und Datei-Stream vollständig neu aufbauen. Diese interne Naht
  /// umgeht ausschließlich den normalen String-Body-[HttpTransport]; URI,
  /// Header, Timeout, Entschlüsselung, ResponsePolicy, Callbacks und maximal
  /// ein Session-Refresh bleiben zentral im Runtime.
  Future<T> executeExternalTransport<T>({
    required ApiRequest<T> request,
    required Future<TransportResponse> Function(
      Uri uri,
      Map<String, String> headers,
    )
    send,
  }) {
    if (_disposed) {
      throw StateError(
        'ApiRuntime wurde bereits mit dispose() freigegeben; '
        'executeExternalTransport() ist nicht mehr erlaubt.',
      );
    }
    return _trackOperation(() {
      final RuntimeExecutionPolicy policy = RuntimeExecutionContext.capture();
      return _executeWithSessionRetry(request, policy, externalSend: send);
    });
  }

  /// Narrow Naht für absolute, versionslose GET-Ziele (z.B.
  /// `checkServiceWithUri`): sendet EXAKT die übergebene [uri] OHNE
  /// Standard-Header (kein `appkey`, keine `sessionid`, kein
  /// `Content-type`), honoriert dabei ausschließlich den aufrufer-seitig
  /// übergebenen [timeout] (NICHT `configuration.responseTimeout`) und wirft
  /// bei Überschreitung [TimeoutException].
  ///
  /// Diese Naht ist bewusst unabhängig von jeglicher Buffering-/
  /// Priority-Policy: absolute Ziele sind nie Multi-Request-fähig (siehe
  /// `MultiRequestEligibility`) und werden daher immer direkt gesendet - ein
  /// Zone-Scope hat hier keine Wirkung.
  Future<T> executeAbsoluteGet<T>({
    required Uri uri,
    required Duration timeout,
    required ResponsePolicy<T> responsePolicy,
    required String operationId,
  }) {
    if (_disposed) {
      throw StateError(
        'ApiRuntime wurde bereits mit dispose() freigegeben; '
        'executeAbsoluteGet() ist nicht mehr erlaubt.',
      );
    }

    return _trackOperation(() async {
      final ApiRequestTelemetry tracker = _telemetry.requestStarted(
        operationId: operationId,
        method: ApiHttpMethod.get,
        uri: uri,
        headers: const {},
      );

      final TransportResponse response;
      try {
        response = await _sendAbsolute(uri).timeout(timeout);
      } catch (error) {
        tracker.failed(error);
        rethrow;
      }

      final T result;
      try {
        final TransportResponse normalizedResponse = await _normalizeResponse(
          response,
          responsePolicy,
        );
        result = await responsePolicy.decode(normalizedResponse);
      } catch (error, stackTrace) {
        tracker.failed(error, response: response);
        Error.throwWithStackTrace(error, stackTrace);
      }

      tracker.succeeded(response);
      return result;
    });
  }

  Future<T> _trackOperation<T>(Future<T> Function() action) async {
    _activeOperationCount++;
    try {
      return await action();
    } finally {
      _activeOperationCount--;
      if (_activeOperationCount == 0) {
        final Completer<void>? completer = _idleCompleter;
        _idleCompleter = null;
        if (completer != null && !completer.isCompleted) {
          completer.complete();
        }
      }
    }
  }

  /// Sendet ein absolutes GET direkt über den rohen HTTP-Client des
  /// Transports (NICHT über `HttpTransport.send`, das den KONFIGURIERTEN
  /// `responseTimeout` fest anwenden würde) - so honoriert
  /// [executeAbsoluteGet] ausschließlich den aufrufer-seitigen Timeout.
  Future<TransportResponse> _sendAbsolute(Uri uri) async {
    final http.Request request = http.Request('GET', uri);
    final http.StreamedResponse streamed = await _transport.client.send(
      request,
    );
    final http.Response response = await http.Response.fromStream(streamed);

    return TransportResponse(
      statusCode: response.statusCode,
      headers: response.headers,
      bodyBytes: response.bodyBytes,
      body: response.body,
    );
  }

  /// Entschlüsselt die Antwort, AUSSER [responsePolicy] ist eine
  /// [BinaryResponsePolicy]: Datei-/Preview-Bytes müssen exakt bleiben und
  /// dürfen nie fälschlich als verschlüsseltes Envelope interpretiert werden
  /// (siehe [BinaryResponsePolicy]-Doku).
  Future<TransportResponse> _normalizeResponse<T>(
    TransportResponse response,
    ResponsePolicy<T> responsePolicy,
  ) {
    if (responsePolicy is BinaryResponsePolicy) {
      return Future<TransportResponse>.value(response);
    }
    return const ResponseDecryptor().decryptIfNeeded(response);
  }

  /// Baut einen strukturierten Dedup-Schlüssel aus dem vollständigen stabilen
  /// Request-Vertrag PLUS der zu diesem Zeitpunkt bereits erfassten
  /// [RuntimeExecutionPolicy] (siehe [execute]) - so unterscheiden
  /// unterschiedliche effektive Zone-Scopes (z.B. `low` vs. `high`) trotz
  /// sonst identischem Request auch den Dedup-Schlüssel. Nur die konkrete
  /// Session-ID wird ausgeschlossen, damit ein Session-Refresh die
  /// gemeinsame Ausführung nicht fragmentiert.
  _RequestDedupKey _buildDedupKey<T>(
    ApiRequest<T> request,
    RuntimeExecutionPolicy policy,
  ) {
    final Uri uri = _buildRequestUri(request);
    final Map<String, String> headers = _headerProvider.build(
      authentication: request.authentication,
      contentType: request.contentType,
      additionalHeaders: request.additionalHeaders,
    )..removeWhere((name, _) => name.toLowerCase() == 'sessionid');

    // Nur die vom SessionState dynamisch erzeugte Session-ID wird ignoriert.
    // Setzt ein Endpoint `sessionid` bewusst als Zusatzheader, gehört dieser
    // Wert zum technischen Request-Vertrag und muss den Schlüssel trennen.
    for (final MapEntry<String, String> header
        in request.additionalHeaders?.entries ??
            const <MapEntry<String, String>>[]) {
      if (header.key.toLowerCase() == 'sessionid') {
        headers[header.key] = header.value;
      }
    }

    final List<MapEntry<String, String>> stableHeaders =
        headers.entries.toList()..sort((a, b) {
          final int byName = a.key.toLowerCase().compareTo(b.key.toLowerCase());
          return byName != 0 ? byName : a.key.compareTo(b.key);
        });

    return _RequestDedupKey(
      method: request.method,
      uri: uri,
      body: request.body,
      headers: stableHeaders
          .map((entry) => '${entry.key.toLowerCase()}:${entry.value}')
          .toList(growable: false),
      authentication: request.authentication,
      skipBuffering: policy.skipBuffering,
      priority: policy.priority,
      responsePolicy: request.responsePolicy,
      resultType: T,
      operationId: request.operationId,
    );
  }

  /// Führt einen Request durch die Pipeline aus (URI, Header, Transport,
  /// Dekodierung) inklusive automatischem Session-Refresh.
  ///
  /// Für Requests mit [AuthenticationPolicy.session] und angebundenem
  /// `SessionCoordinator` wird bei Session-Fehlern GENAU EIN
  /// Refresh-plus-Retry versucht (kein Loop):
  /// - `SessionInvalidException`/`TokenOrSessionIsMissingException`:
  ///   Session-Refresh, dann Retry mit neuer Session-ID.
  /// - `Missing2FATokenException`: 2FA-Token über
  ///   `onMissing2FAToken` anfordern; leeres Token -> Exception
  ///   propagiert, sonst Refresh mit Token und Retry.
  ///
  /// Transport-Fehler (Timeout, Netzwerk) werden propagiert; HTTP-Status
  /// bewertet erst die `ResponsePolicy`. Wird ausschließlich über [execute]
  /// aufgerufen (direkt ohne Koordinator, oder als geteilte Aktion des
  /// `RequestCoordinator`).
  Future<T> _executeWithSessionRetry<T>(
    ApiRequest<T> request,
    RuntimeExecutionPolicy policy, {
    Future<TransportResponse> Function(Uri uri, Map<String, String> headers)?
    externalSend,
  }) async {
    final SessionCoordinator? coordinator = _sessionCoordinator;
    final String attemptedSessionId = sessionState.sessionId;
    final bool canRefresh =
        coordinator != null &&
        coordinator.canRefreshSession &&
        request.authentication == AuthenticationPolicy.session;

    try {
      return await _executeOnce(request, policy, externalSend: externalSend);
    } on SessionInvalidException catch (e, st) {
      if (!canRefresh) {
        rethrow;
      }
      return await _refreshAndRetry(
        coordinator,
        request,
        policy,
        attemptedSessionId: attemptedSessionId,
        originalError: e,
        originalStackTrace: st,
        externalSend: externalSend,
      );
    } on TokenOrSessionIsMissingException catch (e, st) {
      if (!canRefresh) {
        rethrow;
      }
      return await _refreshAndRetry(
        coordinator,
        request,
        policy,
        attemptedSessionId: attemptedSessionId,
        originalError: e,
        originalStackTrace: st,
        externalSend: externalSend,
      );
    } on Missing2FATokenException catch (e, st) {
      if (!canRefresh) {
        rethrow;
      }

      return await _refreshAndRetry(
        coordinator,
        request,
        policy,
        attemptedSessionId: attemptedSessionId,
        requestTwoFactorToken: true,
        originalError: e,
        originalStackTrace: st,
        externalSend: externalSend,
      );
    }
  }

  /// Erneuert die Session und wiederholt den Request GENAU EINMAL, mit
  /// DERSELBEN bereits bei [execute] erfassten [policy] - der Retry liest die
  /// Zone-Scopes NICHT erneut, damit ein Session-Refresh-Retry die
  /// ursprünglich erfasste Policy beibehält. Session-Fehler des Retries
  /// propagieren (kein weiterer Refresh, da der Retry [_executeOnce] direkt
  /// aufruft statt [execute]); schlägt der Refresh selbst fehl, propagiert
  /// dessen Exception unverändert. Bleibt der Refresh (defensiv) inaktiv,
  /// OHNE selbst zu werfen, wird die URSPRÜNGLICHE Session-Exception (samt
  /// Stacktrace) erneut geworfen, statt den nicht-existenten lexikalischen
  /// `rethrow`-Kontext zu nutzen.
  ///
  /// Der Retry umgeht IMMER den `BatchCoordinator` (`bypassBuffering: true`),
  /// selbst wenn [request] grundsätzlich Multi-Request-fähig war: Ein erneut
  /// gepufferter Retry würde auf den nächsten Flush warten (zusätzliche,
  /// unnötige Latenz) statt sofort zuzuschlagen, und könnte im Extremfall
  /// denselben demultiplexten Session-Fehler erneut über einen weiteren
  /// Multi-Request einsammeln. Der Retry ist bereits die
  /// Ausnahme-Behandlung EINES konkreten Fehlers und wird daher immer als
  /// direkte Einzelanfrage gesendet.
  Future<T> _refreshAndRetry<T>(
    SessionCoordinator coordinator,
    ApiRequest<T> request,
    RuntimeExecutionPolicy policy, {
    required String attemptedSessionId,
    bool requestTwoFactorToken = false,
    required Object originalError,
    required StackTrace originalStackTrace,
    Future<TransportResponse> Function(Uri uri, Map<String, String> headers)?
    externalSend,
  }) async {
    // Hat eine parallele Recovery die Session bereits ersetzt, ist kein
    // weiterer Login nötig. Das ist die zweite Single-Flight-Garantie für
    // spät fortgesetzte Multi-Teilrequests, nachdem `_ongoingRefresh` schon
    // abgeschlossen und freigegeben wurde.
    if (sessionState.sessionId.isNotEmpty &&
        sessionState.sessionId != attemptedSessionId) {
      return _executeOnce(
        request,
        policy,
        bypassBuffering: true,
        externalSend: externalSend,
      );
    }

    final RefreshSessionResponse refresh = await coordinator.refreshSession(
      requestTwoFactorToken: requestTwoFactorToken,
    );

    if (!refresh.isActive) {
      Error.throwWithStackTrace(originalError, originalStackTrace);
    }

    return _executeOnce(
      request,
      policy,
      bypassBuffering: true,
      externalSend: externalSend,
    );
  }

  Future<T> _executeOnce<T>(
    ApiRequest<T> request,
    RuntimeExecutionPolicy policy, {
    bool bypassBuffering = false,
    Future<TransportResponse> Function(Uri uri, Map<String, String> headers)?
    externalSend,
  }) async {
    final Uri uri = _buildRequestUri(request);
    final Map<String, String> headers = _headerProvider.build(
      authentication: request.authentication,
      contentType: request.contentType,
      additionalHeaders: request.additionalHeaders,
    );

    final ApiRequestTelemetry tracker = _telemetry.requestStarted(
      operationId: request.operationId,
      method: request.method,
      uri: uri,
      headers: headers,
      body: request.body,
    );

    final TransportResponse response;
    try {
      response = externalSend != null
          ? await externalSend(
              uri,
              headers,
            ).timeout(configuration.responseTimeout)
          : await _dispatch(
              request,
              policy,
              uri: uri,
              headers: headers,
              bypassBuffering: bypassBuffering,
            );
    } catch (error) {
      tracker.failed(error);
      rethrow;
    }

    // Erst nach erfolgreicher Dekodierung als Erfolg melden: Wirft die
    // ResponsePolicy (z.B. das V1-Exception-Mapping), zählt der Request
    // als fehlgeschlagen - mit Statuscode der bereits erhaltenen Antwort.
    final T result;
    try {
      final TransportResponse normalizedResponse = await _normalizeResponse(
        response,
        request.responsePolicy,
      );
      result = await request.responsePolicy.decode(normalizedResponse);
    } catch (error, stackTrace) {
      tracker.failed(error, response: response);
      await _triggerResponseErrorCallback(error);
      Error.throwWithStackTrace(error, stackTrace);
    }

    tracker.succeeded(response);

    return result;
  }

  /// Meldet fachliche Response-Fehler genau an der HTTP-Antwort, die sie
  /// erzeugt hat. So wird ein Fehler aus einem verschachtelten Refresh-Login
  /// nicht im äußeren Request ein zweites Mal gemeldet. Callback-Fehler dürfen
  /// die ursprüngliche API-Exception nicht ersetzen.
  Future<void> _triggerResponseErrorCallback(Object error) async {
    try {
      if (error is UserAndPassWrongException) {
        await _callbacks?.triggerUserAndPassWrongEvent(error);
      } else if (error is LicenseException) {
        await _callbacks?.triggerLicenseWrongEvent(error);
      }
    } catch (_) {
      // Event-Handler sind Beobachter; der Response-Fehler bleibt führend.
    }
  }

  /// Naht für den `BatchCoordinator` (PR 3c): gepufferte Requests zweigen
  /// hier in den Multi-Request-Pfad ab.
  ///
  /// Ob [request] grundsätzlich Multi-Request-fähig ist, entscheidet
  /// AUSSCHLIESSLICH `MultiRequestEligibility` anhand von Version und Pfad -
  /// der Request selbst deklariert keine Buffering-Eignung mehr. Direkt
  /// (nie gepuffert) laufen zusätzlich:
  /// - technisch ungeeignete Requests (`MultiRequestEligibility.allows` ==
  ///   `false`),
  /// - [RuntimeExecutionPolicy.skipBuffering] (No-Buffer-Zone-Scope) - dieser
  ///   kann Buffering nur ABSCHALTEN, nie einen ungeeigneten Request
  ///   bufferbar machen,
  /// - [RuntimeExecutionPolicy.priority] == [ApiRequestPriority.high] oder
  ///   [bypassBuffering] (Session-Retry, siehe [_refreshAndRetry]),
  /// - global deaktiviertes `multiRequest`.
  ///
  /// Ein technisch geeigneter, aktuell aber nicht direkt laufender Request
  /// ohne angebundenen `BatchCoordinator` wirft weiterhin [UnsupportedError]
  /// (unverändertes Verhalten vor PR 3c; siehe
  /// `test/runtime/api_runtime_test.dart`). Andernfalls reiht der
  /// `BatchCoordinator` den Request ein und liefert dessen (ggf. aus einem
  /// Multi-Request demultiplexte) Antwort. Der Koordinator erfährt über
  /// `needsSession`, ob dieses Item beim SENDEN (nicht bereits jetzt beim
  /// Enqueue) mit der dann aktuellen Session-ID versehen werden muss - so
  /// bleibt der Koordinator frei von `AuthenticationPolicy`-Wissen, kennt
  /// aber dessen Konsequenz.
  Future<TransportResponse> _dispatch(
    ApiRequest<Object?> request,
    RuntimeExecutionPolicy policy, {
    required Uri uri,
    required Map<String, String> headers,
    bool bypassBuffering = false,
  }) {
    final bool eligible = MultiRequestEligibility.allows(
      target: request.target,
    );

    if (!eligible ||
        policy.skipBuffering ||
        bypassBuffering ||
        policy.priority == ApiRequestPriority.high ||
        !configuration.multiRequest) {
      return _transport.send(
        method: request.method,
        uri: uri,
        headers: headers,
        body: request.body,
      );
    }

    final BatchCoordinator? coordinator = _batchCoordinator;
    if (coordinator == null) {
      throw UnsupportedError(
        'Multi-fähige Requests erfordern bei aktivem multiRequest einen '
        'angebundenen BatchCoordinator (ApiRuntime(batchCoordinator: ...)).',
      );
    }

    final bool needsSession =
        request.authentication == AuthenticationPolicy.session ||
        request.authentication == AuthenticationPolicy.sessionNoRefresh;

    return coordinator.enqueue(
      method: request.method,
      uri: uri,
      headers: headers,
      needsSession: needsSession,
      body: request.body,
      priority: policy.priority,
    );
  }

  Uri _buildRequestUri(ApiRequest<Object?> request) {
    return switch (request.target) {
      VersionedApiRequestTarget(:final version, :final path) =>
        _uriBuilder.build(
          version: version,
          path: path,
          queryParameters: request.queryParameters,
        ),
      final ApiRequestTarget target => _uriBuilder.buildTarget(target: target),
    };
  }

  /// Gibt den Runtime frei. Idempotent: Nur der erste Aufruf schließt den
  /// eigenen HTTP-Client (injizierte Clients bleiben offen) und gibt einen
  /// angebundenen `BatchCoordinator` frei - dessen Flush-Timer wird
  /// abgebrochen und noch gepufferte Requests werden mit einem Fehler
  /// abgeschlossen, statt unbegrenzt zu warten. Weitere Aufrufe sind No-Ops.
  @override
  Future<void> dispose() async {
    if (_disposed) {
      return;
    }

    _disposed = true;
    await _batchCoordinator?.dispose();
    _transport.close();
  }
}

/// Kollisionsfreier, typisierter Schlüssel für eine geteilte
/// Request-Ausführung. Die ResponsePolicy wird absichtlich per Identität
/// verglichen: Zwei unterschiedlich konfigurierte Decoder dürfen nie
/// versehentlich dasselbe bereits dekodierte Future erhalten.
class _RequestDedupKey {
  final ApiHttpMethod method;
  final Uri uri;
  final String? body;
  final List<String> headers;
  final AuthenticationPolicy authentication;
  final bool skipBuffering;
  final ApiRequestPriority priority;
  final Object responsePolicy;
  final Type resultType;
  final String operationId;

  const _RequestDedupKey({
    required this.method,
    required this.uri,
    required this.body,
    required this.headers,
    required this.authentication,
    required this.skipBuffering,
    required this.priority,
    required this.responsePolicy,
    required this.resultType,
    required this.operationId,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is _RequestDedupKey &&
          method == other.method &&
          uri == other.uri &&
          body == other.body &&
          _listsEqual(headers, other.headers) &&
          authentication == other.authentication &&
          skipBuffering == other.skipBuffering &&
          priority == other.priority &&
          identical(responsePolicy, other.responsePolicy) &&
          resultType == other.resultType &&
          operationId == other.operationId;

  @override
  int get hashCode => Object.hash(
    method,
    uri,
    body,
    Object.hashAll(headers),
    authentication,
    skipBuffering,
    priority,
    identityHashCode(responsePolicy),
    resultType,
    operationId,
  );

  static bool _listsEqual(List<String> left, List<String> right) {
    if (left.length != right.length) {
      return false;
    }
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) {
        return false;
      }
    }
    return true;
  }
}
